/*
 * Copyright (c) 2007-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "reg.h"
#include "hif.h"
#include "htc_hif.h"

#define MAILBOX_FOR_BLOCK_SIZE          1

#define DELAY_PER_INTERVAL_MS 10  /* 10 ms*/

static void DevDumpRegisters(struct ar6k_device               *pDev,
                      struct ar6k_irq_proc_registers   *pIrqProcRegs,
                      struct ar6k_irq_enable_registers *pIrqEnableRegs);
void AR6KFreeIOPacket(struct ar6k_device *pDev, struct htc_packet *pPacket)
{
    spin_lock_bh(&pDev->Lock);
    HTC_PACKET_ENQUEUE(&pDev->RegisterIOList,pPacket);
    spin_unlock_bh(&pDev->Lock);
}

struct htc_packet *AR6KAllocIOPacket(struct ar6k_device *pDev)
{
    struct htc_packet *pPacket;

    spin_lock_bh(&pDev->Lock);
    pPacket = HTC_PACKET_DEQUEUE(&pDev->RegisterIOList);
    spin_unlock_bh(&pDev->Lock);

    return pPacket;
}

static struct hif_scatter_req *DevAllocScatterReq(struct hif_device *Context)
{
    struct dl_list *pItem;
    struct ar6k_device *pDev = (struct ar6k_device *)Context;
    spin_lock_bh(&pDev->Lock);
    pItem = DL_ListRemoveItemFromHead(&pDev->ScatterReqHead);
    spin_unlock_bh(&pDev->Lock);
    if (pItem != NULL) {
        return A_CONTAINING_STRUCT(pItem, struct hif_scatter_req, ListLink);
    }
    return NULL;
}

static void DevCleanupVirtualScatterSupport(struct ar6k_device *pDev)
{
    struct hif_scatter_req *pReq;

    while (1) {
        pReq = DevAllocScatterReq((struct hif_device *)pDev);
        if (NULL == pReq) {
            break;
        }
        kfree(pReq);
    }

}

void DevCleanup(struct ar6k_device *pDev)
{
    if (pDev->HifAttached) {
        hif_detach_htc(pDev->HIFDevice);
        pDev->HifAttached = false;
    }

    DevCleanupVirtualScatterSupport(pDev);
}

static int DevEnableInterrupts(struct ar6k_device *pDev)
{
	int                  status;
	struct ar6k_irq_enable_registers regs;

	spin_lock_bh(&pDev->Lock);

	/* Enable all the interrupts except for the internal AR6000 CPU interrupt */
	pDev->IrqEnableRegisters.int_status_enable = INT_STATUS_ENABLE_ERROR_SET(0x01) |
		INT_STATUS_ENABLE_CPU_SET(0x01) |
		INT_STATUS_ENABLE_COUNTER_SET(0x01);

	if (NULL == pDev->GetPendingEventsFunc) {
		pDev->IrqEnableRegisters.int_status_enable |= INT_STATUS_ENABLE_MBOX_DATA_SET(0x01);
	} else {
		/* The HIF layer provided us with a pending events function which means that
		 * the detection of pending mbox messages is handled in the HIF layer.
		 * This is the case for the SPI2 interface.
		 * In the normal case we enable MBOX interrupts, for the case
		 * with HIFs that offer this mechanism, we keep these interrupts
		 * masked */
		pDev->IrqEnableRegisters.int_status_enable &= ~INT_STATUS_ENABLE_MBOX_DATA_SET(0x01);
	}


	/* Set up the CPU Interrupt Status Register */
	pDev->IrqEnableRegisters.cpu_int_status_enable = CPU_INT_STATUS_ENABLE_BIT_SET(0x00);

	/* Set up the Error Interrupt Status Register */
	pDev->IrqEnableRegisters.error_status_enable =
		ERROR_STATUS_ENABLE_RX_UNDERFLOW_SET(0x01) |
		ERROR_STATUS_ENABLE_TX_OVERFLOW_SET(0x01);

	/* Set up the Counter Interrupt Status Register (only for debug interrupt to catch fatal errors) */
	pDev->IrqEnableRegisters.counter_int_status_enable =
		COUNTER_INT_STATUS_ENABLE_BIT_SET(AR6K_TARGET_DEBUG_INTR_MASK);

	/* copy into our temp area */
	memcpy(&regs,&pDev->IrqEnableRegisters,AR6K_IRQ_ENABLE_REGS_SIZE);

	spin_unlock_bh(&pDev->Lock);

	/* always synchronous */
	status = hif_read_write(pDev->HIFDevice,
			INT_STATUS_ENABLE_ADDRESS,
			&regs.int_status_enable,
			AR6K_IRQ_ENABLE_REGS_SIZE,
			HIF_WR_SYNC_BYTE_INC,
			NULL);

	if (status) {
		/* Can't write it for some reason */
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("Failed to update interrupt control registers err: %d\n", status));

	}

	return status;
}

int DevDisableInterrupts(struct ar6k_device *pDev)
{
	struct ar6k_irq_enable_registers regs;

	spin_lock_bh(&pDev->Lock);
	/* Disable all interrupts */
	pDev->IrqEnableRegisters.int_status_enable = 0;
	pDev->IrqEnableRegisters.cpu_int_status_enable = 0;
	pDev->IrqEnableRegisters.error_status_enable = 0;
	pDev->IrqEnableRegisters.counter_int_status_enable = 0;
	/* copy into our temp area */
	memcpy(&regs,&pDev->IrqEnableRegisters,AR6K_IRQ_ENABLE_REGS_SIZE);

	spin_unlock_bh(&pDev->Lock);

	/* always synchronous */
	return hif_read_write(pDev->HIFDevice,
			INT_STATUS_ENABLE_ADDRESS,
			&regs.int_status_enable,
			AR6K_IRQ_ENABLE_REGS_SIZE,
			HIF_WR_SYNC_BYTE_INC,
			NULL);
}

static int DevRWCompletionHandler(void *context, int status)
{
    struct htc_packet *pPacket = (struct htc_packet *)context;

    AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
                ("+DevRWCompletionHandler (Pkt:0x%lX) , Status: %d \n",
                (unsigned long)pPacket,
                status));

    COMPLETE_HTC_PACKET(pPacket,status);

    AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
                ("-DevRWCompletionHandler\n"));

    return 0;
}

static int DevServiceDebugInterrupt(struct ar6k_device *pDev)
{
    u32 dummy;
    int status;

    /* Send a target failure event to the application */
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Target debug interrupt\n"));

    if (pDev->TargetFailureCallback != NULL) {
        pDev->TargetFailureCallback(pDev->HTCContext);
    }

    /* clear the interrupt , the debug error interrupt is
     * counter 0 */
        /* read counter to clear interrupt */
    status = hif_read_write(pDev->HIFDevice,
                          COUNT_DEC_ADDRESS,
                          (u8 *)&dummy,
                          4,
                          HIF_RD_SYNC_BYTE_INC,
                          NULL);

    A_ASSERT(status == 0);
    return status;
}

static int DevServiceCounterInterrupt(struct ar6k_device *pDev)
{
    u8 counter_int_status;

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ, ("Counter Interrupt\n"));

    counter_int_status = pDev->IrqProcRegisters.counter_int_status &
                         pDev->IrqEnableRegisters.counter_int_status_enable;

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,
                    ("Valid interrupt source(s) in COUNTER_INT_STATUS: 0x%x\n",
                    counter_int_status));

        /* Check if the debug interrupt is pending
         * NOTE: other modules like GMBOX may use the counter interrupt for
         * credit flow control on other counters, we only need to check for the debug assertion
         * counter interrupt */
    if (counter_int_status & AR6K_TARGET_DEBUG_INTR_MASK) {
        return DevServiceDebugInterrupt(pDev);
    }

    return 0;
}

static int DevServiceCPUInterrupt(struct ar6k_device *pDev)
{
    int status;
    u8 cpu_int_status;
    u8 regBuffer[4];

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ, ("CPU Interrupt\n"));
    cpu_int_status = pDev->IrqProcRegisters.cpu_int_status &
                     pDev->IrqEnableRegisters.cpu_int_status_enable;
    A_ASSERT(cpu_int_status);
    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,
                    ("Valid interrupt source(s) in CPU_INT_STATUS: 0x%x\n",
                    cpu_int_status));

        /* Clear the interrupt */
    pDev->IrqProcRegisters.cpu_int_status &= ~cpu_int_status; /* W1C */

        /* set up the register transfer buffer to hit the register 4 times , this is done
         * to make the access 4-byte aligned to mitigate issues with host bus interconnects that
         * restrict bus transfer lengths to be a multiple of 4-bytes */

        /* set W1C value to clear the interrupt, this hits the register first */
    regBuffer[0] = cpu_int_status;
        /* the remaining 4 values are set to zero which have no-effect  */
    regBuffer[1] = 0;
    regBuffer[2] = 0;
    regBuffer[3] = 0;

    status = hif_read_write(pDev->HIFDevice,
                          CPU_INT_STATUS_ADDRESS,
                          regBuffer,
                          4,
                          HIF_WR_SYNC_BYTE_FIX,
                          NULL);

    A_ASSERT(status == 0);
    return status;
}

static int DevServiceErrorInterrupt(struct ar6k_device *pDev)
{
    int status;
    u8 error_int_status;
    u8 regBuffer[4];

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ, ("Error Interrupt\n"));
    error_int_status = pDev->IrqProcRegisters.error_int_status & 0x0F;
    A_ASSERT(error_int_status);
    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,
                    ("Valid interrupt source(s) in ERROR_INT_STATUS: 0x%x\n",
                    error_int_status));

    if (ERROR_INT_STATUS_WAKEUP_GET(error_int_status)) {
        /* Wakeup */
        AR_DEBUG_PRINTF(ATH_DEBUG_IRQ, ("Error : Wakeup\n"));
    }

    if (ERROR_INT_STATUS_RX_UNDERFLOW_GET(error_int_status)) {
        /* Rx Underflow */
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Error : Rx Underflow\n"));
    }

    if (ERROR_INT_STATUS_TX_OVERFLOW_GET(error_int_status)) {
        /* Tx Overflow */
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Error : Tx Overflow\n"));
    }

        /* Clear the interrupt */
    pDev->IrqProcRegisters.error_int_status &= ~error_int_status; /* W1C */

        /* set up the register transfer buffer to hit the register 4 times , this is done
         * to make the access 4-byte aligned to mitigate issues with host bus interconnects that
         * restrict bus transfer lengths to be a multiple of 4-bytes */

        /* set W1C value to clear the interrupt, this hits the register first */
    regBuffer[0] = error_int_status;
        /* the remaining 4 values are set to zero which have no-effect  */
    regBuffer[1] = 0;
    regBuffer[2] = 0;
    regBuffer[3] = 0;

    status = hif_read_write(pDev->HIFDevice,
                          ERROR_INT_STATUS_ADDRESS,
                          regBuffer,
                          4,
                          HIF_WR_SYNC_BYTE_FIX,
                          NULL);

    A_ASSERT(status == 0);
    return status;
}

/* process pending interrupts synchronously */
static int ProcessPendingIRQs(struct ar6k_device *pDev, bool *pDone, bool *pASyncProcessing)
{
    int    status = 0;
    u8 host_int_status = 0;
    u32 lookAhead = 0;

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("+ProcessPendingIRQs: (dev: 0x%lX)\n", (unsigned long)pDev));

    /*** NOTE: the HIF implementation guarantees that the context of this call allows
     *         us to perform SYNCHRONOUS I/O, that is we can block, sleep or call any API that
     *         can block or switch thread/task ontexts.
     *         This is a fully schedulable context.
     * */
    do {

            if (pDev->IrqEnableRegisters.int_status_enable == 0) {
                /* interrupt enables have been cleared, do not try to process any pending interrupts that
                 * may result in more bus transactions.  The target may be unresponsive at this
                 * point. */
                 break;
            }

            if (pDev->GetPendingEventsFunc != NULL) {
                struct hif_pending_events_info events;

#ifdef THREAD_X
            events.Polling= 0;
#endif
                /* the HIF layer uses a special mechanism to get events
                 * get this synchronously  */
            status = pDev->GetPendingEventsFunc(pDev->HIFDevice,
                                                &events,
                                                NULL);

            if (status) {
                break;
            }

            if (events.Events & HIF_RECV_MSG_AVAIL) {
                lookAhead = events.LookAhead;
                if (0 == lookAhead) {
                    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" ProcessPendingIRQs1 lookAhead is zero! \n"));
                }
            }

            if (!(events.Events & HIF_OTHER_EVENTS) ||
                !(pDev->IrqEnableRegisters.int_status_enable & OTHER_INTS_ENABLED)) {
                    /* no need to read the register table, no other interesting interrupts.
                     * Some interfaces (like SPI) can shadow interrupt sources without
                     * requiring the host to do a full table read */
                break;
            }

            /* otherwise fall through and read the register table */
        }

        /*
         * Read the first 28 bytes of the HTC register table. This will yield us
         * the value of different int status registers and the lookahead
         * registers.
         *    length = sizeof(int_status) + sizeof(cpu_int_status) +
         *             sizeof(error_int_status) + sizeof(counter_int_status) +
         *             sizeof(mbox_frame) + sizeof(rx_lookahead_valid) +
         *             sizeof(hole) +  sizeof(rx_lookahead) +
         *             sizeof(int_status_enable) + sizeof(cpu_int_status_enable) +
         *             sizeof(error_status_enable) +
         *             sizeof(counter_int_status_enable);
         *
        */
#ifdef CONFIG_MMC_SDHCI_S3C
            pDev->IrqProcRegisters.host_int_status = 0;
            pDev->IrqProcRegisters.rx_lookahead_valid = 0;
            pDev->IrqProcRegisters.host_int_status2 = 0;
            pDev->IrqProcRegisters.rx_lookahead[0] = 0;
            pDev->IrqProcRegisters.rx_lookahead[1] = 0xaaa5555;
#endif /* CONFIG_MMC_SDHCI_S3C */
        status = hif_read_write(pDev->HIFDevice,
                              HOST_INT_STATUS_ADDRESS,
                              (u8 *)&pDev->IrqProcRegisters,
                              AR6K_IRQ_PROC_REGS_SIZE,
                              HIF_RD_SYNC_BYTE_INC,
                              NULL);

        if (status) {
            break;
        }

#ifdef ATH_DEBUG_MODULE
        if (AR_DEBUG_LVL_CHECK(ATH_DEBUG_IRQ)) {
            DevDumpRegisters(pDev,
                             &pDev->IrqProcRegisters,
                             &pDev->IrqEnableRegisters);
        }
#endif

            /* Update only those registers that are enabled */
        host_int_status = pDev->IrqProcRegisters.host_int_status &
                          pDev->IrqEnableRegisters.int_status_enable;

        if (NULL == pDev->GetPendingEventsFunc) {
                /* only look at mailbox status if the HIF layer did not provide this function,
                 * on some HIF interfaces reading the RX lookahead is not valid to do */
            if (host_int_status & (1 << HTC_MAILBOX)) {
                    /* mask out pending mailbox value, we use "lookAhead" as the real flag for
                     * mailbox processing below */
                host_int_status &= ~(1 << HTC_MAILBOX);
                if (pDev->IrqProcRegisters.rx_lookahead_valid & (1 << HTC_MAILBOX)) {
                        /* mailbox has a message and the look ahead is valid */
                    lookAhead = pDev->IrqProcRegisters.rx_lookahead[HTC_MAILBOX];
                    if (0 == lookAhead) {
                        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" ProcessPendingIRQs2, lookAhead is zero! \n"));
                    }
                }
            }
        } else {
                /* not valid to check if the HIF has another mechanism for reading mailbox pending status*/
            host_int_status &= ~(1 << HTC_MAILBOX);
        }

    } while (false);


    do {

            /* did the interrupt status fetches succeed? */
        if (status) {
            break;
        }

        if ((0 == host_int_status) && (0 == lookAhead)) {
                /* nothing to process, the caller can use this to break out of a loop */
            *pDone = true;
            break;
        }

        if (lookAhead != 0) {
            int fetched = 0;

            AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("Pending mailbox message, LookAhead: 0x%X\n",lookAhead));
                /* Mailbox Interrupt, the HTC layer may issue async requests to empty the
                 * mailbox...
                 * When emptying the recv mailbox we use the async handler above called from the
                 * completion routine of the callers read request. This can improve performance
                 * by reducing context switching when we rapidly pull packets */
            status = pDev->MessagePendingCallback(pDev->HTCContext, &lookAhead, 1, pASyncProcessing, &fetched);
            if (status) {
                break;
            }

            if (!fetched) {
                    /* HTC could not pull any messages out due to lack of resources */
                    /* force DSR handler to ack the interrupt */
                *pASyncProcessing = false;
                pDev->RecheckIRQStatusCnt = 0;
            }
        }

            /* now handle the rest of them */
        AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,
                            (" Valid interrupt source(s) for OTHER interrupts: 0x%x\n",
                            host_int_status));

        if (HOST_INT_STATUS_CPU_GET(host_int_status)) {
                /* CPU Interrupt */
            status = DevServiceCPUInterrupt(pDev);
            if (status){
                break;
            }
        }

        if (HOST_INT_STATUS_ERROR_GET(host_int_status)) {
                /* Error Interrupt */
            status = DevServiceErrorInterrupt(pDev);
            if (status){
                break;
            }
        }

        if (HOST_INT_STATUS_COUNTER_GET(host_int_status)) {
                /* Counter Interrupt */
            status = DevServiceCounterInterrupt(pDev);
            if (status){
                break;
            }
        }

    } while (false);

        /* an optimization to bypass reading the IRQ status registers unecessarily which can re-wake
         * the target, if upper layers determine that we are in a low-throughput mode, we can
         * rely on taking another interrupt rather than re-checking the status registers which can
         * re-wake the target.
         *
         * NOTE : for host interfaces that use the special GetPendingEventsFunc, this optimization cannot
         * be used due to possible side-effects.  For example, SPI requires the host to drain all
         * messages from the mailbox before exiting the ISR routine. */
    if (!(*pASyncProcessing) && (pDev->RecheckIRQStatusCnt == 0) && (pDev->GetPendingEventsFunc == NULL)) {
        AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("Bypassing IRQ Status re-check, forcing done \n"));
        *pDone = true;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("-ProcessPendingIRQs: (done:%d, async:%d) status=%d \n",
                *pDone, *pASyncProcessing, status));

    return status;
}

/* callback when our fetch to get interrupt status registers completes */
static void DevGetEventAsyncHandler(void *Context, struct htc_packet *pPacket)
{
    struct ar6k_device *pDev = (struct ar6k_device *)Context;
    u32 lookAhead = 0;
    bool      otherInts = false;

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("+DevGetEventAsyncHandler: (dev: 0x%lX)\n", (unsigned long)pDev));

    do {

        if (pPacket->Status) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
                    (" GetEvents I/O request failed, status:%d \n", pPacket->Status));
            /* bail out, don't unmask HIF interrupt */
            break;
        }

        if (pDev->GetPendingEventsFunc != NULL) {
                /* the HIF layer collected the information for us */
            struct hif_pending_events_info *pEvents = (struct hif_pending_events_info *)pPacket->pBuffer;
            if (pEvents->Events & HIF_RECV_MSG_AVAIL) {
                lookAhead = pEvents->LookAhead;
                if (0 == lookAhead) {
                    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" DevGetEventAsyncHandler1, lookAhead is zero! \n"));
                }
            }
            if (pEvents->Events & HIF_OTHER_EVENTS) {
                otherInts = true;
            }
        } else {
                /* standard interrupt table handling.... */
            struct ar6k_irq_proc_registers *pReg = (struct ar6k_irq_proc_registers *)pPacket->pBuffer;
            u8 host_int_status;

            host_int_status = pReg->host_int_status & pDev->IrqEnableRegisters.int_status_enable;

            if (host_int_status & (1 << HTC_MAILBOX)) {
                host_int_status &= ~(1 << HTC_MAILBOX);
                if (pReg->rx_lookahead_valid & (1 << HTC_MAILBOX)) {
                        /* mailbox has a message and the look ahead is valid */
                    lookAhead = pReg->rx_lookahead[HTC_MAILBOX];
                    if (0 == lookAhead) {
                        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" DevGetEventAsyncHandler2, lookAhead is zero! \n"));
                    }
                }
            }

            if (host_int_status) {
                    /* there are other interrupts to handle */
                otherInts = true;
            }
        }

        if (otherInts || (lookAhead == 0)) {
            /* if there are other interrupts to process, we cannot do this in the async handler so
             * ack the interrupt which will cause our sync handler to run again
             * if however there are no more messages, we can now ack the interrupt  */
            AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,
                (" Acking interrupt from DevGetEventAsyncHandler (otherints:%d, lookahead:0x%X)\n",
                otherInts, lookAhead));
            hif_ack_interrupt(pDev->HIFDevice);
        } else {
            int      fetched = 0;
            int status;

            AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,
                    (" DevGetEventAsyncHandler : detected another message, lookahead :0x%X \n",
                    lookAhead));
                /* lookahead is non-zero and there are no other interrupts to service,
                 * go get the next message */
            status = pDev->MessagePendingCallback(pDev->HTCContext, &lookAhead, 1, NULL, &fetched);

            if (!status && !fetched) {
                    /* HTC layer could not pull out messages due to lack of resources, stop IRQ processing */
                AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("MessagePendingCallback did not pull any messages, force-ack \n"));
                DevAsyncIrqProcessComplete(pDev);
            }
        }

    } while (false);

        /* free this IO packet */
    AR6KFreeIOPacket(pDev,pPacket);
    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("-DevGetEventAsyncHandler \n"));
}

/* Synchronousinterrupt handler, this handler kicks off all interrupt processing.*/
static int DevDsrHandler(void *context)
{
    struct ar6k_device *pDev = (struct ar6k_device *)context;
    int    status = 0;
    bool      done = false;
    bool      asyncProc = false;

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("+DevDsrHandler: (dev: 0x%lX)\n", (unsigned long)pDev));

        /* reset the recv counter that tracks when we need to yield from the DSR */
    pDev->CurrentDSRRecvCount = 0;
        /* reset counter used to flag a re-scan of IRQ status registers on the target */
    pDev->RecheckIRQStatusCnt = 0;

    while (!done) {
        status = ProcessPendingIRQs(pDev, &done, &asyncProc);
        if (status) {
            break;
        }

        if (HIF_DEVICE_IRQ_SYNC_ONLY == pDev->HifIRQProcessingMode) {
            /* the HIF layer does not allow async IRQ processing, override the asyncProc flag */
            asyncProc = false;
            /* this will cause us to re-enter ProcessPendingIRQ() and re-read interrupt status registers.
             * this has a nice side effect of blocking us until all async read requests are completed.
             * This behavior is required on some HIF implementations that do not allow ASYNC
             * processing in interrupt handlers (like Windows CE) */

            if (pDev->DSRCanYield && DEV_CHECK_RECV_YIELD(pDev)) {
                /* ProcessPendingIRQs() pulled enough recv messages to satisfy the yield count, stop
                 * checking for more messages and return */
                break;
            }
        }

        if (asyncProc) {
                /* the function performed some async I/O for performance, we
                   need to exit the ISR immediately, the check below will prevent the interrupt from being
                   Ack'd while we handle it asynchronously */
            break;
        }

    }

    if (!status && !asyncProc) {
            /* Ack the interrupt only if :
             *  1. we did not get any errors in processing interrupts
             *  2. there are no outstanding async processing requests */
        if (pDev->DSRCanYield) {
                /* if the DSR can yield do not ACK the interrupt, there could be more pending messages.
                 * The HIF layer must ACK the interrupt on behalf of HTC */
            AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,(" Yield in effect (cur RX count: %d) \n", pDev->CurrentDSRRecvCount));
        } else {
            AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,(" Acking interrupt from DevDsrHandler \n"));
            hif_ack_interrupt(pDev->HIFDevice);
        }
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("-DevDsrHandler \n"));
    return status;
}

/* called by the HTC layer when it wants us to check if the device has any more pending
 * recv messages, this starts off a series of async requests to read interrupt registers  */
int DevCheckPendingRecvMsgsAsync(void *context)
{
    struct ar6k_device  *pDev = (struct ar6k_device *)context;
    int      status = 0;
    struct htc_packet   *pIOPacket;

    /* this is called in an ASYNC only context, we may NOT block, sleep or call any apis that can
     * cause us to switch contexts */

   AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("+DevCheckPendingRecvMsgsAsync: (dev: 0x%lX)\n", (unsigned long)pDev));

   do {

        if (HIF_DEVICE_IRQ_SYNC_ONLY == pDev->HifIRQProcessingMode) {
                /* break the async processing chain right here, no need to continue.
                 * The DevDsrHandler() will handle things in a loop when things are driven
                 * synchronously  */
            break;
        }

            /* an optimization to bypass reading the IRQ status registers unecessarily which can re-wake
             * the target, if upper layers determine that we are in a low-throughput mode, we can
             * rely on taking another interrupt rather than re-checking the status registers which can
             * re-wake the target */
        if (pDev->RecheckIRQStatusCnt == 0) {
            AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("Bypassing IRQ Status re-check, re-acking HIF interrupts\n"));
                /* ack interrupt */
            hif_ack_interrupt(pDev->HIFDevice);
            break;
        }

            /* first allocate one of our HTC packets we created for async I/O
             * we reuse HTC packet definitions so that we can use the completion mechanism
             * in DevRWCompletionHandler() */
        pIOPacket = AR6KAllocIOPacket(pDev);

        if (NULL == pIOPacket) {
                /* there should be only 1 asynchronous request out at a time to read these registers
                 * so this should actually never happen */
            status = A_NO_MEMORY;
            A_ASSERT(false);
            break;
        }

            /* stick in our completion routine when the I/O operation completes */
        pIOPacket->Completion = DevGetEventAsyncHandler;
        pIOPacket->pContext = pDev;

        if (pDev->GetPendingEventsFunc) {
                /* HIF layer has it's own mechanism, pass the IO to it.. */
            status = pDev->GetPendingEventsFunc(pDev->HIFDevice,
                                                (struct hif_pending_events_info *)pIOPacket->pBuffer,
                                                pIOPacket);

        } else {
                /* standard way, read the interrupt register table asynchronously again */
            status = hif_read_write(pDev->HIFDevice,
                                  HOST_INT_STATUS_ADDRESS,
                                  pIOPacket->pBuffer,
                                  AR6K_IRQ_PROC_REGS_SIZE,
                                  HIF_RD_ASYNC_BYTE_INC,
                                  pIOPacket);
        }

        AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,(" Async IO issued to get interrupt status...\n"));
   } while (false);

   AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("-DevCheckPendingRecvMsgsAsync \n"));

   return status;
}

void DevAsyncIrqProcessComplete(struct ar6k_device *pDev)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("DevAsyncIrqProcessComplete - forcing HIF IRQ ACK \n"));
    hif_ack_interrupt(pDev->HIFDevice);
}


/* mailbox recv message polling */
int DevPollMboxMsgRecv(struct ar6k_device *pDev,
                            u32 *pLookAhead,
                            int          TimeoutMS)
{
    int status = 0;
    int      timeout = TimeoutMS/DELAY_PER_INTERVAL_MS;

    A_ASSERT(timeout > 0);

    AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("+DevPollMboxMsgRecv \n"));

    while (true) {

        if (pDev->GetPendingEventsFunc != NULL) {

            struct hif_pending_events_info events;

#ifdef THREAD_X
			events.Polling =1;
#endif

            /* the HIF layer uses a special mechanism to get events, do this
             * synchronously */
            status = pDev->GetPendingEventsFunc(pDev->HIFDevice,
                                            &events,
                                            NULL);
            if (status)
            {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Failed to get pending events \n"));
                break;
            }

            if (events.Events & HIF_RECV_MSG_AVAIL)
            {
                    /*  there is a message available, the lookahead should be valid now */
                *pLookAhead = events.LookAhead;

                break;
            }
        } else {

                /* this is the standard HIF way.... */
                /* load the register table */
            status = hif_read_write(pDev->HIFDevice,
                                  HOST_INT_STATUS_ADDRESS,
                                  (u8 *)&pDev->IrqProcRegisters,
                                  AR6K_IRQ_PROC_REGS_SIZE,
                                  HIF_RD_SYNC_BYTE_INC,
                                  NULL);

            if (status){
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Failed to read register table \n"));
                break;
            }

                /* check for MBOX data and valid lookahead */
            if (pDev->IrqProcRegisters.host_int_status & (1 << HTC_MAILBOX)) {
                if (pDev->IrqProcRegisters.rx_lookahead_valid & (1 << HTC_MAILBOX))
                {
                    /* mailbox has a message and the look ahead is valid */
                    *pLookAhead = pDev->IrqProcRegisters.rx_lookahead[HTC_MAILBOX];
                    break;
                }
            }

        }

        timeout--;

        if (timeout <= 0) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, (" Timeout waiting for recv message \n"));
            status = A_ERROR;

                /* check if the target asserted */
            if ( pDev->IrqProcRegisters.counter_int_status & AR6K_TARGET_DEBUG_INTR_MASK) {
                    /* target signaled an assert, process this pending interrupt
                     * this will call the target failure handler */
                DevServiceDebugInterrupt(pDev);
            }

            break;
        }

            /* delay a little  */
        mdelay(DELAY_PER_INTERVAL_MS);
        AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("  Retry Mbox Poll : %d \n",timeout));
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("-DevPollMboxMsgRecv \n"));

    return status;
}
int DevSetup(struct ar6k_device *pDev)
{
    u32 blocksizes[AR6K_MAILBOXES];
    int status = 0;
    int      i;
    struct htc_callbacks htcCallbacks;

    do {

        DL_LIST_INIT(&pDev->ScatterReqHead);
           /* initialize our free list of IO packets */
        INIT_HTC_PACKET_QUEUE(&pDev->RegisterIOList);
        spin_lock_init(&pDev->Lock);

        memset(&htcCallbacks, 0, sizeof(struct htc_callbacks));
            /* the device layer handles these */
        htcCallbacks.rwCompletionHandler = DevRWCompletionHandler;
        htcCallbacks.dsrHandler = DevDsrHandler;
        htcCallbacks.context = pDev;

        status = hif_attach_htc(pDev->HIFDevice, &htcCallbacks);

        if (status) {
            break;
        }

        pDev->HifAttached = true;

            /* get the addresses for all 4 mailboxes */
        status = hif_config_dev(pDev->HIFDevice, HIF_DEVICE_GET_MBOX_ADDR,
                                    &pDev->MailBoxInfo, sizeof(pDev->MailBoxInfo));

        if (status) {
            A_ASSERT(false);
            break;
        }

            /* carve up register I/O packets (these are for ASYNC register I/O ) */
        for (i = 0; i < AR6K_MAX_REG_IO_BUFFERS; i++) {
            struct htc_packet *pIOPacket;
            pIOPacket = &pDev->RegIOBuffers[i].HtcPacket;
            SET_HTC_PACKET_INFO_RX_REFILL(pIOPacket,
                                          pDev,
                                          pDev->RegIOBuffers[i].Buffer,
                                          AR6K_REG_IO_BUFFER_SIZE,
                                          0); /* don't care */
            AR6KFreeIOPacket(pDev,pIOPacket);
        }

            /* get the block sizes */
        status = hif_config_dev(pDev->HIFDevice, HIF_DEVICE_GET_MBOX_BLOCK_SIZE,
                                    blocksizes, sizeof(blocksizes));

        if (status) {
            A_ASSERT(false);
            break;
        }

            /* note: we actually get the block size of a mailbox other than 0, for SDIO the block
             * size on mailbox 0 is artificially set to 1.  So we use the block size that is set
             * for the other 3 mailboxes */
        pDev->BlockSize = blocksizes[MAILBOX_FOR_BLOCK_SIZE];
            /* must be a power of 2 */
        A_ASSERT((pDev->BlockSize & (pDev->BlockSize - 1)) == 0);

            /* assemble mask, used for padding to a block */
        pDev->BlockMask = pDev->BlockSize - 1;

        AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("BlockSize: %d, MailboxAddress:0x%X \n",
                    pDev->BlockSize, pDev->MailBoxInfo.MboxAddresses[HTC_MAILBOX]));

        pDev->GetPendingEventsFunc = NULL;
            /* see if the HIF layer implements the get pending events function  */
        hif_config_dev(pDev->HIFDevice,
                           HIF_DEVICE_GET_PENDING_EVENTS_FUNC,
                           &pDev->GetPendingEventsFunc,
                           sizeof(pDev->GetPendingEventsFunc));

            /* assume we can process HIF interrupt events asynchronously */
        pDev->HifIRQProcessingMode = HIF_DEVICE_IRQ_ASYNC_SYNC;

            /* see if the HIF layer overrides this assumption */
        hif_config_dev(pDev->HIFDevice,
                           HIF_DEVICE_GET_IRQ_PROC_MODE,
                           &pDev->HifIRQProcessingMode,
                           sizeof(pDev->HifIRQProcessingMode));

        switch (pDev->HifIRQProcessingMode) {
            case HIF_DEVICE_IRQ_SYNC_ONLY:
                AR_DEBUG_PRINTF(ATH_DEBUG_WARN,("HIF Interrupt processing is SYNC ONLY\n"));
                    /* see if HIF layer wants HTC to yield */
                hif_config_dev(pDev->HIFDevice,
                                   HIF_DEVICE_GET_IRQ_YIELD_PARAMS,
                                   &pDev->HifIRQYieldParams,
                                   sizeof(pDev->HifIRQYieldParams));

                if (pDev->HifIRQYieldParams.RecvPacketYieldCount > 0) {
                    AR_DEBUG_PRINTF(ATH_DEBUG_WARN,
                        ("HIF requests that DSR yield per %d RECV packets \n",
                        pDev->HifIRQYieldParams.RecvPacketYieldCount));
                    pDev->DSRCanYield = true;
                }
                break;
            case HIF_DEVICE_IRQ_ASYNC_SYNC:
                AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("HIF Interrupt processing is ASYNC and SYNC\n"));
                break;
            default:
                A_ASSERT(false);
        }

        pDev->HifMaskUmaskRecvEvent = NULL;

            /* see if the HIF layer implements the mask/unmask recv events function  */
        hif_config_dev(pDev->HIFDevice,
                           HIF_DEVICE_GET_RECV_EVENT_MASK_UNMASK_FUNC,
                           &pDev->HifMaskUmaskRecvEvent,
                           sizeof(pDev->HifMaskUmaskRecvEvent));

        AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("HIF special overrides : 0x%lX , 0x%lX\n",
                 (unsigned long)pDev->GetPendingEventsFunc, (unsigned long)pDev->HifMaskUmaskRecvEvent));

        status = DevDisableInterrupts(pDev);

        if (status) {
            break;
        }

    } while (false);

    if (status) {
        if (pDev->HifAttached) {
            hif_detach_htc(pDev->HIFDevice);
            pDev->HifAttached = false;
        }
    }

    return status;

}

/* enable device interrupts */
int DevUnmaskInterrupts(struct ar6k_device *pDev)
{
    /* for good measure, make sure interrupt are disabled before unmasking at the HIF
     * layer.
     * The rationale here is that between device insertion (where we clear the interrupts the first time)
     * and when HTC is finally ready to handle interrupts, other software can perform target "soft" resets.
     * The AR6K interrupt enables reset back to an "enabled" state when this happens.
     *  */
    int IntStatus = 0;
    DevDisableInterrupts(pDev);

#ifdef THREAD_X
    // Tobe verified...
    IntStatus = DevEnableInterrupts(pDev);
    /* Unmask the host controller interrupts */
    hif_unmask_interrupt(pDev->HIFDevice);
#else
    /* Unmask the host controller interrupts */
    hif_unmask_interrupt(pDev->HIFDevice);
    IntStatus = DevEnableInterrupts(pDev);
#endif

    return IntStatus;
}

/* disable all device interrupts */
int DevMaskInterrupts(struct ar6k_device *pDev)
{
        /* mask the interrupt at the HIF layer, we don't want a stray interrupt taken while
         * we zero out our shadow registers in DevDisableInterrupts()*/
    hif_mask_interrupt(pDev->HIFDevice);

    return DevDisableInterrupts(pDev);
}

/* callback when our fetch to enable/disable completes */
static void DevDoEnableDisableRecvAsyncHandler(void *Context, struct htc_packet *pPacket)
{
    struct ar6k_device *pDev = (struct ar6k_device *)Context;

    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("+DevDoEnableDisableRecvAsyncHandler: (dev: 0x%lX)\n", (unsigned long)pDev));

    if (pPacket->Status) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
                (" Failed to disable receiver, status:%d \n", pPacket->Status));
    }
        /* free this IO packet */
    AR6KFreeIOPacket(pDev,pPacket);
    AR_DEBUG_PRINTF(ATH_DEBUG_IRQ,("-DevDoEnableDisableRecvAsyncHandler \n"));
}

/* disable packet reception (used in case the host runs out of buffers)
 * this is the "override" method when the HIF reports another methods to
 * disable recv events */
static int DevDoEnableDisableRecvOverride(struct ar6k_device *pDev, bool EnableRecv, bool AsyncMode)
{
    int                  status = 0;
    struct htc_packet                *pIOPacket = NULL;

    AR_DEBUG_PRINTF(ATH_DEBUG_TRC,("DevDoEnableDisableRecvOverride: Enable:%d Mode:%d\n",
            EnableRecv,AsyncMode));

    do {

        if (AsyncMode) {

            pIOPacket = AR6KAllocIOPacket(pDev);

            if (NULL == pIOPacket) {
                status = A_NO_MEMORY;
                A_ASSERT(false);
                break;
            }

                /* stick in our completion routine when the I/O operation completes */
            pIOPacket->Completion = DevDoEnableDisableRecvAsyncHandler;
            pIOPacket->pContext = pDev;

                /* call the HIF layer override and do this asynchronously */
            status = pDev->HifMaskUmaskRecvEvent(pDev->HIFDevice,
                                                 EnableRecv ? HIF_UNMASK_RECV : HIF_MASK_RECV,
                                                 pIOPacket);
            break;
        }

            /* if we get here we are doing it synchronously */
        status = pDev->HifMaskUmaskRecvEvent(pDev->HIFDevice,
                                             EnableRecv ? HIF_UNMASK_RECV : HIF_MASK_RECV,
                                             NULL);

    } while (false);

    if (status && (pIOPacket != NULL)) {
        AR6KFreeIOPacket(pDev,pIOPacket);
    }

    return status;
}

/* disable packet reception (used in case the host runs out of buffers)
 * this is the "normal" method using the interrupt enable registers through
 * the host I/F */
static int DevDoEnableDisableRecvNormal(struct ar6k_device *pDev, bool EnableRecv, bool AsyncMode)
{
    int                  status = 0;
    struct htc_packet                *pIOPacket = NULL;
    struct ar6k_irq_enable_registers regs;

        /* take the lock to protect interrupt enable shadows */
    spin_lock_bh(&pDev->Lock);

    if (EnableRecv) {
        pDev->IrqEnableRegisters.int_status_enable |= INT_STATUS_ENABLE_MBOX_DATA_SET(0x01);
    } else {
        pDev->IrqEnableRegisters.int_status_enable &= ~INT_STATUS_ENABLE_MBOX_DATA_SET(0x01);
    }

        /* copy into our temp area */
    memcpy(&regs,&pDev->IrqEnableRegisters,AR6K_IRQ_ENABLE_REGS_SIZE);
    spin_unlock_bh(&pDev->Lock);

    do {

        if (AsyncMode) {

            pIOPacket = AR6KAllocIOPacket(pDev);

            if (NULL == pIOPacket) {
                status = A_NO_MEMORY;
                A_ASSERT(false);
                break;
            }

                /* copy values to write to our async I/O buffer */
            memcpy(pIOPacket->pBuffer,&regs,AR6K_IRQ_ENABLE_REGS_SIZE);

                /* stick in our completion routine when the I/O operation completes */
            pIOPacket->Completion = DevDoEnableDisableRecvAsyncHandler;
            pIOPacket->pContext = pDev;

                /* write it out asynchronously */
            hif_read_write(pDev->HIFDevice,
                         INT_STATUS_ENABLE_ADDRESS,
                         pIOPacket->pBuffer,
                         AR6K_IRQ_ENABLE_REGS_SIZE,
                         HIF_WR_ASYNC_BYTE_INC,
                         pIOPacket);
            break;
        }

        /* if we get here we are doing it synchronously */

        status = hif_read_write(pDev->HIFDevice,
                              INT_STATUS_ENABLE_ADDRESS,
                              &regs.int_status_enable,
                              AR6K_IRQ_ENABLE_REGS_SIZE,
                              HIF_WR_SYNC_BYTE_INC,
                              NULL);

    } while (false);

    if (status && (pIOPacket != NULL)) {
        AR6KFreeIOPacket(pDev,pIOPacket);
    }

    return status;
}


int DevStopRecv(struct ar6k_device *pDev, bool AsyncMode)
{
    if (NULL == pDev->HifMaskUmaskRecvEvent) {
        return DevDoEnableDisableRecvNormal(pDev,false,AsyncMode);
    } else {
        return DevDoEnableDisableRecvOverride(pDev,false,AsyncMode);
    }
}

int DevEnableRecv(struct ar6k_device *pDev, bool AsyncMode)
{
    if (NULL == pDev->HifMaskUmaskRecvEvent) {
        return DevDoEnableDisableRecvNormal(pDev,true,AsyncMode);
    } else {
        return DevDoEnableDisableRecvOverride(pDev,true,AsyncMode);
    }
}

static void DevDumpRegisters(struct ar6k_device               *pDev,
                      struct ar6k_irq_proc_registers   *pIrqProcRegs,
                      struct ar6k_irq_enable_registers *pIrqEnableRegs)
{

    AR_DEBUG_PRINTF(ATH_DEBUG_ANY, ("\n<------- Register Table -------->\n"));

    if (pIrqProcRegs != NULL) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Host Int Status:           0x%x\n",pIrqProcRegs->host_int_status));
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("CPU Int Status:            0x%x\n",pIrqProcRegs->cpu_int_status));
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Error Int Status:          0x%x\n",pIrqProcRegs->error_int_status));
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Counter Int Status:        0x%x\n",pIrqProcRegs->counter_int_status));
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Mbox Frame:                0x%x\n",pIrqProcRegs->mbox_frame));
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Rx Lookahead Valid:        0x%x\n",pIrqProcRegs->rx_lookahead_valid));
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Rx Lookahead 0:            0x%x\n",pIrqProcRegs->rx_lookahead[0]));
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Rx Lookahead 1:            0x%x\n",pIrqProcRegs->rx_lookahead[1]));

        if (pDev->MailBoxInfo.GMboxAddress != 0) {
                /* if the target supports GMBOX hardware, dump some additional state */
            AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
                ("GMBOX Host Int Status 2:   0x%x\n",pIrqProcRegs->host_int_status2));
            AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
                ("GMBOX RX Avail:            0x%x\n",pIrqProcRegs->gmbox_rx_avail));
            AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
                ("GMBOX lookahead alias 0:   0x%x\n",pIrqProcRegs->rx_gmbox_lookahead_alias[0]));
            AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
                ("GMBOX lookahead alias 1:   0x%x\n",pIrqProcRegs->rx_gmbox_lookahead_alias[1]));
        }

    }

    if (pIrqEnableRegs != NULL) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Int Status Enable:         0x%x\n",pIrqEnableRegs->int_status_enable));
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("Counter Int Status Enable: 0x%x\n",pIrqEnableRegs->counter_int_status_enable));
    }
    AR_DEBUG_PRINTF(ATH_DEBUG_ANY, ("<------------------------------->\n"));
}


#define DEV_GET_VIRT_DMA_INFO(p)  ((struct dev_scatter_dma_virtual_info *)((p)->HIFPrivate[0]))

static void DevFreeScatterReq(struct hif_device *Context, struct hif_scatter_req *pReq)
{
    struct ar6k_device *pDev = (struct ar6k_device *)Context;
    spin_lock_bh(&pDev->Lock);
    DL_ListInsertTail(&pDev->ScatterReqHead, &pReq->ListLink);
    spin_unlock_bh(&pDev->Lock);
}

int DevCopyScatterListToFromDMABuffer(struct hif_scatter_req *pReq, bool FromDMA)
{
    u8 *pDMABuffer = NULL;
    int             i, remaining;
    u32 length;

    pDMABuffer = pReq->pScatterBounceBuffer;

    if (pDMABuffer == NULL) {
        A_ASSERT(false);
        return A_EINVAL;
    }

    remaining = (int)pReq->TotalLength;

    for (i = 0; i < pReq->ValidScatterEntries; i++) {

        length = min((int)pReq->ScatterList[i].Length, remaining);

        if (length != (int)pReq->ScatterList[i].Length) {
            A_ASSERT(false);
                /* there is a problem with the scatter list */
            return A_EINVAL;
        }

        if (FromDMA) {
                /* from DMA buffer */
            memcpy(pReq->ScatterList[i].pBuffer, pDMABuffer , length);
        } else {
                /* to DMA buffer */
            memcpy(pDMABuffer, pReq->ScatterList[i].pBuffer, length);
        }

        pDMABuffer += length;
        remaining -= length;
    }

    return 0;
}

static void DevReadWriteScatterAsyncHandler(void *Context, struct htc_packet *pPacket)
{
    struct ar6k_device     *pDev = (struct ar6k_device *)Context;
    struct hif_scatter_req *pReq = (struct hif_scatter_req *)pPacket->pPktContext;
    
    AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("+DevReadWriteScatterAsyncHandler: (dev: 0x%lX)\n", (unsigned long)pDev));
    
    pReq->CompletionStatus = pPacket->Status;

    AR6KFreeIOPacket(pDev,pPacket);

    pReq->CompletionRoutine(pReq);

    AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("-DevReadWriteScatterAsyncHandler \n"));
}

static int DevReadWriteScatter(struct hif_device *Context, struct hif_scatter_req *pReq)
{
    struct ar6k_device     *pDev = (struct ar6k_device *)Context;
    int        status = 0;
    struct htc_packet      *pIOPacket = NULL;
    u32 request = pReq->Request;

    do {

        if (pReq->TotalLength > AR6K_MAX_TRANSFER_SIZE_PER_SCATTER) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
                            ("Invalid length: %d \n", pReq->TotalLength));
            break;
        }

        if (pReq->TotalLength == 0) {
            A_ASSERT(false);
            break;
        }

        if (request & HIF_ASYNCHRONOUS) {
                /* use an I/O packet to carry this request */
            pIOPacket = AR6KAllocIOPacket(pDev);
            if (NULL == pIOPacket) {
                status = A_NO_MEMORY;
                break;
            }

                /* save the request */
            pIOPacket->pPktContext = pReq;
                /* stick in our completion routine when the I/O operation completes */
            pIOPacket->Completion = DevReadWriteScatterAsyncHandler;
            pIOPacket->pContext = pDev;
        }

        if (request & HIF_WRITE) {
            /* in virtual DMA, we are issuing the requests through the legacy hif_read_write API
             * this API will adjust the address automatically for the last byte to fall on the mailbox
             * EOM. */

            /* if the address is an extended address, we can adjust the address here since the extended
             * address will bypass the normal checks in legacy HIF layers */
            if (pReq->Address == pDev->MailBoxInfo.MboxProp[HTC_MAILBOX].ExtendedAddress) {
                pReq->Address += pDev->MailBoxInfo.MboxProp[HTC_MAILBOX].ExtendedSize - pReq->TotalLength;
            }
        }

            /* use legacy readwrite */
        status = hif_read_write(pDev->HIFDevice,
                              pReq->Address,
                              DEV_GET_VIRT_DMA_INFO(pReq)->pVirtDmaBuffer,
                              pReq->TotalLength,
                              request,
                              (request & HIF_ASYNCHRONOUS) ? pIOPacket : NULL);

    } while (false);

    if ((status != A_PENDING) && status && (request & HIF_ASYNCHRONOUS)) {
        if (pIOPacket != NULL) {
            AR6KFreeIOPacket(pDev,pIOPacket);
        }
        pReq->CompletionStatus = status;
        pReq->CompletionRoutine(pReq);
        status = 0;
    }

    return status;
}

    /* function to set up virtual scatter support if HIF layer has not implemented the interface */
static int DevSetupVirtualScatterSupport(struct ar6k_device *pDev)
{
    int                     status = 0;
    int                          bufferSize, sgreqSize;
    int                          i;
    struct dev_scatter_dma_virtual_info *pVirtualInfo;
    struct hif_scatter_req              *pReq;

    bufferSize = sizeof(struct dev_scatter_dma_virtual_info) +
                2 * (L1_CACHE_BYTES) + AR6K_MAX_TRANSFER_SIZE_PER_SCATTER;

    sgreqSize = sizeof(struct hif_scatter_req) +
                    (AR6K_SCATTER_ENTRIES_PER_REQ - 1) * (sizeof(struct hif_scatter_item));

    for (i = 0; i < AR6K_SCATTER_REQS; i++) {
            /* allocate the scatter request, buffer info and the actual virtual buffer itself */
        pReq = (struct hif_scatter_req *)kzalloc(sgreqSize + bufferSize, GFP_KERNEL);

        if (NULL == pReq) {
            status = A_NO_MEMORY;
            break;
        }

        memset(pReq, 0, sgreqSize);

            /* the virtual DMA starts after the scatter request struct */
        pVirtualInfo = (struct dev_scatter_dma_virtual_info *)((u8 *)pReq + sgreqSize);
        memset(pVirtualInfo, 0, sizeof(struct dev_scatter_dma_virtual_info));

        pVirtualInfo->pVirtDmaBuffer = &pVirtualInfo->DataArea[0];
            /* align buffer to cache line in case host controller can actually DMA this */
        pVirtualInfo->pVirtDmaBuffer = (void *)L1_CACHE_ALIGN((unsigned long)pVirtualInfo->pVirtDmaBuffer);
            /* store the structure in the private area */
        pReq->HIFPrivate[0] = pVirtualInfo;
            /* we emulate a DMA bounce interface */
        pReq->ScatterMethod = HIF_SCATTER_DMA_BOUNCE;
        pReq->pScatterBounceBuffer = pVirtualInfo->pVirtDmaBuffer;
            /* free request to the list */
        DevFreeScatterReq((struct hif_device *)pDev,pReq);
    }

    if (status) {
        DevCleanupVirtualScatterSupport(pDev);
    } else {
        pDev->HifScatterInfo.pAllocateReqFunc = DevAllocScatterReq;
        pDev->HifScatterInfo.pFreeReqFunc = DevFreeScatterReq;
        pDev->HifScatterInfo.pReadWriteScatterFunc = DevReadWriteScatter;
        if (pDev->MailBoxInfo.MboxBusIFType == MBOX_BUS_IF_SPI) {
            AR_DEBUG_PRINTF(ATH_DEBUG_WARN, ("AR6K: SPI bus requires RX scatter limits\n"));
            pDev->HifScatterInfo.MaxScatterEntries = AR6K_MIN_SCATTER_ENTRIES_PER_REQ;
            pDev->HifScatterInfo.MaxTransferSizePerScatterReq = AR6K_MIN_TRANSFER_SIZE_PER_SCATTER;
        } else {
            pDev->HifScatterInfo.MaxScatterEntries = AR6K_SCATTER_ENTRIES_PER_REQ;
            pDev->HifScatterInfo.MaxTransferSizePerScatterReq = AR6K_MAX_TRANSFER_SIZE_PER_SCATTER;
        }
        pDev->ScatterIsVirtual = true;
    }

    return status;
}

int DevCleanupMsgBundling(struct ar6k_device *pDev)
{
    if(NULL != pDev)
    {
        DevCleanupVirtualScatterSupport(pDev);
    }

    return 0;
}

int DevSetupMsgBundling(struct ar6k_device *pDev, int MaxMsgsPerTransfer)
{
    int status;

    if (pDev->MailBoxInfo.Flags & HIF_MBOX_FLAG_NO_BUNDLING) {
        AR_DEBUG_PRINTF(ATH_DEBUG_WARN, ("HIF requires bundling disabled\n"));
        return A_ENOTSUP;
    }

    status = hif_config_dev(pDev->HIFDevice,
                                HIF_CONFIGURE_QUERY_SCATTER_REQUEST_SUPPORT,
                                &pDev->HifScatterInfo,
                                sizeof(pDev->HifScatterInfo));

    if (status) {
        AR_DEBUG_PRINTF(ATH_DEBUG_WARN,
            ("AR6K: ** HIF layer does not support scatter requests (%d) \n",status));

            /* we can try to use a virtual DMA scatter mechanism using legacy hif_read_write() */
        status = DevSetupVirtualScatterSupport(pDev);

        if (!status) {
             AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
                ("AR6K: virtual scatter transfers enabled (max scatter items:%d: maxlen:%d) \n",
                    DEV_GET_MAX_MSG_PER_BUNDLE(pDev), DEV_GET_MAX_BUNDLE_LENGTH(pDev)));
        }

    } else {
        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("AR6K: HIF layer supports scatter requests (max scatter items:%d: maxlen:%d) \n",
                    DEV_GET_MAX_MSG_PER_BUNDLE(pDev), DEV_GET_MAX_BUNDLE_LENGTH(pDev)));
    }

    if (!status) {
            /* for the recv path, the maximum number of bytes per recv bundle is just limited
             * by the maximum transfer size at the HIF layer */
        pDev->MaxRecvBundleSize = pDev->HifScatterInfo.MaxTransferSizePerScatterReq;

        if (pDev->MailBoxInfo.MboxBusIFType == MBOX_BUS_IF_SPI) {
            AR_DEBUG_PRINTF(ATH_DEBUG_WARN, ("AR6K : SPI bus requires TX bundling disabled\n"));
            pDev->MaxSendBundleSize = 0;
        } else {
                /* for the send path, the max transfer size is limited by the existence and size of
                 * the extended mailbox address range */
            if (pDev->MailBoxInfo.MboxProp[0].ExtendedAddress != 0) {
                pDev->MaxSendBundleSize = pDev->MailBoxInfo.MboxProp[0].ExtendedSize;
            } else {
                    /* legacy */
                pDev->MaxSendBundleSize = AR6K_LEGACY_MAX_WRITE_LENGTH;
            }

            if (pDev->MaxSendBundleSize > pDev->HifScatterInfo.MaxTransferSizePerScatterReq) {
                    /* limit send bundle size to what the HIF can support for scatter requests */
                pDev->MaxSendBundleSize = pDev->HifScatterInfo.MaxTransferSizePerScatterReq;
            }
        }

        AR_DEBUG_PRINTF(ATH_DEBUG_ANY,
            ("AR6K: max recv: %d max send: %d \n",
                    DEV_GET_MAX_BUNDLE_RECV_LENGTH(pDev), DEV_GET_MAX_BUNDLE_SEND_LENGTH(pDev)));

    }
    return status;
}

int DevSubmitScatterRequest(struct ar6k_device *pDev, struct hif_scatter_req *pScatterReq, bool Read, bool Async)
{
    int status;

    if (Read) {
            /* read operation */
        pScatterReq->Request = (Async) ? HIF_RD_ASYNC_BLOCK_FIX : HIF_RD_SYNC_BLOCK_FIX;
        pScatterReq->Address = pDev->MailBoxInfo.MboxAddresses[HTC_MAILBOX];
        A_ASSERT(pScatterReq->TotalLength <= (u32)DEV_GET_MAX_BUNDLE_RECV_LENGTH(pDev));
    } else {
        u32 mailboxWidth;

            /* write operation */
        pScatterReq->Request = (Async) ? HIF_WR_ASYNC_BLOCK_INC : HIF_WR_SYNC_BLOCK_INC;
        A_ASSERT(pScatterReq->TotalLength <= (u32)DEV_GET_MAX_BUNDLE_SEND_LENGTH(pDev));
        if (pScatterReq->TotalLength > AR6K_LEGACY_MAX_WRITE_LENGTH) {
                /* for large writes use the extended address */
            pScatterReq->Address = pDev->MailBoxInfo.MboxProp[HTC_MAILBOX].ExtendedAddress;
            mailboxWidth = pDev->MailBoxInfo.MboxProp[HTC_MAILBOX].ExtendedSize;
        } else {
            pScatterReq->Address = pDev->MailBoxInfo.MboxAddresses[HTC_MAILBOX];
            mailboxWidth = AR6K_LEGACY_MAX_WRITE_LENGTH;
        }

        if (!pDev->ScatterIsVirtual) {
            /* we are passing this scatter list down to the HIF layer' scatter request handler, fixup the address
             * so that the last byte falls on the EOM, we do this for those HIFs that support the
             * scatter API */
            pScatterReq->Address += (mailboxWidth - pScatterReq->TotalLength);
        }

    }

    AR_DEBUG_PRINTF(ATH_DEBUG_RECV | ATH_DEBUG_SEND,
                ("DevSubmitScatterRequest, Entries: %d, Total Length: %d Mbox:0x%X (mode: %s : %s)\n",
                pScatterReq->ValidScatterEntries,
                pScatterReq->TotalLength,
                pScatterReq->Address,
                Async ? "ASYNC" : "SYNC",
                (Read) ? "RD" : "WR"));

    status = DEV_PREPARE_SCATTER_OPERATION(pScatterReq);

    if (status) {
        if (Async) {
            pScatterReq->CompletionStatus = status;
            pScatterReq->CompletionRoutine(pScatterReq);
            return 0;
        }
        return status;
    }

    status = pDev->HifScatterInfo.pReadWriteScatterFunc(pDev->ScatterIsVirtual ? pDev : pDev->HIFDevice,
                                                        pScatterReq);
    if (!Async) {
            /* in sync mode, we can touch the scatter request */
        pScatterReq->CompletionStatus = status;
        DEV_FINISH_SCATTER_OPERATION(pScatterReq);
    } else {
        if (status == A_PENDING) {
            status = 0;
        }
    }

    return status;
}
