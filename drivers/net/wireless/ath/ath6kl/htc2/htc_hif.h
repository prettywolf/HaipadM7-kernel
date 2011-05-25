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

#ifndef HTC_HIF_H
#define HTC_HIF_H 

#include "htc_debug.h"
#include "htc.h"

#define AR6K_MAILBOXES 4

/* HTC runs over mailbox 0 */
#define HTC_MAILBOX          0

#define AR6K_TARGET_DEBUG_INTR_MASK     0x01

#define OTHER_INTS_ENABLED (INT_STATUS_ENABLE_ERROR_MASK |   \
                            INT_STATUS_ENABLE_CPU_MASK   |   \
                            INT_STATUS_ENABLE_COUNTER_MASK)


struct ar6k_irq_proc_registers {
	u8 host_int_status;
	u8 cpu_int_status;
	u8 error_int_status;
	u8 counter_int_status;
	u8 mbox_frame;
	u8 rx_lookahead_valid;
	u8 host_int_status2;
	u8 gmbox_rx_avail;
	u32 rx_lookahead[2];
	u32 rx_gmbox_lookahead_alias[2];
} __attribute__ ((packed));

#define AR6K_IRQ_PROC_REGS_SIZE sizeof(struct ar6k_irq_proc_registers)

struct ar6k_irq_enable_registers {
	u8 int_status_enable;
	u8 cpu_int_status_enable;
	u8 error_status_enable;
	u8 counter_int_status_enable;
} __attribute__ ((packed));

#define AR6K_IRQ_ENABLE_REGS_SIZE sizeof(struct ar6k_irq_enable_registers)

#define AR6K_REG_IO_BUFFER_SIZE     32
#define AR6K_MAX_REG_IO_BUFFERS     8
#define FROM_DMA_BUFFER true
#define TO_DMA_BUFFER   false
#define AR6K_SCATTER_ENTRIES_PER_REQ            16
#define AR6K_MAX_TRANSFER_SIZE_PER_SCATTER      16*1024
#define AR6K_SCATTER_REQS                       4
#define AR6K_LEGACY_MAX_WRITE_LENGTH            2048

#ifndef A_CACHE_LINE_PAD
#define A_CACHE_LINE_PAD                        128
#endif
#define AR6K_MIN_SCATTER_ENTRIES_PER_REQ        2
#define AR6K_MIN_TRANSFER_SIZE_PER_SCATTER      4*1024

/* buffers for ASYNC I/O */
struct ar6k_async_reg_io_buffer {
	struct htc_packet    HtcPacket;   /* we use an HTC packet as a wrapper for our async register-based I/O */
	u8 _Pad1[A_CACHE_LINE_PAD];
	u8 Buffer[AR6K_REG_IO_BUFFER_SIZE];  /* cache-line safe with pads around */
	u8 _Pad2[A_CACHE_LINE_PAD];
};

struct ar6k_device {
	spinlock_t                   Lock;
	u8 _Pad1[A_CACHE_LINE_PAD];
	struct ar6k_irq_proc_registers     IrqProcRegisters;   /* cache-line safe with pads around */
	u8 _Pad2[A_CACHE_LINE_PAD];
	struct ar6k_irq_enable_registers   IrqEnableRegisters; /* cache-line safe with pads around */
	u8 _Pad3[A_CACHE_LINE_PAD];
	void                        *HIFDevice;
	u32 BlockSize;
	u32 BlockMask;
	struct hif_device_mbox_info        MailBoxInfo;
	HIF_PENDING_EVENTS_FUNC     GetPendingEventsFunc;
	void                        *HTCContext;
	struct htc_packet_queue            RegisterIOList;
	struct ar6k_async_reg_io_buffer    RegIOBuffers[AR6K_MAX_REG_IO_BUFFERS];
	void                        (*TargetFailureCallback)(void *Context);
	int                    (*MessagePendingCallback)(void *Context,
			u32 LookAheads[],
			int NumLookAheads, 
			bool *pAsyncProc,
			int *pNumPktsFetched);
	HIF_DEVICE_IRQ_PROCESSING_MODE  HifIRQProcessingMode;
	HIF_MASK_UNMASK_RECV_EVENT      HifMaskUmaskRecvEvent;
	bool                          HifAttached;
	struct hif_device_irq_yield_params     HifIRQYieldParams;
	bool                          DSRCanYield;
	int                             CurrentDSRRecvCount;
	struct hif_device_scatter_support_info HifScatterInfo;
	struct dl_list                         ScatterReqHead; 
	bool                          ScatterIsVirtual;
	int                             MaxRecvBundleSize;
	int                             MaxSendBundleSize;
	int                             RecheckIRQStatusCnt;
};

#define REF_IRQ_STATUS_RECHECK(p) (p)->RecheckIRQStatusCnt = 1  /* note: no need to lock this, it only gets set */

int DevSetup(struct ar6k_device *pDev);
void     DevCleanup(struct ar6k_device *pDev);
int DevUnmaskInterrupts(struct ar6k_device *pDev);
int DevMaskInterrupts(struct ar6k_device *pDev);
int DevPollMboxMsgRecv(struct ar6k_device *pDev,
		u32 *pLookAhead,
		int          TimeoutMS);
int DevCheckPendingRecvMsgsAsync(void *context);
void     DevAsyncIrqProcessComplete(struct ar6k_device *pDev);
int DevStopRecv(struct ar6k_device *pDev, bool ASyncMode);
int DevEnableRecv(struct ar6k_device *pDev, bool ASyncMode);
int DevDisableInterrupts(struct ar6k_device *pDev);

#define DEV_IS_LEN_BLOCK_ALIGNED(pDev, length) (((length) % (pDev)->BlockSize) == 0)



#define DEV_CHECK_RECV_YIELD(pDev) \
	((pDev)->CurrentDSRRecvCount >= (pDev)->HifIRQYieldParams.RecvPacketYieldCount)

#define IS_DEV_IRQ_PROC_SYNC_MODE(pDev) (HIF_DEVICE_IRQ_SYNC_ONLY == (pDev)->HifIRQProcessingMode)
#define IS_DEV_IRQ_PROCESSING_ASYNC_ALLOWED(pDev) ((pDev)->HifIRQProcessingMode != HIF_DEVICE_IRQ_SYNC_ONLY)

/**************************************************/
/****** Scatter Function and Definitions
 * 
 *  
 */

int DevCopyScatterListToFromDMABuffer(struct hif_scatter_req *pReq, bool FromDMA);

/* copy any READ data back into scatter list */        
#define DEV_FINISH_SCATTER_OPERATION(pR)				\
	do {									\
		if (!((pR)->CompletionStatus) &&				\
				!((pR)->Request & HIF_WRITE) &&				\
				((pR)->ScatterMethod == HIF_SCATTER_DMA_BOUNCE)) {		\
			(pR)->CompletionStatus =				\
			DevCopyScatterListToFromDMABuffer((pR),		\
					FROM_DMA_BUFFER); \
		}								\
	} while (0)

/* copy any WRITE data to bounce buffer */
static inline int DEV_PREPARE_SCATTER_OPERATION(struct hif_scatter_req *pReq)  {
	if ((pReq->Request & HIF_WRITE) && (pReq->ScatterMethod == HIF_SCATTER_DMA_BOUNCE)) {
		return DevCopyScatterListToFromDMABuffer(pReq,TO_DMA_BUFFER);    
	} else {
		return 0;
	}
}


int DevSetupMsgBundling(struct ar6k_device *pDev, int MaxMsgsPerTransfer);

int DevCleanupMsgBundling(struct ar6k_device *pDev);

#define DEV_GET_MAX_MSG_PER_BUNDLE(pDev)        (pDev)->HifScatterInfo.MaxScatterEntries
#define DEV_GET_MAX_BUNDLE_LENGTH(pDev)         (pDev)->HifScatterInfo.MaxTransferSizePerScatterReq
#define DEV_ALLOC_SCATTER_REQ(pDev)             \
	(pDev)->HifScatterInfo.pAllocateReqFunc((pDev)->ScatterIsVirtual ? (pDev) : (pDev)->HIFDevice)

#define DEV_FREE_SCATTER_REQ(pDev,pR)           \
	(pDev)->HifScatterInfo.pFreeReqFunc((pDev)->ScatterIsVirtual ? (pDev) : (pDev)->HIFDevice,(pR))

#define DEV_GET_MAX_BUNDLE_RECV_LENGTH(pDev)   (pDev)->MaxRecvBundleSize
#define DEV_GET_MAX_BUNDLE_SEND_LENGTH(pDev)   (pDev)->MaxSendBundleSize

int DevSubmitScatterRequest(struct ar6k_device *pDev, struct hif_scatter_req *pScatterReq, bool Read, bool Async);

/* completely virtual */
struct dev_scatter_dma_virtual_info {
	u8 *pVirtDmaBuffer;      /* dma-able buffer - CPU accessible address */
	u8 DataArea[1];      /* start of data area */
};

void     DumpAR6KDevState(struct ar6k_device *pDev);

#endif /*AR6K_H_*/
