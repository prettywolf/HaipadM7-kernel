//------------------------------------------------------------------------------
// <copyright file="bmi.c" company="Atheros">
//    Copyright (c) 2004-2010 Atheros Corporation.  All rights reserved.
// 
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
//
//------------------------------------------------------------------------------
//==============================================================================
//
// Author(s): ="Atheros"
//==============================================================================

#include <ath6kl.h>
#include <bmi.h>
#include <htc.h>
#include <reg.h>
#include <a_debug.h>

bool bmiDone;

/*
Although we had envisioned BMI to run on top of HTC, this is not how the
final implementation ended up. On the Target side, BMI is a part of the BSP
and does not use the HTC protocol nor even DMA -- it is intentionally kept
very simple.
*/

static bool pendingEventsFuncCheck = false;
static u32 *pBMICmdCredits;
static u8 *pBMICmdBuf;
#define MAX_BMI_CMDBUF_SZ (BMI_DATASZ_MAX + \
                       sizeof(u32) /* cmd */ + \
                       sizeof(u32) /* addr */ + \
                       sizeof(u32))/* length */
#define BMI_COMMAND_FITS(sz) ((sz) <= MAX_BMI_CMDBUF_SZ)
    
/* APIs visible to the driver */
void
bmi_init(void)
{
    bmiDone = false;
    pendingEventsFuncCheck = false;

    /*
     * On some platforms, it's not possible to DMA to a static variable
     * in a device driver (e.g. Linux loadable driver module).
     * So we need to A_MALLOC space for "command credits" and for commands.
     *
     * Note: implicitly relies on A_MALLOC to provide a buffer that is
     * suitable for DMA (or PIO).  This buffer will be passed down the
     * bus stack.
     */
    if (!pBMICmdCredits) {
        pBMICmdCredits = (u32 *)kzalloc(4, GFP_ATOMIC);
        A_ASSERT(pBMICmdCredits);
    }

    if (!pBMICmdBuf) {
        pBMICmdBuf = (u8 *)kzalloc(MAX_BMI_CMDBUF_SZ, GFP_ATOMIC);
        A_ASSERT(pBMICmdBuf);
    }
    
}

void
bmi_cleanup(void)
{
    if (pBMICmdCredits) {
        kfree(pBMICmdCredits);
        pBMICmdCredits = NULL;
    }

    if (pBMICmdBuf) {
        kfree(pBMICmdBuf);
        pBMICmdBuf = NULL;
    }
}

int
bmi_done(struct hif_device *device)
{
    int status;
    u32 cid;

    if (bmiDone) {
        /*ath_dbg(ATH_DBG_BMI, "bmi done skipped\n");*/
        return 0;
    }

    bmiDone = true;
    cid = BMI_DONE;

    status = bmi_send_buf(device, (u8 *)&cid, sizeof(cid));
    if (status) {
        ath_err("unable to write to the device\n");
        return A_ERROR;
    }

    if (pBMICmdCredits) {
        kfree(pBMICmdCredits);
        pBMICmdCredits = NULL;
    }

    if (pBMICmdBuf) {
        kfree(pBMICmdBuf);
        pBMICmdBuf = NULL;
    }

    return 0;
}

int
bmi_get_target_info(struct hif_device *device, struct bmi_target_info *targ_info)
{
    int status;
    u32 cid;

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    cid = BMI_GET_TARGET_INFO;

    status = bmi_send_buf(device, (u8 *)&cid, sizeof(cid));
    if (status) {
        ath_err("unable to write to the device\n");
        return A_ERROR;
    }

    status = bmi_recv_buf(device, (u8 *)&targ_info->target_ver,
                                                sizeof(targ_info->target_ver), true);
    if (status) {
        ath_err("unable to read target version\n");
        return A_ERROR;
    }

    if (targ_info->target_ver == TARGET_VERSION_SENTINAL) {
        /* Determine how many bytes are in the Target's targ_info */
        status = bmi_recv_buf(device, (u8 *)&targ_info->target_info_byte_count,
                                            sizeof(targ_info->target_info_byte_count), true);
        if (status) {
            ath_err("unable to read target info byte count\n");
            return A_ERROR;
        }

        /*
         * The Target's targ_info doesn't match the Host's targ_info.
         * We need to do some backwards compatibility work to make this OK.
         */
        A_ASSERT(targ_info->target_info_byte_count == sizeof(*targ_info));

        /* Read the remainder of the targ_info */
        status = bmi_recv_buf(device,
                        ((u8 *)targ_info)+sizeof(targ_info->target_info_byte_count),
                        sizeof(*targ_info)-sizeof(targ_info->target_info_byte_count), true);
        if (status) {
            ath_err("unable to read target info (%d bytes)\n",
                        targ_info->target_info_byte_count);
            return A_ERROR;
        }
    }

    /*ath_dbg(ATH_DBG_BMI, "target info (ver: 0x%x type: 0x%x)\n",
	    targ_info->target_ver, targ_info->target_type);
*/
    return 0;
}

int
bmi_read_memory(struct hif_device *device,
              u32 address,
              u8 *buffer,
              u32 length)
{
    u32 cid;
    int status;
    u32 offset;
    u32 remaining, rxlen;

    A_ASSERT(BMI_COMMAND_FITS(BMI_DATASZ_MAX + sizeof(cid) + sizeof(address) + sizeof(length)));
    memset (pBMICmdBuf, 0, BMI_DATASZ_MAX + sizeof(cid) + sizeof(address) + sizeof(length));

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    /*ath_dbg(ATH_DBG_BMI, "bmi read memory: device: 0x%p, address: 0x%x, length: %d)\n",
	    device, address, length);
	*/
    cid = BMI_READ_MEMORY;

    remaining = length;

    while (remaining)
    {
        rxlen = (remaining < BMI_DATASZ_MAX) ? remaining : BMI_DATASZ_MAX;
        offset = 0;
        memcpy(&(pBMICmdBuf[offset]), &cid, sizeof(cid));
        offset += sizeof(cid);
        memcpy(&(pBMICmdBuf[offset]), &address, sizeof(address));
        offset += sizeof(address);
        memcpy(&(pBMICmdBuf[offset]), &rxlen, sizeof(rxlen));
        offset += sizeof(length);

        status = bmi_send_buf(device, pBMICmdBuf, offset);
        if (status) {
            ath_err("unable to write to the device\n");
            return A_ERROR;
        }
        status = bmi_recv_buf(device, pBMICmdBuf, rxlen, true);
        if (status) {
            ath_err("unable to read from the device\n");
            return A_ERROR;
        }
        memcpy(&buffer[length - remaining], pBMICmdBuf, rxlen);
        remaining -= rxlen; address += rxlen;
    }

    return 0;
}

int
bmi_write_memory(struct hif_device *device,
               u32 address,
               u8 *buffer,
               u32 length)
{
    u32 cid;
    int status;
    u32 offset;
    u32 remaining, txlen;
    const u32 header = sizeof(cid) + sizeof(address) + sizeof(length);
    u8 alignedBuffer[BMI_DATASZ_MAX];
    u8 *src;

    A_ASSERT(BMI_COMMAND_FITS(BMI_DATASZ_MAX + header));
    memset (pBMICmdBuf, 0, BMI_DATASZ_MAX + header);

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    /*ath_dbg(ATH_DBG_BMI, "bmi write memory: device: 0x%p, address: 0x%x, length: %d)\n",
	    device, address, length);
	*/
	
    cid = BMI_WRITE_MEMORY;

    remaining = length;
    while (remaining)
    {
        src = &buffer[length - remaining];
        if (remaining < (BMI_DATASZ_MAX - header)) {
            if (remaining & 3) {
                /* align it with 4 bytes */
                remaining = remaining + (4 - (remaining & 3));
                memcpy(alignedBuffer, src, remaining);
                src = alignedBuffer;
            } 
            txlen = remaining;
        } else {
            txlen = (BMI_DATASZ_MAX - header);
        }
        offset = 0;
        memcpy(&(pBMICmdBuf[offset]), &cid, sizeof(cid));
        offset += sizeof(cid);
        memcpy(&(pBMICmdBuf[offset]), &address, sizeof(address));
        offset += sizeof(address);
        memcpy(&(pBMICmdBuf[offset]), &txlen, sizeof(txlen));
        offset += sizeof(txlen);
        memcpy(&(pBMICmdBuf[offset]), src, txlen);
        offset += txlen;
        status = bmi_send_buf(device, pBMICmdBuf, offset);
        if (status) {
            ath_err("unable to write to the device\n");
            return A_ERROR;
        }
        remaining -= txlen; address += txlen;
    }

    return 0;
}

int
bmi_execute(struct hif_device *device,
           u32 address,
           u32 *param)
{
    u32 cid;
    int status;
    u32 offset;

    A_ASSERT(BMI_COMMAND_FITS(sizeof(cid) + sizeof(address) + sizeof(param)));
    memset (pBMICmdBuf, 0, sizeof(cid) + sizeof(address) + sizeof(param));

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    /*ath_dbg(ATH_DBG_BMI, "bmi execute: device: 0x%p, address: 0x%x, param: %d)\n",
	    device, address, *param);
	*/
    cid = BMI_EXECUTE;

    offset = 0;
    memcpy(&(pBMICmdBuf[offset]), &cid, sizeof(cid));
    offset += sizeof(cid);
    memcpy(&(pBMICmdBuf[offset]), &address, sizeof(address));
    offset += sizeof(address);
    memcpy(&(pBMICmdBuf[offset]), param, sizeof(*param));
    offset += sizeof(*param);
    status = bmi_send_buf(device, pBMICmdBuf, offset);
    if (status) {
        ath_err("unable to write to the device\n");
        return A_ERROR;
    }

    status = bmi_recv_buf(device, pBMICmdBuf, sizeof(*param), false);
    if (status) {
        ath_err("unable to read from the device\n");
        return A_ERROR;
    }

    memcpy(param, pBMICmdBuf, sizeof(*param));

    return 0;
}

int
bmi_set_app_start(struct hif_device *device,
               u32 address)
{
    u32 cid;
    int status;
    u32 offset;

    A_ASSERT(BMI_COMMAND_FITS(sizeof(cid) + sizeof(address)));
    memset (pBMICmdBuf, 0, sizeof(cid) + sizeof(address));

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    /*ath_dbg(ATH_DBG_BMI, "bmi set app start: device: 0x%p, address: 0x%x)\n",
	    device, address);
	*/
    cid = BMI_SET_APP_START;

    offset = 0;
    memcpy(&(pBMICmdBuf[offset]), &cid, sizeof(cid));
    offset += sizeof(cid);
    memcpy(&(pBMICmdBuf[offset]), &address, sizeof(address));
    offset += sizeof(address);
    status = bmi_send_buf(device, pBMICmdBuf, offset);
    if (status) {
        ath_err("unable to write to the device\n");
        return A_ERROR;
    }

    return 0;
}

int
bmi_read_soc_register(struct hif_device *device,
                   u32 address,
                   u32 *param)
{
    u32 cid;
    int status;
    u32 offset;

    A_ASSERT(BMI_COMMAND_FITS(sizeof(cid) + sizeof(address)));
    memset (pBMICmdBuf, 0, sizeof(cid) + sizeof(address));

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    /*ath_dbg(ATH_DBG_BMI, "bmi read SOC reg: device: 0x%p, address: 0x%x)\n",
	    device, address);
	*/
    cid = BMI_READ_SOC_REGISTER;

    offset = 0;
    memcpy(&(pBMICmdBuf[offset]), &cid, sizeof(cid));
    offset += sizeof(cid);
    memcpy(&(pBMICmdBuf[offset]), &address, sizeof(address));
    offset += sizeof(address);

    status = bmi_send_buf(device, pBMICmdBuf, offset);
    if (status) {
        ath_err("unable to write to the device\n");
        return A_ERROR;
    }

    status = bmi_recv_buf(device, pBMICmdBuf, sizeof(*param), true);
    if (status) {
        ath_err("unable to read from the device\n");
        return A_ERROR;
    }
    memcpy(param, pBMICmdBuf, sizeof(*param));

    return 0;
}

int
bmi_write_soc_register(struct hif_device *device,
                    u32 address,
                    u32 param)
{
    u32 cid;
    int status;
    u32 offset;

    A_ASSERT(BMI_COMMAND_FITS(sizeof(cid) + sizeof(address) + sizeof(param)));
    memset (pBMICmdBuf, 0, sizeof(cid) + sizeof(address) + sizeof(param));

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    /*ath_dbg(ATH_DBG_BMI, "bmi write SOC reg: device: 0x%p, address: 0x%x, param: %d)\n",
	    device, address, param);
	*/
    cid = BMI_WRITE_SOC_REGISTER;

    offset = 0;
    memcpy(&(pBMICmdBuf[offset]), &cid, sizeof(cid));
    offset += sizeof(cid);
    memcpy(&(pBMICmdBuf[offset]), &address, sizeof(address));
    offset += sizeof(address);
    memcpy(&(pBMICmdBuf[offset]), &param, sizeof(param));
    offset += sizeof(param);
    status = bmi_send_buf(device, pBMICmdBuf, offset);
    if (status) {
        ath_err("unable to write to the device\n");
        return A_ERROR;
    }

    return 0;
}

int
bmi_lz_data(struct hif_device *device,
          u8 *buffer,
          u32 length)
{
    u32 cid;
    int status;
    u32 offset;
    u32 remaining, txlen;
    const u32 header = sizeof(cid) + sizeof(length);

    A_ASSERT(BMI_COMMAND_FITS(BMI_DATASZ_MAX+header));
    memset (pBMICmdBuf, 0, BMI_DATASZ_MAX+header);

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    /*ath_dbg(ATH_DBG_BMI, "bmi send LZ data: device: 0x%p, length: %d)\n",
            device, length);
*/
    cid = BMI_LZ_DATA;

    remaining = length;
    while (remaining)
    {
        txlen = (remaining < (BMI_DATASZ_MAX - header)) ?
                                       remaining : (BMI_DATASZ_MAX - header);
        offset = 0;
        memcpy(&(pBMICmdBuf[offset]), &cid, sizeof(cid));
        offset += sizeof(cid);
        memcpy(&(pBMICmdBuf[offset]), &txlen, sizeof(txlen));
        offset += sizeof(txlen);
        memcpy(&(pBMICmdBuf[offset]), &buffer[length - remaining], txlen);
        offset += txlen;
        status = bmi_send_buf(device, pBMICmdBuf, offset);
        if (status) {
            ath_err("unable to write to the device\n");
            return A_ERROR;
        }
        remaining -= txlen;
    }

    return 0;
}

int
bmi_lz_stream_start(struct hif_device *device,
                 u32 address)
{
    u32 cid;
    int status;
    u32 offset;

    A_ASSERT(BMI_COMMAND_FITS(sizeof(cid) + sizeof(address)));
    memset (pBMICmdBuf, 0, sizeof(cid) + sizeof(address));

    if (bmiDone) {
        ath_err("cmd disallowed\n");
        return A_ERROR;
    }

    /*ath_dbg(ATH_DBG_BMI, "bmi LZ stream start: device: 0x%p, address: 0x%x)\n",
            device, address);
	*/
    cid = BMI_LZ_STREAM_START;
    offset = 0;
    memcpy(&(pBMICmdBuf[offset]), &cid, sizeof(cid));
    offset += sizeof(cid);
    memcpy(&(pBMICmdBuf[offset]), &address, sizeof(address));
    offset += sizeof(address);
    status = bmi_send_buf(device, pBMICmdBuf, offset);
    if (status) {
        ath_err("unable to start LZ stream to the device\n");
        return A_ERROR;
    }

    return 0;
}

/* BMI Access routines */
int
bmi_send_buf(struct hif_device *device,
              u8 *buffer,
              u32 length)
{
    int status;
    u32 timeout;
    u32 address;
    u32 mboxAddress[HTC_MAILBOX_NUM_MAX];

    hif_config_dev(device, HIF_DEVICE_GET_MBOX_ADDR,
                       &mboxAddress[0], sizeof(mboxAddress));

    *pBMICmdCredits = 0;
    timeout = BMI_COMMUNICATION_TIMEOUT;

    while(timeout-- && !(*pBMICmdCredits)) {
        /* Read the counter register to get the command credits */
        address = COUNT_DEC_ADDRESS + (HTC_MAILBOX_NUM_MAX + ENDPOINT1) * 4;
        /* hit the credit counter with a 4-byte access, the first byte read will hit the counter and cause
         * a decrement, while the remaining 3 bytes has no effect.  The rationale behind this is to
         * make all HIF accesses 4-byte aligned */
        status = hif_read_write(device, address, (u8 *)pBMICmdCredits, 4,
            HIF_RD_SYNC_BYTE_INC, NULL);
        if (status) {
            ath_err("unable to decrement the command credit count register\n");
            return A_ERROR;
        }
        /* the counter is only 8=bits, ignore anything in the upper 3 bytes */
        (*pBMICmdCredits) &= 0xFF;
    }

    if (*pBMICmdCredits) {
        address = mboxAddress[ENDPOINT1];
        status = hif_read_write(device, address, buffer, length,
            HIF_WR_SYNC_BYTE_INC, NULL);
        if (status) {
            ath_err("unable to send the bmi data to the device\n");
            return A_ERROR;
        }
    } else {
        ath_err("bmi communication timeout - bmi_send_buf\n");
        return A_ERROR;
    }

    return status;
}

int
bmi_recv_buf(struct hif_device *device,
                 u8 *buffer,
                 u32 length,
                 bool want_timeout)
{
    int status;
    u32 address;
    u32 mboxAddress[HTC_MAILBOX_NUM_MAX];
    struct hif_pending_events_info     hifPendingEvents;
    static HIF_PENDING_EVENTS_FUNC getPendingEventsFunc = NULL;
    
    if (!pendingEventsFuncCheck) {
            /* see if the HIF layer implements an alternative function to get pending events
             * do this only once! */
        hif_config_dev(device,
                           HIF_DEVICE_GET_PENDING_EVENTS_FUNC,
                           &getPendingEventsFunc,
                           sizeof(getPendingEventsFunc));
        pendingEventsFuncCheck = true;
    }
                       
    hif_config_dev(device, HIF_DEVICE_GET_MBOX_ADDR,
                       &mboxAddress[0], sizeof(mboxAddress));

    /*
     * During normal bootup, small reads may be required.
     * Rather than issue an HIF Read and then wait as the Target
     * adds successive bytes to the FIFO, we wait here until
     * we know that response data is available.
     *
     * This allows us to cleanly timeout on an unexpected
     * Target failure rather than risk problems at the HIF level.  In
     * particular, this avoids SDIO timeouts and possibly garbage
     * data on some host controllers.  And on an interconnect
     * such as Compact Flash (as well as some SDIO masters) which
     * does not provide any indication on data timeout, it avoids
     * a potential hang or garbage response.
     *
     * Synchronization is more difficult for reads larger than the
     * size of the MBOX FIFO (128B), because the Target is unable
     * to push the 129th byte of data until AFTER the Host posts an
     * HIF Read and removes some FIFO data.  So for large reads the
     * Host proceeds to post an HIF Read BEFORE all the data is
     * actually available to read.  Fortunately, large BMI reads do
     * not occur in practice -- they're supported for debug/development.
     *
     * So Host/Target BMI synchronization is divided into these cases:
     *  CASE 1: length < 4
     *        Should not happen
     *
     *  CASE 2: 4 <= length <= 128
     *        Wait for first 4 bytes to be in FIFO
     *        If CONSERVATIVE_BMI_READ is enabled, also wait for
     *        a BMI command credit, which indicates that the ENTIRE
     *        response is available in the the FIFO
     *
     *  CASE 3: length > 128
     *        Wait for the first 4 bytes to be in FIFO
     *
     * For most uses, a small timeout should be sufficient and we will
     * usually see a response quickly; but there may be some unusual
     * (debug) cases of BMI_EXECUTE where we want an larger timeout.
     * For now, we use an unbounded busy loop while waiting for
     * BMI_EXECUTE.
     *
     * If BMI_EXECUTE ever needs to support longer-latency execution,
     * especially in production, this code needs to be enhanced to sleep
     * and yield.  Also note that BMI_COMMUNICATION_TIMEOUT is currently
     * a function of Host processor speed.
     */
    if (length >= 4) { /* NB: Currently, always true */
        /*
         * NB: word_available is declared static for esoteric reasons
         * having to do with protection on some OSes.
         */
        static u32 word_available;
        u32 timeout;

        word_available = 0;
        timeout = BMI_COMMUNICATION_TIMEOUT;
        while((!want_timeout || timeout--) && !word_available) {
            
            if (getPendingEventsFunc != NULL) {
                status = getPendingEventsFunc(device,
                                              &hifPendingEvents,
                                              NULL);
                if (status) {
                    ath_err("bmi: failed to get pending events \n");
                    break;
                }
  
                if (hifPendingEvents.AvailableRecvBytes >= sizeof(u32)) {
                    word_available = 1;    
                }
                continue;    
            }
            
            status = hif_read_write(device, RX_LOOKAHEAD_VALID_ADDRESS, (u8 *)&word_available,
                sizeof(word_available), HIF_RD_SYNC_BYTE_INC, NULL);
            if (status) {
                ath_err("unable to read RX_LOOKAHEAD_VALID register\n");
                return A_ERROR;
            }
            /* We did a 4-byte read to the same register; all we really want is one bit */ 
            word_available &= (1 << ENDPOINT1);
        }

        if (!word_available) {
            ath_err("bmi communication timeout - bmi_recv_buf FIFO empty\n");
            return A_ERROR;
        }
    }

#define CONSERVATIVE_BMI_READ 0
#if CONSERVATIVE_BMI_READ
    /*
     * This is an extra-conservative CREDIT check.  It guarantees
     * that ALL data is available in the FIFO before we start to
     * read from the interconnect.
     *
     * This credit check is useless when firmware chooses to
     * allow multiple outstanding BMI Command Credits, since the next
     * credit will already be present.  To restrict the Target to one
     * BMI Command Credit, see HI_OPTION_BMI_CRED_LIMIT.
     *
     * And for large reads (when HI_OPTION_BMI_CRED_LIMIT is set)
     * we cannot wait for the next credit because the Target's FIFO
     * will not hold the entire response.  So we need the Host to
     * start to empty the FIFO sooner.  (And again, large reads are
     * not used in practice; they are for debug/development only.)
     *
     * For a more conservative Host implementation (which would be
     * safer for a Compact Flash interconnect):
     *   Set CONSERVATIVE_BMI_READ (above) to 1
     *   Set HI_OPTION_BMI_CRED_LIMIT and
     *   reduce BMI_DATASZ_MAX to 32 or 64
     */
    if ((length > 4) && (length < 128)) { /* check against MBOX FIFO size */
        u32 timeout;

        *pBMICmdCredits = 0;
        timeout = BMI_COMMUNICATION_TIMEOUT;
        while((!want_timeout || timeout--) && !(*pBMICmdCredits) {
            /* Read the counter register to get the command credits */
            address = COUNT_ADDRESS + (HTC_MAILBOX_NUM_MAX + ENDPOINT1) * 1;
            /* read the counter using a 4-byte read.  Since the counter is NOT auto-decrementing,
             * we can read this counter multiple times using a non-incrementing address mode.
             * The rationale here is to make all HIF accesses a multiple of 4 bytes */
            status = hif_read_write(device, address, (u8 *)pBMICmdCredits, sizeof(*pBMICmdCredits),
                HIF_RD_SYNC_BYTE_FIX, NULL);
            if (status) {
                ath_err("unable to read the command credit count register\n");
                return A_ERROR;
            }
                /* we did a 4-byte read to the same count register so mask off upper bytes */
            (*pBMICmdCredits) &= 0xFF;
        }

        if (!(*pBMICmdCredits)) {
            ath_err("bmi communication timeout- bmi_recv_buf no credit\n");
            return A_ERROR;
        }
    }
#endif

    address = mboxAddress[ENDPOINT1];
    status = hif_read_write(device, address, buffer, length, HIF_RD_SYNC_BYTE_INC, NULL);
    if (status) {
        ath_err("unable to read the bmi data from the device\n");
        return A_ERROR;
    }

    return 0;
}

int
bmi_fast_download(struct hif_device *device, u32 address, u8 *buffer, u32 length)
{
    int status = A_ERROR;
    u32 lastWord = 0;
    u32 lastWordOffset = length & ~0x3;
    u32 unalignedBytes = length & 0x3;

    status = bmi_lz_stream_start (device, address);
    if (status) {
            return A_ERROR;
    }

    if (unalignedBytes) {
            /* copy the last word into a zero padded buffer */
        memcpy(&lastWord, &buffer[lastWordOffset], unalignedBytes);
    }

    status = bmi_lz_data(device, buffer, lastWordOffset);

    if (status) {
        return A_ERROR;
    }

    if (unalignedBytes) {
        status = bmi_lz_data(device, (u8 *)&lastWord, 4);
    }

    if (!status) {
        //
        // Close compressed stream and open a new (fake) one.  This serves mainly to flush Target caches.
        //
        status = bmi_lz_stream_start (device, 0x00);
        if (status) {
           return A_ERROR;
        }
    }
	return status;
}

int
bmi_raw_write(struct hif_device *device, u8 *buffer, u32 length)
{
    return bmi_send_buf(device, buffer, length);
}

int
bmi_raw_read(struct hif_device *device, u8 *buffer, u32 length, bool want_timeout)
{
    return bmi_recv_buf(device, buffer, length, want_timeout);
}
