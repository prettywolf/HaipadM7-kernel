
/*
 * Copyright (c) 2011 Atheros Communications Inc.
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

#include "ar6000_drv.h"
#include "cfg80211.h"
#include "aggr_rx.h"

unsigned int enableuartprint = ENABLEUARTPRINT_DEFAULT;
unsigned int enabletimerwar = 0;
module_param(enableuartprint, uint, 0644);
module_param(enabletimerwar, uint, 0644);

DECLARE_WAIT_QUEUE_HEAD(arEvent);
static int __ath6kl_init_netdev(struct net_device *dev)
{
	int r;

	rtnl_lock();
	r = ar6000_init(dev);
	rtnl_unlock();

	if (r) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000_avail: ar6000_init\n"));
		return r;
	}

	return 0;
}

static int ath6kl_init_netdev_wmi(struct net_device *dev)
{
	return __ath6kl_init_netdev(dev);
}

static int ath6kl_init_netdev(struct ar6_softc *ar)
{
	int r;

        r = ar6000_sysfs_bmi_get_config(ar, wlaninitmode);
        if (r) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("ar6000_avail: "
				 "ar6000_sysfs_bmi_get_config failed\n"));
		return r;
        }

	return ath6kl_init_netdev_wmi(ar->arNetDev);
}

#define AR6000_DATA_OFFSET    64
struct sk_buff *ar6k_buf_alloc(int size)
{
	struct sk_buff *skb;
	u16 reserved;

	/* Add chacheline space at front and back of buffer */
	reserved = (2 * L1_CACHE_BYTES) + AR6000_DATA_OFFSET +
		   sizeof(struct htc_packet);
	skb = dev_alloc_skb(size + reserved);

	if (skb)
		skb_reserve(skb, reserved - L1_CACHE_BYTES);
	return skb;
}

static void ar6000_alloc_netbufs(struct sk_buff_head  *q, u16 num)
{
    struct sk_buff *osbuf;

    while(num) {
        if((osbuf = ar6k_buf_alloc(AR6000_BUFFER_SIZE))) {
            skb_queue_tail(q, osbuf);
        } else {
            break;
        }
        num--;
    }

    if(num)
        A_PRINTF("%s(), allocation of netbuf failed", __func__);
}

static void ar6000_refill_amsdu_rxbufs(struct ar6_softc *ar, int Count)
{
	struct htc_packet *pPacket;
	struct sk_buff *osBuf;

	while (Count) {
		osBuf = ar6k_buf_alloc(AR6000_AMSDU_BUFFER_SIZE);
		if (!osBuf)
			return;

		/* the HTC packet wrapper is at the head of the reserved area
		 * in the skb */
		pPacket = (struct htc_packet *) osBuf->head;
		SET_HTC_PACKET_INFO_RX_REFILL(pPacket,osBuf,
				 osBuf->data,
				AR6000_AMSDU_BUFFER_SIZE,0);
		spin_lock_bh(&ar->arLock);
		HTC_PACKET_ENQUEUE(&ar->amsdu_rx_buffer_queue,pPacket);
		spin_unlock_bh(&ar->arLock);
		Count--;
	}
}

/* callback to allocate a large receive buffer for a pending packet.  This function is called when
 * an HTC packet arrives whose length exceeds a threshold value
 *
 * We use a pre-allocated list of buffers of maximum AMSDU size (4K).
 */
static struct htc_packet *ar6000_alloc_amsdu_rxbuf(void *Context,
						   enum htc_endpoint_id Endpoint,
						   int Length)
{
	struct htc_packet  *pPacket = NULL;
	struct ar6_softc  *ar = (struct ar6_softc *)Context;
	int refillCount = 0;

	AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_RX,("ar6000_alloc_amsdu_rxbuf: eid=%d, Length:%d\n",Endpoint,Length));

	if ((Length <= AR6000_BUFFER_SIZE) ||
	    (Length > AR6000_AMSDU_BUFFER_SIZE))
		return NULL;

	spin_lock_bh(&ar->arLock);

	pPacket = HTC_PACKET_DEQUEUE(&ar->amsdu_rx_buffer_queue);
	/* see if we need to refill again */
	refillCount = AR6000_MAX_AMSDU_RX_BUFFERS - HTC_PACKET_QUEUE_DEPTH(&ar->amsdu_rx_buffer_queue);
	spin_unlock_bh(&ar->arLock);

	if (!pPacket)
		return NULL;

	/* set actual endpoint ID */
	pPacket->Endpoint = Endpoint;

	if (refillCount >= AR6000_AMSDU_REFILL_THRESHOLD)
		ar6000_refill_amsdu_rxbufs(ar,refillCount);

	return pPacket;
}

static void ar6000_rx_refill(void *Context,
			     enum htc_endpoint_id Endpoint)
{
	struct ar6_softc *ar = (struct ar6_softc *)Context;
	struct sk_buff *osBuf;
	int RxBuffers;
	int buffersToRefill;
	struct htc_packet *pPacket;
	struct htc_packet_queue queue;

	buffersToRefill = (int) AR6000_MAX_RX_BUFFERS -
			HTCGetNumRecvBuffers(ar->arHtcTarget, Endpoint);

	if (buffersToRefill <= 0)
		return;

	INIT_HTC_PACKET_QUEUE(&queue);

	AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_RX,("ar6000_rx_refill: providing htc with %d buffers at eid=%d\n",
				buffersToRefill, Endpoint));

	for (RxBuffers = 0; RxBuffers < buffersToRefill; RxBuffers++) {
		osBuf = ar6k_buf_alloc(AR6000_BUFFER_SIZE);
		if (!osBuf)
			break;

		/* the HTC packet wrapper is at the head of the reserved area
		 * in the skb */
		pPacket = (struct htc_packet *) osBuf->head;
		SET_HTC_PACKET_INFO_RX_REFILL(pPacket,osBuf,
				osBuf->data,
				AR6000_BUFFER_SIZE,Endpoint);
		HTC_PACKET_ENQUEUE(&queue,pPacket);
	}

	if (!HTC_QUEUE_EMPTY(&queue))
		HTCAddReceivePktMultiple(ar->arHtcTarget, &queue);
}

/* connect to a service */
static int ar6000_connectservice(struct ar6_softc *ar,
		struct htc_service_connect_req  *pConnect,
		char *pDesc)
{
	int status;
	struct htc_service_connect_resp response;

	memset(&response, 0, sizeof(response));

	status = HTCConnectService(ar->arHtcTarget, pConnect, &response);
	if (status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" Failed to connect to %s service status:%d \n",
					pDesc, status));
		return status;
	}

	switch (pConnect->ServiceID) {
	case WMI_CONTROL_SVC :
		if (ar->arWmiEnabled)
			wmi_set_control_ep(ar->arWmi, response.Endpoint);
		ar->arControlEp = response.Endpoint;
		break;
	case WMI_DATA_BE_SVC :
		arSetAc2EndpointIDMap(ar, WMM_AC_BE, response.Endpoint);
		break;
	case WMI_DATA_BK_SVC :
		arSetAc2EndpointIDMap(ar, WMM_AC_BK, response.Endpoint);
		break;
	case WMI_DATA_VI_SVC :
		arSetAc2EndpointIDMap(ar, WMM_AC_VI, response.Endpoint);
		break;
	case WMI_DATA_VO_SVC :
		arSetAc2EndpointIDMap(ar, WMM_AC_VO, response.Endpoint);
		break;
	default:
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ServiceID not mapped %d\n", pConnect->ServiceID));
		return -EINVAL;
	}

	return 0;
}

static int ar6k_init_service_ep(struct ar6_softc *ar)
{
	struct htc_service_connect_req connect;

	memset(&connect, 0, sizeof(connect));
	connect.pMetaData = NULL;
	connect.MetaDataLength = 0;

	/* these fields are the same for all service endpoints */
	connect.EpCallbacks.pContext = ar;
	connect.EpCallbacks.EpTxCompleteMultiple = ar6000_tx_complete;
	connect.EpCallbacks.EpRecv = ar6000_rx;
	connect.EpCallbacks.EpRecvRefill = ar6000_rx_refill;
	connect.EpCallbacks.EpSendFull = ar6000_tx_queue_full;
	/* set the max queue depth so that our ar6000_tx_queue_full
	   handler gets called. */
	connect.MaxSendQueueDepth = MAX_DEFAULT_SEND_QUEUE_DEPTH;
	connect.EpCallbacks.RecvRefillWaterMark = AR6000_MAX_RX_BUFFERS / 4;
	if (!connect.EpCallbacks.RecvRefillWaterMark)
		connect.EpCallbacks.RecvRefillWaterMark++;

	/* connect to control service */
	connect.ServiceID = WMI_CONTROL_SVC;
	if (ar6000_connectservice(ar, &connect, "WMI CONTROL"))
		return -EIO;

	connect.LocalConnectionFlags |= HTC_LOCAL_CONN_FLAGS_ENABLE_SEND_BUNDLE_PADDING;
	/* limit the HTC message size on the send path, although
	 * e can receive A-MSDU frames of 4K, we will only send
	 * ethernet-sized (802.3) frames on the send path. */
	connect.MaxSendMsgSize = WMI_MAX_TX_DATA_FRAME_LENGTH;

	/* to reduce the amount of committed memory for larger
	 * A_MSDU frames, use the recv-alloc threshold
	 * mechanism for larger packets */
	connect.EpCallbacks.RecvAllocThreshold = AR6000_BUFFER_SIZE;
	connect.EpCallbacks.EpRecvAllocThresh = ar6000_alloc_amsdu_rxbuf;

	/* for the remaining data services set the connection flag
	 * to reduce dribbling, if configured to do so */
	if (reduce_credit_dribble) {
		connect.ConnectionFlags |= HTC_CONNECT_FLAGS_REDUCE_CREDIT_DRIBBLE;
		/* the credit dribble trigger threshold is
		 * (reduce_credit_dribble - 1) for a value
		 * of 0-3 */
		connect.ConnectionFlags &= ~HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_MASK;
		connect.ConnectionFlags |=
			((u16)reduce_credit_dribble - 1) & HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_MASK;
	}

	connect.ServiceID = WMI_DATA_BE_SVC;

	if (ar6000_connectservice(ar, &connect, "WMI DATA BE"))
		return -EIO;

	/* connect to back-ground map this to WMI LOW_PRI */
	connect.ServiceID = WMI_DATA_BK_SVC;
	if (ar6000_connectservice(ar, &connect, "WMI DATA BK"))
		return -EIO;

	/* connect to Video service, map this to to HI PRI */
	connect.ServiceID = WMI_DATA_VI_SVC;
	if (ar6000_connectservice(ar, &connect, "WMI DATA VI"))
		return -EIO;

	/* connect to VO service, this is currently not
	 * mapped to a WMI priority stream due to historical reasons.
	 * WMI originally defined 3 priorities over 3 mailboxes
	 * We can change this when WMI is reworked so that priorities are not
	 * dependent on mailboxes */
	connect.ServiceID = WMI_DATA_VO_SVC;
	if (ar6000_connectservice(ar, &connect, "WMI DATA VO"))
		return -EIO;

	return 0;
}

static void ath6k_credit_init(void *Context,
		struct htc_endpoint_credit_dist *pEPList,
		int TotalCredits)
{
	struct htc_endpoint_credit_dist *pCurEpDist;
	int count;
	struct common_credit_state_info *pCredInfo = (struct common_credit_state_info *)Context;

	pCredInfo->CurrentFreeCredits = TotalCredits;
	pCredInfo->TotalAvailableCredits = TotalCredits;

	pCurEpDist = pEPList;

	while (pCurEpDist) {

		pCurEpDist->TxCreditsMin = pCurEpDist->TxCreditsPerMaxMsg;

		if (TotalCredits > 4)
			if ((pCurEpDist->ServiceID == WMI_DATA_BK_SVC) ||
			    (pCurEpDist->ServiceID == WMI_DATA_BE_SVC)){
				AH6K_DEPOSITE_CREDITS_TO_EP(pCredInfo,
						pCurEpDist,
						pCurEpDist->TxCreditsMin);
				SET_EP_ACTIVE(pCurEpDist);
			}

		if (pCurEpDist->ServiceID == WMI_CONTROL_SVC) {
			AH6K_DEPOSITE_CREDITS_TO_EP(pCredInfo,pCurEpDist,pCurEpDist->TxCreditsMin);
			/* control service is always marked active, it never goes inactive EVER */
			SET_EP_ACTIVE(pCurEpDist);
		} else if (pCurEpDist->ServiceID == WMI_DATA_BK_SVC)
			/* this is the lowest priority data endpoint */
			pCredInfo->pLowestPriEpDist = pCurEpDist;

		/* Streams have to be created (explicit | implicit)for all kinds
		 * of traffic. BE endpoints are also inactive in the beginning.
		 * When BE traffic starts it creates implicit streams that
		 * redistributes credits.
		 */

		/* note, all other endpoints have minimums set but are initially given NO credits.
		 * Credits will be distributed as traffic activity demands */
		pCurEpDist = pCurEpDist->pNext;
	}

	WARN_ON(pCredInfo->CurrentFreeCredits <= 0);

	pCurEpDist = pEPList;
	while (pCurEpDist) {
		if (pCurEpDist->ServiceID == WMI_CONTROL_SVC)
			pCurEpDist->TxCreditsNorm = pCurEpDist->TxCreditsPerMaxMsg;
		else {
			/* for the remaining data endpoints, we assume that each TxCreditsPerMaxMsg are
			 * the same.
			 * We use a simple calculation here, we take the remaining credits and
			 * determine how many max messages this can cover and then set each endpoint's
			 * normal value equal to 3/4 this amount.
			 * */
			count = (pCredInfo->CurrentFreeCredits/pCurEpDist->TxCreditsPerMaxMsg)
				* pCurEpDist->TxCreditsPerMaxMsg;
			count = (count * 3) >> 2;
			count = max(count,pCurEpDist->TxCreditsPerMaxMsg);
			pCurEpDist->TxCreditsNorm = count;

		}
		pCurEpDist = pCurEpDist->pNext;
	}

}

/* initialize and setup credit distribution */
static int ath6k_setup_credit_dist(void * HTCHandle,
				   struct common_credit_state_info *pCredInfo)
{
	u16 servicepriority[5];

	memset(pCredInfo, 0, sizeof(struct common_credit_state_info));

	servicepriority[0] = WMI_CONTROL_SVC;  /* highest */
	servicepriority[1] = WMI_DATA_VO_SVC;
	servicepriority[2] = WMI_DATA_VI_SVC;
	servicepriority[3] = WMI_DATA_BE_SVC;
	servicepriority[4] = WMI_DATA_BK_SVC; /* lowest */

	/* set callbacks and priority list */
	HTCSetCreditDistribution(HTCHandle,
			pCredInfo,
			ath6k_credit_distribute,
			ath6k_credit_init,
			servicepriority,
			5);

	return 0;
}

static void ar6000_init_control_info(struct ar6_softc *ar)
{
	u8 ctr;

	ar->arWmiEnabled         = false;
	ar6000_init_profile_info(ar);
	ar->arDefTxKeyIndex      = 0;
	memset(ar->arWepKeyList, 0, sizeof(ar->arWepKeyList));
	ar->arChannelHint        = 0;
	ar->arListenIntervalT    = A_DEFAULT_LISTEN_INTERVAL;
	ar->arListenIntervalB    = 0;
	ar->arVersion.host_ver   = AR6K_SW_VERSION;
	ar->arTxPwr              = 0;
	ar->arSkipScan           = 0;
	ar->arWmmEnabled         = true;
	ar->intra_bss            = 1;
	ar->scan_triggered       = 0;
	memset(&ar->scParams, 0, sizeof(ar->scParams));
	ar->scParams.shortScanRatio = WMI_SHORTSCANRATIO_DEFAULT;
	ar->scParams.scanCtrlFlags = DEFAULT_SCAN_CTRL_FLAGS;

	memset((u8 *)ar->sta_list, 0, AP_MAX_NUM_STA * sizeof(struct ar6k_sta));

	spin_lock_init(&ar->mcastpsqLock);

	/* Init the PS queues */
	for (ctr = 0; ctr < AP_MAX_NUM_STA; ctr++) {
		spin_lock_init(&ar->sta_list[ctr].psqLock);
		skb_queue_head_init(&ar->sta_list[ctr].psq);
	}

	skb_queue_head_init(&ar->mcastpsq);

	memcpy(ar->ap_country_code, DEF_AP_COUNTRY_CODE, 3);
}

/* set HTC/Mbox operational parameters, this can only be called
 * when the target is in the BMI phase
 */
static int ar6000_set_htc_params(struct ar6_softc *ar, u32 MboxIsrYieldValue,
				 u8 HtcControlBuffers)
{
	int status;
	u32 blocksizes[HTC_MAILBOX_NUM_MAX];

	/* get the block sizes */
	status = hif_config_dev(ar->arHifDevice, HIF_DEVICE_GET_MBOX_BLOCK_SIZE,
				blocksizes, sizeof(blocksizes));

	if (status) {
		AR_DEBUG_PRINTF(ATH_LOG_ERR,("Failed to get block size info from HIF layer...\n"));
		goto out;
	}

	if (HtcControlBuffers)
		blocksizes[1] |=  ((u32)HtcControlBuffers) << 16;

	/* set the host interest area for the block size */
	status = bmi_write_memory(ar->arHifDevice,
			HOST_INTEREST_ITEM_ADDRESS(ar,
			hi_mbox_io_block_sz),
			(u8 *)&blocksizes[1],
			4);
	if (status) {
		AR_DEBUG_PRINTF(ATH_LOG_ERR,("bmi_write_memory for IO block size failed \n"));
		goto out;
	}

	AR_DEBUG_PRINTF(ATH_LOG_INF,("Block Size Set: %d (target address:0x%X)\n",
				blocksizes[1], HOST_INTEREST_ITEM_ADDRESS(ar, hi_mbox_io_block_sz)));

	if (MboxIsrYieldValue) {
		/* set the host interest area for the mbox ISR yield limit */
		status = bmi_write_memory(ar->arHifDevice,
				HOST_INTEREST_ITEM_ADDRESS(ar,
				hi_mbox_isr_yield_limit),
				(u8 *)&MboxIsrYieldValue,
				4);
		if (status) {
			AR_DEBUG_PRINTF(ATH_LOG_ERR,("bmi_write_memory for yield limit failed \n"));
			goto out;
		}
	}

out:
	return status;
}

/* This should be called in BMI phase after firmware is downloaded */
static void ar6000_copy_cust_data_from_target(struct ar6_softc *ar)
{
	u32 eepHeaderAddr;
	u8 AR6003CustDataShadow[AR6003_CUST_DATA_SIZE+4];
	u8 *tmp_custdata = NULL;
	u16 i, data_size;

	if (ar->arTargetType != TARGET_TYPE_AR6003)
		return;

	if (bmi_read_memory(ar->arHifDevice,
			    HOST_INTEREST_ITEM_ADDRESS(ar, hi_board_data),
			    (u8 *)&eepHeaderAddr, 4)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("bmi_read_memory for reading board data address failed \n"));
		return;
	}

	eepHeaderAddr += 36;
	data_size = AR6003_CUST_DATA_SIZE;
	tmp_custdata = AR6003CustDataShadow;

	for (i = 0; i < data_size; i += 4) {
		if (bmi_read_soc_register(ar->arHifDevice, eepHeaderAddr,
					  (u32 *)&tmp_custdata[i])) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("bmi_read_soc_register () failed \n"));
			return ;
		}
		eepHeaderAddr +=4;
	}

	memcpy(custDataAR6003, tmp_custdata, data_size);
}

#define REG_DUMP_COUNT_AR6003   60
#define REGISTER_DUMP_LEN_MAX   60

static void ar6000_dump_target_assert_info(struct ar6_softc *ar)
{
	u32 address;
	u32 regDumpArea = 0;
	int status;
	u32 regDumpValues[REGISTER_DUMP_LEN_MAX];
	u32 i;

	if (ar->arTargetType != TARGET_TYPE_AR6003)
		return;

	/* the reg dump pointer is copied to the host interest area */
	address = HOST_INTEREST_ITEM_ADDRESS(ar, hi_failure_state);
	address = TARG_VTOP(ar->arTargetType, address);

	/* read RAM location through diagnostic window */
	status = ar6000_ReadRegDiag(ar->arHifDevice, &address, &regDumpArea);

	if (status || !regDumpArea) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("AR6K: Failed to get ptr to register dump area \n"));
		return;
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("AR6K: Location of register dump data: 0x%X \n",regDumpArea));

	regDumpArea = TARG_VTOP(ar->arTargetType, regDumpArea);

	/* fetch register dump data */
	status = ar6000_access_datadiag(ar->arHifDevice,
					regDumpArea,
					(u8 *)&regDumpValues[0],
					REG_DUMP_COUNT_AR6003 * (sizeof(u32)),
					true);

	if (status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("AR6K: Failed to get register dump \n"));
		return;
	}
	AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("AR6K: Register Dump: \n"));

	for (i = 0; i < REG_DUMP_COUNT_AR6003; i++)
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" %d :  0x%8.8X \n",i, regDumpValues[i]));

}

static void ar6000_target_failure(void *Instance, int Status)
{
	struct ar6_softc *ar = (struct ar6_softc *)Instance;

	if (Status) {

		printk(KERN_ERR "ar6000_target_failure: target asserted \n");

		del_timer(&ar->arHBChallengeResp.timer);

		/* try dumping target assertion information (if any) */
		ar6000_dump_target_assert_info(ar);

	}
}

static int ar6000_target_config_wlan_params(struct ar6_softc *ar)
{
	int status = 0;
#if WLAN_CONFIG_DISABLE_11N
	WMI_SET_HT_CAP_CMD htCap;
#endif /* WLAN_CONFIG_DISABLE_11N */

	/* 
	 * configure the device for rx dot11 header rules 0,0 are the default values
	 * therefore this command can be skipped if the inputs are 0,FALSE,FALSE.Required
	 * if checksum offload is needed. Set RxMetaVersion to 2
	 */
	if ((wmi_set_rx_frame_format_cmd(ar->arWmi,ar->rxMetaVersion,
					 processDot11Hdr, processDot11Hdr))) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set the rx frame format.\n"));
		status = -EIO;
	}

#if WLAN_CONFIG_IGNORE_POWER_SAVE_FAIL_EVENT_DURING_SCAN
	if ((wmi_pmparams_cmd(ar->arWmi, 0, 1, 0, 0, 1, IGNORE_POWER_SAVE_FAIL_EVENT_DURING_SCAN)) != 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set power save fail event policy\n"));
		status = -EIO;
	}
#endif

#if WLAN_CONFIG_DONOT_IGNORE_BARKER_IN_ERP
	if ((wmi_set_lpreamble_cmd(ar->arWmi, 0, WMI_DONOT_IGNORE_BARKER_IN_ERP)) != 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set barker preamble policy\n"));
		status = -EIO;
	}
#endif

	if ((wmi_set_keepalive_cmd(ar->arWmi, WLAN_CONFIG_KEEP_ALIVE_INTERVAL)) != 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set keep alive interval\n"));
		status = -EIO;
	}

#if WLAN_CONFIG_DISABLE_11N
	memset(&htCap, 0, sizeof(WMI_SET_HT_CAP_CMD));
	if (wmi_set_ht_cap_cmd(ar->arWmi, &htCap)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set ht capabilities \n"));
		status = -EIO;
	}

	htCap.band = 1;
	if (wmi_set_ht_cap_cmd(ar->arWmi, &htCap)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set ht capabilities \n"));
		status = -EIO;
	}
#endif /* WLAN_CONFIG_DISABLE_11N */

#ifdef ATH6K_CONFIG_OTA_MODE
	if (wmi_powermode_cmd(ar->arWmi, MAX_PERF_POWER)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set power mode \n"));
		status = -EIO;
	}
#endif

	if (wmi_disctimeout_cmd(ar->arWmi, WLAN_CONFIG_DISCONNECT_TIMEOUT)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set disconnect timeout \n"));
		status = -EIO;
	}

#if WLAN_CONFIG_DISABLE_TX_BURSTING  
	if (wmi_set_wmm_txop(ar->arWmi, WMI_TXOP_DISABLED)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set txop bursting \n"));
		status = -EIO;
	}
#endif 

	return status;
}

int ar6000_configure_target(struct ar6_softc *ar)
{
	u32 param;

	if (enableuartprint) {
		param = 1;
		if (bmi_write_memory(ar->arHifDevice,
				     HOST_INTEREST_ITEM_ADDRESS(ar,
				     hi_serial_enable),
				     (u8 *)&param,
				     4)!= 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("bmi_write_memory for enableuartprint failed \n"));
			return -EIO;
		}
		AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("Serial console prints enabled\n"));
	}

	/* Tell target which HTC version it is used*/
	param = HTC_PROTOCOL_VERSION;
	if (bmi_write_memory(ar->arHifDevice,
			     HOST_INTEREST_ITEM_ADDRESS(ar,
			     hi_app_host_interest),
			     (u8 *)&param,
			     4)!= 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("bmi_write_memory for htc version failed \n"));
		return -EIO;
	}

	if (enabletimerwar) {
		param = 0;

		if (bmi_read_memory(ar->arHifDevice,
				    HOST_INTEREST_ITEM_ADDRESS(ar,
				    hi_option_flag),
				    (u8 *)&param,
				    4)!= 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("bmi_read_memory for enabletimerwar failed \n"));
			return -EIO;
		}

		param |= HI_OPTION_TIMER_WAR;

		if (bmi_write_memory(ar->arHifDevice,
				     HOST_INTEREST_ITEM_ADDRESS(ar,
				     hi_option_flag),
				     (u8 *)&param,
				     4) != 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("bmi_write_memory for enabletimerwar failed \n"));
			return -EIO;
		}
		AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("Timer WAR enabled\n"));
	}

	/* set the firmware mode to STA/IBSS/AP */
	param = 0;

	if (bmi_read_memory(ar->arHifDevice,
				HOST_INTEREST_ITEM_ADDRESS(ar, hi_option_flag),
				(u8 *)&param,
				4)!= 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("bmi_read_memory for setting fwmode failed \n"));
		return -EIO;
	}

	param |= (1 << HI_OPTION_NUM_DEV_SHIFT);
	param |= (fwmode << HI_OPTION_FW_MODE_SHIFT);
	param |= (0 << HI_OPTION_MAC_ADDR_METHOD_SHIFT);
	param |= (0 << HI_OPTION_FW_BRIDGE_SHIFT);


	if (bmi_write_memory(ar->arHifDevice,
			     HOST_INTEREST_ITEM_ADDRESS(ar,
			     hi_option_flag),
			     (u8 *)&param,
			     4) != 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("bmi_write_memory for setting fwmode failed \n"));
		return -EIO;
	}
	AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("Firmware mode set\n"));

#ifdef ATH6KL_DISABLE_TARGET_DBGLOGS
	{
		param = 0;

		if (bmi_read_memory(ar->arHifDevice,
				    HOST_INTEREST_ITEM_ADDRESS(ar,
				    hi_option_flag),
				    (u8 *)&param,
				    4)!= 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("bmi_read_memory for disabling debug logs failed\n"));
			return -EIO;
		}

		param |= HI_OPTION_DISABLE_DBGLOG;

		if (bmi_write_memory(ar->arHifDevice,
				     HOST_INTEREST_ITEM_ADDRESS(ar,
				     hi_option_flag),
				     (u8 *)&param,
				     4) != 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("bmi_write_memory for HI_OPTION_DISABLE_DBGLOG\n"));
			return -EIO;
		}
		AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("Firmware mode set\n"));
	}
#endif /* ATH6KL_DISABLE_TARGET_DBGLOGS */

	/*
	 * Hardcode the address use for the extended board data
	 * Ideally this should be pre-allocate by the OS at boot time
	 * But since it is a new feature and board data is loaded
	 * at init time, we have to workaround this from host.
	 * It is difficult to patch the firmware boot code,
	 * but possible in theory.
	 */

	if (ar->arTargetType == TARGET_TYPE_AR6003) {
		u32 ramReservedSz;
		if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
			param = AR6003_REV2_BOARD_EXT_DATA_ADDRESS;
			ramReservedSz =  AR6003_REV2_RAM_RESERVE_SIZE;
		} else {
			param = AR6003_REV3_BOARD_EXT_DATA_ADDRESS;
			ramReservedSz =  AR6003_REV3_RAM_RESERVE_SIZE;
		}
		if (bmi_write_memory(ar->arHifDevice,
				     HOST_INTEREST_ITEM_ADDRESS(ar,
				     hi_board_ext_data),
				     (u8 *)&param, 4) != 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("bmi_write_memory for "
					 "hi_board_ext_data failed\n"));
			return -EIO;
		}
		if (bmi_write_memory(ar->arHifDevice,
				     HOST_INTEREST_ITEM_ADDRESS(ar,
				     hi_end_RAM_reserve_sz),
				     (u8 *)&ramReservedSz, 4) != 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR ,
					("bmi_write_memory for "
					 "hi_end_RAM_reserve_sz failed\n"));
			return -EIO;
		}
	}

	/* Set the block size for the target */

	if (ar6000_set_htc_params(ar, mbox_yield_limit, 0))
		/* use default number of control buffers */
		return -EIO;
	return 0;
}

int ar6000_avail_ev(void *hif_handle)
{
	int i;
	struct net_device *dev;
	void *ar_netif;
	struct ar6_softc *ar;
	int device_index = 0;
	struct htc_init_info  htcInfo;
	struct wireless_dev *wdev;
	int r = 0;
	struct hif_device_os_device_info osDevInfo;
	struct bmi_target_info targ_info;

	memset(&osDevInfo, 0, sizeof(osDevInfo));
	if (hif_config_dev(hif_handle, HIF_DEVICE_GET_OS_DEVICE,
			   &osDevInfo, sizeof(osDevInfo))) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s: Failed to get OS device instance\n", __func__));
		return -ENOMEM;
	}

	for (i = 0; i < MAX_AR6000; i++) {
		if (!ar6000_devices[i])
			break;
	}

	if (i == MAX_AR6000) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000_available: max devices reached\n"));
		return -EINVAL;
	}

	device_index = i;

	wdev = ar6k_cfg80211_init(osDevInfo.pOSDevice);
	if (!wdev) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s: ar6k_cfg80211_init failed\n", __func__));
		return -ENOMEM;
	}
	ar_netif = wdev_priv(wdev);

	if (ar_netif == NULL) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("%s: Can't allocate ar6k priv memory\n", __func__));
		return -ENOMEM;
	}

	memset(ar_netif, 0, sizeof(struct ar6_softc));
	ar = (struct ar6_softc *)ar_netif;

	ar->wdev = wdev;
	wdev->iftype = NL80211_IFTYPE_STATION;

	dev = alloc_netdev_mq(0, "wlan%d", ether_setup, 1);
	if (!dev) {
		printk(KERN_CRIT "AR6K: no memory for network device instance\n");
		ar6k_cfg80211_deinit(ar);
		return -ENOMEM;
	}

	dev->ieee80211_ptr = wdev;
	SET_NETDEV_DEV(dev, wiphy_dev(wdev->wiphy));
	wdev->netdev = dev;
	ar->arNetworkType = INFRA_NETWORK;
	ar->smeState = SME_DISCONNECTED;
	ar->arAutoAuthStage = AUTH_IDLE;
	memcpy(&ar->osDevInfo, &osDevInfo, sizeof(ar->osDevInfo));

	init_netdev(dev);

	ar->arNetDev = dev;
	ar->arHifDevice = hif_handle;
	ar->arWlanState = WLAN_ENABLED;
	ar->arDeviceIndex = device_index;

	ar->arWlanPowerState = WLAN_POWER_STATE_ON;
	ar->arWlanOff = false;
#ifdef CONFIG_PM
	ar->arWowState = WLAN_WOW_STATE_NONE;
	ar->arBTOff = true;
	ar->arBTSharing = WLAN_CONFIG_BT_SHARING;
	ar->arWlanOffConfig = WLAN_CONFIG_WLAN_OFF;
	ar->arSuspendConfig = WLAN_CONFIG_PM_SUSPEND;
	ar->arWow2Config = WLAN_CONFIG_PM_WOW2;
#endif /* CONFIG_PM */

	setup_timer(&ar->arHBChallengeResp.timer, ar6000_detect_error,
		    (unsigned long) dev);

	spin_lock_init(&ar->arLock);
	ar->arHBChallengeResp.seqNum = 0;
	ar->arHBChallengeResp.outstanding = false;
	ar->arHBChallengeResp.missCnt = 0;
	ar->arHBChallengeResp.frequency = AR6000_HB_CHALLENGE_RESP_FREQ_DEFAULT;
	ar->arHBChallengeResp.missThres = AR6000_HB_CHALLENGE_RESP_MISS_THRES_DEFAULT;

	ar6000_init_control_info(ar);
	init_waitqueue_head(&arEvent);
	sema_init(&ar->arSem, 1);
	ar->bIsDestroyProgress = false;

	INIT_HTC_PACKET_QUEUE(&ar->amsdu_rx_buffer_queue);

	setup_timer(&ar->disconnect_timer, disconnect_timer_handler,
		    (unsigned long) dev);

	bmi_init();

	r = bmi_get_target_info(ar->arHifDevice, &targ_info);
	if (r)
		goto avail_ev_failed;

	ar->arVersion.target_ver = targ_info.target_ver;
	ar->arTargetType = targ_info.target_type;

	r = ar6000_configure_target(ar);
	if (r)
		goto avail_ev_failed;

	memset(&htcInfo, 0, sizeof(htcInfo));
	htcInfo.pContext = ar;
	htcInfo.TargetFailure = ar6000_target_failure;

	ar->arHtcTarget = HTCCreate(ar->arHifDevice,&htcInfo);

	if (!ar->arHtcTarget) {
		r = -ENOMEM;
		goto avail_ev_failed;
	}


#ifdef WAPI_ENABLE
	ar->arWapiEnable = 0;
#endif

	if(csumOffload)
		/*if external frame work is also needed, change and use an extended rxMetaVerion*/
		ar->rxMetaVersion = WMI_META_VERSION_2;

	ar->aggr_cntxt = aggr_init(ar6000_alloc_netbufs);
	if (!ar->aggr_cntxt) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s() Failed to initialize aggr.\n", __func__));
		r = -ENOMEM;
		goto avail_ev_failed;
	}

	aggr_register_rx_dispatcher(ar->aggr_cntxt, (void *)dev, ar6000_deliver_frames_to_nw_stack);

	hif_claim_dev(ar->arHifDevice, ar);

	ar6000_devices[device_index] = dev;

	AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("BMI enabled: %d\n", wlaninitmode));
	if ((wlaninitmode == WLAN_INIT_MODE_UDEV) ||
	    (wlaninitmode == WLAN_INIT_MODE_DRV)) {
		r = ath6kl_init_netdev(ar);
		if (r)
			goto avail_ev_failed;
	}

	/* This runs the init function if registered */
	r = register_netdev(dev);
	if (r) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000_avail: register_netdev failed\n"));
		ar6000_destroy(dev, 0);
		return r;
	}

	ar->is_netdev_registered = true;

	AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("ar6000_avail: name=%s hifdevice=0x%lx, dev=0x%lx (%d), ar=0x%lx\n",
				dev->name, (unsigned long)ar->arHifDevice, (unsigned long)dev, device_index,
				(unsigned long)ar));

avail_ev_failed :
	return r;
}

int ar6000_unavail_ev(void *context, void *hif_handle)
{
	struct ar6_softc *ar = (struct ar6_softc *) context;

	ar6000_devices[ar->arDeviceIndex] = NULL;
	ar6000_destroy(ar->arNetDev, 1);

	return 0;
}

int ar6000_init(struct net_device *dev)
{
	struct ar6_softc *ar = ar6k_priv(dev);
	int status;
	s32 timeleft;
	int ret = 0;

	if(!ar)
		return -EIO;

	if (wlaninitmode == WLAN_INIT_MODE_USR ||
	    wlaninitmode == WLAN_INIT_MODE_DRV) {
		if (enablerssicompensation) {
			ar6000_copy_cust_data_from_target(ar);
			read_rssi_compensation_param(ar);
		}
	}

	dev_hold(dev);
	rtnl_unlock();

	/* Do we need to finish the BMI phase */
	if ((wlaninitmode == WLAN_INIT_MODE_USR ||
	    wlaninitmode == WLAN_INIT_MODE_DRV) &&
	    bmi_done(ar->arHifDevice)) {
		ret = -EIO;
		goto ar6000_init_done;
	}

	if (!bypasswmi) {
		/* Indicate that WMI is enabled (although not ready yet) */
		ar->arWmiEnabled = true;
		ar->arWmi = wmi_init((void *) ar);
		if (!ar->arWmi) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s() Failed to initialize WMI.\n", __func__));
			ret = -EIO;
			goto ar6000_init_done;
		}

		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s() Got WMI @ 0x%lx.\n", __func__,
					(unsigned long) ar->arWmi));
	}

	/* the reason we have to wait for the target here is that the driver layer
	 * has to init BMI in order to set the host block size,
	 */
	if (HTCWaitTarget(ar->arHtcTarget)) {
		ret = -EIO;
		goto ar6000_init_done;
	}

	if (ar6k_init_service_ep(ar)) {
		ret = -EIO;
		goto ar6000_init_done;
	}

	/* setup access class priority mappings */
	ar->arAcStreamPriMap[WMM_AC_BK] = 0; /* lowest  */
	ar->arAcStreamPriMap[WMM_AC_BE] = 1; /*         */
	ar->arAcStreamPriMap[WMM_AC_VI] = 2; /*         */
	ar->arAcStreamPriMap[WMM_AC_VO] = 3; /* highest */

	if (regscanmode) {
		u32 param;

		if (bmi_read_memory(ar->arHifDevice,
				    HOST_INTEREST_ITEM_ADDRESS(ar,
				    hi_option_flag),
				    (u8 *)&param,
				    4) != 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("bmi_read_memory forsetting "
					 "regscanmode failed\n"));
			return -EIO;
		}

		if (regscanmode == 1)
			param |= HI_OPTION_SKIP_REG_SCAN;
		else if (regscanmode == 2)
			param |= HI_OPTION_INIT_REG_SCAN;

		if (bmi_write_memory(ar->arHifDevice,
				     HOST_INTEREST_ITEM_ADDRESS(ar,
				     hi_option_flag),
				     (u8 *)&param,
				     4) != 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("bmi_write_memory forsetting "
					 "regscanmode failed\n"));
			return -EIO;
		}
		AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("Regulatory scan mode set\n"));
	}

	/*
	 * give our connected endpoints some buffers
	 */
	ar6000_rx_refill(ar, ar->arControlEp);
	ar6000_rx_refill(ar, arAc2EndpointID(ar,WMM_AC_BE));

	if (bypasswmi) {
		ar6000_rx_refill(ar,arAc2EndpointID(ar,WMM_AC_BK));
		ar6000_rx_refill(ar,arAc2EndpointID(ar,WMM_AC_VI));
		ar6000_rx_refill(ar,arAc2EndpointID(ar,WMM_AC_VO));
	}

	/* allocate some buffers that handle larger AMSDU frames */
	ar6000_refill_amsdu_rxbufs(ar,AR6000_MAX_AMSDU_RX_BUFFERS);

	/* setup credit distribution */
	ath6k_setup_credit_dist(ar->arHtcTarget, &ar->arCreditStateInfo);

	ar6000_cookie_init(ar);

	/* start HTC */
	status = HTCStart(ar->arHtcTarget);

	if (status) {
		if (ar->arWmiEnabled == true) {
			wmi_shutdown(ar->arWmi);
			ar->arWmiEnabled = false;
			ar->arWmi = NULL;
		}
		ar6000_cookie_cleanup(ar);
		ret = -EIO;
		goto ar6000_init_done;
	}

	if (!bypasswmi) {
		/* Wait for Wmi event to be ready */
		timeleft = wait_event_interruptible_timeout(arEvent,
				(ar->arWmiReady == true), wmitimeout * HZ);

		if (ar->arVersion.abi_ver != AR6K_ABI_VERSION) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ABI Version mismatch: Host(0x%x), Target(0x%x)\n",
							AR6K_ABI_VERSION, ar->arVersion.abi_ver));
#ifndef ATH6K_SKIP_ABI_VERSION_CHECK
			ret = -EIO;
			goto ar6000_init_done;
#endif /* ATH6K_SKIP_ABI_VERSION_CHECK */
		}

		if(!timeleft || signal_pending(current))
		{
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("WMI is not ready or wait was interrupted\n"));
			ret = -EIO;
			goto ar6000_init_done;
		}

		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s() WMI is ready\n", __func__));

		/* Communicate the wmi protocol verision to the target */
		if ((ar6000_set_host_app_area(ar)) != 0)
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to set the host app area\n"));

		ar6000_target_config_wlan_params(ar);
	}

	if (bypasswmi) {
		/* for tests like endpoint ping, the MAC address needs to be non-zero otherwise
		 * the data path through a raw socket is disabled */
		dev->dev_addr[0] = 0x00;
		dev->dev_addr[1] = 0x01;
		dev->dev_addr[2] = 0x02;
		dev->dev_addr[3] = 0xAA;
		dev->dev_addr[4] = 0xBB;
		dev->dev_addr[5] = 0xCC;
	}

ar6000_init_done:
	rtnl_lock();
	dev_put(dev);

	return ret;
}

/*
 * We need to differentiate between the surprise and planned removal of the
 * device because of the following consideration:
 * - In case of surprise removal, the hcd already frees up the pending
 *   for the device and hence there is no need to unregister the function
 *   driver inorder to get these requests. For planned removal, the function
 *   driver has to explicitly unregister itself to have the hcd return all the
 *   pending requests before the data structures for the devices are freed up.
 *   Note that as per the current implementation, the function driver will
 *   end up releasing all the devices since there is no API to selectively
 *   release a particular device.
  - Certain commands issued to the target can be skipped for surprise
 *   removal since they will anyway not go through.
 */
void ar6000_destroy(struct net_device *dev, unsigned int unregister)
{
	struct ar6_softc *ar;


	if (!dev || !ar6k_priv(dev)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s(): Failed to get device structure.\n", __func__));
		return;
	}

	ar = ar6k_priv(dev);
	ar->bIsDestroyProgress = true;

	if (down_interruptible(&ar->arSem)) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s(): down_interruptible failed \n", __func__));
		return;
	}

	if (ar->arWlanPowerState != WLAN_POWER_STATE_CUT_PWR)
		ar6000_stop_endpoint(dev, false, true);

	ar->arWlanState = WLAN_DISABLED;
	if (ar->arHtcTarget)
		HTCCleanup(ar->arHtcTarget);

	if (ar->arHifDevice) {
		/*release the device so we do not get called back on remove incase we
		 * we're explicity destroyed by module unload */
		hif_release_dev(ar->arHifDevice);
		hif_shutdown_dev(ar->arHifDevice);
	}
	aggr_module_destroy(ar->aggr_cntxt);

	ar6000_cookie_cleanup(ar);

	ar6000_cleanup_amsdu_rxbufs(ar);

	bmi_cleanup();

#ifdef HTC_RAW_INTERFACE
	if (ar->arRawHtc) {
		kfree(ar->arRawHtc);
		ar->arRawHtc = NULL;
	}
#endif 
	if (unregister && ar->is_netdev_registered) {
		unregister_netdev(dev);
		ar->is_netdev_registered = 0;
	}

	free_netdev(dev);

	ar6k_cfg80211_deinit(ar);

}

static int __init ar6k_init_module(void)
{
	static int probed = 0;
	int r;

	if (probed)
		return -ENODEV;

	probed++;

	r = hif_init();
	if (r)
		return r;

	return 0;
}
module_init(ar6k_init_module);

static void __exit ar6k_cleanup_module(void)
{
	int i = 0;
	struct net_device *ar6000_netdev;

	for (i=0; i < MAX_AR6000; i++) {
		if (ar6000_devices[i] != NULL) {
			ar6000_netdev = ar6000_devices[i];
			ar6000_devices[i] = NULL;
			ar6000_destroy(ar6000_netdev, 1);
		}
	}

	hif_shutdown_dev(NULL);

	AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("ar6000_cleanup: success\n"));
}
module_exit(ar6k_cleanup_module);
