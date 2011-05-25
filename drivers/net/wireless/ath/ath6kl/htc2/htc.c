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

#include "htc_hif.h"

static int HTCWaitforControlMessage(struct htc_target *target, struct htc_packet **ppControlPacket);
static void HTCAsyncRecvScatterCompletion(struct hif_scatter_req *pScatterReq);
static void HTCRecvCompleteHandler(void *Context, struct htc_packet *pPacket);
static void HTCIssueSendBundle(struct htc_endpoint      *pEndpoint,
		struct htc_packet_queue  *pQueue,
		int               *pBundlesSent,
		int               *pTotalBundlesPkts);

/* call the distribute credits callback with the distribution */
#define DO_DISTRIBUTION(t,reason,description,pList) \
{ \
    AR_DEBUG_PRINTF(ATH_DEBUG_SEND, \
        ("  calling distribute function (%s) (dfn:0x%lX, ctxt:0x%lX, dist:0x%lX) \n", \
                (description), \
                (unsigned long)(t)->DistributeCredits, \
                (unsigned long)(t)->pCredDistContext, \
                (unsigned long)pList));\
    (t)->DistributeCredits((t)->pCredDistContext, \
                           (pList),\
                           (reason));\
}

#define DEV_CALC_RECV_PADDED_LEN(pDev, length) (((length) +	\
			(pDev)->BlockMask) & (~((pDev)->BlockMask)))
#define DEV_CALC_SEND_PADDED_LEN(pDev, length) DEV_CALC_RECV_PADDED_LEN(pDev,length)

static void DumpCreditDist(struct htc_endpoint_credit_dist *pEPDist)
{
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, ("--- EP : %d  ServiceID: 0x%X    --------------\n",
				pEPDist->Endpoint, pEPDist->ServiceID));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" this:0x%lX next:0x%lX prev:0x%lX\n",
				(unsigned long)pEPDist, (unsigned long)pEPDist->pNext, (unsigned long)pEPDist->pPrev));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" DistFlags          : 0x%X \n", pEPDist->DistFlags));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxCreditsNorm      : %d \n", pEPDist->TxCreditsNorm));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxCreditsMin       : %d \n", pEPDist->TxCreditsMin));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxCredits          : %d \n", pEPDist->TxCredits));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxCreditsAssigned  : %d \n", pEPDist->TxCreditsAssigned));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxCreditsSeek      : %d \n", pEPDist->TxCreditsSeek));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxCreditSize       : %d \n", pEPDist->TxCreditSize));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxCreditsPerMaxMsg : %d \n", pEPDist->TxCreditsPerMaxMsg));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxCreditsToDist    : %d \n", pEPDist->TxCreditsToDist));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, (" TxQueueDepth       : %d \n",
				HTC_PACKET_QUEUE_DEPTH(&((struct htc_endpoint *)pEPDist->pHTCReserved)->TxQueue)));
	AR_DEBUG_PRINTF(ATH_DEBUG_ANY, ("----------------------------------------------------\n"));
}

static void DumpCreditDistStates(struct htc_target *target)
{
	struct htc_endpoint_credit_dist *pEPList = target->EpCreditDistributionListHead;

	while (pEPList) {
		DumpCreditDist(pEPList);
		pEPList = pEPList->pNext;
	}

	if (target->DistributeCredits) {
		DO_DISTRIBUTION(target,
				HTC_DUMP_CREDIT_STATE,
				"Dump State",
				NULL);
	}
}

#ifdef ATH_DEBUG_MODULE
static struct ath_debug_mask_description g_HTCDebugDescription[] = {
    { ATH_DEBUG_SEND , "Send"},
    { ATH_DEBUG_RECV , "Recv"},
    { ATH_DEBUG_SYNC , "Sync"},
    { ATH_DEBUG_DUMP , "Dump Data (RX or TX)"},
    { ATH_DEBUG_IRQ  , "Interrupt Processing"}
};

ATH_DEBUG_INSTANTIATE_MODULE_VAR(htc,
                                 "htc",
                                 "Host Target Communications",
                                 ATH_DEBUG_MASK_DEFAULTS,
                                 ATH_DEBUG_DESCRIPTION_COUNT(g_HTCDebugDescription),
                                 g_HTCDebugDescription);

#endif

static void htc_reclaim_txctrl_buf(struct htc_target *target,
				   struct htc_packet *pkt)
{
	spin_lock_bh(&target->HTCLock);
	list_add_tail(&pkt->list, &target->free_ctrl_txbuf);
	spin_unlock_bh(&target->HTCLock);
}

static struct htc_packet *htc_get_control_buf(struct htc_target *target,
						bool tx)
{
	struct htc_packet *packet = NULL;
	struct list_head *buf_list;

	buf_list = tx ? &target->free_ctrl_txbuf :
		&target->free_ctrl_rxbuf;

	spin_lock_bh(&target->HTCLock);

	if (list_empty(buf_list)) {
		spin_unlock_bh(&target->HTCLock);
		return NULL;
	}

	packet = list_first_entry(buf_list, struct htc_packet, list);
	list_del(&packet->list);
	spin_unlock_bh(&target->HTCLock);

	if (tx)
		packet->pBuffer = packet->pBufferStart + HTC_HDR_LENGTH;

	return packet;
}

static void CompleteSentPacket(struct htc_target *target, struct htc_endpoint *pEndpoint, struct htc_packet *pPacket)
{
	pPacket->Completion = NULL;

	if (pPacket->Status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("CompleteSentPacket: request failed (status:%d, ep:%d, length:%d creds:%d) \n",
				 pPacket->Status, pPacket->Endpoint, pPacket->ActualLength, pPacket->PktInfo.AsTx.CreditsUsed));
		/* on failure to submit, reclaim credits for this packet */
		spin_lock_bh(&target->HTCRxLock);
		pEndpoint->CreditDist.TxCreditsToDist += pPacket->PktInfo.AsTx.CreditsUsed;
		pEndpoint->CreditDist.TxQueueDepth = HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue);
		DO_DISTRIBUTION(target,
				HTC_CREDIT_DIST_SEND_COMPLETE,
				"Send Complete",
				target->EpCreditDistributionListHead->pNext);
		spin_unlock_bh(&target->HTCRxLock);
	}
	pPacket->pBuffer += HTC_HDR_LENGTH;
}

static void DoSendCompletion(struct htc_endpoint       *pEndpoint,
		struct htc_packet_queue   *pQueueToIndicate)
{
	if (HTC_QUEUE_EMPTY(pQueueToIndicate))
		return;

	if (pEndpoint->EpCallBacks.EpTxCompleteMultiple != NULL) {
		AR_DEBUG_PRINTF(ATH_DEBUG_SEND, (" HTC calling ep %d, send complete multiple callback (%d pkts) \n",
					pEndpoint->Id, HTC_PACKET_QUEUE_DEPTH(pQueueToIndicate)));
		pEndpoint->EpCallBacks.EpTxCompleteMultiple(pEndpoint->EpCallBacks.pContext,
				pQueueToIndicate);
		/* all packets are now owned by the callback, reset queue to be safe */
		INIT_HTC_PACKET_QUEUE(pQueueToIndicate);
	} else {
		struct htc_packet *pPacket;
		/* using legacy EpTxComplete */
		do {
			pPacket = HTC_PACKET_DEQUEUE(pQueueToIndicate);
			AR_DEBUG_PRINTF(ATH_DEBUG_SEND, (" HTC calling ep %d send complete callback on packet 0x%lX \n",
						pEndpoint->Id, (unsigned long)(pPacket)));
			if ( pEndpoint->EpCallBacks.EpTxComplete)
				pEndpoint->EpCallBacks.EpTxComplete(pEndpoint->EpCallBacks.pContext, pPacket);
		} while (!HTC_QUEUE_EMPTY(pQueueToIndicate));
	}
}

static void HTCSendPktCompletionHandler(void *Context, struct htc_packet *pPacket)
{
    struct htc_target      *target = (struct htc_target *)Context;
    struct htc_endpoint    *pEndpoint = &target->EndPoint[pPacket->Endpoint];
    struct htc_packet_queue container;

    CompleteSentPacket(target,pEndpoint,pPacket);
    INIT_HTC_PACKET_QUEUE_AND_ADD(&container,pPacket);
        /* do completion */
    DoSendCompletion(pEndpoint,&container);
}

static int HTCIssueSend(struct htc_target *target, struct htc_packet *pPacket)
{
	int status;
	bool   sync = false;
	u32 padded_len, send_len;

	if (!pPacket->Completion)
		sync = true;

	send_len = pPacket->ActualLength + HTC_HDR_LENGTH;

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,
			("+-HTCIssueSend: transmit length : %d (%s) \n",
			 send_len,
			 sync ? "SYNC" : "ASYNC" ));

	padded_len = DEV_CALC_SEND_PADDED_LEN(target->Device, send_len);

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,
			("DevSendPacket, Padded Length: %d Mbox:0x%X (mode:%s)\n",
			 padded_len,
			 target->Device->MailBoxInfo.MboxAddresses[HTC_MAILBOX],
			 sync ? "SYNC" : "ASYNC"));

	status = hif_read_write(target->Device->HIFDevice,
			target->Device->MailBoxInfo.MboxAddresses[HTC_MAILBOX],
			pPacket->pBuffer,
			padded_len,
			sync ? HIF_WR_SYNC_BLOCK_INC : HIF_WR_ASYNC_BLOCK_INC,
			sync ? NULL : pPacket);

	if (sync) {
		pPacket->Status = status;
		pPacket->pBuffer += HTC_HDR_LENGTH;
	} else {
		if (status == A_PENDING)
			status = 0;
	}

	return status;
}

static void GetHTCSendPackets(struct htc_target        *target,
		struct htc_endpoint      *pEndpoint,
		struct htc_packet_queue  *pQueue)
{
	int          creditsRequired;
	int          remainder;
	u8 sendFlags;
	struct htc_packet   *pPacket;
	unsigned int transferLength;

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("+GetHTCSendPackets \n"));

	while (true) {

		sendFlags = 0;
		pPacket = HTC_GET_PKT_AT_HEAD(&pEndpoint->TxQueue);
		if (pPacket == NULL)
			break;

		AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Got head packet:0x%lX , Queue Depth: %d\n",
					(unsigned long)pPacket, HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)));

		transferLength = DEV_CALC_SEND_PADDED_LEN(target->Device, pPacket->ActualLength + HTC_HDR_LENGTH);

		if (transferLength <= target->TargetCreditSize)
			creditsRequired = 1;
		else {
			/* figure out how many credits this message requires */
			creditsRequired = transferLength / target->TargetCreditSize;
			remainder = transferLength % target->TargetCreditSize;

			if (remainder) {
				creditsRequired++;
			}
		}

		AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Creds Required:%d   Got:%d\n",
					creditsRequired, pEndpoint->CreditDist.TxCredits));

		if (pEndpoint->CreditDist.TxCredits < creditsRequired) {

			/* not enough credits */
			if (pPacket->Endpoint == ENDPOINT_0) {
				/* leave it in the queue */
				break;
			}
			/* invoke the registered distribution function only if this is not
			 * endpoint 0, we let the driver layer provide more credits if it can.
			 * We pass the credit distribution list starting at the endpoint in question
			 * */

			/* set how many credits we need  */
			pEndpoint->CreditDist.TxCreditsSeek =
				creditsRequired - pEndpoint->CreditDist.TxCredits;
			DO_DISTRIBUTION(target,
					HTC_CREDIT_DIST_SEEK_CREDITS,
					"Seek Credits",
					&pEndpoint->CreditDist);
			pEndpoint->CreditDist.TxCreditsSeek = 0;

			if (pEndpoint->CreditDist.TxCredits < creditsRequired) {
				/* still not enough credits to send, leave packet in the queue */
				AR_DEBUG_PRINTF(ATH_DEBUG_SEND,
						(" Not enough credits for ep %d leaving packet in queue..\n",
						 pPacket->Endpoint));
				break;
			}

		}

		pEndpoint->CreditDist.TxCredits -= creditsRequired;
		INC_HTC_EP_STAT(pEndpoint, TxCreditsConsummed, creditsRequired);

		/* check if we need credits back from the target */
		if (pEndpoint->CreditDist.TxCredits < pEndpoint->CreditDist.TxCreditsPerMaxMsg) {
			/* we are getting low on credits, see if we can ask for more from the distribution function */
			pEndpoint->CreditDist.TxCreditsSeek =
				pEndpoint->CreditDist.TxCreditsPerMaxMsg - pEndpoint->CreditDist.TxCredits;

			DO_DISTRIBUTION(target,
					HTC_CREDIT_DIST_SEEK_CREDITS,
					"Seek Credits",
					&pEndpoint->CreditDist);

			pEndpoint->CreditDist.TxCreditsSeek = 0;
			/* see if we were successful in getting more */
			if (pEndpoint->CreditDist.TxCredits < pEndpoint->CreditDist.TxCreditsPerMaxMsg) {
				/* tell the target we need credits ASAP! */
				sendFlags |= HTC_FLAGS_NEED_CREDIT_UPDATE;
				INC_HTC_EP_STAT(pEndpoint, TxCreditLowIndications, 1);
				AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Host Needs Credits  \n"));
			}
		}

		/* now we can fully dequeue */
		pPacket = HTC_PACKET_DEQUEUE(&pEndpoint->TxQueue);
		/* save the number of credits this packet consumed */
		pPacket->PktInfo.AsTx.CreditsUsed = creditsRequired;
		/* all TX packets are handled asynchronously */
		pPacket->Completion = HTCSendPktCompletionHandler;
		pPacket->pContext = target;
		INC_HTC_EP_STAT(pEndpoint, TxIssued, 1);
		/* save send flags */
		pPacket->PktInfo.AsTx.SendFlags = sendFlags;
		pPacket->PktInfo.AsTx.SeqNo = pEndpoint->SeqNo;
		pEndpoint->SeqNo++;
		/* queue this packet into the caller's queue */
		HTC_PACKET_ENQUEUE(pQueue,pPacket);
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-GetHTCSendPackets \n"));

}

static bool HTCTrySend(struct htc_target *target,
		       struct htc_endpoint *pEndpoint,
		       struct htc_packet_queue *pCallersSendQueue)
{
	struct htc_packet_queue sendQueue; /* temp queue to hold packets at various stages */
	struct htc_packet *pPacket;
	int bundlesSent;
	int pktsInBundles;
	int overflow;
	bool ret = true;

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("+HTCTrySend (Queue:0x%lX Depth:%d)\n",
				(unsigned long)pCallersSendQueue,
				(pCallersSendQueue == NULL) ? 0 : HTC_PACKET_QUEUE_DEPTH(pCallersSendQueue)));

	/* init the local send queue */
	INIT_HTC_PACKET_QUEUE(&sendQueue);

	if (!pCallersSendQueue)
		goto fail_tx;

	if (HTC_QUEUE_EMPTY(pCallersSendQueue)) {
		ret = false;
		goto fail_tx;
	}

	if (HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue) >= pEndpoint->MaxTxQueueDepth)
		overflow = HTC_PACKET_QUEUE_DEPTH(pCallersSendQueue);
	else {
		overflow = HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue);
		overflow += HTC_PACKET_QUEUE_DEPTH(pCallersSendQueue);
		overflow -= pEndpoint->MaxTxQueueDepth;
	}

	if (overflow > 0)
		AR_DEBUG_PRINTF(ATH_DEBUG_SEND,
				(" Endpoint %d, TX queue will overflow :%d , Tx Depth:%d, Max:%d \n",
				 pEndpoint->Id, overflow, HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue),
				 pEndpoint->MaxTxQueueDepth));

	if ((overflow <= 0) || (!pEndpoint->EpCallBacks.EpSendFull)) {
		HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(&sendQueue, pCallersSendQueue);
	} else {
		int i;
		int goodPkts = HTC_PACKET_QUEUE_DEPTH(pCallersSendQueue) - overflow;

		BUG_ON(goodPkts < 0);

		for (i = 0; i < goodPkts; i++) {
			pPacket = HTC_PACKET_DEQUEUE(pCallersSendQueue);
			HTC_PACKET_ENQUEUE(&sendQueue,pPacket);
		}

		ITERATE_OVER_LIST_ALLOW_REMOVE(&pCallersSendQueue->QueueHead, pPacket, struct htc_packet, ListLink) {

			AR_DEBUG_PRINTF(ATH_DEBUG_SEND, (" Indicating overflowed TX packet: 0x%lX \n",
						(unsigned long)pPacket));
			if (pEndpoint->EpCallBacks.EpSendFull(pEndpoint->EpCallBacks.pContext,
						pPacket) == HTC_SEND_FULL_DROP) {
				INC_HTC_EP_STAT(pEndpoint, TxDropped, 1);
			} else {
				HTC_PACKET_REMOVE(pCallersSendQueue, pPacket);
				HTC_PACKET_ENQUEUE(&sendQueue,pPacket);
			}

		} ITERATE_END;

		if (HTC_QUEUE_EMPTY(&sendQueue))
			ret = false;
	}


fail_tx:
	if (!ret) {
		AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-HTCTrySend:  \n"));
		return ret;
	}

	spin_lock_bh(&target->HTCTxLock);

	if (!HTC_QUEUE_EMPTY(&sendQueue)) {
		/* transfer packets */
		HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(&pEndpoint->TxQueue,&sendQueue);
		A_ASSERT(HTC_QUEUE_EMPTY(&sendQueue));
		INIT_HTC_PACKET_QUEUE(&sendQueue);
	}

	pEndpoint->TxProcessCount++;
	if (pEndpoint->TxProcessCount > 1) {
		pEndpoint->TxProcessCount--;
		spin_unlock_bh(&target->HTCTxLock);
		AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-HTCTrySend (busy) \n"));
		return true;
	}

/***** beyond this point only 1 thread may enter ******/

/* now drain the endpoint TX queue for transmission as long as we have enough
 * credits */
	while (true) {

		if (HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue) == 0)
			break;

		GetHTCSendPackets(target, pEndpoint, &sendQueue);

		if (HTC_PACKET_QUEUE_DEPTH(&sendQueue) == 0)
			break;

		spin_unlock_bh(&target->HTCTxLock);

		bundlesSent = 0;
		pktsInBundles = 0;

		while (true) {

			/* try to send a bundle on each pass */
			if ((target->SendBundlingEnabled) &&
					(HTC_PACKET_QUEUE_DEPTH(&sendQueue) >= HTC_MIN_HTC_MSGS_TO_BUNDLE)) {
				int temp1,temp2;

				HTCIssueSendBundle(pEndpoint, &sendQueue, &temp1, &temp2);
				bundlesSent += temp1;
				pktsInBundles += temp2;
			}

			pPacket = HTC_PACKET_DEQUEUE(&sendQueue);
			if (!pPacket)
				break;

			HTC_PREPARE_SEND_PKT(pPacket,
					pPacket->PktInfo.AsTx.SendFlags,
					0,
					pPacket->PktInfo.AsTx.SeqNo);
			HTCIssueSend(target, pPacket);

		}

		spin_lock_bh(&target->HTCTxLock);

		INC_HTC_EP_STAT(pEndpoint, TxBundles, bundlesSent);
		INC_HTC_EP_STAT(pEndpoint, TxPacketsBundled, pktsInBundles);

	}

	pEndpoint->TxProcessCount = 0;
	spin_unlock_bh(&target->HTCTxLock);

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-HTCTrySend:  \n"));

	return true;
}

static void HTCCheckEndpointTxQueues(struct htc_target *target)
{
	struct htc_endpoint                *pEndpoint;
	struct htc_endpoint_credit_dist    *pDistItem;

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("+HTCCheckEndpointTxQueues \n"));
	pDistItem = target->EpCreditDistributionListHead;

	/* run through the credit distribution list to see
	 * if there are packets queued
	 * NOTE: no locks need to be taken since the distribution list
	 * is not dynamic (cannot be re-ordered) and we are not modifying any state */
	while (pDistItem != NULL) {
		pEndpoint = (struct htc_endpoint *)pDistItem->pHTCReserved;

		if (HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue) > 0) {
			AR_DEBUG_PRINTF(ATH_DEBUG_SEND, (" Ep %d has %d credits and %d Packets in TX Queue \n",
						pDistItem->Endpoint, pEndpoint->CreditDist.TxCredits, HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue)));
			/* try to start the stalled queue, this list is ordered by priority.
			 * Highest priority queue get's processed first, if there are credits available the
			 * highest priority queue will get a chance to reclaim credits from lower priority
			 * ones */
			HTCTrySend(target, pEndpoint, NULL);
		}

		pDistItem = pDistItem->pNext;
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("-HTCCheckEndpointTxQueues \n"));
}

static int HTCSendSetupComplete(struct htc_target *target)
{
	struct htc_packet *pSendPacket = NULL;
	int status;

	pSendPacket = htc_get_control_buf(target, true);

	if (NULL == pSendPacket) {
		status = -ENOMEM;
		goto fail_alloc_rx;
	}

	if (target->HTCTargetVersion >= HTC_VERSION_2P1) {
		struct htc_setup_comp_ext_msg *pSetupCompleteEx;
		u32 setupFlags = 0;

		pSetupCompleteEx = (struct htc_setup_comp_ext_msg *)pSendPacket->pBuffer;
		memset(pSetupCompleteEx, 0, sizeof(struct htc_setup_comp_ext_msg));
		pSetupCompleteEx->MessageID = HTC_MSG_SETUP_COMPLETE_EX_ID;
		if (target->MaxMsgPerBundle > 0) {
			/* Indicate HTC bundling to the target */
			setupFlags |= HTC_SETUP_COMPLETE_FLAGS_ENABLE_BUNDLE_RECV;
			pSetupCompleteEx->MaxMsgsPerBundledRecv = target->MaxMsgPerBundle;
		}
		memcpy(&pSetupCompleteEx->SetupFlags, &setupFlags, sizeof(pSetupCompleteEx->SetupFlags));
		SET_HTC_PACKET_INFO_TX(pSendPacket,
				NULL,
				(u8 *)pSetupCompleteEx,
				sizeof(struct htc_setup_comp_ext_msg),
				ENDPOINT_0,
				HTC_SERVICE_TX_PACKET_TAG);

	}  else {
		struct htc_setup_comp_msg *pSetupComplete;
		pSetupComplete = (struct htc_setup_comp_msg *)pSendPacket->pBuffer;
		memset(pSetupComplete, 0, sizeof(struct htc_setup_comp_msg));
		pSetupComplete->MessageID = HTC_MSG_SETUP_COMPLETE_ID;
		SET_HTC_PACKET_INFO_TX(pSendPacket,
				NULL,
				(u8 *)pSetupComplete,
				sizeof(struct htc_setup_comp_msg),
				ENDPOINT_0,
				HTC_SERVICE_TX_PACKET_TAG);
	}

	/* we want synchronous operation */
	pSendPacket->Completion = NULL;
	HTC_PREPARE_SEND_PKT(pSendPacket,0,0,0);
	status = HTCIssueSend(target,pSendPacket);


fail_alloc_rx:
	if (pSendPacket != NULL)
		htc_reclaim_txctrl_buf(target, pSendPacket);

	return status;
}

static void reclaim_rx_ctrl_buf(struct htc_target *target,
				struct htc_packet *packet)
{
	spin_lock_bh(&target->HTCLock);
	list_add_tail(&packet->list, &target->free_ctrl_rxbuf);
	spin_unlock_bh(&target->HTCLock);
}

int HTCConnectService(void *HTCHandle,
		struct htc_service_connect_req  *pConnectReq,
		struct htc_service_connect_resp *pConnectResp)
{
	struct htc_target *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	int status = 0;
	struct htc_packet *pRecvPacket = NULL;
	struct htc_packet *pSendPacket = NULL;
	struct htc_conn_service_resp *pResponseMsg;
	struct htc_conn_service_msg *pConnectMsg;
	enum htc_endpoint_id assignedEndpoint = ENDPOINT_MAX;
	struct htc_endpoint *pEndpoint;
	unsigned int maxMsgSize = 0;

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+HTCConnectService, target:0x%lX SvcID:0x%X \n",
				(unsigned long)target, pConnectReq->ServiceID));

	if (HTC_CTRL_RSVD_SVC == pConnectReq->ServiceID) {
		/* special case for pseudo control service */
		assignedEndpoint = ENDPOINT_0;
		maxMsgSize = HTC_MAX_CONTROL_MESSAGE_LENGTH;
	} else {
		/* allocate a packet to send to the target */
		pSendPacket = htc_get_control_buf(target, true);

		if (NULL == pSendPacket) {
			status = A_NO_MEMORY;
			goto fail_tx;
		}

		pConnectMsg = (struct htc_conn_service_msg *)pSendPacket->pBuffer;
		BUG_ON(pConnectMsg == NULL);
		memset(pConnectMsg, 0, sizeof(struct htc_conn_service_msg));
		pConnectMsg->MessageID = HTC_MSG_CONNECT_SERVICE_ID;
		pConnectMsg->ServiceID = pConnectReq->ServiceID;
		pConnectMsg->ConnectionFlags = pConnectReq->ConnectionFlags;

		if ((pConnectReq->pMetaData != NULL) &&
				(pConnectReq->MetaDataLength <= HTC_SERVICE_META_DATA_MAX_LENGTH)) {
			/* copy meta data into message buffer (after header ) */
			memcpy((u8 *)pConnectMsg + sizeof(struct htc_conn_service_msg),
					pConnectReq->pMetaData,
					pConnectReq->MetaDataLength);
			pConnectMsg->ServiceMetaLength = pConnectReq->MetaDataLength;
		}

		SET_HTC_PACKET_INFO_TX(pSendPacket,
				NULL,
				(u8 *)pConnectMsg,
				sizeof(struct htc_conn_service_msg) + pConnectMsg->ServiceMetaLength,
				ENDPOINT_0,
				HTC_SERVICE_TX_PACKET_TAG);

		/* we want synchronous operation */
		pSendPacket->Completion = NULL;
		HTC_PREPARE_SEND_PKT(pSendPacket,0,0,0);
		status = HTCIssueSend(target,pSendPacket);

		if (status)
			goto fail_tx;

		/* wait for response */
		status = HTCWaitforControlMessage(target, &pRecvPacket);

		if (status)
			goto fail_tx;

		/* we controlled the buffer creation so it has to be properly aligned */
		pResponseMsg = (struct htc_conn_service_resp *)pRecvPacket->pBuffer;

		if ((pResponseMsg->MessageID != HTC_MSG_CONNECT_SERVICE_RESPONSE_ID) ||
				(pRecvPacket->ActualLength < sizeof(struct htc_conn_service_resp))) {
			status = -ENOMEM;
			goto fail_tx;
		}

		pConnectResp->ConnectRespCode = pResponseMsg->Status;
		/* check response status */
		if (pResponseMsg->Status != HTC_SERVICE_SUCCESS) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					(" Target failed service 0x%X connect request (status:%d)\n",
					 pResponseMsg->ServiceID, pResponseMsg->Status));
			status = -ENOMEM;
			goto fail_tx;
		}

		assignedEndpoint = (enum htc_endpoint_id) pResponseMsg->EndpointID;
		maxMsgSize = pResponseMsg->MaxMsgSize;

		if ((pConnectResp->pMetaData != NULL) &&
				(pResponseMsg->ServiceMetaLength > 0) &&
				(pResponseMsg->ServiceMetaLength <= HTC_SERVICE_META_DATA_MAX_LENGTH)) {
			/* caller supplied a buffer and the target responded with data */
			int copyLength = min((int)pConnectResp->BufferLength, (int)pResponseMsg->ServiceMetaLength);
			/* copy the meta data */
			memcpy(pConnectResp->pMetaData,
					((u8 *)pResponseMsg) + sizeof(struct htc_conn_service_resp),
					copyLength);
			pConnectResp->ActualLength = copyLength;
		}

	}

	/* the rest of these are parameter checks so set the error status */
	status = -ENOMEM;

	if (assignedEndpoint >= ENDPOINT_MAX)
		goto fail_tx;

	if (!maxMsgSize)
		goto fail_tx;

	pEndpoint = &target->EndPoint[assignedEndpoint];
	pEndpoint->Id = assignedEndpoint;
	if (pEndpoint->ServiceID != 0)
		goto fail_tx;

	/* return assigned endpoint to caller */
	pConnectResp->Endpoint = assignedEndpoint;
	pConnectResp->MaxMsgLength = maxMsgSize;

	/* setup the endpoint */
	pEndpoint->ServiceID = pConnectReq->ServiceID; /* this marks the endpoint in use */
	pEndpoint->MaxTxQueueDepth = pConnectReq->MaxSendQueueDepth;
	pEndpoint->MaxMsgLength = maxMsgSize;
	/* copy all the callbacks */
	pEndpoint->EpCallBacks = pConnectReq->EpCallbacks;
	/* set the credit distribution info for this endpoint, this information is
	 * passed back to the credit distribution callback function */
	pEndpoint->CreditDist.ServiceID = pConnectReq->ServiceID;
	pEndpoint->CreditDist.pHTCReserved = pEndpoint;
	pEndpoint->CreditDist.Endpoint = assignedEndpoint;
	pEndpoint->CreditDist.TxCreditSize = target->TargetCreditSize;

	if (pConnectReq->MaxSendMsgSize != 0) {
		/* override TxCreditsPerMaxMsg calculation, this optimizes the credit-low indications
		 * since the host will actually issue smaller messages in the Send path */
		if (pConnectReq->MaxSendMsgSize > maxMsgSize)
			goto fail_tx;

		pEndpoint->CreditDist.TxCreditsPerMaxMsg = pConnectReq->MaxSendMsgSize / target->TargetCreditSize;
	} else {
		pEndpoint->CreditDist.TxCreditsPerMaxMsg = maxMsgSize / target->TargetCreditSize;
	}

	if (0 == pEndpoint->CreditDist.TxCreditsPerMaxMsg) {
		pEndpoint->CreditDist.TxCreditsPerMaxMsg = 1;
	}

	/* save local connection flags */
	pEndpoint->LocalConnectionFlags = pConnectReq->LocalConnectionFlags;

	status = 0;

fail_tx:
	if (pSendPacket != NULL)
		htc_reclaim_txctrl_buf(target, pSendPacket);

	if (pRecvPacket != NULL) {
		HTC_PACKET_RESET_RX(pRecvPacket);
		reclaim_rx_ctrl_buf(target,pRecvPacket);
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-HTCConnectService \n"));

	return status;
}

static void AddToEndpointDistList(struct htc_target *target,
				  struct htc_endpoint_credit_dist *pEpDist)
{
    struct htc_endpoint_credit_dist *pCurEntry,*pLastEntry;

    if (NULL == target->EpCreditDistributionListHead) {
        target->EpCreditDistributionListHead = pEpDist;
        pEpDist->pNext = NULL;
        pEpDist->pPrev = NULL;
        return;
    }

        /* queue to the end of the list, this does not have to be very
         * fast since this list is built at startup time */
    pCurEntry = target->EpCreditDistributionListHead;

    while (pCurEntry) {
        pLastEntry = pCurEntry;
        pCurEntry = pCurEntry->pNext;
    }

    pLastEntry->pNext = pEpDist;
    pEpDist->pPrev = pLastEntry;
    pEpDist->pNext = NULL;
}

static void HTCDefaultCreditInit(void *Context,
                                 struct htc_endpoint_credit_dist *pEPList,
                                 int TotalCredits)
{
    struct htc_endpoint_credit_dist *pCurEpDist;
    int totalEps = 0;
    int creditsPerEndpoint;

    pCurEpDist = pEPList;

    while (pCurEpDist != NULL) {
        pCurEpDist = pCurEpDist->pNext;
        totalEps++;
    }

        /* even distribution */
    creditsPerEndpoint = TotalCredits/totalEps;

    pCurEpDist = pEPList;

    while (pCurEpDist != NULL) {

        if (creditsPerEndpoint < pCurEpDist->TxCreditsPerMaxMsg)
		break;

	pCurEpDist->TxCreditsMin = pCurEpDist->TxCreditsPerMaxMsg;
        pCurEpDist->TxCreditsNorm = 0xFFFF;
        pCurEpDist->TxCredits = creditsPerEndpoint;
        pCurEpDist->TxCreditsAssigned = creditsPerEndpoint;
        pCurEpDist = pCurEpDist->pNext;
    }

}

static void HTCDefaultCreditDist(void *Context,
				 struct htc_endpoint_credit_dist *pEPDistList,
				 enum htc_credit_dist_reason Reason)
{
	struct htc_endpoint_credit_dist *pCurEpDist;

	if (Reason == HTC_CREDIT_DIST_SEND_COMPLETE) {
		pCurEpDist = pEPDistList;
		while (pCurEpDist) {
			if (pCurEpDist->TxCreditsToDist > 0) {
				/* just give the endpoint back the credits */
				pCurEpDist->TxCredits += pCurEpDist->TxCreditsToDist;
				pCurEpDist->TxCreditsToDist = 0;
			}
			pCurEpDist = pCurEpDist->pNext;
		}
	}
}

void HTCSetCreditDistribution(void *HTCHandle,
                              void *pCreditDistContext,
                              void (*CreditDistFunc) (void *,struct htc_endpoint_credit_dist *,
			      enum htc_credit_dist_reason),
                              void (*CreditInitFunc) (void *,struct htc_endpoint_credit_dist *,
			      int),
                              u16 ServicePriorityOrder[],
                              int ListLength)
{
	struct htc_target *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	int i;
	int ep;

	if (CreditInitFunc != NULL) {
		target->InitCredits = CreditInitFunc;
		BUG_ON(CreditDistFunc == NULL);
		target->DistributeCredits = CreditDistFunc;
		target->pCredDistContext = pCreditDistContext;
	} else {
		BUG_ON(CreditDistFunc != NULL);
		target->InitCredits = HTCDefaultCreditInit;
		target->DistributeCredits = HTCDefaultCreditDist;
		target->pCredDistContext = target;
	}

	AddToEndpointDistList(target, &target->EndPoint[ENDPOINT_0].CreditDist);

	for (i = 0; i < ListLength; i++) {
		for (ep = ENDPOINT_1; ep < ENDPOINT_MAX; ep++) {
			if (target->EndPoint[ep].ServiceID == ServicePriorityOrder[i]) {
				AddToEndpointDistList(target, &target->EndPoint[ep].CreditDist);
				break;
			}
		}
		AR_DEBUG_ASSERT(ep < ENDPOINT_MAX);
	}

}

static void HTCAsyncSendScatterCompletion(struct hif_scatter_req *pScatterReq)
{
	int                 i;
	struct htc_packet          *pPacket;
	struct htc_endpoint        *pEndpoint = (struct htc_endpoint *)pScatterReq->Context;
	struct htc_target          *target = (struct htc_target *)pEndpoint->target;
	int            status = 0;
	struct htc_packet_queue    sendCompletes;

	INIT_HTC_PACKET_QUEUE(&sendCompletes);

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("+HTCAsyncSendScatterCompletion  TotLen: %d  Entries: %d\n",
				pScatterReq->TotalLength, pScatterReq->ValidScatterEntries));

	DEV_FINISH_SCATTER_OPERATION(pScatterReq);

	if (pScatterReq->CompletionStatus) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("** Send Scatter Request Failed: %d \n",pScatterReq->CompletionStatus));
		status = A_ERROR;
	}

	/* walk through the scatter list and process */
	for (i = 0; i < pScatterReq->ValidScatterEntries; i++) {
		pPacket = (struct htc_packet *)(pScatterReq->ScatterList[i].pCallerContexts[0]);
		A_ASSERT(pPacket != NULL);
		pPacket->Status = status;
		CompleteSentPacket(target,pEndpoint,pPacket);
		/* add it to the completion queue */
		HTC_PACKET_ENQUEUE(&sendCompletes, pPacket);
	}

	/* free scatter request */
	DEV_FREE_SCATTER_REQ(target->Device,pScatterReq);
	/* complete all packets */
	DoSendCompletion(pEndpoint,&sendCompletes);

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-HTCAsyncSendScatterCompletion \n"));
}

    /* drain a queue and send as bundles
     * this function may return without fully draining the queue under the following conditions :
     *    - scatter resources are exhausted
     *    - a message that will consume a partial credit will stop the bundling process early
     *    - we drop below the minimum number of messages for a bundle
     * */
static void HTCIssueSendBundle(struct htc_endpoint      *pEndpoint,
		struct htc_packet_queue  *pQueue,
		int               *pBundlesSent,
		int               *pTotalBundlesPkts)
{
	int                 pktsToScatter;
	unsigned int        scatterSpaceRemaining;
	struct hif_scatter_req     *pScatterReq = NULL;
	int                 i, packetsInScatterReq;
	unsigned int        transferLength;
	struct htc_packet          *pPacket;
	bool              done = false;
	int                 bundlesSent = 0;
	int                 totalPktsInBundle = 0;
	struct htc_target          *target = pEndpoint->target;
	int                 creditRemainder = 0;
	int                 creditPad;

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("+HTCIssueSendBundle \n"));

	while (!done) {

		pktsToScatter = HTC_PACKET_QUEUE_DEPTH(pQueue);
		pktsToScatter = min(pktsToScatter, target->MaxMsgPerBundle);

		if (pktsToScatter < HTC_MIN_HTC_MSGS_TO_BUNDLE) {
			/* not enough to bundle */
			break;
		}

		pScatterReq = DEV_ALLOC_SCATTER_REQ(target->Device);

		if (pScatterReq == NULL) {
			/* no scatter resources  */
			AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("   No more scatter resources \n"));
			break;
		}

		AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("   pkts to scatter: %d \n", pktsToScatter));

		pScatterReq->TotalLength = 0;
		pScatterReq->ValidScatterEntries = 0;

		packetsInScatterReq = 0;
		scatterSpaceRemaining = DEV_GET_MAX_BUNDLE_SEND_LENGTH(target->Device);

		for (i = 0; i < pktsToScatter; i++) {

			pScatterReq->ScatterList[i].pCallerContexts[0] = NULL;

			pPacket = HTC_GET_PKT_AT_HEAD(pQueue);
			if (pPacket == NULL) {
				A_ASSERT(false);
				break;
			}

			creditPad = 0;
			transferLength = DEV_CALC_SEND_PADDED_LEN(target->Device,
					pPacket->ActualLength + HTC_HDR_LENGTH);
			/* see if the padded transfer length falls on a credit boundary */
			creditRemainder = transferLength % target->TargetCreditSize;

			if (creditRemainder != 0) {
				/* the transfer consumes a "partial" credit, this packet cannot be bundled unless
				 * we add additional "dummy" padding (max 255 bytes) to consume the entire credit
				 *** NOTE: only allow the send padding if the endpoint is allowed to */
				if (pEndpoint->LocalConnectionFlags & HTC_LOCAL_CONN_FLAGS_ENABLE_SEND_BUNDLE_PADDING) {
					if (transferLength < target->TargetCreditSize) {
						/* special case where the transfer is less than a credit */
						creditPad = target->TargetCreditSize - transferLength;
					} else {
						creditPad = creditRemainder;
					}

					/* now check to see if we can indicate padding in the HTC header */
					if ((creditPad > 0) && (creditPad <= 255)) {
						/* adjust the transferlength of this packet with the new credit padding */
						transferLength += creditPad;
					} else {
						/* the amount to pad is too large, bail on this packet, we have to
						 * send it using the non-bundled method */
						pPacket = NULL;
					}
				} else {
					/* bail on this packet, user does not want padding applied */
					pPacket = NULL;
				}
			}

			if (NULL == pPacket) {
				/* can't bundle */
				done = true;
				break;
			}

			if (scatterSpaceRemaining < transferLength) {
				/* exceeds what we can transfer */
				break;
			}

			scatterSpaceRemaining -= transferLength;
			/* now remove it from the queue */
			pPacket = HTC_PACKET_DEQUEUE(pQueue);
			/* save it in the scatter list */
			pScatterReq->ScatterList[i].pCallerContexts[0] = pPacket;
			/* prepare packet and flag message as part of a send bundle */
			HTC_PREPARE_SEND_PKT(pPacket,
					pPacket->PktInfo.AsTx.SendFlags | HTC_FLAGS_SEND_BUNDLE,
					creditPad,
					pPacket->PktInfo.AsTx.SeqNo);
			pScatterReq->ScatterList[i].pBuffer = pPacket->pBuffer;
			pScatterReq->ScatterList[i].Length = transferLength;
			A_ASSERT(transferLength);
			pScatterReq->TotalLength += transferLength;
			pScatterReq->ValidScatterEntries++;
			packetsInScatterReq++;
			AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("  %d, Adding packet : 0x%lX, len:%d (remaining space:%d) \n",
						i, (unsigned long)pPacket,transferLength,scatterSpaceRemaining));
		}

		if (packetsInScatterReq >= HTC_MIN_HTC_MSGS_TO_BUNDLE) {
			/* send path is always asynchronous */
			pScatterReq->CompletionRoutine = HTCAsyncSendScatterCompletion;
			pScatterReq->Context = pEndpoint;
			bundlesSent++;
			totalPktsInBundle += packetsInScatterReq;
			packetsInScatterReq = 0;
			AR_DEBUG_PRINTF(ATH_DEBUG_SEND,(" Send Scatter total bytes: %d , entries: %d\n",
						pScatterReq->TotalLength,pScatterReq->ValidScatterEntries));
			DevSubmitScatterRequest(target->Device, pScatterReq, false, true);
			/* we don't own this anymore */
			pScatterReq = NULL;
			/* try to send some more */
			continue;
		}

		/* not enough packets to use the scatter request, cleanup */
		if (pScatterReq != NULL) {
			if (packetsInScatterReq > 0) {
				/* work backwards to requeue requests */
				for (i = (packetsInScatterReq - 1); i >= 0; i--) {
					pPacket = (struct htc_packet *)(pScatterReq->ScatterList[i].pCallerContexts[0]);
					if (pPacket != NULL) {
						/* undo any prep */
						HTC_UNPREPARE_SEND_PKT(pPacket);
						/* queue back to the head */
						HTC_PACKET_ENQUEUE_TO_HEAD(pQueue,pPacket);
					}
				}
			}
			DEV_FREE_SCATTER_REQ(target->Device,pScatterReq);
		}

		/* if we get here, we sent all that we could, get out */
		break;

	}

	*pBundlesSent = bundlesSent;
	*pTotalBundlesPkts = totalPktsInBundle;
	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,("-HTCIssueSendBundle (sent:%d) \n",bundlesSent));

	return;
}

int HTCSendPktsMultiple(void *HTCHandle, struct htc_packet_queue *pPktQueue)
{
	struct htc_target      *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	struct htc_endpoint    *pEndpoint;
	struct htc_packet      *pPacket;

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("+HTCSendPktsMultiple: Queue: 0x%lX, Pkts %d \n",
				(unsigned long)pPktQueue, HTC_PACKET_QUEUE_DEPTH(pPktQueue)));

	pPacket = HTC_GET_PKT_AT_HEAD(pPktQueue);
	if (NULL == pPacket) {
		AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("-HTCSendPktsMultiple \n"));
		return -EINVAL;
	}

	BUG_ON(pPacket->Endpoint >= ENDPOINT_MAX);
	pEndpoint = &target->EndPoint[pPacket->Endpoint];

	HTCTrySend(target, pEndpoint, pPktQueue);

	/* do completion on any packets that couldn't get in */
	if (!HTC_QUEUE_EMPTY(pPktQueue)) {

		HTC_PACKET_QUEUE_ITERATE_ALLOW_REMOVE(pPktQueue,pPacket) {
			if (HTC_STOPPING(target))
				pPacket->Status = A_ECANCELED;
			else
				pPacket->Status = A_NO_RESOURCE;
		} HTC_PACKET_QUEUE_ITERATE_END;

		DoSendCompletion(pEndpoint,pPktQueue);
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("-HTCSendPktsMultiple \n"));

	return 0;
}

int HTCSendPkt(void * HTCHandle, struct htc_packet *pPacket)
{
	struct htc_packet_queue queue;

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND,
			("+-HTCSendPkt: Enter endPointId: %d, buffer: 0x%lX, length: %d \n",
			 pPacket->Endpoint, (unsigned long)pPacket->pBuffer, pPacket->ActualLength));
	INIT_HTC_PACKET_QUEUE_AND_ADD(&queue,pPacket);
	return HTCSendPktsMultiple(HTCHandle, &queue);
}

/* flush endpoint TX queue */
static void HTCFlushEndpointTX(struct htc_target *target,
			       struct htc_endpoint *pEndpoint,
			       u16 Tag)
{
	struct htc_packet *pPacket;
	struct htc_packet_queue discardQueue;
	struct htc_packet_queue container;

	/* initialize the discard queue */
	INIT_HTC_PACKET_QUEUE(&discardQueue);

	spin_lock_bh(&target->HTCTxLock);

	ITERATE_OVER_LIST_ALLOW_REMOVE(&pEndpoint->TxQueue.QueueHead, pPacket, struct htc_packet, ListLink) {

		if ((HTC_TX_PACKET_TAG_ALL == Tag) || (Tag == pPacket->PktInfo.AsTx.Tag)) {
			HTC_PACKET_REMOVE(&pEndpoint->TxQueue, pPacket);
			HTC_PACKET_ENQUEUE(&discardQueue, pPacket);
		}

	} ITERATE_END;

	spin_unlock_bh(&target->HTCTxLock);

	while (1) {
		pPacket = HTC_PACKET_DEQUEUE(&discardQueue);
		if (!pPacket)
			break;
		pPacket->Status = A_ECANCELED;
		AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("  Flushing TX packet:0x%lX, length:%d, ep:%d tag:0x%X \n",
					(unsigned long)pPacket, pPacket->ActualLength, pPacket->Endpoint, pPacket->PktInfo.AsTx.Tag));
		INIT_HTC_PACKET_QUEUE_AND_ADD(&container,pPacket);
		DoSendCompletion(pEndpoint,&container);
	}

}

static void HTCFlushSendPkts(struct htc_target *target)
{
	struct htc_endpoint    *pEndpoint;
	int             i;

	if (AR_DEBUG_LVL_CHECK(ATH_DEBUG_TRC)) {
		DumpCreditDistStates(target);
	}

	for (i = ENDPOINT_0; i < ENDPOINT_MAX; i++) {
		pEndpoint = &target->EndPoint[i];
		if (pEndpoint->ServiceID == 0) {
			/* not in use.. */
			continue;
		}
		HTCFlushEndpointTX(target,pEndpoint,HTC_TX_PACKET_TAG_ALL);
	}


}

void HTCFlushEndpoint(void * HTCHandle, enum htc_endpoint_id Endpoint, u16 Tag)
{
	struct htc_target      *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	struct htc_endpoint    *pEndpoint = &target->EndPoint[Endpoint];

	BUG_ON(pEndpoint->ServiceID == 0);
	HTCFlushEndpointTX(target, pEndpoint, Tag);
}

void HTCIndicateActivityChange(void *      HTCHandle,
		enum htc_endpoint_id Endpoint,
		bool          Active)
{
	struct htc_target      *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	struct htc_endpoint    *pEndpoint = &target->EndPoint[Endpoint];
	bool          doDist = false;

	BUG_ON(pEndpoint->ServiceID == 0);

	spin_lock_bh(&target->HTCTxLock);

	if (Active) {
		if (!(pEndpoint->CreditDist.DistFlags & HTC_EP_ACTIVE)) {
			pEndpoint->CreditDist.DistFlags |= HTC_EP_ACTIVE;
			doDist = true;
		}
	} else {
		if (pEndpoint->CreditDist.DistFlags & HTC_EP_ACTIVE) {
			pEndpoint->CreditDist.DistFlags &= ~HTC_EP_ACTIVE;
			doDist = true;
		}
	}

	if (doDist) {
		pEndpoint->CreditDist.TxQueueDepth = HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue);
		DO_DISTRIBUTION(target,
				HTC_CREDIT_DIST_ACTIVITY_CHANGE,
				"Activity Change",
				target->EpCreditDistributionListHead->pNext);
	}

	spin_unlock_bh(&target->HTCTxLock);

	if (doDist && !Active)
		HTCCheckEndpointTxQueues(target);
}

/* HTC Rx */

#define DUMP_RECV_PKT_INFO(pP) \
    AR_DEBUG_PRINTF(ATH_DEBUG_RECV, (" HTC RECV packet 0x%lX (%d bytes) (hdr:0x%X) on ep : %d \n", \
                        (unsigned long)(pP), \
                        (pP)->ActualLength, \
                        (pP)->PktInfo.AsRx.ExpectedHdr, \
                        (pP)->Endpoint));

#define HTC_RX_STAT_PROFILE(t,ep,numLookAheads) \
{				\
    INC_HTC_EP_STAT((ep), RxReceived, 1);	\
    if ((numLookAheads) == 1) {	 \
        INC_HTC_EP_STAT((ep), RxLookAheads, 1);	 \
    } else if ((numLookAheads) > 1) {	\
        INC_HTC_EP_STAT((ep), RxBundleLookAheads, 1);\
    } \
}

/* for bundled frames, we can force the flag to indicate there are more packets */
#define FORCE_MORE_RX_PACKET_INDICATION_FLAG(P) \
    (P)->PktInfo.AsRx.IndicationFlags |= HTC_RX_FLAGS_INDICATE_MORE_PKTS;


static int dev_rx_pkt(struct htc_target *target, struct htc_packet *pPacket,
		      u32 RecvLength)
{
	u32 padded_len;
	int status;
	bool sync = (pPacket->Completion) ? false : true;

	padded_len = DEV_CALC_RECV_PADDED_LEN(target->Device, RecvLength);

	if (padded_len > pPacket->BufferLength) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("dev_rx_pkt, Not enough space for padlen:%d recvlen:%d bufferlen:%d \n",
				 padded_len,RecvLength,pPacket->BufferLength));
		if (!sync) {
			COMPLETE_HTC_PACKET(pPacket,A_EINVAL);
			return 0;
		}
		return -ENOMEM;
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
			("dev_rx_pkt (0x%lX : hdr:0x%X) Padded Length: %d Mbox:0x%X (mode:%s)\n",
			 (unsigned long)pPacket, pPacket->PktInfo.AsRx.ExpectedHdr,
			 padded_len,
			 target->Device->MailBoxInfo.MboxAddresses[HTC_MAILBOX],
			 sync ? "SYNC" : "ASYNC"));

	status = hif_read_write(target->Device->HIFDevice,
			target->Device->MailBoxInfo.MboxAddresses[HTC_MAILBOX],
			pPacket->pBuffer,
			padded_len,
			sync ? HIF_RD_SYNC_BLOCK_FIX : HIF_RD_ASYNC_BLOCK_FIX,
			sync ? NULL : pPacket);

	if (sync)
		pPacket->Status = status;

	return status;
}

static void SetRxPacketIndicationFlags(u32 LookAhead,
		struct htc_endpoint  *pEndpoint,
		struct htc_packet    *pPacket)
{
	struct htc_frame_hdr *pHdr = (struct htc_frame_hdr *)&LookAhead;

	if (pHdr->EndpointID == pPacket->Endpoint) {
		if (!HTC_QUEUE_EMPTY(&pEndpoint->RxBuffers))
			FORCE_MORE_RX_PACKET_INDICATION_FLAG(pPacket);
	}
}

/* optimization for recv packets, we can indicate a "hint" that there are more
 * single-packets to fetch on this endpoint */
#define SET_MORE_RX_PACKET_INDICATION_FLAG(L,N,E,P) \
    if ((N) > 0) { SetRxPacketIndicationFlags((L)[0],(E),(P)); }

static void CheckRecvWaterMark(struct htc_endpoint    *pEndpoint)
{
	if (pEndpoint->EpCallBacks.RecvRefillWaterMark > 0) {
		if (HTC_PACKET_QUEUE_DEPTH(&pEndpoint->RxBuffers) < pEndpoint->EpCallBacks.RecvRefillWaterMark) {
			pEndpoint->EpCallBacks.EpRecvRefill(pEndpoint->EpCallBacks.pContext,
					pEndpoint->Id);
		}
	}
}

static int AllocAndPrepareRxPackets(struct htc_target  *target,
		u32 LookAheads[],
		int              Messages,
		struct htc_endpoint     *pEndpoint,
		struct htc_packet_queue *pQueue)
{
	int         status = 0;
	struct htc_packet      *pPacket;
	struct htc_frame_hdr   *pHdr;
	int              i,j;
	int              numMessages;
	int              fullLength;
	bool           noRecycle;

	/* lock RX while we assemble the packet buffers */
	spin_lock_bh(&target->HTCRxLock);

	for (i = 0; i < Messages; i++) {

		pHdr = (struct htc_frame_hdr *)&LookAheads[i];

		if (pHdr->EndpointID >= ENDPOINT_MAX) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Invalid Endpoint in look-ahead: %d \n",pHdr->EndpointID));
			status = -ENOMEM;
			break;
		}

		if (pHdr->EndpointID != pEndpoint->Id) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Invalid Endpoint in look-ahead: %d should be : %d (index:%d)\n",
						pHdr->EndpointID, pEndpoint->Id, i));
			status = -ENOMEM;
			break;
		}

		if (pHdr->PayloadLen > HTC_MAX_PAYLOAD_LENGTH) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Payload length %d exceeds max HTC : %d !\n",
						pHdr->PayloadLen, (u32)HTC_MAX_PAYLOAD_LENGTH));
			status = -ENOMEM;
			break;
		}

		if (0 == pEndpoint->ServiceID) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Endpoint %d is not connected !\n",pHdr->EndpointID));
			/* endpoint isn't even connected */
			status = -ENOMEM;
			break;
		}

		if ((pHdr->Flags & HTC_FLAGS_RECV_BUNDLE_CNT_MASK) == 0) {
			/* HTC header only indicates 1 message to fetch */
			numMessages = 1;
		} else {
			/* HTC header indicates that every packet to follow has the same padded length so that it can
			 * be optimally fetched as a full bundle */
			numMessages = (pHdr->Flags & HTC_FLAGS_RECV_BUNDLE_CNT_MASK) >> HTC_FLAGS_RECV_BUNDLE_CNT_SHIFT;
			/* the count doesn't include the starter frame, just a count of frames to follow */
			numMessages++;
			A_ASSERT(numMessages <= target->MaxMsgPerBundle);
			INC_HTC_EP_STAT(pEndpoint, RxBundleIndFromHdr, 1);
			AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
					("HTC header indicates :%d messages can be fetched as a bundle \n",numMessages));
		}

		fullLength = DEV_CALC_RECV_PADDED_LEN(target->Device,pHdr->PayloadLen + sizeof(struct htc_frame_hdr));

		/* get packet buffers for each message, if there was a bundle detected in the header,
		 * use pHdr as a template to fetch all packets in the bundle */
		for (j = 0; j < numMessages; j++) {

			/* reset flag, any packets allocated using the RecvAlloc() API cannot be recycled on cleanup,
			 * they must be explicitly returned */
			noRecycle = false;

			if (pEndpoint->EpCallBacks.EpRecvAlloc != NULL) {
				spin_unlock_bh(&target->HTCRxLock);
				noRecycle = true;
				/* user is using a per-packet allocation callback */
				pPacket = pEndpoint->EpCallBacks.EpRecvAlloc(pEndpoint->EpCallBacks.pContext,
						pEndpoint->Id,
						fullLength);
				spin_lock_bh(&target->HTCRxLock);

			} else if ((pEndpoint->EpCallBacks.EpRecvAllocThresh != NULL) &&
					(fullLength > pEndpoint->EpCallBacks.RecvAllocThreshold)) {
				INC_HTC_EP_STAT(pEndpoint,RxAllocThreshHit,1);
				INC_HTC_EP_STAT(pEndpoint,RxAllocThreshBytes,pHdr->PayloadLen);
				/* threshold was hit, call the special recv allocation callback */
				spin_unlock_bh(&target->HTCRxLock);
				noRecycle = true;
				/* user wants to allocate packets above a certain threshold */
				pPacket = pEndpoint->EpCallBacks.EpRecvAllocThresh(pEndpoint->EpCallBacks.pContext,
						pEndpoint->Id,
						fullLength);
				spin_lock_bh(&target->HTCRxLock);

			} else {
				/* user is using a refill handler that can refill multiple HTC buffers */

				/* get a packet from the endpoint recv queue */
				pPacket = HTC_PACKET_DEQUEUE(&pEndpoint->RxBuffers);

				if (NULL == pPacket) {
					/* check for refill handler */
					if (pEndpoint->EpCallBacks.EpRecvRefill != NULL) {
						spin_unlock_bh(&target->HTCRxLock);
						/* call the re-fill handler */
						pEndpoint->EpCallBacks.EpRecvRefill(pEndpoint->EpCallBacks.pContext,
								pEndpoint->Id);
						spin_lock_bh(&target->HTCRxLock);
						/* check if we have more buffers */
						pPacket = HTC_PACKET_DEQUEUE(&pEndpoint->RxBuffers);
						/* fall through */
					}
				}
			}

			if (NULL == pPacket) {
				/* this is not an error, we simply need to mark that we are waiting for buffers.*/
				target->RecvStateFlags |= HTC_RECV_WAIT_BUFFERS;
				target->EpWaitingForBuffers = pEndpoint->Id;
				status = A_NO_RESOURCE;
				break;
			}

			BUG_ON(pPacket->Endpoint != pEndpoint->Id);
			/* clear flags */
			pPacket->PktInfo.AsRx.HTCRxFlags = 0;
			pPacket->PktInfo.AsRx.IndicationFlags = 0;
			pPacket->Status = 0;

			if (noRecycle) {
				/* flag that these packets cannot be recycled, they have to be returned to the
				 * user */
				pPacket->PktInfo.AsRx.HTCRxFlags |= HTC_RX_PKT_NO_RECYCLE;
			}
			/* add packet to queue (also incase we need to cleanup down below)  */
			HTC_PACKET_ENQUEUE(pQueue,pPacket);

			if (HTC_STOPPING(target)) {
				status = A_ECANCELED;
				break;
			}

			/* make sure this message can fit in the endpoint buffer */
			if ((u32)fullLength > pPacket->BufferLength) {
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
						("Payload Length Error : header reports payload of: %d (%d) endpoint buffer size: %d \n",
						 pHdr->PayloadLen, fullLength, pPacket->BufferLength));
				status = -ENOMEM;
				break;
			}

			if (j > 0) {
				pPacket->PktInfo.AsRx.HTCRxFlags |= HTC_RX_PKT_REFRESH_HDR;
				pPacket->PktInfo.AsRx.ExpectedHdr = 0xFFFFFFFF;
			} else {

				pPacket->PktInfo.AsRx.ExpectedHdr = LookAheads[i]; /* set expected look ahead */
			}
			pPacket->ActualLength = pHdr->PayloadLen + HTC_HDR_LENGTH;
		}

		if (status) {
			if (A_NO_RESOURCE == status) {
				status = 0;
			}
			break;
		}

	}

	spin_unlock_bh(&target->HTCRxLock);

	if (status) {
		while (!HTC_QUEUE_EMPTY(pQueue)) {
			pPacket = HTC_PACKET_DEQUEUE(pQueue);
			HTC_RECYCLE_RX_PKT(target,pPacket,&target->EndPoint[pPacket->Endpoint]);
		}
	}

	return status;
}

/* Function to report a target failure from the device */
static void HTCReportFailure(void *Context)
{
	struct htc_target *target = (struct htc_target *)Context;

	target->TargetFailure = true;

	if (target->HTCInitInfo.TargetFailure != NULL)
		target->HTCInitInfo.TargetFailure(target->HTCInitInfo.pContext, A_ERROR);
}

/* callback when a control message arrives on this endpoint */
static void HTCControlRecv(void *Context, struct htc_packet *pPacket)
{
	BUG_ON(pPacket->Endpoint != ENDPOINT_0);

	if (pPacket->Status == A_ECANCELED) {
		reclaim_rx_ctrl_buf((struct htc_target*)Context,pPacket);
		return;
	}

	if (pPacket->ActualLength > 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("HTCControlRecv, got message with length:%d \n",
				 pPacket->ActualLength + (u32)HTC_HDR_LENGTH));

#ifdef ATH_DEBUG_MODULE
		DebugDumpBytes(pPacket->pBuffer - HTC_HDR_LENGTH,
				pPacket->ActualLength + HTC_HDR_LENGTH,
				"Unexpected ENDPOINT 0 Message");
#endif
	}

	HTC_RECYCLE_RX_PKT((struct htc_target*)Context,pPacket,&((struct htc_target*)Context)->EndPoint[0]);
}

static void HTCProcessCreditRpt(struct htc_target *target,
		struct htc_credit_report *pRpt,
		int NumEntries, enum htc_endpoint_id FromEndpoint)
{
	int i;
	struct htc_endpoint *pEndpoint;
	int totalCredits = 0;
	bool doDist = false;

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("+HTCProcessCreditRpt, Credit Report Entries:%d \n", NumEntries));

	spin_lock_bh(&target->HTCTxLock);

	for (i = 0; i < NumEntries; i++, pRpt++) {
		BUG_ON(pRpt->EndpointID >= ENDPOINT_MAX);

		pEndpoint = &target->EndPoint[pRpt->EndpointID];

		AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("  Endpoint %d got %d credits \n",
					pRpt->EndpointID, pRpt->Credits));

		INC_HTC_EP_STAT(pEndpoint, TxCreditRpts, 1);
		INC_HTC_EP_STAT(pEndpoint, TxCreditsReturned, pRpt->Credits);

		if (FromEndpoint == pRpt->EndpointID) {
			/* this credit report arrived on the same endpoint indicating it arrived in an RX
			 * packet */
			INC_HTC_EP_STAT(pEndpoint, TxCreditsFromRx, pRpt->Credits);
			INC_HTC_EP_STAT(pEndpoint, TxCreditRptsFromRx, 1);
		} else if (FromEndpoint == ENDPOINT_0) {
			/* this credit arrived on endpoint 0 as a NULL message */
			INC_HTC_EP_STAT(pEndpoint, TxCreditsFromEp0, pRpt->Credits);
			INC_HTC_EP_STAT(pEndpoint, TxCreditRptsFromEp0, 1);
		} else {
			/* arrived on another endpoint */
			INC_HTC_EP_STAT(pEndpoint, TxCreditsFromOther, pRpt->Credits);
			INC_HTC_EP_STAT(pEndpoint, TxCreditRptsFromOther, 1);
		}

		if (ENDPOINT_0 == pRpt->EndpointID)
			/* always give endpoint 0 credits back */
			pEndpoint->CreditDist.TxCredits += pRpt->Credits;
		else {
			pEndpoint->CreditDist.TxCreditsToDist += pRpt->Credits;
			doDist = true;
		}

		/* refresh tx depth for distribution function that will recover these credits
		 * NOTE: this is only valid when there are credits to recover! */
		pEndpoint->CreditDist.TxQueueDepth = HTC_PACKET_QUEUE_DEPTH(&pEndpoint->TxQueue);

		totalCredits += pRpt->Credits;
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("  Report indicated %d credits to distribute \n", totalCredits));

	if (doDist)
		/* this was a credit return based on a completed send operations
		 * note, this is done with the lock held */
		DO_DISTRIBUTION(target,
				HTC_CREDIT_DIST_SEND_COMPLETE,
				"Send Complete",
				target->EpCreditDistributionListHead->pNext);

	spin_unlock_bh(&target->HTCTxLock);

	if (totalCredits)
		HTCCheckEndpointTxQueues(target);

	AR_DEBUG_PRINTF(ATH_DEBUG_SEND, ("-HTCProcessCreditRpt \n"));
}

static int HTCProcessTrailer(struct htc_target *target,
		u8 *pBuffer,
		int         Length,
		u32 *pNextLookAheads,
		int        *pNumLookAheads,
		enum htc_endpoint_id FromEndpoint)
{
	struct htc_record_hdr          *pRecord;
	u8 *pRecordBuf;
	struct htc_lookahead_report    *pLookAhead;
	u8 *pOrigBuffer;
	int origLength;
	int status;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("+HTCProcessTrailer (length:%d) \n", Length));

	if (AR_DEBUG_LVL_CHECK(ATH_DEBUG_RECV))
		AR_DEBUG_PRINTBUF(pBuffer,Length,"Recv Trailer");

	pOrigBuffer = pBuffer;
	origLength = Length;
	status = 0;

	while (Length > 0) {

		if (Length < sizeof(struct htc_record_hdr)) {
			status = -ENOMEM;
			break;
		}

		/* these are byte aligned structs */
		pRecord = (struct htc_record_hdr *)pBuffer;
		Length -= sizeof(struct htc_record_hdr);
		pBuffer += sizeof(struct htc_record_hdr);

		if (pRecord->Length > Length) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					(" invalid record length: %d (id:%d) buffer has: %d bytes left \n",
					 pRecord->Length, pRecord->RecordID, Length));
			status = -ENOMEM;
			break;
		}
		pRecordBuf = pBuffer;

		switch (pRecord->RecordID) {
		case HTC_RECORD_CREDITS:
			BUG_ON(pRecord->Length < sizeof(struct htc_credit_report));
			HTCProcessCreditRpt(target,
					(struct htc_credit_report *)pRecordBuf,
					pRecord->Length / (sizeof(struct htc_credit_report)),
					FromEndpoint);
			break;
		case HTC_RECORD_LOOKAHEAD:
				BUG_ON(pRecord->Length < sizeof(struct htc_lookahead_report));
				pLookAhead = (struct htc_lookahead_report *)pRecordBuf;
				if ((pLookAhead->PreValid == ((~pLookAhead->PostValid) & 0xFF)) &&
						(pNextLookAheads != NULL)) {

					AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
							(" LookAhead Report Found (pre valid:0x%X, post valid:0x%X) \n",
							 pLookAhead->PreValid,
							 pLookAhead->PostValid));

					/* look ahead bytes are valid, copy them over */
					((u8 *)(&pNextLookAheads[0]))[0] = pLookAhead->LookAhead[0];
					((u8 *)(&pNextLookAheads[0]))[1] = pLookAhead->LookAhead[1];
					((u8 *)(&pNextLookAheads[0]))[2] = pLookAhead->LookAhead[2];
					((u8 *)(&pNextLookAheads[0]))[3] = pLookAhead->LookAhead[3];

#ifdef ATH_DEBUG_MODULE
					if (AR_DEBUG_LVL_CHECK(ATH_DEBUG_RECV)) {
						DebugDumpBytes((u8 *)pNextLookAheads,4,"Next Look Ahead");
					}
#endif
					*pNumLookAheads = 1;
				}
				break;
		case HTC_RECORD_LOOKAHEAD_BUNDLE:
				BUG_ON(pRecord->Length < sizeof(struct htc_bundled_lookahd_report));
				if (pRecord->Length >= sizeof(struct htc_bundled_lookahd_report) &&
						(pNextLookAheads != NULL)) {
					struct htc_bundled_lookahd_report    *pBundledLookAheadRpt;
					int                             i;

					pBundledLookAheadRpt = (struct htc_bundled_lookahd_report *)pRecordBuf;

#ifdef ATH_DEBUG_MODULE
					if (AR_DEBUG_LVL_CHECK(ATH_DEBUG_RECV)) {
						DebugDumpBytes(pRecordBuf,pRecord->Length,"Bundle LookAhead");
					}
#endif

					BUG_ON((pRecord->Length / (sizeof(struct htc_bundled_lookahd_report))) <
						HTC_HOST_MAX_MSG_PER_BUNDLE);

					for (i = 0; i < (int)(pRecord->Length / (sizeof(struct htc_bundled_lookahd_report))); i++) {
						((u8 *)(&pNextLookAheads[i]))[0] = pBundledLookAheadRpt->LookAhead[0];
						((u8 *)(&pNextLookAheads[i]))[1] = pBundledLookAheadRpt->LookAhead[1];
						((u8 *)(&pNextLookAheads[i]))[2] = pBundledLookAheadRpt->LookAhead[2];
						((u8 *)(&pNextLookAheads[i]))[3] = pBundledLookAheadRpt->LookAhead[3];
						pBundledLookAheadRpt++;
					}

					*pNumLookAheads = i;
				}
				break;
			default:
				AR_DEBUG_PRINTF(ATH_DEBUG_ERR, (" unhandled record: id:%d length:%d \n",
							pRecord->RecordID, pRecord->Length));
				break;
		}

		if (status)
			break;

		/* advance buffer past this record for next time around */
		pBuffer += pRecord->Length;
		Length -= pRecord->Length;
	}

#ifdef ATH_DEBUG_MODULE
	if (status) {
		DebugDumpBytes(pOrigBuffer,origLength,"BAD Recv Trailer");
	}
#endif

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("-HTCProcessTrailer \n"));
	return status;

}

static int HTCProcessRecvHeader(struct htc_target *target,
		struct htc_packet *pPacket,
		u32 *pNextLookAheads,
		int        *pNumLookAheads)
{
	u8 temp;
	u8 *pBuf;
	int  status = 0;
	u16 payloadLen;
	u32 lookAhead;

	pBuf = pPacket->pBuffer;

	if (pNumLookAheads != NULL)
		*pNumLookAheads = 0;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("+HTCProcessRecvHeader \n"));

	if (AR_DEBUG_LVL_CHECK(ATH_DEBUG_RECV)) {
		AR_DEBUG_PRINTBUF(pBuf,pPacket->ActualLength,"HTC Recv PKT");
	}

	/* note, we cannot assume the alignment of pBuffer, so we use the safe macros to
	 * retrieve 16 bit fields */
	payloadLen = A_GET_UINT16_FIELD(pBuf, struct htc_frame_hdr, PayloadLen);

	((u8 *)&lookAhead)[0] = pBuf[0];
	((u8 *)&lookAhead)[1] = pBuf[1];
	((u8 *)&lookAhead)[2] = pBuf[2];
	((u8 *)&lookAhead)[3] = pBuf[3];

	if (pPacket->PktInfo.AsRx.HTCRxFlags & HTC_RX_PKT_REFRESH_HDR) {
		/* refresh expected hdr, since this was unknown at the time we grabbed the packets
		 * as part of a bundle */
		pPacket->PktInfo.AsRx.ExpectedHdr = lookAhead;
		/* refresh actual length since we now have the real header */
		pPacket->ActualLength = payloadLen + HTC_HDR_LENGTH;

		/* validate the actual header that was refreshed  */
		if (pPacket->ActualLength > pPacket->BufferLength) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("Refreshed HDR payload length (%d) in bundled RECV is invalid (hdr: 0x%X) \n",
					 payloadLen, lookAhead));
			/* limit this to max buffer just to print out some of the buffer */
			pPacket->ActualLength = min(pPacket->ActualLength, pPacket->BufferLength);
			status = -ENOMEM;
			goto fail_rx;
		}

		if (pPacket->Endpoint != A_GET_UINT8_FIELD(pBuf, struct htc_frame_hdr, EndpointID)) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("Refreshed HDR endpoint (%d) does not match expected endpoint (%d) \n",
					 A_GET_UINT8_FIELD(pBuf, struct htc_frame_hdr, EndpointID), pPacket->Endpoint));
			status = -ENOMEM;
			goto fail_rx;
		}
	}

	if (lookAhead != pPacket->PktInfo.AsRx.ExpectedHdr) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("HTCProcessRecvHeader, lookahead mismatch! (pPkt:0x%lX flags:0x%X) \n",
				 (unsigned long)pPacket, pPacket->PktInfo.AsRx.HTCRxFlags));
#ifdef ATH_DEBUG_MODULE
		DebugDumpBytes((u8 *)&pPacket->PktInfo.AsRx.ExpectedHdr,4,"Expected Message LookAhead");
		DebugDumpBytes(pBuf,sizeof(struct htc_frame_hdr),"Current Frame Header");
#ifdef HTC_CAPTURE_LAST_FRAME
		DebugDumpBytes((u8 *)&target->LastFrameHdr,sizeof(struct htc_frame_hdr),"Last Frame Header");
		if (target->LastTrailerLength != 0) {
			DebugDumpBytes(target->LastTrailer,
					target->LastTrailerLength,
					"Last trailer");
		}
#endif
#endif
		status = -ENOMEM;
		goto fail_rx;
	}

	temp = A_GET_UINT8_FIELD(pBuf, struct htc_frame_hdr, Flags);

	if (temp & HTC_FLAGS_RECV_TRAILER) {

		temp = A_GET_UINT8_FIELD(pBuf, struct htc_frame_hdr, ControlBytes[0]);

		if ((temp < sizeof(struct htc_record_hdr)) || (temp > payloadLen)) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("HTCProcessRecvHeader, invalid header (payloadlength should be :%d, CB[0] is:%d) \n",
					 payloadLen, temp));
			status = -ENOMEM;
			goto fail_rx;
		}

		if (pPacket->PktInfo.AsRx.HTCRxFlags & HTC_RX_PKT_IGNORE_LOOKAHEAD) {
			pNextLookAheads = NULL;
			pNumLookAheads = NULL;
		}

		status = HTCProcessTrailer(target,
				(pBuf + HTC_HDR_LENGTH + payloadLen - temp),
				temp,
				pNextLookAheads,
				pNumLookAheads,
				pPacket->Endpoint);

		if (status)
			goto fail_rx;

#ifdef HTC_CAPTURE_LAST_FRAME
		memcpy(target->LastTrailer, (pBuf + HTC_HDR_LENGTH + payloadLen - temp), temp);
		target->LastTrailerLength = temp;
#endif
		pPacket->ActualLength -= temp;
	}
#ifdef HTC_CAPTURE_LAST_FRAME
	else {
		target->LastTrailerLength = 0;
	}
#endif

	pPacket->pBuffer += HTC_HDR_LENGTH;
	pPacket->ActualLength -= HTC_HDR_LENGTH;

fail_rx:
	if (status) {
#ifdef ATH_DEBUG_MODULE
		DebugDumpBytes(pBuf,pPacket->ActualLength < 256 ? pPacket->ActualLength : 256 ,"BAD HTC Recv PKT");
#endif
	} else {
#ifdef HTC_CAPTURE_LAST_FRAME
		memcpy(&target->LastFrameHdr,pBuf,sizeof(struct htc_frame_hdr));
#endif
		if (AR_DEBUG_LVL_CHECK(ATH_DEBUG_RECV)) {
			if (pPacket->ActualLength > 0) {
				AR_DEBUG_PRINTBUF(pPacket->pBuffer,pPacket->ActualLength,"HTC - Application Msg");
			}
		}
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("-HTCProcessRecvHeader \n"));
	return status;
}

static void DoRecvCompletion(struct htc_endpoint *pEndpoint,
                             struct htc_packet_queue *pQueueToIndicate)
{

	if (HTC_QUEUE_EMPTY(pQueueToIndicate))
		return;

	if (pEndpoint->EpCallBacks.EpRecvPktMultiple != NULL) {
		AR_DEBUG_PRINTF(ATH_DEBUG_RECV, (" HTC calling ep %d, recv multiple callback (%d pkts) \n",
					pEndpoint->Id, HTC_PACKET_QUEUE_DEPTH(pQueueToIndicate)));
		/* a recv multiple handler is being used, pass the queue to the handler */
		pEndpoint->EpCallBacks.EpRecvPktMultiple(pEndpoint->EpCallBacks.pContext,
				pQueueToIndicate);
		INIT_HTC_PACKET_QUEUE(pQueueToIndicate);
	} else {
		struct htc_packet *pPacket;
		/* using legacy EpRecv */
		do {
			pPacket = HTC_PACKET_DEQUEUE(pQueueToIndicate);
			AR_DEBUG_PRINTF(ATH_DEBUG_RECV, (" HTC calling ep %d recv callback on packet 0x%lX \n",
						pEndpoint->Id, (unsigned long)(pPacket)));
			pEndpoint->EpCallBacks.EpRecv(pEndpoint->EpCallBacks.pContext, pPacket);
		} while (!HTC_QUEUE_EMPTY(pQueueToIndicate));
	}

}

static void DrainRecvIndicationQueue(struct htc_target *target, struct htc_endpoint *pEndpoint)
{
	struct htc_packet_queue     recvCompletions;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("+DrainRecvIndicationQueue \n"));

	INIT_HTC_PACKET_QUEUE(&recvCompletions);

	spin_lock_bh(&target->HTCTxLock);

	pEndpoint->RxProcessCount++;
	if (pEndpoint->RxProcessCount > 1) {
		pEndpoint->RxProcessCount--;
		/* another thread or task is draining the RX completion queue on this endpoint
		 * that thread will reset the rx processing count when the queue is drained */
		spin_unlock_bh(&target->HTCTxLock);
		return;
	}

	/******* at this point only 1 thread may enter ******/

	while (true) {

		/* transfer items from main recv queue to the local one so we can release the lock */
		HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(&recvCompletions, &pEndpoint->RecvIndicationQueue);

		if (HTC_QUEUE_EMPTY(&recvCompletions)) {
			/* all drained */
			break;
		}

		/* release lock while we do the recv completions
		 * other threads can now queue more recv completions */
		spin_unlock_bh(&target->HTCTxLock);

		AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
				("DrainRecvIndicationQueue : completing %d RECV packets \n",
				 HTC_PACKET_QUEUE_DEPTH(&recvCompletions)));
		/* do completion */
		DoRecvCompletion(pEndpoint,&recvCompletions);

		/* re-acquire lock to grab some more completions */
		spin_lock_bh(&target->HTCTxLock);
	}

	pEndpoint->RxProcessCount = 0;
	spin_unlock_bh(&target->HTCTxLock);

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("-DrainRecvIndicationQueue \n"));

}

static int HTCIssueRecvPacketBundle(struct htc_target        *target,
		struct htc_packet_queue  *pRecvPktQueue,
		struct htc_packet_queue  *pSyncCompletionQueue,
		int               *pNumPacketsFetched,
		bool             PartialBundle)
{
	int        status = 0;
	struct hif_scatter_req *pScatterReq;
	int             i, totalLength;
	int             pktsToScatter;
	struct htc_packet      *pPacket;
	bool          asyncMode = (pSyncCompletionQueue == NULL) ? true : false;
	int             scatterSpaceRemaining = DEV_GET_MAX_BUNDLE_RECV_LENGTH(target->Device);

	pktsToScatter = HTC_PACKET_QUEUE_DEPTH(pRecvPktQueue);
	pktsToScatter = min(pktsToScatter, target->MaxMsgPerBundle);

	if ((HTC_PACKET_QUEUE_DEPTH(pRecvPktQueue) - pktsToScatter) > 0) {
		/* we were forced to split this bundle receive operation
		 * all packets in this partial bundle must have their lookaheads ignored */
		PartialBundle = true;
		/* this would only happen if the target ignored our max bundle limit */
		AR_DEBUG_PRINTF(ATH_DEBUG_WARN,
				("HTCIssueRecvPacketBundle : partial bundle detected num:%d , %d \n",
				 HTC_PACKET_QUEUE_DEPTH(pRecvPktQueue), pktsToScatter));
	}

	totalLength = 0;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("+HTCIssueRecvPacketBundle (Numpackets: %d , actual : %d) \n",
				HTC_PACKET_QUEUE_DEPTH(pRecvPktQueue), pktsToScatter));

	pScatterReq = DEV_ALLOC_SCATTER_REQ(target->Device);

	if (pScatterReq == NULL)
		goto fail_rx_pkt;;

	pScatterReq->CallerFlags = 0;

	if (PartialBundle) {
		pScatterReq->CallerFlags |= HTC_SCATTER_REQ_FLAGS_PARTIAL_BUNDLE;
	}

	for (i = 0; i < pktsToScatter; i++) {
		int paddedLength;

		pPacket = HTC_PACKET_DEQUEUE(pRecvPktQueue);
		A_ASSERT(pPacket != NULL);

		paddedLength = DEV_CALC_RECV_PADDED_LEN(target->Device, pPacket->ActualLength);

		if ((scatterSpaceRemaining - paddedLength) < 0) {
			HTC_PACKET_ENQUEUE_TO_HEAD(pRecvPktQueue,pPacket);
			break;
		}

		scatterSpaceRemaining -= paddedLength;

		if (PartialBundle || (i < (pktsToScatter - 1))) {
			/* packet 0..n-1 cannot be checked for look-aheads since we are fetching a bundle
			 * the last packet however can have it's lookahead used */
			pPacket->PktInfo.AsRx.HTCRxFlags |= HTC_RX_PKT_IGNORE_LOOKAHEAD;
		}

		/* note: 1 HTC packet per scatter entry */
		/* setup packet into */
		pScatterReq->ScatterList[i].pBuffer = pPacket->pBuffer;
		pScatterReq->ScatterList[i].Length = paddedLength;

		pPacket->PktInfo.AsRx.HTCRxFlags |= HTC_RX_PKT_PART_OF_BUNDLE;

		if (asyncMode) {
			pScatterReq->ScatterList[i].pCallerContexts[0] = pPacket;
		} else {
			HTC_PACKET_ENQUEUE(pSyncCompletionQueue,pPacket);
		}

		BUG_ON(!pScatterReq->ScatterList[i].Length);
		totalLength += pScatterReq->ScatterList[i].Length;
	}

	pScatterReq->TotalLength = totalLength;
	pScatterReq->ValidScatterEntries = i;

	if (asyncMode) {
		pScatterReq->CompletionRoutine = HTCAsyncRecvScatterCompletion;
		pScatterReq->Context = target;
	}

	status = DevSubmitScatterRequest(target->Device, pScatterReq, true, asyncMode);

	if (!status) {
		*pNumPacketsFetched = i;
	}

	if (!asyncMode) {
		/* free scatter request */
		DEV_FREE_SCATTER_REQ(target->Device, pScatterReq);
	}


fail_rx_pkt:
	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("-HTCIssueRecvPacketBundle (status:%d) (fetched:%d) \n",
				status,*pNumPacketsFetched));

	return status;
}

static int HTCRecvMessagePendingHandler(void *Context, u32 MsgLookAheads[], int NumLookAheads, bool *pAsyncProc, int *pNumPktsFetched)
{
	struct htc_target      *target = (struct htc_target *)Context;
	int         status = 0;
	struct htc_packet      *pPacket;
	struct htc_endpoint    *pEndpoint;
	bool          asyncProc = false;
	u32 lookAheads[HTC_HOST_MAX_MSG_PER_BUNDLE];
	int             pktsFetched;
	struct htc_packet_queue recvPktQueue, syncCompletedPktsQueue;
	bool          partialBundle;
	enum htc_endpoint_id id;
	int             totalFetched = 0;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("+HTCRecvMessagePendingHandler NumLookAheads: %d \n",NumLookAheads));

	if (pNumPktsFetched != NULL) {
		*pNumPktsFetched = 0;
	}

	if (IS_DEV_IRQ_PROCESSING_ASYNC_ALLOWED(target->Device)) {
		/* We use async mode to get the packets if the device layer supports it.
		 * The device layer interfaces with HIF in which HIF may have restrictions on
		 * how interrupts are processed */
		asyncProc = true;
	}

	if (pAsyncProc != NULL) {
		/* indicate to caller how we decided to process this */
		*pAsyncProc = asyncProc;
	}

	BUG_ON(NumLookAheads > HTC_HOST_MAX_MSG_PER_BUNDLE);

	/* on first entry copy the lookaheads into our temp array for processing */
	memcpy(lookAheads, MsgLookAheads, (sizeof(u32)) * NumLookAheads);

	while (true) {

		/* reset packets queues */
		INIT_HTC_PACKET_QUEUE(&recvPktQueue);
		INIT_HTC_PACKET_QUEUE(&syncCompletedPktsQueue);

		/* first lookahead sets the expected endpoint IDs for all packets in a bundle */
		id = ((struct htc_frame_hdr *)&lookAheads[0])->EndpointID;
		pEndpoint = &target->EndPoint[id];

		if (id >= ENDPOINT_MAX) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("MsgPend, Invalid Endpoint in look-ahead: %d \n",id));
			status = -ENOMEM;
			break;
		}

		/* try to allocate as many HTC RX packets indicated by the lookaheads
		 * these packets are stored in the recvPkt queue */
		status = AllocAndPrepareRxPackets(target,
				lookAheads,
				NumLookAheads,
				pEndpoint,
				&recvPktQueue);
		if (status) {
			break;
		}

		if (HTC_PACKET_QUEUE_DEPTH(&recvPktQueue) >= 2) {
			/* a recv bundle was detected, force IRQ status re-check again */
			REF_IRQ_STATUS_RECHECK(target->Device);
		}

		totalFetched += HTC_PACKET_QUEUE_DEPTH(&recvPktQueue);

		/* we've got packet buffers for all we can currently fetch,
		 * this count is not valid anymore  */
		NumLookAheads = 0;
		partialBundle = false;

		/* now go fetch the list of HTC packets */
		while (!HTC_QUEUE_EMPTY(&recvPktQueue)) {

			pktsFetched = 0;

			if (target->RecvBundlingEnabled && (HTC_PACKET_QUEUE_DEPTH(&recvPktQueue) > 1)) {
				/* there are enough packets to attempt a bundle transfer and recv bundling is allowed  */
				status = HTCIssueRecvPacketBundle(target,
						&recvPktQueue,
						asyncProc ? NULL : &syncCompletedPktsQueue,
						&pktsFetched,
						partialBundle);
				if (status) {
					break;
				}

				if (HTC_PACKET_QUEUE_DEPTH(&recvPktQueue) != 0) {
					/* we couldn't fetch all packets at one time, this creates a broken
					 * bundle  */
					partialBundle = true;
				}
			}

			/* see if the previous operation fetched any packets using bundling */
			if (0 == pktsFetched) {
				/* dequeue one packet */
				pPacket = HTC_PACKET_DEQUEUE(&recvPktQueue);
				A_ASSERT(pPacket != NULL);

				if (asyncProc) {
					/* we use async mode to get the packet if the device layer supports it
					 * set our callback and context */
					pPacket->Completion = HTCRecvCompleteHandler;
					pPacket->pContext = target;
				} else {
					/* fully synchronous */
					pPacket->Completion = NULL;
				}

				if (HTC_PACKET_QUEUE_DEPTH(&recvPktQueue) > 0) {
					/* lookaheads in all packets except the last one in the bundle must be ignored */
					pPacket->PktInfo.AsRx.HTCRxFlags |= HTC_RX_PKT_IGNORE_LOOKAHEAD;
				}

				/* go fetch the packet */
				status = dev_rx_pkt(target, pPacket, pPacket->ActualLength);
				if (status) {
					break;
				}

				if (!asyncProc) {
					/* sent synchronously, queue this packet for synchronous completion */
					HTC_PACKET_ENQUEUE(&syncCompletedPktsQueue,pPacket);
				}

			}

		}

		if (!status) {
			CheckRecvWaterMark(pEndpoint);
		}

		if (asyncProc) {
			/* we did this asynchronously so we can get out of the loop, the asynch processing
			 * creates a chain of requests to continue processing pending messages in the
			 * context of callbacks  */
			break;
		}

		/* synchronous handling */
		if (target->Device->DSRCanYield) {
			/* for the SYNC case, increment count that tracks when the DSR should yield */
			target->Device->CurrentDSRRecvCount++;
		}

		/* in the sync case, all packet buffers are now filled,
		 * we can process each packet, check lookaheads and then repeat */

		/* unload sync completion queue */
		while (!HTC_QUEUE_EMPTY(&syncCompletedPktsQueue)) {
			struct htc_packet_queue    container;

			pPacket = HTC_PACKET_DEQUEUE(&syncCompletedPktsQueue);
			BUG_ON(!pPacket);

			pEndpoint = &target->EndPoint[pPacket->Endpoint];
			/* reset count on each iteration, we are only interested in the last packet's lookahead
			 * information when we break out of this loop */
			NumLookAheads = 0;
			/* process header for each of the recv packets
			 * note: the lookahead of the last packet is useful for us to continue in this loop */
			status = HTCProcessRecvHeader(target,pPacket,lookAheads,&NumLookAheads);
			if (status) {
				break;
			}

			if (HTC_QUEUE_EMPTY(&syncCompletedPktsQueue)) {
				/* last packet's more packets flag is set based on the lookahead */
				SET_MORE_RX_PACKET_INDICATION_FLAG(lookAheads,NumLookAheads,pEndpoint,pPacket);
			} else {
				/* packets in a bundle automatically have this flag set */
				FORCE_MORE_RX_PACKET_INDICATION_FLAG(pPacket);
			}
			/* good packet, indicate it */
			HTC_RX_STAT_PROFILE(target,pEndpoint,NumLookAheads);

			if (pPacket->PktInfo.AsRx.HTCRxFlags & HTC_RX_PKT_PART_OF_BUNDLE) {
				INC_HTC_EP_STAT(pEndpoint, RxPacketsBundled, 1);
			}

			INIT_HTC_PACKET_QUEUE_AND_ADD(&container,pPacket);
			DoRecvCompletion(pEndpoint,&container);
		}

		if (status) {
			break;
		}

		if (NumLookAheads == 0) {
			/* no more look aheads */
			break;
		}

		/* when we process recv synchronously we need to check if we should yield and stop
		 * fetching more packets indicated by the embedded lookaheads */
		if (target->Device->DSRCanYield) {
			if (DEV_CHECK_RECV_YIELD(target->Device)) {
				/* break out, don't fetch any more packets */
				break;
			}
		}

		/* for SYNCH processing, if we get here, we are running through the loop again due to a detected lookahead.
		 * Set flag that we should re-check IRQ status registers again before leaving IRQ processing,
		 * this can net better performance in high throughput situations */
		REF_IRQ_STATUS_RECHECK(target->Device);
	}

	if (status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("Failed to get pending recv messages (%d) \n",status));
		/* cleanup any packets we allocated but didn't use to actually fetch any packets */
		while (!HTC_QUEUE_EMPTY(&recvPktQueue)) {
			pPacket = HTC_PACKET_DEQUEUE(&recvPktQueue);
			/* clean up packets */
			HTC_RECYCLE_RX_PKT(target, pPacket, &target->EndPoint[pPacket->Endpoint]);
		}
		/* cleanup any packets in sync completion queue */
		while (!HTC_QUEUE_EMPTY(&syncCompletedPktsQueue)) {
			pPacket = HTC_PACKET_DEQUEUE(&syncCompletedPktsQueue);
			/* clean up packets */
			HTC_RECYCLE_RX_PKT(target, pPacket, &target->EndPoint[pPacket->Endpoint]);
		}
		if  (HTC_STOPPING(target)) {
			AR_DEBUG_PRINTF(ATH_DEBUG_WARN,
					(" Host is going to stop. blocking receiver for HTCStop.. \n"));
			DevStopRecv(target->Device, asyncProc ? true : false);
		}
	}
	/* before leaving, check to see if host ran out of buffers and needs to stop the
	 * receiver */
	if (target->RecvStateFlags & HTC_RECV_WAIT_BUFFERS) {
		AR_DEBUG_PRINTF(ATH_DEBUG_WARN,
				(" Host has no RX buffers, blocking receiver to prevent overrun.. \n"));
		/* try to stop receive at the device layer */
		DevStopRecv(target->Device, asyncProc ? true : false);
	}

	if (pNumPktsFetched != NULL) {
		*pNumPktsFetched = totalFetched;
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("-HTCRecvMessagePendingHandler \n"));

	return status;
}

static void HTCAsyncRecvCheckMorePackets(struct htc_target  *target,
                                                u32 NextLookAheads[],
                                                int         NumLookAheads,
                                                bool      CheckMoreMsgs)
{
	if (NumLookAheads > 0) {
		int nextStatus;
		int      fetched = 0;

		AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
				("HTCAsyncRecvCheckMorePackets - num lookaheads were non-zero : %d \n",
				 NumLookAheads));
		/* force status re-check */
		REF_IRQ_STATUS_RECHECK(target->Device);
		/* we have more packets, get the next packet fetch started */
		nextStatus = HTCRecvMessagePendingHandler(target, NextLookAheads, NumLookAheads, NULL, &fetched);
		if (nextStatus) {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
					("Next look ahead from recv header was INVALID\n"));
#ifdef ATH_DEBUG_MODULE
			DebugDumpBytes((u8 *)NextLookAheads,
					NumLookAheads * (sizeof(u32)),
					"BAD lookaheads from lookahead report");
#endif
		}
		if (!nextStatus && !fetched)
			DevAsyncIrqProcessComplete(target->Device);
	} else {
		if (CheckMoreMsgs) {
			AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
					("HTCAsyncRecvCheckMorePackets - rechecking for more messages...\n"));
			DevCheckPendingRecvMsgsAsync(target->Device);
		} else {
			AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("HTCAsyncRecvCheckMorePackets - no check \n"));
		}
	}

}

static void HTCAsyncRecvScatterCompletion(struct hif_scatter_req *pScatterReq)
{
	int                 i;
	struct htc_packet          *pPacket;
	struct htc_endpoint        *pEndpoint;
	u32 lookAheads[HTC_HOST_MAX_MSG_PER_BUNDLE];
	int                 numLookAheads = 0;
	struct htc_target          *target = (struct htc_target *)pScatterReq->Context;
	int            status;
	bool              partialBundle = false;
	struct htc_packet_queue    localRecvQueue;
	bool              procError = false;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("+HTCAsyncRecvScatterCompletion  TotLen: %d  Entries: %d\n",
				pScatterReq->TotalLength, pScatterReq->ValidScatterEntries));

	BUG_ON(IS_DEV_IRQ_PROC_SYNC_MODE(target->Device));

	if (pScatterReq->CompletionStatus) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("** Recv Scatter Request Failed: %d \n",pScatterReq->CompletionStatus));
	}

	if (pScatterReq->CallerFlags & HTC_SCATTER_REQ_FLAGS_PARTIAL_BUNDLE) {
		partialBundle = true;
	}

	DEV_FINISH_SCATTER_OPERATION(pScatterReq);

	INIT_HTC_PACKET_QUEUE(&localRecvQueue);

	pPacket = (struct htc_packet *)pScatterReq->ScatterList[0].pCallerContexts[0];
	/* note: all packets in a scatter req are for the same endpoint ! */
	pEndpoint = &target->EndPoint[pPacket->Endpoint];

	/* walk through the scatter list and process */
	/* **** NOTE: DO NOT HOLD ANY LOCKS here, HTCProcessRecvHeader can take the TX lock
	 * as it processes credit reports */
	for (i = 0; i < pScatterReq->ValidScatterEntries; i++) {
		pPacket = (struct htc_packet *)pScatterReq->ScatterList[i].pCallerContexts[0];
		A_ASSERT(pPacket != NULL);
		/* reset count, we are only interested in the look ahead in the last packet when we
		 * break out of this loop */
		numLookAheads = 0;

		if (!pScatterReq->CompletionStatus) {
			/* process header for each of the recv packets */
			status = HTCProcessRecvHeader(target,pPacket,lookAheads,&numLookAheads);
		} else {
			status = A_ERROR;
		}

		if (!status) {
			spin_lock_bh(&target->HTCRxLock);
			HTC_RX_STAT_PROFILE(target,pEndpoint,numLookAheads);
			INC_HTC_EP_STAT(pEndpoint, RxPacketsBundled, 1);
			spin_unlock_bh(&target->HTCRxLock);
			if (i == (pScatterReq->ValidScatterEntries - 1)) {
				/* last packet's more packets flag is set based on the lookahead */
				SET_MORE_RX_PACKET_INDICATION_FLAG(lookAheads,numLookAheads,pEndpoint,pPacket);
			} else {
				/* packets in a bundle automatically have this flag set */
				FORCE_MORE_RX_PACKET_INDICATION_FLAG(pPacket);
			}

			DUMP_RECV_PKT_INFO(pPacket);
			/* since we can't hold a lock in this loop, we insert into our local recv queue for
			 * storage until we can transfer them to the recv completion queue */
			HTC_PACKET_ENQUEUE(&localRecvQueue,pPacket);

		} else {
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" Recv packet scatter entry %d failed (out of %d) \n",
						i, pScatterReq->ValidScatterEntries));
			/* recycle failed recv */
			HTC_RECYCLE_RX_PKT(target, pPacket, pEndpoint);
			/* set flag and continue processing the remaining scatter entries */
			procError = true;
		}

	}

	DEV_FREE_SCATTER_REQ(target->Device,pScatterReq);

	spin_lock_bh(&target->HTCRxLock);
	HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(&pEndpoint->RecvIndicationQueue, &localRecvQueue);

	spin_unlock_bh(&target->HTCRxLock);

	if (!procError) {
		HTCAsyncRecvCheckMorePackets(target,
				lookAheads,
				numLookAheads,
				partialBundle ? false : true);
	}

	DrainRecvIndicationQueue(target,pEndpoint);

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("-HTCAsyncRecvScatterCompletion \n"));
}

static void HTCRecvCompleteHandler(void *Context, struct htc_packet *pPacket)
{
	struct htc_target *target = (struct htc_target *)Context;
	struct htc_endpoint    *pEndpoint;
	u32 nextLookAheads[HTC_HOST_MAX_MSG_PER_BUNDLE];
	int             numLookAheads = 0;
	int        status;
	bool          checkMorePkts = true;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("+HTCRecvCompleteHandler (pkt:0x%lX, status:%d, ep:%d) \n",
				(unsigned long)pPacket, pPacket->Status, pPacket->Endpoint));

	BUG_ON(IS_DEV_IRQ_PROC_SYNC_MODE(target->Device));
	BUG_ON(pPacket->Endpoint >= ENDPOINT_MAX);
	pEndpoint = &target->EndPoint[pPacket->Endpoint];
	pPacket->Completion = NULL;

	/* get completion status */
	status = pPacket->Status;

	if (status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("HTCRecvCompleteHandler: request failed (status:%d, ep:%d) \n",
					pPacket->Status, pPacket->Endpoint));
		goto fail_tx_comp;
	}

	status = HTCProcessRecvHeader(target,pPacket,nextLookAheads,&numLookAheads);

	if (status)
		goto fail_tx_comp;

	if (pPacket->PktInfo.AsRx.HTCRxFlags & HTC_RX_PKT_IGNORE_LOOKAHEAD)
		/* this packet was part of a bundle that had to be broken up.
		 * It was fetched one message at a time.  There may be other asynchronous reads queued behind this one.
		 * Do no issue another check for more packets since the last one in the series of requests
		 * will handle it */
		checkMorePkts = false;

	DUMP_RECV_PKT_INFO(pPacket);
	spin_lock_bh(&target->HTCRxLock);
	SET_MORE_RX_PACKET_INDICATION_FLAG(nextLookAheads,numLookAheads,pEndpoint,pPacket);
	HTC_PACKET_ENQUEUE(&pEndpoint->RecvIndicationQueue,pPacket);
	HTC_RX_STAT_PROFILE(target,pEndpoint,numLookAheads);
	spin_unlock_bh(&target->HTCRxLock);

	HTCAsyncRecvCheckMorePackets(target,nextLookAheads,numLookAheads,checkMorePkts);

fail_tx_comp:
	if (status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("HTCRecvCompleteHandler , message fetch failed (status = %d) \n",
				 status));
		/* recycle this packet */
		HTC_RECYCLE_RX_PKT(target, pPacket, pEndpoint);
	} else {
		/* a good packet was queued, drain the queue */
		DrainRecvIndicationQueue(target,pEndpoint);
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("-HTCRecvCompleteHandler\n"));
}

/* synchronously wait for a control message from the target,
 * This function is used at initialization time ONLY.  At init messages
 * on ENDPOINT 0 are expected. */
static int HTCWaitforControlMessage(struct htc_target *target, struct htc_packet **ppControlPacket)
{
	int        status;
	u32 lookAhead;
	struct htc_packet      *pPacket = NULL;
	struct htc_frame_hdr   *pHdr;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("+HTCWaitforControlMessage \n"));

	*ppControlPacket = NULL;

	status = DevPollMboxMsgRecv(target->Device,
			&lookAhead,
			HTC_TARGET_RESPONSE_TIMEOUT);

	if (status)
		goto fail_ctrl_rx;

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
			("HTCWaitforControlMessage : lookAhead : 0x%X \n", lookAhead));

	pHdr = (struct htc_frame_hdr *)&lookAhead;

	BUG_ON(pHdr->EndpointID != ENDPOINT_0);

	pPacket = htc_get_control_buf(target, false);

	BUG_ON(pPacket == NULL);

	pPacket->PktInfo.AsRx.HTCRxFlags = 0;
	pPacket->PktInfo.AsRx.ExpectedHdr = lookAhead;
	pPacket->ActualLength = pHdr->PayloadLen + HTC_HDR_LENGTH;

	BUG_ON(pPacket->ActualLength > pPacket->BufferLength);

	/* we want synchronous operation */
	pPacket->Completion = NULL;

	/* get the message from the device, this will block */
	status = dev_rx_pkt(target, pPacket, pPacket->ActualLength);

	if (status)
		goto fail_ctrl_rx;

	/* process receive header */
	status = HTCProcessRecvHeader(target,pPacket,NULL,NULL);

	pPacket->Status = status;

	if (status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,
				("HTCWaitforControlMessage, HTCProcessRecvHeader failed (status = %d) \n",
				 status));
		goto fail_ctrl_rx;
	}

	/* give the caller this control message packet, they are responsible to free */
	*ppControlPacket = pPacket;


fail_ctrl_rx:
	if (status) {
		if (pPacket != NULL) {
			/* cleanup buffer on error */
			HTC_PACKET_RESET_RX(pPacket);
			reclaim_rx_ctrl_buf(target,pPacket);
		}
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,("-HTCWaitforControlMessage \n"));

	return status;
}

int HTCAddReceivePktMultiple(void * HTCHandle, struct htc_packet_queue *pPktQueue)
{
	struct htc_target      *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	struct htc_endpoint    *pEndpoint;
	bool          unblockRecv = false;
	int        status = 0;
	struct htc_packet      *pFirstPacket;

	pFirstPacket = HTC_GET_PKT_AT_HEAD(pPktQueue);

	BUG_ON(!pFirstPacket);

	if (pFirstPacket->Endpoint >= ENDPOINT_MAX) {
		status = -EINVAL;
		goto fail_rx_multiple;
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_RECV,
			("+- HTCAddReceivePktMultiple : endPointId: %d, cnt:%d, length: %d\n",
			 pFirstPacket->Endpoint,
			 HTC_PACKET_QUEUE_DEPTH(pPktQueue),
			 pFirstPacket->BufferLength));

	pEndpoint = &target->EndPoint[pFirstPacket->Endpoint];

	spin_lock_bh(&target->HTCRxLock);

	if (HTC_STOPPING(target)) {
		struct htc_packet *pPacket;

		spin_unlock_bh(&target->HTCRxLock);

		/* walk through queue and mark each one canceled */
		HTC_PACKET_QUEUE_ITERATE_ALLOW_REMOVE(pPktQueue,pPacket) {
			pPacket->Status = A_ECANCELED;
		} HTC_PACKET_QUEUE_ITERATE_END;

		DoRecvCompletion(pEndpoint,pPktQueue);
		goto fail_rx_multiple;
	}

	/* store receive packets */
	HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(&pEndpoint->RxBuffers, pPktQueue);

	/* check if we are blocked waiting for a new buffer */
	if (target->RecvStateFlags & HTC_RECV_WAIT_BUFFERS) {
		if (target->EpWaitingForBuffers == pFirstPacket->Endpoint) {
			AR_DEBUG_PRINTF(ATH_DEBUG_RECV,(" receiver was blocked on ep:%d, unblocking.. \n",
						target->EpWaitingForBuffers));
			target->RecvStateFlags &= ~HTC_RECV_WAIT_BUFFERS;
			target->EpWaitingForBuffers = ENDPOINT_MAX;
			unblockRecv = true;
		}
	}

	spin_unlock_bh(&target->HTCRxLock);

	if (unblockRecv && !HTC_STOPPING(target)) {
		/* TODO : implement a buffer threshold count? */
		DevEnableRecv(target->Device,false);
	}

fail_rx_multiple:
	return status;
}

/* Makes a buffer available to the HTC module */
int HTCAddReceivePkt(void * HTCHandle, struct htc_packet *pPacket)
{
	struct htc_packet_queue queue;
	INIT_HTC_PACKET_QUEUE_AND_ADD(&queue,pPacket);
	return HTCAddReceivePktMultiple(HTCHandle, &queue);
}

static void HTCFlushRxQueue(struct htc_target *target, struct htc_endpoint *pEndpoint, struct htc_packet_queue *pQueue)
{
	struct htc_packet  *pPacket;
	struct htc_packet_queue container;

	spin_lock_bh(&target->HTCRxLock);

	while (1) {
		pPacket = HTC_PACKET_DEQUEUE(pQueue);
		if (NULL == pPacket) {
			break;
		}
		spin_unlock_bh(&target->HTCRxLock);
		pPacket->Status = A_ECANCELED;
		pPacket->ActualLength = 0;
		AR_DEBUG_PRINTF(ATH_DEBUG_RECV, ("  Flushing RX packet:0x%lX, length:%d, ep:%d \n",
					(unsigned long)pPacket, pPacket->BufferLength, pPacket->Endpoint));
		INIT_HTC_PACKET_QUEUE_AND_ADD(&container,pPacket);
		/* give the packet back */
		DoRecvCompletion(pEndpoint,&container);
		spin_lock_bh(&target->HTCRxLock);
	}

	spin_unlock_bh(&target->HTCRxLock);
}

static void HTCFlushEndpointRX(struct htc_target *target, struct htc_endpoint *pEndpoint)
{
	/* flush any recv indications not already made */
	HTCFlushRxQueue(target,pEndpoint,&pEndpoint->RecvIndicationQueue);
	/* flush any rx buffers */
	HTCFlushRxQueue(target,pEndpoint,&pEndpoint->RxBuffers);
}

void HTCFlushRecvBuffers(struct htc_target *target)
{
	struct htc_endpoint    *pEndpoint;
	int             i;

	for (i = ENDPOINT_0; i < ENDPOINT_MAX; i++) {
		pEndpoint = &target->EndPoint[i];
		if (pEndpoint->ServiceID == 0) {
			/* not in use.. */
			continue;
		}
		HTCFlushEndpointRX(target,pEndpoint);
	}
}

int HTCGetNumRecvBuffers(void *      HTCHandle,
		enum htc_endpoint_id Endpoint)
{
	struct htc_target *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	return HTC_PACKET_QUEUE_DEPTH(&(target->EndPoint[Endpoint].RxBuffers));
}
void HTCFreeControlBuffer(struct htc_target *target, struct htc_packet *pPacket,
		struct htc_packet_queue *pList)
{
	spin_lock_bh(&target->HTCLock);
	HTC_PACKET_ENQUEUE(pList,pPacket);
	spin_unlock_bh(&target->HTCLock);
}

static void ResetEndpointStates(struct htc_target *target)
{
	struct htc_endpoint        *pEndpoint;
	int                  i;

	for (i = ENDPOINT_0; i < ENDPOINT_MAX; i++) {
		pEndpoint = &target->EndPoint[i];

		memset(&pEndpoint->CreditDist, 0, sizeof(pEndpoint->CreditDist));
		pEndpoint->ServiceID = 0;
		pEndpoint->MaxMsgLength = 0;
		pEndpoint->MaxTxQueueDepth = 0;
		memset(&pEndpoint->EndPointStats, 0, sizeof(pEndpoint->EndPointStats));
		INIT_HTC_PACKET_QUEUE(&pEndpoint->RxBuffers);
		INIT_HTC_PACKET_QUEUE(&pEndpoint->TxQueue);
		INIT_HTC_PACKET_QUEUE(&pEndpoint->RecvIndicationQueue);
		pEndpoint->target = target;
	}
	/* reset distribution list */
	target->EpCreditDistributionListHead = NULL;
}

/* cleanup the HTC instance */
void HTCCleanup(struct htc_target *target)
{
	struct htc_packet *packet, *tmp_packet;

	DevCleanup(target->Device);

	list_for_each_entry_safe(packet, tmp_packet,
				 &target->free_ctrl_txbuf, list) {
		list_del(&packet->list);
		kfree(packet->pBufferStart);
		kfree(packet);
	}

	list_for_each_entry_safe(packet, tmp_packet,
				 &target->free_ctrl_rxbuf, list) {
		list_del(&packet->list);
		kfree(packet->pBufferStart);
		kfree(packet);
	}

	kfree(target->Device);
	kfree(target);
}

/* registered target arrival callback from the HIF layer */
void * HTCCreate(void *hif_handle, struct htc_init_info *pInfo)
{
	struct htc_target *target = NULL;
	int status = 0, i = 0;
	u32 blocksizes[HTC_MAILBOX_NUM_MAX], ctrl_bufsz;

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("HTCCreate - Enter\n"));


	/* allocate target memory */
	if ((target = kzalloc(sizeof(*target), GFP_KERNEL)) == NULL) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unable to allocate memory\n"));
		status = -ENOMEM;
		goto fail_create_htc;
	}

	target->Device = kzalloc(sizeof(*target->Device), GFP_KERNEL);
	if (target->Device == NULL) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unable to allocate memory\n"));
		status = -ENOMEM;
		goto fail_create_htc;
	}

	spin_lock_init(&target->HTCLock);
	spin_lock_init(&target->HTCRxLock);
	spin_lock_init(&target->HTCTxLock);
	INIT_LIST_HEAD(&target->free_ctrl_txbuf);
	INIT_LIST_HEAD(&target->free_ctrl_rxbuf);

	target->Device->HIFDevice = hif_handle;
	target->Device->HTCContext = target;
	target->Device->TargetFailureCallback = HTCReportFailure;
	target->Device->MessagePendingCallback = HTCRecvMessagePendingHandler;
	target->EpWaitingForBuffers = ENDPOINT_MAX;

	memcpy(&target->HTCInitInfo, pInfo, sizeof(struct htc_init_info));

	ResetEndpointStates(target);

	status = DevSetup(target->Device);

	if (status)
		goto fail_create_htc;

	status = hif_config_dev(hif_handle, HIF_DEVICE_GET_MBOX_BLOCK_SIZE,
				blocksizes, sizeof(blocksizes));
	if (status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Failed to get block size info from HIF layer...\n"));
		goto fail_create_htc;
	}

	if (blocksizes[1] > HTC_MAX_CONTROL_MESSAGE_LENGTH)
		ctrl_bufsz = blocksizes[1] + HTC_HDR_LENGTH;
	else
		ctrl_bufsz = HTC_MAX_CONTROL_MESSAGE_LENGTH + HTC_HDR_LENGTH;

	for (i = 0; i < NUM_CONTROL_BUFFERS; i++) {
		struct htc_packet *packet;

		packet = kzalloc(sizeof(*packet), GFP_KERNEL);
		if (!packet)
			break;

		packet->pBufferStart = kzalloc(ctrl_bufsz, GFP_KERNEL);
		if (!packet->pBufferStart)
			break;

		packet->BufferLength = ctrl_bufsz;
		if (i < NUM_CONTROL_RX_BUFFERS) {
			packet->ActualLength = 0;
			packet->pPktContext = target;
			packet->pBuffer = packet->pBufferStart;
			packet->Endpoint = ENDPOINT_0;
			list_add_tail(&packet->list, &target->free_ctrl_rxbuf);
		} else
			list_add_tail(&packet->list, &target->free_ctrl_txbuf);
	}

fail_create_htc:
	if (i != NUM_CONTROL_BUFFERS || status) {
		if (target != NULL) {
			HTCCleanup(target);
			target = NULL;
		}
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("HTCCreate - Exit\n"));

	return target;
}

void *HTCGetHifDevice(void * HTCHandle)
{
    struct htc_target *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
    return target->Device->HIFDevice;
}

int HTCWaitTarget(void * HTCHandle)
{
	struct htc_target              *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	int status;
	struct htc_packet *pPacket = NULL;
	struct htc_ready_ext_msg        *pRdyMsg;

	struct htc_service_connect_req  connect;
	struct htc_service_connect_resp resp;

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("HTCWaitTarget - Enter (target:0x%lX) \n", (unsigned long)target));

	/* we should be getting 1 control message that the target is ready */
	status = HTCWaitforControlMessage(target, &pPacket);

	if (status) {
		AR_DEBUG_PRINTF(ATH_DEBUG_ERR, (" Target Not Available!!\n"));
		goto fail_wait_target;
	}

	/* we controlled the buffer creation so it has to be properly aligned */
	pRdyMsg = (struct htc_ready_ext_msg *)pPacket->pBuffer;

	if ((pRdyMsg->Version2_0_Info.MessageID != HTC_MSG_READY_ID) ||
			(pPacket->ActualLength < sizeof(struct htc_ready_msg))) {
		/* this message is not valid */
		AR_DEBUG_ASSERT(false);
		status = -ENOMEM;
		goto fail_wait_target;
	}


	if (pRdyMsg->Version2_0_Info.CreditCount == 0 || pRdyMsg->Version2_0_Info.CreditSize == 0) {
		/* this message is not valid */
		AR_DEBUG_ASSERT(false);
		status = -ENOMEM;
		goto fail_wait_target;
	}

	target->TargetCredits = pRdyMsg->Version2_0_Info.CreditCount;
	target->TargetCreditSize = pRdyMsg->Version2_0_Info.CreditSize;

	AR_DEBUG_PRINTF(ATH_DEBUG_WARN, (" Target Ready: credits: %d credit size: %d\n",
				target->TargetCredits, target->TargetCreditSize));

	/* check if this is an extended ready message */
	if (pPacket->ActualLength >= sizeof(struct htc_ready_ext_msg)) {
		/* this is an extended message */
		target->HTCTargetVersion = pRdyMsg->HTCVersion;
		target->MaxMsgPerBundle = pRdyMsg->MaxMsgsPerHTCBundle;
	} else {
		/* legacy */
		target->HTCTargetVersion = HTC_VERSION_2P0;
		target->MaxMsgPerBundle = 0;
	}

#ifdef HTC_FORCE_LEGACY_2P0
	/* for testing and comparison...*/
	target->HTCTargetVersion = HTC_VERSION_2P0;
	target->MaxMsgPerBundle = 0;
#endif

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC,
			("Using HTC Protocol Version : %s (%d)\n ",
			 (target->HTCTargetVersion == HTC_VERSION_2P0) ? "2.0" : ">= 2.1",
			 target->HTCTargetVersion));

	if (target->MaxMsgPerBundle > 0) {
		/* limit what HTC can handle */
		target->MaxMsgPerBundle = min(HTC_HOST_MAX_MSG_PER_BUNDLE, target->MaxMsgPerBundle);
		/* target supports message bundling, setup device layer */
		if (DevSetupMsgBundling(target->Device,target->MaxMsgPerBundle)) {
			/* device layer can't handle bundling */
			target->MaxMsgPerBundle = 0;
		} else {
			/* limit bundle what the device layer can handle */
			target->MaxMsgPerBundle = min(DEV_GET_MAX_MSG_PER_BUNDLE(target->Device),
					target->MaxMsgPerBundle);
		}
	}

	if (target->MaxMsgPerBundle > 0) {
		AR_DEBUG_PRINTF(ATH_DEBUG_TRC,
				(" HTC bundling allowed. Max Msg Per HTC Bundle: %d\n", target->MaxMsgPerBundle));

		if (DEV_GET_MAX_BUNDLE_SEND_LENGTH(target->Device) != 0) {
			target->SendBundlingEnabled = true;
		}
		if (DEV_GET_MAX_BUNDLE_RECV_LENGTH(target->Device) != 0) {
			target->RecvBundlingEnabled = true;
		}

		if (!DEV_IS_LEN_BLOCK_ALIGNED(target->Device,target->TargetCreditSize)) {
			AR_DEBUG_PRINTF(ATH_DEBUG_WARN, ("*** Credit size: %d is not block aligned! Disabling send bundling \n",
						target->TargetCreditSize));
			/* disallow send bundling since the credit size is not aligned to a block size
			 * the I/O block padding will spill into the next credit buffer which is fatal */
			target->SendBundlingEnabled = false;
		}
	}

	/* setup our pseudo HTC control endpoint connection */
	memset(&connect, 0, sizeof(connect));
	memset(&resp, 0, sizeof(resp));
	connect.EpCallbacks.pContext = target;
	connect.EpCallbacks.EpTxComplete = NULL;
	connect.EpCallbacks.EpRecv = HTCControlRecv;
	connect.EpCallbacks.EpRecvRefill = NULL;  /* not needed */
	connect.EpCallbacks.EpSendFull = NULL;    /* not nedded */
	connect.MaxSendQueueDepth = NUM_CONTROL_BUFFERS;
	connect.ServiceID = HTC_CTRL_RSVD_SVC;

	/* connect fake service */
	status = HTCConnectService((void *)target,
			&connect,
			&resp);

fail_wait_target:
	if (pPacket != NULL) {
		HTC_PACKET_RESET_RX(pPacket);
		reclaim_rx_ctrl_buf(target, pPacket);
	}

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("HTCWaitTarget - Exit\n"));

	return status;
}

/* Start HTC, enable interrupts and let the target know host has finished setup */
int HTCStart(void * HTCHandle)
{
	struct htc_target *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	struct htc_packet *pPacket;
	int   status;

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("HTCStart Enter\n"));

	/* make sure interrupts are disabled at the chip level,
	 * this function can be called again from a reboot of the target without shutting down HTC */
	DevDisableInterrupts(target->Device);
	/* make sure state is cleared again */
	target->OpStateFlags = 0;
	target->RecvStateFlags = 0;

	/* now that we are starting, push control receive buffers into the
	 * HTC control endpoint */

	while (1) {
		pPacket = htc_get_control_buf(HTCHandle, false);
		if (!pPacket)
			break;
		status = HTCAddReceivePkt((void *)target, pPacket);
		if (status)
			goto out;
	}

	BUG_ON(target->InitCredits == NULL);
	BUG_ON(target->EpCreditDistributionListHead == NULL);
	BUG_ON(target->EpCreditDistributionListHead->pNext == NULL);

	/* call init credits callback to do the distribution ,
	 * NOTE: the first entry in the distribution list is ENDPOINT_0, so
	 * we pass the start of the list after this one. */
	target->InitCredits(target->pCredDistContext,
			target->EpCreditDistributionListHead->pNext,
			target->TargetCredits);

#ifdef ATH_DEBUG_MODULE

	if (AR_DEBUG_LVL_CHECK(ATH_DEBUG_TRC)) {
		DumpCreditDistStates(target);
	}
#endif

	/* the caller is done connecting to services, so we can indicate to the
	 * target that the setup phase is complete */
	status = HTCSendSetupComplete(target);

	if (status)
		goto out;

	/* unmask interrupts */
	status = DevUnmaskInterrupts(target->Device);

	if (status) {
		HTCStop(target);
	}


out:
	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("HTCStart Exit\n"));
	return status;
}

/* stop HTC communications, i.e. stop interrupt reception, and flush all queued buffers */
void HTCStop(void * HTCHandle)
{
	struct htc_target *target = GET_HTC_TARGET_FROM_HANDLE(HTCHandle);
	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("+HTCStop \n"));

	spin_lock_bh(&target->HTCLock);
	/* mark that we are shutting down .. */
	target->OpStateFlags |= HTC_OP_STATE_STOPPING;
	spin_unlock_bh(&target->HTCLock);

	/* Masking interrupts is a synchronous operation, when this function returns
	 * all pending HIF I/O has completed, we can safely flush the queues */
	DevMaskInterrupts(target->Device);

	/* flush all send packets */
	HTCFlushSendPkts(target);
	/* flush all recv buffers */
	HTCFlushRecvBuffers(target);

	DevCleanupMsgBundling(target->Device);

	ResetEndpointStates(target);

	AR_DEBUG_PRINTF(ATH_DEBUG_TRC, ("-HTCStop \n"));
}
