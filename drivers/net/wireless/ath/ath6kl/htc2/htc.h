/*
 * Copyright (c) 2004-2011 Atheros Communications Inc.
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

#ifndef HTC_H
#define HTC_H

#include "dl_list.h"
#include <ath6kl.h>
#include "bmi.h"

#define ASSEMBLE_UNALIGNED_UINT16(p,highbyte,lowbyte) \
        (((u16)(((u8 *)(p))[(highbyte)])) << 8 | (u16)(((u8 *)(p))[(lowbyte)]))
        
/* alignment independent macros (little-endian) to fetch UINT16s or UINT8s from a 
 *structure using only the type and field name.
 * Use these macros if there is the potential for unaligned buffer accesses. */
#define A_GET_UINT16_FIELD(p,type,field) \
    ASSEMBLE_UNALIGNED_UINT16(p,\
                              offsetof(type,field) + 1, \
                              offsetof(type,field))

#define A_SET_UINT16_FIELD(p,type,field,value) \
{                                              \
    ((u8 *)(p))[offsetof(type,field)] = (u8)(value);        \
    ((u8 *)(p))[offsetof(type,field) + 1] = (u8)((value) >> 8); \
}
  
#define A_GET_UINT8_FIELD(p,type,field) \
            ((u8 *)(p))[offsetof(type,field)]
            
#define A_SET_UINT8_FIELD(p,type,field,value) \
    ((u8 *)(p))[offsetof(type,field)] = (value)

/* frame header flags */

/* send direction */
#define HTC_FLAGS_NEED_CREDIT_UPDATE (1 << 0)
#define HTC_FLAGS_SEND_BUNDLE        (1 << 1)

/* receive direction */
#define HTC_FLAGS_RECV_UNUSED_0      (1 << 0)
#define HTC_FLAGS_RECV_TRAILER       (1 << 1)
#define HTC_FLAGS_RECV_UNUSED_2      (1 << 0)
#define HTC_FLAGS_RECV_UNUSED_3      (1 << 0)
#define HTC_FLAGS_RECV_BUNDLE_CNT_MASK (0xF0)
#define HTC_FLAGS_RECV_BUNDLE_CNT_SHIFT 4

/****** DANGER DANGER ***************
 * 
 *   The frame header length and message formats defined herein were
 *   selected to accommodate optimal alignment for target processing.  This reduces code
 *   size and improves performance.
 * 
 *   Any changes to the header length may alter the alignment and cause exceptions
 *   on the target. When adding to the messagestructures insure that fields are
 *   properly aligned.
 * 
 */

/* HTC frame header */
struct htc_frame_hdr {
	/* do not remove or re-arrange these fields, these are minimally required
	 * to take advantage of 4-byte lookaheads in some hardware implementations */
	u8 EndpointID;
	u8 Flags;
	u16 PayloadLen;       /* length of data (including trailer) that follows the header */

	/***** end of 4-byte lookahead ****/

	u8 ControlBytes[2];
} __attribute__ ((packed));

#define HTC_HDR_LENGTH  (sizeof(struct htc_frame_hdr))
#define HTC_MAX_TRAILER_LENGTH   255
#define HTC_MAX_PAYLOAD_LENGTH   (4096 - sizeof(struct htc_frame_hdr))

/* HTC control message IDs */

#define HTC_MSG_READY_ID                    1
#define HTC_MSG_CONNECT_SERVICE_ID          2
#define HTC_MSG_CONNECT_SERVICE_RESPONSE_ID 3   
#define HTC_MSG_SETUP_COMPLETE_ID           4
#define HTC_MSG_SETUP_COMPLETE_EX_ID        5

#define HTC_MAX_CONTROL_MESSAGE_LENGTH  256
         
#define HTC_VERSION_2P0  0x00  
#define HTC_VERSION_2P1  0x01

#define HTC_SERVICE_META_DATA_MAX_LENGTH 128

#define HTC_CONNECT_FLAGS_REDUCE_CREDIT_DRIBBLE 	(1 << 2)
#define HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_MASK		(0x3)  
#define HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_ONE_FOURTH	0x0
#define HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_ONE_HALF	0x1
#define HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_THREE_FOURTHS	0x2
#define HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_UNITY		0x3

/* HTC ready message */
struct htc_ready_msg {
	u16 MessageID;
	u16 CreditCount;
	u16 CreditSize;
	u8 MaxEndpoints;
	u8 _Pad1;
} __attribute__ ((packed));

/* extended HTC ready message */
struct htc_ready_ext_msg {
	struct htc_ready_msg Version2_0_Info;
	u8 HTCVersion;
	u8 MaxMsgsPerHTCBundle;
} __attribute__ ((packed));

/* connect service */
struct htc_conn_service_msg {
	u16 MessageID;
	u16 ServiceID;
	u16 ConnectionFlags;
	u8 ServiceMetaLength;
	u8 _Pad1;
} __attribute__ ((packed));

/* connect response */
struct htc_conn_service_resp {
	u16 MessageID;
	u16 ServiceID;
	u8 Status;
	u8 EndpointID;
	u16 MaxMsgSize;
	u8 ServiceMetaLength;
	u8 _Pad1;
} __attribute__ ((packed));

struct htc_setup_comp_msg {
	u16 MessageID;
} __attribute__ ((packed));

/* extended setup completion message */
struct htc_setup_comp_ext_msg {
	u16 MessageID;
	u32 SetupFlags;
	u8 MaxMsgsPerBundledRecv;
	u8 Rsvd[3];
} __attribute__ ((packed));

#define HTC_SETUP_COMPLETE_FLAGS_ENABLE_BUNDLE_RECV     (1 << 0)

/* connect response status codes */
#define HTC_SERVICE_SUCCESS      0  /* success */
#define HTC_SERVICE_NOT_FOUND    1  /* service could not be found */
#define HTC_SERVICE_FAILED       2  /* specific service failed the connect */
#define HTC_SERVICE_NO_RESOURCES 3  /* no resources (i.e. no more endpoints) */  
#define HTC_SERVICE_NO_MORE_EP   4  /* specific service is not allowing any more 
                                       endpoints */

/* report record IDs */
#define HTC_RECORD_NULL             0
#define HTC_RECORD_CREDITS          1
#define HTC_RECORD_LOOKAHEAD        2
#define HTC_RECORD_LOOKAHEAD_BUNDLE 3

struct htc_record_hdr {
	u8 RecordID;
	u8 Length;
} __attribute__ ((packed));

struct htc_credit_report {
	u8 EndpointID;
	u8 Credits;
} __attribute__ ((packed));

/*
 * NOTE: The LookAhead array is guarded by a PreValid
 * and Post Valid guard bytes. The PreValid bytes must
 * equal the inverse of the PostValid byte.
 */
struct htc_lookahead_report {    
    u8 PreValid;
    u8 LookAhead[4];
    u8 PostValid;
} __attribute__ ((packed));

struct htc_bundled_lookahd_report {
    u8 LookAhead[4];
} __attribute__ ((packed));

/* Current service IDs */

enum htc_service_grp_ids {
	RSVD_SERVICE_GROUP  = 0,
	WMI_SERVICE_GROUP   = 1, 

	HTC_TEST_GROUP = 254,
	HTC_SERVICE_GROUP_LAST = 255
};

#define MAKE_SERVICE_ID(group,index) \
            (int)(((int)group << 8) | (int)(index))

/* NOTE: service ID of 0x0000 is reserved and should never be used */
#define HTC_CTRL_RSVD_SVC MAKE_SERVICE_ID(RSVD_SERVICE_GROUP,1)
#define WMI_CONTROL_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP,0)
#define WMI_DATA_BE_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP,1)
#define WMI_DATA_BK_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP,2)
#define WMI_DATA_VI_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP,3)
#define WMI_DATA_VO_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP,4)
#define WMI_MAX_SERVICES  5

/* raw stream service (i.e. flash, tcmd, calibration apps) */
#define HTC_RAW_STREAMS_SVC MAKE_SERVICE_ID(HTC_TEST_GROUP,0)

/* ------ Endpoint IDS ------ */

enum htc_endpoint_id {
    ENDPOINT_UNUSED = -1,
    ENDPOINT_0 = 0,
    ENDPOINT_1 = 1,
    ENDPOINT_2 = 2,
    ENDPOINT_3,
    ENDPOINT_4,
    ENDPOINT_5,
    ENDPOINT_6,
    ENDPOINT_7,
    ENDPOINT_8,
    ENDPOINT_MAX,
};

struct htc_tx_packet_info {
	u16 Tag;
	int CreditsUsed;
	u8 SendFlags;
	int SeqNo;
};
/* HTC Packet Queueing Macros */
struct htc_packet_queue {
       struct dl_list     QueueHead;
       int         Depth;
};

#define HTC_TX_PACKET_TAG_ALL          0    /* a tag of zero is reserved and used to flush ALL packets */
#define HTC_TX_PACKET_TAG_INTERNAL     1
#define HTC_TX_PACKET_TAG_USER_DEFINED (HTC_TX_PACKET_TAG_INTERNAL + 9)

struct htc_rx_packet_info {
	u32 ExpectedHdr;
	u32 HTCRxFlags;
	u32 IndicationFlags;
};

#define HTC_RX_FLAGS_INDICATE_MORE_PKTS  (1 << 0)   /* more packets on this endpoint are being fetched */

/* wrapper around endpoint-specific packets */
struct htc_packet {
	struct list_head list;
	struct dl_list         ListLink;
	void            *pPktContext;   /* caller's per packet specific context */

	u8 *pBufferStart;  /* the true buffer start , the caller can
			      store the real buffer start here.  In
			      receive callbacks, the HTC layer sets pBuffer
			      to the start of the payload past the header. This
			      field allows the caller to reset pBuffer when it
			      recycles receive packets back to HTC */
	/*
	 * Pointer to the start of the buffer. In the transmit
	 * direction this points to the start of the payload. In the
	 * receive direction, however, the buffer when queued up
	 * points to the start of the HTC header but when returned
	 * to the caller points to the start of the payload
	 */
	u8 *pBuffer;       /* payload start (RX/TX) */
	u32 BufferLength;   /* length of buffer */
	u32 ActualLength;   /* actual length of payload */
	enum htc_endpoint_id Endpoint;       /* endpoint that this packet was sent/recv'd from */
	int        Status;         /* completion status */
	union {
		struct htc_tx_packet_info  AsTx;   /* Tx Packet specific info */
		struct htc_rx_packet_info  AsRx;   /* Rx Packet specific info */
	} PktInfo;

	void (*Completion) (void *, struct htc_packet *);
	void                  *pContext;    /* HTC private completion context */
};



#define COMPLETE_HTC_PACKET(p,status)        \
{                                            \
    (p)->Status = (status);                  \
    (p)->Completion((p)->pContext,(p));      \
}

/* macro to set an initial RX packet for refilling HTC */
#define SET_HTC_PACKET_INFO_RX_REFILL(p,c,b,len,ep) \
{                                                 \
    (p)->pPktContext = (c);                       \
    (p)->pBuffer = (b);                           \
    (p)->pBufferStart = (b);                      \
    (p)->BufferLength = (len);                    \
    (p)->Endpoint = (ep);                         \
}

/* fast macro to recycle an RX packet that will be re-queued to HTC */
#define HTC_PACKET_RESET_RX(p)              \
    { (p)->pBuffer = (p)->pBufferStart; (p)->ActualLength = 0; }  

/* macro to set packet parameters for TX */
#define SET_HTC_PACKET_INFO_TX(p,c,b,len,ep,tag)  \
{                                                 \
    (p)->pPktContext = (c);                       \
    (p)->pBuffer = (b);                           \
    (p)->ActualLength = (len);                    \
    (p)->Endpoint = (ep);                         \
    (p)->PktInfo.AsTx.Tag = (tag);                \
}

/* initialize queue */
#define INIT_HTC_PACKET_QUEUE(pQ)   \
{                                   \
    DL_LIST_INIT(&(pQ)->QueueHead); \
    (pQ)->Depth = 0;                \
}

/* enqueue HTC packet to the tail of the queue */
#define HTC_PACKET_ENQUEUE(pQ,p)                        \
{   DL_ListInsertTail(&(pQ)->QueueHead,&(p)->ListLink); \
    (pQ)->Depth++;                                      \
}

/* enqueue HTC packet to the tail of the queue */
#define HTC_PACKET_ENQUEUE_TO_HEAD(pQ,p)                \
{   DL_ListInsertHead(&(pQ)->QueueHead,&(p)->ListLink); \
    (pQ)->Depth++;                                      \
}
/* test if a queue is empty */
#define HTC_QUEUE_EMPTY(pQ)       ((pQ)->Depth == 0)
/* get packet at head without removing it */
static inline struct htc_packet *HTC_GET_PKT_AT_HEAD(struct htc_packet_queue *queue)   {
    if (queue->Depth == 0) {
        return NULL; 
    }  
    return A_CONTAINING_STRUCT((DL_LIST_GET_ITEM_AT_HEAD(&queue->QueueHead)),struct htc_packet,ListLink);
}
/* remove a packet from a queue, where-ever it is in the queue */
#define HTC_PACKET_REMOVE(pQ,p)     \
{                                   \
    DL_ListRemove(&(p)->ListLink);  \
    (pQ)->Depth--;                  \
}

/* dequeue an HTC packet from the head of the queue */
static inline struct htc_packet *HTC_PACKET_DEQUEUE(struct htc_packet_queue *queue) {
  struct dl_list    *pItem = DL_ListRemoveItemFromHead(&queue->QueueHead);
    if (pItem != NULL) {
        queue->Depth--;
        return A_CONTAINING_STRUCT(pItem,struct htc_packet, ListLink);
    }
    return NULL;
}

/* dequeue an HTC packet from the tail of the queue */
static inline struct htc_packet *HTC_PACKET_DEQUEUE_TAIL(struct htc_packet_queue *queue) {
  struct dl_list    *pItem = DL_ListRemoveItemFromTail(&queue->QueueHead);
    if (pItem != NULL) {
        queue->Depth--;
        return A_CONTAINING_STRUCT(pItem,struct htc_packet, ListLink);
    }
    return NULL;
}

#define HTC_PACKET_QUEUE_DEPTH(pQ) (pQ)->Depth


#define HTC_GET_ENDPOINT_FROM_PKT(p) (p)->Endpoint
#define HTC_GET_TAG_FROM_PKT(p)      (p)->PktInfo.AsTx.Tag

    /* transfer the packets from one queue to the tail of another queue */
#define HTC_PACKET_QUEUE_TRANSFER_TO_TAIL(pQDest,pQSrc) \
{                                                                           \
    DL_ListTransferItemsToTail(&(pQDest)->QueueHead,&(pQSrc)->QueueHead);   \
    (pQDest)->Depth += (pQSrc)->Depth;                                      \
    (pQSrc)->Depth = 0;                                                     \
}

    /* fast version to init and add a single packet to a queue */
#define INIT_HTC_PACKET_QUEUE_AND_ADD(pQ,pP) \
{                                            \
    DL_LIST_INIT_AND_ADD(&(pQ)->QueueHead,&(pP)->ListLink)  \
    (pQ)->Depth = 1;                                        \
}
    
#define HTC_PACKET_QUEUE_ITERATE_ALLOW_REMOVE(pQ, pPTemp) \
    ITERATE_OVER_LIST_ALLOW_REMOVE(&(pQ)->QueueHead,(pPTemp),struct htc_packet, ListLink) 

#define HTC_PACKET_QUEUE_ITERATE_END ITERATE_END

/* TODO.. for BMI */
#define ENDPOINT1 0
// TODO -remove me, but we have to fix BMI first
#define HTC_MAILBOX_NUM_MAX    4

/* this is the amount of header room required by users of HTC */
#define HTC_HEADER_LEN         HTC_HDR_LENGTH

struct htc_init_info {
    void   *pContext;
    void   (*TargetFailure)(void *Instance, int Status);
};

enum htc_send_full_action {
	HTC_SEND_FULL_KEEP = 0,
	HTC_SEND_FULL_DROP = 1,
};

struct htc_ep_callbacks {
	void  *pContext;
	void (*EpTxComplete) (void *, struct htc_packet *);
	void (*EpRecv) (void *, struct htc_packet *);
	void (*EpRecvRefill) (void *, enum htc_endpoint_id Endpoint);
	enum htc_send_full_action (* EpSendFull) (void *, struct htc_packet *);
	struct htc_packet *(*EpRecvAlloc) (void *, enum htc_endpoint_id, int);
	struct htc_packet *(*EpRecvAllocThresh) (void *, enum htc_endpoint_id, int);
	void (*EpTxCompleteMultiple) (void *, struct htc_packet_queue *);
	void (*EpRecvPktMultiple) (void *, struct htc_packet_queue *);
	int RecvAllocThreshold;
	int RecvRefillWaterMark;
};

/* service connection information */
struct htc_service_connect_req {
	u16   ServiceID;
	u16 ConnectionFlags;
	u8 *pMetaData;
	u8 MetaDataLength;
	struct htc_ep_callbacks EpCallbacks;
	int              MaxSendQueueDepth;
	u32 LocalConnectionFlags;
	unsigned int     MaxSendMsgSize;
};

#define HTC_LOCAL_CONN_FLAGS_ENABLE_SEND_BUNDLE_PADDING (1 << 0)  /* enable send bundle padding for this endpoint */

/* service connection response information */
struct htc_service_connect_resp {
	u8 *pMetaData;
	u8 BufferLength;
	u8 ActualLength;
	enum htc_endpoint_id Endpoint;
	unsigned int    MaxMsgLength;
	u8 ConnectRespCode;
};

/* endpoint distributionstructure */
struct htc_endpoint_credit_dist {
  struct htc_endpoint_credit_dist *pNext;
  struct htc_endpoint_credit_dist *pPrev;
    u16      ServiceID;          /* Service ID (set by HTC) */
    enum htc_endpoint_id     Endpoint;           /* endpoint for this distributionstruct (set by HTC) */
    u32 DistFlags;          /* distribution flags, distribution function can
                                               set default activity using SET_EP_ACTIVE() macro */
    int                 TxCreditsNorm;      /* credits for normal operation, anything above this
                                               indicates the endpoint is over-subscribed, this field
                                               is only relevant to the credit distribution function */
    int                 TxCreditsMin;       /* floor for credit distribution, this field is
                                               only relevant to the credit distribution function */
    int                 TxCreditsAssigned;  /* number of credits assigned to this EP, this field
                                               is only relevant to the credit dist function */
    int                 TxCredits;          /* current credits available, this field is used by
                                               HTC to determine whether a message can be sent or
                                               must be queued */
    int                 TxCreditsToDist;    /* pending credits to distribute on this endpoint, this
                                               is set by HTC when credit reports arrive.
                                               The credit distribution functions sets this to zero
                                               when it distributes the credits */
    int                 TxCreditsSeek;      /* this is the number of credits that the current pending TX
                                               packet needs to transmit.  This is set by HTC when
                                               and endpoint needs credits in order to transmit */
    int                 TxCreditSize;       /* size in bytes of each credit (set by HTC) */
    int                 TxCreditsPerMaxMsg; /* credits required for a maximum sized messages (set by HTC) */
    void                *pHTCReserved;      /* reserved for HTC use */    
    int                 TxQueueDepth;       /* current depth of TX queue , i.e. messages waiting for credits
                                               This field is valid only when HTC_CREDIT_DIST_ACTIVITY_CHANGE
                                               or HTC_CREDIT_DIST_SEND_COMPLETE is indicated on an endpoint
                                               that has non-zero credits to recover
                                              */
};

#define HTC_EP_ACTIVE                            ((u32) (1u << 31))

/* macro to check if an endpoint has gone active, useful for credit
 * distributions */
#define IS_EP_ACTIVE(epDist)  ((epDist)->DistFlags & HTC_EP_ACTIVE)
#define SET_EP_ACTIVE(epDist) (epDist)->DistFlags |= HTC_EP_ACTIVE

    /* credit distibution code that is passed into the distrbution function,
     * there are mandatory and optional codes that must be handled */
enum htc_credit_dist_reason {
	HTC_CREDIT_DIST_SEND_COMPLETE = 0,
	HTC_CREDIT_DIST_ACTIVITY_CHANGE = 1,
	HTC_CREDIT_DIST_SEEK_CREDITS,
	HTC_DUMP_CREDIT_STATE,
};

    /* endpoint statistics action */
enum  htc_ep_stat_action {
	HTC_EP_STAT_SAMPLE = 0,                /* only read statistics */
	HTC_EP_STAT_SAMPLE_AND_CLEAR = 1,      /* sample and immediately clear statistics */
	HTC_EP_STAT_CLEAR,                      /* clear only */
};

    /* endpoint statistics */
struct htc_endpoint_stats {
    u32 TxCreditLowIndications;  /* number of times the host set the credit-low flag in a send message on
                                        this endpoint */
    u32 TxIssued;               /* running count of total TX packets issued */
    u32 TxPacketsBundled;       /* running count of TX packets that were issued in bundles */
    u32 TxBundles;              /* running count of TX bundles that were issued */
    u32 TxDropped;              /* tx packets that were dropped */
    u32 TxCreditRpts;           /* running count of total credit reports received for this endpoint */
    u32 TxCreditRptsFromRx;     /* credit reports received from this endpoint's RX packets */
    u32 TxCreditRptsFromOther;  /* credit reports received from RX packets of other endpoints */
    u32 TxCreditRptsFromEp0;    /* credit reports received from endpoint 0 RX packets */
    u32 TxCreditsFromRx;        /* count of credits received via Rx packets on this endpoint */
    u32 TxCreditsFromOther;     /* count of credits received via another endpoint */
    u32 TxCreditsFromEp0;       /* count of credits received via another endpoint */
    u32 TxCreditsConsummed;     /* count of consummed credits */
    u32 TxCreditsReturned;      /* count of credits returned */
    u32 RxReceived;             /* count of RX packets received */
    u32 RxLookAheads;           /* count of lookahead records
                                         found in messages received on this endpoint */
    u32 RxPacketsBundled;       /* count of recv packets received in a bundle */
    u32 RxBundleLookAheads;     /* count of number of bundled lookaheads */
    u32 RxBundleIndFromHdr;     /* count of the number of bundle indications from the HTC header */
    u32 RxAllocThreshHit;       /* count of the number of times the recv allocation threshold was hit */
    u32 RxAllocThreshBytes;     /* total number of bytes */
};

/* HTC operational parameters */
#define HTC_TARGET_RESPONSE_TIMEOUT        2000 /* in ms */
#define HTC_TARGET_DEBUG_INTR_MASK         0x01
#define HTC_TARGET_CREDIT_INTR_MASK        0xF0

#define HTC_HOST_MAX_MSG_PER_BUNDLE        8
#define HTC_MIN_HTC_MSGS_TO_BUNDLE         2

/* packet flags */

#define HTC_RX_PKT_IGNORE_LOOKAHEAD      (1 << 0)
#define HTC_RX_PKT_REFRESH_HDR           (1 << 1)
#define HTC_RX_PKT_PART_OF_BUNDLE        (1 << 2)
#define HTC_RX_PKT_NO_RECYCLE            (1 << 3)

/* scatter request flags */

#define HTC_SCATTER_REQ_FLAGS_PARTIAL_BUNDLE  (1 << 0)

struct htc_endpoint {
	enum htc_endpoint_id Id;
	u16 ServiceID;
	struct htc_packet_queue TxQueue;
	struct htc_packet_queue RxBuffers;
	struct htc_endpoint_credit_dist CreditDist;
	struct htc_ep_callbacks EpCallBacks;
	int MaxTxQueueDepth;
	int MaxMsgLength;
	int TxProcessCount;
	struct htc_packet_queue RecvIndicationQueue;
	int RxProcessCount;
	struct htc_target *target;
	u8 SeqNo;
	u32 LocalConnectionFlags;
	struct htc_endpoint_stats EndPointStats;
};

#define INC_HTC_EP_STAT(p,stat,count) (p)->EndPointStats.stat += (count);
#define HTC_SERVICE_TX_PACKET_TAG  HTC_TX_PACKET_TAG_INTERNAL

#define NUM_CONTROL_BUFFERS     8
#define NUM_CONTROL_TX_BUFFERS  2
#define NUM_CONTROL_RX_BUFFERS  (NUM_CONTROL_BUFFERS - NUM_CONTROL_TX_BUFFERS)

struct htc_control_buffer {
	struct htc_packet    HtcPacket;
	u8 *Buffer;
};

#define HTC_RECV_WAIT_BUFFERS        (1 << 0)
#define HTC_OP_STATE_STOPPING        (1 << 0)

struct ar6k_device;

/* our HTC target state */
struct htc_target {
	struct htc_endpoint                EndPoint[ENDPOINT_MAX];
	struct htc_endpoint_credit_dist   *EpCreditDistributionListHead;
	struct list_head free_ctrl_txbuf;
	struct list_head free_ctrl_rxbuf;
	void (*DistributeCredits) (void *, struct htc_endpoint_credit_dist *,
			enum htc_credit_dist_reason);
	void (*InitCredits) (void *,  struct htc_endpoint_credit_dist *,
			int);
	void                       *pCredDistContext;
	int                         TargetCredits;
	unsigned int                TargetCreditSize;
	spinlock_t                   HTCLock;
	spinlock_t                   HTCRxLock;
	spinlock_t                   HTCTxLock;
	struct ar6k_device                 *Device;         /* AR6K - specific state */
	u32 OpStateFlags;
	u32 RecvStateFlags;
	enum htc_endpoint_id             EpWaitingForBuffers;
	bool                      TargetFailure;
#ifdef HTC_CAPTURE_LAST_FRAME
	struct htc_frame_hdr               LastFrameHdr;  /* useful for debugging */
	u8 LastTrailer[256];
	u8 LastTrailerLength;
#endif
	struct htc_init_info               HTCInitInfo;
	u8 HTCTargetVersion;
	int                         MaxMsgPerBundle;       /* max messages per bundle for HTC */
	bool                      SendBundlingEnabled;   /* run time enable for send bundling (dynamic) */
	int                         RecvBundlingEnabled;   /* run time enable for recv bundling (dynamic) */
};



#define HTC_STOPPING(t) ((t)->OpStateFlags & HTC_OP_STATE_STOPPING)

#define GET_HTC_TARGET_FROM_HANDLE(hnd) ((struct htc_target *)(hnd))
#define HTC_RECYCLE_RX_PKT(target,p,e)                           \
{                                                                \
    if ((p)->PktInfo.AsRx.HTCRxFlags & HTC_RX_PKT_NO_RECYCLE) {  \
         HTC_PACKET_RESET_RX(pPacket);                           \
         pPacket->Status = A_ECANCELED;                          \
         (e)->EpCallBacks.EpRecv((e)->EpCallBacks.pContext,      \
                                 (p));                           \
    } else {                                                     \
        HTC_PACKET_RESET_RX(pPacket);                            \
        HTCAddReceivePkt((void *)(target),(p));              \
    }                                                            \
}

/* internal HTC functions */
void        HTCControlTxComplete(void *Context,struct htc_packet *pPacket);
void        HTCFreeControlBuffer(struct htc_target *target,struct htc_packet *pPacket,struct htc_packet_queue *pList);
void        HTCFlushRecvBuffers(struct htc_target *target);

#ifdef ATH_DEBUG_MODULE
void 		DebugDumpBytes(u8 *buffer, u16 length, char *pDescription);
#endif

void * HTCCreate(void *HifDevice,struct htc_init_info *pInfo);
void       *HTCGetHifDevice(void * HTCHandle);
void        HTCSetCreditDistribution(void *               HTCHandle,
                                     void                     *pCreditDistContext,
                                     void (*CreditDistFunc) (void *,
				     struct htc_endpoint_credit_dist *, enum htc_credit_dist_reason),
                                     void (*CreditInitFunc) (void *,
				     struct htc_endpoint_credit_dist *, int),
                                     u16           ServicePriorityOrder[],
                                     int                      ListLength);
int    HTCWaitTarget(void * HTCHandle);
int    HTCStart(void * HTCHandle);
int    HTCAddReceivePkt(void * HTCHandle,struct htc_packet *pPacket);
int    HTCConnectService(void * HTCHandle,
                            struct htc_service_connect_req  *pReq,
                            struct htc_service_connect_resp *pResp);
int    HTCSendPkt(void * HTCHandle,struct htc_packet *pPacket);
void HTCStop(void * HTCHandle);
void HTCCleanup(struct htc_target *target);
void        HTCFlushEndpoint(void * HTCHandle, enum htc_endpoint_id Endpoint, u16 Tag);
void        HTCDumpCreditStates(void * HTCHandle);
void        HTCIndicateActivityChange(void *      HTCHandle,
                                      enum htc_endpoint_id Endpoint,
                                      bool          Active);
int    HTCSendPktsMultiple(void * HTCHandle,struct htc_packet_queue *pPktQueue);
int         HTCGetNumRecvBuffers(void *      HTCHandle,
                                 enum htc_endpoint_id Endpoint);
int HTCAddReceivePktMultiple(void * HTCHandle, struct htc_packet_queue *pPktQueue);

#define HTC_PREPARE_SEND_PKT(pP,sendflags,ctrl0,ctrl1)       \
{                                                   \
    u8 *pHdrBuf;                               \
    (pP)->pBuffer -= HTC_HDR_LENGTH;                \
    pHdrBuf = (pP)->pBuffer;                        \
    A_SET_UINT16_FIELD(pHdrBuf,struct htc_frame_hdr,PayloadLen,(u16)(pP)->ActualLength);  \
    A_SET_UINT8_FIELD(pHdrBuf,struct htc_frame_hdr,Flags,(sendflags));                         \
    A_SET_UINT8_FIELD(pHdrBuf,struct htc_frame_hdr,EndpointID, (u8)(pP)->Endpoint); \
    A_SET_UINT8_FIELD(pHdrBuf,struct htc_frame_hdr,ControlBytes[0], (u8)(ctrl0));   \
    A_SET_UINT8_FIELD(pHdrBuf,struct htc_frame_hdr,ControlBytes[1], (u8)(ctrl1));   \
}

#define HTC_UNPREPARE_SEND_PKT(pP)     \
    (pP)->pBuffer += HTC_HDR_LENGTH;   \

#endif
