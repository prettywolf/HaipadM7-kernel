//------------------------------------------------------------------------------
// Copyright (c) 2004-2010 Atheros Corporation.  All rights reserved.
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
// This module implements the hardware independent layer of the
// Wireless Module Interface (WMI) protocol.
//
// Author(s): ="Atheros"
//==============================================================================

#include <linux/ieee80211.h>
#include <ath6kl.h>
#include "htc.h"
#include <ieee80211.h>
#include <ieee80211_node.h>
#include "wmi.h"
#define ATH_MODULE_NAME wmi
#include "a_debug.h"
#include "ar6xapi_linux.h"

#define ATH_DEBUG_WMI ATH_DEBUG_MAKE_MODULE_MASK(0)

#ifdef ATH_DEBUG_MODULE

static struct ath_debug_mask_description wmi_debug_desc[] = {
    { ATH_DEBUG_WMI , "General WMI Tracing"},
};

ATH_DEBUG_INSTANTIATE_MODULE_VAR(wmi,
                                 "wmi",
                                 "Wireless Module Interface",
                                 ATH_DEBUG_MASK_DEFAULTS,
                                 ATH_DEBUG_DESCRIPTION_COUNT(wmi_debug_desc),
                                 wmi_debug_desc);

#endif

#ifndef REXOS
#define DBGARG      _A_FUNCNAME_
#define DBGFMT      "%s() : "
#define DBG_WMI     ATH_DEBUG_WMI
#define DBG_ERROR   ATH_DEBUG_ERR
#define DBG_WMI2    ATH_DEBUG_WMI
#define A_DPRINTF   AR_DEBUG_PRINTF
#endif

static int wmi_ready_event_rx(struct wmi_t *wmip, u8 *datap, int len);

static int wmi_connect_event_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);
static int wmi_disconnect_event_rx(struct wmi_t *wmip, u8 *datap,
                                        int len);

static int wmi_tkip_micerr_event_rx(struct wmi_t *wmip, u8 *datap,
                                        int len);
static int wmi_bssInfo_event_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);
static int wmi_opt_frame_event_rx(struct wmi_t *wmip, u8 *datap,
                                       int len);
static int wmi_pstream_timeout_event_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);
static int wmi_sync_point(struct wmi_t *wmip);

static int wmi_bitrate_reply_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);
static int wmi_ratemask_reply_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);
static int wmi_channelList_reply_rx(struct wmi_t *wmip, u8 *datap,
                                         int len);
static int wmi_regDomain_event_rx(struct wmi_t *wmip, u8 *datap,
                                       int len);
static int wmi_txPwr_reply_rx(struct wmi_t *wmip, u8 *datap, int len);
static int wmi_neighborReport_event_rx(struct wmi_t *wmip, u8 *datap,
                                             int len);
static int wmi_scanComplete_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);
static int wmi_errorEvent_rx(struct wmi_t *wmip, u8 *datap, int len);
static int wmi_statsEvent_rx(struct wmi_t *wmip, u8 *datap, int len);
static int wmi_rssiThresholdEvent_rx(struct wmi_t *wmip, u8 *datap, int len);
static int wmi_hbChallengeResp_rx(struct wmi_t *wmip, u8 *datap, int len);
static int wmi_reportErrorEvent_rx(struct wmi_t *wmip, u8 *datap, int len);
static int wmi_cac_event_rx(struct wmi_t *wmip, u8 *datap, int len);
static int wmi_channel_change_event_rx(struct wmi_t *wmip, u8 *datap, int len);
static int wmi_roam_tbl_event_rx(struct wmi_t *wmip, u8 *datap,
                                      int len);
static int wmi_roam_data_event_rx(struct wmi_t *wmip, u8 *datap,
                                      int len);
static int wmi_get_wow_list_event_rx(struct wmi_t *wmip, u8 *datap,
                                      int len);
static int
wmi_get_pmkid_list_event_rx(struct wmi_t *wmip, u8 *datap, u32 len);

static int
wmi_set_params_event_rx(struct wmi_t *wmip, u8 *datap, u32 len);

static int
wmi_txRetryErrEvent_rx(struct wmi_t *wmip, u8 *datap, int len);

static int
wmi_snrThresholdEvent_rx(struct wmi_t *wmip, u8 *datap, int len);

static int
wmi_lqThresholdEvent_rx(struct wmi_t *wmip, u8 *datap, int len);

static bool
wmi_is_bitrate_index_valid(struct wmi_t *wmip, s32 rateIndex);

static int
wmi_aplistEvent_rx(struct wmi_t *wmip, u8 *datap, int len);

static int wmi_keepalive_reply_rx(struct wmi_t *wmip, u8 *datap, int len);

int wmi_cmd_send_xtnd(struct wmi_t *wmip, void *osbuf, enum wmix_command_id cmdId,
                  enum wmi_sync_flag syncflag);

u8 ar6000_get_upper_threshold(s16 rssi, struct sq_threshold_params_s *sq_thresh, u32 size);
u8 ar6000_get_lower_threshold(s16 rssi, struct sq_threshold_params_s *sq_thresh, u32 size);

void wmi_cache_configure_rssithreshold(struct wmi_t *wmip, struct wmi_rssi_threshold_params_cmd *rssiCmd);
void wmi_cache_configure_snrthreshold(struct wmi_t *wmip, struct wmi_snr_threshold_params_cmd *snrCmd);
static int wmi_send_rssi_threshold_params(struct wmi_t *wmip,
                              struct wmi_rssi_threshold_params_cmd *rssiCmd);
static int wmi_send_snr_threshold_params(struct wmi_t *wmip,
                             struct wmi_snr_threshold_params_cmd *snrCmd);
#if defined(CONFIG_TARGET_PROFILE_SUPPORT)
static int
wmi_prof_count_rx(struct wmi_t *wmip, u8 *datap, int len);
#endif /* CONFIG_TARGET_PROFILE_SUPPORT */

static int wmi_pspoll_event_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);
static int wmi_dtimexpiry_event_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);

static int wmi_peer_node_event_rx (struct wmi_t *wmip, u8 *datap,
                                        int len);
static int wmi_addba_req_event_rx(struct wmi_t *, u8 *, int);
static int wmi_addba_resp_event_rx(struct wmi_t *, u8 *, int);
static int wmi_delba_req_event_rx(struct wmi_t *, u8 *, int);

#ifdef WAPI_ENABLE
static int wmi_wapi_rekey_event_rx(struct wmi_t *wmip, u8 *datap,
                                     int len);
#endif

#if defined(UNDER_CE)
#if defined(NDIS51_MINIPORT)
unsigned int processDot11Hdr = 0;
#else
unsigned int processDot11Hdr = 1;
#endif
#else
extern unsigned int processDot11Hdr;
#endif

int wps_enable;
static const s32 wmi_rateTable[][2] = {
  //{W/O SGI, with SGI}
    {1000, 1000},
    {2000, 2000},
    {5500, 5500},
    {11000, 11000},
    {6000, 6000},
    {9000, 9000},
    {12000, 12000},
    {18000, 18000},
    {24000, 24000},
    {36000, 36000},
    {48000, 48000},
    {54000, 54000},
    {6500, 7200},
    {13000, 14400},
    {19500, 21700},
    {26000, 28900},
    {39000, 43300},
    {52000, 57800},
    {58500, 65000},
    {65000, 72200},
    {13500, 15000},
    {27000, 30000},
    {40500, 45000},
    {54000, 60000},
    {81000, 90000},
    {108000, 120000},
    {121500, 135000},
    {135000, 150000},
    {0, 0}};

#define MODE_A_SUPPORT_RATE_START       ((s32) 4)
#define MODE_A_SUPPORT_RATE_STOP        ((s32) 11)

#define MODE_GONLY_SUPPORT_RATE_START   MODE_A_SUPPORT_RATE_START
#define MODE_GONLY_SUPPORT_RATE_STOP    MODE_A_SUPPORT_RATE_STOP

#define MODE_B_SUPPORT_RATE_START       ((s32) 0)
#define MODE_B_SUPPORT_RATE_STOP        ((s32) 3)

#define MODE_G_SUPPORT_RATE_START       ((s32) 0)
#define MODE_G_SUPPORT_RATE_STOP        ((s32) 11)

#define MODE_GHT20_SUPPORT_RATE_START   ((s32) 0)
#define MODE_GHT20_SUPPORT_RATE_STOP    ((s32) 19)

#define MAX_NUMBER_OF_SUPPORT_RATES     (MODE_GHT20_SUPPORT_RATE_STOP + 1)

/* 802.1d to AC mapping. Refer pg 57 of WMM-test-plan-v1.2 */
const u8 up_to_ac[]= {
                WMM_AC_BE,
                WMM_AC_BK,
                WMM_AC_BK,
                WMM_AC_BE,
                WMM_AC_VI,
                WMM_AC_VI,
                WMM_AC_VO,
                WMM_AC_VO,
            };

/* This stuff is used when we want a simple layer-3 visibility */
typedef struct _iphdr {
    u8 ip_ver_hdrlen;          /* version and hdr length */
    u8 ip_tos;                 /* type of service */
    u16 ip_len;                 /* total length */
    u16 ip_id;                  /* identification */
    s16 ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u8 ip_ttl;                 /* time to live */
    u8 ip_p;                   /* protocol */
    u16 ip_sum;                 /* checksum */
    u8 ip_src[4];              /* source and dest address */
    u8 ip_dst[4];
} __attribute__ ((packed)) iphdr;

static s16 rssi_event_value = 0;
static s16 snr_event_value = 0;

bool is_probe_ssid = false;

void *
wmi_init(void *devt)
{
    struct wmi_t *wmip;


    wmip = kmalloc (sizeof(struct wmi_t), GFP_KERNEL);
    if (wmip == NULL) {
        return (NULL);
    }

    memset(wmip, 0, sizeof(struct wmi_t ));
    spin_lock_init(&wmip->wmi_lock);

    wmip->wmi_devt = devt;
    wlan_node_table_init(wmip, &wmip->wmi_scan_table);
    wmi_qos_state_init(wmip);

    wmip->wmi_powerMode = REC_POWER;
    wmip->wmi_phyMode = WMI_11G_MODE;

    wmip->wmi_pair_crypto_type  = NONE_CRYPT;
    wmip->wmi_grp_crypto_type   = NONE_CRYPT;

    wmip->wmi_ht_allowed[A_BAND_24GHZ] = 1;
    wmip->wmi_ht_allowed[A_BAND_5GHZ] = 1;

    return (wmip);
}

void
wmi_qos_state_init(struct wmi_t *wmip)
{
    u8 i;

    if (wmip == NULL) {
        return;
    }

    spin_lock_bh(&wmip->wmi_lock);

    /* Initialize QoS States */
    wmip->wmi_numQoSStream = 0;

    wmip->wmi_fatPipeExists = 0;

    for (i=0; i < WMM_NUM_AC; i++) {
        wmip->wmi_streamExistsForAC[i]=0;
    }

    spin_unlock_bh(&wmip->wmi_lock);
}

void
wmi_set_control_ep(struct wmi_t * wmip, enum htc_endpoint_id eid)
{
    A_ASSERT( eid != ENDPOINT_UNUSED);
    wmip->wmi_endpoint_id = eid;
}

enum htc_endpoint_id
wmi_get_control_ep(struct wmi_t * wmip)
{
    return(wmip->wmi_endpoint_id);
}

void
wmi_shutdown(struct wmi_t *wmip)
{
    if (wmip != NULL) {
        wlan_node_table_cleanup(&wmip->wmi_scan_table);
        kfree(wmip);
    }
}

/*
 *  performs DIX to 802.3 encapsulation for transmit packets.
 *  uses passed in buffer.  Returns buffer or NULL if failed.
 *  Assumes the entire DIX header is contigous and that there is
 *  enough room in the buffer for a 802.3 mac header and LLC+SNAP headers.
 */
int
wmi_dix_2_dot3(struct wmi_t *wmip, void *osbuf)
{
    u8 *datap;
    u16 typeorlen;
    ATH_MAC_HDR      macHdr;
    ATH_LLC_SNAP_HDR *llcHdr;

    A_ASSERT(osbuf != NULL);

    if (skb_headroom((struct sk_buff *)osbuf) <
        (sizeof(ATH_LLC_SNAP_HDR) + sizeof(struct wmi_data_hdr)))
    {
        return A_NO_MEMORY;
    }

    datap = ((struct sk_buff *)osbuf)->data;

    typeorlen = *(u16 *)(datap + ETH_ALEN + ETH_ALEN);

    if (!IS_ETHERTYPE(ntohs(typeorlen))) {
        /*
         * packet is already in 802.3 format - return success
         */
        A_DPRINTF(DBG_WMI, (DBGFMT "packet already 802.3\n", DBGARG));
        return (0);
    }

    /*
     * Save mac fields and length to be inserted later
     */
    memcpy(macHdr.dstMac, datap, ETH_ALEN);
    memcpy(macHdr.srcMac, datap + ETH_ALEN, ETH_ALEN);
    macHdr.typeOrLen = htons(((struct sk_buff *)osbuf)->len - sizeof(ATH_MAC_HDR) +
                                  sizeof(ATH_LLC_SNAP_HDR));

    /*
     * Make room for LLC+SNAP headers
     */
    skb_push((struct sk_buff *)osbuf, sizeof(ATH_LLC_SNAP_HDR));
    datap = ((struct sk_buff *)osbuf)->data;

    memcpy(datap, &macHdr, sizeof (ATH_MAC_HDR));

    llcHdr = (ATH_LLC_SNAP_HDR *)(datap + sizeof(ATH_MAC_HDR));
    llcHdr->dsap      = 0xAA;
    llcHdr->ssap      = 0xAA;
    llcHdr->cntl      = 0x03;
    llcHdr->orgCode[0] = 0x0;
    llcHdr->orgCode[1] = 0x0;
    llcHdr->orgCode[2] = 0x0;
    llcHdr->etherType = typeorlen;

    return (0);
}

int wmi_meta_add(struct wmi_t *wmip, void *osbuf, u8 *pVersion,void *pTxMetaS)
{
    switch(*pVersion){
	case 0:
		return (0);
    	case WMI_META_VERSION_1:
	        {
		struct wmi_tx_meta_v1    *pV1= NULL;
        	A_ASSERT(osbuf != NULL);
		skb_push((struct sk_buff *)osbuf, WMI_MAX_TX_META_SZ);
		pV1 = (struct wmi_tx_meta_v1 *)((struct sk_buff *)osbuf)->data;
        	/* the pktID is used in conjunction with txComplete messages
        	* allowing the target to notify which tx requests have been
        	* completed and how. */
        	pV1->pktID = 0;
        	/* the ratePolicyID allows the host to specify which rate policy
        	* to use for transmitting this packet. 0 means use default behavior. */
        	pV1->ratePolicyID = 0;
        	A_ASSERT(pVersion != NULL);
        	/* the version must be used to populate the meta field of the WMI_DATA_HDR */
        	*pVersion = WMI_META_VERSION_1;
		return (0);
    		}
	case WMI_META_VERSION_2:
		{
		struct wmi_tx_meta_v2 *pV2 ;
        	A_ASSERT(osbuf != NULL);
		skb_push((struct sk_buff *)osbuf, WMI_MAX_TX_META_SZ);
		pV2 = (struct wmi_tx_meta_v2 *)((struct sk_buff *)osbuf)->data;
		memcpy(pV2,(struct wmi_tx_meta_v2 *)pTxMetaS,sizeof(struct wmi_tx_meta_v2));
		return (0);
    		}
	default:
		return (0);
    }
}

/* Adds a WMI data header */
int
wmi_data_hdr_add(struct wmi_t *wmip, void *osbuf, u8 msgType, bool bMoreData,
                 enum wmi_data_hdr_data_type data_type,u8 metaVersion, void *pTxMetaS)
{
    struct wmi_data_hdr     *dtHdr;
//    u8 metaVersion = 0;
    int status;

    A_ASSERT(osbuf != NULL);

    /* adds the meta data field after the wmi data hdr. If metaVersion
     * is returns 0 then no meta field was added. */
    if ((status = wmi_meta_add(wmip, osbuf, &metaVersion,pTxMetaS)) != 0) {
        return status;
    }

    skb_push((struct sk_buff *)osbuf, sizeof(struct wmi_data_hdr));

    dtHdr = (struct wmi_data_hdr *)((struct sk_buff *)osbuf)->data;
    memset(dtHdr, 0, sizeof(struct wmi_data_hdr));

    WMI_DATA_HDR_SET_MSG_TYPE(dtHdr, msgType);
    WMI_DATA_HDR_SET_DATA_TYPE(dtHdr, data_type);

    if (bMoreData) {
        WMI_DATA_HDR_SET_MORE_BIT(dtHdr);
    }

    WMI_DATA_HDR_SET_META(dtHdr, metaVersion);

    dtHdr->info3 = 0;

    return (0);
}


u8 wmi_implicit_create_pstream(struct wmi_t *wmip, void *osbuf, u32 layer2Priority, bool wmmEnabled)
{
    u8 *datap;
    u8 trafficClass = WMM_AC_BE;
    u16 ipType = IP_ETHERTYPE;
    struct wmi_data_hdr    *dtHdr;
    u8 streamExists = 0;
    u8 userPriority;
    u32 hdrsize, metasize;
    ATH_LLC_SNAP_HDR    *llcHdr;

    struct wmi_create_pstream_cmd  cmd;

    A_ASSERT(osbuf != NULL);

    //
    // Initialize header size
    //
    hdrsize = 0;

    datap = ((struct sk_buff *)osbuf)->data;
    dtHdr = (struct wmi_data_hdr *)datap;
    metasize = (WMI_DATA_HDR_GET_META(dtHdr))? WMI_MAX_TX_META_SZ : 0;

    if (!wmmEnabled)
    {
            /* If WMM is disabled all traffic goes as BE traffic */
        userPriority = 0;
    }
    else
    {
        if (processDot11Hdr)
        {
             hdrsize = roundup(sizeof(struct ieee80211_qos_hdr),sizeof(u32));
             llcHdr = (ATH_LLC_SNAP_HDR *)(datap + sizeof(struct wmi_data_hdr) + metasize +
                          hdrsize);


        }
        else
        {
            llcHdr = (ATH_LLC_SNAP_HDR *)(datap + sizeof(struct wmi_data_hdr) + metasize +
                          sizeof(ATH_MAC_HDR));
        }

        if (llcHdr->etherType == htons(ipType))
        {
            /* Extract the endpoint info from the TOS field in the IP header */

            userPriority = wmi_determine_userPriority (((u8 *)llcHdr) + sizeof(ATH_LLC_SNAP_HDR),layer2Priority);
        }
        else
        {
            userPriority = layer2Priority & 0x7;
        }
    }


    /* workaround for WMM S5 */
    if ((WMM_AC_VI == wmip->wmi_traffic_class) && ((5 == userPriority) || (4 == userPriority)))
    {
        userPriority = 1;
    }

    trafficClass = convert_userPriority_to_trafficClass(userPriority);

    WMI_DATA_HDR_SET_UP(dtHdr, userPriority);
    /* lower 3-bits are 802.1d priority */
    //dtHdr->info |= (userPriority & WMI_DATA_HDR_UP_MASK) << WMI_DATA_HDR_UP_SHIFT;

    spin_lock_bh(&wmip->wmi_lock);
    streamExists = wmip->wmi_fatPipeExists;
    spin_unlock_bh(&wmip->wmi_lock);

    if (!(streamExists & (1 << trafficClass)))
    {

        memset(&cmd, 0, sizeof(cmd));
        cmd.trafficClass = trafficClass;
        cmd.userPriority = userPriority;
        cmd.inactivityInt = WMI_IMPLICIT_PSTREAM_INACTIVITY_INT;
            /* Implicit streams are created with TSID 0xFF */

        cmd.tsid = WMI_IMPLICIT_PSTREAM;
        wmi_create_pstream_cmd(wmip, &cmd);
    }

    return trafficClass;
}

int
wmi_dot11_hdr_add (struct wmi_t *wmip, void *osbuf, enum network_type mode)
{
    u8 *datap;
    u16 typeorlen;
    ATH_MAC_HDR      macHdr;
    ATH_LLC_SNAP_HDR *llcHdr;
    struct           ieee80211_frame *wh;
    u32 hdrsize;

    A_ASSERT(osbuf != NULL);

    if (skb_headroom((struct sk_buff *)osbuf) <
        (sizeof(struct ieee80211_qos_hdr) +  sizeof(ATH_LLC_SNAP_HDR) + sizeof(struct wmi_data_hdr)))
    {
        return A_NO_MEMORY;
    }

    datap = ((struct sk_buff *)osbuf)->data;

    typeorlen = *(u16 *)(datap + ETH_ALEN + ETH_ALEN);

    if (!IS_ETHERTYPE(ntohs(typeorlen))) {
/*
         * packet is already in 802.3 format - return success
         */
        A_DPRINTF(DBG_WMI, (DBGFMT "packet already 802.3\n", DBGARG));
        goto AddDot11Hdr;
    }

    /*
     * Save mac fields and length to be inserted later
     */
    memcpy(macHdr.dstMac, datap, ETH_ALEN);
    memcpy(macHdr.srcMac, datap + ETH_ALEN, ETH_ALEN);
    macHdr.typeOrLen = htons(((struct sk_buff *)osbuf)->len - sizeof(ATH_MAC_HDR) +
                                  sizeof(ATH_LLC_SNAP_HDR));

    // Remove the Ethernet hdr
    skb_pull((struct sk_buff *)osbuf, sizeof(ATH_MAC_HDR));

    /*
     * Make room for LLC+SNAP headers
     */
    skb_push((struct sk_buff *)osbuf, sizeof(ATH_LLC_SNAP_HDR));
    datap = ((struct sk_buff *)osbuf)->data;

    llcHdr = (ATH_LLC_SNAP_HDR *)(datap);
    llcHdr->dsap       = 0xAA;
    llcHdr->ssap       = 0xAA;
    llcHdr->cntl       = 0x03;
    llcHdr->orgCode[0] = 0x0;
    llcHdr->orgCode[1] = 0x0;
    llcHdr->orgCode[2] = 0x0;
    llcHdr->etherType  = typeorlen;

AddDot11Hdr:
    /* Make room for 802.11 hdr */
    if (wmip->wmi_is_wmm_enabled)
    {
        hdrsize = roundup(sizeof(struct ieee80211_qos_hdr),sizeof(u32));
	skb_push((struct sk_buff *)osbuf, hdrsize);
        wh = (struct ieee80211_frame *) ((struct sk_buff *)osbuf)->data;
        wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_QOS;
    }
    else
    {
        hdrsize = roundup(sizeof(struct ieee80211_frame),sizeof(u32));
	skb_push((struct sk_buff *)osbuf, hdrsize);
        wh = (struct ieee80211_frame *) ((struct sk_buff *)osbuf)->data;
        wh->i_fc[0] = IEEE80211_FC0_SUBTYPE_DATA;
    }
    /* Setup the SA & DA */
    memcpy(wh->i_addr2, macHdr.srcMac, ETH_ALEN);

    if (mode == INFRA_NETWORK) {
        memcpy(wh->i_addr3, macHdr.dstMac, ETH_ALEN);
    }
    else if (mode == ADHOC_NETWORK) {
        memcpy(wh->i_addr1, macHdr.dstMac, ETH_ALEN);
    }

    return (0);
}

int
wmi_dot11_hdr_remove(struct wmi_t *wmip, void *osbuf)
{
    u8 *datap;
    struct           ieee80211_frame *pwh,wh;
    u8 type,subtype;
    ATH_LLC_SNAP_HDR *llcHdr;
    ATH_MAC_HDR      macHdr;
    u32 hdrsize;

    A_ASSERT(osbuf != NULL);
    datap = ((struct sk_buff *)osbuf)->data;

    pwh = (struct ieee80211_frame *)datap;
    type = pwh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = pwh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    memcpy((u8 *)&wh, datap, sizeof(struct ieee80211_frame));

    /* strip off the 802.11 hdr*/
    if (subtype == IEEE80211_FC0_SUBTYPE_QOS) {
        hdrsize = roundup(sizeof(struct ieee80211_qos_hdr),sizeof(u32));
	skb_pull((struct sk_buff *)osbuf, hdrsize);
    } else if (subtype == IEEE80211_FC0_SUBTYPE_DATA) {
	skb_pull((struct sk_buff *)osbuf, sizeof(struct ieee80211_frame));
    }

    datap = ((struct sk_buff *)osbuf)->data;
    llcHdr = (ATH_LLC_SNAP_HDR *)(datap);

    macHdr.typeOrLen = llcHdr->etherType;
    memset(macHdr.dstMac, 0, sizeof(macHdr.dstMac));
    memset(macHdr.srcMac, 0, sizeof(macHdr.srcMac));

    switch (wh.i_fc[1] & IEEE80211_FC1_DIR_MASK) {
    case IEEE80211_FC1_DIR_NODS:
        memcpy(macHdr.dstMac, wh.i_addr1, ETH_ALEN);
        memcpy(macHdr.srcMac, wh.i_addr2, ETH_ALEN);
        break;
    case IEEE80211_FC1_DIR_TODS:
        memcpy(macHdr.dstMac, wh.i_addr3, ETH_ALEN);
        memcpy(macHdr.srcMac, wh.i_addr2, ETH_ALEN);
        break;
    case IEEE80211_FC1_DIR_FROMDS:
        memcpy(macHdr.dstMac, wh.i_addr1, ETH_ALEN);
        memcpy(macHdr.srcMac, wh.i_addr3, ETH_ALEN);
        break;
    case IEEE80211_FC1_DIR_DSTODS:
        break;
    }

    // Remove the LLC Hdr.
    skb_pull((struct sk_buff *)osbuf, sizeof(ATH_LLC_SNAP_HDR));

    // Insert the ATH MAC hdr.
    skb_push((struct sk_buff *)osbuf, sizeof(ATH_MAC_HDR));
    datap = ((struct sk_buff *)osbuf)->data;

    memcpy (datap, &macHdr, sizeof(ATH_MAC_HDR));

    return 0;
}

/*
 *  performs 802.3 to DIX encapsulation for received packets.
 *  Assumes the entire 802.3 header is contigous.
 */
int
wmi_dot3_2_dix(void *osbuf)
{
    u8 *datap;
    ATH_MAC_HDR      macHdr;
    ATH_LLC_SNAP_HDR *llcHdr;

    A_ASSERT(osbuf != NULL);
    datap = ((struct sk_buff *)osbuf)->data;

    memcpy(&macHdr, datap, sizeof(ATH_MAC_HDR));
    llcHdr = (ATH_LLC_SNAP_HDR *)(datap + sizeof(ATH_MAC_HDR));
    macHdr.typeOrLen = llcHdr->etherType;

    skb_pull((struct sk_buff *)osbuf, sizeof(ATH_LLC_SNAP_HDR));

    datap = ((struct sk_buff *)osbuf)->data;

    memcpy(datap, &macHdr, sizeof (ATH_MAC_HDR));

    return (0);
}

/*
 * Removes a WMI data header
 */
int
wmi_data_hdr_remove(struct wmi_t *wmip, void *osbuf)
{
    A_ASSERT(osbuf != NULL);

    skb_pull((struct sk_buff *)osbuf, sizeof(struct wmi_data_hdr));

    return 0;
}

void
wmi_iterate_nodes(struct wmi_t *wmip, wlan_node_iter_func *f, void *arg)
{
    wlan_iterate_nodes(&wmip->wmi_scan_table, f, arg);
}

/*
 * WMI Extended Event received from Target.
 */
int
wmi_control_rx_xtnd(struct wmi_t *wmip, void *osbuf)
{
    struct wmix_cmd_hdr *cmd;
    u16 id;
    u8 *datap;
    u32 len;
    int status = 0;

    if (((struct sk_buff *)osbuf)->len < sizeof(struct wmix_cmd_hdr)) {
        A_DPRINTF(DBG_WMI, (DBGFMT "bad packet 1\n", DBGARG));
        wmip->wmi_stats.cmd_len_err++;
        return A_ERROR;
    }

    cmd = (struct wmix_cmd_hdr *)((struct sk_buff *)osbuf)->data;
    id = cmd->commandId;

    skb_pull((struct sk_buff *)osbuf, sizeof(struct wmix_cmd_hdr));

    datap = ((struct sk_buff *)osbuf)->data;
    len = ((struct sk_buff *)osbuf)->len;

    switch (id) {
    case (WMIX_HB_CHALLENGE_RESP_EVENTID):
        wmi_hbChallengeResp_rx(wmip, datap, len);
        break;
    case (WMIX_DBGLOG_EVENTID):
        break;
#if defined(CONFIG_TARGET_PROFILE_SUPPORT)
    case (WMIX_PROF_COUNT_EVENTID):
        wmi_prof_count_rx(wmip, datap, len);
        break;
#endif /* CONFIG_TARGET_PROFILE_SUPPORT */
    default:
        A_DPRINTF(DBG_WMI|DBG_ERROR,
            (DBGFMT "Unknown id 0x%x\n", DBGARG, id));
        wmip->wmi_stats.cmd_id_err++;
        status = A_ERROR;
        break;
    }

    return status;
}

/*
 * Control Path
 */
u32 cmdRecvNum;

int
wmi_control_rx(struct wmi_t *wmip, void *osbuf)
{
    struct wmi_cmd_hdr *cmd;
    u16 id;
    u8 *datap;
    u32 len, i, loggingReq;
    int status = 0;

    A_ASSERT(osbuf != NULL);
    if (((struct sk_buff *)osbuf)->len < sizeof(struct wmi_cmd_hdr)) {
        dev_kfree_skb((struct sk_buff *)osbuf);
        A_DPRINTF(DBG_WMI, (DBGFMT "bad packet 1\n", DBGARG));
        wmip->wmi_stats.cmd_len_err++;
        return A_ERROR;
    }

    cmd = (struct wmi_cmd_hdr *)((struct sk_buff *)osbuf)->data;
    id = cmd->commandId;

    skb_pull((struct sk_buff *)osbuf, sizeof(struct wmi_cmd_hdr));

    datap = ((struct sk_buff *)osbuf)->data;
    len = ((struct sk_buff *)osbuf)->len;

    loggingReq = 0;

    ar6000_get_driver_cfg(wmip->wmi_devt,
                    AR6000_DRIVER_CFG_LOG_RAW_WMI_MSGS,
                    &loggingReq);

    if(loggingReq) {
        AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("WMI %d \n",id));
        AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("WMI recv, MsgNo %d : ", cmdRecvNum));
        for(i = 0; i < len; i++)
            AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("%x ", datap[i]));
        AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("\n"));
    }

    spin_lock_bh(&wmip->wmi_lock);
    cmdRecvNum++;
    spin_unlock_bh(&wmip->wmi_lock);

    switch (id) {
    case (WMI_GET_BITRATE_CMDID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_GET_BITRATE_CMDID\n", DBGARG));
        status = wmi_bitrate_reply_rx(wmip, datap, len);
        break;
    case (WMI_GET_CHANNEL_LIST_CMDID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_GET_CHANNEL_LIST_CMDID\n", DBGARG));
        status = wmi_channelList_reply_rx(wmip, datap, len);
        break;
    case (WMI_GET_TX_PWR_CMDID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_GET_TX_PWR_CMDID\n", DBGARG));
        status = wmi_txPwr_reply_rx(wmip, datap, len);
        break;
    case (WMI_READY_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_READY_EVENTID\n", DBGARG));
        status = wmi_ready_event_rx(wmip, datap, len);
        break;
    case (WMI_CONNECT_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_CONNECT_EVENTID\n", DBGARG));
	status = wmi_connect_event_rx(wmip, datap, len);
        break;
    case (WMI_DISCONNECT_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_DISCONNECT_EVENTID\n", DBGARG));
        status = wmi_disconnect_event_rx(wmip, datap, len);
        break;
    case (WMI_PEER_NODE_EVENTID):
        A_DPRINTF (DBG_WMI, (DBGFMT "WMI_PEER_NODE_EVENTID\n", DBGARG));
        status = wmi_peer_node_event_rx(wmip, datap, len);
        break;
    case (WMI_TKIP_MICERR_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_TKIP_MICERR_EVENTID\n", DBGARG));
        status = wmi_tkip_micerr_event_rx(wmip, datap, len);
        break;
    case (WMI_BSSINFO_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_BSSINFO_EVENTID\n", DBGARG));
        {
            /*
             * convert WMI_BSS_INFO_HDR2 to WMI_BSS_INFO_HDR
             * Take a local copy of the WMI_BSS_INFO_HDR2 from the wmi buffer
             * and reconstruct the WMI_BSS_INFO_HDR in its place
            */
            struct wmi_bss_info_hdr2 bih2;
            struct wmi_bss_info_hdr *bih;
            memcpy(&bih2, datap, sizeof(struct wmi_bss_info_hdr2));

	    skb_push((struct sk_buff *)osbuf, 4);
            datap = ((struct sk_buff *)osbuf)->data;
            len = ((struct sk_buff *)osbuf)->len;
            bih = (struct wmi_bss_info_hdr *)datap;

            bih->channel = bih2.channel;
            bih->frameType = bih2.frameType;
            bih->snr = bih2.snr;
            bih->rssi = bih2.snr - 95;
            bih->ieMask = bih2.ieMask;
            memcpy(bih->bssid, bih2.bssid, ETH_ALEN);

            status = wmi_bssInfo_event_rx(wmip, datap, len);
        }
        break;
    case (WMI_REGDOMAIN_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_REGDOMAIN_EVENTID\n", DBGARG));
        status = wmi_regDomain_event_rx(wmip, datap, len);
        break;
    case (WMI_PSTREAM_TIMEOUT_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_PSTREAM_TIMEOUT_EVENTID\n", DBGARG));
        status = wmi_pstream_timeout_event_rx(wmip, datap, len);
        break;
    case (WMI_NEIGHBOR_REPORT_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_NEIGHBOR_REPORT_EVENTID\n", DBGARG));
        status = wmi_neighborReport_event_rx(wmip, datap, len);
        break;
    case (WMI_SCAN_COMPLETE_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_SCAN_COMPLETE_EVENTID\n", DBGARG));
        status = wmi_scanComplete_rx(wmip, datap, len);
        break;
    case (WMI_CMDERROR_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_CMDERROR_EVENTID\n", DBGARG));
        status = wmi_errorEvent_rx(wmip, datap, len);
        break;
    case (WMI_REPORT_STATISTICS_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_REPORT_STATISTICS_EVENTID\n", DBGARG));
        status = wmi_statsEvent_rx(wmip, datap, len);
        break;
    case (WMI_RSSI_THRESHOLD_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_RSSI_THRESHOLD_EVENTID\n", DBGARG));
        status = wmi_rssiThresholdEvent_rx(wmip, datap, len);
        break;
    case (WMI_ERROR_REPORT_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_ERROR_REPORT_EVENTID\n", DBGARG));
        status = wmi_reportErrorEvent_rx(wmip, datap, len);
        break;
    case (WMI_OPT_RX_FRAME_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_OPT_RX_FRAME_EVENTID\n", DBGARG));
        status = wmi_opt_frame_event_rx(wmip, datap, len);
        break;
    case (WMI_REPORT_ROAM_TBL_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_REPORT_ROAM_TBL_EVENTID\n", DBGARG));
        status = wmi_roam_tbl_event_rx(wmip, datap, len);
        break;
    case (WMI_EXTENSION_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_EXTENSION_EVENTID\n", DBGARG));
        status = wmi_control_rx_xtnd(wmip, osbuf);
        break;
    case (WMI_CAC_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_CAC_EVENTID\n", DBGARG));
        status = wmi_cac_event_rx(wmip, datap, len);
        break;
    case (WMI_CHANNEL_CHANGE_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_CHANNEL_CHANGE_EVENTID\n", DBGARG));
        status = wmi_channel_change_event_rx(wmip, datap, len);
        break;
    case (WMI_REPORT_ROAM_DATA_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_REPORT_ROAM_DATA_EVENTID\n", DBGARG));
        status = wmi_roam_data_event_rx(wmip, datap, len);
        break;
    case (WMI_GET_FIXRATES_CMDID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_GET_FIXRATES_CMDID\n", DBGARG));
        status = wmi_ratemask_reply_rx(wmip, datap, len);
        break;
    case (WMI_TX_RETRY_ERR_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_TX_RETRY_ERR_EVENTID\n", DBGARG));
        status = wmi_txRetryErrEvent_rx(wmip, datap, len);
        break;
    case (WMI_SNR_THRESHOLD_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_SNR_THRESHOLD_EVENTID\n", DBGARG));
        status = wmi_snrThresholdEvent_rx(wmip, datap, len);
        break;
    case (WMI_LQ_THRESHOLD_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_LQ_THRESHOLD_EVENTID\n", DBGARG));
        status = wmi_lqThresholdEvent_rx(wmip, datap, len);
        break;
    case (WMI_APLIST_EVENTID):
        AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("Received APLIST Event\n"));
        status = wmi_aplistEvent_rx(wmip, datap, len);
        break;
    case (WMI_GET_KEEPALIVE_CMDID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_GET_KEEPALIVE_CMDID\n", DBGARG));
        status = wmi_keepalive_reply_rx(wmip, datap, len);
        break;
    case (WMI_GET_WOW_LIST_EVENTID):
        status = wmi_get_wow_list_event_rx(wmip, datap, len);
        break;
    case (WMI_GET_PMKID_LIST_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_GET_PMKID_LIST Event\n", DBGARG));
        status = wmi_get_pmkid_list_event_rx(wmip, datap, len);
        break;
    case (WMI_PSPOLL_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_PSPOLL_EVENT\n", DBGARG));
        status = wmi_pspoll_event_rx(wmip, datap, len);
        break;
    case (WMI_DTIMEXPIRY_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_DTIMEXPIRY_EVENT\n", DBGARG));
        status = wmi_dtimexpiry_event_rx(wmip, datap, len);
        break;
    case (WMI_SET_PARAMS_REPLY_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_SET_PARAMS_REPLY Event\n", DBGARG));
        status = wmi_set_params_event_rx(wmip, datap, len);
        break;
    case (WMI_ADDBA_REQ_EVENTID):
        status = wmi_addba_req_event_rx(wmip, datap, len);
        break;
    case (WMI_ADDBA_RESP_EVENTID):
        status = wmi_addba_resp_event_rx(wmip, datap, len);
        break;
    case (WMI_DELBA_REQ_EVENTID):
        status = wmi_delba_req_event_rx(wmip, datap, len);
        break;
	case (WMI_REPORT_BTCOEX_CONFIG_EVENTID):
	    A_DPRINTF(DBG_WMI, (DBGFMT "WMI_BTCOEX_CONFIG_EVENTID", DBGARG));
	    break;
	case (WMI_REPORT_BTCOEX_STATS_EVENTID):
	    A_DPRINTF(DBG_WMI, (DBGFMT "WMI_BTCOEX_STATS_EVENTID", DBGARG));
	    break;
    case (WMI_TX_COMPLETE_EVENTID):
        {
            int index;
            struct tx_complete_msg_v1 *pV1;
            struct wmi_tx_complete_event *pEv = (struct wmi_tx_complete_event *)datap;
            A_PRINTF("comp: %d %d %d\n", pEv->numMessages, pEv->msgLen, pEv->msgType);

            for(index = 0 ; index < pEv->numMessages ; index++) {
                pV1 = (struct tx_complete_msg_v1 *)(datap + sizeof(struct wmi_tx_complete_event) + index*sizeof(struct tx_complete_msg_v1));
                A_PRINTF("msg: %d %d %d %d\n", pV1->status, pV1->pktID, pV1->rateIdx, pV1->ackFailures);
            }
        }
        break;
#ifdef WAPI_ENABLE
    case (WMI_WAPI_REKEY_EVENTID):
        A_DPRINTF(DBG_WMI, (DBGFMT "WMI_WAPI_REKEY_EVENTID", DBGARG));
        status = wmi_wapi_rekey_event_rx(wmip, datap, len);
        break;
#endif
    default:
        A_DPRINTF(DBG_WMI|DBG_ERROR,
            (DBGFMT "Unknown id 0x%x\n", DBGARG, id));
        wmip->wmi_stats.cmd_id_err++;
        status = A_ERROR;
        break;
    }

    dev_kfree_skb((struct sk_buff *)osbuf);

    return status;
}

/* Send a "simple" wmi command -- one with no arguments */
static int
wmi_simple_cmd(struct wmi_t *wmip, enum wmi_cmd_id cmdid)
{
    void *osbuf;

    osbuf = ar6k_buf_alloc(0);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    return (wmi_cmd_send(wmip, osbuf, cmdid, NO_SYNC_WMIFLAG));
}

/* Send a "simple" extended wmi command -- one with no arguments.
   Enabling this command only if GPIO or profiling support is enabled.
   This is to suppress warnings on some platforms */
#if defined(CONFIG_TARGET_PROFILE_SUPPORT)
static int
wmi_simple_cmd_xtnd(struct wmi_t *wmip, enum wmix_command_id cmdid)
{u
    void *osbuf;

    osbuf = ar6k_buf_alloc(0);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    return (wmi_cmd_send_xtnd(wmip, osbuf, cmdid, NO_SYNC_WMIFLAG));
}t
#endif

static int
wmi_ready_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_ready_event_2 *ev = (struct wmi_ready_event_2 *)datap;

    if (len < sizeof(struct wmi_ready_event_2)) {
        return A_EINVAL;
    }
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));
    wmip->wmi_ready = true;
    ar6000_ready_event(wmip->wmi_devt, ev->macaddr, ev->phyCapability,
                      ev->sw_version, ev->abi_version);

    return 0;
}

#define LE_READ_4(p)                            \
    ((u32)                            \
     ((((u8 *)(p))[0]      ) | (((u8 *)(p))[1] <<  8) | \
      (((u8 *)(p))[2] << 16) | (((u8 *)(p))[3] << 24)))

static int __inline
iswmmoui(const u8 *frm)
{
    return frm[1] > 3 && LE_READ_4(frm+2) == ((WMM_OUI_TYPE<<24)|WMM_OUI);
}

static int __inline
iswmmparam(const u8 *frm)
{
    return frm[1] > 5 && frm[6] == WMM_PARAM_OUI_SUBTYPE;
}


static int
wmi_connect_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_connect_event *ev;
    u8 *pie,*peie;

    if (len < sizeof(struct wmi_connect_event))
    {
        return A_EINVAL;
    }
    ev = (struct wmi_connect_event *)datap;

    A_DPRINTF(DBG_WMI,
        (DBGFMT "freq %d bssid %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
        DBGARG, ev->channel,
        ev->bssid[0], ev->bssid[1], ev->bssid[2],
        ev->bssid[3], ev->bssid[4], ev->bssid[5]));

    memcpy(wmip->wmi_bssid, ev->bssid, ETH_ALEN);

    /* initialize pointer to start of assoc rsp IEs */
    pie = ev->assocInfo + ev->beaconIeLen + ev->assocReqLen +
                            sizeof(u16)  +  /* capinfo*/
                            sizeof(u16)  +  /* status Code */
                            sizeof(u16)  ;  /* associd */

    /* initialize pointer to end of assoc rsp IEs */
    peie = ev->assocInfo + ev->beaconIeLen + ev->assocReqLen + ev->assocRespLen;

    while (pie < peie)
    {
        switch (*pie)
        {
            case WLAN_EID_VENDOR_SPECIFIC:
                if (iswmmoui(pie))
                {
                    if(iswmmparam (pie))
                    {
                        wmip->wmi_is_wmm_enabled = true;
                    }
                }
            break;
        }

        if (wmip->wmi_is_wmm_enabled)
        {
            break;
        }
        pie += pie[1] + 2;
    }

    ar6000_connect_event(wmip->wmi_devt, ev->channel, ev->bssid,
                         ev->listenInterval, ev->beaconInterval,
                         (enum network_type) ev->networkType, ev->beaconIeLen,
                         ev->assocReqLen, ev->assocRespLen,
                         ev->assocInfo);

    return 0;
}

static int
wmi_regDomain_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_reg_domain_event *ev;

    if (len < sizeof(*ev)) {
        return A_EINVAL;
    }
    ev = (struct wmi_reg_domain_event *)datap;

    ar6000_regDomain_event(wmip->wmi_devt, ev->regDomain);

    return 0;
}

static int
wmi_neighborReport_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_neighbor_report_event *ev;
    int numAps;

    if (len < sizeof(*ev)) {
        return A_EINVAL;
    }
    ev = (struct wmi_neighbor_report_event *)datap;
    numAps = ev->numberOfAps;

    if (len < (int)(sizeof(*ev) + ((numAps - 1) * sizeof(struct wmi_neighbor_info)))) {
        return A_EINVAL;
    }

    ar6000_neighborReport_event(wmip->wmi_devt, numAps, ev->neighbor);

    return 0;
}

static int
wmi_disconnect_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_disconnect_event *ev;
    wmip->wmi_traffic_class = 100;

    if (len < sizeof(struct wmi_disconnect_event)) {
        return A_EINVAL;
    }
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ev = (struct wmi_disconnect_event *)datap;

    memset(wmip->wmi_bssid, 0, sizeof(wmip->wmi_bssid));

    wmip->wmi_is_wmm_enabled = false;
    wmip->wmi_pair_crypto_type = NONE_CRYPT;
    wmip->wmi_grp_crypto_type = NONE_CRYPT;

    ar6000_disconnect_event(wmip->wmi_devt, ev->disconnectReason, ev->bssid,
                            ev->assocRespLen, ev->assocInfo, ev->protocolReasonStatus);

    return 0;
}

static int
wmi_peer_node_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_peer_node_event *ev;

    if (len < sizeof(struct wmi_peer_node_event)) {
        return A_EINVAL;
    }
    ev = (struct wmi_peer_node_event *)datap;
    if (ev->eventCode == PEER_NODE_JOIN_EVENT) {
        A_DPRINTF (DBG_WMI, (DBGFMT "Joined node with Macaddr: ", DBGARG));
    } else if(ev->eventCode == PEER_NODE_LEAVE_EVENT) {
        A_DPRINTF (DBG_WMI, (DBGFMT "left node with Macaddr: ", DBGARG));
    }

    ar6000_peer_event (wmip->wmi_devt, ev->eventCode, ev->peerMacAddr);

    return 0;
}

static int
wmi_tkip_micerr_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_tkip_micerr_event *ev;

    if (len < sizeof(*ev)) {
        return A_EINVAL;
    }
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ev = (struct wmi_tkip_micerr_event *)datap;
    ar6000_tkip_micerr_event(wmip->wmi_devt, ev->keyid, ev->ismcast);

    return 0;
}

static int
wmi_bssInfo_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    bss_t *bss = NULL;
    struct wmi_bss_info_hdr *bih;
    u8 *buf;
    u32 nodeCachingAllowed = 1;
    u8 cached_ssid_len = 0;
    u8 cached_ssid_buf[IEEE80211_NWID_LEN] = {0};
    u8 beacon_ssid_len = 0;

    if (len <= sizeof(struct wmi_bss_info_hdr)) {
        return A_EINVAL;
    }

    bih = (struct wmi_bss_info_hdr *)datap;
    bss = wlan_find_node(&wmip->wmi_scan_table, bih->bssid);

    if (bih->rssi > 0) {
        if (NULL == bss)
            return 0;  //no node found in the table, just drop the node with incorrect RSSI
        else
            bih->rssi = bss->ni_rssi; //Adjust RSSI in datap in case it is used in ar6000_bssInfo_event_rx
    }

    ar6000_bssInfo_event_rx(wmip->wmi_devt, datap, len);
    /* What is driver config for wlan node caching? */
    if(ar6000_get_driver_cfg(wmip->wmi_devt,
                    AR6000_DRIVER_CFG_GET_WLANNODECACHING,
                    &nodeCachingAllowed) != 0) {
        wmi_node_return(wmip, bss);
        return A_EINVAL;
    }

    if(!nodeCachingAllowed) {
        wmi_node_return(wmip, bss);
        return 0;
    }

    buf = datap + sizeof(struct wmi_bss_info_hdr);
    len -= sizeof(struct wmi_bss_info_hdr);

	A_DPRINTF(DBG_WMI2, (DBGFMT "bssInfo event - ch %u, rssi %02x, "
		"bssid \"%pM\"\n", DBGARG, bih->channel,
		(unsigned char) bih->rssi, bih->bssid));

    if(wps_enable && (bih->frameType == PROBERESP_FTYPE) ) {
        wmi_node_return(wmip, bss);
        return 0;
    }

    if (bss != NULL) {
        /*
         * Free up the node.  Not the most efficient process given
         * we are about to allocate a new node but it is simple and should be
         * adequate.
         */

        /* In case of hidden AP, beacon will not have ssid,
         * but a directed probe response will have it,
         * so cache the probe-resp-ssid if already present. */
        if ((true == is_probe_ssid) && (BEACON_FTYPE == bih->frameType))
        {
            u8 *ie_ssid;

            ie_ssid = bss->ni_cie.ie_ssid;
            if(ie_ssid && (ie_ssid[1] <= IEEE80211_NWID_LEN) && (ie_ssid[2] != 0))
            {
                cached_ssid_len = ie_ssid[1];
                memcpy(cached_ssid_buf, ie_ssid + 2, cached_ssid_len);
            }
        }

        /*
         * Use the current average rssi of associated AP base on assumpiton
         * 1. Most os with GUI will update RSSI by wmi_get_stats_cmd() periodically
         * 2. wmi_get_stats_cmd(..) will be called when calling wmi_startscan_cmd(...)
         * The average value of RSSI give end-user better feeling for instance value of scan result
         * It also sync up RSSI info in GUI between scan result and RSSI signal icon
         */
        if (memcmp(wmip->wmi_bssid, bih->bssid, ETH_ALEN) == 0) {
            bih->rssi = bss->ni_rssi;
            bih->snr  = bss->ni_snr;
        }

        wlan_node_reclaim(&wmip->wmi_scan_table, bss);
    }

    /*  beacon/probe response frame format
     *  [8] time stamp
     *  [2] beacon interval
     *  [2] capability information
     *  [tlv] ssid */
    beacon_ssid_len = buf[SSID_IE_LEN_INDEX];

    /* If ssid is cached for this hidden AP, then change buffer len accordingly. */
    if ((true == is_probe_ssid) && (BEACON_FTYPE == bih->frameType) &&
        (0 != cached_ssid_len) &&
        (0 == beacon_ssid_len || (cached_ssid_len > beacon_ssid_len && 0 == buf[SSID_IE_LEN_INDEX + 1])))
    {
        len += (cached_ssid_len - beacon_ssid_len);
    }

    bss = wlan_node_alloc(&wmip->wmi_scan_table, len);
    if (bss == NULL) {
        return A_NO_MEMORY;
    }

    bss->ni_snr        = bih->snr;
    bss->ni_rssi       = bih->rssi;
    A_ASSERT(bss->ni_buf != NULL);

    /* In case of hidden AP, beacon will not have ssid,
     * but a directed probe response will have it,
     * so place the cached-ssid(probe-resp) in the bssinfo. */
    if ((true == is_probe_ssid) && (BEACON_FTYPE == bih->frameType) &&
         (0 != cached_ssid_len) &&
         (0 == beacon_ssid_len || (beacon_ssid_len && 0 == buf[SSID_IE_LEN_INDEX + 1])))
    {
        u8 *ni_buf = bss->ni_buf;
        int buf_len = len;

        /* copy the first 14 bytes such as
         * time-stamp(8), beacon-interval(2), cap-info(2), ssid-id(1), ssid-len(1). */
        memcpy(ni_buf, buf, SSID_IE_LEN_INDEX + 1);

        ni_buf[SSID_IE_LEN_INDEX] = cached_ssid_len;
        ni_buf += (SSID_IE_LEN_INDEX + 1);

        buf += (SSID_IE_LEN_INDEX + 1);
        buf_len -= (SSID_IE_LEN_INDEX + 1);

        /* copy the cached ssid */
        memcpy(ni_buf, cached_ssid_buf, cached_ssid_len);
        ni_buf += cached_ssid_len;

        buf += beacon_ssid_len;
        buf_len -= beacon_ssid_len;

        if (cached_ssid_len > beacon_ssid_len)
            buf_len -= (cached_ssid_len - beacon_ssid_len);

        /* now copy the rest of bytes */
        memcpy(ni_buf, buf, buf_len);
    }
    else
        memcpy(bss->ni_buf, buf, len);

    bss->ni_framelen = len;
    if (wlan_parse_beacon(bss->ni_buf, len, &bss->ni_cie) != 0) {
        wlan_node_free(bss);
        return A_EINVAL;
    }

    /*
     * Update the frequency in ie_chan, overwriting of channel number
     * which is done in wlan_parse_beacon
     */
    bss->ni_cie.ie_chan = bih->channel;
    wlan_setup_node(&wmip->wmi_scan_table, bss, bih->bssid);

    return 0;
}

static int
wmi_opt_frame_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    bss_t *bss;
    struct wmi_opt_rx_info_hdr *bih;
    u8 *buf;

    if (len <= sizeof(struct wmi_opt_rx_info_hdr)) {
        return A_EINVAL;
    }

    bih = (struct wmi_opt_rx_info_hdr *)datap;
    buf = datap + sizeof(struct wmi_opt_rx_info_hdr);
    len -= sizeof(struct wmi_opt_rx_info_hdr);

    A_DPRINTF(DBG_WMI2, (DBGFMT "opt frame event %2.2x:%2.2x\n", DBGARG,
        bih->bssid[4], bih->bssid[5]));

    bss = wlan_find_node(&wmip->wmi_scan_table, bih->bssid);
    if (bss != NULL) {
        /*
         * Free up the node.  Not the most efficient process given
         * we are about to allocate a new node but it is simple and should be
         * adequate.
         */
        wlan_node_reclaim(&wmip->wmi_scan_table, bss);
    }

    bss = wlan_node_alloc(&wmip->wmi_scan_table, len);
    if (bss == NULL) {
        return A_NO_MEMORY;
    }

    bss->ni_snr        = bih->snr;
    bss->ni_cie.ie_chan = bih->channel;
    A_ASSERT(bss->ni_buf != NULL);
    memcpy(bss->ni_buf, buf, len);
    wlan_setup_node(&wmip->wmi_scan_table, bss, bih->bssid);

    return 0;
}

    /* This event indicates inactivity timeout of a fatpipe(pstream)
     * at the target
     */
static int
wmi_pstream_timeout_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_pstream_timeout_event *ev;

    if (len < sizeof(struct wmi_pstream_timeout_event)) {
        return A_EINVAL;
    }

    A_DPRINTF(DBG_WMI, (DBGFMT "wmi_pstream_timeout_event_rx\n", DBGARG));

    ev = (struct wmi_pstream_timeout_event *)datap;

        /* When the pstream (fat pipe == AC) timesout, it means there were no
         * thinStreams within this pstream & it got implicitly created due to
         * data flow on this AC. We start the inactivity timer only for
         * implicitly created pstream. Just reset the host state.
     */
        /* Set the activeTsids for this AC to 0 */
    spin_lock_bh(&wmip->wmi_lock);
    wmip->wmi_streamExistsForAC[ev->trafficClass]=0;
    wmip->wmi_fatPipeExists &= ~(1 << ev->trafficClass);
    spin_unlock_bh(&wmip->wmi_lock);

        /*Indicate inactivity to driver layer for this fatpipe (pstream)*/
    ar6000_indicate_tx_activity(wmip->wmi_devt, ev->trafficClass, false);

    return 0;
}

static int
wmi_bitrate_reply_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_bit_rate_reply *reply;
    s32 rate;
    u32 sgi,index;
    /* 54149:
     * WMI_BIT_RATE_CMD structure is changed to WMI_BIT_RATE_REPLY.
     * since there is difference in the length and to avoid returning
     * error value.
     */
    if (len < sizeof(struct wmi_bit_rate_reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_bit_rate_reply *)datap;
    A_DPRINTF(DBG_WMI,
        (DBGFMT "Enter - rateindex %d\n", DBGARG, reply->rateIndex));

    if (reply->rateIndex == (s8) RATE_AUTO) {
        rate = RATE_AUTO;
    } else {
        // the SGI state is stored as the MSb of the rateIndex
        index = reply->rateIndex & 0x7f;
        sgi = (reply->rateIndex & 0x80)? 1:0;
        rate = wmi_rateTable[index][sgi];
    }

    ar6000_bitrate_rx(wmip->wmi_devt, rate);
    return 0;
}

static int
wmi_ratemask_reply_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_fix_rates_reply *reply;

    if (len < sizeof(struct wmi_fix_rates_reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_fix_rates_reply *)datap;
    A_DPRINTF(DBG_WMI,
        (DBGFMT "Enter - fixed rate mask %x\n", DBGARG, reply->fixRateMask));

    ar6000_ratemask_rx(wmip->wmi_devt, reply->fixRateMask);

    return 0;
}

static int
wmi_channelList_reply_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_channel_list_reply *reply;

    if (len < sizeof(struct wmi_channel_list_reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_channel_list_reply *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_channelList_rx(wmip->wmi_devt, reply->numChannels,
                          reply->channelList);

    return 0;
}

static int
wmi_txPwr_reply_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_tx_pwr_reply *reply;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_tx_pwr_reply *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_txPwr_rx(wmip->wmi_devt, reply->dbM);

    return 0;
}
static int
wmi_keepalive_reply_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_get_keepalive_cmd *reply;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_get_keepalive_cmd *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_keepalive_rx(wmip->wmi_devt, reply->configured);

    return 0;
}

static int
wmi_scanComplete_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_scan_complete_event *ev;

    ev = (struct wmi_scan_complete_event *)datap;
    if ((int)ev->status == 0) {
        wlan_refresh_inactive_nodes(&wmip->wmi_scan_table);
    }
    ar6000_scanComplete_event(wmip->wmi_devt, (int) ev->status);
    is_probe_ssid = false;

    return 0;
}

/*
 * Target is reporting a programming error.  This is for
 * developer aid only.  Target only checks a few common violations
 * and it is responsibility of host to do all error checking.
 * Behavior of target after wmi error event is undefined.
 * A reset is recommended.
 */
static int
wmi_errorEvent_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_cmd_error_event *ev;

    ev = (struct wmi_cmd_error_event *)datap;
    AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("Programming Error: cmd=%d ", ev->commandId));
    switch (ev->errorCode) {
    case (INVALID_PARAM):
        AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("Illegal Parameter\n"));
        break;
    case (ILLEGAL_STATE):
        AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("Illegal State\n"));
        break;
    case (INTERNAL_ERROR):
        AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("Internal Error\n"));
        break;
    }

    return 0;
}


static int
wmi_statsEvent_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_targetStats_event(wmip->wmi_devt, datap, len);

    return 0;
}

static int
wmi_rssiThresholdEvent_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_rssi_threshold_event *reply;
    enum wmi_rssi_threshold_val newThreshold;
    struct wmi_rssi_threshold_params_cmd cmd;
    struct sq_threshold_params_s *sq_thresh =
           &wmip->wmi_SqThresholdParams[SIGNAL_QUALITY_METRICS_RSSI];
    u8 upper_rssi_threshold, lower_rssi_threshold;
    s16 rssi;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_rssi_threshold_event *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));
    newThreshold = (enum wmi_rssi_threshold_val) reply->range;
    rssi = reply->rssi;

    /*
     * Identify the threshold breached and communicate that to the app. After
     * that install a new set of thresholds based on the signal quality
     * reported by the target
     */
    if (newThreshold) {
        /* Upper threshold breached */
        if (rssi < sq_thresh->upper_threshold[0]) {
            A_DPRINTF(DBG_WMI, (DBGFMT "Spurious upper RSSI threshold event: "
                      " %d\n", DBGARG, rssi));
        } else if ((rssi < sq_thresh->upper_threshold[1]) &&
                   (rssi >= sq_thresh->upper_threshold[0]))
        {
            newThreshold = WMI_RSSI_THRESHOLD1_ABOVE;
        } else if ((rssi < sq_thresh->upper_threshold[2]) &&
                   (rssi >= sq_thresh->upper_threshold[1]))
        {
            newThreshold = WMI_RSSI_THRESHOLD2_ABOVE;
        } else if ((rssi < sq_thresh->upper_threshold[3]) &&
                   (rssi >= sq_thresh->upper_threshold[2]))
        {
            newThreshold = WMI_RSSI_THRESHOLD3_ABOVE;
        } else if ((rssi < sq_thresh->upper_threshold[4]) &&
                   (rssi >= sq_thresh->upper_threshold[3]))
        {
            newThreshold = WMI_RSSI_THRESHOLD4_ABOVE;
        } else if ((rssi < sq_thresh->upper_threshold[5]) &&
                   (rssi >= sq_thresh->upper_threshold[4]))
        {
            newThreshold = WMI_RSSI_THRESHOLD5_ABOVE;
        } else if (rssi >= sq_thresh->upper_threshold[5]) {
            newThreshold = WMI_RSSI_THRESHOLD6_ABOVE;
        }
    } else {
        /* Lower threshold breached */
        if (rssi > sq_thresh->lower_threshold[0]) {
            A_DPRINTF(DBG_WMI, (DBGFMT "Spurious lower RSSI threshold event: "
                      "%d %d\n", DBGARG, rssi, sq_thresh->lower_threshold[0]));
        } else if ((rssi > sq_thresh->lower_threshold[1]) &&
                   (rssi <= sq_thresh->lower_threshold[0]))
        {
            newThreshold = WMI_RSSI_THRESHOLD6_BELOW;
        } else if ((rssi > sq_thresh->lower_threshold[2]) &&
                   (rssi <= sq_thresh->lower_threshold[1]))
        {
            newThreshold = WMI_RSSI_THRESHOLD5_BELOW;
        } else if ((rssi > sq_thresh->lower_threshold[3]) &&
                   (rssi <= sq_thresh->lower_threshold[2]))
        {
            newThreshold = WMI_RSSI_THRESHOLD4_BELOW;
        } else if ((rssi > sq_thresh->lower_threshold[4]) &&
                   (rssi <= sq_thresh->lower_threshold[3]))
        {
            newThreshold = WMI_RSSI_THRESHOLD3_BELOW;
        } else if ((rssi > sq_thresh->lower_threshold[5]) &&
                   (rssi <= sq_thresh->lower_threshold[4]))
        {
            newThreshold = WMI_RSSI_THRESHOLD2_BELOW;
        } else if (rssi <= sq_thresh->lower_threshold[5]) {
            newThreshold = WMI_RSSI_THRESHOLD1_BELOW;
        }
    }
    /* Calculate and install the next set of thresholds */
    lower_rssi_threshold = ar6000_get_lower_threshold(rssi, sq_thresh,
                                      sq_thresh->lower_threshold_valid_count);
    upper_rssi_threshold = ar6000_get_upper_threshold(rssi, sq_thresh,
                                      sq_thresh->upper_threshold_valid_count);
    /* Issue a wmi command to install the thresholds */
    cmd.thresholdAbove1_Val = upper_rssi_threshold;
    cmd.thresholdBelow1_Val = lower_rssi_threshold;
    cmd.weight = sq_thresh->weight;
    cmd.pollTime = sq_thresh->polling_interval;

    rssi_event_value = rssi;

    if (wmi_send_rssi_threshold_params(wmip, &cmd) != 0) {
        A_DPRINTF(DBG_WMI, (DBGFMT "Unable to configure the RSSI thresholds\n",
                  DBGARG));
    }

    ar6000_rssiThreshold_event(wmip->wmi_devt, newThreshold, reply->rssi);

    return 0;
}


static int
wmi_reportErrorEvent_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_target_error_report_event *reply;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_target_error_report_event *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_reportError_event(wmip->wmi_devt, (enum wmi_target_error_val) reply->errorVal);

    return 0;
}

static int
wmi_cac_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_cac_event *reply;
    WMM_TSPEC_IE *tspec_ie;
    u16 activeTsids;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_cac_event *)datap;

    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    if ((reply->cac_indication == CAC_INDICATION_ADMISSION_RESP) &&
        (reply->statusCode != TSPEC_STATUS_CODE_ADMISSION_ACCEPTED)) {
        tspec_ie = (WMM_TSPEC_IE *) &(reply->tspecSuggestion);

        wmi_delete_pstream_cmd(wmip, reply->ac,
                (tspec_ie->tsInfo_info >> TSPEC_TSID_S) & TSPEC_TSID_MASK);
    }
    else if (reply->cac_indication == CAC_INDICATION_NO_RESP) {
        u8 i;

        /* following assumes that there is only one outstanding ADDTS request
           when this event is received */
        spin_lock_bh(&wmip->wmi_lock);
        activeTsids = wmip->wmi_streamExistsForAC[reply->ac];
        spin_unlock_bh(&wmip->wmi_lock);

        for (i = 0; i < sizeof(activeTsids) * 8; i++) {
            if ((activeTsids >> i) & 1) {
                break;
            }
        }
        if (i < (sizeof(activeTsids) * 8)) {
            wmi_delete_pstream_cmd(wmip, reply->ac, i);
        }
    }
        /*
         * Ev#72990: Clear active tsids and Add missing handling
         * for delete qos stream from AP
         */
    else if (reply->cac_indication == CAC_INDICATION_DELETE) {
        u8 tsid = 0;

        tspec_ie = (WMM_TSPEC_IE *) &(reply->tspecSuggestion);
        tsid= ((tspec_ie->tsInfo_info >> TSPEC_TSID_S) & TSPEC_TSID_MASK);

        spin_lock_bh(&wmip->wmi_lock);
        wmip->wmi_streamExistsForAC[reply->ac] &= ~(1<<tsid);
        activeTsids = wmip->wmi_streamExistsForAC[reply->ac];
        spin_unlock_bh(&wmip->wmi_lock);

        /* Indicate stream inactivity to driver layer only if all tsids
         * within this AC are deleted.
         */
       if (!activeTsids) {
           ar6000_indicate_tx_activity(wmip->wmi_devt, reply->ac, false);
           wmip->wmi_fatPipeExists &= ~(1 << reply->ac);
        }
    }

    ar6000_cac_event(wmip->wmi_devt, reply->ac,
                reply->cac_indication, reply->statusCode,
                reply->tspecSuggestion);

    return 0;
}

static int
wmi_channel_change_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_channel_change_event *reply;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_channel_change_event *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_channel_change_event(wmip->wmi_devt, reply->oldChannel,
                               reply->newChannel);

    return 0;
}

static int
wmi_hbChallengeResp_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    WMIX_HB_CHALLENGE_RESP_EVENT *reply;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (WMIX_HB_CHALLENGE_RESP_EVENT *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "wmi: challenge response event\n", DBGARG));

    ar6000_hbChallengeResp_event(wmip->wmi_devt, reply->cookie, reply->source);

    return 0;
}

static int
wmi_roam_tbl_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_target_roam_tbl *reply;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_target_roam_tbl *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_roam_tbl_event(wmip->wmi_devt, reply);

    return 0;
}

static int
wmi_roam_data_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_target_roam_data *reply;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_target_roam_data *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_roam_data_event(wmip->wmi_devt, reply);

    return 0;
}

static int
wmi_txRetryErrEvent_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    if (len < sizeof(struct wmi_tx_retry_err_event)) {
        return A_EINVAL;
    }
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_tx_retry_err_event(wmip->wmi_devt);

    return 0;
}

static int
wmi_snrThresholdEvent_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_snr_threshold_event *reply;
    struct sq_threshold_params_s *sq_thresh =
           &wmip->wmi_SqThresholdParams[SIGNAL_QUALITY_METRICS_SNR];
    enum wmi_snr_threshold_val newThreshold;
    struct wmi_snr_threshold_params_cmd cmd;
    u8 upper_snr_threshold, lower_snr_threshold;
    s16 snr;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_snr_threshold_event *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    newThreshold = (enum wmi_snr_threshold_val) reply->range;
    snr = reply->snr;
    /*
     * Identify the threshold breached and communicate that to the app. After
     * that install a new set of thresholds based on the signal quality
     * reported by the target
     */
    if (newThreshold) {
        /* Upper threshold breached */
        if (snr < sq_thresh->upper_threshold[0]) {
            A_DPRINTF(DBG_WMI, (DBGFMT "Spurious upper SNR threshold event: "
                     "%d\n", DBGARG, snr));
        } else if ((snr < sq_thresh->upper_threshold[1]) &&
                   (snr >= sq_thresh->upper_threshold[0]))
        {
            newThreshold = WMI_SNR_THRESHOLD1_ABOVE;
        } else if ((snr < sq_thresh->upper_threshold[2]) &&
                   (snr >= sq_thresh->upper_threshold[1]))
        {
            newThreshold = WMI_SNR_THRESHOLD2_ABOVE;
        } else if ((snr < sq_thresh->upper_threshold[3]) &&
                   (snr >= sq_thresh->upper_threshold[2]))
        {
            newThreshold = WMI_SNR_THRESHOLD3_ABOVE;
        } else if (snr >= sq_thresh->upper_threshold[3]) {
            newThreshold = WMI_SNR_THRESHOLD4_ABOVE;
        }
    } else {
        /* Lower threshold breached */
        if (snr > sq_thresh->lower_threshold[0]) {
            A_DPRINTF(DBG_WMI, (DBGFMT "Spurious lower SNR threshold event: "
                      "%d %d\n", DBGARG, snr, sq_thresh->lower_threshold[0]));
        } else if ((snr > sq_thresh->lower_threshold[1]) &&
                   (snr <= sq_thresh->lower_threshold[0]))
        {
            newThreshold = WMI_SNR_THRESHOLD4_BELOW;
        } else if ((snr > sq_thresh->lower_threshold[2]) &&
                   (snr <= sq_thresh->lower_threshold[1]))
        {
            newThreshold = WMI_SNR_THRESHOLD3_BELOW;
        } else if ((snr > sq_thresh->lower_threshold[3]) &&
                   (snr <= sq_thresh->lower_threshold[2]))
        {
            newThreshold = WMI_SNR_THRESHOLD2_BELOW;
        } else if (snr <= sq_thresh->lower_threshold[3]) {
            newThreshold = WMI_SNR_THRESHOLD1_BELOW;
        }
    }

    /* Calculate and install the next set of thresholds */
    lower_snr_threshold = ar6000_get_lower_threshold(snr, sq_thresh,
                                      sq_thresh->lower_threshold_valid_count);
    upper_snr_threshold = ar6000_get_upper_threshold(snr, sq_thresh,
                                      sq_thresh->upper_threshold_valid_count);

    /* Issue a wmi command to install the thresholds */
    cmd.thresholdAbove1_Val = upper_snr_threshold;
    cmd.thresholdBelow1_Val = lower_snr_threshold;
    cmd.weight = sq_thresh->weight;
    cmd.pollTime = sq_thresh->polling_interval;

    A_DPRINTF(DBG_WMI, (DBGFMT "snr: %d, threshold: %d, lower: %d, upper: %d\n"
              ,DBGARG, snr, newThreshold, lower_snr_threshold,
              upper_snr_threshold));

    snr_event_value = snr;

    if (wmi_send_snr_threshold_params(wmip, &cmd) != 0) {
        A_DPRINTF(DBG_WMI, (DBGFMT "Unable to configure the SNR thresholds\n",
                  DBGARG));
    }
    ar6000_snrThresholdEvent_rx(wmip->wmi_devt, newThreshold, reply->snr);

    return 0;
}

static int
wmi_lqThresholdEvent_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_lq_threshold_event *reply;

    if (len < sizeof(*reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_lq_threshold_event *)datap;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    ar6000_lqThresholdEvent_rx(wmip->wmi_devt,
                                (enum wmi_lq_threshold_val) reply->range,
                                reply->lq);

    return 0;
}

static int
wmi_aplistEvent_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    u16 ap_info_entry_size;
    struct wmi_aplist_event *ev = (struct wmi_aplist_event *)datap;
    struct wmi_ap_info_v1 *ap_info_v1;
    u8 i;

    if (len < sizeof(struct wmi_aplist_event)) {
        return A_EINVAL;
    }

    if (ev->apListVer == APLIST_VER1) {
        ap_info_entry_size = sizeof(struct wmi_ap_info_v1);
        ap_info_v1 = (struct wmi_ap_info_v1 *)ev->apList;
    } else {
        return A_EINVAL;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("Number of APs in APLIST Event is %d\n", ev->numAP));
    if (len < (int)(sizeof(struct wmi_aplist_event) +
              (ev->numAP - 1) * ap_info_entry_size))
    {
        return A_EINVAL;
    }

    /*
     * AP List Ver1 Contents
     */
    for (i = 0; i < ev->numAP; i++) {
        AR_DEBUG_PRINTF(ATH_DEBUG_WMI, ("AP#%d BSSID %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x "\
                    "Channel %d\n", i,
                   ap_info_v1->bssid[0], ap_info_v1->bssid[1],
                   ap_info_v1->bssid[2], ap_info_v1->bssid[3],
                   ap_info_v1->bssid[4], ap_info_v1->bssid[5],
                   ap_info_v1->channel));
        ap_info_v1++;
    }
    return 0;
}

/*
 * Called to send a wmi command. Command specific data is already built
 * on osbuf and current osbuf->data points to it.
 */
int
wmi_cmd_send(struct wmi_t *wmip, void *osbuf, enum wmi_cmd_id cmdId,
               enum wmi_sync_flag syncflag)
{
    int status;
#define IS_OPT_TX_CMD(cmdId) ((cmdId == WMI_OPT_TX_FRAME_CMDID))
    struct wmi_cmd_hdr         *cHdr;
    enum htc_endpoint_id     eid  = wmip->wmi_endpoint_id;

    A_ASSERT(osbuf != NULL);

    if (syncflag >= END_WMIFLAG) {
        dev_kfree_skb((struct sk_buff *)osbuf);
        return A_EINVAL;
    }

    if ((syncflag == SYNC_BEFORE_WMIFLAG) || (syncflag == SYNC_BOTH_WMIFLAG)) {
        /*
         * We want to make sure all data currently queued is transmitted before
         * the cmd execution.  Establish a new sync point.
         */
        wmi_sync_point(wmip);
    }

    skb_push((struct sk_buff *)osbuf, sizeof(struct wmi_cmd_hdr));

    cHdr = (struct wmi_cmd_hdr *)((struct sk_buff *)osbuf)->data;
    cHdr->commandId = (u16) cmdId;
    cHdr->info1 = 0; // added for virtual interface

    /*
     * Only for OPT_TX_CMD, use BE endpoint.
     */
    if (IS_OPT_TX_CMD(cmdId)) {
        if ((status=wmi_data_hdr_add(wmip, osbuf, OPT_MSGTYPE, false, false,0,NULL)) != 0) {
            dev_kfree_skb((struct sk_buff *)osbuf);
            return status;
        }
        eid = ar6000_ac2_endpoint_id(wmip->wmi_devt, WMM_AC_BE);
    }
    ar6000_control_tx(wmip->wmi_devt, osbuf, eid);

    if ((syncflag == SYNC_AFTER_WMIFLAG) || (syncflag == SYNC_BOTH_WMIFLAG)) {
        /*
         * We want to make sure all new data queued waits for the command to
         * execute. Establish a new sync point.
         */
        wmi_sync_point(wmip);
    }
    return (0);
#undef IS_OPT_TX_CMD
}

int
wmi_cmd_send_xtnd(struct wmi_t *wmip, void *osbuf, enum wmix_command_id cmdId,
                  enum wmi_sync_flag syncflag)
{
    struct wmix_cmd_hdr     *cHdr;

    skb_push((struct sk_buff *)osbuf, sizeof(struct wmix_cmd_hdr));

    cHdr = (struct wmix_cmd_hdr *)((struct sk_buff *)osbuf)->data;
    cHdr->commandId = (u32) cmdId;

    return wmi_cmd_send(wmip, osbuf, WMI_EXTENSION_CMDID, syncflag);
}

int
wmi_connect_cmd(struct wmi_t *wmip, enum network_type netType,
                enum dot11_auth_mode dot11AuthMode, enum auth_mode authMode,
                enum crypto_type pairwiseCrypto, u8 pairwiseCryptoLen,
                enum crypto_type groupCrypto, u8 groupCryptoLen,
                int ssidLength, u8 *ssid,
                u8 *bssid, u16 channel, u32 ctrl_flags)
{
    void *osbuf;
    struct wmi_connect_cmd *cc;
    wmip->wmi_traffic_class = 100;

    if ((pairwiseCrypto == NONE_CRYPT) && (groupCrypto != NONE_CRYPT)) {
        return A_EINVAL;
    }
    if ((pairwiseCrypto != NONE_CRYPT) && (groupCrypto == NONE_CRYPT)) {
        return A_EINVAL;
    }

    osbuf = ar6k_buf_alloc(sizeof(struct wmi_connect_cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(struct wmi_connect_cmd));

    cc = (struct wmi_connect_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cc, 0, sizeof(*cc));

    if (ssidLength)
    {
        memcpy(cc->ssid, ssid, ssidLength);
    }

    cc->ssidLength          = ssidLength;
    cc->networkType         = netType;
    cc->dot11AuthMode       = dot11AuthMode;
    cc->authMode            = authMode;
    cc->pairwiseCryptoType  = pairwiseCrypto;
    cc->pairwiseCryptoLen   = pairwiseCryptoLen;
    cc->groupCryptoType     = groupCrypto;
    cc->groupCryptoLen      = groupCryptoLen;
    cc->channel             = channel;
    cc->ctrl_flags          = ctrl_flags;

    if (bssid != NULL) {
        memcpy(cc->bssid, bssid, ETH_ALEN);
    }

    wmip->wmi_pair_crypto_type  = pairwiseCrypto;
    wmip->wmi_grp_crypto_type   = groupCrypto;

    return (wmi_cmd_send(wmip, osbuf, WMI_CONNECT_CMDID, NO_SYNC_WMIFLAG));
}

int
wmi_reconnect_cmd(struct wmi_t *wmip, u8 *bssid, u16 channel)
{
    void *osbuf;
    struct wmi_reconnect_cmd *cc;
    wmip->wmi_traffic_class = 100;

    osbuf = ar6k_buf_alloc(sizeof(struct wmi_reconnect_cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(struct wmi_reconnect_cmd));

    cc = (struct wmi_reconnect_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cc, 0, sizeof(*cc));

    cc->channel = channel;

    if (bssid != NULL) {
        memcpy(cc->bssid, bssid, ETH_ALEN);
    }

    return (wmi_cmd_send(wmip, osbuf, WMI_RECONNECT_CMDID, NO_SYNC_WMIFLAG));
}

int
wmi_disconnect_cmd(struct wmi_t *wmip)
{
    int status;
    wmip->wmi_traffic_class = 100;

    /* Bug fix for 24817(elevator bug) - the disconnect command does not
       need to do a SYNC before.*/
    status = wmi_simple_cmd(wmip, WMI_DISCONNECT_CMDID);

    return status;
}

int
wmi_startscan_cmd(struct wmi_t *wmip, enum wmi_scan_type scanType,
                  u32 forceFgScan, u32 isLegacy,
                  u32 homeDwellTime, u32 forceScanInterval,
                  s8 numChan, u16 *channelList)
{
    void *osbuf;
    struct wmi_start_scan_cmd *sc;
    s8 size;

    size = sizeof (*sc);

    if ((scanType != WMI_LONG_SCAN) && (scanType != WMI_SHORT_SCAN)) {
        return A_EINVAL;
    }

    if (numChan) {
        if (numChan > WMI_MAX_CHANNELS) {
            return A_EINVAL;
        }
        size += sizeof(u16) * (numChan - 1);
    }

    osbuf = ar6k_buf_alloc(size);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, size);

    sc = (struct wmi_start_scan_cmd *)(((struct sk_buff *)osbuf)->data);
    sc->scanType = scanType;
    sc->forceFgScan = forceFgScan;
    sc->isLegacy = isLegacy;
    sc->homeDwellTime = homeDwellTime;
    sc->forceScanInterval = forceScanInterval;
    sc->numChannels = numChan;
    if (numChan) {
        memcpy(sc->channelList, channelList, numChan * sizeof(u16));
    }

    return (wmi_cmd_send(wmip, osbuf, WMI_START_SCAN_CMDID, NO_SYNC_WMIFLAG));
}

int
wmi_scanparams_cmd(struct wmi_t *wmip, u16 fg_start_sec,
                   u16 fg_end_sec, u16 bg_sec,
                   u16 minact_chdw_msec, u16 maxact_chdw_msec,
                   u16 pas_chdw_msec,
                   u8 shScanRatio, u8 scanCtrlFlags,
                   u32 max_dfsch_act_time, u16 maxact_scan_per_ssid)
{
    void *osbuf;
    struct wmi_scan_params_cmd *sc;

    osbuf = ar6k_buf_alloc(sizeof(*sc));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*sc));

    sc = (struct wmi_scan_params_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(sc, 0, sizeof(*sc));
    sc->fg_start_period  = fg_start_sec;
    sc->fg_end_period    = fg_end_sec;
    sc->bg_period        = bg_sec;
    sc->minact_chdwell_time = minact_chdw_msec;
    sc->maxact_chdwell_time = maxact_chdw_msec;
    sc->pas_chdwell_time = pas_chdw_msec;
    sc->shortScanRatio   = shScanRatio;
    sc->scanCtrlFlags    = scanCtrlFlags;
    sc->max_dfsch_act_time = max_dfsch_act_time;
    sc->maxact_scan_per_ssid = maxact_scan_per_ssid;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_SCAN_PARAMS_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_bssfilter_cmd(struct wmi_t *wmip, u8 filter, u32 ieMask)
{
    void *osbuf;
    struct wmi_bss_filter_cmd *cmd;

    if (filter >= LAST_BSS_FILTER) {
        return A_EINVAL;
    }

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_bss_filter_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->bssFilter = filter;
    cmd->ieMask = ieMask;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_BSS_FILTER_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_probedSsid_cmd(struct wmi_t *wmip, u8 index, u8 flag,
                   u8 ssidLength, u8 *ssid)
{
    void *osbuf;
    struct wmi_probed_ssid_cmd *cmd;

    if (index > MAX_PROBED_SSID_INDEX) {
        return A_EINVAL;
    }
    if (ssidLength > sizeof(cmd->ssid)) {
        return A_EINVAL;
    }
    if ((flag & (DISABLE_SSID_FLAG | ANY_SSID_FLAG)) && (ssidLength > 0)) {
        return A_EINVAL;
    }
    if ((flag & SPECIFIC_SSID_FLAG) && !ssidLength) {
        return A_EINVAL;
    }

    if (flag & SPECIFIC_SSID_FLAG) {
        is_probe_ssid = true;
    }

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_probed_ssid_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->entryIndex = index;
    cmd->flag       = flag;
    cmd->ssidLength = ssidLength;
    memcpy(cmd->ssid, ssid, ssidLength);

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_PROBED_SSID_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_listeninterval_cmd(struct wmi_t *wmip, u16 listenInterval, u16 listenBeacons)
{
    void *osbuf;
    struct wmi_listen_int_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_listen_int_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->listenInterval = listenInterval;
    cmd->numBeacons = listenBeacons;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_LISTEN_INT_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_powermode_cmd(struct wmi_t *wmip, u8 powerMode)
{
    void *osbuf;
    struct wmi_power_mode_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_power_mode_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->powerMode = powerMode;
    wmip->wmi_powerMode = powerMode;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_POWER_MODE_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_pmparams_cmd(struct wmi_t *wmip, u16 idlePeriod,
                 u16 psPollNum, u16 dtimPolicy,
                 u16 tx_wakeup_policy, u16 num_tx_to_wakeup,
                 u16 ps_fail_event_policy)
{
    void *osbuf;
    struct wmi_power_params_cmd *pm;

    osbuf = ar6k_buf_alloc(sizeof(*pm));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*pm));

    pm = (struct wmi_power_params_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(pm, 0, sizeof(*pm));
    pm->idle_period   = idlePeriod;
    pm->pspoll_number = psPollNum;
    pm->dtim_policy   = dtimPolicy;
    pm->tx_wakeup_policy = tx_wakeup_policy;
    pm->num_tx_to_wakeup = num_tx_to_wakeup;
    pm->ps_fail_event_policy = ps_fail_event_policy;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_POWER_PARAMS_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_disctimeout_cmd(struct wmi_t *wmip, u8 timeout)
{
    void *osbuf;
   struct wmi_disc_timeout_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_disc_timeout_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->disconnectTimeout = timeout;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_DISC_TIMEOUT_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_addKey_cmd(struct wmi_t *wmip, u8 keyIndex, enum crypto_type keyType,
               u8 keyUsage, u8 keyLength, u8 *keyRSC,
               u8 *keyMaterial, u8 key_op_ctrl, u8 *macAddr,
               enum wmi_sync_flag sync_flag)
{
    void *osbuf;
    struct wmi_add_cipher_key_cmd *cmd;

    if ((keyIndex > WMI_MAX_KEY_INDEX) || (keyLength > WMI_MAX_KEY_LEN) ||
        (keyMaterial == NULL))
    {
        return A_EINVAL;
    }

    if ((WEP_CRYPT != keyType) && (NULL == keyRSC)) {
        return A_EINVAL;
    }

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_add_cipher_key_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->keyIndex = keyIndex;
    cmd->keyType  = keyType;
    cmd->keyUsage = keyUsage;
    cmd->keyLength = keyLength;
    memcpy(cmd->key, keyMaterial, keyLength);
#ifdef WAPI_ENABLE
    if (NULL != keyRSC && key_op_ctrl != KEY_OP_INIT_WAPIPN) {
#else
    if (NULL != keyRSC) {
#endif // WAPI_ENABLE
        memcpy(cmd->keyRSC, keyRSC, sizeof(cmd->keyRSC));
    }
    cmd->key_op_ctrl = key_op_ctrl;

    if(macAddr) {
        memcpy(cmd->key_macaddr,macAddr,ETH_ALEN);
    }

    return (wmi_cmd_send(wmip, osbuf, WMI_ADD_CIPHER_KEY_CMDID, sync_flag));
}

int
wmi_add_krk_cmd(struct wmi_t *wmip, u8 *krk)
{
    void *osbuf;
    struct wmi_add_krk_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_add_krk_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    memcpy(cmd->krk, krk, WMI_KRK_LEN);

    return (wmi_cmd_send(wmip, osbuf, WMI_ADD_KRK_CMDID, NO_SYNC_WMIFLAG));
}

int
wmi_deleteKey_cmd(struct wmi_t *wmip, u8 keyIndex)
{
    void *osbuf;
    struct wmi_delete_cipher_key_cmd *cmd;

    if (keyIndex > WMI_MAX_KEY_INDEX) {
        return A_EINVAL;
    }

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_delete_cipher_key_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->keyIndex = keyIndex;

    return (wmi_cmd_send(wmip, osbuf, WMI_DELETE_CIPHER_KEY_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_dataSync_send(struct wmi_t *wmip, void *osbuf, enum htc_endpoint_id eid)
{
    struct wmi_data_hdr     *dtHdr;

    A_ASSERT( eid != wmip->wmi_endpoint_id);
    A_ASSERT(osbuf != NULL);

    skb_push((struct sk_buff *)osbuf, sizeof(struct wmi_data_hdr));

    dtHdr = (struct wmi_data_hdr *)((struct sk_buff *)osbuf)->data;
    dtHdr->info =
      (SYNC_MSGTYPE & WMI_DATA_HDR_MSG_TYPE_MASK) << WMI_DATA_HDR_MSG_TYPE_SHIFT;

    dtHdr->info3 = 0;
    A_DPRINTF(DBG_WMI, (DBGFMT "Enter - eid %d\n", DBGARG, eid));

    return (ar6000_control_tx(wmip->wmi_devt, osbuf, eid));
}

typedef struct _WMI_DATA_SYNC_BUFS {
    u8 trafficClass;
    void               *osbuf;
}WMI_DATA_SYNC_BUFS;

static int
wmi_sync_point(struct wmi_t *wmip)
{
    void *cmd_osbuf;
    struct wmi_sync_cmd *cmd;
    WMI_DATA_SYNC_BUFS dataSyncBufs[WMM_NUM_AC];
    u8 i,numPriStreams=0;
    int status = 0;

    A_DPRINTF(DBG_WMI, (DBGFMT "Enter\n", DBGARG));

    memset(dataSyncBufs,0,sizeof(dataSyncBufs));

    /* lock out while we walk through the priority list and assemble our local array */
    spin_lock_bh(&wmip->wmi_lock);

    for (i=0; i < WMM_NUM_AC ; i++) {
        if (wmip->wmi_fatPipeExists & (1 << i)) {
            numPriStreams++;
            dataSyncBufs[numPriStreams-1].trafficClass = i;
        }
    }

    spin_unlock_bh(&wmip->wmi_lock);

    /* dataSyncBufs is now filled with entries (starting at index 0) containing valid streamIDs */

    do {
        /*
         * We allocate all network buffers needed so we will be able to
         * send all required frames.
         */
        cmd_osbuf = ar6k_buf_alloc(sizeof(*cmd));
        if (cmd_osbuf == NULL) {
            status = A_NO_MEMORY;
            break;
    }

	skb_put(cmd_osbuf, sizeof(*cmd));

        cmd = (struct wmi_sync_cmd *)(((struct sk_buff *)cmd_osbuf)->data);
        memset(cmd, 0, sizeof(*cmd));

        /* In the SYNC cmd sent on the control Ep, send a bitmap of the data
         * eps on which the Data Sync will be sent
         */
        cmd->dataSyncMap = wmip->wmi_fatPipeExists;

        for (i=0; i < numPriStreams ; i++) {
            dataSyncBufs[i].osbuf = ar6k_buf_alloc(0);
            if (dataSyncBufs[i].osbuf == NULL) {
                status = A_NO_MEMORY;
                break;
            }
        } //end for

        /* if Buffer allocation for any of the dataSync fails, then do not
         * send the Synchronize cmd on the control ep
         */
        if (status) {
            break;
        }

    /*
     * Send sync cmd followed by sync data messages on all endpoints being
     * used
     */
    status = wmi_cmd_send(wmip, cmd_osbuf, WMI_SYNCHRONIZE_CMDID,
                          NO_SYNC_WMIFLAG);

        if (status) {
            break;
    }
            /* cmd buffer sent, we no longer own it */
        cmd_osbuf = NULL;

        for(i=0; i < numPriStreams; i++) {
            A_ASSERT(dataSyncBufs[i].osbuf != NULL);
            status = wmi_dataSync_send(wmip,
                                       dataSyncBufs[i].osbuf,
                                       ar6000_ac2_endpoint_id(wmip->wmi_devt,
                                                            dataSyncBufs[i].
                                                            trafficClass)
                                      );

            if (status) {
                break;
            }
            /* we don't own this buffer anymore, NULL it out of the array so it
             * won't get cleaned up */
            dataSyncBufs[i].osbuf = NULL;
        } //end for

    } while(false);

    /* free up any resources left over (possibly due to an error) */

    if (cmd_osbuf != NULL) {
        dev_kfree_skb((struct sk_buff *)cmd_osbuf);
            }

    for (i = 0; i < numPriStreams; i++) {
        if (dataSyncBufs[i].osbuf != NULL) {
            dev_kfree_skb((struct sk_buff *)dataSyncBufs[i].osbuf);
        }
    }

    return (status);
}

int
wmi_create_pstream_cmd(struct wmi_t *wmip, struct wmi_create_pstream_cmd *params)
{
    void *osbuf;
    struct wmi_create_pstream_cmd *cmd;
    u8 fatPipeExistsForAC=0;
    s32 minimalPHY = 0;
    s32 nominalPHY = 0;

    /* Validate all the parameters. */
    if( !((params->userPriority < 8) &&
         (params->userPriority <= 0x7) &&
         (convert_userPriority_to_trafficClass(params->userPriority) == params->trafficClass)  &&
         (params->trafficDirection == UPLINK_TRAFFIC ||
            params->trafficDirection == DNLINK_TRAFFIC ||
            params->trafficDirection == BIDIR_TRAFFIC) &&
         (params->trafficType == TRAFFIC_TYPE_APERIODIC ||
            params->trafficType == TRAFFIC_TYPE_PERIODIC ) &&
         (params->voicePSCapability == DISABLE_FOR_THIS_AC  ||
            params->voicePSCapability == ENABLE_FOR_THIS_AC ||
            params->voicePSCapability == ENABLE_FOR_ALL_AC) &&
         (params->tsid == WMI_IMPLICIT_PSTREAM || params->tsid <= WMI_MAX_THINSTREAM)) )
    {
        return  A_EINVAL;
    }

    //
    // check nominal PHY rate is >= minimalPHY, so that DUT
    // can allow TSRS IE
    //

    // get the physical rate
    minimalPHY = ((params->minPhyRate / 1000)/1000); // unit of bps

    // check minimal phy < nominal phy rate
    //
    if (params->nominalPHY >= minimalPHY)
    {
        nominalPHY = (params->nominalPHY * 1000)/500; // unit of 500 kbps
        A_DPRINTF(DBG_WMI,
                  (DBGFMT "TSRS IE Enabled::MinPhy %x->NominalPhy ===> %x\n", DBGARG,
                  minimalPHY, nominalPHY));

        params->nominalPHY = nominalPHY;
    }
    else
    {
        params->nominalPHY = 0;
    }

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    A_DPRINTF(DBG_WMI,
        (DBGFMT "Sending create_pstream_cmd: ac=%d    tsid:%d\n", DBGARG,
        params->trafficClass, params->tsid));

    cmd = (struct wmi_create_pstream_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    memcpy(cmd, params, sizeof(*cmd));

        /* this is an implicitly created Fat pipe */
    if ((u32)params->tsid == (u32)WMI_IMPLICIT_PSTREAM) {
        spin_lock_bh(&wmip->wmi_lock);
        fatPipeExistsForAC = (wmip->wmi_fatPipeExists & (1 << params->trafficClass));
        wmip->wmi_fatPipeExists |= (1<<params->trafficClass);
        spin_unlock_bh(&wmip->wmi_lock);
    } else {
            /* this is an explicitly created thin stream within a fat pipe */
    spin_lock_bh(&wmip->wmi_lock);
        fatPipeExistsForAC = (wmip->wmi_fatPipeExists & (1 << params->trafficClass));
    wmip->wmi_streamExistsForAC[params->trafficClass] |= (1<<params->tsid);
            /* if a thinstream becomes active, the fat pipe automatically
            * becomes active
            */
        wmip->wmi_fatPipeExists |= (1<<params->trafficClass);
    spin_unlock_bh(&wmip->wmi_lock);
    }

        /* Indicate activty change to driver layer only if this is the
         * first TSID to get created in this AC explicitly or an implicit
         * fat pipe is getting created.
         */
    if (!fatPipeExistsForAC) {
        ar6000_indicate_tx_activity(wmip->wmi_devt, params->trafficClass, true);
    }

    /* mike: should be SYNC_BEFORE_WMIFLAG */
    return (wmi_cmd_send(wmip, osbuf, WMI_CREATE_PSTREAM_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_delete_pstream_cmd(struct wmi_t *wmip, u8 trafficClass, u8 tsid)
{
    void *osbuf;
    struct wmi_delete_pstream_cmd *cmd;
    int status;
    u16 activeTsids=0;

    /* validate the parameters */
    if (trafficClass > 3) {
        A_DPRINTF(DBG_WMI, (DBGFMT "Invalid trafficClass: %d\n", DBGARG, trafficClass));
        return A_EINVAL;
    }

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_delete_pstream_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));

    cmd->trafficClass = trafficClass;
    cmd->tsid = tsid;

    spin_lock_bh(&wmip->wmi_lock);
    activeTsids = wmip->wmi_streamExistsForAC[trafficClass];
    spin_unlock_bh(&wmip->wmi_lock);

        /* Check if the tsid was created & exists */
    if (!(activeTsids & (1<<tsid))) {

        dev_kfree_skb((struct sk_buff *)osbuf);
        A_DPRINTF(DBG_WMI,
        (DBGFMT "TSID %d does'nt exist for trafficClass: %d\n", DBGARG, tsid, trafficClass));
        return A_ERROR;
    }

    A_DPRINTF(DBG_WMI,
        (DBGFMT "Sending delete_pstream_cmd: trafficClass: %d tsid=%d\n", DBGARG, trafficClass, tsid));

    status = (wmi_cmd_send(wmip, osbuf, WMI_DELETE_PSTREAM_CMDID,
                         SYNC_BEFORE_WMIFLAG));

    spin_lock_bh(&wmip->wmi_lock);
    wmip->wmi_streamExistsForAC[trafficClass] &= ~(1<<tsid);
    activeTsids = wmip->wmi_streamExistsForAC[trafficClass];
    spin_unlock_bh(&wmip->wmi_lock);


        /* Indicate stream inactivity to driver layer only if all tsids
         * within this AC are deleted.
         */
    if(!activeTsids) {
        ar6000_indicate_tx_activity(wmip->wmi_devt, trafficClass, false);
        wmip->wmi_fatPipeExists &= ~(1<<trafficClass);
    }

    return status;
}

/*
 * Returns true iff the given rate index is legal in the current PHY mode.
 */
bool
wmi_is_bitrate_index_valid(struct wmi_t *wmip, s32 rateIndex)
{
    enum wmi_phy_mode phyMode = (enum wmi_phy_mode) wmip->wmi_phyMode;
    bool isValid = true;
    switch(phyMode) {
        case WMI_11A_MODE:
            if (wmip->wmi_ht_allowed[A_BAND_5GHZ]){
                if ((rateIndex < MODE_A_SUPPORT_RATE_START) || (rateIndex > MODE_GHT20_SUPPORT_RATE_STOP)) {
                    isValid = false;
                }
            } else {
                if ((rateIndex < MODE_A_SUPPORT_RATE_START) || (rateIndex > MODE_A_SUPPORT_RATE_STOP)) {
                    isValid = false;
                }
            }
            break;

        case WMI_11B_MODE:
            if ((rateIndex < MODE_B_SUPPORT_RATE_START) || (rateIndex > MODE_B_SUPPORT_RATE_STOP)) {
                isValid = false;
            }
            break;

        case WMI_11GONLY_MODE:
            if (wmip->wmi_ht_allowed[A_BAND_24GHZ]){
                if ((rateIndex < MODE_GONLY_SUPPORT_RATE_START) || (rateIndex > MODE_GHT20_SUPPORT_RATE_STOP)) {
                    isValid = false;
                }
            } else {
                if ((rateIndex < MODE_GONLY_SUPPORT_RATE_START) || (rateIndex > MODE_GONLY_SUPPORT_RATE_STOP)) {
                    isValid = false;
                }
            }
            break;

        case WMI_11G_MODE:
        case WMI_11AG_MODE:
            if (wmip->wmi_ht_allowed[A_BAND_24GHZ]){
                if ((rateIndex < MODE_G_SUPPORT_RATE_START) || (rateIndex > MODE_GHT20_SUPPORT_RATE_STOP)) {
                    isValid = false;
                }
            } else {
                if ((rateIndex < MODE_G_SUPPORT_RATE_START) || (rateIndex > MODE_G_SUPPORT_RATE_STOP)) {
                    isValid = false;
                }
            }
            break;
        default:
            A_ASSERT(false);
            break;
    }

    return isValid;
}

s8 wmi_validate_bitrate(struct wmi_t *wmip, s32 rate, s8 *rate_idx)
{
    s8 i;

    for (i=0;;i++)
    {
        if (wmi_rateTable[(u32) i][0] == 0) {
            return A_EINVAL;
        }
        if (wmi_rateTable[(u32) i][0] == rate) {
            break;
        }
    }

    if(wmi_is_bitrate_index_valid(wmip, (s32) i) != true) {
        return A_EINVAL;
    }

    *rate_idx = i;
    return 0;
}

void
wmi_cache_configure_rssithreshold(struct wmi_t *wmip, struct wmi_rssi_threshold_params_cmd *rssiCmd)
{
    struct sq_threshold_params_s *sq_thresh =
           &wmip->wmi_SqThresholdParams[SIGNAL_QUALITY_METRICS_RSSI];
    /*
     * Parse the command and store the threshold values here. The checks
     * for valid values can be put here
     */
    sq_thresh->weight = rssiCmd->weight;
    sq_thresh->polling_interval = rssiCmd->pollTime;

    sq_thresh->upper_threshold[0] = rssiCmd->thresholdAbove1_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->upper_threshold[1] = rssiCmd->thresholdAbove2_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->upper_threshold[2] = rssiCmd->thresholdAbove3_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->upper_threshold[3] = rssiCmd->thresholdAbove4_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->upper_threshold[4] = rssiCmd->thresholdAbove5_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->upper_threshold[5] = rssiCmd->thresholdAbove6_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->upper_threshold_valid_count = 6;

    /* List sorted in descending order */
    sq_thresh->lower_threshold[0] = rssiCmd->thresholdBelow6_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->lower_threshold[1] = rssiCmd->thresholdBelow5_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->lower_threshold[2] = rssiCmd->thresholdBelow4_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->lower_threshold[3] = rssiCmd->thresholdBelow3_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->lower_threshold[4] = rssiCmd->thresholdBelow2_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->lower_threshold[5] = rssiCmd->thresholdBelow1_Val - SIGNAL_QUALITY_NOISE_FLOOR;
    sq_thresh->lower_threshold_valid_count = 6;

    if (!rssi_event_value) {
    /*
     * Configuring the thresholds to their extremes allows the host to get an
     * event from the target which is used for the configuring the correct
     * thresholds
     */
    rssiCmd->thresholdAbove1_Val = sq_thresh->upper_threshold[0];
    rssiCmd->thresholdBelow1_Val = sq_thresh->lower_threshold[0];
    } else {
        /*
         * In case the user issues multiple times of rssi_threshold_setting,
         * we should not use the extreames anymore, the target does not expect that.
         */
        rssiCmd->thresholdAbove1_Val = ar6000_get_upper_threshold(rssi_event_value, sq_thresh,
                                              sq_thresh->upper_threshold_valid_count);
        rssiCmd->thresholdBelow1_Val = ar6000_get_lower_threshold(rssi_event_value, sq_thresh,
                                              sq_thresh->lower_threshold_valid_count);
}
}

int
wmi_set_ip_cmd(struct wmi_t *wmip, struct wmi_set_ip_cmd *ipCmd)
{
    void    *osbuf;
    struct wmi_set_ip_cmd *cmd;

    /* Multicast address are not valid */
    if((*((u8 *)&ipCmd->ips[0]) >= 0xE0) ||
       (*((u8 *)&ipCmd->ips[1]) >= 0xE0)) {
        return A_EINVAL;
    }

    osbuf = ar6k_buf_alloc(sizeof(struct wmi_set_ip_cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(struct wmi_set_ip_cmd));
    cmd = (struct wmi_set_ip_cmd *)(((struct sk_buff *)osbuf)->data);
    memcpy(cmd, ipCmd, sizeof(struct wmi_set_ip_cmd));

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_IP_CMDID,
                            NO_SYNC_WMIFLAG));
}

int
wmi_set_host_sleep_mode_cmd(struct wmi_t *wmip,
                              struct wmi_set_host_sleep_mode_cmd *hostModeCmd)
{
    void    *osbuf;
    s8 size;
    struct wmi_set_host_sleep_mode_cmd *cmd;
    u16 activeTsids=0;
    u8 streamExists=0;
    u8 i;

    if( hostModeCmd->awake == hostModeCmd->asleep) {
        return A_EINVAL;
    }

    size = sizeof (*cmd);

    osbuf = ar6k_buf_alloc(size);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, size);

    cmd = (struct wmi_set_host_sleep_mode_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, size);
    memcpy(cmd, hostModeCmd, sizeof(struct wmi_set_host_sleep_mode_cmd));

    if(hostModeCmd->asleep) {
        /*
         * Relinquish credits from all implicitly created pstreams since when we
         * go to sleep. If user created explicit thinstreams exists with in a
         * fatpipe leave them intact for the user to delete
         */
        spin_lock_bh(&wmip->wmi_lock);
        streamExists = wmip->wmi_fatPipeExists;
        spin_unlock_bh(&wmip->wmi_lock);

        for(i=0;i< WMM_NUM_AC;i++) {
            if (streamExists & (1<<i)) {
                spin_lock_bh(&wmip->wmi_lock);
                activeTsids = wmip->wmi_streamExistsForAC[i];
                spin_unlock_bh(&wmip->wmi_lock);
                /* If there are no user created thin streams delete the fatpipe */
                if(!activeTsids) {
                    streamExists &= ~(1<<i);
                    /*Indicate inactivity to drv layer for this fatpipe(pstream)*/
                    ar6000_indicate_tx_activity(wmip->wmi_devt, i, false);
                }
            }
        }

        /* Update the fatpipes that exists*/
        spin_lock_bh(&wmip->wmi_lock);
        wmip->wmi_fatPipeExists = streamExists;
        spin_unlock_bh(&wmip->wmi_lock);
    }

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_HOST_SLEEP_MODE_CMDID,
                            NO_SYNC_WMIFLAG));
}

int
wmi_set_wow_mode_cmd(struct wmi_t *wmip,
                              struct wmi_set_wow_mode_cmd *wowModeCmd)
{
    void    *osbuf;
    s8 size;
    struct wmi_set_wow_mode_cmd *cmd;

    size = sizeof (*cmd);

    osbuf = ar6k_buf_alloc(size);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, size);

    cmd = (struct wmi_set_wow_mode_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, size);
    memcpy(cmd, wowModeCmd, sizeof(struct wmi_set_wow_mode_cmd));

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_WOW_MODE_CMDID,
                            NO_SYNC_WMIFLAG));

}

static int
wmi_get_wow_list_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_get_wow_list_reply *reply;

    if (len < sizeof(struct wmi_get_wow_list_reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_get_wow_list_reply *)datap;

    ar6000_wow_list_event(wmip->wmi_devt, reply->num_filters,
                          reply);

    return 0;
}

int wmi_add_wow_pattern_cmd(struct wmi_t *wmip,
                                 struct wmi_add_wow_pattern_cmd *addWowCmd,
                                 u8 *pattern, u8 *mask,
                                 u8 pattern_size)
{
    void    *osbuf;
    s8 size;
    struct wmi_add_wow_pattern_cmd *cmd;
    u8 *filter_mask = NULL;

    size = sizeof (*cmd);

    size += ((2 * addWowCmd->filter_size)* sizeof(u8));
    osbuf = ar6k_buf_alloc(size);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, size);

    cmd = (struct wmi_add_wow_pattern_cmd *)(((struct sk_buff *)osbuf)->data);
    cmd->filter_list_id = addWowCmd->filter_list_id;
    cmd->filter_offset = addWowCmd->filter_offset;
    cmd->filter_size = addWowCmd->filter_size;

    memcpy(cmd->filter, pattern, addWowCmd->filter_size);

    filter_mask = (u8 *)(cmd->filter + cmd->filter_size);
    memcpy(filter_mask, mask, addWowCmd->filter_size);


    return (wmi_cmd_send(wmip, osbuf, WMI_ADD_WOW_PATTERN_CMDID,
                            NO_SYNC_WMIFLAG));
}

int
wmi_del_wow_pattern_cmd(struct wmi_t *wmip,
                              struct wmi_del_wow_pattern_cmd *delWowCmd)
{
    void    *osbuf;
    s8 size;
    struct wmi_del_wow_pattern_cmd *cmd;

    size = sizeof (*cmd);

    osbuf = ar6k_buf_alloc(size);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, size);

    cmd = (struct wmi_del_wow_pattern_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, size);
    memcpy(cmd, delWowCmd, sizeof(struct wmi_del_wow_pattern_cmd));

    return (wmi_cmd_send(wmip, osbuf, WMI_DEL_WOW_PATTERN_CMDID,
                            NO_SYNC_WMIFLAG));

}

void
wmi_cache_configure_snrthreshold(struct wmi_t *wmip, struct wmi_snr_threshold_params_cmd *snrCmd)
{
    struct sq_threshold_params_s *sq_thresh =
           &wmip->wmi_SqThresholdParams[SIGNAL_QUALITY_METRICS_SNR];
    /*
     * Parse the command and store the threshold values here. The checks
     * for valid values can be put here
     */
    sq_thresh->weight = snrCmd->weight;
    sq_thresh->polling_interval = snrCmd->pollTime;

    sq_thresh->upper_threshold[0] = snrCmd->thresholdAbove1_Val;
    sq_thresh->upper_threshold[1] = snrCmd->thresholdAbove2_Val;
    sq_thresh->upper_threshold[2] = snrCmd->thresholdAbove3_Val;
    sq_thresh->upper_threshold[3] = snrCmd->thresholdAbove4_Val;
    sq_thresh->upper_threshold_valid_count = 4;

    /* List sorted in descending order */
    sq_thresh->lower_threshold[0] = snrCmd->thresholdBelow4_Val;
    sq_thresh->lower_threshold[1] = snrCmd->thresholdBelow3_Val;
    sq_thresh->lower_threshold[2] = snrCmd->thresholdBelow2_Val;
    sq_thresh->lower_threshold[3] = snrCmd->thresholdBelow1_Val;
    sq_thresh->lower_threshold_valid_count = 4;

    if (!snr_event_value) {
    /*
     * Configuring the thresholds to their extremes allows the host to get an
     * event from the target which is used for the configuring the correct
     * thresholds
     */
    snrCmd->thresholdAbove1_Val = (u8)sq_thresh->upper_threshold[0];
    snrCmd->thresholdBelow1_Val = (u8)sq_thresh->lower_threshold[0];
    } else {
        /*
         * In case the user issues multiple times of snr_threshold_setting,
         * we should not use the extreames anymore, the target does not expect that.
         */
        snrCmd->thresholdAbove1_Val = ar6000_get_upper_threshold(snr_event_value, sq_thresh,
                                              sq_thresh->upper_threshold_valid_count);
        snrCmd->thresholdBelow1_Val = ar6000_get_lower_threshold(snr_event_value, sq_thresh,
                                              sq_thresh->lower_threshold_valid_count);
    }

}

int
wmi_get_challenge_resp_cmd(struct wmi_t *wmip, u32 cookie, u32 source)
{
    void *osbuf;
    struct wmix_hb_challenge_resp_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmix_hb_challenge_resp_cmd *)(((struct sk_buff *)osbuf)->data);
    cmd->cookie = cookie;
    cmd->source = source;

    return (wmi_cmd_send_xtnd(wmip, osbuf, WMIX_HB_CHALLENGE_RESP_CMDID,
                              NO_SYNC_WMIFLAG));
}

int
wmi_get_stats_cmd(struct wmi_t *wmip)
{
    return wmi_simple_cmd(wmip, WMI_GET_STATISTICS_CMDID);
}

int
wmi_set_txPwr_cmd(struct wmi_t *wmip, u8 dbM)
{
    void *osbuf;
    struct wmi_set_tx_pwr_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_set_tx_pwr_cmd *)(((struct sk_buff *)osbuf)->data);
    cmd->dbM = dbM;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_TX_PWR_CMDID, NO_SYNC_WMIFLAG));
}

int
wmi_get_txPwr_cmd(struct wmi_t *wmip)
{
    return wmi_simple_cmd(wmip, WMI_GET_TX_PWR_CMDID);
}

void
wmi_get_current_bssid(struct wmi_t *wmip, u8 *bssid)
{
    if (bssid != NULL) {
        memcpy(bssid, wmip->wmi_bssid, ETH_ALEN);
    }
}

u8 wmi_determine_userPriority(
    u8 *pkt,
    u32 layer2Pri)
{
    u8 ipPri;
    iphdr *ipHdr = (iphdr *)pkt;

    /* Determine IPTOS priority */
    /*
     * IP Tos format :
     *      (Refer Pg 57 WMM-test-plan-v1.2)
     * IP-TOS - 8bits
     *          : DSCP(6-bits) ECN(2-bits)
     *          : DSCP - P2 P1 P0 X X X
     *              where (P2 P1 P0) form 802.1D
     */
    ipPri = ipHdr->ip_tos >> 5;
    ipPri &= 0x7;

    if ((layer2Pri & 0x7) > ipPri)
        return ((u8)layer2Pri & 0x7);
    else
        return ipPri;
}

u8 convert_userPriority_to_trafficClass(u8 userPriority)
{
    return  (up_to_ac[userPriority & 0x7]);
}

int
wmi_set_lpreamble_cmd(struct wmi_t *wmip, u8 status, u8 preamblePolicy)
{
    void *osbuf;
    struct wmi_set_lpreamble_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_set_lpreamble_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->status = status;
    cmd->preamblePolicy = preamblePolicy;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_LPREAMBLE_CMDID,
            NO_SYNC_WMIFLAG));
}

int
wmi_set_rts_cmd(struct wmi_t *wmip, u16 threshold)
{
    void *osbuf;
    struct wmi_set_rts_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_set_rts_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->threshold = threshold;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_RTS_CMDID,
            NO_SYNC_WMIFLAG));
}

int
wmi_set_wmm_txop(struct wmi_t *wmip, enum wmi_txop_cfg cfg)
{
    void *osbuf;
    struct wmi_set_wmm_txop_cmd *cmd;

    if( !((cfg == WMI_TXOP_DISABLED) || (cfg == WMI_TXOP_ENABLED)) )
        return A_EINVAL;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_set_wmm_txop_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->txopEnable = cfg;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_WMM_TXOP_CMDID,
            NO_SYNC_WMIFLAG));

}

int
wmi_set_btcoex_fe_ant_cmd(struct wmi_t *wmip, struct wmi_set_btcoex_fe_ant_cmd * cmd)
{
	void *osbuf;
    struct wmi_set_btcoex_fe_ant_cmd *alloc_cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }
    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));
    alloc_cmd = (struct wmi_set_btcoex_fe_ant_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(alloc_cmd, 0, sizeof(*cmd));
	memcpy(alloc_cmd,cmd,sizeof(struct wmi_set_btcoex_fe_ant_cmd));
    return (wmi_cmd_send(wmip, osbuf, WMI_SET_BTCOEX_FE_ANT_CMDID,
                         NO_SYNC_WMIFLAG));

}


int
wmi_set_btcoex_colocated_bt_dev_cmd(struct wmi_t *wmip,
						struct wmi_set_btcoex_colocated_bt_dev_cmd * cmd)
{
	void *osbuf;
    struct wmi_set_btcoex_colocated_bt_dev_cmd *alloc_cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }
    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));
    alloc_cmd = (struct wmi_set_btcoex_colocated_bt_dev_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(alloc_cmd, 0, sizeof(*cmd));
    memcpy(alloc_cmd,cmd,sizeof(struct wmi_set_btcoex_colocated_bt_dev_cmd));
    A_PRINTF("colocated bt = %d\n", alloc_cmd->btcoexCoLocatedBTdev);
    return (wmi_cmd_send(wmip, osbuf, WMI_SET_BTCOEX_COLOCATED_BT_DEV_CMDID,
                         NO_SYNC_WMIFLAG));

}

int
wmi_set_keepalive_cmd(struct wmi_t *wmip, u8 keepaliveInterval)
{
    void *osbuf;
    struct wmi_set_keepalive_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_set_keepalive_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));
    cmd->keepaliveInterval = keepaliveInterval;
    wmip->wmi_keepaliveInterval = keepaliveInterval;

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_KEEPALIVE_CMDID,
                         NO_SYNC_WMIFLAG));
}

s32 wmi_get_rate(s8 rateindex)
{
    if (rateindex == RATE_AUTO) {
        return 0;
    } else {
        return(wmi_rateTable[(u32) rateindex][0]);
    }
}

void
wmi_node_return (struct wmi_t *wmip, bss_t *bss)
{
    if (NULL != bss)
    {
        wlan_node_return (&wmip->wmi_scan_table, bss);
    }
}

bss_t *
wmi_find_Ssidnode (struct wmi_t *wmip, u8 *pSsid,
                   u32 ssidLength, bool bIsWPA2, bool bMatchSSID)
{
    bss_t *node = NULL;
    node = wlan_find_Ssidnode (&wmip->wmi_scan_table, pSsid,
                               ssidLength, bIsWPA2, bMatchSSID);
    return node;
}

void
wmi_free_allnodes(struct wmi_t *wmip)
{
    wlan_free_allnodes(&wmip->wmi_scan_table);
}

bss_t *
wmi_find_node(struct wmi_t *wmip, const u8 *macaddr)
{
    bss_t *ni=NULL;
    ni=wlan_find_node(&wmip->wmi_scan_table,macaddr);
    return ni;
}

void
wmi_free_node(struct wmi_t *wmip, const u8 *macaddr)
{
    bss_t *ni=NULL;

    ni=wlan_find_node(&wmip->wmi_scan_table,macaddr);
    if (ni != NULL) {
        wlan_node_reclaim(&wmip->wmi_scan_table, ni);
    }

    return;
}

static int
wmi_get_pmkid_list_event_rx(struct wmi_t *wmip, u8 *datap, u32 len)
{
    struct wmi_pmkid_list_reply *reply;
    u32 expected_len;

    if (len < sizeof(struct wmi_pmkid_list_reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_pmkid_list_reply *)datap;
    expected_len = sizeof(reply->numPMKID) + reply->numPMKID * WMI_PMKID_LEN;

    if (len < expected_len) {
        return A_EINVAL;
    }

    ar6000_pmkid_list_event(wmip->wmi_devt, reply->numPMKID,
                           reply->pmkidList, reply->bssidList[0]);

    return 0;
}


static int
wmi_set_params_event_rx(struct wmi_t *wmip, u8 *datap, u32 len)
{
    struct wmi_set_params_reply *reply;

    if (len < sizeof(struct wmi_set_params_reply)) {
        return A_EINVAL;
    }
    reply = (struct wmi_set_params_reply *)datap;

    if (0 == reply->status)
    {

    }
    else
    {

    }

    return 0;
}

#if defined(CONFIG_TARGET_PROFILE_SUPPORT)

/* Called to handle WMIX_PROF_CONT_EVENTID */
static int
wmi_prof_count_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    WMIX_PROF_COUNT_EVENT *prof_data = (WMIX_PROF_COUNT_EVENT *)datap;

    A_DPRINTF(DBG_WMI,
        (DBGFMT "Enter - addr=0x%x count=%d\n", DBGARG,
        prof_data->addr, prof_data->count));

    prof_count_rx(prof_data->addr, prof_data->count);

    return 0;
}
#endif /* CONFIG_TARGET_PROFILE_SUPPORT */

u8 ar6000_get_upper_threshold(s16 rssi, struct sq_threshold_params_s *sq_thresh,
                           u32 size)
{
    u32 index;
    u8 threshold = (u8)sq_thresh->upper_threshold[size - 1];

    /* The list is already in sorted order. Get the next lower value */
    for (index = 0; index < size; index ++) {
        if (rssi < sq_thresh->upper_threshold[index]) {
            threshold = (u8)sq_thresh->upper_threshold[index];
            break;
        }
    }

    return threshold;
}

u8 ar6000_get_lower_threshold(s16 rssi, struct sq_threshold_params_s *sq_thresh,
                           u32 size)
{
    u32 index;
    u8 threshold = (u8)sq_thresh->lower_threshold[size - 1];

    /* The list is already in sorted order. Get the next lower value */
    for (index = 0; index < size; index ++) {
        if (rssi > sq_thresh->lower_threshold[index]) {
            threshold = (u8)sq_thresh->lower_threshold[index];
            break;
        }
    }

    return threshold;
}
static int
wmi_send_rssi_threshold_params(struct wmi_t *wmip,
                              struct wmi_rssi_threshold_params_cmd *rssiCmd)
{
    void    *osbuf;
    s8 size;
    struct wmi_rssi_threshold_params_cmd *cmd;

    size = sizeof (*cmd);

    osbuf = ar6k_buf_alloc(size);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, size);

    cmd = (struct wmi_rssi_threshold_params_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, size);
    memcpy(cmd, rssiCmd, sizeof(struct wmi_rssi_threshold_params_cmd));

    return (wmi_cmd_send(wmip, osbuf, WMI_RSSI_THRESHOLD_PARAMS_CMDID,
                            NO_SYNC_WMIFLAG));
}
static int
wmi_send_snr_threshold_params(struct wmi_t *wmip,
                             struct wmi_snr_threshold_params_cmd *snrCmd)
{
    void    *osbuf;
    s8 size;
    struct wmi_snr_threshold_params_cmd *cmd;

    size = sizeof (*cmd);

    osbuf = ar6k_buf_alloc(size);
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, size);
    cmd = (struct wmi_snr_threshold_params_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, size);
    memcpy(cmd, snrCmd, sizeof(struct wmi_snr_threshold_params_cmd));

    return (wmi_cmd_send(wmip, osbuf, WMI_SNR_THRESHOLD_PARAMS_CMDID,
                            NO_SYNC_WMIFLAG));
}

int wmi_add_current_bss (struct wmi_t *wmip, u8 *id, bss_t *bss)
{
    wlan_setup_node (&wmip->wmi_scan_table, bss, id);
    return 0;
}

static int
wmi_addba_req_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_addba_req_event *cmd = (struct wmi_addba_req_event *)datap;

    ar6000_aggr_rcv_addba_req_evt(wmip->wmi_devt, cmd);

    return 0;
}


static int
wmi_addba_resp_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_addba_resp_event *cmd = (struct wmi_addba_resp_event *)datap;

    ar6000_aggr_rcv_addba_resp_evt(wmip->wmi_devt, cmd);

    return 0;
}

static int
wmi_delba_req_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_delba_event *cmd = (struct wmi_delba_event *)datap;

    ar6000_aggr_rcv_delba_req_evt(wmip->wmi_devt, cmd);

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
////                                                                        ////
////                AP mode functions                                       ////
////                                                                        ////
////////////////////////////////////////////////////////////////////////////////
/*
 * IOCTL: AR6000_XIOCTL_AP_COMMIT_CONFIG
 *
 * When AR6K in AP mode, This command will be called after
 * changing ssid, channel etc. It will pass the profile to
 * target with a flag which will indicate which parameter changed,
 * also if this flag is 0, there was no change in parametes, so
 * commit cmd will not be sent to target. Without calling this IOCTL
 * the changes will not take effect.
 */
int
wmi_ap_profile_commit(struct wmi_t *wmip, struct wmi_connect_cmd *p)
{
    void *osbuf;
    struct wmi_connect_cmd *cm;

    osbuf = ar6k_buf_alloc(sizeof(*cm));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cm));
    cm = (struct wmi_connect_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cm, 0, sizeof(*cm));

    memcpy(cm,p,sizeof(*cm));

    return (wmi_cmd_send(wmip, osbuf, WMI_AP_CONFIG_COMMIT_CMDID, NO_SYNC_WMIFLAG));
}

static int
wmi_pspoll_event_rx(struct wmi_t *wmip, u8 *datap, int len)
{
    struct wmi_pspoll_event *ev;

    if (len < sizeof(struct wmi_pspoll_event)) {
        return A_EINVAL;
    }
    ev = (struct wmi_pspoll_event *)datap;

    ar6000_pspoll_event(wmip->wmi_devt, ev->aid);
    return 0;
}

static int
wmi_dtimexpiry_event_rx(struct wmi_t *wmip, u8 *datap,int len)
{
    ar6000_dtimexpiry_event(wmip->wmi_devt);
    return 0;
}

#ifdef WAPI_ENABLE
static int
wmi_wapi_rekey_event_rx(struct wmi_t *wmip, u8 *datap,int len)
{
    u8 *ev;

    if (len < 7) {
        return A_EINVAL;
    }
    ev = (u8 *)datap;

    ap_wapi_rekey_event(wmip->wmi_devt, *ev, &ev[1]);
    return 0;
}
#endif

int
wmi_set_pvb_cmd(struct wmi_t *wmip, u16 aid, bool flag)
{
    struct wmi_ap_set_pvb_cmd *cmd;
    void *osbuf = NULL;

    osbuf = ar6k_buf_alloc(sizeof(struct wmi_ap_set_pvb_cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(struct wmi_ap_set_pvb_cmd));
    cmd = (struct wmi_ap_set_pvb_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(cmd, 0, sizeof(*cmd));

    cmd->aid = aid;
    cmd->flag = flag;

    return (wmi_cmd_send(wmip, osbuf, WMI_AP_SET_PVB_CMDID, NO_SYNC_WMIFLAG));
}

int
wmi_set_ht_cap_cmd(struct wmi_t *wmip, struct wmi_set_ht_cap_cmd *cmd)
{
    void *osbuf;
    struct wmi_set_ht_cap_cmd *htCap;
    u8 band;

    osbuf = ar6k_buf_alloc(sizeof(*htCap));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*htCap));

    band = (cmd->band)? A_BAND_5GHZ : A_BAND_24GHZ;
    wmip->wmi_ht_allowed[band] = (cmd->enable)? 1:0;

    htCap = (struct wmi_set_ht_cap_cmd *)(((struct sk_buff *)osbuf)->data);
    memset(htCap, 0, sizeof(*htCap));
    memcpy(htCap, cmd, sizeof(*htCap));

    return (wmi_cmd_send(wmip, osbuf, WMI_SET_HT_CAP_CMDID,
                         NO_SYNC_WMIFLAG));
}

int
wmi_set_rx_frame_format_cmd(struct wmi_t *wmip, u8 rxMetaVersion,
                            bool rxDot11Hdr, bool defragOnHost)
{
    void *osbuf;
    struct wmi_rx_frame_format_cmd *cmd;

    osbuf = ar6k_buf_alloc(sizeof(*cmd));
    if (osbuf == NULL) {
        return A_NO_MEMORY;
    }

    skb_put((struct sk_buff *)osbuf, sizeof(*cmd));

    cmd = (struct wmi_rx_frame_format_cmd *)(((struct sk_buff *)osbuf)->data);
    cmd->dot11Hdr = (rxDot11Hdr==true)? 1:0;
    cmd->defragOnHost = (defragOnHost==true)? 1:0;
    cmd->metaVersion = rxMetaVersion;  /*  */

    /* Delete the local aggr state, on host */
    return (wmi_cmd_send(wmip, osbuf, WMI_RX_FRAME_FORMAT_CMDID, NO_SYNC_WMIFLAG));
}
