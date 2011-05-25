//------------------------------------------------------------------------------
// Copyright (c) 2004-2010 Atheros Communications Inc.
// All rights reserved.
//
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
//
// Author(s): ="Atheros"
//------------------------------------------------------------------------------

#ifndef _AR6000_H_
#define _AR6000_H_

#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/sched.h>
#include <net/cfg80211.h>
#include "htc.h"
#include <ieee80211.h>
#include <ieee80211_ioctl.h>
#include <ieee80211_node.h>
#include "wmi.h"
#include "aggr_rx.h"
#include <linux/rtnetlink.h>
#include "ar6xapi_linux.h"
#include <linux/firmware.h>
#include "targaddrs.h"
#define ATH_MODULE_NAME driver
#include "a_debug.h"

#define MAX_AR6000                        1
#define AR6000_MAX_RX_BUFFERS             16
#define AR6000_BUFFER_SIZE                1664
#define AR6000_MAX_AMSDU_RX_BUFFERS       4
#define AR6000_AMSDU_REFILL_THRESHOLD     3
#define AR6000_AMSDU_BUFFER_SIZE          (WMI_MAX_AMSDU_RX_DATA_FRAME_LENGTH + 128)

#define USER_SAVEDKEYS_STAT_INIT     0
#define USER_SAVEDKEYS_STAT_RUN      1

#define AR6000_TX_TIMEOUT      10
#define AR6000_MAX_ENDPOINTS   4
#define MAX_NODE_NUM           15

/* MAX_HI_COOKIE_NUM are reserved for high priority traffic */
#define MAX_DEF_COOKIE_NUM                180
#define MAX_HI_COOKIE_NUM                 18 /* 10% of MAX_COOKIE_NUM */
#define MAX_COOKIE_NUM                    (MAX_DEF_COOKIE_NUM + MAX_HI_COOKIE_NUM)

#define MAX_DEFAULT_SEND_QUEUE_DEPTH      (MAX_DEF_COOKIE_NUM / WMM_NUM_AC)

#define AR6000_HB_CHALLENGE_RESP_FREQ_DEFAULT        1
#define AR6000_HB_CHALLENGE_RESP_MISS_THRES_DEFAULT  1
#define A_DISCONNECT_TIMER_INTERVAL       10 * 1000
#define A_DEFAULT_LISTEN_INTERVAL         100
#define A_MAX_WOW_LISTEN_INTERVAL         1000

#ifdef ENABLEUARTPRINT_SET
#define ENABLEUARTPRINT_DEFAULT    1
#else
#define ENABLEUARTPRINT_DEFAULT    0
#endif

#ifdef ATH6KL_CONFIG_HIF_VIRTUAL_SCATTER
#define NOHIFSCATTERSUPPORT_DEFAULT    1
#else
#define NOHIFSCATTERSUPPORT_DEFAULT    0
#endif

/* AR6003 1.0 definitions */
#define AR6003_REV1_VERSION                 0x300002ba
#define AR6003_REV1_PATCH_DOWNLOAD_ADDRESS  0x57ea6c
#define AR6003_REV1_OTP_FILE                "ath6k/AR6003/hw1.0/otp.bin.z77"
#define AR6003_REV1_FIRMWARE_FILE           "ath6k/AR6003/hw1.0/athwlan.bin.z77"
#define AR6003_REV1_TCMD_FIRMWARE_FILE      "ath6k/AR6003/hw1.0/athtcmd_ram.bin"
#define AR6003_REV1_ART_FIRMWARE_FILE       "ath6k/AR6003/hw1.0/device.bin"
#define AR6003_REV1_PATCH_FILE              "ath6k/AR6003/hw1.0/data.patch.bin"
#define AR6003_REV1_EPPING_FIRMWARE_FILE    "ath6k/AR6003/hw1.0/endpointping.bin"
#ifdef CONFIG_AR600x_SD31_XXX
#define AR6003_REV1_BOARD_DATA_FILE         "ath6k/AR6003/hw1.0/bdata.SD31.bin"
#elif defined(CONFIG_AR600x_SD32_XXX)
#define AR6003_REV1_BOARD_DATA_FILE         "ath6k/AR6003/hw1.0/bdata.SD32.bin"
#elif defined(CONFIG_AR600x_WB31_XXX)
#define AR6003_REV1_BOARD_DATA_FILE         "ath6k/AR6003/hw1.0/bdata.WB31.bin"
#else
#define AR6003_REV1_BOARD_DATA_FILE         "ath6k/AR6003/hw1.0/bdata.CUSTOM.bin"
#endif

/* AR6003 2.0 definitions */
#define AR6003_REV2_VERSION                 0x30000384 
#define AR6003_REV2_PATCH_DOWNLOAD_ADDRESS  0x57e910
#define AR6003_REV2_OTP_FILE                "ath6k/AR6003/hw2.0/otp.bin.z77"
#define AR6003_REV2_FIRMWARE_FILE           "ath6k/AR6003/hw2.0/athwlan.bin.z77"
#define AR6003_REV2_TCMD_FIRMWARE_FILE      "ath6k/AR6003/hw2.0/athtcmd_ram.bin"
#define AR6003_REV2_ART_FIRMWARE_FILE       "ath6k/AR6003/hw2.0/device.bin"
#define AR6003_REV2_PATCH_FILE              "ath6k/AR6003/hw2.0/data.patch.bin"
#define AR6003_REV2_EPPING_FIRMWARE_FILE    "ath6k/AR6003/hw2.0/endpointping.bin"
#ifdef CONFIG_AR600x_SD31_XXX
#define AR6003_REV2_BOARD_DATA_FILE         "ath6k/AR6003/hw2.0/bdata.SD31.bin"
#elif defined(CONFIG_AR600x_SD32_XXX)
#define AR6003_REV2_BOARD_DATA_FILE         "ath6k/AR6003/hw2.0/bdata.SD32.bin"
#elif defined(CONFIG_AR600x_WB31_XXX)
#define AR6003_REV2_BOARD_DATA_FILE         "ath6k/AR6003/hw2.0/bdata.WB31.bin"
#else
#define AR6003_REV2_BOARD_DATA_FILE         "ath6k/AR6003/hw2.0/bdata.CUSTOM.bin"
#endif

/* AR6003 3.0 definitions */
#define AR6003_REV3_VERSION                 0x30000582
#define AR6003_REV3_OTP_FILE                "ath6k/AR6003/hw2.1.1/otp.bin"
#define AR6003_REV3_FIRMWARE_FILE           "ath6k/AR6003/hw2.1.1/athwlan.bin"
#define AR6003_REV3_TCMD_FIRMWARE_FILE    "ath6k/AR6003/hw2.1.1/athtcmd_ram.bin"
#define AR6003_REV3_ART_FIRMWARE_FILE       "ath6k/AR6003/hw2.1.1/device.bin"
#define AR6003_REV3_PATCH_FILE            "ath6k/AR6003/hw2.1.1/data.patch.bin"
#define AR6003_REV3_EPPING_FIRMWARE_FILE "ath6k/AR6003/hw2.1.1/endpointping.bin"
#ifdef CONFIG_AR600x_SD31_XXX
#define AR6003_REV3_BOARD_DATA_FILE       "ath6k/AR6003/hw2.1.1/bdata.SD31.bin"
#elif defined(CONFIG_AR600x_SD32_XXX)
#define AR6003_REV3_BOARD_DATA_FILE        "ath6k/AR6003/hw2.1.1/bdata.SD32.bin"
#elif defined(CONFIG_AR600x_WB31_XXX)
#define AR6003_REV3_BOARD_DATA_FILE        "ath6k/AR6003/hw2.1.1/bdata.WB31.bin"
#else
#define AR6003_REV3_BOARD_DATA_FILE      "ath6k/AR6003/hw2.1.1/bdata.CUSTOM.bin"
#endif

/* Per STA data, used in AP mode */
#define STA_PWR_MGMT_MASK 0x1
#define STA_PWR_MGMT_SHIFT 0x0
#define STA_PWR_MGMT_AWAKE 0x0
#define STA_PWR_MGMT_SLEEP 0x1

#define STA_SET_PWR_SLEEP(sta) (sta->flags |= (STA_PWR_MGMT_MASK << STA_PWR_MGMT_SHIFT))
#define STA_CLR_PWR_SLEEP(sta) (sta->flags &= ~(STA_PWR_MGMT_MASK << STA_PWR_MGMT_SHIFT))
#define STA_IS_PWR_SLEEP(sta) ((sta->flags >> STA_PWR_MGMT_SHIFT) & STA_PWR_MGMT_MASK)

#define STA_PS_POLLED_MASK 0x1
#define STA_PS_POLLED_SHIFT 0x1
#define STA_SET_PS_POLLED(sta) (sta->flags |= (STA_PS_POLLED_MASK << STA_PS_POLLED_SHIFT))
#define STA_CLR_PS_POLLED(sta) (sta->flags &= ~(STA_PS_POLLED_MASK << STA_PS_POLLED_SHIFT))
#define STA_IS_PS_POLLED(sta) (sta->flags & (STA_PS_POLLED_MASK << STA_PS_POLLED_SHIFT))

#define WLAN_INIT_MODE_DEFAULT     WLAN_INIT_MODE_DRV

#define arAc2EndpointID(ar,ac)          (ar)->arAc2EpMapping[(ac)]
#define arSetAc2EndpointIDMap(ar,ac,ep)  \
{  (ar)->arAc2EpMapping[(ac)] = (ep); \
   (ar)->arEp2AcMapping[(ep)] = (ac); }
#define arEndpoint2Ac(ar,ep)           (ar)->arEp2AcMapping[(ep)]

/* HTC TX packet tagging definitions */
#define AR6K_CONTROL_PKT_TAG    HTC_TX_PACKET_TAG_USER_DEFINED
#define AR6K_DATA_PKT_TAG       (AR6K_CONTROL_PKT_TAG + 1)

#define AR6003_CUST_DATA_SIZE 16

#define HOST_INTEREST_ITEM_ADDRESS(target, item) \
         (((target)->arTargetType == TARGET_TYPE_AR6003) ? AR6003_HOST_INTEREST_ITEM_ADDRESS(item) : 0)

#define AH6K_DEPOSITE_CREDITS_TO_EP(pCredInfo,pEpDist,credits)      \
	(pEpDist)->TxCredits += (credits);              \
	(pEpDist)->TxCreditsAssigned += (credits);      \
	(pCredInfo)->CurrentFreeCredits -= (credits);


#define AR6000_STAT_INC(ar, stat)       (ar->arNetStats.stat++)


enum {
	DRV_HB_CHALLENGE,
	APP_HB_CHALLENGE
};

enum wlan_init_mode {
	WLAN_INIT_MODE_NONE,
	WLAN_INIT_MODE_USR,
	WLAN_INIT_MODE_UDEV,
	WLAN_INIT_MODE_DRV
};

enum wlan_suspend_state {
	WLAN_SUSPEND_CUT_PWR,
	WLAN_SUSPEND_DEEP_SLEEP,
	WLAN_SUSPEND_WOW,
	WLAN_SUSPEND_CUT_PWR_IF_BT_OFF
};

enum wlan_off_state {
	WLAN_OFF_CUT_PWR,
	WLAN_OFF_DEEP_SLEEP,
};

enum wlan_low_pwr_state {
	WLAN_POWER_STATE_ON,
	WLAN_POWER_STATE_CUT_PWR,
	WLAN_POWER_STATE_DEEP_SLEEP,
	WLAN_POWER_STATE_WOW
};

enum wlan_wow_state {
	WLAN_WOW_STATE_NONE,
	WLAN_WOW_STATE_SUSPENDED,
	WLAN_WOW_STATE_SUSPENDING
};

enum ar6k_bin_file { 
	AR6K_OTP_FILE,
	AR6K_FIRMWARE_FILE,
	AR6K_PATCH_FILE,
	AR6K_BOARD_DATA_FILE,
};

enum sme_state {
	SME_DISCONNECTED,
	SME_CONNECTING,
	SME_CONNECTED
};

enum ar6k_wlan_state {
	WLAN_DISABLED,
	WLAN_ENABLED
};

struct user_rssi_thold {
	s16 tag;
	s16 rssi;
};

struct user_rssi_params {
	u8 weight;
	u32 pollTime;
	struct user_rssi_thold    tholds[12];
};

/* HTC RAW streams */

#define arRawStream2EndpointID(ar,raw)          (ar)->arRawHtc->arRaw2EpMapping[(raw)]
#define arSetRawStream2EndpointIDMap(ar,raw,ep)  \
{  (ar)->arRawHtc->arRaw2EpMapping[(raw)] = (ep); \
   (ar)->arRawHtc->arEp2RawMapping[(ep)] = (raw); }

#define arEndpoint2RawStreamID(ar,ep)           (ar)->arRawHtc->arEp2RawMapping[(ep)]

#define RAW_HTC_READ_BUFFERS_NUM    4
#define RAW_HTC_WRITE_BUFFERS_NUM   4
#define HTC_RAW_BUFFER_SIZE  1664

enum htc_raw_stream_id {
	HTC_RAW_STREAM_NOT_MAPPED = -1,
	HTC_RAW_STREAM_0 = 0,
	HTC_RAW_STREAM_1 = 1,
	HTC_RAW_STREAM_2 = 2,
	HTC_RAW_STREAM_3 = 3,
	HTC_RAW_STREAM_NUM_MAX
};

struct raw_htc_buffer {
	int currPtr;
	int length;
	unsigned char data[HTC_RAW_BUFFER_SIZE];
	struct htc_packet    HTCPacket;
};

struct ar6_raw_htc {
	enum htc_endpoint_id arRaw2EpMapping[HTC_RAW_STREAM_NUM_MAX];
	enum htc_raw_stream_id arEp2RawMapping[ENDPOINT_MAX];
	struct semaphore raw_htc_read_sem[HTC_RAW_STREAM_NUM_MAX];
	struct semaphore raw_htc_write_sem[HTC_RAW_STREAM_NUM_MAX];
	wait_queue_head_t raw_htc_read_queue[HTC_RAW_STREAM_NUM_MAX];
	wait_queue_head_t raw_htc_write_queue[HTC_RAW_STREAM_NUM_MAX];
	struct raw_htc_buffer raw_htc_read_buffer[HTC_RAW_STREAM_NUM_MAX][RAW_HTC_READ_BUFFERS_NUM];
	struct raw_htc_buffer raw_htc_write_buffer[HTC_RAW_STREAM_NUM_MAX][RAW_HTC_WRITE_BUFFERS_NUM];
	bool write_buffer_available[HTC_RAW_STREAM_NUM_MAX];
	bool read_buffer_available[HTC_RAW_STREAM_NUM_MAX];
};

struct user_savedkeys {
	struct ieee80211req_key ucast_ik;
	struct ieee80211req_key bcast_ik;
	enum crypto_type keyType;
	bool keyOk;
};

struct ar_wep_key {
	u8 arKeyIndex;
	u8 arKeyLen;
	u8 arKey[64];
};

struct ar_key {
	u8 key[WLAN_MAX_KEY_LEN];
	u8 key_len;
	u8 seq[IW_ENCODE_SEQ_MAX_SIZE];
	u8 seq_len;
	u32 cipher;
};

struct ar_node_mapping {
	u8 macAddress[6];
	u8 epId;
	u8 txPending;
};

struct ar_cookie {
	unsigned long arc_bp[2];    /* Must be first field */
	struct htc_packet HtcPkt;
	struct ar_cookie *arc_list_next;
};

struct ar_hb_chlng_resp {
	struct timer_list timer;
	u32 frequency;
	u32 seqNum;
	bool outstanding;
	u8 missCnt;
	u8 missThres;
};

struct common_credit_state_info {
	int TotalAvailableCredits;
	int CurrentFreeCredits;
	struct htc_endpoint_credit_dist *pLowestPriEpDist;
};

struct ar6k_sta {
	u16 flags;
	u8 mac[ETH_ALEN];
	u8 aid;
	u8 keymgmt;
	u8 ucipher;
	u8 auth;
	u8 wpa_ie[IEEE80211_MAX_IE];
	struct sk_buff_head psq;
	spinlock_t psqLock;
};

struct ar6000_version {
	u32 host_ver;
	u32 target_ver;
	u32 wlan_ver;
	u32 abi_ver;
};

struct targetStats {
	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_unicast_pkts;
	u64 tx_unicast_bytes;
	u64 tx_multicast_pkts;
	u64 tx_multicast_bytes;
	u64 tx_broadcast_pkts;
	u64 tx_broadcast_bytes;
	u64 tx_rts_success_cnt;
	u64 tx_packet_per_ac[4];

	u64 tx_errors;
	u64 tx_failed_cnt;
	u64 tx_retry_cnt;
	u64 tx_mult_retry_cnt;
	u64 tx_rts_fail_cnt;

	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_unicast_pkts;
	u64 rx_unicast_bytes;
	u64 rx_multicast_pkts;
	u64 rx_multicast_bytes;
	u64 rx_broadcast_pkts;
	u64 rx_broadcast_bytes;
	u64 rx_fragment_pkt;

	u64 rx_errors;
	u64 rx_crcerr;
	u64 rx_key_cache_miss;
	u64 rx_decrypt_err;
	u64 rx_duplicate_frames;

	u64 tkip_local_mic_failure;
	u64 tkip_counter_measures_invoked;
	u64 tkip_replays;
	u64 tkip_format_errors;
	u64 ccmp_format_errors;
	u64 ccmp_replays;

	u64 power_save_failure_cnt;

	u64 cs_bmiss_cnt;
	u64 cs_lowRssi_cnt;
	u64 cs_connect_cnt;
	u64 cs_disconnect_cnt;

	s32 tx_unicast_rate;
	s32 rx_unicast_rate;

	u32 lq_val;

	u32 wow_num_pkts_dropped;
	u16 wow_num_events_discarded;

	s16 noise_floor_calibation;
	s16 cs_rssi;
	s16 cs_aveBeacon_rssi;
	u8 cs_aveBeacon_snr;
	u8 cs_lastRoam_msec;
	u8 cs_snr;

	u8 wow_num_host_pkt_wakeups;
	u8 wow_num_host_event_wakeups;

	u32 arp_received;
	u32 arp_matched;
	u32 arp_replied;
};

struct ar6_softc {
	struct net_device *arNetDev;
	void *arWmi;
	int  arTxPending[ENDPOINT_MAX];
	int  arTotalTxDataPending;
	bool arWmiEnabled;
	bool arWmiReady;
	bool arConnected;
	void *arHtcTarget;
	void *arHifDevice;
	spinlock_t arLock;
	struct semaphore arSem;
	int  arSsidLen;
	u_char arSsid[32];
	u8 arNextMode;
	u8 arNetworkType;
	u8 arDot11AuthMode;
	u8 arAuthMode;
	u8 arPairwiseCrypto;
	u8 arPairwiseCryptoLen;
	u8 arGroupCrypto;
	u8 arGroupCryptoLen;
	u8 arDefTxKeyIndex;
	struct ar_wep_key arWepKeyList[WMI_MAX_KEY_INDEX + 1];
	u8 arBssid[6];
	u8 arReqBssid[6];
	u16 arChannelHint;
	u16 arBssChannel;
	u16 arListenIntervalB;
	u16 arListenIntervalT;
	struct ar6000_version arVersion;
	u32 arTargetType;
	u8 arTxPwr;
	struct net_device_stats arNetStats;
	bool statsUpdatePending;
	struct targetStats  arTargetStats;
	enum ar6k_wlan_state arWlanState;
	struct ar_node_mapping  arNodeMap[MAX_NODE_NUM];
	u8 arIbssPsEnable;
	u8 arNodeNum;
	u8 arNexEpId;
	struct ar_cookie *arCookieList;
	u32 arCookieCount;
	u8 arSkipScan;
	bool arConnectPending;
	bool arWmmEnabled;
	struct ar_hb_chlng_resp arHBChallengeResp;
	u32 arMgmtFilter;
	enum htc_endpoint_id  arAc2EpMapping[WMM_NUM_AC];
	bool arAcStreamActive[WMM_NUM_AC];
	u8 arAcStreamPriMap[WMM_NUM_AC];
	u8 arHiAcStreamActivePri;
	u8 arEp2AcMapping[ENDPOINT_MAX];
	enum htc_endpoint_id arControlEp;
#ifdef HTC_RAW_INTERFACE
	struct ar6_raw_htc *arRawHtc;
#endif
	bool arNetQueueStopped;
	bool arRawIfInit;
	int  arDeviceIndex;
	struct common_credit_state_info arCreditStateInfo;
	bool arWMIControlEpFull;
	u32 arConnectCtrlFlags;
	s32 user_savedkeys_stat;
	u32 user_key_ctrl;
	struct user_savedkeys  user_saved_keys;
	struct user_rssi_thold rssi_map[12];
	u8 arUserBssFilter;
	struct ar6k_sta sta_list[AP_MAX_NUM_STA];
	u8 sta_list_index;
	struct ieee80211req_key ap_mode_bkey;
	struct sk_buff_head mcastpsq;
	spinlock_t  mcastpsqLock;
	bool DTIMExpired;
	u8 intra_bss;
	void *aggr_cntxt;
	struct wmi_ap_mode_stat arAPStats;
	u8 ap_country_code[3];
	struct htc_packet_queue amsdu_rx_buffer_queue;
	bool bIsDestroyProgress;
	struct timer_list disconnect_timer;
	u8 rxMetaVersion;
#ifdef WAPI_ENABLE
	u8 arWapiEnable;
#endif
	struct hif_device_os_device_info   osDevInfo;
	struct wireless_dev *wdev;
	struct cfg80211_scan_request    *scan_request;
	struct ar_key  keys[WMI_MAX_KEY_INDEX + 1];
	u32 smeState;
	u16 arWlanPowerState;
	bool  arWlanOff;
#ifdef CONFIG_PM
	u16 arWowState;
	bool arBTOff;
	bool arBTSharing;
	u16 arSuspendConfig;
	u16 arWlanOffConfig;
	u16 arWow2Config;
#endif
	u8 scan_triggered;
	struct wmi_scan_params_cmd  scParams;
#define AR_MCAST_FILTER_MAC_ADDR_SIZE  4
	u8 arAutoAuthStage;

	bool is_netdev_registered;
};

extern wait_queue_head_t arEvent;
extern unsigned int enablerssicompensation;
extern unsigned int mbox_yield_limit;
extern unsigned int fwmode;
extern int wlaninitmode;
extern unsigned int csumOffload;
extern int reduce_credit_dribble;
extern bool bypasswmi;
extern unsigned int regscanmode;
extern unsigned int wmitimeout;
extern unsigned int processDot11Hdr;
extern struct net_device *ar6000_devices[MAX_AR6000];
extern u8 custDataAR6003[AR6003_CUST_DATA_SIZE];
extern u8 bcast_mac[];

void ar6000_destroy(struct net_device *dev, unsigned int unregister);
int ar6000_configure_target(struct ar6_softc *ar);
int ar6000_sysfs_bmi_get_config(struct ar6_softc *ar, u32 mode);
void ar6000_detect_error(unsigned long ptr);
void ar6000_destroy(struct net_device *dev, unsigned int unregister);
void disconnect_timer_handler(unsigned long ptr);
void init_netdev(struct net_device *dev);
void ar6000_deliver_frames_to_nw_stack(void *dev, void *osbuf);
void ar6000_cookie_init(struct ar6_softc *ar);
void ar6000_cookie_cleanup(struct ar6_softc *ar);
void read_rssi_compensation_param(struct ar6_softc *ar);
void ar6000_rx(void *Context, struct htc_packet *pPacket);
void ar6000_tx_complete(void *Context, struct htc_packet_queue *pPackets);;
enum htc_send_full_action ar6000_tx_queue_full(void *Context, struct htc_packet *pPacket);
int ar6000_set_host_app_area(struct ar6_softc *ar);
void ath6k_credit_distribute(void *Context,
		struct htc_endpoint_credit_dist *pEPDistList,
		enum htc_credit_dist_reason Reason);
void ar6000_cleanup_amsdu_rxbufs(struct ar6_softc *ar);
int ar6000_access_datadiag(struct hif_device *hifDevice, u32 address,
			   u8 *data, u32 length, bool read);
void ar6000_reset_device(struct hif_device *hifDevice,
			 u32 TargetType, bool waitForCompletion,
			 bool coldReset);
int ar6000_ReadRegDiag(struct hif_device *hifDevice, u32 *address, u32 *data);
void ar6000_init_profile_info(struct ar6_softc *ar);
int ar6000_init(struct net_device *dev);
void ar6000_TxDataCleanup(struct ar6_softc *ar);
void ar6000_restart_endpoint(struct net_device *dev);
void ar6000_stop_endpoint(struct net_device *dev, bool keepprofile, bool getdbglogs);

static inline void *ar6k_priv(struct net_device *dev)
{
    return (wdev_priv(dev->ieee80211_ptr));
}

/* DEBUG macros, to be be cleaned up */
#define  ATH_DEBUG_DBG_LOG       ATH_DEBUG_MAKE_MODULE_MASK(0)
#define  ATH_DEBUG_WLAN_CONNECT  ATH_DEBUG_MAKE_MODULE_MASK(1)
#define  ATH_DEBUG_WLAN_SCAN     ATH_DEBUG_MAKE_MODULE_MASK(2)
#define  ATH_DEBUG_WLAN_TX       ATH_DEBUG_MAKE_MODULE_MASK(3)
#define  ATH_DEBUG_WLAN_RX       ATH_DEBUG_MAKE_MODULE_MASK(4)
#define  ATH_DEBUG_HTC_RAW       ATH_DEBUG_MAKE_MODULE_MASK(5)
#define  ATH_DEBUG_HCI_BRIDGE    ATH_DEBUG_MAKE_MODULE_MASK(6)
#define  ATH_DEBUG_HCI_RECV      ATH_DEBUG_MAKE_MODULE_MASK(7)
#define  ATH_DEBUG_HCI_SEND      ATH_DEBUG_MAKE_MODULE_MASK(8)
#define  ATH_DEBUG_HCI_DUMP      ATH_DEBUG_MAKE_MODULE_MASK(9)

#define DBG_INFO        0x00000001
#define DBG_ERROR       0x00000002
#define DBG_WARNING     0x00000004
#define DBG_SDIO        0x00000008
#define DBG_HIF         0x00000010
#define DBG_HTC         0x00000020
#define DBG_WMI         0x00000040
#define DBG_WMI2        0x00000080
#define DBG_DRIVER      0x00000100

#define DBG_DEFAULTS    (DBG_ERROR|DBG_WARNING)


ATH_DEBUG_DECLARE_EXTERN(htc);
ATH_DEBUG_DECLARE_EXTERN(wmi);
ATH_DEBUG_DECLARE_EXTERN(bmi);
ATH_DEBUG_DECLARE_EXTERN(hif);
ATH_DEBUG_DECLARE_EXTERN(wlan);
ATH_DEBUG_DECLARE_EXTERN(misc);

#endif /* _AR6000_H_ */
