/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
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

/*
 * This file contains the definitions of the WMI protocol specified in the
 * Wireless Module Interface (WMI).  It includes definitions of all the
 * commands and events. Commands are messages from the host to the WM.
 * Events and Replies are messages from the WM to the host.
 */

#ifndef _WMI_H_
#define _WMI_H_

#include <linux/ieee80211.h>

#define HTC_PROTOCOL_VERSION    	0x0002
#define WMI_PROTOCOL_VERSION    	0x0002
#define WMI_CONTROL_MSG_MAX_LEN     	   256
#define IS_ETHERTYPE(_typeOrLen)        ((_typeOrLen) >= 0x0600)

#define IP_ETHERTYPE 0x0800

#define WMI_IMPLICIT_PSTREAM 0xFF
#define WMI_MAX_THINSTREAM 15

#define IBSS_MAX_NUM_STA          8

#define SSID_IE_LEN_INDEX 13

/* Host side link management data structures */
#define SIGNAL_QUALITY_THRESHOLD_LEVELS 6
#define SIGNAL_QUALITY_UPPER_THRESHOLD_LEVELS SIGNAL_QUALITY_THRESHOLD_LEVELS
#define SIGNAL_QUALITY_LOWER_THRESHOLD_LEVELS SIGNAL_QUALITY_THRESHOLD_LEVELS

#define A_BAND_24GHZ           0
#define A_BAND_5GHZ            1
#define A_NUM_BANDS            2

#define WMI_IMPLICIT_PSTREAM_INACTIVITY_INT 5000 /* 5 seconds */

struct sq_threshold_params_s {
	s16 upper_threshold[SIGNAL_QUALITY_UPPER_THRESHOLD_LEVELS];
	s16 lower_threshold[SIGNAL_QUALITY_LOWER_THRESHOLD_LEVELS];
	u32 upper_threshold_valid_count;
	u32 lower_threshold_valid_count;
	u32 polling_interval;
	u8 weight;
	u8 last_rssi;
	u8 last_rssi_poll_event;
};

struct wmi_stats {
	u32 cmd_len_err;
	u32 cmd_id_err;
};

struct wmi_t {
	bool                          wmi_ready;
	bool                          wmi_numQoSStream;
	u16 wmi_streamExistsForAC[WMM_NUM_AC];
	u8 wmi_fatPipeExists;
	void                           *wmi_devt;
	struct wmi_stats                wmi_stats;
	struct ieee80211_node_table     wmi_scan_table;
	u8 wmi_bssid[ETH_ALEN];
	u8 wmi_powerMode;
	u8 wmi_phyMode;
	u8 wmi_keepaliveInterval;
	spinlock_t                      wmi_lock;
	enum htc_endpoint_id                 wmi_endpoint_id;
	struct sq_threshold_params_s             wmi_SqThresholdParams[SIGNAL_QUALITY_METRICS_NUM_MAX];
	enum crypto_type                     wmi_pair_crypto_type;
	enum crypto_type                     wmi_grp_crypto_type;
	bool                          wmi_is_wmm_enabled;
	u8 wmi_ht_allowed[A_NUM_BANDS];
	u8 wmi_traffic_class;
};

struct host_app_area_s {
    u32 wmi_protocol_ver;
} __attribute__ ((packed));

enum wmi_msg_type {
    DATA_MSGTYPE = 0x0,
    CNTL_MSGTYPE,
    SYNC_MSGTYPE,
    OPT_MSGTYPE,
};


/*
 * Macros for operating on WMI_DATA_HDR (info) field
 */

#define WMI_DATA_HDR_MSG_TYPE_MASK  0x03
#define WMI_DATA_HDR_MSG_TYPE_SHIFT 0
#define WMI_DATA_HDR_UP_MASK        0x07
#define WMI_DATA_HDR_UP_SHIFT       2
/* In AP mode, the same bit (b5) is used to indicate Power save state in
 * the Rx dir and More data bit state in the tx direction.
 */
#define WMI_DATA_HDR_PS_MASK        0x1
#define WMI_DATA_HDR_PS_SHIFT       5

#define WMI_DATA_HDR_MORE_MASK      0x1
#define WMI_DATA_HDR_MORE_SHIFT     5

enum wmi_data_hdr_data_type {
    WMI_DATA_HDR_DATA_TYPE_802_3 = 0,
    WMI_DATA_HDR_DATA_TYPE_802_11,
    WMI_DATA_HDR_DATA_TYPE_ACL, /* used to be used for the PAL */
};

#define WMI_DATA_HDR_DATA_TYPE_MASK     0x3
#define WMI_DATA_HDR_DATA_TYPE_SHIFT    6

#define WMI_DATA_HDR_SET_MORE_BIT(h) ((h)->info |= (WMI_DATA_HDR_MORE_MASK << WMI_DATA_HDR_MORE_SHIFT))

#define WMI_DATA_HDR_IS_MSG_TYPE(h, t)  (((h)->info & (WMI_DATA_HDR_MSG_TYPE_MASK)) == (t))
#define WMI_DATA_HDR_SET_MSG_TYPE(h, t) (h)->info = (((h)->info & ~(WMI_DATA_HDR_MSG_TYPE_MASK << WMI_DATA_HDR_MSG_TYPE_SHIFT)) | (t << WMI_DATA_HDR_MSG_TYPE_SHIFT))
#define WMI_DATA_HDR_GET_UP(h)    (((h)->info >> WMI_DATA_HDR_UP_SHIFT) & WMI_DATA_HDR_UP_MASK)
#define WMI_DATA_HDR_SET_UP(h, p) (h)->info = (((h)->info & ~(WMI_DATA_HDR_UP_MASK << WMI_DATA_HDR_UP_SHIFT)) | (p << WMI_DATA_HDR_UP_SHIFT))

#define WMI_DATA_HDR_GET_DATA_TYPE(h)   (((h)->info >> WMI_DATA_HDR_DATA_TYPE_SHIFT) & WMI_DATA_HDR_DATA_TYPE_MASK)
#define WMI_DATA_HDR_SET_DATA_TYPE(h, p) (h)->info = (((h)->info & ~(WMI_DATA_HDR_DATA_TYPE_MASK << WMI_DATA_HDR_DATA_TYPE_SHIFT)) | ((p) << WMI_DATA_HDR_DATA_TYPE_SHIFT))

#define WMI_DATA_HDR_GET_DOT11(h)   (WMI_DATA_HDR_GET_DATA_TYPE((h)) == WMI_DATA_HDR_DATA_TYPE_802_11)

/* Macros for operating on WMI_DATA_HDR (info2) field */
#define WMI_DATA_HDR_SEQNO_MASK     0xFFF
#define WMI_DATA_HDR_SEQNO_SHIFT    0

#define WMI_DATA_HDR_AMSDU_MASK     0x1
#define WMI_DATA_HDR_AMSDU_SHIFT    12

#define WMI_DATA_HDR_META_MASK      0x7
#define WMI_DATA_HDR_META_SHIFT     13

#define GET_SEQ_NO(_v)                  ((_v) & WMI_DATA_HDR_SEQNO_MASK)
#define GET_ISMSDU(_v)                  ((_v) & WMI_DATA_HDR_AMSDU_MASK)

#define WMI_DATA_HDR_GET_SEQNO(h)        GET_SEQ_NO((h)->info2 >> WMI_DATA_HDR_SEQNO_SHIFT)
#define WMI_DATA_HDR_SET_SEQNO(h, _v)   ((h)->info2 = ((h)->info2 & ~(WMI_DATA_HDR_SEQNO_MASK << WMI_DATA_HDR_SEQNO_SHIFT)) | (GET_SEQ_NO(_v) << WMI_DATA_HDR_SEQNO_SHIFT))

#define WMI_DATA_HDR_IS_AMSDU(h)        GET_ISMSDU((h)->info2 >> WMI_DATA_HDR_AMSDU_SHIFT)
#define WMI_DATA_HDR_SET_AMSDU(h, _v)   ((h)->info2 = ((h)->info2 & ~(WMI_DATA_HDR_AMSDU_MASK << WMI_DATA_HDR_AMSDU_SHIFT)) | (GET_ISMSDU(_v) << WMI_DATA_HDR_AMSDU_SHIFT))

#define WMI_DATA_HDR_GET_META(h)        (((h)->info2 >> WMI_DATA_HDR_META_SHIFT) & WMI_DATA_HDR_META_MASK)
#define WMI_DATA_HDR_SET_META(h, _v)    ((h)->info2 = ((h)->info2 & ~(WMI_DATA_HDR_META_MASK << WMI_DATA_HDR_META_SHIFT)) | ((_v) << WMI_DATA_HDR_META_SHIFT))

struct wmi_data_hdr {
    s8 rssi;
    u8 info;               /* usage of 'info' field(8-bit):
                                     *  b1:b0       - WMI_MSG_TYPE
                                     *  b4:b3:b2    - UP(tid)
                                     *  b5          - Used in AP mode. More-data in tx dir, PS in rx.
                                     *  b7:b6       -  Dot3 header(0),
                                     *                 Dot11 Header(1),
                                     *                 ACL data(2)
                                     */

    u16 info2;              /* usage of 'info2' field(16-bit):
                                     * b11:b0       - seq_no
                                     * b12          - A-MSDU?
                                     * b15:b13      - META_DATA_VERSION 0 - 7
                                     */
    u16 info3;
} __attribute__ ((packed));

/*
 *  TX META VERSION DEFINITIONS
 */
#define WMI_MAX_TX_META_SZ  (12)
#define WMI_MAX_TX_META_VERSION (7)
#define WMI_META_VERSION_1 (0x01)
#define WMI_META_VERSION_2 (0X02)

struct wmi_tx_meta_v1 {
    u8 pktID;           /* The packet ID to identify the tx request */
    u8 ratePolicyID;    /* The rate policy to be used for the tx of this frame */
} __attribute__ ((packed));

struct wmi_tx_meta_v2 {
    u8 csumStart;       /*Offset from start of the WMI header for csum calculation to begin */
    u8 csumDest;        /*Offset from start of WMI header where final csum goes*/
    u8 csumFlags;    /*number of bytes over which csum is calculated*/
} __attribute__ ((packed));

struct wmi_rx_meta_v1 {
    u8 status; /* one of WMI_RX_STATUS_... */
    u8 rix;    /* rate index mapped to rate at which this packet was received. */
    u8 rssi;   /* rssi of packet */
    u8 channel;/* rf channel during packet reception */
    u16 flags;  /* a combination of WMI_RX_FLAGS_... */
} __attribute__ ((packed));

struct wmi_rx_meta_v2 {
    u16 csum;
    u8 csumFlags;/* bit 0 set -partial csum valid
                             bit 1 set -test mode */
} __attribute__ ((packed));

/* Control Path */
struct wmi_cmd_hdr {
    u16 commandId;
/*
 * info1 - 16 bits
 * b03:b00 - id
 * b15:b04 - unused
 */
    u16 info1;

    u16 reserved;      /* For alignment */
} __attribute__ ((packed));        /* used for commands and events */

/*
 * List of Commnands
 */
enum wmi_cmd_id {
    WMI_CONNECT_CMDID           = 0x0001,
    WMI_RECONNECT_CMDID,
    WMI_DISCONNECT_CMDID,
    WMI_SYNCHRONIZE_CMDID,
    WMI_CREATE_PSTREAM_CMDID,
    WMI_DELETE_PSTREAM_CMDID,
    WMI_START_SCAN_CMDID,
    WMI_SET_SCAN_PARAMS_CMDID,
    WMI_SET_BSS_FILTER_CMDID,
    WMI_SET_PROBED_SSID_CMDID,               /* 10 */
    WMI_SET_LISTEN_INT_CMDID,
    WMI_SET_BMISS_TIME_CMDID,
    WMI_SET_DISC_TIMEOUT_CMDID,
    WMI_GET_CHANNEL_LIST_CMDID,
    WMI_SET_BEACON_INT_CMDID,
    WMI_GET_STATISTICS_CMDID,
    WMI_SET_CHANNEL_PARAMS_CMDID,
    WMI_SET_POWER_MODE_CMDID,
    WMI_SET_IBSS_PM_CAPS_CMDID,
    WMI_SET_POWER_PARAMS_CMDID,              /* 20 */
    WMI_SET_POWERSAVE_TIMERS_POLICY_CMDID,
    WMI_ADD_CIPHER_KEY_CMDID,
    WMI_DELETE_CIPHER_KEY_CMDID,
    WMI_ADD_KRK_CMDID,
    WMI_DELETE_KRK_CMDID,
    WMI_SET_PMKID_CMDID,
    WMI_SET_TX_PWR_CMDID,
    WMI_GET_TX_PWR_CMDID,
    WMI_SET_ASSOC_INFO_CMDID,
    WMI_ADD_BAD_AP_CMDID,                    /* 30 */
    WMI_DELETE_BAD_AP_CMDID,
    WMI_SET_TKIP_COUNTERMEASURES_CMDID,
    WMI_RSSI_THRESHOLD_PARAMS_CMDID,
    WMI_TARGET_ERROR_REPORT_BITMASK_CMDID,
    WMI_SET_ACCESS_PARAMS_CMDID,
    WMI_SET_RETRY_LIMITS_CMDID,
    WMI_SET_OPT_MODE_CMDID,
    WMI_OPT_TX_FRAME_CMDID,
    WMI_SET_VOICE_PKT_SIZE_CMDID,
    WMI_SET_MAX_SP_LEN_CMDID,                /* 40 */
    WMI_SET_ROAM_CTRL_CMDID,
    WMI_GET_ROAM_TBL_CMDID,
    WMI_GET_ROAM_DATA_CMDID,
    WMI_ENABLE_RM_CMDID,
    WMI_SET_MAX_OFFHOME_DURATION_CMDID,
    WMI_EXTENSION_CMDID,                        /* Non-wireless extensions */
    WMI_SNR_THRESHOLD_PARAMS_CMDID,
    WMI_LQ_THRESHOLD_PARAMS_CMDID,
    WMI_SET_LPREAMBLE_CMDID,
    WMI_SET_RTS_CMDID,                       /* 50 */
    WMI_CLR_RSSI_SNR_CMDID,
    WMI_SET_FIXRATES_CMDID,
    WMI_GET_FIXRATES_CMDID,
    WMI_SET_AUTH_MODE_CMDID,
    WMI_SET_REASSOC_MODE_CMDID,
    WMI_SET_WMM_CMDID,
    WMI_SET_WMM_TXOP_CMDID,
    WMI_TEST_CMDID,
    /* COEX AR6002 only*/
    WMI_SET_BT_STATUS_CMDID,                
    WMI_SET_BT_PARAMS_CMDID,                /* 60 */

    WMI_SET_KEEPALIVE_CMDID,
    WMI_GET_KEEPALIVE_CMDID,
    WMI_SET_APPIE_CMDID,
    WMI_GET_APPIE_CMDID,
    WMI_SET_WSC_STATUS_CMDID,

    /* Wake on Wireless */
    WMI_SET_HOST_SLEEP_MODE_CMDID,
    WMI_SET_WOW_MODE_CMDID,
    WMI_GET_WOW_LIST_CMDID,
    WMI_ADD_WOW_PATTERN_CMDID,
    WMI_DEL_WOW_PATTERN_CMDID,               /* 70 */

    WMI_SET_FRAMERATES_CMDID,
    WMI_SET_AP_PS_CMDID,
    WMI_SET_QOS_SUPP_CMDID,
    /* WMI_THIN_RESERVED_... mark the start and end
     * values for WMI_THIN_RESERVED command IDs. These
     * command IDs can be found in wmi_thin.h */
    WMI_THIN_RESERVED_START = 0x8000,
    WMI_THIN_RESERVED_END = 0x8fff,
    /*
     * Developer commands starts at 0xF000
     */
    WMI_SET_BITRATE_CMDID = 0xF000,
    WMI_GET_BITRATE_CMDID,
    WMI_SET_WHALPARAM_CMDID,


    /*Should add the new command to the tail for compatible with
     * etna.
     */
    WMI_SET_MAC_ADDRESS_CMDID,
    WMI_SET_AKMP_PARAMS_CMDID,
    WMI_SET_PMKID_LIST_CMDID,
    WMI_GET_PMKID_LIST_CMDID,
    WMI_ABORT_SCAN_CMDID,
    WMI_SET_TARGET_EVENT_REPORT_CMDID,

    // Unused
    WMI_UNUSED1,
    WMI_UNUSED2,

    /*
     * AP mode commands
     */
    WMI_AP_HIDDEN_SSID_CMDID,
    WMI_AP_SET_NUM_STA_CMDID,
    WMI_AP_ACL_POLICY_CMDID,
    WMI_AP_ACL_MAC_LIST_CMDID,
    WMI_AP_CONFIG_COMMIT_CMDID,
    WMI_AP_SET_MLME_CMDID,
    WMI_AP_SET_PVB_CMDID,
    WMI_AP_CONN_INACT_CMDID,
    WMI_AP_PROT_SCAN_TIME_CMDID,
    WMI_AP_SET_COUNTRY_CMDID,
    WMI_AP_SET_DTIM_CMDID,
    WMI_AP_MODE_STAT_CMDID,

    WMI_SET_IP_CMDID,
    WMI_SET_PARAMS_CMDID,
    WMI_SET_MCAST_FILTER_CMDID,
    WMI_DEL_MCAST_FILTER_CMDID,

    WMI_ALLOW_AGGR_CMDID,
    WMI_ADDBA_REQ_CMDID,
    WMI_DELBA_REQ_CMDID,
    WMI_SET_HT_CAP_CMDID,
    WMI_SET_HT_OP_CMDID,
    WMI_SET_TX_SELECT_RATES_CMDID,
    WMI_SET_TX_SGI_PARAM_CMDID,
    WMI_SET_RATE_POLICY_CMDID,

    WMI_HCI_CMD_CMDID,
    WMI_RX_FRAME_FORMAT_CMDID,
    WMI_SET_THIN_MODE_CMDID,
    WMI_SET_BT_WLAN_CONN_PRECEDENCE_CMDID,

    WMI_AP_SET_11BG_RATESET_CMDID,
    WMI_SET_PMK_CMDID,
    WMI_MCAST_FILTER_CMDID,
    /* COEX CMDID AR6003*/
    WMI_SET_BTCOEX_FE_ANT_CMDID,
    WMI_SET_BTCOEX_COLOCATED_BT_DEV_CMDID,
    WMI_SET_BTCOEX_SCO_CONFIG_CMDID,
    WMI_SET_BTCOEX_A2DP_CONFIG_CMDID,
    WMI_SET_BTCOEX_ACLCOEX_CONFIG_CMDID,
    WMI_SET_BTCOEX_BTINQUIRY_PAGE_CONFIG_CMDID,
    WMI_SET_BTCOEX_DEBUG_CMDID,
    WMI_SET_BTCOEX_BT_OPERATING_STATUS_CMDID,
    WMI_GET_BTCOEX_STATS_CMDID,
    WMI_GET_BTCOEX_CONFIG_CMDID,

	WMI_SET_DFS_ENABLE_CMDID,   /* F034 */
	WMI_SET_DFS_MINRSSITHRESH_CMDID,
	WMI_SET_DFS_MAXPULSEDUR_CMDID,
	WMI_DFS_RADAR_DETECTED_CMDID,

	/* P2P CMDS */
	WMI_P2P_SET_CONFIG_CMDID,    /* F038 */
	WMI_WPS_SET_CONFIG_CMDID,
	WMI_SET_REQ_DEV_ATTR_CMDID,
	WMI_P2P_FIND_CMDID,
	WMI_P2P_STOP_FIND_CMDID,
	WMI_P2P_GO_NEG_START_CMDID,
	WMI_P2P_LISTEN_CMDID,

	WMI_CONFIG_TX_MAC_RULES_CMDID,    /* F040 */
	WMI_SET_PROMISCUOUS_MODE_CMDID,
	WMI_RX_FRAME_FILTER_CMDID,
	WMI_SET_CHANNEL_CMDID,

	/* WAC commands */
	WMI_ENABLE_WAC_CMDID,
	WMI_WAC_SCAN_REPLY_CMDID,
	WMI_WAC_CTRL_REQ_CMDID,
	WMI_SET_DIV_PARAMS_CMDID,

	WMI_GET_PMK_CMDID,
	WMI_SET_PASSPHRASE_CMDID,
	WMI_SEND_ASSOC_RES_CMDID,
	WMI_SET_ASSOC_REQ_RELAY_CMDID,
	WMI_GET_RFKILL_MODE_CMDID,

	/* ACS command, consists of sub-commands */
	WMI_ACS_CTRL_CMDID,

	/* Ultra low power store / recall commands */
	WMI_STORERECALL_CONFIGURE_CMDID,
	WMI_STORERECALL_RECALL_CMDID,
	WMI_STORERECALL_HOST_READY_CMDID,
	WMI_FORCE_TARGET_ASSERT_CMDID,
	WMI_SET_EXCESS_TX_RETRY_THRES_CMDID,
};

/*
 * Connect Command
 */
enum network_type {
    INFRA_NETWORK       = 0x01,
    ADHOC_NETWORK       = 0x02,
    ADHOC_CREATOR       = 0x04,
    AP_NETWORK          = 0x10,
};

enum dot11_auth_mode {
    OPEN_AUTH           = 0x01,
    SHARED_AUTH         = 0x02,
    LEAP_AUTH           = 0x04,  /* different from IEEE_AUTH_MODE definitions */
};

enum {
	AUTH_IDLE,
	AUTH_OPEN_IN_PROGRESS,
};

enum auth_mode {
    NONE_AUTH           = 0x01,
    WPA_AUTH            = 0x02,
    WPA2_AUTH           = 0x04,
    WPA_PSK_AUTH        = 0x08,
    WPA2_PSK_AUTH       = 0x10,
    WPA_AUTH_CCKM       = 0x20,
    WPA2_AUTH_CCKM      = 0x40,
};

#define WMI_MIN_CRYPTO_TYPE NONE_CRYPT
#define WMI_MAX_CRYPTO_TYPE (AES_CRYPT + 1)

#ifdef WAPI_ENABLE
#undef WMI_MAX_CRYPTO_TYPE
#define WMI_MAX_CRYPTO_TYPE (WAPI_CRYPT + 1)
#endif /* WAPI_ENABLE */

#ifdef WAPI_ENABLE
#define IW_ENCODE_ALG_SM4       0x20
#define IW_AUTH_WAPI_ENABLED    0x20
#endif

#define WMI_MIN_KEY_INDEX   0
#define WMI_MAX_KEY_INDEX   3

#ifdef WAPI_ENABLE
#undef WMI_MAX_KEY_INDEX
#define WMI_MAX_KEY_INDEX   7 /* wapi grpKey 0-3, prwKey 4-7 */
#endif /* WAPI_ENABLE */

#define WMI_MAX_KEY_LEN     32

enum wmi_connect_ctrl_flags_bits {
    CONNECT_ASSOC_POLICY_USER           = 0x0001,
    CONNECT_SEND_REASSOC                = 0x0002,
    CONNECT_IGNORE_WPAx_GROUP_CIPHER    = 0x0004,
    CONNECT_PROFILE_MATCH_DONE          = 0x0008,
    CONNECT_IGNORE_AAC_BEACON           = 0x0010,
    CONNECT_CSA_FOLLOW_BSS              = 0x0020,
    CONNECT_DO_WPA_OFFLOAD              = 0x0040,
    CONNECT_DO_NOT_DEAUTH               = 0x0080,
};

struct wmi_connect_cmd {
    u8 networkType;
    u8 dot11AuthMode;
    u8 authMode;
    u8 pairwiseCryptoType;
    u8 pairwiseCryptoLen;
    u8 groupCryptoType;
    u8 groupCryptoLen;
    u8 ssidLength;
    u8     ssid[IEEE80211_MAX_SSID_LEN];
    u16 channel;
    u8 bssid[ETH_ALEN];
    u32 ctrl_flags;
} __attribute__ ((packed));

/*
 * WMI_RECONNECT_CMDID
 */
struct wmi_reconnect_cmd {
    u16 channel;                    /* hint */
    u8 bssid[ETH_ALEN];         /* mandatory if set */
} __attribute__ ((packed));

/*
 * WMI_ADD_CIPHER_KEY_CMDID
 */
enum key_usage {
    PAIRWISE_USAGE      = 0x00,
    GROUP_USAGE         = 0x01,
    TX_USAGE            = 0x02,     /* default Tx Key - Static WEP only */
};

/*
 * Bit Flag
 * Bit 0 - Initialise TSC - default is Initialize
 */
#define KEY_OP_INIT_TSC       0x01
#define KEY_OP_INIT_RSC       0x02
#ifdef WAPI_ENABLE
#define KEY_OP_INIT_WAPIPN    0x10
#endif /* WAPI_ENABLE */

#define KEY_OP_INIT_VAL     0x03     /* Default Initialise the TSC & RSC */
#define KEY_OP_VALID_MASK   0x03

struct wmi_add_cipher_key_cmd {
    u8 keyIndex;
    u8 keyType;
    u8 keyUsage;           /* enum key_usage */
    u8 keyLength;
    u8 keyRSC[8];          /* key replay sequence counter */
    u8 key[WLAN_MAX_KEY_LEN];
    u8 key_op_ctrl;       /* Additional Key Control information */
    u8 key_macaddr[ETH_ALEN];
} __attribute__ ((packed));

/*
 * WMI_DELETE_CIPHER_KEY_CMDID
 */
struct wmi_delete_cipher_key_cmd {
    u8 keyIndex;
} __attribute__ ((packed));

#define WMI_KRK_LEN     16
/*
 * WMI_ADD_KRK_CMDID
 */
struct wmi_add_krk_cmd {
    u8 krk[WMI_KRK_LEN];
} __attribute__ ((packed));

#define WMI_PMKID_LEN 16

/*
 * WMI_START_SCAN_CMD
 */
enum wmi_scan_type {
    WMI_LONG_SCAN  = 0,
    WMI_SHORT_SCAN = 1,
};

struct wmi_start_scan_cmd {
    u32   forceFgScan;
    u32   isLegacy;        /* For Legacy Cisco AP compatibility */
    u32 homeDwellTime;   /* Maximum duration in the home channel(milliseconds) */
    u32 forceScanInterval;    /* Time interval between scans (milliseconds)*/
    u8 scanType;           /* WMI_SCAN_TYPE */
    u8 numChannels;            /* how many channels follow */
    u16 channelList[1];         /* channels in Mhz */
} __attribute__ ((packed));

/*
 * WMI_SET_SCAN_PARAMS_CMDID
 */
#define WMI_SHORTSCANRATIO_DEFAULT      3
/* 
 *  Warning: ScanCtrlFlag value of 0xFF is used to disable all flags in WMI_SCAN_PARAMS_CMD 
 *  Do not add any more flags to WMI_SCAN_CTRL_FLAG_BITS
 */
enum wmi_scan_ctrl_flags_bits {
    CONNECT_SCAN_CTRL_FLAGS = 0x01,    /* set if can scan in the Connect cmd */
    SCAN_CONNECTED_CTRL_FLAGS = 0x02,  /* set if scan for the SSID it is */
                                       /* already connected to */
    ACTIVE_SCAN_CTRL_FLAGS = 0x04,     /* set if enable active scan */
    ROAM_SCAN_CTRL_FLAGS = 0x08,       /* set if enable roam scan when bmiss and lowrssi */
    REPORT_BSSINFO_CTRL_FLAGS = 0x10,   /* set if follows customer BSSINFO reporting rule */
    ENABLE_AUTO_CTRL_FLAGS = 0x20,      /* if disabled, target doesn't
                                          scan after a disconnect event  */
    ENABLE_SCAN_ABORT_EVENT = 0x40      /* Scan complete event with canceled status will be generated when a scan is prempted before it gets completed */
};

#define DEFAULT_SCAN_CTRL_FLAGS         (CONNECT_SCAN_CTRL_FLAGS| SCAN_CONNECTED_CTRL_FLAGS| ACTIVE_SCAN_CTRL_FLAGS| ROAM_SCAN_CTRL_FLAGS | ENABLE_AUTO_CTRL_FLAGS)

struct wmi_scan_params_cmd {
    u16 fg_start_period;        /* seconds */
    u16 fg_end_period;          /* seconds */
    u16 bg_period;              /* seconds */
    u16 maxact_chdwell_time;    /* msec */
    u16 pas_chdwell_time;       /* msec */
    u8 shortScanRatio;         /* how many shorts scan for one long */
    u8 scanCtrlFlags;
    u16 minact_chdwell_time;    /* msec */
    u16 maxact_scan_per_ssid;   /* max active scans per ssid */
    u32 max_dfsch_act_time;  /* msecs */
} __attribute__ ((packed));

/*
 * WMI_SET_BSS_FILTER_CMDID
 */
enum wmi_bss_filter {
    NONE_BSS_FILTER = 0x0,              /* no beacons forwarded */
    ALL_BSS_FILTER,                     /* all beacons forwarded */
    PROFILE_FILTER,                     /* only beacons matching profile */
    ALL_BUT_PROFILE_FILTER,             /* all but beacons matching profile */
    CURRENT_BSS_FILTER,                 /* only beacons matching current BSS */
    ALL_BUT_BSS_FILTER,                 /* all but beacons matching BSS */
    PROBED_SSID_FILTER,                 /* beacons matching probed ssid */
    LAST_BSS_FILTER,                    /* marker only */
};

struct wmi_bss_filter_cmd {
    u8 bssFilter;                      /* see WMI_BSS_FILTER */
    u8 reserved1;                      /* For alignment */
    u16 reserved2;                      /* For alignment */
    u32 ieMask;
} __attribute__ ((packed));

/*
 * WMI_SET_PROBED_SSID_CMDID
 */
#define MAX_PROBED_SSID_INDEX   9

enum wmi_ssid_flag {
    DISABLE_SSID_FLAG  = 0,                  /* disables entry */
    SPECIFIC_SSID_FLAG = 0x01,               /* probes specified ssid */
    ANY_SSID_FLAG      = 0x02,               /* probes for any ssid */
};

struct wmi_probed_ssid_cmd {
    u8 entryIndex;                     /* 0 to MAX_PROBED_SSID_INDEX */
    u8 flag;                           /* WMI_SSID_FLG */
    u8 ssidLength;
    u8 ssid[32];
} __attribute__ ((packed));

/*
 * WMI_SET_LISTEN_INT_CMDID
 * The Listen interval is between 15 and 3000 TUs
 */

struct wmi_listen_int_cmd {
    u16 listenInterval;
    u16 numBeacons;
} __attribute__ ((packed));

/*
 * WMI_SET_POWER_MODE_CMDID
 */
enum wmi_power_mode {
    REC_POWER = 0x01,
    MAX_PERF_POWER,
};

struct wmi_power_mode_cmd {
    u8 powerMode;      /* WMI_POWER_MODE */
} __attribute__ ((packed));

struct wmi_set_params_reply {
    s8 status;      /* WMI_SET_PARAMS_REPLY */
} __attribute__ ((packed));

/*
 * Policy to determnine whether power save failure event should be sent to
 * host during scanning
 */
enum power_save_fail_event_policy {
    SEND_POWER_SAVE_FAIL_EVENT_ALWAYS = 1,
    IGNORE_POWER_SAVE_FAIL_EVENT_DURING_SCAN = 2,
};

struct wmi_power_params_cmd {
    u16 idle_period;             /* msec */
    u16 pspoll_number;
    u16 dtim_policy;
    u16 tx_wakeup_policy;
    u16 num_tx_to_wakeup;
    u16 ps_fail_event_policy;
} __attribute__ ((packed));

/*
 * WMI_SET_DISC_TIMEOUT_CMDID
 */
struct wmi_disc_timeout_cmd {
    u8 disconnectTimeout;          /* seconds */
} __attribute__ ((packed));

enum dir_type {
    UPLINK_TRAFFIC = 0,
    DNLINK_TRAFFIC = 1,
    BIDIR_TRAFFIC = 2,
};

enum voiceps_cap_type {
    DISABLE_FOR_THIS_AC = 0,
    ENABLE_FOR_THIS_AC  = 1,
    ENABLE_FOR_ALL_AC   = 2,
};

enum traffic_type {
    TRAFFIC_TYPE_APERIODIC = 0,
    TRAFFIC_TYPE_PERIODIC = 1,
};

/*
 * WMI_SYNCHRONIZE_CMDID
 */
struct wmi_sync_cmd {
    u8 dataSyncMap;
} __attribute__ ((packed));

/*
 * WMI_CREATE_PSTREAM_CMDID
 */
struct wmi_create_pstream_cmd {
    u32 minServiceInt;           /* in milli-sec */
    u32 maxServiceInt;           /* in milli-sec */
    u32 inactivityInt;           /* in milli-sec */
    u32 suspensionInt;           /* in milli-sec */
    u32 serviceStartTime;
    u32 minDataRate;             /* in bps */
    u32 meanDataRate;            /* in bps */
    u32 peakDataRate;            /* in bps */
    u32 maxBurstSize;
    u32 delayBound;
    u32 minPhyRate;              /* in bps */
    u32 sba;
    u32 mediumTime;
    u16 nominalMSDU;             /* in octects */
    u16 maxMSDU;                 /* in octects */
    u8 trafficClass;
    u8 trafficDirection;        /* DIR_TYPE */
    u8 rxQueueNum;
    u8 trafficType;             /* TRAFFIC_TYPE */
    u8 voicePSCapability;       /* VOICEPS_CAP_TYPE */
    u8 tsid;
    u8 userPriority;            /* 802.1D user priority */
    u8 nominalPHY;              /* nominal phy rate */
} __attribute__ ((packed));

/*
 * WMI_DELETE_PSTREAM_CMDID
 */
struct wmi_delete_pstream_cmd {
    u8 txQueueNumber;
    u8 rxQueueNumber;
    u8 trafficDirection;
    u8 trafficClass;
    u8 tsid;
} __attribute__ ((packed));

/*
 * WMI_SET_CHANNEL_PARAMS_CMDID
 */
enum wmi_phy_mode {
    WMI_11A_MODE  = 0x1,
    WMI_11G_MODE  = 0x2,
    WMI_11AG_MODE = 0x3,
    WMI_11B_MODE  = 0x4,
    WMI_11GONLY_MODE = 0x5,    
};

#define WMI_MAX_CHANNELS        32

/*
 *  WMI_RSSI_THRESHOLD_PARAMS_CMDID
 *  Setting the polltime to 0 would disable polling.
 *  Threshold values are in the ascending order, and should agree to:
 *  (lowThreshold_lowerVal < lowThreshold_upperVal < highThreshold_lowerVal
 *      < highThreshold_upperVal)
 */

struct wmi_rssi_threshold_params_cmd {
    u32 pollTime;               /* Polling time as a factor of LI */
    s16 thresholdAbove1_Val;          /* lowest of upper */
    s16 thresholdAbove2_Val;
    s16 thresholdAbove3_Val;
    s16 thresholdAbove4_Val;
    s16 thresholdAbove5_Val;
    s16 thresholdAbove6_Val;          /* highest of upper */
    s16 thresholdBelow1_Val;         /* lowest of bellow */
    s16 thresholdBelow2_Val;
    s16 thresholdBelow3_Val;
    s16 thresholdBelow4_Val;
    s16 thresholdBelow5_Val;
    s16 thresholdBelow6_Val;         /* highest of bellow */
    u8 weight;                  /* "alpha" */
    u8 reserved[3];
} __attribute__ ((packed))  ;

/*
 *  WMI_SNR_THRESHOLD_PARAMS_CMDID
 *  Setting the polltime to 0 would disable polling.
 */

struct wmi_snr_threshold_params_cmd{
    u32 pollTime;               /* Polling time as a factor of LI */
    u8 weight;                  /* "alpha" */
    u8 thresholdAbove1_Val;      /* lowest of uppper*/
    u8 thresholdAbove2_Val;
    u8 thresholdAbove3_Val;
    u8 thresholdAbove4_Val;      /* highest of upper */
    u8 thresholdBelow1_Val;     /* lowest of bellow */
    u8 thresholdBelow2_Val;
    u8 thresholdBelow3_Val;
    u8 thresholdBelow4_Val;     /* highest of bellow */
    u8 reserved[3];
} __attribute__ ((packed));

enum wmi_preamble_policy {
    WMI_IGNORE_BARKER_IN_ERP = 0,
    WMI_DONOT_IGNORE_BARKER_IN_ERP
};

struct wmi_set_lpreamble_cmd {
    u8 status;
    u8 preamblePolicy;
}__attribute__ ((packed));

struct wmi_set_rts_cmd {
    u16 threshold;
}__attribute__ ((packed));

/*
 * WMI_SET_TX_PWR_CMDID
 */
struct wmi_set_tx_pwr_cmd {
    u8 dbM;                  /* in dbM units */
} __attribute__ ((packed));

struct wmi_tx_pwr_reply {
    u8 dbM;                  /* in dbM units */
} __attribute__ ((packed));

/*-----------------------AR6003 BTCOEX -----------------------------------*/

/*  ---------------WMI_SET_BTCOEX_FE_ANT_CMDID --------------------------*/
/* Indicates front end antenna configuration. This command needs to be issued
 * right after initialization and after WMI_SET_BTCOEX_COLOCATED_BT_DEV_CMDID.
 * AR6003 enables coexistence and antenna switching based on the configuration.
 */
struct wmi_set_btcoex_fe_ant_cmd {
	u8 btcoexFeAntType; /* 1 - WMI_BTCOEX_FE_ANT_SINGLE for single antenna front end
                                2 - WMI_BTCOEX_FE_ANT_DUAL for dual antenna front end
                                    (for isolations less 35dB, for higher isolation there
                                    is not need to pass this command).
                                    (not implemented)
                              */
}__attribute__ ((packed));

/* -------------WMI_SET_BTCOEX_COLOCATED_BT_DEV_CMDID ----------------*/
/* Indicate the bluetooth chip to the firmware. Firmware can have different algorithm based
 * bluetooth chip type.Based on bluetooth device, different coexistence protocol would be used.
 */
struct wmi_set_btcoex_colocated_bt_dev_cmd {
	u8 btcoexCoLocatedBTdev; /*1 - Qcom BT (3 -wire PTA)
                                    2 - CSR BT  (3 wire PTA)
                                    3 - Atheros 3001 BT (3 wire PTA)
                                    4 - STE bluetooth (4-wire ePTA)
                                    5 - Atheros 3002 BT (4-wire MCI)
                                    defaults= 3 (Atheros 3001 BT )
                                    */
}__attribute__ ((packed));

/* -------------WMI_SET_BTCOEX_BTINQUIRY_PAGE_CONFIG_CMDID ------------*/
/* Configuration parameters during bluetooth inquiry and page. Page configuration
 * is applicable only on interfaces which can distinguish page (applicable only for ePTA -
 * STE bluetooth).
 * Bluetooth inquiry start and end is indicated via WMI_SET_BTCOEX_BT_OPERATING_STATUS_CMDID.
 * During this the station will be  power-save mode.
 */
struct wmi_set_btcoex_btinquiry_page_config_cmd {
	u32 btInquiryDataFetchFrequency;/* The frequency of querying the AP for data
                                            (via pspoll) is configured by this parameter.
                                            "default = 10 ms" */

	u32 protectBmissDurPostBtInquiry;/* The firmware will continue to be in inquiry state
                                             for configured duration, after inquiry completion
                                             . This is to ensure other bluetooth transactions
                                             (RDP, SDP profiles, link key exchange ...etc)
                                             goes through smoothly without wifi stomping.
                                             default = 10 secs*/

	u32 maxpageStomp;                 /*Applicable only for STE-BT interface. Currently not
                                             used */
	u32 btInquiryPageFlag;           /* Not used */
}__attribute__ ((packed));

/*---------------------WMI_SET_BTCOEX_SCO_CONFIG_CMDID ---------------*/
/* Configure  SCO parameters. These parameters would be used whenever firmware is indicated
 * of (e)SCO profile on bluetooth ( via WMI_SET_BTCOEX_BT_OPERATING_STATUS_CMDID).
 * Configration of BTCOEX_SCO_CONFIG data structure are common configuration and applies
 * ps-poll mode and opt mode.
 * Ps-poll Mode - Station is in power-save and retrieves downlink data between sco gaps.
 * Opt Mode - station is in awake state and access point can send data to station any time.
 * BTCOEX_PSPOLLMODE_SCO_CONFIG - Configuration applied only during ps-poll mode.
 * BTCOEX_OPTMODE_SCO_CONFIG - Configuration applied only during opt mode.
 */
struct btcoex_sco_config {
	u32 scoSlots;					/* Number of SCO Tx/Rx slots.
										   HVx, EV3, 2EV3 = 2 */
	u32 scoIdleSlots;				/* Number of Bluetooth idle slots between
										   consecutive SCO Tx/Rx slots
										   HVx, EV3 = 4
										   2EV3 = 10
                                         */
	u32 scoFlags;				   /* SCO Options Flags :
										  bits:	   meaning:
 										  0   Allow Close Range Optimization
 										  1   Is EDR capable or Not
 										  2   IS Co-located Bt role Master
                                          3   Firmware determines the periodicity of SCO.
							  			 */

    u32 linkId;                      /* applicable to STE-BT - not used */
}__attribute__ ((packed));

struct btcoex_pspollmode_sco_config {
	u32 scoCyclesForceTrigger;	/* Number SCO cycles after which
											force a pspoll. default = 10 */
    u32 scoDataResponseTimeout;	 /* Timeout Waiting for Downlink pkt
											in response for ps-poll,
											default = 20 msecs */

	u32 scoStompDutyCyleVal;		 /* not implemented */

	u32 scoStompDutyCyleMaxVal;     /*Not implemented */

	u32 scoPsPollLatencyFraction; 	 /* Fraction of idle
											period, within which
											additional ps-polls can be queued
                                            1 - 1/4 of idle duration
                                            2 - 1/2 of idle duration
                                            3 - 3/4 of idle duration
                                            default =2 (1/2)
                                           */
}__attribute__ ((packed));

struct btcoex_optmode_sco_config {
	u32 scoStompCntIn100ms;/*max number of SCO stomp in 100ms allowed in
                                   opt mode. If exceeds the configured value,
                                   switch to ps-poll mode
                                  default = 3 */

	u32 scoContStompMax;   /* max number of continuous stomp allowed in opt mode.
                                   if exceeded switch to pspoll mode
                                    default = 3 */

	u32 scoMinlowRateMbps; /* Low rate threshold */

	u32 scoLowRateCnt;     /* number of low rate pkts (< scoMinlowRateMbps) allowed in 100 ms.
                                   If exceeded switch/stay to ps-poll mode, lower stay in opt mode.
                                   default = 36
                                 */

	u32 scoHighPktRatio;   /*(Total Rx pkts in 100 ms + 1)/
                                  ((Total tx pkts in 100 ms - No of high rate pkts in 100 ms) + 1) in 100 ms,
                                  if exceeded switch/stay in opt mode and if lower switch/stay in  pspoll mode.
                                  default = 5 (80% of high rates)
                                 */

	u32 scoMaxAggrSize;    /* Max number of Rx subframes allowed in this mode. (Firmware re-negogiates
                                   max number of aggregates if it was negogiated to higher value
                                   default = 1
                                   Recommended value Basic rate headsets = 1, EDR (2-EV3)  =4.
                                 */
}__attribute__ ((packed));

struct btcoex_wlanscan_sco_config {
    u32 scanInterval;
    u32 maxScanStompCnt;
}__attribute__ ((packed));

struct wmi_set_btcoex_sco_config_cmd {
	struct btcoex_sco_config scoConfig;
	struct btcoex_pspollmode_sco_config scoPspollConfig;
	struct btcoex_optmode_sco_config scoOptModeConfig;
	struct btcoex_wlanscan_sco_config scoWlanScanConfig;
}__attribute__ ((packed));

/* ------------------WMI_SET_BTCOEX_A2DP_CONFIG_CMDID -------------------*/
/* Configure A2DP profile parameters. These parameters would be used whenver firmware is indicated
 * of A2DP profile on bluetooth ( via WMI_SET_BTCOEX_BT_OPERATING_STATUS_CMDID).
 * Configuration of BTCOEX_A2DP_CONFIG data structure are common configuration and applies to
 * ps-poll mode and opt mode.
 * Ps-poll Mode - Station is in power-save and retrieves downlink data between a2dp data bursts.
 * Opt Mode - station is in power save during a2dp bursts and awake in the gaps.
 * BTCOEX_PSPOLLMODE_A2DP_CONFIG - Configuration applied only during ps-poll mode.
 * BTCOEX_OPTMODE_A2DP_CONFIG - Configuration applied only during opt mode.
 */

struct btcoex_a2dp_config {
    u32 a2dpFlags;      /* A2DP Option flags:
		                        bits:    meaning:
               		            0       Allow Close Range Optimization
       	                     	1       IS EDR capable
       	                     	2       IS Co-located Bt role Master
                                3       a2dp traffic is high priority
                                4       Fw detect the role of bluetooth.
                             */
	u32 linkId;         /* Applicable only to STE-BT - not used */

}__attribute__ ((packed));

struct btcoex_pspollmode_a2dp_config {
    u32 a2dpWlanMaxDur; /* MAX time firmware uses the medium for
                      			wlan, after it identifies the idle time
                                default (30 msecs) */

    u32 a2dpMinBurstCnt;   /* Minimum number of bluetooth data frames
                  				to replenish Wlan Usage  limit (default 3) */

    u32 a2dpDataRespTimeout; /* Max duration firmware waits for downlink
                                     by stomping on  bluetooth
                                     after ps-poll is acknowledged.
                                     default = 20 ms
                                   */
}__attribute__ ((packed));

struct btcoex_optmode_a2dp_config {
	u32 a2dpMinlowRateMbps;  /* Low rate threshold */

	u32 a2dpLowRateCnt;    /* number of low rate pkts (< a2dpMinlowRateMbps) allowed in 100 ms.
                                   If exceeded switch/stay to ps-poll mode, lower stay in opt mode.
                                   default = 36
                                 */

	u32 a2dpHighPktRatio;   /*(Total Rx pkts in 100 ms + 1)/
                                  ((Total tx pkts in 100 ms - No of high rate pkts in 100 ms) + 1) in 100 ms,
                                  if exceeded switch/stay in opt mode and if lower switch/stay in  pspoll mode.
                                  default = 5 (80% of high rates)
                                 */

	u32 a2dpMaxAggrSize;    /* Max number of Rx subframes allowed in this mode. (Firmware re-negogiates
                                   max number of aggregates if it was negogiated to higher value
                                   default = 1
                                  Recommended value Basic rate headsets = 1, EDR (2-EV3)  =8.
                                 */
	u32 a2dpPktStompCnt;    /*number of a2dp pkts that can be stomped per burst.
                                   default = 6*/

}__attribute__ ((packed));

struct wmi_set_btcoex_a2dp_config_cmd {
	struct btcoex_a2dp_config a2dpConfig;
	struct btcoex_pspollmode_a2dp_config a2dppspollConfig;
	struct btcoex_optmode_a2dp_config a2dpOptConfig;
}__attribute__ ((packed));

/*------------ WMI_SET_BTCOEX_ACLCOEX_CONFIG_CMDID---------------------*/
/* Configure non-A2dp ACL profile parameters.The starts of ACL profile can either be
 * indicated via WMI_SET_BTCOEX_BT_OPERATING_STATUS_CMDID orenabled via firmware detection
 *  which is configured via "aclCoexFlags".
 * Configration of btcoex_aclcoex_config data structure are common configuration and applies
 * ps-poll mode and opt mode.
 * Ps-poll Mode - Station is in power-save and retrieves downlink data during wlan medium.
 * Opt Mode - station is in power save during bluetooth medium time and awake during wlan duration.
 *             (Not implemented yet)
 *
 * struct btcoex_pspollmode_aclcoex_config - Configuration applied only during ps-poll mode.
 * struct btcoex_optmode_aclcoex_config - Configuration applied only during opt mode.
 */

struct btcoex_aclcoex_config {
    u32 aclWlanMediumDur; 	    /* Wlan usage time during Acl (non-a2dp)
                     					coexistence (default 30 msecs)
                                    */

    u32 aclBtMediumDur; 	   /* Bt usage time during acl coexistence
					                     (default 30 msecs)
                                   */

	u32 aclDetectTimeout;	   /* BT activity observation time limit.
									  In this time duration, number of bt pkts are counted.
									  If the Cnt reaches "aclPktCntLowerLimit" value
									  for "aclIterToEnableCoex" iteration continuously,
									  firmware gets into ACL coexistence mode.
									  Similarly, if bt traffic count during ACL coexistence
									  has not reached "aclPktCntLowerLimit" continuously
									  for "aclIterToEnableCoex", then ACL coexistence is
									  disabled.
    								  -default 100 msecs
                                    */

	 u32 aclPktCntLowerLimit;   /* Acl Pkt Cnt to be received in duration of
										"aclDetectTimeout" for
										"aclIterForEnDis" times to enabling ACL coex.
                                        Similar logic is used to disable acl coexistence.
                                        (If "aclPktCntLowerLimit"  cnt of acl pkts
                                         are not seen by the for "aclIterForEnDis"
                                         then acl coexistence is disabled).
                                        default = 10
                                   */

	 u32 aclIterForEnDis;      /* number of Iteration of "aclPktCntLowerLimit" for Enabling and
                                       Disabling Acl Coexistence.
                                       default = 3
                                     */

	 u32 aclPktCntUpperLimit; /* This is upperBound limit, if there is more than
									  "aclPktCntUpperLimit" seen in "aclDetectTimeout",
									  ACL coexistence is enabled right away.
									  - default 15*/

	u32 aclCoexFlags;			/* A2DP Option flags:
		  	                          bits:    meaning:
       		                          0       Allow Close Range Optimization
                    		          1       disable Firmware detection
                                      (Currently supported configuration is aclCoexFlags =0)
                      			 	*/
	u32 linkId;                /* Applicable only for STE-BT - not used */

}__attribute__ ((packed));

struct btcoex_pspollmode_aclcoex_config {
    u32 aclDataRespTimeout;   /* Max duration firmware waits for downlink
                                      by stomping on  bluetooth
                                      after ps-poll is acknowledged.
                                     default = 20 ms */

}__attribute__ ((packed));


/* Not implemented yet*/
struct btcoex_optmode_aclcoex_config {
	u32 aclCoexMinlowRateMbps;
	u32 aclCoexLowRateCnt;
	u32 aclCoexHighPktRatio;
	u32 aclCoexMaxAggrSize;
	u32 aclPktStompCnt;
}__attribute__ ((packed));

struct wmi_set_btcoex_aclcoex_config_cmd {
	struct btcoex_aclcoex_config aclCoexConfig;
	struct btcoex_pspollmode_aclcoex_config aclCoexPspollConfig;
	struct btcoex_optmode_aclcoex_config aclCoexOptConfig;
}__attribute__ ((packed));

/* -----------WMI_SET_BTCOEX_BT_OPERATING_STATUS_CMDID ------------------*/
enum wmi_btcoex_bt_profile {
	WMI_BTCOEX_BT_PROFILE_SCO =1,
	WMI_BTCOEX_BT_PROFILE_A2DP,
	WMI_BTCOEX_BT_PROFILE_INQUIRY_PAGE,
	WMI_BTCOEX_BT_PROFILE_ACLCOEX,
};

/*------------------WMI_REPORT_BTCOEX_CONFIG_EVENTID------------------- */
/* Event from firmware to host, sent in response to WMI_GET_BTCOEX_CONFIG_CMDID
 * */
struct wmi_btcoex_config_event {
	u32 btProfileType;
	u32 linkId; /* not used */
	union {
		struct wmi_set_btcoex_sco_config_cmd scoConfigCmd;
		struct wmi_set_btcoex_a2dp_config_cmd a2dpConfigCmd;
		struct wmi_set_btcoex_aclcoex_config_cmd aclcoexConfig;
        struct wmi_set_btcoex_btinquiry_page_config_cmd btinquiryPageConfigCmd;
    } __attribute__ ((packed)) info;
} __attribute__ ((packed));

/*------------- WMI_REPORT_BTCOEX_BTCOEX_STATS_EVENTID--------------------*/
/* Used for firmware development and debugging*/
struct btcoex_general_stats {
	u32 highRatePktCnt;
	u32 firstBmissCnt;
	u32 psPollFailureCnt;
	u32 nullFrameFailureCnt;
	u32 optModeTransitionCnt;
};

struct btcoex_sco_stats {
	u32 scoStompCntAvg;
	u32 scoStompIn100ms;
	u32 scoMaxContStomp;
	u32 scoAvgNoRetries;
	u32 scoMaxNoRetriesIn100ms;
};

struct btcoex_a2dp_stats {
	u32 a2dpBurstCnt;
	u32 a2dpMaxBurstCnt;
	u32 a2dpAvgIdletimeIn100ms;
	u32 a2dpAvgStompCnt;
};

struct btcoex_aclcoex_stats {
	u32 aclPktCntInBtTime;
	u32 aclStompCntInWlanTime;
	u32 aclPktCntIn100ms;
};

struct wmi_btcoex_stats_event {
	struct btcoex_general_stats coexStats;
	struct btcoex_sco_stats scoStats;
	struct btcoex_a2dp_stats a2dpStats;
	struct btcoex_aclcoex_stats aclCoexStats;
};

/*--------------------------END OF BTCOEX -------------------------------------*/
struct wmi_report_sleep_state_event {
    u32 sleepState;
};

enum wmi_report_sleep_status {
    WMI_REPORT_SLEEP_STATUS_IS_DEEP_SLEEP =0,
    WMI_REPORT_SLEEP_STATUS_IS_AWAKE
};
enum target_event_report_config {
    DISCONN_EVT_IN_RECONN = 0,  /* default */
    NO_DISCONN_EVT_IN_RECONN
};

/*
 * Command Replies
 */

/*
 * WMI_GET_CHANNEL_LIST_CMDID reply
 */
struct wmi_channel_list_reply {
    u8 reserved1;
    u8 numChannels;            /* number of channels in reply */
    u16 channelList[1];         /* channel in Mhz */
} __attribute__ ((packed));

/*
 * List of Events (target to host)
 */
enum wmi_event_id {
    WMI_READY_EVENTID           = 0x1001,
    WMI_CONNECT_EVENTID,
    WMI_DISCONNECT_EVENTID,
    WMI_BSSINFO_EVENTID,
    WMI_CMDERROR_EVENTID,
    WMI_REGDOMAIN_EVENTID,
    WMI_PSTREAM_TIMEOUT_EVENTID,
    WMI_NEIGHBOR_REPORT_EVENTID,
    WMI_TKIP_MICERR_EVENTID,
    WMI_SCAN_COMPLETE_EVENTID,           /* 0x100a */
    WMI_REPORT_STATISTICS_EVENTID,
    WMI_RSSI_THRESHOLD_EVENTID,
    WMI_ERROR_REPORT_EVENTID,
    WMI_OPT_RX_FRAME_EVENTID,
    WMI_REPORT_ROAM_TBL_EVENTID,
    WMI_EXTENSION_EVENTID,
    WMI_CAC_EVENTID,
    WMI_SNR_THRESHOLD_EVENTID,
    WMI_LQ_THRESHOLD_EVENTID,
    WMI_TX_RETRY_ERR_EVENTID,            /* 0x1014 */
    WMI_REPORT_ROAM_DATA_EVENTID,
    WMI_TEST_EVENTID,
    WMI_APLIST_EVENTID,
    WMI_GET_WOW_LIST_EVENTID,
    WMI_GET_PMKID_LIST_EVENTID,
    WMI_CHANNEL_CHANGE_EVENTID,
    WMI_PEER_NODE_EVENTID,
    WMI_PSPOLL_EVENTID,
    WMI_DTIMEXPIRY_EVENTID,
    WMI_WLAN_VERSION_EVENTID,
    WMI_SET_PARAMS_REPLY_EVENTID,
    WMI_ADDBA_REQ_EVENTID,              /*0x1020 */
    WMI_ADDBA_RESP_EVENTID,
    WMI_DELBA_REQ_EVENTID,
    WMI_TX_COMPLETE_EVENTID,
    WMI_HCI_EVENT_EVENTID,
    WMI_ACL_DATA_EVENTID,
    WMI_REPORT_SLEEP_STATE_EVENTID,
#ifdef WAPI_ENABLE
    WMI_WAPI_REKEY_EVENTID,
#endif
    WMI_REPORT_BTCOEX_STATS_EVENTID,
    WMI_REPORT_BTCOEX_CONFIG_EVENTID,
	WMI_GET_PMK_EVENTID,

	/* DFS Events */
	WMI_DFS_HOST_ATTACH_EVENTID,
	WMI_DFS_HOST_INIT_EVENTID,
	WMI_DFS_RESET_DELAYLINES_EVENTID,
	WMI_DFS_RESET_RADARQ_EVENTID,
	WMI_DFS_RESET_AR_EVENTID,
	WMI_DFS_RESET_ARQ_EVENTID,
	WMI_DFS_SET_DUR_MULTIPLIER_EVENTID,
	WMI_DFS_SET_BANGRADAR_EVENTID,
	WMI_DFS_SET_DEBUGLEVEL_EVENTID,
	WMI_DFS_PHYERR_EVENTID,
	/* CCX Evants */
	WMI_CCX_RM_STATUS_EVENTID,

	/* P2P Events */
	WMI_P2P_GO_NEG_RESULT_EVENTID,

	WMI_WAC_SCAN_DONE_EVENTID,
	WMI_WAC_REPORT_BSS_EVENTID,
	WMI_WAC_START_WPS_EVENTID,
	WMI_WAC_CTRL_REQ_REPLY_EVENTID,

	/* RFKILL Events */
	WMI_RFKILL_STATE_CHANGE_EVENTID,
	WMI_RFKILL_GET_MODE_CMD_EVENTID,
	WMI_THIN_RESERVED_START_EVENTID = 0x8000,

	/*
	 * Events in this range are reserved for thinmode
	 * See wmi_thin.h for actual definitions
	 */
	WMI_THIN_RESERVED_END_EVENTID = 0x8fff,

	WMI_SET_CHANNEL_EVENTID,
	WMI_ASSOC_REQ_EVENTID,

	/* generic ACS event */
	WMI_ACS_EVENTID,
	WMI_REPORT_WMM_PARAMS_EVENTID
};

struct wmi_ready_event_2 {
    u32 sw_version;
    u32 abi_version;
    u8 macaddr[ETH_ALEN];
    u8 phyCapability;              /* WMI_PHY_CAPABILITY */
} __attribute__ ((packed));

/*
 * Connect Event
 */
struct wmi_connect_event {
    u16 channel;
    u8 bssid[ETH_ALEN];
    u16 listenInterval;
    u16 beaconInterval;
    u32 networkType;
    u8 beaconIeLen;
    u8 assocReqLen;
    u8 assocRespLen;
    u8 assocInfo[1];
} __attribute__ ((packed));

/*
 * Disconnect Event
 */
enum wmi_disconnect_reason {
    NO_NETWORK_AVAIL   = 0x01,
    LOST_LINK          = 0x02,     /* bmiss */
    DISCONNECT_CMD     = 0x03,
    BSS_DISCONNECTED   = 0x04,
    AUTH_FAILED        = 0x05,
    ASSOC_FAILED       = 0x06,
    NO_RESOURCES_AVAIL = 0x07,
    CSERV_DISCONNECT   = 0x08,
    INVALID_PROFILE    = 0x0a,
    DOT11H_CHANNEL_SWITCH = 0x0b,
    PROFILE_MISMATCH   = 0x0c,
    CONNECTION_EVICTED = 0x0d,
    IBSS_MERGE         = 0xe,
};

struct wmi_disconnect_event {
    u16 protocolReasonStatus;  /* reason code, see 802.11 spec. */
    u8 bssid[ETH_ALEN];    /* set if known */
    u8 disconnectReason ;      /* see WMI_DISCONNECT_REASON */
    u8 assocRespLen;
    u8 assocInfo[1];
} __attribute__ ((packed));

/*
 * BSS Info Event.
 * Mechanism used to inform host of the presence and characteristic of
 * wireless networks present.  Consists of bss info header followed by
 * the beacon or probe-response frame body.  The 802.11 header is not included.
 */
enum wmi_bi_ftype {
    BEACON_FTYPE = 0x1,
    PROBERESP_FTYPE,
    ACTION_MGMT_FTYPE,
    PROBEREQ_FTYPE,
};

struct wmi_bss_info_hdr {
    u16 channel;
    u8 frameType;          /* see WMI_BI_FTYPE */
    u8 snr;
    s16 rssi;
    u8 bssid[ETH_ALEN];
    u32 ieMask;
} __attribute__ ((packed));

/*
 * BSS INFO HDR version 2.0
 * With 6 bytes HTC header and 6 bytes of WMI header
 * WMI_BSS_INFO_HDR cannot be accommodated in the removed 802.11 management
 * header space.
 * - Reduce the ieMask to 2 bytes as only two bit flags are used
 * - Remove rssi and compute it on the host. rssi = snr - 95
 */
struct wmi_bss_info_hdr2 {
    u16 channel;
    u8 frameType;          /* see WMI_BI_FTYPE */
    u8 snr;
    u8 bssid[ETH_ALEN];
    u16 ieMask;
} __attribute__ ((packed));

/*
 * Command Error Event
 */
enum wmi_error_code {
    INVALID_PARAM  = 0x01,
    ILLEGAL_STATE  = 0x02,
    INTERNAL_ERROR = 0x03,
};

struct wmi_cmd_error_event {
    u16 commandId;
    u8 errorCode;
} __attribute__ ((packed));

/*
 * New Regulatory Domain Event
 */
struct wmi_reg_domain_event {
    u32 regDomain;
} __attribute__ ((packed)) ;

struct wmi_pstream_timeout_event {
    u8 txQueueNumber;
    u8 rxQueueNumber;
    u8 trafficDirection;
    u8 trafficClass;
} __attribute__ ((packed));

/*
 * The WMI_NEIGHBOR_REPORT Event is generated by the target to inform
 * the host of BSS's it has found that matches the current profile.
 * It can be used by the host to cache PMKs and/to initiate pre-authentication
 * if the BSS supports it.  The first bssid is always the current associated
 * BSS.
 * The bssid and bssFlags information repeats according to the number
 * or APs reported.
 */
enum wmi_bss_flags {
    WMI_DEFAULT_BSS_FLAGS   = 0x00,
    WMI_PREAUTH_CAPABLE_BSS = 0x01,
    WMI_PMKID_VALID_BSS     = 0x02,
};

struct wmi_neighbor_info {
    u8 bssid[ETH_ALEN];
    u8 bssFlags;            /* see WMI_BSS_FLAGS */
} __attribute__ ((packed));

struct wmi_neighbor_report_event {
    s8 numberOfAps;
    struct wmi_neighbor_info neighbor[1];
} __attribute__ ((packed));

/*
 * TKIP MIC Error Event
 */
struct wmi_tkip_micerr_event {
    u8 keyid;
    u8 ismcast;
} __attribute__ ((packed));

/*
 * WMI_SCAN_COMPLETE_EVENTID - no parameters (old), staus parameter (new)
 */
struct wmi_scan_complete_event {
    s32 status;
} __attribute__ ((packed));

#define MAX_OPT_DATA_LEN 1400

/*
 * Special frame receive Event.
 * Mechanism used to inform host of the receiption of the special frames.
 * Consists of special frame info header followed by special frame body.
 * The 802.11 header is not included.
 */
struct wmi_opt_rx_info_hdr {
    u16 channel;
    u8 frameType;          /* see WMI_OPT_FTYPE */
    s8 snr;
    u8 srcAddr[ETH_ALEN];
    u8 bssid[ETH_ALEN];
} __attribute__ ((packed));

/*
 * Reporting statistics.
 */
struct  tx_stats_t {
    u32 tx_packets;
    u32 tx_bytes;
    u32 tx_unicast_pkts;
    u32 tx_unicast_bytes;
    u32 tx_multicast_pkts;
    u32 tx_multicast_bytes;
    u32 tx_broadcast_pkts;
    u32 tx_broadcast_bytes;
    u32 tx_rts_success_cnt;
    u32 tx_packet_per_ac[4];
    u32 tx_errors_per_ac[4];

    u32 tx_errors;
    u32 tx_failed_cnt;
    u32 tx_retry_cnt;
    u32 tx_mult_retry_cnt;
    u32 tx_rts_fail_cnt;
    s32 tx_unicast_rate;
}__attribute__ ((packed));

struct rx_stats_t {
    u32 rx_packets;
    u32 rx_bytes;
    u32 rx_unicast_pkts;
    u32 rx_unicast_bytes;
    u32 rx_multicast_pkts;
    u32 rx_multicast_bytes;
    u32 rx_broadcast_pkts;
    u32 rx_broadcast_bytes;
    u32 rx_fragment_pkt;

    u32 rx_errors;
    u32 rx_crcerr;
    u32 rx_key_cache_miss;
    u32 rx_decrypt_err;
    u32 rx_duplicate_frames;
    s32 rx_unicast_rate;
}__attribute__ ((packed));

struct tkip_ccmp_stats_t {
    u32 tkip_local_mic_failure;
    u32 tkip_counter_measures_invoked;
    u32 tkip_replays;
    u32 tkip_format_errors;
    u32 ccmp_format_errors;
    u32 ccmp_replays;
}__attribute__ ((packed));

struct pm_stats_t {
    u32 power_save_failure_cnt;
    u16 stop_tx_failure_cnt;
    u16 atim_tx_failure_cnt;
    u16 atim_rx_failure_cnt;
    u16 bcn_rx_failure_cnt;
}__attribute__ ((packed));

struct cserv_stats_t {
    u32 cs_bmiss_cnt;
    u32 cs_lowRssi_cnt;
    u16 cs_connect_cnt;
    u16 cs_disconnect_cnt;
    s16 cs_aveBeacon_rssi;
    u16 cs_roam_count;
    s16 cs_rssi;
    u8 cs_snr;
    u8 cs_aveBeacon_snr;
    u8 cs_lastRoam_msec;
} __attribute__ ((packed));

struct wlan_net_stats_t {
    struct tx_stats_t          tx_stats;
    struct rx_stats_t          rx_stats;
    struct tkip_ccmp_stats_t   tkipCcmpStats;
}__attribute__ ((packed));

struct arp_stats_t {
    u32 arp_received;
    u32 arp_matched;
    u32 arp_replied;
} __attribute__ ((packed));

struct wlan_wow_stats_t {
    u32 wow_num_pkts_dropped;
    u16 wow_num_events_discarded;
    u8 wow_num_host_pkt_wakeups;
    u8 wow_num_host_event_wakeups;
} __attribute__ ((packed));

struct wmi_target_stats {
    u32 lqVal;
    s32 noise_floor_calibation;
    struct pm_stats_t   pmStats;
    struct wlan_net_stats_t    txrxStats;
    struct wlan_wow_stats_t    wowStats;
    struct arp_stats_t         arpStats;
    struct cserv_stats_t       cservStats;
} __attribute__ ((packed));

/*
 * WMI_RSSI_THRESHOLD_EVENTID.
 * Indicate the RSSI events to host. Events are indicated when we breach a
 * thresold value.
 */
enum wmi_rssi_threshold_val {
    WMI_RSSI_THRESHOLD1_ABOVE = 0,
    WMI_RSSI_THRESHOLD2_ABOVE,
    WMI_RSSI_THRESHOLD3_ABOVE,
    WMI_RSSI_THRESHOLD4_ABOVE,
    WMI_RSSI_THRESHOLD5_ABOVE,
    WMI_RSSI_THRESHOLD6_ABOVE,
    WMI_RSSI_THRESHOLD1_BELOW,
    WMI_RSSI_THRESHOLD2_BELOW,
    WMI_RSSI_THRESHOLD3_BELOW,
    WMI_RSSI_THRESHOLD4_BELOW,
    WMI_RSSI_THRESHOLD5_BELOW,
    WMI_RSSI_THRESHOLD6_BELOW
};

struct wmi_rssi_threshold_event {
    s16 rssi;
    u8 range;
}__attribute__ ((packed));

/*
 *  WMI_ERROR_REPORT_EVENTID
 */
enum wmi_target_error_val {
    WMI_TARGET_PM_ERR_FAIL      = 0x00000001,
    WMI_TARGET_KEY_NOT_FOUND    = 0x00000002,
    WMI_TARGET_DECRYPTION_ERR   = 0x00000004,
    WMI_TARGET_BMISS            = 0x00000008,
    WMI_PSDISABLE_NODE_JOIN     = 0x00000010,
    WMI_TARGET_COM_ERR          = 0x00000020,
    WMI_TARGET_FATAL_ERR        = 0x00000040
};

struct wmi_target_error_report_event {
    u32 errorVal;
}__attribute__ ((packed));

struct wmi_tx_retry_err_event {
    u8 retrys;
}__attribute__ ((packed));

enum wmi_snr_threshold_val {
    WMI_SNR_THRESHOLD1_ABOVE = 1,
    WMI_SNR_THRESHOLD1_BELOW,
    WMI_SNR_THRESHOLD2_ABOVE,
    WMI_SNR_THRESHOLD2_BELOW,
    WMI_SNR_THRESHOLD3_ABOVE,
    WMI_SNR_THRESHOLD3_BELOW,
    WMI_SNR_THRESHOLD4_ABOVE,
    WMI_SNR_THRESHOLD4_BELOW
};

struct wmi_snr_threshold_event {
    u8 range;  /* WMI_SNR_THRESHOLD_VAL */
    u8 snr;
}__attribute__ ((packed));

enum wmi_lq_threshold_val {
    WMI_LQ_THRESHOLD1_ABOVE = 1,
    WMI_LQ_THRESHOLD1_BELOW,
    WMI_LQ_THRESHOLD2_ABOVE,
    WMI_LQ_THRESHOLD2_BELOW,
    WMI_LQ_THRESHOLD3_ABOVE,
    WMI_LQ_THRESHOLD3_BELOW,
    WMI_LQ_THRESHOLD4_ABOVE,
    WMI_LQ_THRESHOLD4_BELOW
};

struct wmi_lq_threshold_event {
    s32 lq;
    u8 range;  /* WMI_LQ_THRESHOLD_VAL */
}__attribute__ ((packed));
/*
 * WMI_REPORT_ROAM_TBL_EVENTID
 */
#define MAX_ROAM_TBL_CAND   5

struct wmi_bss_roam_info {
    s32 roam_util;
    u8 bssid[ETH_ALEN];
    s8 rssi;
    s8 rssidt;
    s8 last_rssi;
    s8 util;
    s8 bias;
    u8 reserved; /* For alignment */
} __attribute__ ((packed));


struct wmi_target_roam_tbl {
    u16 roamMode;
    u16 numEntries;
    struct wmi_bss_roam_info bssRoamInfo[1];
} __attribute__ ((packed));

/*
 *  WMI_CAC_EVENTID
 */
enum cac_indication {
    CAC_INDICATION_ADMISSION = 0x00,
    CAC_INDICATION_ADMISSION_RESP = 0x01,
    CAC_INDICATION_DELETE = 0x02,
    CAC_INDICATION_NO_RESP = 0x03,
};

#define WMM_TSPEC_IE_LEN   63

struct wmi_cac_event {
    u8 ac;
    u8 cac_indication;
    u8 statusCode;
    u8 tspecSuggestion[WMM_TSPEC_IE_LEN];
}__attribute__ ((packed));

/*
 * WMI_APLIST_EVENTID
 */

enum aplist_ver {
    APLIST_VER1 = 1,
};

struct wmi_ap_info_v1 {
    u8 bssid[ETH_ALEN];
    u16 channel;
} __attribute__ ((packed));

union wmi_ap_info {
    struct wmi_ap_info_v1 apInfoV1;
} __attribute__ ((packed));

struct wmi_aplist_event {
    u8 apListVer;
    u8 numAP;
    union wmi_ap_info apList[1];
} __attribute__ ((packed));

/*
 * developer commands
 */

/*
 * WMI_SET_BITRATE_CMDID
 *
 * Get bit rate cmd uses same definition as set bit rate cmd
 */
enum wmi_bit_rate {
    RATE_AUTO   = -1,
    RATE_1Mb    = 0,
    RATE_2Mb    = 1,
    RATE_5_5Mb  = 2,
    RATE_11Mb   = 3,
    RATE_6Mb    = 4,
    RATE_9Mb    = 5,
    RATE_12Mb   = 6,
    RATE_18Mb   = 7,
    RATE_24Mb   = 8,
    RATE_36Mb   = 9,
    RATE_48Mb   = 10,
    RATE_54Mb   = 11,
    RATE_MCS_0_20 = 12,
    RATE_MCS_1_20 = 13,
    RATE_MCS_2_20 = 14,
    RATE_MCS_3_20 = 15,
    RATE_MCS_4_20 = 16,
    RATE_MCS_5_20 = 17,
    RATE_MCS_6_20 = 18,
    RATE_MCS_7_20 = 19,
    RATE_MCS_0_40 = 20,
    RATE_MCS_1_40 = 21,
    RATE_MCS_2_40 = 22,
    RATE_MCS_3_40 = 23,
    RATE_MCS_4_40 = 24,
    RATE_MCS_5_40 = 25,
    RATE_MCS_6_40 = 26,
    RATE_MCS_7_40 = 27,
};

struct wmi_bit_rate_reply {
    s8 rateIndex;          /* see wmi_bit_rate */
} __attribute__ ((packed));

/*
 * WMI_SET_FIXRATES_CMDID
 *
 * Get fix rates cmd uses same definition as set fix rates cmd
 */
struct wmi_fix_rates_reply {
    u32 fixRateMask;          /* see wmi_bit_rate */
} __attribute__ ((packed));

enum roam_data_type {
    ROAM_DATA_TIME = 1,            /* Get The Roam Time Data */
};

struct wmi_target_roam_time {
    u32 disassoc_time;
    u32 no_txrx_time;
    u32 assoc_time;
    u32 allow_txrx_time;
    u8 disassoc_bssid[ETH_ALEN];
    s8 disassoc_bss_rssi;
    u8 assoc_bssid[ETH_ALEN];
    s8 assoc_bss_rssi;
} __attribute__ ((packed));

struct wmi_target_roam_data {
    union {
        struct wmi_target_roam_time roamTime;
    } __attribute__ ((packed)) u;
    u8 roamDataType ;
} __attribute__ ((packed));

enum wmi_txop_cfg {
    WMI_TXOP_DISABLED = 0,
    WMI_TXOP_ENABLED
};

struct wmi_set_wmm_txop_cmd {
    u8 txopEnable;
}__attribute__ ((packed));

struct wmi_set_keepalive_cmd {
    u8 keepaliveInterval;
} __attribute__ ((packed));

struct wmi_get_keepalive_cmd {
    u32 configured;
    u8 keepaliveInterval;
} __attribute__ ((packed));

/*
 * Notify the WSC registration status to the target
 */
#define WSC_REG_ACTIVE     1
#define WSC_REG_INACTIVE   0

#define WOW_MAX_FILTER_LISTS 1 /*4*/
#define WOW_MAX_FILTERS_PER_LIST 4
#define WOW_PATTERN_SIZE 64
#define WOW_MASK_SIZE 64

#define MAC_MAX_FILTERS_PER_LIST 4

struct wow_filter {
    u8 wow_valid_filter;
    u8 wow_filter_id;
    u8 wow_filter_size;
    u8 wow_filter_offset;
    u8 wow_filter_mask[WOW_MASK_SIZE];
    u8 wow_filter_pattern[WOW_PATTERN_SIZE];
} __attribute__ ((packed));

#define MAX_IP_ADDRS  2

struct wmi_set_ip_cmd {
    u32 ips[MAX_IP_ADDRS];  /* IP in Network Byte Order */
} __attribute__ ((packed));

struct wmi_set_host_sleep_mode_cmd {
    u32 awake;
    u32 asleep;
} __attribute__ ((packed));

enum wmi_wow_filter {
    WOW_FILTER_SSID = 0x1
};

struct wmi_set_wow_mode_cmd {
    u32 enable_wow;
    enum wmi_wow_filter filter;
    u16 hostReqDelay;
} __attribute__ ((packed));

/*
 * WMI_GET_WOW_LIST_CMD reply
 */
struct wmi_get_wow_list_reply {
    u8 num_filters;     /* number of patterns in reply */
    u8 this_filter_num; /*  this is filter # x of total num_filters */
    u8 wow_mode;
    u8 host_mode;
    struct wow_filter  wow_filters[1];
} __attribute__ ((packed));

struct wmi_add_wow_pattern_cmd {
    u8 filter_list_id;
    u8 filter_size;
    u8 filter_offset;
    u8 filter[1];
} __attribute__ ((packed));

struct wmi_del_wow_pattern_cmd {
    u16 filter_list_id;
    u16 filter_id;
} __attribute__ ((packed));

/*
 * WMI_SET_AKMP_PARAMS_CMD
 */

struct wmi_pmkid {
    u8 pmkid[WMI_PMKID_LEN];
} __attribute__ ((packed));

/*
 * WMI_GET_PMKID_LIST_CMD  Reply
 * Following the Number of PMKIDs is the list of PMKIDs
 */
struct wmi_pmkid_list_reply {
    u32 numPMKID;
    u8 bssidList[ETH_ALEN][1];
    struct wmi_pmkid   pmkidList[1];
} __attribute__ ((packed));

struct wmi_channel_change_event {
    u16 oldChannel;
    u32 newChannel;
} __attribute__ ((packed));

/* WMI_ADDBA_REQ_EVENTID */
struct wmi_addba_req_event {
    u8 tid;
    u8 win_sz;
    u16 st_seq_no;
    u8 status;         /* f/w response for ADDBA Req; OK(0) or failure(!=0) */
} __attribute__ ((packed));

/* WMI_ADDBA_RESP_EVENTID */
struct wmi_addba_resp_event {
    u8 tid;
    u8 status;         /* OK(0), failure (!=0) */
    u16 amsdu_sz;       /* Three values: Not supported(0), 3839, 8k */
} __attribute__ ((packed));

/* WMI_DELBA_EVENTID
 * f/w received a DELBA for peer and processed it.
 * Host is notified of this
 */
struct wmi_delba_event {
    u8 tid;
    u8 is_peer_initiator;
    u16 reason_code;
} __attribute__ ((packed));

#define PEER_NODE_JOIN_EVENT 0x00
#define PEER_NODE_LEAVE_EVENT 0x01
#define PEER_FIRST_NODE_JOIN_EVENT 0x10
#define PEER_LAST_NODE_LEAVE_EVENT 0x11

struct wmi_peer_node_event {
    u8 eventCode;
    u8 peerMacAddr[ETH_ALEN];
} __attribute__ ((packed));

/*
 * Transmit complete event data structure(s)
 */

struct tx_complete_msg_v1 {
#define TX_COMPLETE_STATUS_SUCCESS 0
#define TX_COMPLETE_STATUS_RETRIES 1
#define TX_COMPLETE_STATUS_NOLINK  2
#define TX_COMPLETE_STATUS_TIMEOUT 3
#define TX_COMPLETE_STATUS_OTHER   4

    u8 status; /* one of TX_COMPLETE_STATUS_... */
    u8 pktID; /* packet ID to identify parent packet */
    u8 rateIdx; /* rate index on successful transmission */
    u8 ackFailures; /* number of ACK failures in tx attempt */
#if 0 /* optional params currently omitted. */
    u32 queueDelay; // usec delay measured Tx Start time - host delivery time
    u32 mediaDelay; // usec delay measured ACK rx time - host delivery time
#endif
} __attribute__ ((packed)); /* version 1 of tx complete msg */

struct wmi_tx_complete_event {
    u8 numMessages; /* number of tx comp msgs following this struct */
    u8 msgLen; /* length in bytes for each individual msg following this struct */
    u8 msgType; /* version of tx complete msg data following this struct */
    u8 reserved; /* individual messages follow this header */
} __attribute__ ((packed));

/*
 * ------- AP Mode definitions --------------
 */

/*
 * !!! Warning !!!
 * -Changing the following values needs compilation of both driver and firmware
 */
#define AP_MAX_NUM_STA          8
#define AP_ACL_SIZE             10
#define MCAST_AID               0xFF /* Spl. AID used to set DTIM flag in the beacons */
#define DEF_AP_COUNTRY_CODE     "US "
#define DEF_AP_WMODE_G          WMI_11G_MODE
#define DEF_AP_WMODE_AG         WMI_11AG_MODE
#define DEF_AP_DTIM             5
#define DEF_BEACON_INTERVAL     100

/*
 * Used with WMI_AP_ACL_MAC_LIST_CMDID
 */

struct wmi_ap_acl {
    u16 index;
    u8 acl_mac[AP_ACL_SIZE][ETH_ALEN];
    u8 wildcard[AP_ACL_SIZE];
    u8 policy;
} __attribute__ ((packed));

/*
 * Used with WMI_AP_SET_NUM_STA_CMDID
 */

struct wmi_ap_set_pvb_cmd {
    u32 flag;
    u16 aid;
} __attribute__ ((packed));

struct wmi_set_ht_cap_cmd {
    u8 band; /* specifies which band to apply these values */
    u8 enable; /* allows 11n to be disabled on a per band basis */
    u8 chan_width_40M_supported;
    u8 short_GI_20MHz;
    u8 short_GI_40MHz;
    u8 intolerance_40MHz;
    u8 max_ampdu_len_exp;
} __attribute__ ((packed));

struct wmi_rx_frame_format_cmd {
    u8 metaVersion; /* version of meta data for rx packets <0 = default> (0-7 = valid) */
    u8 dot11Hdr; /* 1 == leave .11 header intact , 0 == replace .11 header with .3 <default> */
    u8 defragOnHost; /* 1 == defragmentation is performed by host, 0 == performed by target <default> */
    u8 reserved[1]; /* alignment */
} __attribute__ ((packed));

/* AP mode events */
/* WMI_PS_POLL_EVENT */
struct wmi_pspoll_event {
    u16 aid;
} __attribute__ ((packed));

struct wmi_per_sta_stat {
    u32 tx_bytes;
    u32 tx_pkts;
    u32 tx_error;
    u32 tx_discard;
    u32 rx_bytes;
    u32 rx_pkts;
    u32 rx_error;
    u32 rx_discard;
    u32 aid;
} __attribute__ ((packed));

struct wmi_ap_mode_stat {
    u32 action;
    struct wmi_per_sta_stat  sta[AP_MAX_NUM_STA+1];
} __attribute__ ((packed));

/*
 * End of AP mode definitions
 */

/* Extended WMI (WMIX)
 *
 * Extended WMIX commands are encapsulated in a WMI message with
 * cmd=WMI_EXTENSION_CMD.
 *
 * Extended WMI commands are those that are needed during wireless
 * operation, but which are not really wireless commands.  This allows,
 * for instance, platform-specific commands.  Extended WMI commands are
 * embedded in a WMI command message with WMI_COMMAND_ID=WMI_EXTENSION_CMDID.
 * Extended WMI events are similarly embedded in a WMI event message with
 * WMI_EVENT_ID=WMI_EXTENSION_EVENTID.
 */
struct wmix_cmd_hdr {
    u32 commandId;
} __attribute__ ((packed));

enum wmix_command_id {
    WMIX_DSETOPEN_REPLY_CMDID           = 0x2001,
    WMIX_DSETDATA_REPLY_CMDID,
    WMIX_GPIO_OUTPUT_SET_CMDID,
    WMIX_GPIO_INPUT_GET_CMDID,
    WMIX_GPIO_REGISTER_SET_CMDID,
    WMIX_GPIO_REGISTER_GET_CMDID,
    WMIX_GPIO_INTR_ACK_CMDID,
    WMIX_HB_CHALLENGE_RESP_CMDID,
    WMIX_DBGLOG_CFG_MODULE_CMDID,
    WMIX_PROF_CFG_CMDID,                 /* 0x200a */
    WMIX_PROF_ADDR_SET_CMDID,
    WMIX_PROF_START_CMDID,
    WMIX_PROF_STOP_CMDID,
    WMIX_PROF_COUNT_GET_CMDID,
};

enum wmix_event_id {
    WMIX_DSETOPENREQ_EVENTID            = 0x3001,
    WMIX_DSETCLOSE_EVENTID,
    WMIX_DSETDATAREQ_EVENTID,
    WMIX_GPIO_INTR_EVENTID,
    WMIX_GPIO_DATA_EVENTID,
    WMIX_GPIO_ACK_EVENTID,
    WMIX_HB_CHALLENGE_RESP_EVENTID,
    WMIX_DBGLOG_EVENTID,
    WMIX_PROF_COUNT_EVENTID,
};

/*
 * =============Error Detection support=================
 */

/*
 * WMIX_HB_CHALLENGE_RESP_CMDID
 * Heartbeat Challenge Response command
 */
struct wmix_hb_challenge_resp_cmd {
    u32 cookie;
    u32 source;
} __attribute__ ((packed)) ;

/*
 * WMIX_HB_CHALLENGE_RESP_EVENTID
 * Heartbeat Challenge Response Event
 */
#define WMIX_HB_CHALLENGE_RESP_EVENT struct wmix_hb_challenge_resp_cmd

/* End of Extended WMI (WMIX) */

void * wmi_init(void *devt);

void wmi_qos_state_init(struct wmi_t *wmip);
void wmi_shutdown(struct wmi_t *wmip);
enum htc_endpoint_id wmi_get_control_ep(struct wmi_t * wmip);
void wmi_set_control_ep(struct wmi_t * wmip, enum htc_endpoint_id eid);
int wmi_dix_2_dot3(struct wmi_t *wmip, void *osbuf);
int wmi_data_hdr_add(struct wmi_t *wmip, void *osbuf, u8 msgType, bool bMoreData,
                     enum wmi_data_hdr_data_type data_type,u8 metaVersion, void *pTxMetaS);

int wmi_dot11_hdr_remove (struct wmi_t *wmip, void *osbuf);
int wmi_dot11_hdr_add(struct wmi_t *wmip, void *osbuf, enum network_type mode);

int wmi_data_hdr_remove(struct wmi_t *wmip, void *osbuf);
u8 wmi_implicit_create_pstream(struct wmi_t *wmip, void *osbuf, u32 layer2Priority, bool wmmEnabled);

u8 wmi_determine_userPriority (u8 *pkt, u32 layer2Pri);

int wmi_control_rx(struct wmi_t *wmip, void *osbuf);
void wmi_iterate_nodes(struct wmi_t *wmip, wlan_node_iter_func *f, void *arg);
void wmi_free_allnodes(struct wmi_t *wmip);
struct bss *wmi_find_node(struct wmi_t *wmip, const u8 *macaddr);
void wmi_free_node(struct wmi_t *wmip, const u8 *macaddr);

enum wmi_sync_flag {
    NO_SYNC_WMIFLAG = 0,
    SYNC_BEFORE_WMIFLAG,            /* transmit all queued data before cmd */
    SYNC_AFTER_WMIFLAG,             /* any new data waits until cmd execs */
    SYNC_BOTH_WMIFLAG,
    END_WMIFLAG                     /* end marker */
};

int wmi_cmd_send(struct wmi_t *wmip, void *osbuf, enum wmi_cmd_id cmdId,
                      enum wmi_sync_flag flag);

int wmi_connect_cmd(struct wmi_t *wmip,
                         enum network_type netType,
                         enum dot11_auth_mode dot11AuthMode,
                         enum auth_mode authMode,
                         enum crypto_type pairwiseCrypto,
                         u8 pairwiseCryptoLen,
                         enum crypto_type groupCrypto,
                         u8 groupCryptoLen,
                         int ssidLength,
                         u8 *ssid,
                         u8 *bssid,
                         u16 channel,
                         u32 ctrl_flags);

int wmi_reconnect_cmd(struct wmi_t *wmip,
                           u8 *bssid,
                           u16 channel);
int wmi_disconnect_cmd(struct wmi_t *wmip);
int wmi_startscan_cmd(struct wmi_t *wmip, enum wmi_scan_type scanType,
                           u32 forceFgScan, u32 isLegacy,
                           u32 homeDwellTime, u32 forceScanInterval,
                           s8 numChan, u16 *channelList);
int wmi_scanparams_cmd(struct wmi_t *wmip, u16 fg_start_sec,
                            u16 fg_end_sec, u16 bg_sec,
                            u16 minact_chdw_msec,
                            u16 maxact_chdw_msec, u16 pas_chdw_msec,
                            u8 shScanRatio, u8 scanCtrlFlags,
                            u32 max_dfsch_act_time,
                            u16 maxact_scan_per_ssid);
int wmi_bssfilter_cmd(struct wmi_t *wmip, u8 filter, u32 ieMask);
int wmi_probedSsid_cmd(struct wmi_t *wmip, u8 index, u8 flag,
                            u8 ssidLength, u8 *ssid);
int wmi_listeninterval_cmd(struct wmi_t *wmip, u16 listenInterval, u16 listenBeacons);
int wmi_powermode_cmd(struct wmi_t *wmip, u8 powerMode);
int wmi_pmparams_cmd(struct wmi_t *wmip, u16 idlePeriod,
                           u16 psPollNum, u16 dtimPolicy,
                           u16 wakup_tx_policy, u16 num_tx_to_wakeup,
                           u16 ps_fail_event_policy);
int wmi_disctimeout_cmd(struct wmi_t *wmip, u8 timeout);
int wmi_sync_cmd(struct wmi_t *wmip, u8 syncNumber);
int wmi_create_pstream_cmd(struct wmi_t *wmip, struct wmi_create_pstream_cmd *pstream);
int wmi_delete_pstream_cmd(struct wmi_t *wmip, u8 trafficClass, u8 streamID);
s8 wmi_validate_bitrate(struct wmi_t *wmip, s32 rate, s8 *rate_idx);

int wmi_set_rts_cmd(struct wmi_t *wmip, u16 threshold);
int wmi_set_lpreamble_cmd(struct wmi_t *wmip, u8 status, u8 preamblePolicy);

int wmi_get_challenge_resp_cmd(struct wmi_t *wmip, u32 cookie,
                                    u32 source);

int wmi_get_stats_cmd(struct wmi_t *wmip);

int wmi_addKey_cmd(struct wmi_t *wmip, u8 keyIndex,
                        enum crypto_type keyType, u8 keyUsage,
                        u8 keyLength,u8 *keyRSC,
                        u8 *keyMaterial, u8 key_op_ctrl, u8 *mac,
                        enum wmi_sync_flag sync_flag);
int wmi_add_krk_cmd(struct wmi_t *wmip, u8 *krk);
int wmi_deleteKey_cmd(struct wmi_t *wmip, u8 keyIndex);
int wmi_set_txPwr_cmd(struct wmi_t *wmip, u8 dbM);
int wmi_get_txPwr_cmd(struct wmi_t *wmip);
void wmi_get_current_bssid(struct wmi_t *wmip, u8 *bssid);
u8 convert_userPriority_to_trafficClass(u8 userPriority);

int wmi_set_btcoex_fe_ant_cmd(struct wmi_t *wmip, struct wmi_set_btcoex_fe_ant_cmd * cmd);

int wmi_set_btcoex_colocated_bt_dev_cmd(struct wmi_t *wmip,
		                                struct wmi_set_btcoex_colocated_bt_dev_cmd * cmd);

/*
 *  This function is used to configure the fix rates mask to the target.
 */

int wmi_set_wmm_txop(struct wmi_t *wmip, enum wmi_txop_cfg txEnable);
int wmi_set_keepalive_cmd(struct wmi_t *wmip, u8 keepaliveInterval);

s32 wmi_get_rate(s8 rateindex);

int wmi_set_ip_cmd(struct wmi_t *wmip, struct wmi_set_ip_cmd *cmd);

/*Wake on Wireless WMI commands*/
int wmi_set_host_sleep_mode_cmd(struct wmi_t *wmip, struct wmi_set_host_sleep_mode_cmd *cmd);
int wmi_set_wow_mode_cmd(struct wmi_t *wmip, struct wmi_set_wow_mode_cmd *cmd);
int wmi_add_wow_pattern_cmd(struct wmi_t *wmip,
                                 struct wmi_add_wow_pattern_cmd *cmd, u8 *pattern, u8 *mask, u8 pattern_size);
int wmi_del_wow_pattern_cmd(struct wmi_t *wmip,
                                 struct wmi_del_wow_pattern_cmd *cmd);

struct bss * wmi_find_Ssidnode (struct wmi_t *wmip, u8 *pSsid,
                   u32 ssidLength, bool bIsWPA2, bool bMatchSSID);

void wmi_node_return (struct wmi_t *wmip, struct bss *bss);

int wmi_add_current_bss (struct wmi_t *wmip, u8 *id, struct bss *bss);


/* AP mode */
int wmi_ap_profile_commit(struct wmi_t *wmip, struct wmi_connect_cmd *p);

int wmi_set_pvb_cmd(struct wmi_t *wmip, u16 aid, bool flag);

int wmi_set_ht_cap_cmd(struct wmi_t *wmip, struct wmi_set_ht_cap_cmd *cmd);

int wmi_set_rx_frame_format_cmd(struct wmi_t *wmip, u8 rxMetaVersion, bool rxDot11Hdr, bool defragOnHost);

#endif /* _WMI_H_ */
