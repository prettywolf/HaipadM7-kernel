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
// Author(s): ="Atheros"
//==============================================================================

#ifndef ATH6KL_H
#define ATH6KL_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/semaphore.h>
#include <linux/cache.h>

#define IEEE80211_MAX_IE        256

#define __VER_MAJOR_ 	3
#define __VER_MINOR_ 	0
#define __VER_PATCH_ 	0
#define __BUILD_NUMBER_ 233

/* Format of the version number. */
#define VER_MAJOR_BIT_OFFSET        28
#define VER_MINOR_BIT_OFFSET        24
#define VER_PATCH_BIT_OFFSET        16
#define VER_BUILD_NUM_BIT_OFFSET    0

/*
 * The version has the following format:
 * Bits 28-31: Major version
 * Bits 24-27: Minor version
 * Bits 16-23: Patch version
 * Bits 0-15:  Build number (automatically generated during build process )
 * E.g. Build 1.1.3.7 would be represented as 0x11030007.
 *
 * DO NOT split the following macro into multiple lines as this may confuse the build scripts.
 */
#define AR6K_SW_VERSION     ( ( __VER_MAJOR_ << VER_MAJOR_BIT_OFFSET ) + \
			      ( __VER_MINOR_ << VER_MINOR_BIT_OFFSET ) + \
			      ( __VER_PATCH_ << VER_PATCH_BIT_OFFSET ) + \
			      ( __BUILD_NUMBER_ << VER_BUILD_NUM_BIT_OFFSET ) )

enum ATH6K_DEBUG_MASK {
	ATH_DBG_WLAN_CONNECT = 0x00000001, /* wlan connect */
	ATH_DBG_WLAN_SCAN    = 0x00000002, /* wlan scan */
	ATH_DBG_WLAN_TX      = 0x00000004, /* wlan tx */
	ATH_DBG_WLAN_RX      = 0x00000008, /* wlan rx */
	ATH_DBG_HTC_RAW      = 0x00000010, /* htc raw i/f tracing */
	ATH_DBG_BMI 	     = 0x00000020, /* bmi tracing */
	ATH_DBG_HTC_SEND     = 0x00000040, /* htc send */
	ATH_DBG_HTC_RECV     = 0x00000080, /* htc recv */
	ATH_DBG_IRQ  	     = 0x00000100, /* interrupt processing */
	ATH_DBG_PM           = 0x00000200, /* power management */
	ATH_DBG_WLAN         = 0x00000400, /* general wlan node tracing */
	ATH_DBG_WMI          = 0x00000800, /* wmi tracing */
	ATH_DBG_ANY	     = 0xffffffff  /* enable all logs */
};

extern int ath_printk(const char *level, const char *fmt, ...);

#define ath_info(common, fmt, ...)				\
	ath_printk(KERN_INFO, common, fmt, ##__VA_ARGS__)
#define ath_err(fmt, ...)					\
	ath_printk(KERN_ERR, fmt, ##__VA_ARGS__)
/*
#ifdef CONFIG_ATH6KL_DEBUG

extern unsigned int debug_mask;
#define ath_dbg(mask, fmt, ...)					\
({								\
	int rtn;						\
	if (debug_mask & mask)					\
	     rtn = ath_printk(KERN_DEBUG, fmt, ##__VA_ARGS__);	\
	else							\
	     rtn = 0;						\
								\
	rtn;							\
})

#else

static inline int ath_dbg(enum ATH6K_DEBUG dbg_mask,
			  const char *fmt, ...)
{
	return 0;
}

#endif 
*/
/* TODO: Move below debug macros to separate file.
 *       At present, let it be here to avoid compilation errors.
 */
#define A_LOGGER(mask, mod, args...)    printk(KERN_ALERT args)
#define A_PRINTF(args...)               printk(KERN_ALERT args)

#ifdef DEBUG
extern unsigned int panic_on_assert;
#define A_ASSERT(expr)  \
    if (!(expr)) {   \
        printk(KERN_ALERT"Debug Assert Caught, File %s, Line: %d, Test:%s \n",__FILE__, __LINE__,#expr); \
        panic(#expr);                                                               \
    }
#else
#define A_ASSERT(expr)
#endif /* DEBUG */

/* Host side Test Command support */
#define USE_4BYTE_REGISTER_ACCESS

/* IP/TCP checksum offload */
/* Checksum offload is currently not supported for 64 bit platforms */
#ifndef __LP64__
#define CONFIG_CHECKSUM_OFFLOAD
#endif /* __LP64__ */

#define A_CACHE_LINE_PAD            128

/* Include definitions here that can be used to tune the WLAN module behavior.
 * Different customers can tune the behavior as per their needs, here.
 */

/* This configuration item when defined will consider the barker preamble
 * mentioned in the ERP IE of the beacons from the AP to determine the short
 * preamble support sent in the (Re)Assoc request frames.
 */
#define WLAN_CONFIG_DONOT_IGNORE_BARKER_IN_ERP 0

/* This config item when defined will not send the power module state transition
 * failure events that happen during scan, to the host.
 */
#define WLAN_CONFIG_IGNORE_POWER_SAVE_FAIL_EVENT_DURING_SCAN 0

/*
 * This configuration item enable/disable keepalive support.
 * Keepalive support: In the absence of any data traffic to AP, null
 * frames will be sent to the AP at periodic interval, to keep the association
 * active. This configuration item defines the periodic interval.
 * Use value of zero to disable keepalive support
 * Default: 60 seconds
 */
#define WLAN_CONFIG_KEEP_ALIVE_INTERVAL 60

/*
 * This configuration item sets the value of disconnect timeout
 * Firmware delays sending the disconnec event to the host for this
 * timeout after is gets disconnected from the current AP.
 * If the firmware successly roams within the disconnect timeout
 * it sends a new connect event
 */
#define WLAN_CONFIG_DISCONNECT_TIMEOUT 10

/*
 * This configuration item disables 11n support.
 * 0 - Enable
 * 1 - Disable
 */
#define WLAN_CONFIG_DISABLE_11N         0

/*
 * This configuration item enable BT clock sharing support
 * 1 - Enable
 * 0 - Disable (Default)
 */
#define WLAN_CONFIG_BT_SHARING          0

/*
 * This configuration item sets WIFI OFF policy
 * 0 - CUT_POWER
 * 1 - DEEP_SLEEP (Default)
 */
#define WLAN_CONFIG_WLAN_OFF                1

/*
 * This configuration item sets suspend policy
 * 0 - CUT_POWER (Default)
 * 1 - DEEP_SLEEP
 * 2 - WoW
 * 3 - CUT_POWER if BT OFF (clock sharing designs only)
 */
#define WLAN_CONFIG_PM_SUSPEND              0

/*
 * This configuration item sets suspend policy to use if PM_SUSPEND is
 * set to WoW and device is not connected at the time of suspend
 * 0 - CUT_POWER (Default)
 * 1 - DEEP_SLEEP
 * 2 - WoW
 * 3 - CUT_POWER if BT OFF (clock sharing designs only)
 */
#define WLAN_CONFIG_PM_WOW2                 0

/*
 * This configuration item enables/disables transmit bursting
 * 0 - Enable tx Bursting (default)
 * 1 - Disable tx bursting
 */
#define WLAN_CONFIG_DISABLE_TX_BURSTING     0

/*
 * This configuration item sets WIFI OFF policy
*
 * ABI Version. Reflects the version of binary interface exposed by AR6K target firmware.
 * Needs to be incremented by 1 for any change in the firmware that requires upgrade of
 * the driver on the host side for the change to work correctly
 */
#define AR6K_ABI_VERSION        1

/*
 * Generic error codes that can be used by hw, sta, ap, sim, dk
 * and any other environments.
 * Feel free to add any more non-zero codes that you need.
 */

/* Setting this bit to 1 doesnot initialize the RSC on the firmware */
#define AR6000_USER_SETKEYS_RSC_UNCHANGED     0x00000002

#define AR6000_DRIVER_CFG_BASE                  0x8000

#define AR6000_DRIVER_CFG_GET_WLANNODECACHING   0x8001
#define AR6000_DRIVER_CFG_LOG_RAW_WMI_MSGS      0x8002

#define A_ERROR			(-1)	/* Generic error return */
#define A_DEVICE_NOT_FOUND	1	/* not able to find PCI device */
#define A_NO_MEMORY		2	/* not able to allocate memory,
					 * not avail#defineable */
#define A_MEMORY_NOT_AVAIL	3	/* memory region is not free for
					 * mapping */
#define A_NO_FREE_DESC		4	/* no free descriptors available */
#define A_BAD_ADDRESS		5	/* address does not match descriptor */
#define A_WIN_DRIVER_ERROR	6	/* used in NT_HW version,
					 * if problem at init */
#define A_REGS_NOT_MAPPED	7	/* registers not correctly mapped */
#define A_EPERM			8	/* Not superuser */
#define A_EACCES		0	/* Access denied */
#define A_ENOENT		10	/* No such entry, search failed, etc. */
#define A_EEXIST		11	/* The object already exists
					 * (can't create) */
#define A_EFAULT		12	/* Bad address fault */
#define A_EBUSY			13	/* Object is busy */
#define A_EINVAL		14	/* Invalid parameter */
#define A_EMSGSIZE		15	/* Bad message buffer length */
#define A_ECANCELED		16	/* Operation canceled */
#define A_ENOTSUP		17	/* Operation not supported */
#define A_ECOMM			18	/* Communication error on send */
#define A_EPROTO		19	/* Protocol error */
#define A_ENODEV		20	/* No such device */
#define A_EDEVNOTUP		21	/* device is not UP */
#define A_NO_RESOURCE		22	/* No resources for
					 * requested operation */
#define A_HARDWARE		23	/* Hardware failure */
#define A_PENDING		24	/* Asynchronous routine; will send up
					 * results later
					 * (typically in callback) */
#define A_EBADCHANNEL		25	/* The channel cannot be used */
#define A_DECRYPT_ERROR		26	/* Decryption error */
#define A_PHY_ERROR		27	/* RX PHY error */
#define A_CONSUMED		28	/* Object was consumed */

#define DBGLOG_TIMESTAMP_OFFSET          0
#define DBGLOG_TIMESTAMP_MASK            0x0000FFFF /* Bit 0-15. Contains bit
                                                       8-23 of the LF0 timer */
#define DBGLOG_DBGID_OFFSET              16
#define DBGLOG_DBGID_MASK                0x03FF0000 /* Bit 16-25 */
#define DBGLOG_MODULEID_OFFSET           26
#define DBGLOG_MODULEID_MASK             0x3C000000 /* Bit 26-29 */
#define DBGLOG_MODULEID_NUM_MAX          16 /* Upper limit is width of mask */

#define DBGLOG_NUM_ARGS_OFFSET           30
#define DBGLOG_NUM_ARGS_MASK             0xC0000000 /* Bit 30-31 */
#define DBGLOG_LOG_BUFFER_SIZE           1500

#define DBGLOG_HOST_LOG_BUFFER_SIZE            DBGLOG_LOG_BUFFER_SIZE

#define DBGLOG_GET_DBGID(arg) \
    ((arg & DBGLOG_DBGID_MASK) >> DBGLOG_DBGID_OFFSET)

#define DBGLOG_GET_MODULEID(arg) \
    ((arg & DBGLOG_MODULEID_MASK) >> DBGLOG_MODULEID_OFFSET)

#define DBGLOG_GET_NUMARGS(arg) \
    ((arg & DBGLOG_NUM_ARGS_MASK) >> DBGLOG_NUM_ARGS_OFFSET)

#define DBGLOG_GET_TIMESTAMP(arg) \
    ((arg & DBGLOG_TIMESTAMP_MASK) >> DBGLOG_TIMESTAMP_OFFSET)

struct dbglog_config_s {
    u32 cfgvalid; /* Mask with valid config bits */
    union {
        /* TODO: Take care of endianness */
        struct {
            u32 mmask:16; /* Mask of modules with logging on */
            u32 rep:1; /* Reporting enabled or not */
            u32 tsr:3; /* Time stamp resolution. Def: 1 ms */
            u32 size:10; /* Report size in number of messages */
            u32 reserved:2;
        } dbglog_config;

        u32 value;
    } u;
} __attribute__ ((packed));

/*
 * The signal quality could be in terms of either snr or rssi. We should
 * have an enum for both of them. For the time being, we are going to move
 * it to wmi.h that is shared by both host and the target, since we are
 * repartitioning the code to the host
 */
#define SIGNAL_QUALITY_NOISE_FLOOR        -96
#define SIGNAL_QUALITY_METRICS_NUM_MAX    2

enum {
    SIGNAL_QUALITY_METRICS_SNR = 0,
    SIGNAL_QUALITY_METRICS_RSSI,
    SIGNAL_QUALITY_METRICS_ALL,
};

/*
 * Data Path
 */
typedef struct {
    u8 dstMac[ETH_ALEN];
    u8 srcMac[ETH_ALEN];
    u16 typeOrLen;
} __attribute__ ((packed)) ATH_MAC_HDR;

#define WMI_MAX_TX_DATA_FRAME_LENGTH \
		(1500 + sizeof(struct wmi_data_hdr) + sizeof(ATH_MAC_HDR) + sizeof(ATH_LLC_SNAP_HDR))

/* A normal WMI data frame */
#define WMI_MAX_NORMAL_RX_DATA_FRAME_LENGTH \
		(1500 + sizeof(struct wmi_data_hdr) + sizeof(ATH_MAC_HDR) + sizeof(ATH_LLC_SNAP_HDR))

/* An AMSDU frame */ /* The MAX AMSDU length of AR6003 is 3839 */
#define WMI_MAX_AMSDU_RX_DATA_FRAME_LENGTH  \
		(3840 + sizeof(struct wmi_data_hdr) + sizeof(ATH_MAC_HDR) + sizeof(ATH_LLC_SNAP_HDR))
#define EPPING_ALIGNMENT_PAD  (((sizeof(struct htc_frame_hdr) + 3) & (~0x3)) - sizeof(struct htc_frame_hdr))
typedef struct {
    u8 dsap;
    u8 ssap;
    u8 cntl;
    u8 orgCode[3];
    u16 etherType;
} __attribute__ ((packed)) ATH_LLC_SNAP_HDR;

enum crypto_type {
    NONE_CRYPT          = 0x01,
    WEP_CRYPT           = 0x02,
    TKIP_CRYPT          = 0x04,
    AES_CRYPT           = 0x08,
#ifdef WAPI_ENABLE
    WAPI_CRYPT          = 0x10,
#endif /*WAPI_ENABLE*/
};

struct ieee80211_node_table;
struct ieee80211_frame;

struct ieee80211_common_ie {
    u16 ie_chan;
    u8 *ie_tstamp;
    u8 *ie_ssid;
    u8 *ie_rates;
    u8 *ie_xrates;
    u8 *ie_country;
    u8 *ie_wpa;
    u8 *ie_rsn;
    u8 *ie_wmm;
    u8 *ie_ath;
    u16 ie_capInfo;
    u16 ie_beaconInt;
    u8 *ie_tim;
    u8 *ie_chswitch;
    u8 ie_erp;
    u8 *ie_wsc;
    u8 *ie_htcap;
    u8 *ie_htop;
#ifdef WAPI_ENABLE
    u8 *ie_wapi;
#endif
};

typedef struct bss {
    u8 ni_macaddr[6];
    u8 ni_snr;
    s16 ni_rssi;
    struct bss                   *ni_list_next;
    struct bss                   *ni_list_prev;
    struct bss                   *ni_hash_next;
    struct bss                   *ni_hash_prev;
    struct ieee80211_common_ie   ni_cie;
    u8 *ni_buf;
    u16 ni_framelen;
    struct ieee80211_node_table *ni_table;
    u32 ni_refcnt;
    int                          ni_scangen;

    u32 ni_tstamp;
    u32 ni_actcnt;
#ifdef OS_ROAM_MANAGEMENT
    u32 ni_si_gen;
#endif
} bss_t;

typedef enum {
    ATHEROS_COMPLIANCE = 0x1,
}TSPEC_PARAM_COMPLIANCE;


int wmi_dot3_2_dix(void *osbuf);

typedef void wlan_node_iter_func(void *arg, struct bss *);
struct bss *wlan_node_alloc(struct ieee80211_node_table *nt, int wh_size);
void wlan_node_free(struct bss *ni);
void wlan_setup_node(struct ieee80211_node_table *nt, struct bss *ni,
                const u8 *macaddr);
struct bss *wlan_find_node(struct ieee80211_node_table *nt, const u8 *macaddr);
void wlan_node_reclaim(struct ieee80211_node_table *nt, struct bss *ni);
void wlan_free_allnodes(struct ieee80211_node_table *nt);
void wlan_iterate_nodes(struct ieee80211_node_table *nt, wlan_node_iter_func *f,
                        void *arg);

void wlan_node_table_init(void *wmip, struct ieee80211_node_table *nt);
void wlan_node_table_reset(struct ieee80211_node_table *nt);
void wlan_node_table_cleanup(struct ieee80211_node_table *nt);

int wlan_parse_beacon(u8 *buf, int framelen,
                           struct ieee80211_common_ie *cie);

void wlan_set_nodeage(struct ieee80211_node_table *nt, u32 nodeAge);

void wlan_refresh_inactive_nodes (struct ieee80211_node_table *nt);

struct bss * wlan_find_Ssidnode (struct ieee80211_node_table *nt, u8 *pSsid,
                    u32 ssidLength, bool bIsWPA2, bool bMatchSSID);

void wlan_node_return (struct ieee80211_node_table *nt, struct bss *ni);

struct bss *wlan_node_remove(struct ieee80211_node_table *nt, u8 *bssid);

struct bss * wlan_find_matching_Ssidnode (struct ieee80211_node_table *nt, u8 *pSsid,
                    u32 ssidLength, u32 dot11AuthMode, u32 authMode,
                   u32 pairwiseCryptoType, u32 grpwiseCryptoTyp);


int ar6000_avail_ev(void *hif_handle);
int ar6000_unavail_ev(void *context, void *hif_handle);
int ar6000_suspend_ev(void *context);
int ar6000_resume_ev(void *context);
int ar6000_power_change_ev(void *context, u32 config);
struct sk_buff *ar6k_buf_alloc(int size);
#endif /* ATH6KL_H */
