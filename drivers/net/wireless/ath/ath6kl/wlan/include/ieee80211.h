//------------------------------------------------------------------------------
// <copyright file="ieee80211.h" company="Atheros">
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
// Author(s): ="Atheros"
//==============================================================================
#ifndef _NET80211_IEEE80211_H_
#define _NET80211_IEEE80211_H_

/*
 * 802.11i defines an extended IV for use with non-WEP ciphers.
 * When the EXTIV bit is set in the key id byte an additional
 * 4 bytes immediately follow the IV for TKIP.  For CCMP the
 * EXTIV bit is likewise set but the 8 bytes represent the
 * CCMP header rather than IV+extended-IV.
 */

#ifdef WAPI_ENABLE
#define IEEE80211_WAPI_EXTIVLEN      10   /* extended IV length */
#endif /* WAPI ENABLE */


/* is 802.11 address multicast/broadcast? */
#define IEEE80211_IS_MULTICAST(_a)  (*(_a) & 0x01)
#define IEEE80211_IS_BROADCAST(_a)  (*(_a) == 0xFF)

#define IEEE80211_KEYBUF_SIZE 16
#define IEEE80211_MICBUF_SIZE (8+8)  /* space for both tx and rx */

/*
 * NB: these values are ordered carefully; there are lots of
 * of implications in any reordering.  In particular beware
 * that 4 is not used to avoid conflicting with IEEE80211_F_PRIVACY.
 */
#define IEEE80211_CIPHER_WEP            0
#define IEEE80211_CIPHER_TKIP           1
#define IEEE80211_CIPHER_AES_OCB        2
#define IEEE80211_CIPHER_AES_CCM        3
#define IEEE80211_CIPHER_CKIP           5
#define IEEE80211_CIPHER_CCKM_KRK       6
#define IEEE80211_CIPHER_NONE           7       /* pseudo value */


/*
 * generic definitions for IEEE 802.11 frames
 */
struct ieee80211_frame {
    u8 i_fc[2];
    u8 i_dur[2];
    u8 i_addr1[ETH_ALEN];
    u8 i_addr2[ETH_ALEN];
    u8 i_addr3[ETH_ALEN];
    u8 i_seq[2];
    /* possibly followed by addr4[ETH_ALEN]; */
    /* see below */
} __attribute__ ((packed));

#define IEEE80211_FC0_VERSION_MASK          0x03
#define IEEE80211_FC0_VERSION_SHIFT         0
#define IEEE80211_FC0_VERSION_0             0x00
#define IEEE80211_FC0_TYPE_MASK             0x0c
#define IEEE80211_FC0_TYPE_SHIFT            2
#define IEEE80211_FC0_TYPE_MGT              0x00
#define IEEE80211_FC0_TYPE_CTL              0x04
#define IEEE80211_FC0_TYPE_DATA             0x08

#define IEEE80211_FC0_SUBTYPE_MASK          0xf0
#define IEEE80211_FC0_SUBTYPE_SHIFT         4

/* for TYPE_MGT */
#define IEEE80211_FC0_SUBTYPE_ASSOC_REQ     0x00
#define IEEE80211_FC0_SUBTYPE_ASSOC_RESP    0x10
#define IEEE80211_FC0_SUBTYPE_REASSOC_REQ   0x20
#define IEEE80211_FC0_SUBTYPE_REASSOC_RESP  0x30
#define IEEE80211_FC0_SUBTYPE_PROBE_REQ     0x40
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP    0x50
#define IEEE80211_FC0_SUBTYPE_BEACON        0x80
#define IEEE80211_FC0_SUBTYPE_ATIM          0x90
#define IEEE80211_FC0_SUBTYPE_DISASSOC      0xa0
#define IEEE80211_FC0_SUBTYPE_AUTH          0xb0
#define IEEE80211_FC0_SUBTYPE_DEAUTH        0xc0
/* for TYPE_CTL */
#define IEEE80211_FC0_SUBTYPE_PS_POLL       0xa0
#define IEEE80211_FC0_SUBTYPE_RTS           0xb0
#define IEEE80211_FC0_SUBTYPE_CTS           0xc0
#define IEEE80211_FC0_SUBTYPE_ACK           0xd0
#define IEEE80211_FC0_SUBTYPE_CF_END        0xe0
#define IEEE80211_FC0_SUBTYPE_CF_END_ACK    0xf0
/* for TYPE_DATA (bit combination) */
#define IEEE80211_FC0_SUBTYPE_DATA          0x00
#define IEEE80211_FC0_SUBTYPE_CF_ACK        0x10
#define IEEE80211_FC0_SUBTYPE_CF_POLL       0x20
#define IEEE80211_FC0_SUBTYPE_CF_ACPL       0x30
#define IEEE80211_FC0_SUBTYPE_NODATA        0x40
#define IEEE80211_FC0_SUBTYPE_CFACK         0x50
#define IEEE80211_FC0_SUBTYPE_CFPOLL        0x60
#define IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK 0x70
#define IEEE80211_FC0_SUBTYPE_QOS           0x80
#define IEEE80211_FC0_SUBTYPE_QOS_NULL      0xc0

#define IEEE80211_FC1_DIR_MASK              0x03
#define IEEE80211_FC1_DIR_NODS              0x00    /* STA->STA */
#define IEEE80211_FC1_DIR_TODS              0x01    /* STA->AP  */
#define IEEE80211_FC1_DIR_FROMDS            0x02    /* AP ->STA */
#define IEEE80211_FC1_DIR_DSTODS            0x03    /* AP ->AP  */

#define IEEE80211_FC1_MORE_FRAG             0x04
#define IEEE80211_FC1_RETRY                 0x08
#define IEEE80211_FC1_PWR_MGT               0x10
#define IEEE80211_FC1_MORE_DATA             0x20
#define IEEE80211_FC1_WEP                   0x40
#define IEEE80211_FC1_ORDER                 0x80

#define IEEE80211_NWID_LEN                  32

/*
 * 802.11 rate set.
 */
#define IEEE80211_RATE_SIZE     8       /* 802.11 standard */
#define IEEE80211_RATE_MAXSIZE  15      /* max rates we'll handle */

#define WMM_NUM_AC                  4   /* 4 AC categories */

#ifdef WAPI_ENABLE
#define  WLAN_EID_WAPI      68
#endif

#define ATH_OUI             0x7f0300        /* Atheros OUI */
#define ATH_OUI_TYPE        0x01
#define ATH_OUI_SUBTYPE     0x01
#define ATH_OUI_VERSION     0x00

#define WPA_OUI             0xf25000
#define WPA_OUI_TYPE        0x01
#define WPA_VERSION         1          /* current supported version */

#define WPA_CSE_NULL        0x00
#define WPA_CSE_WEP40       0x01
#define WPA_CSE_TKIP        0x02
#define WPA_CSE_CCMP        0x04
#define WPA_CSE_WEP104      0x05

#define WPA_ASE_NONE        0x00
#define WPA_ASE_8021X_UNSPEC    0x01
#define WPA_ASE_8021X_PSK   0x02

#define RSN_CAP_PREAUTH         0x01

#define WMM_OUI                 0xf25000
#define WMM_OUI_TYPE            0x02
#define WMM_INFO_OUI_SUBTYPE    0x00
#define WMM_PARAM_OUI_SUBTYPE   0x01
#define WMM_VERSION             1

/* WMM stream classes */
#define WMM_NUM_AC  4
#define WMM_AC_BE   0       /* best effort */
#define WMM_AC_BK   1       /* background */
#define WMM_AC_VI   2       /* video */
#define WMM_AC_VO   3       /* voice */

typedef enum {
    TSPEC_STATUS_CODE_ADMISSION_ACCEPTED = 0,
    TSPEC_STATUS_CODE_ADDTS_INVALID_PARAMS = 0x1,
    TSPEC_STATUS_CODE_ADDTS_REQUEST_REFUSED = 0x3,
    TSPEC_STATUS_CODE_UNSPECIFIED_QOS_RELATED_FAILURE = 0xC8,
    TSPEC_STATUS_CODE_REQUESTED_REFUSED_POLICY_CONFIGURATION = 0xC9,
    TSPEC_STATUS_CODE_INSUFFCIENT_BANDWIDTH = 0xCA,
    TSPEC_STATUS_CODE_INVALID_PARAMS = 0xCB,
    TSPEC_STATUS_CODE_DELTS_SENT    = 0x30,
    TSPEC_STATUS_CODE_DELTS_RECV    = 0x31,
} TSPEC_STATUS_CODE;

#define TSPEC_TSID_MASK             0xF
#define TSPEC_TSID_S                1

/*
 * WMM/802.11e Tspec Element
 */
typedef struct wmm_tspec_ie_t {
    u8 elementId;
    u8 len;
    u8 oui[3];
    u8 ouiType;
    u8 ouiSubType;
    u8 version;
    u16 tsInfo_info;
    u8 tsInfo_reserved;
    u16 nominalMSDU;
    u16 maxMSDU;
    u32 minServiceInt;
    u32 maxServiceInt;
    u32 inactivityInt;
    u32 suspensionInt;
    u32 serviceStartTime;
    u32 minDataRate;
    u32 meanDataRate;
    u32 peakDataRate;
    u32 maxBurstSize;
    u32 delayBound;
    u32 minPhyRate;
    u16 sba;
    u16 mediumTime;
} __attribute__ ((packed)) WMM_TSPEC_IE;

#endif /* _NET80211_IEEE80211_H_ */
