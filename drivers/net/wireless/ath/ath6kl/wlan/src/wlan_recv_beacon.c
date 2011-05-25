//------------------------------------------------------------------------------
// <copyright file="wlan_recv_beacon.c" company="Atheros">
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
// IEEE 802.11 input handling.
//
// Author(s): ="Atheros"
//==============================================================================

#include <linux/ieee80211.h>
#include <ath6kl.h>
#include <ieee80211.h>

/* unaligned little endian access */

#define LE_READ_4(p)                            \
    ((u32)                            \
     ((((u8 *)(p))[0]      ) | (((u8 *)(p))[1] <<  8) | \
      (((u8 *)(p))[2] << 16) | (((u8 *)(p))[3] << 24)))


static int __inline
iswpaoui(const u8 *frm)
{
    return frm[1] > 3 && LE_READ_4(frm+2) == ((WPA_OUI_TYPE<<24)|WPA_OUI);
}

static int __inline
iswmmoui(const u8 *frm)
{
    return frm[1] > 3 && LE_READ_4(frm+2) == ((WMM_OUI_TYPE<<24)|WMM_OUI);
}

static int __inline
isatherosoui(const u8 *frm)
{
    return frm[1] > 3 && LE_READ_4(frm+2) == ((ATH_OUI_TYPE<<24)|ATH_OUI);
}

static int __inline
iswscoui(const u8 *frm)
{
    return frm[1] > 3 && LE_READ_4(frm+2) == ((0x04<<24)|WPA_OUI);
}

int
wlan_parse_beacon(u8 *buf, int frame_len, struct ieee80211_common_ie *cie)
{
    u8 *frm, *efrm;
    u8 elemid_ssid = false;

    frm = buf;
    efrm = (u8 *) (frm + frame_len);

    /*
     * beacon/probe response frame format
     *  [8] time stamp
     *  [2] beacon interval
     *  [2] capability information
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] country information
     *  [tlv] parameter set (FH/DS)
     *  [tlv] erp information
     *  [tlv] extended supported rates
     *  [tlv] WMM
     *  [tlv] WPA or RSN
     *  [tlv] Atheros Advanced Capabilities
     */
    if((efrm - frm) < 12)
         return A_EINVAL;

    memset(cie, 0, sizeof(*cie));

    cie->ie_tstamp = frm; frm += 8;
    cie->ie_beaconInt = *(u16 *)frm;  frm += 2;
    cie->ie_capInfo = *(u16 *)frm;  frm += 2;
    cie->ie_chan = 0;

    while (frm < efrm) {
        switch (*frm) {
        case WLAN_EID_SSID:
            if (!elemid_ssid) {
                cie->ie_ssid = frm;
                elemid_ssid = true;
            }
            break;
        case WLAN_EID_SUPP_RATES:
            cie->ie_rates = frm;
            break;
        case WLAN_EID_COUNTRY:
            cie->ie_country = frm;
            break;
        case WLAN_EID_FH_PARAMS:
            break;
        case WLAN_EID_DS_PARAMS:
            cie->ie_chan = frm[2];
            break;
        case WLAN_EID_TIM:
            cie->ie_tim = frm;
            break;
        case WLAN_EID_IBSS_PARAMS:
            break;
        case WLAN_EID_EXT_SUPP_RATES:
            cie->ie_xrates = frm;
            break;
        case WLAN_EID_ERP_INFO:
            if (frm[1] != 1) {
                //A_PRINTF("Discarding ERP Element - Bad Len\n");
                return A_EINVAL;
            }
            cie->ie_erp = frm[2];
            break;
        case WLAN_EID_RSN:
            cie->ie_rsn = frm;
            break;
        case WLAN_EID_HT_CAPABILITY:
            cie->ie_htcap = frm;
            break;
        case WLAN_EID_HT_INFORMATION:
            cie->ie_htop = frm;
            break;
#ifdef WAPI_ENABLE
	case WLAN_EID_WAPI:
            cie->ie_wapi = frm;
            break;
#endif
        case WLAN_EID_VENDOR_SPECIFIC:
            if (iswpaoui(frm)) {
                cie->ie_wpa = frm;
            } else if (iswmmoui(frm)) {
                cie->ie_wmm = frm;
            } else if (isatherosoui(frm)) {
                cie->ie_ath = frm;
            } else if(iswscoui(frm)) {
                cie->ie_wsc = frm;
            }
            break;
        default:
            break;
        }
        frm += frm[1] + 2;
    }

    if((cie->ie_rates == NULL) || (cie->ie_rates[1] > IEEE80211_RATE_MAXSIZE))
	return A_EINVAL;

    if((cie->ie_ssid == NULL) || (cie->ie_ssid[1] > IEEE80211_NWID_LEN))
	return A_EINVAL;

    return 0;
}
