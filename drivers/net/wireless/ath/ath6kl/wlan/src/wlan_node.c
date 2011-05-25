//------------------------------------------------------------------------------
// <copyright file="wlan_node.c" company="Atheros">
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
// IEEE 802.11 node handling support.
//
// Author(s): ="Atheros"
//==============================================================================
#define ATH_MODULE_NAME wlan
#include <a_debug.h>
#include "htc.h"
#include <ieee80211.h>
#include <ath6kl.h>
#include <ieee80211_node.h>
#include <wmi.h>

#define ATH_DEBUG_WLAN ATH_DEBUG_MAKE_MODULE_MASK(0)

#ifdef ATH_DEBUG_MODULE

static struct ath_debug_mask_description wlan_debug_desc[] = {
    { ATH_DEBUG_WLAN , "General WLAN Node Tracing"},
};

ATH_DEBUG_INSTANTIATE_MODULE_VAR(wlan,
                                 "wlan",
                                 "WLAN Node Management",
                                 ATH_DEBUG_MASK_DEFAULTS,
                                 ATH_DEBUG_DESCRIPTION_COUNT(wlan_debug_desc),
                                 wlan_debug_desc);
                                 
#endif

struct bss * wlan_node_alloc(struct ieee80211_node_table *nt, int wh_size)
{
    struct bss *ni;

    ni = kmalloc(sizeof(struct bss), GFP_ATOMIC);

    if ((ni != NULL) &&  wh_size) {
        ni->ni_buf = kmalloc(wh_size, GFP_ATOMIC);
        if (ni->ni_buf == NULL) {
            kfree(ni);
            return NULL;
        }
    } else {
        return ni;
    }

    /* Make sure our lists are clean */
    ni->ni_list_next = NULL;
    ni->ni_list_prev = NULL;
    ni->ni_hash_next = NULL;
    ni->ni_hash_prev = NULL;

    /*
     * ni_scangen never initialized before and during suspend/resume of winmobile,
     * that some junk has been stored in this, due to this scan list didn't properly updated
     */
    ni->ni_scangen   = 0;

#ifdef OS_ROAM_MANAGEMENT
    ni->ni_si_gen    = 0;
#endif

    return ni;
}

void wlan_node_free(struct bss *ni)
{
    if (ni->ni_buf != NULL) {
        kfree(ni->ni_buf);
    }
    kfree(ni);
}

void wlan_setup_node(struct ieee80211_node_table *nt, struct bss *ni,
                     const u8 *macaddr)
{
    int hash;
    u32 timeout_val;

    memcpy(ni->ni_macaddr, macaddr, ETH_ALEN);
    hash = IEEE80211_NODE_HASH (macaddr);
    ieee80211_node_initref (ni);     /* mark referenced */

    timeout_val = nt->nt_nodeAge;

    ni->ni_tstamp = (jiffies / HZ) * 1000; /* in ms */
    ni->ni_actcnt = WLAN_NODE_INACT_CNT;

    spin_lock_bh(&nt->nt_nodelock);

    /* Insert at the end of the node list */
    ni->ni_list_next = NULL;
    ni->ni_list_prev = nt->nt_node_last;
    if(nt->nt_node_last != NULL) {
        nt->nt_node_last->ni_list_next = ni;
    }
    nt->nt_node_last = ni;
    if(nt->nt_node_first == NULL) {
        nt->nt_node_first = ni;
    }

    /* Insert into the hash list i.e. the bucket */
    if((ni->ni_hash_next = nt->nt_hash[hash]) != NULL) {
        nt->nt_hash[hash]->ni_hash_prev = ni;
    }
    ni->ni_hash_prev = NULL;
    nt->nt_hash[hash] = ni;

    spin_unlock_bh(&nt->nt_nodelock);
}

static struct bss * _ieee80211_find_node(struct ieee80211_node_table *nt,
                                    const u8 *macaddr)
{
    struct bss *ni;
    int hash;

    hash = IEEE80211_NODE_HASH(macaddr);
    for(ni = nt->nt_hash[hash]; ni; ni = ni->ni_hash_next) {
	if (memcmp(ni->ni_macaddr, macaddr, ETH_ALEN) == 0) {
            ieee80211_node_incref(ni);  /* mark referenced */
            return ni;
        }
    }

    return NULL;
}

struct bss * wlan_find_node(struct ieee80211_node_table *nt, const u8 *macaddr)
{
    struct bss *ni;

    spin_lock_bh(&nt->nt_nodelock);
    ni = _ieee80211_find_node(nt, macaddr);
    spin_unlock_bh(&nt->nt_nodelock);

    return ni;
}

/*
 * Reclaim a node.  If this is the last reference count then
 * do the normal free work.  Otherwise remove it from the node
 * table and mark it gone by clearing the back-reference.
 */
void wlan_node_reclaim(struct ieee80211_node_table *nt, struct bss *ni)
{
    spin_lock_bh(&nt->nt_nodelock);

    if(ni->ni_list_prev == NULL) {
        /* First in list so fix the list head */
        nt->nt_node_first = ni->ni_list_next;
    } else {
        ni->ni_list_prev->ni_list_next = ni->ni_list_next;
    }

    if(ni->ni_list_next == NULL) {
        /* Last in list so fix list tail */
        nt->nt_node_last = ni->ni_list_prev;
    } else {
        ni->ni_list_next->ni_list_prev = ni->ni_list_prev;
    }

    if(ni->ni_hash_prev == NULL) {
        /* First in list so fix the list head */
        int hash;
        hash = IEEE80211_NODE_HASH(ni->ni_macaddr);
        nt->nt_hash[hash] = ni->ni_hash_next;
    } else {
        ni->ni_hash_prev->ni_hash_next = ni->ni_hash_next;
    }

    if(ni->ni_hash_next != NULL) {
        ni->ni_hash_next->ni_hash_prev = ni->ni_hash_prev;
    }
    wlan_node_free(ni);

    spin_unlock_bh(&nt->nt_nodelock);
}

static void wlan_node_dec_free(struct bss *ni)
{
    if (ieee80211_node_dectestref(ni)) {
        wlan_node_free(ni);
    }
}

void wlan_free_allnodes(struct ieee80211_node_table *nt)
{
    struct bss *ni;

    while ((ni = nt->nt_node_first) != NULL) {
        wlan_node_reclaim(nt, ni);
    }
}

void wlan_iterate_nodes(struct ieee80211_node_table *nt, wlan_node_iter_func *f,
                        void *arg)
{
    struct bss *ni;
    u32 gen;

    gen = ++nt->nt_scangen;

    spin_lock_bh(&nt->nt_nodelock);
    for (ni = nt->nt_node_first; ni; ni = ni->ni_list_next) {
        if (ni->ni_scangen != gen) {
            ni->ni_scangen = gen;
            (void) ieee80211_node_incref(ni);
            (*f)(arg, ni);
            wlan_node_dec_free(ni);
        }
    }
    spin_unlock_bh(&nt->nt_nodelock);
}

/* Node table support. */
void wlan_node_table_init(void *wmip, struct ieee80211_node_table *nt)
{
    int i;

    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN, ("node table = 0x%lx\n", (unsigned long)nt));

    spin_lock_init(&nt->nt_nodelock);

    
    nt->nt_node_first = nt->nt_node_last = NULL;
    for(i = 0; i < IEEE80211_NODE_HASHSIZE; i++)
    {
        nt->nt_hash[i] = NULL;
    }

    nt->nt_wmip = wmip;
    nt->nt_nodeAge = WLAN_NODE_INACT_TIMEOUT_MSEC;

    /*
     * nt_scangen never initialized before and during suspend/resume of winmobile,
     * that some junk has been stored in this, due to this scan list didn't properly updated
     */
    nt->nt_scangen   = 0;

#ifdef OS_ROAM_MANAGEMENT
    nt->nt_si_gen    = 0;
#endif
}

void wlan_refresh_inactive_nodes (struct ieee80211_node_table *nt)
{
    struct bss *bss, *nextBss;
    u8 myBssid[ETH_ALEN];
    u32 timeout_val;
    u32 now;

    now = (jiffies / HZ) * 1000; /* in ms */
    timeout_val = nt->nt_nodeAge;
    wmi_get_current_bssid(nt->nt_wmip, myBssid);

    bss = nt->nt_node_first;
    while (bss != NULL)    {
        nextBss = bss->ni_list_next;
        if (memcmp(myBssid, bss->ni_macaddr, sizeof(myBssid)) != 0) {
            if (((now - bss->ni_tstamp) > timeout_val)  || --bss->ni_actcnt == 0) {
               /* free up all but the current bss - if set */
                wlan_node_reclaim(nt, bss);
            }
        }
        bss = nextBss;
    }
}

void wlan_node_table_cleanup(struct ieee80211_node_table *nt)
{
    wlan_free_allnodes(nt);
}

struct bss * wlan_find_Ssidnode (struct ieee80211_node_table *nt, u8 *pSsid,
                            u32 ssidLength, bool bIsWPA2, bool bMatchSSID)
{
    struct bss   *ni = NULL;
    u8 *pIESsid = NULL;

    spin_lock_bh(&nt->nt_nodelock);

    for (ni = nt->nt_node_first; ni; ni = ni->ni_list_next) {
        pIESsid = ni->ni_cie.ie_ssid;
        if (pIESsid[1] <= 32) {

            /* Step 1 : Check SSID */
            if (memcmp (pSsid, &pIESsid[2], ssidLength) == 0) {
                /*
                 * Step 2.1 : Check MatchSSID is true, if so, return Matched SSID
                 * Profile, otherwise check whether WPA2 or WPA
                 */
                if (bMatchSSID == true) {
                    ieee80211_node_incref (ni);  /* mark referenced */
                    spin_unlock_bh(&nt->nt_nodelock);
                    return ni;
                }

                /* Step 2 : if SSID matches, check WPA or WPA2 */
                if (bIsWPA2 == true && ni->ni_cie.ie_rsn != NULL) {
                    ieee80211_node_incref (ni);  /* mark referenced */
                    spin_unlock_bh(&nt->nt_nodelock);
                    return ni;
                }
                if (bIsWPA2 == false && ni->ni_cie.ie_wpa != NULL) {
                    ieee80211_node_incref(ni);  /* mark referenced */
                    spin_unlock_bh(&nt->nt_nodelock);
                    return ni;
                }
            }
        }
    }

    spin_unlock_bh(&nt->nt_nodelock);

    return NULL;
}

void wlan_node_return (struct ieee80211_node_table *nt, struct bss *ni)
{
    spin_lock_bh(&nt->nt_nodelock);
    wlan_node_dec_free (ni);
    spin_unlock_bh(&nt->nt_nodelock);
}

void wlan_node_remove_core (struct ieee80211_node_table *nt, struct bss *ni)
{
    if(ni->ni_list_prev == NULL) {
        /* First in list so fix the list head */
        nt->nt_node_first = ni->ni_list_next;
    } else {
        ni->ni_list_prev->ni_list_next = ni->ni_list_next;
    }

    if(ni->ni_list_next == NULL) {
        /* Last in list so fix list tail */
        nt->nt_node_last = ni->ni_list_prev;
    } else {
        ni->ni_list_next->ni_list_prev = ni->ni_list_prev;
    }

    if(ni->ni_hash_prev == NULL) {
        /* First in list so fix the list head */
        int hash;
        hash = IEEE80211_NODE_HASH(ni->ni_macaddr);
        nt->nt_hash[hash] = ni->ni_hash_next;
    } else {
        ni->ni_hash_prev->ni_hash_next = ni->ni_hash_next;
    }

    if(ni->ni_hash_next != NULL) {
        ni->ni_hash_next->ni_hash_prev = ni->ni_hash_prev;
    }
}

struct bss * wlan_node_remove(struct ieee80211_node_table *nt, u8 *bssid)
{
    struct bss *bss, *nextBss;

    spin_lock_bh(&nt->nt_nodelock);
    bss = nt->nt_node_first;

    while (bss != NULL) {
        nextBss = bss->ni_list_next;

        if (memcmp(bssid, bss->ni_macaddr, 6) == 0) {
            wlan_node_remove_core (nt, bss);
            spin_unlock_bh(&nt->nt_nodelock);
            return bss;
        }

        bss = nextBss;
    }

    spin_unlock_bh(&nt->nt_nodelock);
    return NULL;
}
