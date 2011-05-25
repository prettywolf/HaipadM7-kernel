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

#ifndef _AR6XAPI_LINUX_H
#define _AR6XAPI_LINUX_H

struct ar6_softc;
enum ar6k_wlan_state;

void ar6000_ready_event(void *devt, u8 *datap, u8 phyCap,
                        u32 sw_ver, u32 abi_ver);
int ar6000_control_tx(void *devt, void *osbuf, enum htc_endpoint_id eid);
void ar6000_connect_event(struct ar6_softc *ar, u16 channel,
                          u8 *bssid, u16 listenInterval,
                          u16 beaconInterval, enum network_type networkType,
                          u8 beaconIeLen, u8 assocReqLen,
                          u8 assocRespLen,u8 *assocInfo);
void ar6000_disconnect_event(struct ar6_softc *ar, u8 reason,
                             u8 *bssid, u8 assocRespLen,
                             u8 *assocInfo, u16 protocolReasonStatus);
void ar6000_tkip_micerr_event(struct ar6_softc *ar, u8 keyid,
                              bool ismcast);
void ar6000_bitrate_rx(void *devt, s32 rateKbps);
void ar6000_channelList_rx(void *devt, s8 numChan, u16 *chanList);
void ar6000_regDomain_event(struct ar6_softc *ar, u32 regCode);
void ar6000_txPwr_rx(void *devt, u8 txPwr);
void ar6000_keepalive_rx(void *devt, u8 configured);
void ar6000_neighborReport_event(struct ar6_softc *ar, int numAps,
                                 struct wmi_neighbor_info *info);
void ar6000_scanComplete_event(struct ar6_softc *ar, int status);
void ar6000_targetStats_event(struct ar6_softc *ar,  u8 *ptr, u32 len);
void ar6000_rssiThreshold_event(struct ar6_softc *ar,
                                enum wmi_rssi_threshold_val newThreshold,
                                s16 rssi);
void ar6000_reportError_event(struct ar6_softc *, enum wmi_target_error_val errorVal);
void ar6000_cac_event(struct ar6_softc *ar, u8 ac, u8 cac_indication,
                                u8 statusCode, u8 *tspecSuggestion);
void ar6000_channel_change_event(struct ar6_softc *ar, u16 oldChannel, u16 newChannel);
void ar6000_hbChallengeResp_event(struct ar6_softc *, u32 cookie, u32 source);
void
ar6000_roam_tbl_event(struct ar6_softc *ar, struct wmi_target_roam_tbl *pTbl);

void
ar6000_roam_data_event(struct ar6_softc *ar, struct wmi_target_roam_data *p);

void
ar6000_wow_list_event(struct ar6_softc *ar, u8 num_filters,
                      struct wmi_get_wow_list_reply *wow_reply);

void ar6000_pmkid_list_event(void *devt, u8 numPMKID,
                             struct wmi_pmkid *pmkidList, u8 *bssidList);

void ar6000_tx_retry_err_event(void *devt);

void ar6000_snrThresholdEvent_rx(void *devt,
                                 enum wmi_snr_threshold_val newThreshold,
                                 u8 snr);

void ar6000_lqThresholdEvent_rx(void *devt, enum wmi_lq_threshold_val range, u8 lqVal);


void ar6000_ratemask_rx(void *devt, u32 ratemask);

int ar6000_get_driver_cfg(struct net_device *dev,
                                u16 cfgParam,
                                void *result);
void ar6000_bssInfo_event_rx(struct ar6_softc *ar, u8 *data, int len);

void ar6000_peer_event(void *devt, u8 eventCode, u8 *bssid);

void ar6000_indicate_tx_activity(void *devt, u8 trafficClass, bool Active);
enum htc_endpoint_id  ar6000_ac2_endpoint_id ( void * devt, u8 ac);
u8 ar6000_endpoint_id2_ac (void * devt, enum htc_endpoint_id ep );

void ar6000_pspoll_event(struct ar6_softc *ar,u8 aid);

void ar6000_dtimexpiry_event(struct ar6_softc *ar);

void ar6000_aggr_rcv_addba_req_evt(struct ar6_softc *ar, struct wmi_addba_req_event *cmd);
void ar6000_aggr_rcv_addba_resp_evt(struct ar6_softc *ar, struct wmi_addba_resp_event *cmd);
void ar6000_aggr_rcv_delba_req_evt(struct ar6_softc *ar, struct wmi_delba_event *cmd);

#ifdef WAPI_ENABLE
void ap_wapi_rekey_event(struct ar6_softc *ar, u8 type, u8 *mac);
#endif

int ar6000_connect_to_ap(struct ar6_softc *ar);
int ar6000_disconnect(struct ar6_softc *ar);
int ar6000_update_wlan_pwr_state(struct ar6_softc *ar, enum ar6k_wlan_state state, bool suspending);

#ifdef CONFIG_PM
void ar6000_check_wow_status(struct ar6_softc *ar, struct sk_buff *skb, bool isEvent);
#endif

#endif
