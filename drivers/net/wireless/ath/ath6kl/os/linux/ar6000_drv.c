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

/*
 * This driver is a pseudo ethernet driver to access the Atheros AR6000
 * WLAN Device
 */

#include "ar6000_drv.h"
#include "ar6xapi_linux.h"
#include "cfg80211.h"
#include "htc.h"
#include "ath6kl.h"
#include "reg.h"

/* LINUX_HACK_FUDGE_FACTOR -- this is used to provide a workaround for linux behavior.  When
 *  the meta data was added to the header it was found that linux did not correctly provide
 *  enough headroom.  However when more headroom was requested beyond what was truly needed
 *  Linux gave the requested headroom. Therefore to get the necessary headroom from Linux
 *  the driver requests more than is needed by the amount = LINUX_HACK_FUDGE_FACTOR */
#define LINUX_HACK_FUDGE_FACTOR 16
#define BDATA_BDADDR_OFFSET     28

u8 bcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#ifdef DEBUG

#define  ATH_DEBUG_DBG_LOG       ATH_DEBUG_MAKE_MODULE_MASK(0)
#define  ATH_DEBUG_WLAN_CONNECT  ATH_DEBUG_MAKE_MODULE_MASK(1)
#define  ATH_DEBUG_WLAN_SCAN     ATH_DEBUG_MAKE_MODULE_MASK(2)
#define  ATH_DEBUG_WLAN_TX       ATH_DEBUG_MAKE_MODULE_MASK(3)
#define  ATH_DEBUG_WLAN_RX       ATH_DEBUG_MAKE_MODULE_MASK(4)
#define  ATH_DEBUG_HTC_RAW       ATH_DEBUG_MAKE_MODULE_MASK(5)

static struct ath_debug_mask_description driver_debug_desc[] = {
    { ATH_DEBUG_DBG_LOG      , "Target Debug Logs"},
    { ATH_DEBUG_WLAN_CONNECT , "WLAN connect"},
    { ATH_DEBUG_WLAN_SCAN    , "WLAN scan"},
    { ATH_DEBUG_WLAN_TX      , "WLAN Tx"},
    { ATH_DEBUG_WLAN_RX      , "WLAN Rx"},
    { ATH_DEBUG_HTC_RAW      , "HTC Raw IF tracing"},
};

ATH_DEBUG_INSTANTIATE_MODULE_VAR(driver,
                                 "driver",
                                 "Linux Driver Interface",
                                 ATH_DEBUG_MASK_DEFAULTS | ATH_DEBUG_WLAN_SCAN |
                                 ATH_DEBUG_HCI_BRIDGE,
                                 ATH_DEBUG_DESCRIPTION_COUNT(driver_debug_desc),
                                 driver_debug_desc);

#endif


#define IS_MAC_NULL(mac) (mac[0]==0 && mac[1]==0 && mac[2]==0 && mac[3]==0 && mac[4]==0 && mac[5]==0)
#define IS_MAC_BCAST(mac) (*mac==0xff)

#define DESCRIPTION "Driver to access the Atheros AR600x Device, version " __stringify(__VER_MAJOR_) "." __stringify(__VER_MINOR_) "." __stringify(__VER_PATCH_) "." __stringify(__BUILD_NUMBER_)

MODULE_AUTHOR("Atheros Communications, Inc.");
MODULE_DESCRIPTION(DESCRIPTION);
MODULE_LICENSE("Dual BSD/GPL");

unsigned int processDot11Hdr = 0;

int wlaninitmode = WLAN_INIT_MODE_DEFAULT;
bool bypasswmi;
unsigned int debug_mask = 0;
unsigned int wmitimeout = 2;
unsigned int wlanNodeCaching = 1;
unsigned int logWmiRawMsgs = 0;
unsigned int regscanmode;
unsigned int fwmode = 1;
unsigned int mbox_yield_limit = 99;
unsigned int enablerssicompensation = 0;
int reduce_credit_dribble = 1 + HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_ONE_HALF;

unsigned int nohifscattersupport = NOHIFSCATTERSUPPORT_DEFAULT;

unsigned int csumOffload=0;

module_param(wlaninitmode, int, 0644);
module_param(bypasswmi, bool, 0644);
module_param(debug_mask, uint, 0644);
module_param(wmitimeout, uint, 0644);
module_param(wlanNodeCaching, uint, 0644);
module_param(logWmiRawMsgs, uint, 0644);
module_param(fwmode, uint, 0644);
module_param(mbox_yield_limit, uint, 0644);
module_param(reduce_credit_dribble, int, 0644);
module_param(enablerssicompensation, uint, 0644);
module_param(processDot11Hdr, uint, 0644);
module_param(csumOffload, uint, 0644);
module_param(nohifscattersupport, uint, 0644);

/* in 2.6.10 and later this is now a pointer to a uint */
unsigned int _mboxnum = HTC_MAILBOX_NUM_MAX;
#define mboxnum &_mboxnum

#ifdef DEBUG
u32 g_dbg_flags = DBG_DEFAULTS;
unsigned int debugflags = 0;
int debugdriver = 0;
unsigned int debughtc = 0;
unsigned int debugbmi = 0;
unsigned int debughif = 0;
unsigned int txcreditsavailable[HTC_MAILBOX_NUM_MAX] = {0};
unsigned int txcreditsconsumed[HTC_MAILBOX_NUM_MAX] = {0};
unsigned int txcreditintrenable[HTC_MAILBOX_NUM_MAX] = {0};
unsigned int txcreditintrenableaggregate[HTC_MAILBOX_NUM_MAX] = {0};
module_param(debugflags, uint, 0644);
module_param(debugdriver, int, 0644);
module_param(debughtc, uint, 0644);
module_param(debugbmi, uint, 0644);
module_param(debughif, uint, 0644);
module_param_array(txcreditsavailable, uint, mboxnum, 0644);
module_param_array(txcreditsconsumed, uint, mboxnum, 0644);
module_param_array(txcreditintrenable, uint, mboxnum, 0644);
module_param_array(txcreditintrenableaggregate, uint, mboxnum, 0644);

#endif /* DEBUG */

u8 custDataAR6003[AR6003_CUST_DATA_SIZE];
unsigned int resetok = 1;
module_param(resetok, uint, 0644);

typedef struct user_rssi_compensation_t {
    u16 customerID;
    union {
    u16 a_enable;
    u16 bg_enable;
    u16 enable;
    };
    s16 bg_param_a;
    s16 bg_param_b;
    s16 a_param_a;
    s16 a_param_b;
    u32 reserved;
} USER_RSSI_CPENSATION;

static USER_RSSI_CPENSATION rssi_compensation_param;

int reconnect_flag = 0;

/* Function declarations */

int ar6000_init(struct net_device *dev);
static int ar6000_open(struct net_device *dev);
static int ar6000_close(struct net_device *dev);
static int ar6000_data_tx(struct sk_buff *skb, struct net_device *dev);
static void	ar6000_set_multicast_list(struct net_device *dev);
static struct net_device_stats *ar6000_get_stats(struct net_device *dev);

/*
 * Static variables
 */

struct net_device *ar6000_devices[MAX_AR6000];
static void ar6000_free_cookie(struct ar6_softc *ar, struct ar_cookie * cookie);
static struct ar_cookie *ar6000_alloc_cookie(struct ar6_softc *ar);

static int ar6000_reinstall_keys(struct ar6_softc *ar,u8 key_op_ctrl);

static struct ar_cookie s_ar_cookie_mem[MAX_COOKIE_NUM];

static struct net_device_ops ar6000_netdev_ops = {
    .ndo_init               = NULL,
    .ndo_open               = ar6000_open,
    .ndo_stop               = ar6000_close,
    .ndo_get_stats          = ar6000_get_stats,
    .ndo_start_xmit         = ar6000_data_tx,
    .ndo_set_multicast_list = ar6000_set_multicast_list,
};

#define AR6K_PATCH_DOWNLOAD_ADDRESS(_param, _ver) do { \
    if ((_ver) == AR6003_REV1_VERSION) { \
        (_param) = AR6003_REV1_PATCH_DOWNLOAD_ADDRESS; \
    } else if ((_ver) == AR6003_REV2_VERSION) { \
        (_param) = AR6003_REV2_PATCH_DOWNLOAD_ADDRESS; \
    } else { \
       AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown Version: %d\n", _ver)); \
       A_ASSERT(0); \
    } \
} while (0)

#define AR6K_DATA_DOWNLOAD_ADDRESS(_param, _ver) do { \
    if ((_ver) == AR6003_REV1_VERSION) { \
        (_param) = AR6003_REV1_OTP_DATA_ADDRESS; \
    } else if ((_ver) == AR6003_REV2_VERSION) { \
        (_param) = AR6003_REV2_OTP_DATA_ADDRESS; \
    } else { \
       AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown Version: %d\n", _ver)); \
       A_ASSERT(0); \
    } \
} while (0)

#define AR6K_DATASET_PATCH_ADDRESS(_param, _ver) do { \
        if ((_ver) == AR6003_REV2_VERSION) { \
                (_param) = AR6003_REV2_DATASET_PATCH_ADDRESS; \
        } else if ((_ver) == AR6003_REV3_VERSION) { \
                (_param) = AR6003_REV3_DATASET_PATCH_ADDRESS; \
        } else { \
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown Version: %d\n", _ver)); \
        A_ASSERT(0); \
        } \
} while (0)

#define AR6K_APP_LOAD_ADDRESS(_param, _ver) do { \
        if ((_ver) == AR6003_REV2_VERSION) { \
                (_param) = AR6003_REV2_APP_LOAD_ADDRESS; \
        } else if ((_ver) == AR6003_REV3_VERSION) { \
                (_param) = AR6003_REV3_APP_LOAD_ADDRESS; \
        } else { \
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown Version: %d\n", _ver)); \
        A_ASSERT(0); \
        } \
} while (0)

#define AR6K_APP_START_OVERRIDE_ADDRESS(_param, _ver) do { \
        if ((_ver) == AR6003_REV2_VERSION) { \
                (_param) = AR6003_REV2_APP_START_OVERRIDE; \
        } else if ((_ver) == AR6003_REV3_VERSION) { \
                (_param) = AR6003_REV3_APP_START_OVERRIDE; \
        } else { \
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown Version: %d\n", _ver)); \
        A_ASSERT(0); \
        } \
} while (0)
#ifdef USE_4BYTE_REGISTER_ACCESS

/* set the window address register (using 4-byte register access ). */
static int ar6000_SetAddressWindowRegister(struct hif_device *hifDevice,
					   u32 RegisterAddr, u32 Address)
{
	int status;
	u8 addrValue[4];
	s32 i;

	/* write bytes 1,2,3 of the register to set the upper address bytes,
	 * the LSB is written last to initiate the access cycle */

	for (i = 1; i <= 3; i++) {
		/* fill the buffer with the address byte value we want to hit 4 times*/
		addrValue[0] = ((u8 *)&Address)[i];
		addrValue[1] = addrValue[0];
		addrValue[2] = addrValue[0];
		addrValue[3] = addrValue[0];

		/* hit each byte of the register address with a 4-byte write
		 * operation to the same address, this is a harmless operation */
		status = hif_read_write(hifDevice,
				RegisterAddr+i,
				addrValue,
				4,
				HIF_WR_SYNC_BYTE_FIX,
				NULL);
		if (status)
			break;
	}

	if (status) {
		AR_DEBUG_PRINTF(ATH_LOG_ERR, ("Cannot write initial bytes of 0x%x to window reg: 0x%X \n",
				Address, RegisterAddr));
		return status;
	}

	/* write the address register again, this time write the whole 4-byte value.
	 * The effect here is that the LSB write causes the cycle to start, the extra
	 * 3 byte write to bytes 1,2,3 has no effect since we are writing the same values again */
	status = hif_read_write(hifDevice,
			RegisterAddr,
			(u8 *)(&Address),
			4,
			HIF_WR_SYNC_BYTE_INC,
			NULL);

	if (status) {
		AR_DEBUG_PRINTF(ATH_LOG_ERR, ("Cannot write 0x%x to window reg: 0x%X \n",
					Address, RegisterAddr));
		return status;
	}

	return 0;
}

#else

static int ar6000_SetAddressWindowRegister(struct hif_device *hifDevice,
					   u32 RegisterAddr, u32 Address)
{
	int status;

	/* write bytes 1,2,3 of the register to set the upper address bytes, the LSB is written
	 * last to initiate the access cycle */
	status = hif_read_write(hifDevice,
			RegisterAddr+1,
			((u8 *)(&Address))+1,
			sizeof(u32)-1,
			HIF_WR_SYNC_BYTE_INC,
			NULL);

	if (status) {
		AR_DEBUG_PRINTF(ATH_LOG_ERR, ("Cannot write initial bytes of 0x%x to window reg: 0x%X \n",
				RegisterAddr, Address));
		return status;
	}

	/* write the LSB of the register, this initiates the operation */
	status = hif_read_write(hifDevice,
			RegisterAddr,
			(u8 *)(&Address),
			sizeof(u8),
			HIF_WR_SYNC_BYTE_INC,
			NULL);

	if (status) {
		AR_DEBUG_PRINTF(ATH_LOG_ERR, ("Cannot write 0x%x to window reg: 0x%X \n",
				RegisterAddr, Address));
		return status;
	}

	return 0;
}

#endif

/*
 * Read from the AR6000 through its diagnostic window.
 * No cooperation from the Target is required for this.
 */
int ar6000_ReadRegDiag(struct hif_device *hifDevice,
			      u32 *address, u32 *data)
{
	int status;

	/* set window register to start read cycle */
	status = ar6000_SetAddressWindowRegister(hifDevice,
			WINDOW_READ_ADDR_ADDRESS,
			*address);

	if (status)
		return status;

	/* read the data */
	status = hif_read_write(hifDevice,
			WINDOW_DATA_ADDRESS,
			(u8 *)data,
			sizeof(u32),
			HIF_RD_SYNC_BYTE_INC,
			NULL);
	if (status) {
		AR_DEBUG_PRINTF(ATH_LOG_ERR, ("Cannot read from WINDOW_DATA_ADDRESS\n"));
		return status;
	}

	return status;
}

/*
 * Write to the AR6000 through its diagnostic window.
 * No cooperation from the Target is required for this.
 */
static int ar6000_WriteRegDiag(struct hif_device *hifDevice, u32 *address,
			       u32 *data)
{
	int status;

	/* set write data */
	status = hif_read_write(hifDevice,
			WINDOW_DATA_ADDRESS,
			(u8 *)data,
			sizeof(u32),
			HIF_WR_SYNC_BYTE_INC,
			NULL);
	if (status) {
		AR_DEBUG_PRINTF(ATH_LOG_ERR, ("Cannot write 0x%x to WINDOW_DATA_ADDRESS\n", *data));
		return status;
	}

	/* set window register, which starts the write cycle */
	return ar6000_SetAddressWindowRegister(hifDevice,
			WINDOW_WRITE_ADDR_ADDRESS,
			*address);
}

int ar6000_access_datadiag(struct hif_device *hifDevice, u32 address,
			   u8 *data, u32 length, bool read)
{
	u32 count;
	int status = 0;
	int (*diag_func) (struct hif_device *, u32 *, u32 *);

	diag_func = read ? ar6000_ReadRegDiag : ar6000_WriteRegDiag;
	for (count = 0; count < length; count += 4, address += 4) {
		status = (diag_func) (hifDevice, &address, (u32 *)&data[count]);
		if (status)
			break;
	}

	return status;
}

int ar6000_ReadDataDiag(struct hif_device *hifDevice, u32 address,
		u8 *data, u32 length)
{
	u32 count;
	int status = 0;

	for (count = 0; count < length; count += 4, address += 4) {
		if ((status = ar6000_ReadRegDiag(hifDevice, &address,
				(u32 *) &data[count])) != 0)
			break;
	}

	return status;
}

int
ar6000_set_host_app_area(struct ar6_softc *ar)
{
    u32 address, data;
    struct host_app_area_s host_app_area;

    /* Fetch the address of the host_app_area_s instance in the host interest area */
    address = TARG_VTOP(ar->arTargetType, HOST_INTEREST_ITEM_ADDRESS(ar, hi_app_host_interest));
    if (ar6000_ReadRegDiag(ar->arHifDevice, &address, &data) != 0) {
        return A_ERROR;
    }
    address = TARG_VTOP(ar->arTargetType, data);
    host_app_area.wmi_protocol_ver = WMI_PROTOCOL_VERSION;
    if (ar6000_access_datadiag(ar->arHifDevice, address,
                             (u8 *)&host_app_area,
                             sizeof(struct host_app_area_s), false))
    {
        return A_ERROR;
    }

    return 0;
}

struct ar6k_sta *
ieee80211_find_conn(struct ar6_softc *ar, u8 *node_addr)
{
    struct ar6k_sta *conn = NULL;
    u8 i, max_conn;

    switch(ar->arNetworkType) {
        case AP_NETWORK:
            max_conn = AP_MAX_NUM_STA;
            break;
        default:
            max_conn=0;
            break;
    }

    for (i = 0; i < max_conn; i++) {
        if (memcmp(node_addr, ar->sta_list[i].mac, ETH_ALEN) == 0) {
            conn = &ar->sta_list[i];
            break;
        }
    }

    return conn;
}

struct ar6k_sta *ieee80211_find_conn_for_aid(struct ar6_softc *ar, u8 aid)
{
    struct ar6k_sta *conn = NULL;
    u8 ctr;

    for (ctr = 0; ctr < AP_MAX_NUM_STA; ctr++) {
        if (ar->sta_list[ctr].aid == aid) {
            conn = &ar->sta_list[ctr];
            break;
        }
    }
    return conn;
}

#ifdef WAPI_ENABLE
static int ap_set_wapi_key(struct ar6_softc *ar, void *ikey)
{
    struct ieee80211req_key *ik = (struct ieee80211req_key *)ikey;
    enum key_usage   keyUsage = 0;
    int    status;

    if (memcmp(ik->ik_macaddr, bcast_mac, ETH_ALEN) == 0) {
        keyUsage = GROUP_USAGE;
    } else {
        keyUsage = PAIRWISE_USAGE;
    }
    A_PRINTF("WAPI_KEY: Type:%d ix:%d mac:%02x:%02x len:%d\n",
        keyUsage, ik->ik_keyix, ik->ik_macaddr[4], ik->ik_macaddr[5],
        ik->ik_keylen);

    status = wmi_addKey_cmd(ar->arWmi, ik->ik_keyix, WAPI_CRYPT, keyUsage,
                            ik->ik_keylen, (u8 *)&ik->ik_keyrsc,
                            ik->ik_keydata, KEY_OP_INIT_VAL, ik->ik_macaddr,
                            SYNC_BOTH_WMIFLAG);

    if (0 != status) {
        return -EIO;
    }
    return 0;
}
#endif

static s16 rssi_compensation_calc(struct ar6_softc *ar, s16 rssi)
{
	if (rssi_compensation_param.enable) {
		if (ar->arBssChannel > 5000) {
			AR_DEBUG_PRINTF(ATH_DEBUG_INFO, (">>> 11a\n"));
			AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("rssi before compensation  = %d\n", rssi));
			rssi = rssi * rssi_compensation_param.a_param_a + rssi_compensation_param.a_param_b;
			rssi = (rssi-50) /100;
			AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("rssi after compensation = %d\n", rssi));
		} else {
			AR_DEBUG_PRINTF(ATH_DEBUG_INFO, (">>> 11bg\n"));
			AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("rssi before compensation  = %d\n", rssi));
			rssi = rssi * rssi_compensation_param.bg_param_a + rssi_compensation_param.bg_param_b;
			rssi = (rssi-50) /100;
			AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("rssi after compensation = %d\n", rssi));
		}
	}

	return rssi;
}

#define bmifn(fn) do { \
    if ((fn) < 0) { \
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("BMI operation failed: %d\n", __LINE__)); \
        return A_ERROR; \
    } \
} while(0)

#ifdef SOFTMAC_FILE_USED
#define AR6003_MAC_ADDRESS_OFFSET     0x16
static
void calculate_crc(u32 TargetType, u8 *eeprom_data)
{
    u16 *ptr_crc;
    u16 *ptr16_eeprom;
    u16 checksum;
    u32 i;
    u32 eeprom_size;

    eeprom_size = 768;
    ptr_crc = (u16 *)((u8 *)eeprom_data + 0x04);


    // Clear the crc
    *ptr_crc = 0;

    // Recalculate new CRC
    checksum = 0;
    ptr16_eeprom = (u16 *)eeprom_data;
    for (i = 0;i < eeprom_size; i += 2)
    {
        checksum = checksum ^ (*ptr16_eeprom);
        ptr16_eeprom++;
    }
    checksum = 0xFFFF ^ checksum;
    *ptr_crc = checksum;
}

static void 
ar6000_softmac_update(struct ar6_softc *ar, u8 *eeprom_data, size_t size)
{
    const char *source = "random generated";
    const struct firmware *softmac_entry;
    u8 *ptr_mac;
    switch (ar->arTargetType) {
    case TARGET_TYPE_AR6003:
        ptr_mac = (u8 *)((u8 *)eeprom_data + AR6003_MAC_ADDRESS_OFFSET);
        break;
    default:
	AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Invalid Target Type\n"));
        return;
    }
	printk(KERN_DEBUG "MAC from EEPROM %pM\n", ptr_mac);

    /* create a random MAC in case we cannot read file from system */
    ptr_mac[0] = 0;
    ptr_mac[1] = 0x03;
    ptr_mac[2] = 0x7F;
    ptr_mac[3] = random32() & 0xff; 
    ptr_mac[4] = random32() & 0xff; 
    ptr_mac[5] = random32() & 0xff; 
    if ((request_firmware(&softmac_entry, "softmac", ((struct device *)ar->osDevInfo.pOSDevice))) == 0)
    {
        char *macbuf = A_MALLOC_NOWAIT(softmac_entry->size+1);
        if (macbuf) {            
            unsigned int softmac[6];
            memcpy(macbuf, softmac_entry->data, softmac_entry->size);
            macbuf[softmac_entry->size] = '\0';
            if (sscanf(macbuf, "%02x:%02x:%02x:%02x:%02x:%02x", 
                        &softmac[0], &softmac[1], &softmac[2],
                        &softmac[3], &softmac[4], &softmac[5])==6) {
                int i;
                for (i=0; i<6; ++i) {
                    ptr_mac[i] = softmac[i] & 0xff;
                }
                source = "softmac file";
            }
            kfree(macbuf);
        }
        release_firmware(softmac_entry);
    }
	printk(KERN_DEBUG "MAC from %s %pM\n", source, ptr_mac);
   calculate_crc(ar->arTargetType, eeprom_data);
}
#endif /* SOFTMAC_FILE_USED */

static int
ar6000_transfer_bin_file(struct ar6_softc *ar, enum ar6k_bin_file file, u32 address, bool compressed)
{
    int status;
    const char *filename;
    const struct firmware *fw_entry;
    u32 fw_entry_size;

    switch (file) {
        case AR6K_OTP_FILE:
            if (ar->arVersion.target_ver == AR6003_REV1_VERSION) {
                filename = AR6003_REV1_OTP_FILE;
            } else if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
                filename = AR6003_REV2_OTP_FILE;
                } else if (ar->arVersion.target_ver == AR6003_REV3_VERSION) {
                        filename = AR6003_REV3_OTP_FILE;
            } else {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown firmware revision: %d\n", ar->arVersion.target_ver));
                return A_ERROR;
            }
            break;

        case AR6K_FIRMWARE_FILE:
            if (ar->arVersion.target_ver == AR6003_REV1_VERSION) {
                filename = AR6003_REV1_FIRMWARE_FILE;
            } else if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
                filename = AR6003_REV2_FIRMWARE_FILE;
                } else if (ar->arVersion.target_ver == AR6003_REV3_VERSION) {
                        filename = AR6003_REV3_FIRMWARE_FILE;
            } else {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown firmware revision: %d\n", ar->arVersion.target_ver));
                return A_ERROR;
            }
            
#ifdef HTC_RAW_INTERFACE
            if (bypasswmi) {
                if (ar->arVersion.target_ver == AR6003_REV1_VERSION) {
                    filename = AR6003_REV1_ART_FIRMWARE_FILE;
                } else if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
                    filename = AR6003_REV2_ART_FIRMWARE_FILE;
                } else {
                    AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown firmware revision: %d\n", ar->arVersion.target_ver));
                    return A_ERROR;
                }
                compressed = false;
            }
#endif 
            break;

        case AR6K_PATCH_FILE:
            if (ar->arVersion.target_ver == AR6003_REV1_VERSION) {
                filename = AR6003_REV1_PATCH_FILE;
            } else if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
                filename = AR6003_REV2_PATCH_FILE;
                } else if (ar->arVersion.target_ver == AR6003_REV3_VERSION) {
                        filename = AR6003_REV3_PATCH_FILE;
            } else {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown firmware revision: %d\n", ar->arVersion.target_ver));
                return A_ERROR;
            }
            break;

        case AR6K_BOARD_DATA_FILE:
            if (ar->arVersion.target_ver == AR6003_REV1_VERSION) {
                filename = AR6003_REV1_BOARD_DATA_FILE;
            } else if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
                filename = AR6003_REV2_BOARD_DATA_FILE;
                } else if (ar->arVersion.target_ver == AR6003_REV3_VERSION) {
                        filename = AR6003_REV3_BOARD_DATA_FILE;
            } else {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown firmware revision: %d\n", ar->arVersion.target_ver));
                return A_ERROR;
            }
            break;

        default:
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Unknown file type: %d\n", file));
            return A_ERROR;
    }
    if ((request_firmware(&fw_entry, filename, ((struct device *)ar->osDevInfo.pOSDevice))) != 0)
    {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Failed to get %s\n", filename));
        return A_ENOENT;
    }

#ifdef SOFTMAC_FILE_USED
    if (file==AR6K_BOARD_DATA_FILE && fw_entry->data) {
        ar6000_softmac_update(ar, (u8 *)fw_entry->data, fw_entry->size);
    }
#endif 


    fw_entry_size = fw_entry->size;

    /* Load extended board data for AR6003 */
    if ((file==AR6K_BOARD_DATA_FILE) && (fw_entry->data)) {
        u32 board_ext_address;
        u32 board_ext_data_size;
        u32 board_data_size;

        board_ext_data_size = (ar->arTargetType == TARGET_TYPE_AR6003) ? AR6003_BOARD_EXT_DATA_SZ : 0;

        board_data_size = (ar->arTargetType == TARGET_TYPE_AR6003) ? AR6003_BOARD_DATA_SZ : 0;
        
        /* Determine where in Target RAM to write Board Data */
        bmifn(bmi_read_memory(ar->arHifDevice, HOST_INTEREST_ITEM_ADDRESS(ar, hi_board_ext_data), (u8 *)&board_ext_address, 4));
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("Board extended Data download address: 0x%x\n", board_ext_address));

        /* check whether the target has allocated memory for extended board data and file contains extended board data */
        if ((board_ext_address) && (fw_entry->size == (board_data_size + board_ext_data_size))) {
            u32 param;

            status = bmi_write_memory(ar->arHifDevice, board_ext_address, (u8 *)(fw_entry->data + board_data_size), board_ext_data_size);

            if (status) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("BMI operation failed: %d\n", __LINE__));
                release_firmware(fw_entry);
                return A_ERROR;
            }

            /* Record the fact that extended board Data IS initialized */
            param = (board_ext_data_size << 16) | 1;
            bmifn(bmi_write_memory(ar->arHifDevice,
            HOST_INTEREST_ITEM_ADDRESS(ar, hi_board_ext_data_config),
				       (unsigned char *)&param, 4));
        }
        fw_entry_size = board_data_size;
    }

    if (compressed) {
        status = bmi_fast_download(ar->arHifDevice, address, (u8 *)fw_entry->data, fw_entry_size);
    } else {
        status = bmi_write_memory(ar->arHifDevice, address, (u8 *)fw_entry->data, fw_entry_size);
    }

    if (status) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("BMI operation failed: %d\n", __LINE__));
        release_firmware(fw_entry);
        return A_ERROR;
    }
    release_firmware(fw_entry);
    return 0;
}

int
ar6000_sysfs_bmi_get_config(struct ar6_softc *ar, u32 mode)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("BMI: Requesting device specific configuration\n"));

    if (mode == WLAN_INIT_MODE_UDEV) {
        char version[16];
        const struct firmware *fw_entry;

        /* Get config using udev through a script in user space */
        sprintf(version, "%2.2x", ar->arVersion.target_ver);
        if ((request_firmware(&fw_entry, version, ((struct device *)ar->osDevInfo.pOSDevice))) != 0)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("BMI: Failure to get configuration for target version: %s\n", version));
            return A_ERROR;
        }

        release_firmware(fw_entry);
    } else {
        /* The config is contained within the driver itself */
        int status;
        u32 param, options, sleep, address;

        /* Temporarily disable system sleep */
        address = MBOX_BASE_ADDRESS + LOCAL_SCRATCH_ADDRESS;
        bmifn(bmi_read_soc_register(ar->arHifDevice, address, &param));
        options = param;
        param |= AR6K_OPTION_SLEEP_DISABLE;
        bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));

        address = RTC_BASE_ADDRESS + SYSTEM_SLEEP_ADDRESS;
        bmifn(bmi_read_soc_register(ar->arHifDevice, address, &param));
        sleep = param;
        param |= SYSTEM_SLEEP_DISABLE_SET(1);
        bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("old options: %d, old sleep: %d\n", options, sleep));

        if (ar->arTargetType == TARGET_TYPE_AR6003) {
            /* Program analog PLL register */
            bmifn(bmi_write_soc_register(ar->arHifDevice, ANALOG_INTF_BASE_ADDRESS + 0x284, 0xF9104001));
            /* Run at 80/88MHz by default */
            param = CPU_CLOCK_STANDARD_SET(1);
        } else {
            /* Run at 40/44MHz by default */
            param = CPU_CLOCK_STANDARD_SET(0);
        }
        address = RTC_BASE_ADDRESS + CPU_CLOCK_ADDRESS;
        bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));

        param = 0;

	address = RTC_BASE_ADDRESS + LPO_CAL_ADDRESS;
	param = LPO_CAL_ENABLE_SET(1);
	bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));

	/* Venus2.0: Lower SDIO pad drive strength,
         * temporary WAR to avoid SDIO CRC error */
        if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("AR6K: Temporary WAR to avoid SDIO CRC error\n"));
            param = 0x20;
            address = GPIO_BASE_ADDRESS + GPIO_PIN10_ADDRESS;
            bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));

            address = GPIO_BASE_ADDRESS + GPIO_PIN11_ADDRESS;
            bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));

            address = GPIO_BASE_ADDRESS + GPIO_PIN12_ADDRESS;
            bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));

            address = GPIO_BASE_ADDRESS + GPIO_PIN13_ADDRESS;
            bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));
        }

#ifdef FORCE_INTERNAL_CLOCK
        /* Ignore external clock, if any, and force use of internal clock */
        if (ar->arTargetType == TARGET_TYPE_AR6003) {
            /* hi_ext_clk_detected = 0 */
            param = 0;
            bmifn(bmi_write_memory(ar->arHifDevice, HOST_INTEREST_ITEM_ADDRESS(ar, hi_ext_clk_detected), (u8 *)&param, 4));

            /* CLOCK_CONTROL &= ~LF_CLK32 */
            address = RTC_BASE_ADDRESS + CLOCK_CONTROL_ADDRESS;
            bmifn(bmi_read_soc_register(ar->arHifDevice, address, &param));
            param &= (~CLOCK_CONTROL_LF_CLK32_SET(1));
            bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));
        }
#endif /* FORCE_INTERNAL_CLOCK */

        /* Transfer Board Data from Target EEPROM to Target RAM */
        if (ar->arTargetType == TARGET_TYPE_AR6003) {
            /* Determine where in Target RAM to write Board Data */
            bmifn(bmi_read_memory(ar->arHifDevice, HOST_INTEREST_ITEM_ADDRESS(ar, hi_board_data), (u8 *)&address, 4));
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO, ("Board Data download address: 0x%x\n", address));

            /* Write EEPROM data to Target RAM */
            if ((ar6000_transfer_bin_file(ar, AR6K_BOARD_DATA_FILE, address, false)) != 0) {
                return A_ERROR;
            }

            /* Record the fact that Board Data IS initialized */
            param = 1;
            bmifn(bmi_write_memory(ar->arHifDevice, HOST_INTEREST_ITEM_ADDRESS(ar, hi_board_data_initialized), (u8 *)&param, 4));

            /* Transfer One time Programmable data */
	    AR6K_APP_LOAD_ADDRESS(address, ar->arVersion.target_ver);
	    if (ar->arVersion.target_ver == AR6003_REV3_VERSION)
		  address = 0x1234;
            status = ar6000_transfer_bin_file(ar, AR6K_OTP_FILE, address, true);
            if (status == 0) {
                /* Execute the OTP code */
                param = 0;
                AR6K_APP_START_OVERRIDE_ADDRESS(address, ar->arVersion.target_ver);
                bmifn(bmi_execute(ar->arHifDevice, address, &param));
            } else if (status != A_ENOENT) {
                return A_ERROR;
            } 
        } else {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Programming of board data for chip %d not supported\n", ar->arTargetType));
            return A_ERROR;
        }

        /* Download Target firmware */
        AR6K_APP_LOAD_ADDRESS(address, ar->arVersion.target_ver);
        if (ar->arVersion.target_ver == AR6003_REV3_VERSION)
                address = 0x1234;
        if ((ar6000_transfer_bin_file(ar, AR6K_FIRMWARE_FILE, address, true)) != 0) {
            return A_ERROR;
        }

        /* Set starting address for firmware */
        AR6K_APP_START_OVERRIDE_ADDRESS(address, ar->arVersion.target_ver);
        bmifn(bmi_set_app_start(ar->arHifDevice, address));

	if(ar->arTargetType == TARGET_TYPE_AR6003) {
		AR6K_DATASET_PATCH_ADDRESS(address, ar->arVersion.target_ver);
		if ((ar6000_transfer_bin_file(ar, AR6K_PATCH_FILE,
					      address, false)) != 0)
			return A_ERROR;
		param = address;
		bmifn(bmi_write_memory(ar->arHifDevice,
		HOST_INTEREST_ITEM_ADDRESS(ar, hi_dset_list_head),
					   (unsigned char *)&param, 4));
	}

        /* Restore system sleep */
        address = RTC_BASE_ADDRESS + SYSTEM_SLEEP_ADDRESS;
        bmifn(bmi_write_soc_register(ar->arHifDevice, address, sleep));

        address = MBOX_BASE_ADDRESS + LOCAL_SCRATCH_ADDRESS;
        param = options | 0x20;
        bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));

        if (ar->arTargetType == TARGET_TYPE_AR6003) {
            /* Configure GPIO AR6003 UART */
#ifndef CONFIG_AR600x_DEBUG_UART_TX_PIN
#define CONFIG_AR600x_DEBUG_UART_TX_PIN 8
#endif
            param = CONFIG_AR600x_DEBUG_UART_TX_PIN;
            bmifn(bmi_write_memory(ar->arHifDevice, HOST_INTEREST_ITEM_ADDRESS(ar, hi_dbg_uart_txpin), (u8 *)&param, 4));

#if (CONFIG_AR600x_DEBUG_UART_TX_PIN == 23)
            {
                address = GPIO_BASE_ADDRESS + CLOCK_GPIO_ADDRESS;
                bmifn(bmi_read_soc_register(ar->arHifDevice, address, &param));
                param |= CLOCK_GPIO_BT_CLK_OUT_EN_SET(1);
                bmifn(bmi_write_soc_register(ar->arHifDevice, address, param));
            }
#endif

            /* Configure GPIO for BT Reset */
#ifdef ATH6KL_CONFIG_GPIO_BT_RESET
#define CONFIG_AR600x_BT_RESET_PIN	0x16
            param = CONFIG_AR600x_BT_RESET_PIN;
            bmifn(bmi_write_memory(ar->arHifDevice, HOST_INTEREST_ITEM_ADDRESS(ar, hi_hci_uart_support_pins), (u8 *)&param, 4));
#endif /* ATH6KL_CONFIG_GPIO_BT_RESET */

            /* Configure UART flow control polarity */
#ifndef CONFIG_ATH6KL_BT_UART_FC_POLARITY
#define CONFIG_ATH6KL_BT_UART_FC_POLARITY 0
#endif

#if (CONFIG_ATH6KL_BT_UART_FC_POLARITY == 1)
            if (ar->arVersion.target_ver == AR6003_REV2_VERSION) {
                param = ((CONFIG_ATH6KL_BT_UART_FC_POLARITY << 1) & 0x2);
                bmifn(bmi_write_memory(ar->arHifDevice, HOST_INTEREST_ITEM_ADDRESS(ar, hi_hci_uart_pwr_mgmt_params), (u8 *)&param, 4));
            }
#endif /* CONFIG_ATH6KL_BT_UART_FC_POLARITY */
        }

#ifdef HTC_RAW_INTERFACE
        if (bypasswmi) {
            /* Don't run bmi_done for ART mode and force resetok=0 */
            resetok = 0;
            msleep(1000);
        }
#endif /* HTC_RAW_INTERFACE */
    }

    return 0;
}

void
ar6000_restart_endpoint(struct net_device *dev)
{
    int status = 0;
    struct ar6_softc *ar = (struct ar6_softc *)ar6k_priv(dev);

    bmi_init();
    do {
        if ( (status=ar6000_configure_target(ar))!= 0)
            break;
        if ( (status=ar6000_sysfs_bmi_get_config(ar, wlaninitmode)) != 0)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000_avail: ar6000_sysfs_bmi_get_config failed\n"));
            break;
        }
        rtnl_lock();
        status = (ar6000_init(dev)==0) ? 0 : A_ERROR;
        rtnl_unlock();

        if (status) {
            break;
        }
        if (ar->arSsidLen && ar->arWlanState == WLAN_ENABLED) {
            ar6000_connect_to_ap(ar);
        }  
    } while (0);

    if (status== 0) {
        return;
    }

    ar6000_devices[ar->arDeviceIndex] = NULL;
    ar6000_destroy(ar->arNetDev, 1);
}

void
ar6000_stop_endpoint(struct net_device *dev, bool keepprofile, bool getdbglogs)
{
    struct ar6_softc *ar = (struct ar6_softc *)ar6k_priv(dev);

    /* Stop the transmit queues */
    netif_stop_queue(dev);

    /* Disable the target and the interrupts associated with it */
    if (ar->arWmiReady == true)
    {
        if (!bypasswmi)
        {
            bool disconnectIssued;
 
            disconnectIssued = (ar->arConnected) || (ar->arConnectPending);
            ar6000_disconnect(ar);
            if (!keepprofile) {
                ar6000_init_profile_info(ar);
            }

            del_timer(&ar->disconnect_timer);

            ar->arWmiReady  = false;
            wmi_shutdown(ar->arWmi);
            ar->arWmiEnabled = false;
            ar->arWmi = NULL;
            /* 
             * After wmi_shudown all WMI events will be dropped.
             * We need to cleanup the buffers allocated in AP mode
             * and give disconnect notification to stack, which usually
             * happens in the disconnect_event. 
             * Simulate the disconnect_event by calling the function directly.
             * Sometimes disconnect_event will be received when the debug logs 
             * are collected.
             */
            if (disconnectIssued) {
                if(ar->arNetworkType & AP_NETWORK) {
                    ar6000_disconnect_event(ar, DISCONNECT_CMD, bcast_mac, 0, NULL, 0);
                } else {
                    ar6000_disconnect_event(ar, DISCONNECT_CMD, ar->arBssid, 0, NULL, 0);
                }
            }
            ar->user_savedkeys_stat = USER_SAVEDKEYS_STAT_INIT;
            ar->user_key_ctrl      = 0;
        }

         AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("%s(): WMI stopped\n", __func__));
    }
    else
    {
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("%s(): WMI not ready 0x%lx 0x%lx\n",
            __func__, (unsigned long) ar, (unsigned long) ar->arWmi));

        /* Shut down WMI if we have started it */
        if(ar->arWmiEnabled == true)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("%s(): Shut down WMI\n", __func__));
            wmi_shutdown(ar->arWmi);
            ar->arWmiEnabled = false;
            ar->arWmi = NULL;
        }
    }

    if (ar->arHtcTarget != NULL) {
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,(" Shutting down HTC .... \n"));
        /* stop HTC */
        HTCStop(ar->arHtcTarget);
    }

    if (resetok) {
        /* try to reset the device if we can
         * The driver may have been configure NOT to reset the target during
         * a debug session */
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,(" Attempting to reset target on instance destroy.... \n"));
        if (ar->arHifDevice != NULL) {
            bool coldReset = (ar->arTargetType == TARGET_TYPE_AR6003) ? true: false;
            ar6000_reset_device(ar->arHifDevice, ar->arTargetType, true, coldReset);
        }
    } else {
        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,(" Host does not want target reset. \n"));
    }
       /* Done with cookies */
    ar6000_cookie_cleanup(ar);

    /* cleanup any allocated AMSDU buffers */
    ar6000_cleanup_amsdu_rxbufs(ar);
}

void disconnect_timer_handler(unsigned long ptr)
{
    struct net_device *dev = (struct net_device *)ptr;
    struct ar6_softc *ar = (struct ar6_softc *)ar6k_priv(dev);

    del_timer(&ar->disconnect_timer);

    ar6000_init_profile_info(ar);
    ar6000_disconnect(ar);
}

void ar6000_detect_error(unsigned long ptr)
{
    struct net_device *dev = (struct net_device *)ptr;
    struct ar6_softc *ar = (struct ar6_softc *)ar6k_priv(dev);
    struct wmi_target_error_report_event errEvent;

    spin_lock_bh(&ar->arLock);

    if (ar->arHBChallengeResp.outstanding) {
        ar->arHBChallengeResp.missCnt++;
    } else {
        ar->arHBChallengeResp.missCnt = 0;
    }

    if (ar->arHBChallengeResp.missCnt > ar->arHBChallengeResp.missThres) {
        /* Send Error Detect event to the application layer and do not reschedule the error detection module timer */
        ar->arHBChallengeResp.missCnt = 0;
        ar->arHBChallengeResp.seqNum = 0;
        errEvent.errorVal = WMI_TARGET_COM_ERR | WMI_TARGET_FATAL_ERR;
        spin_unlock_bh(&ar->arLock);
        return;
    }

    /* Generate the sequence number for the next challenge */
    ar->arHBChallengeResp.seqNum++;
    ar->arHBChallengeResp.outstanding = true;

    spin_unlock_bh(&ar->arLock);

    /* Send the challenge on the control channel */
    if (wmi_get_challenge_resp_cmd(ar->arWmi, ar->arHBChallengeResp.seqNum, DRV_HB_CHALLENGE) != 0) {
        AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Unable to send heart beat challenge\n"));
    }


    /* Reschedule the timer for the next challenge */
    mod_timer(&ar->arHBChallengeResp.timer,
	       jiffies + msecs_to_jiffies(ar->arHBChallengeResp.frequency * 1000));
}

void ar6000_init_profile_info(struct ar6_softc *ar)
{
    ar->arSsidLen            = 0;
    memset(ar->arSsid, 0, sizeof(ar->arSsid));

    switch(fwmode) {
        case HI_OPTION_FW_MODE_IBSS:
            ar->arNetworkType = ar->arNextMode = ADHOC_NETWORK;
            break;
        case HI_OPTION_FW_MODE_BSS_STA:
            ar->arNetworkType = ar->arNextMode = INFRA_NETWORK;
            break;
        case HI_OPTION_FW_MODE_AP:
            ar->arNetworkType = ar->arNextMode = AP_NETWORK;
            break;
    }

    ar->arDot11AuthMode      = OPEN_AUTH;
    ar->arAuthMode           = NONE_AUTH;
    ar->arPairwiseCrypto     = NONE_CRYPT;
    ar->arPairwiseCryptoLen  = 0;
    ar->arGroupCrypto        = NONE_CRYPT;
    ar->arGroupCryptoLen     = 0;
    memset(ar->arWepKeyList, 0, sizeof(ar->arWepKeyList));
    memset(ar->arReqBssid, 0, sizeof(ar->arReqBssid));
    memset(ar->arBssid, 0, sizeof(ar->arBssid));
    ar->arBssChannel = 0;
}

static int
ar6000_open(struct net_device *dev)
{
    unsigned long  flags;
    struct ar6_softc    *ar = (struct ar6_softc *)ar6k_priv(dev);

    spin_lock_irqsave(&ar->arLock, flags);

    if(ar->arWlanState == WLAN_DISABLED) {
        ar->arWlanState = WLAN_ENABLED;
    }

    if( ar->arConnected || bypasswmi) {
        netif_carrier_on(dev);
        /* Wake up the queues */
        netif_wake_queue(dev);
    }
    else
        netif_carrier_off(dev);

    spin_unlock_irqrestore(&ar->arLock, flags);
    return 0;
}

void init_netdev(struct net_device *dev)
{
	dev->netdev_ops = &ar6000_netdev_ops;
	dev->watchdog_timeo = AR6000_TX_TIMEOUT;

	/*
	 * We need the OS to provide us with more headroom in order to
	 * perform dix to 802.3, WMI header encap, and the HTC header
	 */
	dev->hard_header_len = processDot11Hdr ? sizeof(struct ieee80211_qos_hdr) :
				ETH_HLEN;
	dev->hard_header_len += sizeof(ATH_LLC_SNAP_HDR) +
				sizeof(struct wmi_data_hdr) + HTC_HEADER_LEN
				+ WMI_MAX_TX_META_SZ +
				LINUX_HACK_FUDGE_FACTOR;

#ifdef CONFIG_CHECKSUM_OFFLOAD
	if(csumOffload)
		dev->features |= NETIF_F_IP_CSUM;
#endif

	return;
}

static int
ar6000_close(struct net_device *dev)
{
    struct ar6_softc    *ar = (struct ar6_softc *)ar6k_priv(dev);
    netif_stop_queue(dev);

    ar6000_disconnect(ar);

    if(ar->arWmiReady == true) {
        if (wmi_scanparams_cmd(ar->arWmi, 0xFFFF, 0,
                               0, 0, 0, 0, 0, 0, 0, 0) != 0) {
            return -EIO;
        }
        ar->arWlanState = WLAN_DISABLED;
    }
	ar6k_cfg80211_scanComplete_event(ar, A_ECANCELED);

    return 0;
}

void ar6000_TxDataCleanup(struct ar6_softc *ar)
{
        /* flush all the data (non-control) streams
         * we only flush packets that are tagged as data, we leave any control packets that
         * were in the TX queues alone */
    HTCFlushEndpoint(ar->arHtcTarget,
                     arAc2EndpointID(ar, WMM_AC_BE),
                     AR6K_DATA_PKT_TAG);
    HTCFlushEndpoint(ar->arHtcTarget,
                     arAc2EndpointID(ar, WMM_AC_BK),
                     AR6K_DATA_PKT_TAG);
    HTCFlushEndpoint(ar->arHtcTarget,
                     arAc2EndpointID(ar, WMM_AC_VI),
                     AR6K_DATA_PKT_TAG);
    HTCFlushEndpoint(ar->arHtcTarget,
                     arAc2EndpointID(ar, WMM_AC_VO),
                     AR6K_DATA_PKT_TAG);
}

enum htc_endpoint_id
ar6000_ac2_endpoint_id ( void * devt, u8 ac)
{
    struct ar6_softc *ar = (struct ar6_softc *) devt;
    return(arAc2EndpointID(ar, ac));
}

u8 ar6000_endpoint_id2_ac(void * devt, enum htc_endpoint_id ep )
{
    struct ar6_softc *ar = (struct ar6_softc *) devt;
    return(arEndpoint2Ac(ar, ep ));
}

/* reduce an ep's credits back to a set limit */
static void ath6k_reduce_credits(struct common_credit_state_info *pCredInfo,
		struct htc_endpoint_credit_dist  *pEpDist,
		int Limit)
{
	int credits;

	pEpDist->TxCreditsAssigned = Limit;

	if (pEpDist->TxCredits <= Limit)
		return;

	credits = pEpDist->TxCredits - Limit;
	pEpDist->TxCredits -= credits;
	pCredInfo->CurrentFreeCredits += credits;
}

/* HTC has an endpoint that needs credits, pEPDist is the endpoint in question */
static void ath6k_seek_credits(struct common_credit_state_info *pCredInfo,
		struct htc_endpoint_credit_dist *pEPDist)
{
	struct htc_endpoint_credit_dist *pCurEpDist;
	int credits = 0;
	int need;

	if (pEPDist->ServiceID == WMI_CONTROL_SVC)
		goto out;

	if (pEPDist->ServiceID == WMI_DATA_VI_SVC)
		if ((pEPDist->TxCreditsAssigned >= pEPDist->TxCreditsNorm))
			goto out;

	if (pEPDist->ServiceID == WMI_DATA_VO_SVC)
		if ((pEPDist->TxCreditsAssigned >= pEPDist->TxCreditsNorm))
			goto out;

	/* for all other services, we follow a simple algorithm of
	 * 1. checking the free pool for credits
	 * 2. checking lower priority endpoints for credits to take */

	credits = min(pCredInfo->CurrentFreeCredits,pEPDist->TxCreditsSeek);

	if (credits >= pEPDist->TxCreditsSeek)
		goto out;

	/* we don't have enough in the free pool, try taking away from lower priority services
	 *
	 * The rule for taking away credits:
	 *   1. Only take from lower priority endpoints
	 *   2. Only take what is allocated above the minimum (never starve an endpoint completely)
	 *   3. Only take what you need.
	 *
	 * */

	pCurEpDist = pCredInfo->pLowestPriEpDist;

	while (pCurEpDist != pEPDist) {
		need = pEPDist->TxCreditsSeek - pCredInfo->CurrentFreeCredits;

		if ((pCurEpDist->TxCreditsAssigned - need) >= pCurEpDist->TxCreditsMin) {
			/* the current one has been allocated more than it's minimum and it
			 * has enough credits assigned above it's minimum to fulfill our need
			 * try to take away just enough to fulfill our need */
			ath6k_reduce_credits(pCredInfo,
					pCurEpDist,
					pCurEpDist->TxCreditsAssigned - need);

			if (pCredInfo->CurrentFreeCredits >= pEPDist->TxCreditsSeek)
				break;
		}

		pCurEpDist = pCurEpDist->pPrev;
	}

	credits = min(pCredInfo->CurrentFreeCredits,pEPDist->TxCreditsSeek);


out:
	/* did we find some credits? */
	if (credits)
		AH6K_DEPOSITE_CREDITS_TO_EP(pCredInfo, pEPDist, credits);

}

/* redistribute credits based on activity change */
static void ath6k_redistribute_credits(struct common_credit_state_info *pCredInfo,
				       struct htc_endpoint_credit_dist *pEPDistList)
{
	struct htc_endpoint_credit_dist *pCurEpDist = pEPDistList;

	while (pCurEpDist) {

		if ((pCurEpDist->ServiceID == WMI_DATA_BK_SVC)  ||
		    (pCurEpDist->ServiceID == WMI_DATA_BE_SVC))
			SET_EP_ACTIVE(pCurEpDist);

		if (pCurEpDist->ServiceID != WMI_CONTROL_SVC) {
			if (!IS_EP_ACTIVE(pCurEpDist)) {
				if (pCurEpDist->TxQueueDepth == 0)
					ath6k_reduce_credits(pCredInfo, pCurEpDist, 0);
				else
					ath6k_reduce_credits(pCredInfo,
							pCurEpDist,
							pCurEpDist->TxCreditsMin);
			}
		}
		pCurEpDist = pCurEpDist->pNext;
	}
}

/* default credit distribution callback
 * This callback is invoked whenever endpoints require credit distributions.
 * A lock is held while this function is invoked, this function shall NOT block.
 * The pEPDistList is a list of distribution structures in prioritized order as
 * defined by the call to the HTCSetCreditDistribution() api.
 *
 */
void ath6k_credit_distribute(void *Context,
		struct htc_endpoint_credit_dist *pEPDistList,
		enum htc_credit_dist_reason Reason)
{
	struct htc_endpoint_credit_dist *pCurEpDist;
	struct common_credit_state_info *pCredInfo = Context;

	switch (Reason) {
	case HTC_CREDIT_DIST_SEND_COMPLETE :
		pCurEpDist = pEPDistList;
		while (pCurEpDist != NULL) {

			if (pCurEpDist->TxCreditsToDist > 0) {
				pCurEpDist->TxCredits += pCurEpDist->TxCreditsToDist;
				pCurEpDist->TxCreditsToDist = 0;
				if (pCurEpDist->TxCredits > pCurEpDist->TxCreditsAssigned)
					ath6k_reduce_credits(pCredInfo,
							     pCurEpDist,
							     pCurEpDist->TxCreditsAssigned);

				if (pCurEpDist->TxCredits > pCurEpDist->TxCreditsNorm)
					ath6k_reduce_credits(pCredInfo, pCurEpDist, pCurEpDist->TxCreditsNorm);

				if (!IS_EP_ACTIVE(pCurEpDist)) {
					if (pCurEpDist->TxQueueDepth == 0)
						ath6k_reduce_credits(pCredInfo, pCurEpDist, 0);
				}
			}

			pCurEpDist = pCurEpDist->pNext;
		}
			break;

	case HTC_CREDIT_DIST_ACTIVITY_CHANGE :
			ath6k_redistribute_credits(pCredInfo,pEPDistList);
			break;
	case HTC_CREDIT_DIST_SEEK_CREDITS :
			ath6k_seek_credits(pCredInfo,pEPDistList);
			break;
	case HTC_DUMP_CREDIT_STATE :
			AR_DEBUG_PRINTF(ATH_DEBUG_ERR, ("Credit Distribution, total : %d, free : %d\n",
						pCredInfo->TotalAvailableCredits, pCredInfo->CurrentFreeCredits));
			break;
	default:
			break;

	}

	BUG_ON((pCredInfo->CurrentFreeCredits > pCredInfo->TotalAvailableCredits) ||
		pCredInfo->CurrentFreeCredits < 0);
}

void
ar6000_bitrate_rx(void *devt, s32 rateKbps)
{
    wake_up(&arEvent);
}

void
ar6000_ratemask_rx(void *devt, u32 ratemask)
{
    wake_up(&arEvent);
}

void
ar6000_txPwr_rx(void *devt, u8 txPwr)
{
    struct ar6_softc *ar = (struct ar6_softc *)devt;

    ar->arTxPwr = txPwr;
    wake_up(&arEvent);
}

void
ar6000_channelList_rx(void *devt, s8 numChan, u16 *chanList)
{
    wake_up(&arEvent);
}

u8 ar6000_ibss_map_epid(struct sk_buff *skb, struct net_device *dev, u32 *mapNo)
{
    struct ar6_softc      *ar = (struct ar6_softc *)ar6k_priv(dev);
    u8 *datap;
    ATH_MAC_HDR     *macHdr;
    u32 i, eptMap;

    (*mapNo) = 0;
    datap = ((struct sk_buff *)skb)->data;
    macHdr = (ATH_MAC_HDR *)(datap + sizeof(struct wmi_data_hdr));
    if (IEEE80211_IS_MULTICAST(macHdr->dstMac)) {
        return ENDPOINT_2;
    }

    eptMap = -1;
    for (i = 0; i < ar->arNodeNum; i ++) {
        if (memcmp(macHdr->dstMac, ar->arNodeMap[i].macAddress, ETH_ALEN) == 0) {
            (*mapNo) = i + 1;
            ar->arNodeMap[i].txPending ++;
            return ar->arNodeMap[i].epId;
        }

        if ((eptMap == -1) && !ar->arNodeMap[i].txPending) {
            eptMap = i;
        }
    }

    if (eptMap == -1) {
        eptMap = ar->arNodeNum;
        ar->arNodeNum ++;
        A_ASSERT(ar->arNodeNum <= MAX_NODE_NUM);
    }

    memcpy(ar->arNodeMap[eptMap].macAddress, macHdr->dstMac, ETH_ALEN);

    for (i = ENDPOINT_2; i <= ENDPOINT_5; i ++) {
        if (!ar->arTxPending[i]) {
            ar->arNodeMap[eptMap].epId = i;
            break;
        }
        // No free endpoint is available, start redistribution on the inuse endpoints.
        if (i == ENDPOINT_5) {
            ar->arNodeMap[eptMap].epId = ar->arNexEpId;
            ar->arNexEpId ++;
            if (ar->arNexEpId > ENDPOINT_5) {
                ar->arNexEpId = ENDPOINT_2;
            }
        }
    }

    (*mapNo) = eptMap + 1;
    ar->arNodeMap[eptMap].txPending ++;

    return ar->arNodeMap[eptMap].epId;
}

#ifdef DEBUG
static void ar6000_dump_skb(struct sk_buff *skb)
{
   u_char *ch;
   for (ch = ((struct sk_buff *)skb)->data;
        (unsigned long)ch < ((unsigned long)((struct sk_buff *)skb)->data +
        ((struct sk_buff *)skb)->len); ch++)
    {
         AR_DEBUG_PRINTF(ATH_DEBUG_WARN,("%2.2x ", *ch));
    }
    AR_DEBUG_PRINTF(ATH_DEBUG_WARN,("\n"));
}
#endif

static int
ar6000_data_tx(struct sk_buff *skb, struct net_device *dev)
{
#define AC_NOT_MAPPED   99
    struct ar6_softc        *ar = (struct ar6_softc *)ar6k_priv(dev);
    u8 ac = AC_NOT_MAPPED;
    enum htc_endpoint_id    eid = ENDPOINT_UNUSED;
    u32 mapNo = 0;
    int               len;
    struct ar_cookie *cookie;
    bool            checkAdHocPsMapping = false,bMoreData = false;
    u16        htc_tag = AR6K_DATA_PKT_TAG;
    u8 dot11Hdr = processDot11Hdr;
#ifdef CONFIG_PM
    if (ar->arWowState != WLAN_WOW_STATE_NONE) {
        dev_kfree_skb(skb);
        return 0;
    }
#endif /* CONFIG_PM */

    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_TX,("ar6000_data_tx start - skb=0x%lx, data=0x%lx, len=0x%x\n",
                     (unsigned long)skb, (unsigned long)((struct sk_buff *)skb)->data,
                     ((struct sk_buff *)skb)->len));

    /* If target is not associated */
    if( (!ar->arConnected && !bypasswmi)) {
        dev_kfree_skb(skb);
        return 0;
    }

    do {

        if (ar->arWmiReady == false && bypasswmi == 0) {
            break;
        }

        /* AP mode Power save processing */
        /* If the dst STA is in sleep state, queue the pkt in its PS queue */

        if (ar->arNetworkType == AP_NETWORK) {
            ATH_MAC_HDR *datap = (ATH_MAC_HDR *)((struct sk_buff *)skb)->data;
            struct ar6k_sta *conn = NULL;

            /* If the dstMac is a Multicast address & atleast one of the
             * associated STA is in PS mode, then queue the pkt to the
             * mcastq
             */
            if (IEEE80211_IS_MULTICAST(datap->dstMac)) {
                u8 ctr=0;
                bool qMcast=false;


                for (ctr=0; ctr<AP_MAX_NUM_STA; ctr++) {
                    if (STA_IS_PWR_SLEEP((&ar->sta_list[ctr]))) {
                        qMcast = true;
                    }
                }
                if(qMcast) {

                    /* If this transmit is not because of a Dtim Expiry q it */
                    if (ar->DTIMExpired == false) {
                        bool isMcastqEmpty = false;

                        spin_lock_bh(&ar->mcastpsqLock);
                        isMcastqEmpty = skb_queue_empty(&ar->mcastpsq);
                        skb_queue_tail(&ar->mcastpsq, skb);
                        spin_unlock_bh(&ar->mcastpsqLock);

                        /* If this is the first Mcast pkt getting queued
                         * indicate to the target to set the BitmapControl LSB
                         * of the TIM IE.
                         */
                        if (isMcastqEmpty) {
                             wmi_set_pvb_cmd(ar->arWmi, MCAST_AID, 1);
                        }
                        return 0;
                    } else {
                     /* This transmit is because of Dtim expiry. Determine if
                      * MoreData bit has to be set.
                      */
                         spin_lock_bh(&ar->mcastpsqLock);
                         if(!skb_queue_empty(&ar->mcastpsq)) {
                             bMoreData = true;
                         }
                         spin_unlock_bh(&ar->mcastpsqLock);
                    }
                }
            } else {
                conn = ieee80211_find_conn(ar, datap->dstMac);
                if (conn) {
                    if (STA_IS_PWR_SLEEP(conn)) {
                        /* If this transmit is not because of a PsPoll q it*/
                        if (!STA_IS_PS_POLLED(conn)) {
                            bool isPsqEmpty = false;
                            /* Queue the frames if the STA is sleeping */
                            spin_lock_bh(&conn->psqLock);
                            isPsqEmpty = skb_queue_empty(&conn->psq);
                            skb_queue_tail(&conn->psq, skb);
                            spin_unlock_bh(&conn->psqLock);

                            /* If this is the first pkt getting queued
                             * for this STA, update the PVB for this STA
                             */
                            if (isPsqEmpty) {
                                wmi_set_pvb_cmd(ar->arWmi, conn->aid, 1);
                            }

                            return 0;
                         } else {
                         /* This tx is because of a PsPoll. Determine if
                          * MoreData bit has to be set
                          */
                             spin_lock_bh(&conn->psqLock);
                             if (!skb_queue_empty(&conn->psq)) {
                                 bMoreData = true;
                             }
                             spin_unlock_bh(&conn->psqLock);
                         }
                    }
                } else {

                    /* non existent STA. drop the frame */
                    dev_kfree_skb(skb);
                    return 0;
                }
            }
        }

        if (ar->arWmiEnabled) {
        u8 csumStart=0;
        u8 csumDest=0;
        u8 csum=skb->ip_summed;
        if(csumOffload && (csum==CHECKSUM_PARTIAL)){
            csumStart = (skb->head + skb->csum_start - skb_network_header(skb) +
			 sizeof(ATH_LLC_SNAP_HDR));
            csumDest=skb->csum_offset+csumStart;
        }
            if (skb_headroom(skb) < (dev->hard_header_len - LINUX_HACK_FUDGE_FACTOR)) {
                struct sk_buff  *newbuf;

                /*
                 * We really should have gotten enough headroom but sometimes
                 * we still get packets with not enough headroom.  Copy the packet.
                 */
                len = skb->len;
                newbuf = ar6k_buf_alloc(len);
                if (newbuf == NULL) {
                    break;
                }
                skb_put(newbuf, len);
                memcpy(newbuf->data, skb->data, len);
                dev_kfree_skb(skb);
                skb = newbuf;
                /* fall through and assemble header */
            }

            if (dot11Hdr) {
                if (wmi_dot11_hdr_add(ar->arWmi,skb,ar->arNetworkType) != 0) {
                    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000_data_tx-wmi_dot11_hdr_add failed\n"));
                    break;
                }
            } else {
                if (wmi_dix_2_dot3(ar->arWmi, skb) != 0) {
                    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000_data_tx - wmi_dix_2_dot3 failed\n"));
                    break;
                }
            }
            if(csumOffload && (csum ==CHECKSUM_PARTIAL)){
                struct wmi_tx_meta_v2  metaV2;
                metaV2.csumStart =csumStart;
                metaV2.csumDest = csumDest;
                metaV2.csumFlags = 0x1;/*instruct target to calculate checksum*/
                if (wmi_data_hdr_add(ar->arWmi, skb, DATA_MSGTYPE, bMoreData, dot11Hdr,
                                        WMI_META_VERSION_2,&metaV2) != 0) {
                    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000_data_tx - wmi_data_hdr_add failed\n"));
                    break;
                }

            }
            else
            {
                if (wmi_data_hdr_add(ar->arWmi, skb, DATA_MSGTYPE, bMoreData, dot11Hdr,0,NULL) != 0) {
                    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000_data_tx - wmi_data_hdr_add failed\n"));
                    break;
                }
            }


            if ((ar->arNetworkType == ADHOC_NETWORK) &&
                ar->arIbssPsEnable && ar->arConnected) {
                    /* flag to check adhoc mapping once we take the lock below: */
                checkAdHocPsMapping = true;

            } else {
                    /* get the stream mapping */
                ac  =  wmi_implicit_create_pstream(ar->arWmi, skb, 0, ar->arWmmEnabled);
            }

	} else
		/* not a ping packet, drop it */
		ac = AC_NOT_MAPPED;
    } while (false);

        /* did we succeed ? */
    if ((ac == AC_NOT_MAPPED) && !checkAdHocPsMapping) {
            /* cleanup and exit */
        dev_kfree_skb(skb);
        AR6000_STAT_INC(ar, tx_dropped);
        AR6000_STAT_INC(ar, tx_aborted_errors);
        return 0;
    }

    cookie = NULL;

        /* take the lock to protect driver data */
    spin_lock_bh(&ar->arLock);

    do {

        if (checkAdHocPsMapping) {
            eid = ar6000_ibss_map_epid(skb, dev, &mapNo);
        }else {
            eid = arAc2EndpointID (ar, ac);
        }
            /* validate that the endpoint is connected */
        if (eid == 0 || eid == ENDPOINT_UNUSED ) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" eid %d is NOT mapped!\n", eid));
            break;
        }
            /* allocate resource for this packet */
        cookie = ar6000_alloc_cookie(ar);

        if (cookie != NULL) {
                /* update counts while the lock is held */
            ar->arTxPending[eid]++;
            ar->arTotalTxDataPending++;
        }

    } while (false);

    spin_unlock_bh(&ar->arLock);

    if (cookie != NULL) {
        cookie->arc_bp[0] = (unsigned long)skb;
        cookie->arc_bp[1] = mapNo;
        SET_HTC_PACKET_INFO_TX(&cookie->HtcPkt,
                               cookie,
                               ((struct sk_buff *)skb)->data,
                               ((struct sk_buff *)skb)->len,
                               eid,
                               htc_tag);

#ifdef DEBUG
        if (debugdriver >= 3) {
            ar6000_dump_skb(skb);
        }
#endif
            /* HTC interface is asynchronous, if this fails, cleanup will happen in
             * the ar6000_tx_complete callback */
        HTCSendPkt(ar->arHtcTarget, &cookie->HtcPkt);
    } else {
            /* no packet to send, cleanup */
        dev_kfree_skb(skb);
        AR6000_STAT_INC(ar, tx_dropped);
        AR6000_STAT_INC(ar, tx_aborted_errors);
    }

    return 0;
}

enum htc_send_full_action ar6000_tx_queue_full(void *Context, struct htc_packet *pPacket)
{
    struct ar6_softc     *ar = (struct ar6_softc *)Context;
    enum htc_send_full_action    action = HTC_SEND_FULL_KEEP;
    bool                  stopNet = false;
    enum htc_endpoint_id         Endpoint = HTC_GET_ENDPOINT_FROM_PKT(pPacket);

    do {

        if (bypasswmi) {
            int accessClass;

            if (HTC_GET_TAG_FROM_PKT(pPacket) == AR6K_CONTROL_PKT_TAG) {
                    /* don't drop special control packets */
                break;
            }

            accessClass = arEndpoint2Ac(ar,Endpoint);
                /* for endpoint ping testing drop Best Effort and Background */
            if ((accessClass == WMM_AC_BE) || (accessClass == WMM_AC_BK)) {
                action = HTC_SEND_FULL_DROP;
                stopNet = false;
            } else {
                    /* keep but stop the netqueues */
                stopNet = true;
            }
            break;
        }

        if (Endpoint == ar->arControlEp) {
                /* under normal WMI if this is getting full, then something is running rampant
                 * the host should not be exhausting the WMI queue with too many commands
                 * the only exception to this is during testing using endpointping */
            spin_lock_bh(&ar->arLock);
                /* set flag to handle subsequent messages */
            ar->arWMIControlEpFull = true;
            spin_unlock_bh(&ar->arLock);
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("WMI Control Endpoint is FULL!!! \n"));
                /* no need to stop the network */
            stopNet = false;
            break;
        }

        /* if we get here, we are dealing with data endpoints getting full */

        if (HTC_GET_TAG_FROM_PKT(pPacket) == AR6K_CONTROL_PKT_TAG) {
            /* don't drop control packets issued on ANY data endpoint */
            break;
        }

        if (ar->arNetworkType == ADHOC_NETWORK) {
            /* in adhoc mode, we cannot differentiate traffic priorities so there is no need to
             * continue, however we should stop the network */
            stopNet = true;
            break;
        }
        /* the last MAX_HI_COOKIE_NUM "batch" of cookies are reserved for the highest
         * active stream */
        if (ar->arAcStreamPriMap[arEndpoint2Ac(ar,Endpoint)] < ar->arHiAcStreamActivePri &&
            ar->arCookieCount <= MAX_HI_COOKIE_NUM) {
                /* this stream's priority is less than the highest active priority, we
                 * give preference to the highest priority stream by directing
                 * HTC to drop the packet that overflowed */
            action = HTC_SEND_FULL_DROP;
                /* since we are dropping packets, no need to stop the network */
            stopNet = false;
            break;
        }

    } while (false);

    if (stopNet) {
        spin_lock_bh(&ar->arLock);
        ar->arNetQueueStopped = true;
        spin_unlock_bh(&ar->arLock);
        /* one of the data endpoints queues is getting full..need to stop network stack
         * the queue will resume in ar6000_tx_complete() */
        netif_stop_queue(ar->arNetDev);
    }

    return action;
}


void ar6000_tx_complete(void *Context, struct htc_packet_queue *pPacketQueue)
{
    struct ar6_softc     *ar = (struct ar6_softc *)Context;
    u32 mapNo = 0;
    int        status;
    struct ar_cookie * ar_cookie;
    enum htc_endpoint_id   eid;
    bool          wakeEvent = false;
    struct sk_buff_head  skb_queue;
    struct htc_packet      *pPacket;
    struct sk_buff  *pktSkb;
    bool          flushing = false;

    skb_queue_head_init(&skb_queue);

        /* lock the driver as we update internal state */
    spin_lock_bh(&ar->arLock);

        /* reap completed packets */
    while (!HTC_QUEUE_EMPTY(pPacketQueue)) {

        pPacket = HTC_PACKET_DEQUEUE(pPacketQueue);

        ar_cookie = (struct ar_cookie *)pPacket->pPktContext;
        A_ASSERT(ar_cookie);

        status = pPacket->Status;
        pktSkb = (struct sk_buff *)ar_cookie->arc_bp[0];
        eid = pPacket->Endpoint;
        mapNo = ar_cookie->arc_bp[1];

        A_ASSERT(pktSkb);
        A_ASSERT(pPacket->pBuffer == ((struct sk_buff *)pktSkb)->data);

            /* add this to the list, use faster non-lock API */
        __skb_queue_tail(&skb_queue,pktSkb);

        if (!status) {
            A_ASSERT(pPacket->ActualLength == ((struct sk_buff *)pktSkb)->len);
        }

        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_TX,("ar6000_tx_complete skb=0x%lx data=0x%lx len=0x%x eid=%d ",
                         (unsigned long)pktSkb, (unsigned long)pPacket->pBuffer,
                         pPacket->ActualLength,
                         eid));

        ar->arTxPending[eid]--;

        if ((eid  != ar->arControlEp) || bypasswmi) {
            ar->arTotalTxDataPending--;
        }

        if (eid == ar->arControlEp)
        {
            if (ar->arWMIControlEpFull) {
                    /* since this packet completed, the WMI EP is no longer full */
                ar->arWMIControlEpFull = false;
            }

            if (ar->arTxPending[eid] == 0) {
                wakeEvent = true;
            }
        }

        if (status) {
            if (status == A_ECANCELED) {
                    /* a packet was flushed  */
                flushing = true;
            }
            AR6000_STAT_INC(ar, tx_errors);
            if (status != A_NO_RESOURCE) {
                AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("%s() -TX ERROR, status: 0x%x\n", __func__,
                            status));
            }
        } else {
            AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_TX,("OK\n"));
            flushing = false;
            AR6000_STAT_INC(ar, tx_packets);
            ar->arNetStats.tx_bytes += ((struct sk_buff *)pktSkb)->len;
        }

        // TODO this needs to be looked at
        if ((ar->arNetworkType == ADHOC_NETWORK) && ar->arIbssPsEnable
            && (eid != ar->arControlEp) && mapNo)
        {
            mapNo --;
            ar->arNodeMap[mapNo].txPending --;

            if (!ar->arNodeMap[mapNo].txPending && (mapNo == (ar->arNodeNum - 1))) {
                u32 i;
                for (i = ar->arNodeNum; i > 0; i --) {
                    if (!ar->arNodeMap[i - 1].txPending) {
                        memset(&ar->arNodeMap[i - 1], 0, sizeof(struct ar_node_mapping));
                        ar->arNodeNum --;
                    } else {
                        break;
                    }
                }
            }
        }

        ar6000_free_cookie(ar, ar_cookie);

        if (ar->arNetQueueStopped) {
            ar->arNetQueueStopped = false;
        }
    }

    spin_unlock_bh(&ar->arLock);

    /* lock is released, we can freely call other kernel APIs */

        /* free all skbs in our local list */
    while (!skb_queue_empty(&skb_queue)) {
            /* use non-lock version */
        pktSkb = __skb_dequeue(&skb_queue);
        dev_kfree_skb(pktSkb);
    }

    if ((ar->arConnected == true) || bypasswmi) {
        if (!flushing) {
                /* don't wake the queue if we are flushing, other wise it will just
                 * keep queueing packets, which will keep failing */
            netif_wake_queue(ar->arNetDev);
        }
    }

    if (wakeEvent) {
        wake_up(&arEvent);
    }

}

/*
 * Receive event handler.  This is called by HTC when a packet is received
 */
int pktcount;
void ar6000_rx(void *Context, struct htc_packet *pPacket)
{
    struct ar6_softc *ar = (struct ar6_softc *)Context;
    struct sk_buff *skb = (struct sk_buff *)pPacket->pPktContext;
    int minHdrLen;
    u8 containsDot11Hdr = 0;
    int        status = pPacket->Status;
    enum htc_endpoint_id   ept = pPacket->Endpoint;

    A_ASSERT((status) ||
             (pPacket->pBuffer == (((struct sk_buff *)skb)->data + HTC_HEADER_LEN)));

    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_RX,("ar6000_rx ar=0x%lx eid=%d, skb=0x%lx, data=0x%lx, len=0x%x status:%d",
                    (unsigned long)ar, ept, (unsigned long)skb, (unsigned long)pPacket->pBuffer,
                    pPacket->ActualLength, status));
    if (status) {
        if (status != A_ECANCELED) {
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("RX ERR (%d) \n",status));
        }
    }

        /* take lock to protect buffer counts
         * and adaptive power throughput state */
    spin_lock_bh(&ar->arLock);

    if (!status) {
        AR6000_STAT_INC(ar, rx_packets);
        ar->arNetStats.rx_bytes += pPacket->ActualLength;

        skb_put((struct sk_buff *)skb, pPacket->ActualLength + HTC_HEADER_LEN);
        skb_pull((struct sk_buff *)skb, HTC_HEADER_LEN);

#ifdef DEBUG
        if (debugdriver >= 2) {
            ar6000_dump_skb(skb);
        }
#endif /* DEBUG */
    }

    spin_unlock_bh(&ar->arLock);

    skb->dev = ar->arNetDev;
    if (status) {
        AR6000_STAT_INC(ar, rx_errors);
        dev_kfree_skb(skb);
    } else if (ar->arWmiEnabled == true) {
        if (ept == ar->arControlEp) {
           /*
            * this is a wmi control msg
            */
#ifdef CONFIG_PM 
            ar6000_check_wow_status(ar, skb, true);
#endif /* CONFIG_PM */
            wmi_control_rx(ar->arWmi, skb);
        } else {
                struct wmi_data_hdr *dhdr = (struct wmi_data_hdr *)((struct sk_buff *)skb)->data;
                bool is_amsdu;
                u8 tid;

		/*
		 * This check can be removed if after a while we do not
		 * see the warning. For now we leave it to ensure
		 * we drop these frames accordingly in case the
		 * target generates them for some reason. These
		 * were used for an internal PAL but that's not
		 * used or supported anymore. These frames should
		 * not come up from the target.
		 */
                if (WARN_ON(WMI_DATA_HDR_GET_DATA_TYPE(dhdr) ==
			    WMI_DATA_HDR_DATA_TYPE_ACL)) {
			AR6000_STAT_INC(ar, rx_errors);
			dev_kfree_skb(skb);
			return;
		}

#ifdef CONFIG_PM 
                ar6000_check_wow_status(ar, NULL, false);
#endif /* CONFIG_PM */
                /*
                 * this is a wmi data packet
                 */
                 // NWF

                if (processDot11Hdr) {
                    minHdrLen = sizeof(struct wmi_data_hdr) + sizeof(struct ieee80211_frame) + sizeof(ATH_LLC_SNAP_HDR);
                } else {
                    minHdrLen = sizeof (struct wmi_data_hdr) + sizeof(ATH_MAC_HDR) +
                          sizeof(ATH_LLC_SNAP_HDR);
                }

                /* In the case of AP mode we may receive NULL data frames
                 * that do not have LLC hdr. They are 16 bytes in size.
                 * Allow these frames in the AP mode.
                 * ACL data frames don't follow ethernet frame bounds for
                 * min length
                 */
                if (ar->arNetworkType != AP_NETWORK &&
                    ((pPacket->ActualLength < minHdrLen) ||
                    (pPacket->ActualLength > WMI_MAX_AMSDU_RX_DATA_FRAME_LENGTH)))
                {
                    /*
                     * packet is too short or too long
                     */
                    AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("TOO SHORT or TOO LONG\n"));
                    AR6000_STAT_INC(ar, rx_errors);
                    AR6000_STAT_INC(ar, rx_length_errors);
                    dev_kfree_skb(skb);
                } else {
                    u16 seq_no;
                    u8 meta_type;

                    /* Get the Power save state of the STA */
                    if (ar->arNetworkType == AP_NETWORK) {
                        struct ar6k_sta *conn = NULL;
                        u8 psState=0,prevPsState;
                        ATH_MAC_HDR *datap=NULL;
                        u16 offset;

                        meta_type = WMI_DATA_HDR_GET_META(dhdr);

                        psState = (((struct wmi_data_hdr *)((struct sk_buff *)skb)->data)->info
                                     >> WMI_DATA_HDR_PS_SHIFT) & WMI_DATA_HDR_PS_MASK;

                        offset = sizeof(struct wmi_data_hdr);

                        switch (meta_type) {
                            case 0:
                                break;
                            case WMI_META_VERSION_1:
                                offset += sizeof(struct wmi_rx_meta_v1);
                                break;
                            case WMI_META_VERSION_2:
                                offset += sizeof(struct wmi_rx_meta_v2);
                                break;
                            default:
                                break;
                        }

                        datap = (ATH_MAC_HDR *)(((struct sk_buff *)skb)->data+offset);
                        conn = ieee80211_find_conn(ar, datap->srcMac);

                        if (conn) {
                            /* if there is a change in PS state of the STA,
                             * take appropriate steps.
                             * 1. If Sleep-->Awake, flush the psq for the STA
                             *    Clear the PVB for the STA.
                             * 2. If Awake-->Sleep, Starting queueing frames
                             * the STA.
                             */
                            prevPsState = STA_IS_PWR_SLEEP(conn);
                            if (psState) {
                                STA_SET_PWR_SLEEP(conn);
                            } else {
                                STA_CLR_PWR_SLEEP(conn);
                            }

                            if (prevPsState ^ STA_IS_PWR_SLEEP(conn)) {

                                if (!STA_IS_PWR_SLEEP(conn)) {

                                    spin_lock_bh(&conn->psqLock);
                                    while (!skb_queue_empty(&conn->psq)) {
                                        struct sk_buff *skb=NULL;

                                        skb = skb_dequeue(&conn->psq);
                                        spin_unlock_bh(&conn->psqLock);
                                        ar6000_data_tx(skb,ar->arNetDev);
                                        spin_lock_bh(&conn->psqLock);
                                    }
                                    spin_unlock_bh(&conn->psqLock);
                                    /* Clear the PVB for this STA */
                                    wmi_set_pvb_cmd(ar->arWmi, conn->aid, 0);
                                }
                            }
                        } else {
                            /* This frame is from a STA that is not associated*/
                            A_ASSERT(false);
                        }

                        /* Drop NULL data frames here */
                        if((pPacket->ActualLength < minHdrLen) ||
                                (pPacket->ActualLength > WMI_MAX_AMSDU_RX_DATA_FRAME_LENGTH)) {
                            dev_kfree_skb(skb);
                            goto rx_done;
                        }
                    }

                    is_amsdu = WMI_DATA_HDR_IS_AMSDU(dhdr) ? true : false;
                    tid = WMI_DATA_HDR_GET_UP(dhdr);
                    seq_no = WMI_DATA_HDR_GET_SEQNO(dhdr);
                    meta_type = WMI_DATA_HDR_GET_META(dhdr);
                    containsDot11Hdr = WMI_DATA_HDR_GET_DOT11(dhdr);

                    wmi_data_hdr_remove(ar->arWmi, skb);

                    switch (meta_type) {
                        case WMI_META_VERSION_1:
                            {
                                struct wmi_rx_meta_v1 *pMeta = (struct wmi_rx_meta_v1 *)((struct sk_buff *)skb)->data;
                                A_PRINTF("META %d %d %d %d %x\n", pMeta->status, pMeta->rix, pMeta->rssi, pMeta->channel, pMeta->flags);
                                skb_pull((struct sk_buff *)(void *)skb, sizeof(struct wmi_rx_meta_v1));
                                break;
                            }
                        case WMI_META_VERSION_2:
                            {
                                struct wmi_rx_meta_v2 *pMeta = (struct wmi_rx_meta_v2 *)((struct sk_buff *)skb)->data;
                                if(pMeta->csumFlags & 0x1){
                                    skb->ip_summed=CHECKSUM_COMPLETE;
                                    skb->csum=(pMeta->csum);
                                }
                                skb_pull((struct sk_buff *)(void *)skb, sizeof(struct wmi_rx_meta_v2));
                                break;
                            }
                        default:
                            break;
                    }

                    A_ASSERT(status == 0);

                    /* NWF: print the 802.11 hdr bytes */
                    if(containsDot11Hdr) {
                        status = wmi_dot11_hdr_remove(ar->arWmi,skb);
                    } else if(!is_amsdu) {
                        status = wmi_dot3_2_dix(skb);
                    }

                    if (status) {
                        /* Drop frames that could not be processed (lack of memory, etc.) */
                        dev_kfree_skb(skb);
                        goto rx_done;
                    }

                    if ((ar->arNetDev->flags & IFF_UP) == IFF_UP) {
                        if (ar->arNetworkType == AP_NETWORK) {
                            struct sk_buff *skb1 = NULL;
                            ATH_MAC_HDR *datap;

                            datap = (ATH_MAC_HDR *)((struct sk_buff *)skb)->data;
                            if (IEEE80211_IS_MULTICAST(datap->dstMac)) {
                                /* Bcast/Mcast frames should be sent to the OS
                                 * stack as well as on the air.
                                 */
                                skb1 = skb_copy(skb,GFP_ATOMIC);
                            } else {
                                /* Search for a connected STA with dstMac as
                                 * the Mac address. If found send the frame to
                                 * it on the air else send the frame up the
                                 * stack
                                 */
                                struct ar6k_sta *conn = NULL;
                                conn = ieee80211_find_conn(ar, datap->dstMac);

                                if (conn && ar->intra_bss) {
                                    skb1 = skb;
                                    skb = NULL;
                                } else if(conn && !ar->intra_bss) {
                                    dev_kfree_skb(skb);
                                    skb = NULL;
                                }
                            }
                            if (skb1) {
                                ar6000_data_tx(skb1, ar->arNetDev);
                            }
                        }
                    }
                    aggr_process_recv_frm(ar->aggr_cntxt, tid, seq_no, is_amsdu, (void **)&skb);
                    ar6000_deliver_frames_to_nw_stack((void *) ar->arNetDev, (void *)skb);
                }
            }
    } else {
        if (EPPING_ALIGNMENT_PAD > 0) {
            skb_pull((struct sk_buff *)skb, EPPING_ALIGNMENT_PAD);
        }
        ar6000_deliver_frames_to_nw_stack((void *)ar->arNetDev, (void *)skb);
    }

rx_done:

    return;
}

void ar6000_deliver_frames_to_nw_stack(void *dev, void *osbuf)
{
    struct sk_buff *skb = (struct sk_buff *)osbuf;

    if(skb) {
        skb->dev = dev;
        if ((skb->dev->flags & IFF_UP) == IFF_UP) {
#ifdef CONFIG_PM 
            ar6000_check_wow_status((struct ar6_softc *)ar6k_priv(dev), skb, false);
#endif /* CONFIG_PM */
            skb->protocol = eth_type_trans(skb, skb->dev);
        /*
         * If this routine is called on a ISR (Hard IRQ) or DSR (Soft IRQ)
         * or tasklet use the netif_rx to deliver the packet to the stack
         * netif_rx will queue the packet onto the receive queue and mark
         * the softirq thread has a pending action to complete. Kernel will 
         * schedule the softIrq kernel thread after processing the DSR.
         *
         * If this routine is called on a process context, use netif_rx_ni
         * which will schedle the softIrq kernel thread after queuing the packet.
         */
            if (in_interrupt()) {
                netif_rx(skb);
            } else {
                netif_rx_ni(skb);
            }
        } else {
            dev_kfree_skb(skb);
        }
    }
}

/* clean up our amsdu buffer list */
void ar6000_cleanup_amsdu_rxbufs(struct ar6_softc *ar)
{
	struct htc_packet  *pPacket;
	void        *osBuf;

	/* empty AMSDU buffer queue and free OS bufs */
	while (true) {

		spin_lock_bh(&ar->arLock);
		pPacket = HTC_PACKET_DEQUEUE(&ar->amsdu_rx_buffer_queue);
		spin_unlock_bh(&ar->arLock);

		if (NULL == pPacket) {
			break;
		}

		osBuf = pPacket->pPktContext;
		if (NULL == osBuf) {
			A_ASSERT(false);
			break;
		}

		dev_kfree_skb(osBuf);
	}

}

static void	
ar6000_set_multicast_list(struct net_device *dev)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("ar6000: Multicast filter not supported\n"));
}

static struct net_device_stats *
ar6000_get_stats(struct net_device *dev)
{
    struct ar6_softc *ar = (struct ar6_softc *)ar6k_priv(dev);
    return &ar->arNetStats;
}

void
ar6000_ready_event(void *devt, u8 *datap, u8 phyCap, u32 sw_ver, u32 abi_ver)
{
    struct ar6_softc *ar = (struct ar6_softc *)devt;
    struct net_device *dev = ar->arNetDev;

    memcpy(dev->dev_addr, datap, ETH_ALEN);
    AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("mac address = %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
        dev->dev_addr[0], dev->dev_addr[1],
        dev->dev_addr[2], dev->dev_addr[3],
        dev->dev_addr[4], dev->dev_addr[5]));

    ar->arVersion.wlan_ver = sw_ver;
    ar->arVersion.abi_ver = abi_ver;

    /* Indicate to the waiting thread that the ready event was received */
    ar->arWmiReady = true;
    wake_up(&arEvent);
}

void ar6000_install_static_wep_keys(struct ar6_softc *ar)
{
    u8 index;
    u8 keyUsage;

    for (index = WMI_MIN_KEY_INDEX; index <= WMI_MAX_KEY_INDEX; index++) {
        if (ar->arWepKeyList[index].arKeyLen) {
            keyUsage = GROUP_USAGE;
            if (index == ar->arDefTxKeyIndex) {
                keyUsage |= TX_USAGE;
            }
            wmi_addKey_cmd(ar->arWmi,
                           index,
                           WEP_CRYPT,
                           keyUsage,
                           ar->arWepKeyList[index].arKeyLen,
                           NULL,
                           ar->arWepKeyList[index].arKey, KEY_OP_INIT_VAL, NULL,
                           NO_SYNC_WMIFLAG);
        }
    }
}

void
add_new_sta(struct ar6_softc *ar, u8 *mac, u16 aid, u8 *wpaie,
            u8 ielen, u8 keymgmt, u8 ucipher, u8 auth)
{
    u8 free_slot=aid-1;

        memcpy(ar->sta_list[free_slot].mac, mac, ETH_ALEN);
        memcpy(ar->sta_list[free_slot].wpa_ie, wpaie, ielen);
        ar->sta_list[free_slot].aid = aid;
        ar->sta_list[free_slot].keymgmt = keymgmt;
        ar->sta_list[free_slot].ucipher = ucipher;
        ar->sta_list[free_slot].auth = auth;
        ar->sta_list_index = ar->sta_list_index | (1 << free_slot);
    ar->arAPStats.sta[free_slot].aid = aid;
}

void
ar6000_connect_event(struct ar6_softc *ar, u16 channel, u8 *bssid,
                     u16 listenInterval, u16 beaconInterval,
                     enum network_type networkType, u8 beaconIeLen,
                     u8 assocReqLen, u8 assocRespLen,
                     u8 *assocInfo)
{
    union iwreq_data wrqu;
    int i, beacon_ie_pos, assoc_resp_ie_pos, assoc_req_ie_pos;
    static const char *tag1 = "ASSOCINFO(ReqIEs=";
    static const char *tag2 = "ASSOCRESPIE=";
    static const char *beaconIetag = "BEACONIE=";
    char buf[WMI_CONTROL_MSG_MAX_LEN * 2 + strlen(tag1) + 1];
    char *pos;
    u8 key_op_ctrl;
    unsigned long flags;
    struct ieee80211req_key *ik;
    enum crypto_type keyType = NONE_CRYPT;

    if(ar->arNetworkType & AP_NETWORK) {
        struct net_device *dev = ar->arNetDev;
        if(memcmp(dev->dev_addr, bssid, ETH_ALEN)==0) {
            ik = &ar->ap_mode_bkey;

            switch(ar->arAuthMode) {
            case NONE_AUTH:
                if(ar->arPairwiseCrypto == WEP_CRYPT) {
                    ar6000_install_static_wep_keys(ar);
                }
#ifdef WAPI_ENABLE
                else if(ar->arPairwiseCrypto == WAPI_CRYPT) {
                    ap_set_wapi_key(ar, ik);
                }
#endif
                break;
            case WPA_PSK_AUTH:
            case WPA2_PSK_AUTH:
            case (WPA_PSK_AUTH|WPA2_PSK_AUTH):
                switch (ik->ik_type) {
                    case IEEE80211_CIPHER_TKIP:
                        keyType = TKIP_CRYPT;
                        break;
                    case IEEE80211_CIPHER_AES_CCM:
                        keyType = AES_CRYPT;
                        break;
                    default:
                       goto skip_key;
                }
                wmi_addKey_cmd(ar->arWmi, ik->ik_keyix, keyType, GROUP_USAGE,
                                ik->ik_keylen, (u8 *)&ik->ik_keyrsc,
                                ik->ik_keydata, KEY_OP_INIT_VAL, ik->ik_macaddr,
                                SYNC_BOTH_WMIFLAG);

                break;
            }
skip_key:
            ar->arConnected  = true;
            return;
        }

        A_PRINTF("NEW STA %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x \n "
            " AID=%d \n", bssid[0], bssid[1], bssid[2],
             bssid[3], bssid[4], bssid[5], channel);
        switch ((listenInterval>>8)&0xFF) {
            case OPEN_AUTH:
                A_PRINTF("AUTH: OPEN\n");
                break;
            case SHARED_AUTH:
                A_PRINTF("AUTH: SHARED\n");
                break;
            default:
                A_PRINTF("AUTH: Unknown\n");
                break;
        }
        switch (listenInterval&0xFF) {
            case WPA_PSK_AUTH:
                A_PRINTF("KeyMgmt: WPA-PSK\n");
                break;
            case WPA2_PSK_AUTH:
                A_PRINTF("KeyMgmt: WPA2-PSK\n");
                break;
            default:
                A_PRINTF("KeyMgmt: NONE\n");
                break;
        }
        switch (beaconInterval) {
            case AES_CRYPT:
                A_PRINTF("Cipher: AES\n");
                break;
            case TKIP_CRYPT:
                A_PRINTF("Cipher: TKIP\n");
                break;
            case WEP_CRYPT:
                A_PRINTF("Cipher: WEP\n");
                break;
#ifdef WAPI_ENABLE
            case WAPI_CRYPT:
                A_PRINTF("Cipher: WAPI\n");
                break;
#endif
            default:
                A_PRINTF("Cipher: NONE\n");
                break;
        }

        add_new_sta(ar, bssid, channel /*aid*/,
            assocInfo /* WPA IE */, assocRespLen /* IE len */,
            listenInterval&0xFF /* Keymgmt */, beaconInterval /* cipher */,
            (listenInterval>>8)&0xFF /* auth alg */);

        /* Send event to application */
        memset(&wrqu, 0, sizeof(wrqu));
        memcpy(wrqu.addr.sa_data, bssid, ETH_ALEN);
        wireless_send_event(ar->arNetDev, IWEVREGISTERED, &wrqu, NULL);
        /* In case the queue is stopped when we switch modes, this will
         * wake it up
         */
        netif_wake_queue(ar->arNetDev);
        return;
    }

    ar6k_cfg80211_connect_event(ar, channel, bssid,
                                listenInterval, beaconInterval,
                                networkType, beaconIeLen,
                                assocReqLen, assocRespLen,
                                assocInfo);

    memcpy(ar->arBssid, bssid, sizeof(ar->arBssid));
    ar->arBssChannel = channel;

    A_PRINTF("AR6000 connected event on freq %d ", channel);
    A_PRINTF("with bssid %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x "
            " listenInterval=%d, beaconInterval = %d, beaconIeLen = %d assocReqLen=%d"
            " assocRespLen =%d\n",
             bssid[0], bssid[1], bssid[2],
             bssid[3], bssid[4], bssid[5],
             listenInterval, beaconInterval,
             beaconIeLen, assocReqLen, assocRespLen);
    if (networkType & ADHOC_NETWORK) {
        if (networkType & ADHOC_CREATOR) {
            A_PRINTF("Network: Adhoc (Creator)\n");
        } else {
            A_PRINTF("Network: Adhoc (Joiner)\n");
        }
    } else {
        A_PRINTF("Network: Infrastructure\n");
    }

    if ((ar->arNetworkType == INFRA_NETWORK)) {
        wmi_listeninterval_cmd(ar->arWmi, ar->arListenIntervalT, ar->arListenIntervalB);
    }

    if (beaconIeLen && (sizeof(buf) > (9 + beaconIeLen * 2))) {
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\nBeaconIEs= "));

        beacon_ie_pos = 0;
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "%s", beaconIetag);
        pos = buf + 9;
        for (i = beacon_ie_pos; i < beacon_ie_pos + beaconIeLen; i++) {
            AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("%2.2x ", assocInfo[i]));
            sprintf(pos, "%2.2x", assocInfo[i]);
            pos += 2;
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\n"));

        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.length = strlen(buf);
        wireless_send_event(ar->arNetDev, IWEVCUSTOM, &wrqu, buf);
    }

    if (assocRespLen && (sizeof(buf) > (12 + (assocRespLen * 2))))
    {
        assoc_resp_ie_pos = beaconIeLen + assocReqLen +
                            sizeof(u16)  +  /* capinfo*/
                            sizeof(u16)  +  /* status Code */
                            sizeof(u16)  ;  /* associd */
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "%s", tag2);
        pos = buf + 12;
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\nAssocRespIEs= "));
        /*
         * The Association Response Frame w.o. the WLAN header is delivered to
         * the host, so skip over to the IEs
         */
        for (i = assoc_resp_ie_pos; i < assoc_resp_ie_pos + assocRespLen - 6; i++)
        {
            AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("%2.2x ", assocInfo[i]));
            sprintf(pos, "%2.2x", assocInfo[i]);
            pos += 2;
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\n"));

        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.length = strlen(buf);
        wireless_send_event(ar->arNetDev, IWEVCUSTOM, &wrqu, buf);
    }

    if (assocReqLen && (sizeof(buf) > (17 + (assocReqLen * 2)))) {
        /*
         * assoc Request includes capability and listen interval. Skip these.
         */
        assoc_req_ie_pos =  beaconIeLen +
                            sizeof(u16)  +  /* capinfo*/
                            sizeof(u16);    /* listen interval */

        memset(buf, 0, sizeof(buf));
        sprintf(buf, "%s", tag1);
        pos = buf + 17;
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("AssocReqIEs= "));
        for (i = assoc_req_ie_pos; i < assoc_req_ie_pos + assocReqLen - 4; i++) {
            AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("%2.2x ", assocInfo[i]));
            sprintf(pos, "%2.2x", assocInfo[i]);
            pos += 2;
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\n"));

        memset(&wrqu, 0, sizeof(wrqu));
        wrqu.data.length = strlen(buf);
        wireless_send_event(ar->arNetDev, IWEVCUSTOM, &wrqu, buf);
    }

    if (ar->user_savedkeys_stat == USER_SAVEDKEYS_STAT_RUN &&
        ar->user_saved_keys.keyOk == true)
    {
        key_op_ctrl = KEY_OP_VALID_MASK & ~KEY_OP_INIT_TSC;

        if (ar->user_key_ctrl & AR6000_USER_SETKEYS_RSC_UNCHANGED) {
            key_op_ctrl &= ~KEY_OP_INIT_RSC;
        } else {
            key_op_ctrl |= KEY_OP_INIT_RSC;
        }
        ar6000_reinstall_keys(ar, key_op_ctrl);
    }

    netif_wake_queue(ar->arNetDev);

    /* Update connect & link status atomically */
    spin_lock_irqsave(&ar->arLock, flags);
    ar->arConnected  = true;
    ar->arConnectPending = false;
    netif_carrier_on(ar->arNetDev);
    spin_unlock_irqrestore(&ar->arLock, flags);
    /* reset the rx aggr state */
    aggr_reset_state(ar->aggr_cntxt);
    reconnect_flag = 0;

    memset(&wrqu, 0, sizeof(wrqu));
    memcpy(wrqu.addr.sa_data, bssid, ETH_ALEN);
    wrqu.addr.sa_family = ARPHRD_ETHER;
    wireless_send_event(ar->arNetDev, SIOCGIWAP, &wrqu, NULL);
    if ((ar->arNetworkType == ADHOC_NETWORK) && ar->arIbssPsEnable) {
        memset(ar->arNodeMap, 0, sizeof(ar->arNodeMap));
        ar->arNodeNum = 0;
        ar->arNexEpId = ENDPOINT_2;
    }
   if (!ar->arUserBssFilter) {
        wmi_bssfilter_cmd(ar->arWmi, NONE_BSS_FILTER, 0);
   }

}

void
sta_cleanup(struct ar6_softc *ar, u8 i)
{
    struct sk_buff *skb;

    /* empty the queued pkts in the PS queue if any */
    spin_lock_bh(&ar->sta_list[i].psqLock);
    while (!skb_queue_empty(&ar->sta_list[i].psq)) {
        skb = skb_dequeue(&ar->sta_list[i].psq);
        dev_kfree_skb(skb);
    }
    spin_unlock_bh(&ar->sta_list[i].psqLock);

    /* Zero out the state fields */
    memset(&ar->arAPStats.sta[ar->sta_list[i].aid-1], 0, sizeof(struct wmi_per_sta_stat));
    memset(&ar->sta_list[i].mac, 0, ETH_ALEN);
    memset(&ar->sta_list[i].wpa_ie, 0, IEEE80211_MAX_IE);
    ar->sta_list[i].aid = 0;
    ar->sta_list[i].flags = 0;

    ar->sta_list_index = ar->sta_list_index & ~(1 << i);

}

u8 remove_sta(struct ar6_softc *ar, u8 *mac, u16 reason)
{
    u8 i, removed=0;

    if(IS_MAC_NULL(mac)) {
        return removed;
    }

    if(IS_MAC_BCAST(mac)) {
        A_PRINTF("DEL ALL STA\n");
        for(i=0; i < AP_MAX_NUM_STA; i++) {
            if(!IS_MAC_NULL(ar->sta_list[i].mac)) {
                sta_cleanup(ar, i);
                removed = 1;
            }
        }
    } else {
        for(i=0; i < AP_MAX_NUM_STA; i++) {
            if(memcmp(ar->sta_list[i].mac, mac, ETH_ALEN)==0) {
                A_PRINTF("DEL STA %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x "
                " aid=%d REASON=%d\n", mac[0], mac[1], mac[2],
                 mac[3], mac[4], mac[5], ar->sta_list[i].aid, reason);

                sta_cleanup(ar, i);
                removed = 1;
                break;
            }
        }
    }
    return removed;
}

void
ar6000_disconnect_event(struct ar6_softc *ar, u8 reason, u8 *bssid,
                        u8 assocRespLen, u8 *assocInfo, u16 protocolReasonStatus)
{
    u8 i;
    unsigned long flags;
    union iwreq_data wrqu;

    if(ar->arNetworkType & AP_NETWORK) {
        union iwreq_data wrqu;
        struct sk_buff *skb;

        if(!remove_sta(ar, bssid, protocolReasonStatus)) {
            return;
        }

        /* If there are no more associated STAs, empty the mcast PS q */
        if (ar->sta_list_index == 0) {
            spin_lock_bh(&ar->mcastpsqLock);
            while (!skb_queue_empty(&ar->mcastpsq)) {
                skb = skb_dequeue(&ar->mcastpsq);
                dev_kfree_skb(skb);
            }
            spin_unlock_bh(&ar->mcastpsqLock);

            /* Clear the LSB of the BitMapCtl field of the TIM IE */
            if (ar->arWmiReady) {
                wmi_set_pvb_cmd(ar->arWmi, MCAST_AID, 0);
            }
        }

        if(!IS_MAC_BCAST(bssid)) {
            /* Send event to application */
            memset(&wrqu, 0, sizeof(wrqu));
            memcpy(wrqu.addr.sa_data, bssid, ETH_ALEN);
            wireless_send_event(ar->arNetDev, IWEVEXPIRED, &wrqu, NULL);
        }

        ar->arConnected = false;
        return;
    }

    ar6k_cfg80211_disconnect_event(ar, reason, bssid,
                                   assocRespLen, assocInfo,
                                   protocolReasonStatus);

    /* Send disconnect event to supplicant */
    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.addr.sa_family = ARPHRD_ETHER;
    wireless_send_event(ar->arNetDev, SIOCGIWAP, &wrqu, NULL);

    /* it is necessary to clear the host-side rx aggregation state */
    aggr_reset_state(ar->aggr_cntxt);

    del_timer(&ar->disconnect_timer);

    A_PRINTF("AR6000 disconnected");
    if (bssid[0] || bssid[1] || bssid[2] || bssid[3] || bssid[4] || bssid[5]) {
        A_PRINTF(" from %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x ",
                 bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\nDisconnect Reason is %d", reason));
    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\nProtocol Reason/Status Code is %d", protocolReasonStatus));
    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\nAssocResp Frame = %s",
                    assocRespLen ? " " : "NULL"));
    for (i = 0; i < assocRespLen; i++) {
        if (!(i % 0x10)) {
            AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\n"));
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("%2.2x ", assocInfo[i]));
    }
    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("\n"));
    /*
     * If the event is due to disconnect cmd from the host, only they the target
     * would stop trying to connect. Under any other condition, target would
     * keep trying to connect.
     *
     */
    if( reason == DISCONNECT_CMD)
    {
        if ((!ar->arUserBssFilter) && (ar->arWmiReady)) {
            wmi_bssfilter_cmd(ar->arWmi, NONE_BSS_FILTER, 0);
        }
    } else {
        ar->arConnectPending = true;
        if (((reason == ASSOC_FAILED) && (protocolReasonStatus == 0x11)) ||
            ((reason == ASSOC_FAILED) && (protocolReasonStatus == 0x0) && (reconnect_flag == 1))) {
            ar->arConnected = true;
            return;
        }
    }

    if ((reason == NO_NETWORK_AVAIL) && (ar->arWmiReady)) 
    {
        bss_t *pWmiSsidnode = NULL;

        /* remove the current associated bssid node */
        wmi_free_node (ar->arWmi, bssid);

        /*
         * In case any other same SSID nodes are present
         * remove it, since those nodes also not available now
         */
        do
        {
            /*
             * Find the nodes based on SSID and remove it
             * NOTE :: This case will not work out for Hidden-SSID
             */
            pWmiSsidnode = wmi_find_Ssidnode (ar->arWmi, ar->arSsid, ar->arSsidLen, false, true);

            if (pWmiSsidnode)
            {
                wmi_free_node (ar->arWmi, pWmiSsidnode->ni_macaddr);
            }

        } while (pWmiSsidnode);
    }

    /* Update connect & link status atomically */
    spin_lock_irqsave(&ar->arLock, flags);
    ar->arConnected = false;
    netif_carrier_off(ar->arNetDev);
    spin_unlock_irqrestore(&ar->arLock, flags);

    if( (reason != CSERV_DISCONNECT) || (reconnect_flag != 1) ) {
        reconnect_flag = 0;
    }

    if (reason != CSERV_DISCONNECT)
    {
        ar->user_savedkeys_stat = USER_SAVEDKEYS_STAT_INIT;
        ar->user_key_ctrl      = 0;
    }

    netif_stop_queue(ar->arNetDev);
    memset(ar->arBssid, 0, sizeof(ar->arBssid));
    ar->arBssChannel = 0;

    ar6000_TxDataCleanup(ar);
}

void
ar6000_regDomain_event(struct ar6_softc *ar, u32 regCode)
{
    A_PRINTF("AR6000 Reg Code = 0x%x\n", regCode);
}

void
ar6000_aggr_rcv_addba_req_evt(struct ar6_softc *ar, struct wmi_addba_req_event *evt)
{
    if(evt->status == 0) {
        aggr_recv_addba_req_evt(ar->aggr_cntxt, evt->tid, evt->st_seq_no, evt->win_sz);
    }
}

void
ar6000_aggr_rcv_addba_resp_evt(struct ar6_softc *ar, struct wmi_addba_resp_event *evt)
{
    A_PRINTF("ADDBA RESP. tid %d status %d, sz %d\n", evt->tid, evt->status, evt->amsdu_sz);
    if(evt->status == 0) {
    }
}

void
ar6000_aggr_rcv_delba_req_evt(struct ar6_softc *ar, struct wmi_delba_event *evt)
{
    aggr_recv_delba_req_evt(ar->aggr_cntxt, evt->tid);
}

void
ar6000_neighborReport_event(struct ar6_softc *ar, int numAps, struct wmi_neighbor_info *info)
{
#if WIRELESS_EXT >= 18
    struct iw_pmkid_cand *pmkcand;
#else /* WIRELESS_EXT >= 18 */
    static const char *tag = "PRE-AUTH";
    char buf[128];
#endif /* WIRELESS_EXT >= 18 */

    union iwreq_data wrqu;
    int i;

    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_SCAN,("AR6000 Neighbor Report Event\n"));
    for (i=0; i < numAps; info++, i++) {
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_SCAN,("bssid %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x ",
            info->bssid[0], info->bssid[1], info->bssid[2],
            info->bssid[3], info->bssid[4], info->bssid[5]));
        if (info->bssFlags & WMI_PREAUTH_CAPABLE_BSS) {
            AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_SCAN,("preauth-cap"));
        }
        if (info->bssFlags & WMI_PMKID_VALID_BSS) {
            AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_SCAN,(" pmkid-valid\n"));
            continue;           /* we skip bss if the pmkid is already valid */
        }
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_SCAN,("\n"));
        memset(&wrqu, 0, sizeof(wrqu));
#if WIRELESS_EXT >= 18
        pmkcand = kmalloc(sizeof(struct iw_pmkid_cand), GFP_ATOMIC);
        memset(pmkcand, 0, sizeof(struct iw_pmkid_cand));
        pmkcand->index = i;
        pmkcand->flags = info->bssFlags;
        memcpy(pmkcand->bssid.sa_data, info->bssid, ETH_ALEN);
        wrqu.data.length = sizeof(struct iw_pmkid_cand);
        wireless_send_event(ar->arNetDev, IWEVPMKIDCAND, &wrqu, (char *)pmkcand);
        kfree(pmkcand);
#else /* WIRELESS_EXT >= 18 */
        snprintf(buf, sizeof(buf), "%s%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x",
                 tag,
                 info->bssid[0], info->bssid[1], info->bssid[2],
                 info->bssid[3], info->bssid[4], info->bssid[5],
                 i, info->bssFlags);
        wrqu.data.length = strlen(buf);
        wireless_send_event(ar->arNetDev, IWEVCUSTOM, &wrqu, buf);
#endif /* WIRELESS_EXT >= 18 */
    }
}

void
ar6000_tkip_micerr_event(struct ar6_softc *ar, u8 keyid, bool ismcast)
{
    static const char *tag = "MLME-MICHAELMICFAILURE.indication";
    char buf[128];
    union iwreq_data wrqu;

    /*
     * For AP case, keyid will have aid of STA which sent pkt with
     * MIC error. Use this aid to get MAC & send it to hostapd.
     */
    if (ar->arNetworkType == AP_NETWORK) {
        struct ar6k_sta *s = ieee80211_find_conn_for_aid(ar, (keyid >> 2));
        if(!s){
            A_PRINTF("AP TKIP MIC error received from Invalid aid / STA not found =%d\n", keyid);
            return;
        }
        A_PRINTF("AP TKIP MIC error received from aid=%d\n", keyid);
        snprintf(buf,sizeof(buf), "%s addr=%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
            tag, s->mac[0],s->mac[1],s->mac[2],s->mac[3],s->mac[4],s->mac[5]);
    } else {

    ar6k_cfg80211_tkip_micerr_event(ar, keyid, ismcast);

        A_PRINTF("AR6000 TKIP MIC error received for keyid %d %scast\n",
             keyid & 0x3, ismcast ? "multi": "uni");
        snprintf(buf, sizeof(buf), "%s(keyid=%d %sicast)", tag, keyid & 0x3,
             ismcast ? "mult" : "un");
    }

    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = strlen(buf);
    wireless_send_event(ar->arNetDev, IWEVCUSTOM, &wrqu, buf);
}

void
ar6000_scanComplete_event(struct ar6_softc *ar, int status)
{

    ar6k_cfg80211_scanComplete_event(ar, status);

    if (!ar->arUserBssFilter) {
        wmi_bssfilter_cmd(ar->arWmi, NONE_BSS_FILTER, 0);
    }
    if (ar->scan_triggered) {
        if (status== 0) {
            union iwreq_data wrqu;
            memset(&wrqu, 0, sizeof(wrqu));
            wireless_send_event(ar->arNetDev, SIOCGIWSCAN, &wrqu, NULL);
        }
        ar->scan_triggered = 0;
    }

    AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_SCAN,( "AR6000 scan complete: %d\n", status));
}

void
ar6000_targetStats_event(struct ar6_softc *ar,  u8 *ptr, u32 len)
{
    u8 ac;

    if(ar->arNetworkType == AP_NETWORK) {
        struct wmi_ap_mode_stat *p = (struct wmi_ap_mode_stat *)ptr;
        struct wmi_ap_mode_stat *ap = &ar->arAPStats;

        if (len < sizeof(*p)) {
            return;
        }

        for(ac=0;ac<AP_MAX_NUM_STA;ac++) {
            ap->sta[ac].tx_bytes   += p->sta[ac].tx_bytes;
            ap->sta[ac].tx_pkts    += p->sta[ac].tx_pkts;
            ap->sta[ac].tx_error   += p->sta[ac].tx_error;
            ap->sta[ac].tx_discard += p->sta[ac].tx_discard;
            ap->sta[ac].rx_bytes   += p->sta[ac].rx_bytes;
            ap->sta[ac].rx_pkts    += p->sta[ac].rx_pkts;
            ap->sta[ac].rx_error   += p->sta[ac].rx_error;
            ap->sta[ac].rx_discard += p->sta[ac].rx_discard;
        }

    } else {
         struct wmi_target_stats *pTarget = (struct wmi_target_stats *)ptr;
         struct targetStats *pStats = &ar->arTargetStats;

        if (len < sizeof(*pTarget)) {
            return;
        }

        // Update the RSSI of the connected bss.
        if (ar->arConnected) {
            bss_t *pConnBss = NULL;

            pConnBss = wmi_find_node(ar->arWmi,ar->arBssid);
            if (pConnBss)
            {
                pConnBss->ni_rssi = pTarget->cservStats.cs_aveBeacon_rssi;
                pConnBss->ni_snr = pTarget->cservStats.cs_aveBeacon_snr;
                wmi_node_return(ar->arWmi, pConnBss);
            }
        }

        AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("AR6000 updating target stats\n"));
        pStats->tx_packets          += pTarget->txrxStats.tx_stats.tx_packets;
        pStats->tx_bytes            += pTarget->txrxStats.tx_stats.tx_bytes;
        pStats->tx_unicast_pkts     += pTarget->txrxStats.tx_stats.tx_unicast_pkts;
        pStats->tx_unicast_bytes    += pTarget->txrxStats.tx_stats.tx_unicast_bytes;
        pStats->tx_multicast_pkts   += pTarget->txrxStats.tx_stats.tx_multicast_pkts;
        pStats->tx_multicast_bytes  += pTarget->txrxStats.tx_stats.tx_multicast_bytes;
        pStats->tx_broadcast_pkts   += pTarget->txrxStats.tx_stats.tx_broadcast_pkts;
        pStats->tx_broadcast_bytes  += pTarget->txrxStats.tx_stats.tx_broadcast_bytes;
        pStats->tx_rts_success_cnt  += pTarget->txrxStats.tx_stats.tx_rts_success_cnt;
        for(ac = 0; ac < WMM_NUM_AC; ac++)
            pStats->tx_packet_per_ac[ac] += pTarget->txrxStats.tx_stats.tx_packet_per_ac[ac];
        pStats->tx_errors           += pTarget->txrxStats.tx_stats.tx_errors;
        pStats->tx_failed_cnt       += pTarget->txrxStats.tx_stats.tx_failed_cnt;
        pStats->tx_retry_cnt        += pTarget->txrxStats.tx_stats.tx_retry_cnt;
        pStats->tx_mult_retry_cnt   += pTarget->txrxStats.tx_stats.tx_mult_retry_cnt;
        pStats->tx_rts_fail_cnt     += pTarget->txrxStats.tx_stats.tx_rts_fail_cnt;
        pStats->tx_unicast_rate      = wmi_get_rate(pTarget->txrxStats.tx_stats.tx_unicast_rate);

        pStats->rx_packets          += pTarget->txrxStats.rx_stats.rx_packets;
        pStats->rx_bytes            += pTarget->txrxStats.rx_stats.rx_bytes;
        pStats->rx_unicast_pkts     += pTarget->txrxStats.rx_stats.rx_unicast_pkts;
        pStats->rx_unicast_bytes    += pTarget->txrxStats.rx_stats.rx_unicast_bytes;
        pStats->rx_multicast_pkts   += pTarget->txrxStats.rx_stats.rx_multicast_pkts;
        pStats->rx_multicast_bytes  += pTarget->txrxStats.rx_stats.rx_multicast_bytes;
        pStats->rx_broadcast_pkts   += pTarget->txrxStats.rx_stats.rx_broadcast_pkts;
        pStats->rx_broadcast_bytes  += pTarget->txrxStats.rx_stats.rx_broadcast_bytes;
        pStats->rx_fragment_pkt     += pTarget->txrxStats.rx_stats.rx_fragment_pkt;
        pStats->rx_errors           += pTarget->txrxStats.rx_stats.rx_errors;
        pStats->rx_crcerr           += pTarget->txrxStats.rx_stats.rx_crcerr;
        pStats->rx_key_cache_miss   += pTarget->txrxStats.rx_stats.rx_key_cache_miss;
        pStats->rx_decrypt_err      += pTarget->txrxStats.rx_stats.rx_decrypt_err;
        pStats->rx_duplicate_frames += pTarget->txrxStats.rx_stats.rx_duplicate_frames;
        pStats->rx_unicast_rate      = wmi_get_rate(pTarget->txrxStats.rx_stats.rx_unicast_rate);


        pStats->tkip_local_mic_failure
                                += pTarget->txrxStats.tkipCcmpStats.tkip_local_mic_failure;
        pStats->tkip_counter_measures_invoked
                                += pTarget->txrxStats.tkipCcmpStats.tkip_counter_measures_invoked;
        pStats->tkip_replays        += pTarget->txrxStats.tkipCcmpStats.tkip_replays;
        pStats->tkip_format_errors  += pTarget->txrxStats.tkipCcmpStats.tkip_format_errors;
        pStats->ccmp_format_errors  += pTarget->txrxStats.tkipCcmpStats.ccmp_format_errors;
        pStats->ccmp_replays        += pTarget->txrxStats.tkipCcmpStats.ccmp_replays;

        pStats->power_save_failure_cnt += pTarget->pmStats.power_save_failure_cnt;
        pStats->noise_floor_calibation = pTarget->noise_floor_calibation;

        pStats->cs_bmiss_cnt        += pTarget->cservStats.cs_bmiss_cnt;
        pStats->cs_lowRssi_cnt      += pTarget->cservStats.cs_lowRssi_cnt;
        pStats->cs_connect_cnt      += pTarget->cservStats.cs_connect_cnt;
        pStats->cs_disconnect_cnt   += pTarget->cservStats.cs_disconnect_cnt;
        pStats->cs_aveBeacon_snr    = pTarget->cservStats.cs_aveBeacon_snr;
        pStats->cs_aveBeacon_rssi   = pTarget->cservStats.cs_aveBeacon_rssi;

        if (enablerssicompensation) {
            pStats->cs_aveBeacon_rssi =
                    rssi_compensation_calc(ar, pStats->cs_aveBeacon_rssi);
        }
        pStats->cs_lastRoam_msec    = pTarget->cservStats.cs_lastRoam_msec;
        pStats->cs_snr              = pTarget->cservStats.cs_snr;
        pStats->cs_rssi             = pTarget->cservStats.cs_rssi;

        pStats->lq_val              = pTarget->lqVal;

        pStats->wow_num_pkts_dropped += pTarget->wowStats.wow_num_pkts_dropped;
        pStats->wow_num_host_pkt_wakeups += pTarget->wowStats.wow_num_host_pkt_wakeups;
        pStats->wow_num_host_event_wakeups += pTarget->wowStats.wow_num_host_event_wakeups;
        pStats->wow_num_events_discarded += pTarget->wowStats.wow_num_events_discarded;
        pStats->arp_received += pTarget->arpStats.arp_received;
        pStats->arp_matched  += pTarget->arpStats.arp_matched;
        pStats->arp_replied  += pTarget->arpStats.arp_replied;

        if (ar->statsUpdatePending) {
            ar->statsUpdatePending = false;
            wake_up(&arEvent);
        }
    }
}

void
ar6000_rssiThreshold_event(struct ar6_softc *ar,  enum wmi_rssi_threshold_val newThreshold, s16 rssi)
{
    struct user_rssi_thold userRssiThold;

    rssi = rssi + SIGNAL_QUALITY_NOISE_FLOOR;

    if (enablerssicompensation) {
        rssi = rssi_compensation_calc(ar, rssi);
    }

    /* Send an event to the app */
    userRssiThold.tag = ar->rssi_map[newThreshold].tag;
    userRssiThold.rssi = rssi;
    A_PRINTF("rssi Threshold range = %d tag = %d  rssi = %d\n", newThreshold,
             userRssiThold.tag, userRssiThold.rssi);
}


void
ar6000_hbChallengeResp_event(struct ar6_softc *ar, u32 cookie, u32 source)
{
    if (source != APP_HB_CHALLENGE) {
        /* This would ignore the replys that come in after their due time */
        if (cookie == ar->arHBChallengeResp.seqNum) {
            ar->arHBChallengeResp.outstanding = false;
        }
    }
}


void
ar6000_reportError_event(struct ar6_softc *ar, enum wmi_target_error_val errorVal)
{
	static const char * const errString[] = {
		[WMI_TARGET_PM_ERR_FAIL]    "WMI_TARGET_PM_ERR_FAIL",
		[WMI_TARGET_KEY_NOT_FOUND]  "WMI_TARGET_KEY_NOT_FOUND",
		[WMI_TARGET_DECRYPTION_ERR] "WMI_TARGET_DECRYPTION_ERR",
		[WMI_TARGET_BMISS]          "WMI_TARGET_BMISS",
		[WMI_PSDISABLE_NODE_JOIN]   "WMI_PSDISABLE_NODE_JOIN"
	};

    A_PRINTF("AR6000 Error on Target. Error = 0x%x\n", errorVal);

    /* One error is reported at a time, and errorval is a bitmask */
    if(errorVal & (errorVal - 1))
       return;

    A_PRINTF("AR6000 Error type = ");
    switch(errorVal)
    {
        case WMI_TARGET_PM_ERR_FAIL:
        case WMI_TARGET_KEY_NOT_FOUND:
        case WMI_TARGET_DECRYPTION_ERR:
        case WMI_TARGET_BMISS:
        case WMI_PSDISABLE_NODE_JOIN:
            A_PRINTF("%s\n", errString[errorVal]);
            break;
        default:
            A_PRINTF("INVALID\n");
            break;
    }

}


void
ar6000_cac_event(struct ar6_softc *ar, u8 ac, u8 cacIndication,
                 u8 statusCode, u8 *tspecSuggestion)
{
    WMM_TSPEC_IE    *tspecIe;

    /*
     * This is the TSPEC IE suggestion from AP.
     * Suggestion provided by AP under some error
     * cases, could be helpful for the host app.
     * Check documentation.
     */
    tspecIe = (WMM_TSPEC_IE *)tspecSuggestion;

    /*
     * What do we do, if we get TSPEC rejection? One thought
     * that comes to mind is implictly delete the pstream...
     */
    A_PRINTF("AR6000 CAC notification. "
                "AC = %d, cacIndication = 0x%x, statusCode = 0x%x\n",
                 ac, cacIndication, statusCode);
}

void
ar6000_channel_change_event(struct ar6_softc *ar, u16 oldChannel,
                            u16 newChannel)
{
    A_PRINTF("Channel Change notification\nOld Channel: %d, New Channel: %d\n",
             oldChannel, newChannel);
}

#define AR6000_PRINT_BSSID(_pBss)  do {     \
        A_PRINTF("%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x ",\
                 (_pBss)[0],(_pBss)[1],(_pBss)[2],(_pBss)[3],\
                 (_pBss)[4],(_pBss)[5]);  \
} while(0)

void
ar6000_roam_tbl_event(struct ar6_softc *ar, struct wmi_target_roam_tbl *pTbl)
{
    u8 i;

    A_PRINTF("ROAM TABLE NO OF ENTRIES is %d ROAM MODE is %d\n",
              pTbl->numEntries, pTbl->roamMode);
    for (i= 0; i < pTbl->numEntries; i++) {
        A_PRINTF("[%d]bssid %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x ", i,
            pTbl->bssRoamInfo[i].bssid[0], pTbl->bssRoamInfo[i].bssid[1],
            pTbl->bssRoamInfo[i].bssid[2],
            pTbl->bssRoamInfo[i].bssid[3],
            pTbl->bssRoamInfo[i].bssid[4],
            pTbl->bssRoamInfo[i].bssid[5]);
        A_PRINTF("RSSI %d RSSIDT %d LAST RSSI %d UTIL %d ROAM_UTIL %d"
                 " BIAS %d\n",
            pTbl->bssRoamInfo[i].rssi,
            pTbl->bssRoamInfo[i].rssidt,
            pTbl->bssRoamInfo[i].last_rssi,
            pTbl->bssRoamInfo[i].util,
            pTbl->bssRoamInfo[i].roam_util,
            pTbl->bssRoamInfo[i].bias);
    }
}

void
ar6000_wow_list_event(struct ar6_softc *ar, u8 num_filters, struct wmi_get_wow_list_reply *wow_reply)
{
    u8 i,j;

    /*Each event now contains exactly one filter, see bug 26613*/
    A_PRINTF("WOW pattern %d of %d patterns\n", wow_reply->this_filter_num,                 wow_reply->num_filters);
    A_PRINTF("wow mode = %s host mode = %s\n",
            (wow_reply->wow_mode == 0? "disabled":"enabled"),
            (wow_reply->host_mode == 1 ? "awake":"asleep"));


    /*If there are no patterns, the reply will only contain generic
      WoW information. Pattern information will exist only if there are
      patterns present. Bug 26716*/

   /* If this event contains pattern information, display it*/
    if (wow_reply->this_filter_num) {
        i=0;
        A_PRINTF("id=%d size=%d offset=%d\n",
                    wow_reply->wow_filters[i].wow_filter_id,
                    wow_reply->wow_filters[i].wow_filter_size,
                    wow_reply->wow_filters[i].wow_filter_offset);
       A_PRINTF("wow pattern = ");
       for (j=0; j< wow_reply->wow_filters[i].wow_filter_size; j++) {
             A_PRINTF("%2.2x",wow_reply->wow_filters[i].wow_filter_pattern[j]);
        }

        A_PRINTF("\nwow mask = ");
        for (j=0; j< wow_reply->wow_filters[i].wow_filter_size; j++) {
            A_PRINTF("%2.2x",wow_reply->wow_filters[i].wow_filter_mask[j]);
        }
        A_PRINTF("\n");
    }
}

/*
 * Report the Roaming related data collected on the target
 */
void
ar6000_display_roam_time(struct wmi_target_roam_time *p)
{
    A_PRINTF("Disconnect Data : BSSID: ");
    AR6000_PRINT_BSSID(p->disassoc_bssid);
    A_PRINTF(" RSSI %d DISASSOC Time %d NO_TXRX_TIME %d\n",
             p->disassoc_bss_rssi,p->disassoc_time,
             p->no_txrx_time);
    A_PRINTF("Connect Data: BSSID: ");
    AR6000_PRINT_BSSID(p->assoc_bssid);
    A_PRINTF(" RSSI %d ASSOC Time %d TXRX_TIME %d\n",
             p->assoc_bss_rssi,p->assoc_time,
             p->allow_txrx_time);
}

void
ar6000_roam_data_event(struct ar6_softc *ar, struct wmi_target_roam_data *p)
{
    switch (p->roamDataType) {
        case ROAM_DATA_TIME:
            ar6000_display_roam_time(&p->u.roamTime);
            break;
        default:
            break;
    }
}

void ar6000_bssInfo_event_rx(struct ar6_softc *ar, u8 *datap, int len)
{
	struct sk_buff *skb;
	struct wmi_bss_info_hdr *bih = (struct wmi_bss_info_hdr *)datap;


	if (!ar->arMgmtFilter)
		return;

	if (((ar->arMgmtFilter & IEEE80211_FILTER_TYPE_BEACON) &&
				(bih->frameType != BEACON_FTYPE))  ||
			((ar->arMgmtFilter & IEEE80211_FILTER_TYPE_PROBE_RESP) &&
			 (bih->frameType != PROBERESP_FTYPE)))
		return;

	skb = dev_alloc_skb(len);
	if (!skb)
		return;

	skb_put(skb, len);
	memcpy(skb->data, datap, len);
	skb->dev = ar->arNetDev;
	memcpy(skb_mac_header(skb), skb->data, 6);
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(0x0019);
	netif_rx(skb);
}

u32 wmiSendCmdNum;

int
ar6000_control_tx(void *devt, void *osbuf, enum htc_endpoint_id eid)
{
    struct ar6_softc       *ar = (struct ar6_softc *)devt;
    int         status = 0;
    struct ar_cookie *cookie = NULL;
    int i;
#ifdef CONFIG_PM
    if (ar->arWowState != WLAN_WOW_STATE_NONE) {
        dev_kfree_skb(osbuf);
        return A_EACCES;
    }
#endif /* CONFIG_PM */
        /* take lock to protect ar6000_alloc_cookie() */
    spin_lock_bh(&ar->arLock);

    do {

        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_TX,("ar_contrstatus = ol_tx: skb=0x%lx, len=0x%x eid =%d\n",
                         (unsigned long)osbuf, ((struct sk_buff *)osbuf)->len, eid));

        if (ar->arWMIControlEpFull && (eid == ar->arControlEp)) {
                /* control endpoint is full, don't allocate resources, we
                 * are just going to drop this packet */
            cookie = NULL;
            AR_DEBUG_PRINTF(ATH_DEBUG_ERR,(" WMI Control EP full, dropping packet : 0x%lX, len:%d \n",
                    (unsigned long)osbuf, ((struct sk_buff *)osbuf)->len));
        } else {
            cookie = ar6000_alloc_cookie(ar);
        }

        if (cookie == NULL) {
            status = A_NO_MEMORY;
            break;
        }

        if(logWmiRawMsgs) {
            A_PRINTF("WMI cmd send, msgNo %d :", wmiSendCmdNum);
            for(i = 0; i < ((struct sk_buff *)osbuf)->len; i++)
                A_PRINTF("%x ", ((u8 *)((struct sk_buff *)osbuf)->data)[i]);
            A_PRINTF("\n");
        }

        wmiSendCmdNum++;

    } while (false);

    if (cookie != NULL) {
            /* got a structure to send it out on */
        ar->arTxPending[eid]++;

        if (eid != ar->arControlEp) {
            ar->arTotalTxDataPending++;
        }
    }

    spin_unlock_bh(&ar->arLock);

    if (cookie != NULL) {
        cookie->arc_bp[0] = (unsigned long)osbuf;
        cookie->arc_bp[1] = 0;
        SET_HTC_PACKET_INFO_TX(&cookie->HtcPkt,
                               cookie,
                               ((struct sk_buff *)osbuf)->data,
                               ((struct sk_buff *)osbuf)->len,
                               eid,
                               AR6K_CONTROL_PKT_TAG);
            /* this interface is asynchronous, if there is an error, cleanup will happen in the
             * TX completion callback */
        HTCSendPkt(ar->arHtcTarget, &cookie->HtcPkt);
        status = 0;
    }

    if (status) {
        dev_kfree_skb(osbuf);
    }
    return status;
}

/* indicate tx activity or inactivity on a WMI stream */
void ar6000_indicate_tx_activity(void *devt, u8 TrafficClass, bool Active)
{
    struct ar6_softc  *ar = (struct ar6_softc *)devt;
    enum htc_endpoint_id eid ;
    int i;

    if (ar->arWmiEnabled) {
        eid = arAc2EndpointID(ar, TrafficClass);

        spin_lock_bh(&ar->arLock);

        ar->arAcStreamActive[TrafficClass] = Active;

        if (Active) {
            /* when a stream goes active, keep track of the active stream with the highest priority */

            if (ar->arAcStreamPriMap[TrafficClass] > ar->arHiAcStreamActivePri) {
                    /* set the new highest active priority */
                ar->arHiAcStreamActivePri = ar->arAcStreamPriMap[TrafficClass];
            }

        } else {
            /* when a stream goes inactive, we may have to search for the next active stream
             * that is the highest priority */

            if (ar->arHiAcStreamActivePri == ar->arAcStreamPriMap[TrafficClass]) {

                /* the highest priority stream just went inactive */

                    /* reset and search for the "next" highest "active" priority stream */
                ar->arHiAcStreamActivePri = 0;
                for (i = 0; i < WMM_NUM_AC; i++) {
                    if (ar->arAcStreamActive[i]) {
                        if (ar->arAcStreamPriMap[i] > ar->arHiAcStreamActivePri) {
                            /* set the new highest active priority */
                            ar->arHiAcStreamActivePri = ar->arAcStreamPriMap[i];
                        }
                    }
                }
            }
        }

        spin_unlock_bh(&ar->arLock);

    } else {
            /* for mbox ping testing, the traffic class is mapped directly as a stream ID,
             * see handling of AR6000_XIOCTL_TRAFFIC_ACTIVITY_CHANGE in ioctl.c
             * convert the stream ID to a endpoint */
        eid = arAc2EndpointID(ar, TrafficClass);
    }

        /* notify HTC, this may cause credit distribution changes */

    HTCIndicateActivityChange(ar->arHtcTarget,
                              eid,
                              Active);

}

/* Init cookie queue */
void ar6000_cookie_init(struct ar6_softc *ar)
{
    u32 i;

    ar->arCookieList = NULL;
    ar->arCookieCount = 0;

    memset(s_ar_cookie_mem, 0, sizeof(s_ar_cookie_mem));

    for (i = 0; i < MAX_COOKIE_NUM; i++) {
        ar6000_free_cookie(ar, &s_ar_cookie_mem[i]);
    }
}

/* cleanup cookie queue */
void ar6000_cookie_cleanup(struct ar6_softc *ar)
{
    /* It is gone .... */
    ar->arCookieList = NULL;
    ar->arCookieCount = 0;
}

/* Init cookie queue */
static void
ar6000_free_cookie(struct ar6_softc *ar, struct ar_cookie * cookie)
{
    /* Insert first */
    A_ASSERT(ar != NULL);
    A_ASSERT(cookie != NULL);

    cookie->arc_list_next = ar->arCookieList;
    ar->arCookieList = cookie;
    ar->arCookieCount++;
}

/* cleanup cookie queue */
static struct ar_cookie *
ar6000_alloc_cookie(struct ar6_softc  *ar)
{
    struct ar_cookie   *cookie;

    cookie = ar->arCookieList;
    if(cookie != NULL)
    {
        ar->arCookieList = cookie->arc_list_next;
        ar->arCookieCount--;
    }

    return cookie;
}

void
ar6000_tx_retry_err_event(void *devt)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_ERR,("Tx retries reach maximum!\n"));
}

void
ar6000_snrThresholdEvent_rx(void *devt, enum wmi_snr_threshold_val newThreshold, u8 snr)
{
    struct wmi_snr_threshold_event event;

    event.range = newThreshold;
    event.snr = snr;
}

void
ar6000_lqThresholdEvent_rx(void *devt, enum wmi_lq_threshold_val newThreshold, u8 lq)
{
    AR_DEBUG_PRINTF(ATH_DEBUG_INFO,("lq threshold range %d, lq %d\n", newThreshold, lq));
}



u32 a_copy_to_user(void *to, const void *from, u32 n)
{
    return(copy_to_user(to, from, n));
}

u32 a_copy_from_user(void *to, const void *from, u32 n)
{
    return(copy_from_user(to, from, n));
}


int
ar6000_get_driver_cfg(struct net_device *dev,
                        u16 cfgParam,
                        void *result)
{

    int    ret = 0;

    switch(cfgParam)
    {
        case AR6000_DRIVER_CFG_GET_WLANNODECACHING:
           *((u32 *)result) = wlanNodeCaching;
           break;
        case AR6000_DRIVER_CFG_LOG_RAW_WMI_MSGS:
           *((u32 *)result) = logWmiRawMsgs;
            break;
        default:
           ret = EINVAL;
           break;
    }

    return ret;
}

void
ar6000_keepalive_rx(void *devt, u8 configured)
{
    wake_up(&arEvent);
}

void
ar6000_pmkid_list_event(void *devt, u8 numPMKID, struct wmi_pmkid *pmkidList,
                        u8 *bssidList)
{
    u8 i, j;

    A_PRINTF("Number of Cached PMKIDs is %d\n", numPMKID);

    for (i = 0; i < numPMKID; i++) {
        A_PRINTF("\nBSSID %d ", i);
            for (j = 0; j < ETH_ALEN; j++) {
                A_PRINTF("%2.2x", bssidList[j]);
            }
        bssidList += (ETH_ALEN + WMI_PMKID_LEN);
        A_PRINTF("\nPMKID %d ", i);
            for (j = 0; j < WMI_PMKID_LEN; j++) {
                A_PRINTF("%2.2x", pmkidList->pmkid[j]);
            }
        pmkidList = (struct wmi_pmkid *)((u8 *)pmkidList + ETH_ALEN +
                                  WMI_PMKID_LEN);
    }
}

void ar6000_pspoll_event(struct ar6_softc *ar,u8 aid)
{
    struct ar6k_sta *conn=NULL;
    bool isPsqEmpty = false;

    conn = ieee80211_find_conn_for_aid(ar, aid);

    /* If the PS q for this STA is not empty, dequeue and send a pkt from
     * the head of the q. Also update the More data bit in the WMI_DATA_HDR
     * if there are more pkts for this STA in the PS q. If there are no more
     * pkts for this STA, update the PVB for this STA.
     */
    spin_lock_bh(&conn->psqLock);
    isPsqEmpty  = skb_queue_empty(&conn->psq);
    spin_unlock_bh(&conn->psqLock);

    if (isPsqEmpty) {
        /* TODO:No buffered pkts for this STA. Send out a NULL data frame */
    } else {
        struct sk_buff *skb = NULL;

        spin_lock_bh(&conn->psqLock);
        skb = skb_dequeue(&conn->psq);
        spin_unlock_bh(&conn->psqLock);
        /* Set the STA flag to PSPolled, so that the frame will go out */
        STA_SET_PS_POLLED(conn);
        ar6000_data_tx(skb, ar->arNetDev);
        STA_CLR_PS_POLLED(conn);

        /* Clear the PVB for this STA if the queue has become empty */
        spin_lock_bh(&conn->psqLock);
        isPsqEmpty  = skb_queue_empty(&conn->psq);
        spin_unlock_bh(&conn->psqLock);

        if (isPsqEmpty) {
            wmi_set_pvb_cmd(ar->arWmi, conn->aid, 0);
        }
    }
}

void ar6000_dtimexpiry_event(struct ar6_softc *ar)
{
    bool isMcastQueued = false;
    struct sk_buff *skb = NULL;

    /* If there are no associated STAs, ignore the DTIM expiry event.
     * There can be potential race conditions where the last associated
     * STA may disconnect & before the host could clear the 'Indicate DTIM'
     * request to the firmware, the firmware would have just indicated a DTIM
     * expiry event. The race is between 'clear DTIM expiry cmd' going
     * from the host to the firmware & the DTIM expiry event happening from
     * the firmware to the host.
     */
    if (ar->sta_list_index == 0) {
        return;
    }

    spin_lock_bh(&ar->mcastpsqLock);
    isMcastQueued = skb_queue_empty(&ar->mcastpsq);
    spin_unlock_bh(&ar->mcastpsqLock);

    A_ASSERT(isMcastQueued == false);

    /* Flush the mcast psq to the target */
    /* Set the STA flag to DTIMExpired, so that the frame will go out */
    ar->DTIMExpired = true;

    spin_lock_bh(&ar->mcastpsqLock);
    while (!skb_queue_empty(&ar->mcastpsq)) {
        skb = skb_dequeue(&ar->mcastpsq);
        spin_unlock_bh(&ar->mcastpsqLock);

        ar6000_data_tx(skb, ar->arNetDev);

        spin_lock_bh(&ar->mcastpsqLock);
    }
    spin_unlock_bh(&ar->mcastpsqLock);

    /* Reset the DTIMExpired flag back to 0 */
    ar->DTIMExpired = false;

    /* Clear the LSB of the BitMapCtl field of the TIM IE */
    wmi_set_pvb_cmd(ar->arWmi, MCAST_AID, 0);
}

/* This is the function to call when need to use the cust data */
static u8 *ar6000_get_cust_data_buffer(u32 TargetType)
{
	if (TargetType == TARGET_TYPE_AR6003)
		return custDataAR6003;

	return NULL;
}

void read_rssi_compensation_param(struct ar6_softc *ar)
{
	u8 *cust_data_ptr;

	cust_data_ptr = ar6000_get_cust_data_buffer(ar->arTargetType);

	rssi_compensation_param.customerID = *(u16 *)cust_data_ptr & 0xffff;
	rssi_compensation_param.enable = *(u16 *)(cust_data_ptr+2) & 0xffff;
	rssi_compensation_param.bg_param_a = *(u16 *)(cust_data_ptr+4) & 0xffff;
	rssi_compensation_param.bg_param_b = *(u16 *)(cust_data_ptr+6) & 0xffff;
	rssi_compensation_param.a_param_a = *(u16 *)(cust_data_ptr+8) & 0xffff;
	rssi_compensation_param.a_param_b = *(u16 *)(cust_data_ptr+10) &0xffff;
	rssi_compensation_param.reserved = *(u32 *)(cust_data_ptr+12);


	if (rssi_compensation_param.enable != 0x1)
		rssi_compensation_param.enable = 0;
}

#ifdef WAPI_ENABLE
void ap_wapi_rekey_event(struct ar6_softc *ar, u8 type, u8 *mac)
{
    union iwreq_data wrqu;
    char buf[20];

    memset(buf, 0, sizeof(buf));

    strcpy(buf, "WAPI_REKEY");
    buf[10] = type;
    memcpy(&buf[11], mac, ETH_ALEN);

    memset(&wrqu, 0, sizeof(wrqu));
    wrqu.data.length = 10+1+ETH_ALEN;
    wireless_send_event(ar->arNetDev, IWEVCUSTOM, &wrqu, buf);

    A_PRINTF("WAPI REKEY - %d - %02x:%02x\n", type, mac[4], mac[5]);
}
#endif

static int
ar6000_reinstall_keys(struct ar6_softc *ar, u8 key_op_ctrl)
{
    int status = 0;
    struct ieee80211req_key *uik = &ar->user_saved_keys.ucast_ik;
    struct ieee80211req_key *bik = &ar->user_saved_keys.bcast_ik;
    enum crypto_type  keyType = ar->user_saved_keys.keyType;

    if (IEEE80211_CIPHER_CCKM_KRK != uik->ik_type) {
        if (NONE_CRYPT == keyType) {
            goto _reinstall_keys_out;
        }

        if (uik->ik_keylen) {
            status = wmi_addKey_cmd(ar->arWmi, uik->ik_keyix,
                    ar->user_saved_keys.keyType, PAIRWISE_USAGE,
                    uik->ik_keylen, (u8 *)&uik->ik_keyrsc,
                    uik->ik_keydata, key_op_ctrl, uik->ik_macaddr, SYNC_BEFORE_WMIFLAG);
        }

    } else {
        status = wmi_add_krk_cmd(ar->arWmi, uik->ik_keydata);
    }

    if (IEEE80211_CIPHER_CCKM_KRK != bik->ik_type) {
        if (NONE_CRYPT == keyType) {
            goto _reinstall_keys_out;
        }

        if (bik->ik_keylen) {
            status = wmi_addKey_cmd(ar->arWmi, bik->ik_keyix,
                    ar->user_saved_keys.keyType, GROUP_USAGE,
                    bik->ik_keylen, (u8 *)&bik->ik_keyrsc,
                    bik->ik_keydata, key_op_ctrl, bik->ik_macaddr, NO_SYNC_WMIFLAG);
        }
    } else {
        status = wmi_add_krk_cmd(ar->arWmi, bik->ik_keydata);
    }

_reinstall_keys_out:
    ar->user_savedkeys_stat = USER_SAVEDKEYS_STAT_INIT;
    ar->user_key_ctrl      = 0;

    return status;
}


int
ar6000_connect_to_ap(struct ar6_softc *ar)
{
    /* The ssid length check prevents second "essid off" from the user,
       to be treated as a connect cmd. The second "essid off" is ignored.
    */
    if((ar->arWmiReady == true) && (ar->arSsidLen > 0) && ar->arNetworkType!=AP_NETWORK)
    {
        int status;
        if((ADHOC_NETWORK != ar->arNetworkType) &&
           (NONE_AUTH==ar->arAuthMode)          &&
           (WEP_CRYPT==ar->arPairwiseCrypto)) {
                ar6000_install_static_wep_keys(ar);
        }

        if (!ar->arUserBssFilter) {
            if (wmi_bssfilter_cmd(ar->arWmi, ALL_BSS_FILTER, 0) != 0) {
                return -EIO;
            }
        }
#ifdef WAPI_ENABLE
        if (ar->arWapiEnable)  {
            ar->arPairwiseCrypto = WAPI_CRYPT;
            ar->arPairwiseCryptoLen = 0;
            ar->arGroupCrypto = WAPI_CRYPT;
            ar->arGroupCryptoLen = 0;
            ar->arAuthMode = NONE_AUTH;
            ar->arConnectCtrlFlags |= CONNECT_IGNORE_WPAx_GROUP_CIPHER;
        }
#endif
        AR_DEBUG_PRINTF(ATH_DEBUG_WLAN_CONNECT,("Connect called with authmode %d dot11 auth %d"\
                        " PW crypto %d PW crypto Len %d GRP crypto %d"\
                        " GRP crypto Len %d\n",
                        ar->arAuthMode, ar->arDot11AuthMode,
                        ar->arPairwiseCrypto, ar->arPairwiseCryptoLen,
                        ar->arGroupCrypto, ar->arGroupCryptoLen));
        reconnect_flag = 0;
        /* Set the listen interval into 1000TUs or more. This value will be indicated to Ap in the conn.
           later set it back locally at the STA to 100/1000 TUs depending on the power mode */
        if ((ar->arNetworkType == INFRA_NETWORK)) {
            wmi_listeninterval_cmd(ar->arWmi, max(ar->arListenIntervalT, (u16)A_MAX_WOW_LISTEN_INTERVAL), 0);
        }
        status = wmi_connect_cmd(ar->arWmi, ar->arNetworkType,
                                 ar->arDot11AuthMode, ar->arAuthMode,
                                 ar->arPairwiseCrypto, ar->arPairwiseCryptoLen,
                                 ar->arGroupCrypto,ar->arGroupCryptoLen,
                                 ar->arSsidLen, ar->arSsid,
                                 ar->arReqBssid, ar->arChannelHint,
                                 ar->arConnectCtrlFlags);
        if (status) {
            wmi_listeninterval_cmd(ar->arWmi, ar->arListenIntervalT, ar->arListenIntervalB);
            if (!ar->arUserBssFilter) {
                wmi_bssfilter_cmd(ar->arWmi, NONE_BSS_FILTER, 0);
            }
            return status;
        }

        if ((!(ar->arConnectCtrlFlags & CONNECT_DO_WPA_OFFLOAD)) &&
            ((WPA_PSK_AUTH == ar->arAuthMode) || (WPA2_PSK_AUTH == ar->arAuthMode)))
        {
	    mod_timer(&ar->disconnect_timer, jiffies + msecs_to_jiffies(A_DISCONNECT_TIMER_INTERVAL));
        }

        ar->arConnectCtrlFlags &= ~CONNECT_DO_WPA_OFFLOAD;
        
        ar->arConnectPending = true;
        return status;    
    }
    return A_ERROR;
}

int
ar6000_disconnect(struct ar6_softc *ar)
{
    if ((ar->arConnected == true) || (ar->arConnectPending == true)) {
        wmi_disconnect_cmd(ar->arWmi);
        /* 
         * Disconnect cmd is issued, clear connectPending.
         * arConnected will be cleard in disconnect_event notification.
         */
        ar->arConnectPending = false;
    }

    return 0;
}

void ar6000_peer_event(
    void *context,
    u8 eventCode,
    u8 *macAddr)
{
    u8 pos;

    for (pos=0;pos<6;pos++)
        printk("%02x: ",*(macAddr+pos));
    printk("\n");
}

#define AR6003_RESET_CONTROL_ADDRESS 0x00004000
void ar6000_reset_device(struct hif_device *hifDevice,
			 u32 TargetType, bool waitForCompletion,
			 bool coldReset)
{
	int status = 0;
	u32 address;
	u32 data;

	if (TargetType != TARGET_TYPE_AR6003)
		return;

	data = coldReset ? RESET_CONTROL_COLD_RST_MASK :
			   RESET_CONTROL_MBOX_RST_MASK;

	address = AR6003_RESET_CONTROL_ADDRESS;
	status = ar6000_WriteRegDiag(hifDevice, &address, &data);

	if (status)
		AR_DEBUG_PRINTF(ATH_LOG_ERR, ("Failed to reset target \n"));
}

void DebugDumpBytes(u8 *buffer, u16 length, char *pDescription)
{
	char stream[60];
	char byteOffsetStr[10];
	u32 i;
	u16 offset, count, byteOffset;

	A_PRINTF("<---------Dumping %d Bytes : %s ------>\n", length, pDescription);

	count = 0;
	offset = 0;
	byteOffset = 0;
	for(i = 0; i < length; i++) {
		sprintf(stream + offset, "%2.2X ", buffer[i]);
		count ++;
		offset += 3;

		if(count == 16) {
			count = 0;
			offset = 0;
			sprintf(byteOffsetStr,"%4.4X",byteOffset);
			A_PRINTF("[%s]: %s\n", byteOffsetStr, stream);
			memset(stream, 0, 60);
			byteOffset += 16;
		}
	}

	if(offset != 0) {
		sprintf(byteOffsetStr,"%4.4X",byteOffset);
		A_PRINTF("[%s]: %s\n", byteOffsetStr, stream);
	}

	A_PRINTF("<------------------------------------------------->\n");
}
