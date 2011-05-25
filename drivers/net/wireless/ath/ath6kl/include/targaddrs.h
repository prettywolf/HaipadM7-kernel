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

#ifndef TARGADDRS_H
#define TARGADDRS_H

/*
 * xxx_HOST_INTEREST_ADDRESS is the address in Target RAM of the
 * host_interest structure.
 *
 * Host Interest is shared between Host and Target in order to coordinate
 * between the two, and is intended to remain constant (with additions only
 * at the end).
 */
#define AR6003_HOST_INTEREST_ADDRESS    0x00540600

/*
 * These are items that the Host may need to access
 * via BMI or via the Diagnostic Window. The position
 * of items in this structure must remain constant.
 * across firmware revisions!
 *
 * Types for each item must be fixed size across
 * target and host platforms.
 *
 * More items may be added at the end.
 */
struct host_interest {
	/*
	 * Pointer to application-defined area, if any.
	 * Set by Target application during startup.
	 */
	u32 hi_app_host_interest;                      /* 0x00 */

	/* Pointer to register dump area, valid after Target crash. */
	u32 hi_failure_state;                          /* 0x04 */

	/* Pointer to debug logging header */
	u32 hi_dbglog_hdr;                             /* 0x08 */

	u32 hi_unused1;                       /* 0x0c */

	/*
	 * General-purpose flag bits, similar to AR6000_OPTION_* flags.
	 * Can be used by application rather than by OS.
	 */
	u32 hi_option_flag;                            /* 0x10 */

	/*
	 * Boolean that determines whether or not to
	 * display messages on the serial port.
	 */
	u32 hi_serial_enable;                          /* 0x14 */

	/* Start address of DataSet index, if any */
	u32 hi_dset_list_head;                         /* 0x18 */

	/* Override Target application start address */
	u32 hi_app_start;                              /* 0x1c */

	/* Clock and voltage tuning */
	u32 hi_skip_clock_init;                        /* 0x20 */
	u32 hi_core_clock_setting;                     /* 0x24 */
	u32 hi_cpu_clock_setting;                      /* 0x28 */
	u32 hi_system_sleep_setting;                   /* 0x2c */
	u32 hi_xtal_control_setting;                   /* 0x30 */
	u32 hi_pll_ctrl_setting_24ghz;                 /* 0x34 */
	u32 hi_pll_ctrl_setting_5ghz;                  /* 0x38 */
	u32 hi_ref_voltage_trim_setting;               /* 0x3c */
	u32 hi_clock_info;                             /* 0x40 */

	/*
	 * Flash configuration overrides, used only
	 * when firmware is not executing from flash.
	 * (When using flash, modify the global variables
	 * with equivalent names.)
	 */
	u32 hi_bank0_addr_value;                       /* 0x44 */
	u32 hi_bank0_read_value;                       /* 0x48 */
	u32 hi_bank0_write_value;                      /* 0x4c */
	u32 hi_bank0_config_value;                     /* 0x50 */

	/* Pointer to Board Data  */
	u32 hi_board_data;                             /* 0x54 */
	u32 hi_board_data_initialized;                 /* 0x58 */

	u32 hi_dset_RAM_index_table;                   /* 0x5c */

	u32 hi_desired_baud_rate;                      /* 0x60 */
	u32 hi_dbglog_config;                          /* 0x64 */
	u32 hi_end_RAM_reserve_sz;                     /* 0x68 */
	u32 hi_mbox_io_block_sz;                       /* 0x6c */

	u32 hi_num_bpatch_streams;                     /* 0x70 -- unused */
	u32 hi_mbox_isr_yield_limit;                   /* 0x74 */

	u32 hi_refclk_hz;                              /* 0x78 */
	u32 hi_ext_clk_detected;                       /* 0x7c */
	u32 hi_dbg_uart_txpin;                         /* 0x80 */
	u32 hi_dbg_uart_rxpin;                         /* 0x84 */
	u32 hi_hci_uart_baud;                          /* 0x88 */
	u32 hi_hci_uart_pin_assignments;               /* 0x8C */
	/* NOTE: byte [0] = tx pin, [1] = rx pin, [2] = rts pin, [3] = cts pin */
	u32 hi_hci_uart_baud_scale_val;                /* 0x90 */
	u32 hi_hci_uart_baud_step_val;                 /* 0x94 */

	u32 hi_allocram_start;                         /* 0x98 */
	u32 hi_allocram_sz;                            /* 0x9c */
	u32 hi_hci_bridge_flags;                       /* 0xa0 */
	u32 hi_hci_uart_support_pins;                  /* 0xa4 */
	/* NOTE: byte [0] = RESET pin (bit 7 is polarity), bytes[1]..bytes[3] are for future use */
	u32 hi_hci_uart_pwr_mgmt_params;               /* 0xa8 */
	/*
	 * 0xa8   - [1]: 0 = UART FC active low, 1 = UART FC active high
	 *      [31:16]: wakeup timeout in ms
	 */

	/* Pointer to extended board data */
	u32 hi_board_ext_data;                /* 0xac */
	u32 hi_board_ext_data_config;         /* 0xb0 */

	/*
	 * Bit [0]  :   valid
	 * Bit[31:16:   size
	 */
	/*
	 * hi_reset_flag is used to do some stuff when target reset.
	 * such as restore app_start after warm reset or
	 * preserve host Interest area, or preserve ROM data, literals etc.
	 */
	u32 hi_reset_flag;                            /* 0xb4 */
	/* indicate hi_reset_flag is valid */
	u32 hi_reset_flag_valid;                      /* 0xb8 */
	u32 hi_hci_uart_pwr_mgmt_params_ext;           /* 0xbc */
	/*
	 * 0xbc - [31:0]: idle timeout in ms
	 */
	/* ACS flags */
	u32 hi_acs_flags;                              /* 0xc0 */
	u32 hi_console_flags;                          /* 0xc4 */
	u32 hi_nvram_state;                            /* 0xc8 */
	u32 hi_option_flag2;                           /* 0xcc */

	/* If non-zero, override values sent to Host in WMI_READY event. */
	u32 hi_sw_version_override;                    /* 0xd0 */
	u32 hi_abi_version_override;                   /* 0xd4 */

	/*
	 * Percentage of high priority RX traffic to total expected RX traffic -
	 * applicable only to ar6004
	 */
	u32 hi_hp_rx_traffic_ratio;                    /* 0xd8 */

	/* test applications flags */
	u32 hi_test_apps_related    ;                  /* 0xdc */
	/* location of test script */
	u32 hi_ota_testscript;                         /* 0xe0 */
	/* location of CAL data */
	u32 hi_cal_data;                               /* 0xe4 */
	/* Number of packet log buffers */
	u32 hi_pktlog_num_buffers;                     /* 0xe8 */

} __attribute__ ((packed));

#define HI_OPTION_TIMER_WAR		0x00000001
#define HI_OPTION_DISABLE_DBGLOG	0x00000040
#define HI_OPTION_SKIP_REG_SCAN		0x20000000
#define HI_OPTION_INIT_REG_SCAN		0x40000000

#define HI_OPTION_MAC_ADDR_METHOD_SHIFT	3

#define HI_OPTION_FW_MODE_IBSS    0x0
#define HI_OPTION_FW_MODE_BSS_STA 0x1
#define HI_OPTION_FW_MODE_AP      0x2

#define HI_OPTION_NUM_DEV_SHIFT   0x9

#define HI_OPTION_FW_BRIDGE_SHIFT 0x04

/* Fw Mode/SubMode Mask
|------------------------------------------------------------------------------|
|   SUB   |   SUB   |   SUB   |  SUB    |         |         |         |
| MODE[3] | MODE[2] | MODE[1] | MODE[0] | MODE[3] | MODE[2] | MODE[1] | MODE[0|
|   (2)   |   (2)   |   (2)   |   (2)   |   (2)   |   (2)   |   (2)   |   (2)
|------------------------------------------------------------------------------|
*/
#define HI_OPTION_FW_MODE_SHIFT        0xC

/*
 * Intended for use by Host software, this macro returns the Target RAM
 * address of any item in the host_interest structure.
 * Example: target_addr = AR6003_HOST_INTEREST_ITEM_ADDRESS(hi_board_data);
 */
#define AR6003_HOST_INTEREST_ITEM_ADDRESS(item) \
    (u32)((unsigned long)&((((struct host_interest *)(AR6003_HOST_INTEREST_ADDRESS))->item)))

/* Convert a Target virtual address into a Target physical address */
#define AR6003_VTOP(vaddr) ((vaddr) & 0x001fffff)
#define TARG_VTOP(TargetType, vaddr) AR6003_VTOP(vaddr)

#define AR6003_REV2_APP_START_OVERRIDE          0x944C00
#define AR6003_REV2_APP_LOAD_ADDRESS            0x543180
#define AR6003_REV2_BOARD_EXT_DATA_ADDRESS      0x57E500
#define AR6003_REV2_DATASET_PATCH_ADDRESS       0x57e884
#define AR6003_REV2_RAM_RESERVE_SIZE            6912

#define AR6003_REV3_APP_START_OVERRIDE          0x945d00
#define AR6003_REV3_APP_LOAD_ADDRESS            0x545000
#define AR6003_REV3_BOARD_EXT_DATA_ADDRESS      0x542330
#define AR6003_REV3_DATASET_PATCH_ADDRESS       0x57FF74
#define AR6003_REV3_RAM_RESERVE_SIZE            512

#endif /* __TARGADDRS_H__ */
