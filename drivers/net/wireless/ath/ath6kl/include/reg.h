/*
 * Copyright (c) 2004-2010 Atheros Communications Inc.
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

#ifndef REG_H
#define REG_H

#define AR6003_BOARD_DATA_SZ		1024
#define AR6003_BOARD_EXT_DATA_SZ	768

#define RESET_CONTROL_ADDRESS               0x00000000
#define RESET_CONTROL_COLD_RST_MASK         0x00000100
#define RESET_CONTROL_MBOX_RST_MASK         0x00000004

#define CPU_CLOCK_STANDARD_LSB              0
#define CPU_CLOCK_STANDARD_MASK             0x00000003
#define CPU_CLOCK_ADDRESS                   0x00000020
#define CPU_CLOCK_STANDARD_SET(x)           (((x) << CPU_CLOCK_STANDARD_LSB) & \
						  CPU_CLOCK_STANDARD_MASK)

#define CLOCK_CONTROL_ADDRESS               0x00000028
#define CLOCK_CONTROL_LF_CLK32_LSB          2
#define CLOCK_CONTROL_LF_CLK32_MASK         0x00000004
#define CLOCK_CONTROL_LF_CLK32_SET(x)       (((x) << CLOCK_CONTROL_LF_CLK32_LSB) & \
						  CLOCK_CONTROL_LF_CLK32_MASK)

#define SYSTEM_SLEEP_ADDRESS                0x000000c4
#define SYSTEM_SLEEP_DISABLE_LSB            0
#define SYSTEM_SLEEP_DISABLE_MASK           0x00000001
#define SYSTEM_SLEEP_DISABLE_SET(x)         (((x) << SYSTEM_SLEEP_DISABLE_LSB) & \
						  SYSTEM_SLEEP_DISABLE_MASK)

#define LPO_CAL_ADDRESS                     0x000000e0
#define LPO_CAL_ENABLE_LSB                  20
#define LPO_CAL_ENABLE_MASK                 0x00100000
#define LPO_CAL_ENABLE_SET(x)               (((x) << LPO_CAL_ENABLE_LSB) & \
						  LPO_CAL_ENABLE_MASK)

#define GPIO_PIN10_ADDRESS              0x00000050
#define GPIO_PIN11_ADDRESS              0x00000054
#define GPIO_PIN12_ADDRESS              0x00000058
#define GPIO_PIN13_ADDRESS              0x0000005c

#define HOST_INT_STATUS_ADDRESS                  0x00000400
#define HOST_INT_STATUS_ERROR_LSB                7
#define HOST_INT_STATUS_ERROR_MASK               0x00000080
#define HOST_INT_STATUS_ERROR_GET(x)             (((x) & HOST_INT_STATUS_ERROR_MASK) >> \
						  HOST_INT_STATUS_ERROR_LSB)
#define HOST_INT_STATUS_CPU_LSB                  6
#define HOST_INT_STATUS_CPU_MASK                 0x00000040
#define HOST_INT_STATUS_CPU_GET(x)               (((x) & HOST_INT_STATUS_CPU_MASK) >> \
						  HOST_INT_STATUS_CPU_LSB)
#define HOST_INT_STATUS_COUNTER_LSB              4
#define HOST_INT_STATUS_COUNTER_MASK             0x00000010
#define HOST_INT_STATUS_COUNTER_GET(x)           (((x) & HOST_INT_STATUS_COUNTER_MASK) >> \
						  HOST_INT_STATUS_COUNTER_LSB)

#define CPU_INT_STATUS_ADDRESS                   0x00000401

#define ERROR_INT_STATUS_ADDRESS                 0x00000402
#define ERROR_INT_STATUS_WAKEUP_LSB              2
#define ERROR_INT_STATUS_WAKEUP_MASK             0x00000004
#define ERROR_INT_STATUS_WAKEUP_GET(x)           (((x) & ERROR_INT_STATUS_WAKEUP_MASK) >> \
						  ERROR_INT_STATUS_WAKEUP_LSB)
#define ERROR_INT_STATUS_RX_UNDERFLOW_LSB        1
#define ERROR_INT_STATUS_RX_UNDERFLOW_MASK       0x00000002
#define ERROR_INT_STATUS_RX_UNDERFLOW_GET(x)     (((x) & ERROR_INT_STATUS_RX_UNDERFLOW_MASK) >> \
						  ERROR_INT_STATUS_RX_UNDERFLOW_LSB)
#define ERROR_INT_STATUS_TX_OVERFLOW_LSB         0
#define ERROR_INT_STATUS_TX_OVERFLOW_MASK        0x00000001
#define ERROR_INT_STATUS_TX_OVERFLOW_GET(x)      (((x) & ERROR_INT_STATUS_TX_OVERFLOW_MASK) >> \
						  ERROR_INT_STATUS_TX_OVERFLOW_LSB)

#define COUNTER_INT_STATUS_ADDRESS               0x00000403
#define COUNTER_INT_STATUS_COUNTER_LSB           0
#define COUNTER_INT_STATUS_COUNTER_MASK          0x000000ff
#define COUNTER_INT_STATUS_COUNTER_SET(x)        (((x) << COUNTER_INT_STATUS_COUNTER_LSB) & \
						  COUNTER_INT_STATUS_COUNTER_MASK)

#define RX_LOOKAHEAD_VALID_ADDRESS               0x00000405

#define INT_STATUS_ENABLE_ADDRESS                0x00000418
#define INT_STATUS_ENABLE_ERROR_LSB              7
#define INT_STATUS_ENABLE_ERROR_MASK             0x00000080
#define INT_STATUS_ENABLE_ERROR_SET(x)           (((x) << INT_STATUS_ENABLE_ERROR_LSB) & \
						  INT_STATUS_ENABLE_ERROR_MASK)
#define INT_STATUS_ENABLE_CPU_LSB                6
#define INT_STATUS_ENABLE_CPU_MASK               0x00000040
#define INT_STATUS_ENABLE_CPU_SET(x)             (((x) << INT_STATUS_ENABLE_CPU_LSB) & \
						  INT_STATUS_ENABLE_CPU_MASK)
#define INT_STATUS_ENABLE_INT_LSB                5
#define INT_STATUS_ENABLE_INT_MASK               0x00000020
#define INT_STATUS_ENABLE_INT_SET(x)             (((x) << INT_STATUS_ENABLE_INT_LSB) & \
						  INT_STATUS_ENABLE_INT_MASK)
#define INT_STATUS_ENABLE_COUNTER_LSB            4
#define INT_STATUS_ENABLE_COUNTER_MASK           0x00000010
#define INT_STATUS_ENABLE_COUNTER_SET(x)         (((x) << INT_STATUS_ENABLE_COUNTER_LSB) & \
						  INT_STATUS_ENABLE_COUNTER_MASK)
#define INT_STATUS_ENABLE_MBOX_DATA_LSB          0
#define INT_STATUS_ENABLE_MBOX_DATA_MASK         0x0000000f
#define INT_STATUS_ENABLE_MBOX_DATA_SET(x)       (((x) << INT_STATUS_ENABLE_MBOX_DATA_LSB) & \
						  INT_STATUS_ENABLE_MBOX_DATA_MASK)

#define CPU_INT_STATUS_ENABLE_ADDRESS            0x00000419
#define CPU_INT_STATUS_ENABLE_BIT_LSB            0
#define CPU_INT_STATUS_ENABLE_BIT_MASK           0x000000ff
#define CPU_INT_STATUS_ENABLE_BIT_SET(x)         (((x) << CPU_INT_STATUS_ENABLE_BIT_LSB) & \
						  CPU_INT_STATUS_ENABLE_BIT_MASK)

#define ERROR_STATUS_ENABLE_ADDRESS              0x0000041a
#define ERROR_STATUS_ENABLE_RX_UNDERFLOW_LSB     1
#define ERROR_STATUS_ENABLE_RX_UNDERFLOW_MASK    0x00000002
#define ERROR_STATUS_ENABLE_RX_UNDERFLOW_SET(x)  (((x) << ERROR_STATUS_ENABLE_RX_UNDERFLOW_LSB) & \
						  ERROR_STATUS_ENABLE_RX_UNDERFLOW_MASK)
#define ERROR_STATUS_ENABLE_TX_OVERFLOW_LSB      0
#define ERROR_STATUS_ENABLE_TX_OVERFLOW_MASK     0x00000001
#define ERROR_STATUS_ENABLE_TX_OVERFLOW_SET(x)   (((x) << ERROR_STATUS_ENABLE_TX_OVERFLOW_LSB) & \
						  ERROR_STATUS_ENABLE_TX_OVERFLOW_MASK)

#define COUNTER_INT_STATUS_ENABLE_ADDRESS        0x0000041b
#define COUNTER_INT_STATUS_ENABLE_BIT_LSB        0
#define COUNTER_INT_STATUS_ENABLE_BIT_MASK       0x000000ff
#define COUNTER_INT_STATUS_ENABLE_BIT_SET(x)     (((x) << COUNTER_INT_STATUS_ENABLE_BIT_LSB) & \
						  COUNTER_INT_STATUS_ENABLE_BIT_MASK)

#define COUNT_ADDRESS			0x00000420

#define COUNT_DEC_ADDRESS		0x00000440

#define WINDOW_DATA_ADDRESS		0x00000474
#define WINDOW_WRITE_ADDR_ADDRESS	0x00000478
#define WINDOW_READ_ADDR_ADDRESS	0x0000047c
#define CPU_DBG_SEL_ADDRESS		0x00000483
#define CPU_DBG_ADDRESS			0x00000484

#define LOCAL_SCRATCH_ADDRESS		0x000000c0
#define AR6K_OPTION_SLEEP_DISABLE	0x08

#define RTC_BASE_ADDRESS		0x00004000
#define GPIO_BASE_ADDRESS		0x00014000
#define MBOX_BASE_ADDRESS		0x00018000
#define ANALOG_INTF_BASE_ADDRESS 	0x0001c000

#endif