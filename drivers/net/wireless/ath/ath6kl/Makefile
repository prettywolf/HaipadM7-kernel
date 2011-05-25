#------------------------------------------------------------------------------
# Copyright (c) 2004-2010 Atheros Communications Inc.
# All rights reserved.
#
# 
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#
#
# Author(s): ="Atheros"
#------------------------------------------------------------------------------

ccflags-y += -I$(obj)/include
ccflags-y += -I$(obj)/include/common
ccflags-y += -I$(obj)/wlan/include
ccflags-y += -I$(obj)/os/linux/include
ccflags-y += -I$(obj)/os
ccflags-y += -I$(obj)/bmi
ccflags-y += -I$(obj)/htc2
ccflags-y += -I$(obj)/include/common/AR6002/hw4.0

ifeq ($(CONFIG_AR600x_DUAL_ANTENNA),y)
ccflags-y += -DAR600x_DUAL_ANTENNA
endif

ifeq ($(CONFIG_AR600x_SINGLE_ANTENNA),y)
ccflags-y += -DAR600x_SINGLE_ANTENNA
endif

ifeq ($(CONFIG_AR600x_BT_QCOM),y)
ccflags-y += -DAR600x_BT_QCOM
endif

ifeq ($(CONFIG_AR600x_BT_CSR),y)
ccflags-y += -DAR600x_BT_CSR
endif

ifeq ($(CONFIG_AR600x_BT_AR3001),y)
ccflags-y += -DAR600x_BT_AR3001
endif

ifeq ($(CONFIG_ATH6KL_CONFIG_GPIO_BT_RESET),y)
ccflags-y += -DATH6KL_CONFIG_GPIO_BT_RESET
endif

ifeq ($(CONFIG_ATH6KL_HTC_RAW_INTERFACE),y)
ccflags-y += -DHTC_RAW_INTERFACE
endif

ifeq ($(CONFIG_ATH6KL_ENABLE_HOST_DEBUG),y)
ccflags-y += -DDEBUG
ccflags-y += -DATH_DEBUG_MODULE
endif

ifeq ($(CONFIG_ATH6KL_ENABLE_TARGET_DEBUG_PRINTS),y)
ccflags-y += -DENABLEUARTPRINT_SET
endif

ifeq ($(CONFIG_ATH6KL_DISABLE_TARGET_DBGLOGS),y)
ccflags-y += -DATH6KL_DISABLE_TARGET_DBGLOGS
endif

ifeq ($(CONFIG_ATH6KL_VIRTUAL_SCATTER_GATHER),y)
ccflags-y += -DATH6KL_CONFIG_HIF_VIRTUAL_SCATTER
endif

ifeq ($(CONFIG_ATH6KL_SKIP_ABI_VERSION_CHECK),y)
ccflags-y += -DATH6KL_SKIP_ABI_VERSION_CHECK
endif

ccflags-y += -DWAPI_ENABLE
ccflags-y += -DCHECKSUM_OFFLOAD

obj-$(CONFIG_ATH6K_LEGACY) := ath6kl.o
ath6kl-y += debug.o
ath6kl-y += htc2/htc_hif.o
ath6kl-y += htc2/htc.o
ath6kl-y += bmi/src/bmi.o
ath6kl-y += os/linux/cfg80211.o
ath6kl-y += os/linux/ar6000_drv.o
ath6kl-y += init.o
ath6kl-y += os/linux/ar6000_raw_if.o
ath6kl-y += os/linux/ar6000_pm.o
ath6kl-y += wmi/wmi.o
ath6kl-y += reorder/rcv_aggr.o
ath6kl-y += wlan/src/wlan_node.o
ath6kl-y += wlan/src/wlan_recv_beacon.o

# ATH_HIF_TYPE := sdio
ccflags-y += -I$(obj)/hif
ccflags-y += -DSDIO
ath6kl-y += hif/hif.o
ath6kl-y += hif/hif_scatter.o
