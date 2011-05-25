/* linux/drivers/media/video/samsung/tv20/s5pv210/hdmi_param.h
 *
 * hdmi parameter header file for Samsung TVOut driver
 *
 * Copyright (c) 2010 Samsung Electronics
 *	         http://www.samsungsemi.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#ifndef _HDMI_HDMI_PARAM_H_
#define _HDMI_HDMI_PARAM_H_

#define PHY_I2C_ADDRESS         0x70
#define PHY_REG_MODE_SET_DONE	0x1F

struct hdmi_v_params {
	u16 h_blank;
	u32 v_blank;
	u32 hvline;
	u32 h_sync_gen;
	u32 v_sync_gen;
	u8  avi_vic;
	u8  avi_vic_16_9;
	u8  interlaced;
	u8  repetition;
	u8  polarity;
	u32 v_blank_f;
	u32 v_sync_gen2;
	u32 v_sync_gen3;
	enum phy_freq pixel_clock;
};

struct _hdmi_tg_param {
	u16 h_fsz;
	u16 hact_st;
	u16 hact_sz;
	u16 v_fsz;
	u16 vsync;
	u16 vsync2;
	u16 vact_st;
	u16 vact_sz;
	u16 field_chg;
	u16 vact_st2;
	u16 vsync_top_hdmi;
	u16 vsync_bot_hdmi;
	u16 field_top_hdmi;
	u16 field_bot_hdmi;
	u8 mhl_hsync_width;
	u8 mhl_vsync_width;
};

static const struct hdmi_v_params video_params[] = {
	{ 0xA0 , 0x16A0D, 0x32020D, 0x11B80E, 0xA00C , 1 , 1 , 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_25_200,},
	{ 0x8A , 0x16A0D, 0x35A20D, 0x11300E, 0x900F , 2 , 3 , 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_27_027,},
	{ 0x172, 0xF2EE , 0x6722EE, 0x2506C , 0x500A , 4 , 4 , 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_74_250,},
	{ 0x118, 0xB232 , 0x898465, 0x20856, 0x2007 , 5 , 5 , 1, 0, 0,
	  0x232A49,	0x234239,	0x4A44A4,	ePHY_FREQ_74_250,},
	{ 0x114, 0xB106 , 0x6B420D, 0x128024, 0x4007 , 6 , 7 , 1, 1, 1,
	  0x10691D,	0x10A10D,	0x380380,	ePHY_FREQ_27_027,},
	{ 0x114, 0xB106 , 0x6B4106, 0x128024, 0x4007 , 8 , 9 , 0, 1, 1,
	  0,		0,		0,		ePHY_FREQ_27_027,},
	{ 0x228, 0xB106 , 0xD6820D, 0x15084A, 0x4007 , 10, 11, 1, 1, 1,
	  0x10691D,	0x10A10D,	0x700700,	ePHY_FREQ_54_054,},
	{ 0x228, 0xB106 , 0x6B4106, 0x15084A, 0x4007 , 12, 13, 0, 1, 1,
	  0,		0,		0,		ePHY_FREQ_54_054,},
	{ 0x114, 0x16A0D, 0x6B420D, 0x12681E, 0x900F , 14, 15, 0, 1, 1,
	  0,		0,		0,		ePHY_FREQ_54_054,},
	{ 0x118, 0x16C65, 0x898465, 0x20856 , 0x4009 , 16, 16, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_148_500},

	{ 0x90 , 0x18A71, 0x360271, 0x11280A, 0x500A , 17, 18, 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_27,    },
	{ 0x2BC, 0xF2EE , 0x7BC2EE, 0x779B6 , 0x500A , 19, 19, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_74_250,},
	{ 0x2D0, 0xB232 , 0xA50465, 0x8EA0E , 0x2007 , 20, 20, 1, 0, 0,
	  0x232A49,	0x234239,	0x738738,	ePHY_FREQ_74_250,},
	{ 0x120, 0xC138 , 0x6C0271, 0x125016, 0x2005 , 21, 22, 1, 1, 1,
	  0x138951,	0x13A13D,	0x378378,	ePHY_FREQ_27,    },
	{ 0x120, 0xC138 , 0x6C0138, 0x125016, 0x3006 , 23, 24, 0, 1, 1,
	  0,		0,		0,		ePHY_FREQ_27,    },
	{ 0x240, 0xC138 , 0xD80271, 0x14A82E, 0x2005 , 25, 26, 1, 1, 1,
	  0x138951,	0x13A13D,	0x6F06F0,	ePHY_FREQ_54,    },
	{ 0x240, 0xC138 , 0xD80138, 0x14A82E, 0x2005 , 27, 28, 0, 1, 1,
	  0,		0,		0,		ePHY_FREQ_54,    },
	{ 0x120, 0x18A71, 0x6C0271, 0x125816, 0x500A , 29, 30, 0, 1, 1,
	  0,		0,		0,		ePHY_FREQ_54,    },
	{ 0x2D0, 0x16C65, 0xA50465, 0x8EA0E , 0x4009 , 31, 31, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_148_500,},
	{ 0x33E, 0x16C65, 0xABE465, 0xAA27C , 0x4009 , 32, 32, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_74_250,},

	{ 0x2D0, 0x16C65, 0xA50465, 0x8EA0E , 0x4009 , 33, 33, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_74_250,  },
	{ 0x118, 0x16C65, 0x898465, 0x20856 , 0x4009 , 34, 34, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_74_250,  },
	{ 0x228, 0x16A0D, 0xD6820D, 0x14D83E, 0x900F , 35, 36, 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_108_108, },
	{ 0x240, 0x18A71, 0xD80271, 0x14B82E, 0x500A , 37, 38, 0, 1, 1,
	  0,		0,		0,		ePHY_FREQ_108,     },
	{ 0x180, 0x2AA71, 0x9004E2, 0x3181E , 0x1701C, 39, 39, 0, 0, 0,
	  0x2712C6,	0x28728F,	0x4a44a4,	ePHY_FREQ_72,      },
	{ 0x2D0, 0xB232 , 0xA50465, 0x8EA0E , 0x2007 , 40, 40, 1, 0, 0,
	  0x232A49,	0x234239,	0x738738,	ePHY_FREQ_148_500, },
	{ 0x2BC, 0xF2EE , 0x7BC2EE, 0x779B6 , 0x500A , 41, 41, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_148_500, },
	{ 0x90 , 0x18A71, 0x360271, 0x11280A, 0x500A , 42, 43, 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_54,      },
	{ 0x120, 0xC138 , 0x6C0271, 0x125016, 0x2005 , 44, 45, 1, 1, 1,
	  0x138951,	 0x13A13D,	0x378378,	ePHY_FREQ_54,      },
	{ 0x118, 0xB232 , 0x898465, 0x20856 , 0x2007 , 46, 46, 1, 0, 0,
	  0x232A49,	0x234239,	0x4A44A4,	ePHY_FREQ_148_500, },

	{ 0x172, 0xF2EE , 0x6722EE, 0x2506C , 0x500A , 47, 47, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_148_500,},
	{ 0x8A , 0x16A0D, 0x35A20D, 0x11300E, 0x900F , 48, 49, 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_54_054, },
	{ 0x114, 0xB106 , 0x6B420D, 0x128024, 0x4007 , 50, 51, 1, 1, 1,
	  0x10691D,	0x10A10D,	0x380380,	ePHY_FREQ_54_054, },
	{ 0x90 , 0x18A71, 0x360271, 0x11280A, 0x500A , 52, 53, 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_108,    },
	{ 0x120, 0xC138 , 0x6C0271, 0x125016, 0x2005 , 54, 55, 1, 1, 1,
	  0x138951,	0x13A13D,	0x378378,	ePHY_FREQ_108,    },
	{ 0x8A , 0x16A0D, 0x35A20D, 0x11300E, 0x900F , 56, 57, 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_108_108,},
	{ 0x114, 0xB106 , 0x6B420D, 0x128024, 0x4007 , 58, 59, 1, 1, 1,
	  0x10691D,	0x10A10D,	0x380380,	ePHY_FREQ_108_108,},

	{ 0x8A , 0x16A0D, 0x35A20D, 0x11300E, 0x900F , 2 , 3 , 0, 0, 1,
	  0,		0,		0,		ePHY_FREQ_27,	},
	{ 0x172, 0xF2EE , 0x6722EE, 0x2506C , 0x500A , 4 , 4 , 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_74_176, },
	{ 0x118, 0xB232 , 0x898465, 0x20856, 0x2007  , 5 , 5 , 1, 0, 0,
	  0x232A49,	0x234239,	0x4A44A4,	ePHY_FREQ_74_176, },
	{ 0x118, 0x16C65, 0x898465, 0x20856 , 0x4009 , 16, 16, 0, 0, 0,
	  0,		0,		0,		ePHY_FREQ_148_352,},
};

static const struct _hdmi_tg_param hdmi_tg_param[] = {
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },

	{0x35a	, 0x8a	, 0x2d0	, 0x20d	, 0x1	, 0x233	, 0x2d	, 0x1e0 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0x672	, 0x172	, 0x500	, 0x2ee	, 0x1	, 0x233	, 0x1e	, 0x2d0 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0x898	, 0x118	, 0x780	, 0x465	, 0x1	, 0x233	, 0x16	, 0x21c ,
	 0x233	, 0x249	, 0x1	, 0x233	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },

	{0x898	, 0x118	, 0x780	, 0x465	, 0x1	, 0x233	, 0x2d	, 0x438 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0x360	, 0x90	, 0x2d0	, 0x271	, 0x1	, 0x233	, 0x31	, 0x240 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0x7bc	, 0x2bc	, 0x500	, 0x2ee	, 0x1	, 0x233	, 0x1e	, 0x2d0 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0xa50	, 0x2d0	, 0x780	, 0x465	, 0x1	, 0x233	, 0x16	, 0x21c ,
	 0x233	, 0x249	, 0x1	, 0x233	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },

	{0xa50	, 0x2d0	, 0x780	, 0x465	, 0x1	, 0x233	, 0x2d	, 0x438 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },

	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },

	{0x898	, 0x118	, 0x780	, 0x465	, 0x1	, 0x233	, 0x2d	, 0x438 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },

	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },
	{0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 },

	{0x35a	, 0x8a	, 0x2d0	, 0x20d	, 0x1	, 0x233	, 0x2d	, 0x1e0 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0x672	, 0x172	, 0x500	, 0x2ee	, 0x1	, 0x233	, 0x1e	, 0x2d0 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0x898	, 0x118	, 0x780	, 0x465	, 0x1	, 0x233	, 0x16	, 0x21c ,
	 0x233	, 0x249	, 0x1	, 0x233	, 0x1	, 0x233	, 0xf	, 0x1 },

	{0x898	, 0x118	, 0x780	, 0x465	, 0x1	, 0x233	, 0x2d	, 0x438 ,
	 0x233	, 0x248	, 0x1	, 0x1	, 0x1	, 0x233	, 0xf	, 0x1 },

};

static const u8 phy_config[][3][32] = {
	{ /* freq = 25.200 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6B, 0x10, 0x02,
	  0x51, 0x5f, 0xF1, 0x54, 0x7e, 0x84, 0x00, 0x10, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xf3, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6B, 0x10, 0x02,
	  0x51, 0x9f, 0xF6, 0x54, 0x9e, 0x84, 0x00, 0x32, 0x38, 0x00, 0xB8,
	  0x10, 0xE0, 0x22, 0x40, 0xc2, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6B, 0x10, 0x02,
	  0x51, 0xFf, 0xF3, 0x54, 0xbd, 0x84, 0x00, 0x30, 0x38, 0x00, 0xA4,
	  0x10, 0xE0, 0x22, 0x40, 0xa2, 0x26, 0x00, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 25.175 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x1e, 0x20, 0x6B, 0x50, 0x10,
	  0x51, 0xf1, 0x31, 0x54, 0xbd, 0x84, 0x00, 0x10, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xf3, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x2b, 0x40, 0x6B, 0x50, 0x10,
	  0x51, 0xF2, 0x32, 0x54, 0xec, 0x84, 0x00, 0x10, 0x38, 0x00, 0xB8,
	  0x10, 0xE0, 0x22, 0x40, 0xc2, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x1e, 0x20, 0x6B, 0x10, 0x02,
	  0x51, 0xf1, 0x31, 0x54, 0xbd, 0x84, 0x00, 0x10, 0x38, 0x00, 0xA4,
	  0x10, 0xE0, 0x22, 0x40, 0xa2, 0x26, 0x00, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 27 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6B, 0x10, 0x02,
	  0x51, 0xDf, 0xF2, 0x54, 0x87, 0x84, 0x00, 0x30, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xe3, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x02, 0x08, 0x6A, 0x10, 0x02,
	  0x51, 0xCf, 0xF1, 0x54, 0xa9, 0x84, 0x00, 0x10, 0x38, 0x00, 0xB8,
	  0x10, 0xE0, 0x22, 0x40, 0xb5, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xfc, 0x08, 0x6B, 0x10, 0x02,
	  0x51, 0x2f, 0xF2, 0x54, 0xcb, 0x84, 0x00, 0x10, 0x38, 0x00, 0xA4,
	  0x10, 0xE0, 0x22, 0x40, 0x97, 0x26, 0x00, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 27.027 MHz */
	{ 0x01, 0x05, 0x00, 0xD4, 0x10, 0x9C, 0x09, 0x64, 0x6B, 0x10, 0x02,
	  0x51, 0xDf, 0xF2, 0x54, 0x87, 0x84, 0x00, 0x30, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xe2, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD4, 0x10, 0x9C, 0x31, 0x50, 0x6B, 0x10, 0x02,
	  0x51, 0x8f, 0xF3, 0x54, 0xa9, 0x84, 0x00, 0x30, 0x38, 0x00, 0xB8,
	  0x10, 0xE0, 0x22, 0x40, 0xb5, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0x10, 0x10, 0x9C, 0x1b, 0x64, 0x6F, 0x10, 0x02,
	  0x51, 0x7f, 0xF8, 0x54, 0xcb, 0x84, 0x00, 0x32, 0x38, 0x00, 0xA4,
	  0x10, 0xE0, 0x22, 0x40, 0x97, 0x26, 0x00, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 54 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6B, 0x10, 0x01,
	  0x51, 0xDf, 0xF2, 0x54, 0x87, 0x84, 0x00, 0x30, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xe3, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x02, 0x08, 0x6A, 0x10, 0x01,
	  0x51, 0xCf, 0xF1, 0x54, 0xa9, 0x84, 0x00, 0x10, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x22, 0x40, 0xb5, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xfc, 0x08, 0x6B, 0x10, 0x01,
	  0x51, 0x2f, 0xF2, 0x54, 0xcb, 0x84, 0x00, 0x10, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x22, 0x40, 0x97, 0x26, 0x01, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 54.054 MHz */
	{ 0x01, 0x05, 0x00, 0xd4, 0x10, 0x9C, 0x09, 0x64, 0x6B, 0x10, 0x01,
	  0x51, 0xDf, 0xF2, 0x54, 0x87, 0x84, 0x00, 0x30, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xe2, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xd4, 0x10, 0x9C, 0x31, 0x50, 0x6B, 0x10, 0x01,
	  0x51, 0x8f, 0xF3, 0x54, 0xa9, 0x84, 0x00, 0x30, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x22, 0x40, 0xb5, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0x10, 0x10, 0x9C, 0x1b, 0x64, 0x6F, 0x10, 0x01,
	  0x51, 0x7f, 0xF8, 0x54, 0xcb, 0x84, 0x00, 0x32, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x22, 0x40, 0x97, 0x26, 0x01, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 74.250 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xf8, 0x40, 0x6A, 0x10, 0x01,
	  0x51, 0xff, 0xF1, 0x54, 0xba, 0x84, 0x00, 0x10, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xa4, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xd6, 0x40, 0x6B, 0x10, 0x01,
	  0x51, 0x7f, 0xF2, 0x54, 0xe8, 0x84, 0x00, 0x10, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x22, 0x40, 0x83, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x34, 0x40, 0x6B, 0x10, 0x01,
	  0x51, 0xef, 0xF2, 0x54, 0x16, 0x85, 0x00, 0x10, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x22, 0x40, 0xdc, 0x26, 0x02, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 74.176 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xef, 0x5B, 0x6D, 0x10, 0x01,
	  0x51, 0xef, 0xF3, 0x54, 0xb9, 0x84, 0x00, 0x30, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xa5, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0x10, 0x10, 0x9C, 0xab, 0x5B, 0x6F, 0x10, 0x01,
	  0x51, 0xbf, 0xF9, 0x54, 0xe8, 0x84, 0x00, 0x32, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x22, 0x40, 0x84, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD4, 0x10, 0x9C, 0xcd, 0x5B, 0x6F, 0x10, 0x01,
	  0x51, 0xdf, 0xF5, 0x54, 0x16, 0x85, 0x00, 0x30, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x22, 0x40, 0xdc, 0x26, 0x02, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 148.500 MHz  - Pre-emph + Higher Tx amp. */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xf8, 0x40, 0x6A, 0x18, 0x00,
	  0x51, 0xff, 0xF1, 0x54, 0xba, 0x84, 0x00, 0x10, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xa4, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xd6, 0x40, 0x6B, 0x18, 0x00,
	  0x51, 0x7f, 0xF2, 0x54, 0xe8, 0x84, 0x00, 0x10, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x23, 0x41, 0x83, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x34, 0x40, 0x6B, 0x18, 0x00,
	  0x51, 0xef, 0xF2, 0x54, 0x16, 0x85, 0x00, 0x10, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x23, 0x41, 0x6d, 0x26, 0x02, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 148.352 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xef, 0x5B, 0x6D, 0x18, 0x00,
	  0x51, 0xef, 0xF3, 0x54, 0xb9, 0x84, 0x00, 0x30, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xa5, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0x10, 0x10, 0x9C, 0xab, 0x5B, 0x6F, 0x18, 0x00,
	  0x51, 0xbf, 0xF9, 0x54, 0xe8, 0x84, 0x00, 0x32, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x23, 0x41, 0x84, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD4, 0x10, 0x9C, 0xcd, 0x5B, 0x6F, 0x18, 0x00,
	  0x51, 0xdf, 0xF5, 0x54, 0x16, 0x85, 0x00, 0x30, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x23, 0x41, 0x6d, 0x26, 0x02, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 108.108 MHz */
	{ 0x01, 0x05, 0x00, 0xD4, 0x10, 0x9C, 0x09, 0x64, 0x6B, 0x18, 0x00,
	  0x51, 0xDf, 0xF2, 0x54, 0x87, 0x84, 0x00, 0x30, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xe2, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD4, 0x10, 0x9C, 0x31, 0x50, 0x6D, 0x18, 0x00,
	  0x51, 0x8f, 0xF3, 0x54, 0xa9, 0x84, 0x00, 0x30, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x22, 0x40, 0xb5, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0x10, 0x10, 0x9C, 0x1b, 0x64, 0x6F, 0x18, 0x00,
	  0x51, 0x7f, 0xF8, 0x54, 0xcb, 0x84, 0x00, 0x32, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x22, 0x40, 0x97, 0x26, 0x02, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 72 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6B, 0x10, 0x01,
	  0x51, 0xEf, 0xF1, 0x54, 0xb4, 0x84, 0x00, 0x10, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xaa, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6F, 0x10, 0x01,
	  0x51, 0xBf, 0xF4, 0x54, 0xe1, 0x84, 0x00, 0x30, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x22, 0x40, 0x88, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6B, 0x18, 0x00,
	  0x51, 0xDf, 0xF2, 0x54, 0x87, 0x84, 0x00, 0x30, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x22, 0x40, 0xe3, 0x26, 0x02, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 25 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x20, 0x40, 0x6B, 0x50, 0x10,
	  0x51, 0xff, 0xF1, 0x54, 0xbc, 0x84, 0x00, 0x10, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xf5, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x08, 0x40, 0x6B, 0x50, 0x10,
	  0x51, 0x7f, 0xF2, 0x54, 0xea, 0x84, 0x00, 0x10, 0x38, 0x00, 0xB8,
	  0x10, 0xE0, 0x22, 0x40, 0xc4, 0x26, 0x00, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x20, 0x40, 0x6B, 0x10, 0x02,
	  0x51, 0xff, 0xF1, 0x54, 0xbc, 0x84, 0x00, 0x10, 0x38, 0x00, 0xA4,
	  0x10, 0xE0, 0x22, 0x40, 0xa3, 0x26, 0x00, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 65 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x02, 0x0c, 0x6B, 0x10, 0x01,
	  0x51, 0xBf, 0xF1, 0x54, 0xa3, 0x84, 0x00, 0x10, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xbc, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xf2, 0x30, 0x6A, 0x10, 0x01,
	  0x51, 0x2f, 0xF2, 0x54, 0xcb, 0x84, 0x00, 0x10, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x22, 0x40, 0x96, 0x26, 0x01, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xd0, 0x40, 0x6B, 0x10, 0x01,
	  0x51, 0x9f, 0xF2, 0x54, 0xf4, 0x84, 0x00, 0x10, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x22, 0x40, 0x7D, 0x26, 0x01, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 108 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6D, 0x18, 0x00,
	  0x51, 0xDf, 0xF2, 0x54, 0x87, 0x84, 0x00, 0x30, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0xe3, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x02, 0x08, 0x6A, 0x18, 0x00,
	  0x51, 0xCf, 0xF1, 0x54, 0xa9, 0x84, 0x00, 0x10, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x22, 0x40, 0xb5, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xfc, 0x08, 0x6B, 0x18, 0x00,
	  0x51, 0x2f, 0xF2, 0x54, 0xcb, 0x84, 0x00, 0x10, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x22, 0x40, 0x97, 0x26, 0x02, 0x00, 0x00, 0x80, },
	},

	{ /* freq = 162 MHz */
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x1C, 0x30, 0x40, 0x6F, 0x18, 0x00,
	  0x51, 0x7f, 0xF8, 0x54, 0xcb, 0x84, 0x00, 0x32, 0x38, 0x00, 0x08,
	  0x10, 0xE0, 0x22, 0x40, 0x97, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0x18, 0x40, 0x6B, 0x18, 0x00,
	  0x51, 0xAf, 0xF2, 0x54, 0xfd, 0x84, 0x00, 0x10, 0x38, 0x00, 0xF8,
	  0x10, 0xE0, 0x23, 0x41, 0x78, 0x26, 0x02, 0x00, 0x00, 0x80, },
	{ 0x01, 0x05, 0x00, 0xD8, 0x10, 0x9C, 0xd0, 0x40, 0x6B, 0x18, 0x00,
	  0x51, 0x3f, 0xF3, 0x54, 0x30, 0x85, 0x00, 0x10, 0x38, 0x00, 0xE4,
	  0x10, 0xE0, 0x23, 0x41, 0x64, 0x26, 0x02, 0x00, 0x00, 0x80, },
	},
};

#endif /* _HDMI_HDMI_PARAM_H_ */
