/**********************************************************************
 *
 * Copyright(c) 2008 Imagination Technologies Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful but, except
 * as otherwise stated in writing, without any warranty; without even the
 * implied warranty of merchantability or fitness for a particular purpose.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Imagination Technologies Ltd. <gpl-support@imgtec.com>
 * Home Park Estate, Kings Langley, Herts, WD4 8LZ, UK
 *
 ******************************************************************************/

#if !defined (__PDUMPDEFS_H__)
#define __PDUMPDEFS_H__

typedef enum _PDUMP_PIXEL_FORMAT_
{
	PVRSRV_PDUMP_PIXEL_FORMAT_UNSUPPORTED = 0,
	PVRSRV_PDUMP_PIXEL_FORMAT_RGB8 = 1,
	PVRSRV_PDUMP_PIXEL_FORMAT_RGB332 = 2,
	PVRSRV_PDUMP_PIXEL_FORMAT_KRGB555 = 3,
	PVRSRV_PDUMP_PIXEL_FORMAT_RGB565 = 4,
	PVRSRV_PDUMP_PIXEL_FORMAT_ARGB4444 = 5,
	PVRSRV_PDUMP_PIXEL_FORMAT_ARGB1555 = 6,
	PVRSRV_PDUMP_PIXEL_FORMAT_RGB888 = 7,
	PVRSRV_PDUMP_PIXEL_FORMAT_ARGB8888 = 8,
	PVRSRV_PDUMP_PIXEL_FORMAT_YUV8 = 9,
	PVRSRV_PDUMP_PIXEL_FORMAT_AYUV4444 = 10,
	PVRSRV_PDUMP_PIXEL_FORMAT_VY0UY1_8888 = 11,
	PVRSRV_PDUMP_PIXEL_FORMAT_UY0VY1_8888 = 12,
	PVRSRV_PDUMP_PIXEL_FORMAT_Y0UY1V_8888 = 13,
	PVRSRV_PDUMP_PIXEL_FORMAT_Y0VY1U_8888 = 14,
	PVRSRV_PDUMP_PIXEL_FORMAT_YUV888 = 15,
	PVRSRV_PDUMP_PIXEL_FORMAT_UYVY10101010 = 16,
	PVRSRV_PDUMP_PIXEL_FORMAT_VYAUYA8888 = 17,
	PVRSRV_PDUMP_PIXEL_FORMAT_AYUV8888 = 18,
	PVRSRV_PDUMP_PIXEL_FORMAT_AYUV2101010 = 19,
	PVRSRV_PDUMP_PIXEL_FORMAT_YUV101010 = 20,
	PVRSRV_PDUMP_PIXEL_FORMAT_PL12Y8 = 21,
	PVRSRV_PDUMP_PIXEL_FORMAT_YUV_IMC2 = 22,
	PVRSRV_PDUMP_PIXEL_FORMAT_YUV_YV12 = 23,
	PVRSRV_PDUMP_PIXEL_FORMAT_YUV_PL8 = 24,
	PVRSRV_PDUMP_PIXEL_FORMAT_YUV_PL12 = 25,
	PVRSRV_PDUMP_PIXEL_FORMAT_422PL12YUV8 = 26,
	PVRSRV_PDUMP_PIXEL_FORMAT_420PL12YUV8 = 27,
	PVRSRV_PDUMP_PIXEL_FORMAT_PL12Y10 = 28,
	PVRSRV_PDUMP_PIXEL_FORMAT_422PL12YUV10 = 29,
	PVRSRV_PDUMP_PIXEL_FORMAT_420PL12YUV10 = 30,
	PVRSRV_PDUMP_PIXEL_FORMAT_ABGR8888 = 31,
	PVRSRV_PDUMP_PIXEL_FORMAT_BGRA8888 = 32,
	PVRSRV_PDUMP_PIXEL_FORMAT_ARGB8332 = 33,
	PVRSRV_PDUMP_PIXEL_FORMAT_RGB555 = 34,
	PVRSRV_PDUMP_PIXEL_FORMAT_F16 = 35,
	PVRSRV_PDUMP_PIXEL_FORMAT_F32 = 36,
	PVRSRV_PDUMP_PIXEL_FORMAT_L16 = 37,
	PVRSRV_PDUMP_PIXEL_FORMAT_L32 = 38,

	PVRSRV_PDUMP_PIXEL_FORMAT_FORCE_I32 = 0x7fffffff

} PDUMP_PIXEL_FORMAT;

typedef enum _PDUMP_MEM_FORMAT_
{
	PVRSRV_PDUMP_MEM_FORMAT_STRIDE = 0,
	PVRSRV_PDUMP_MEM_FORMAT_RESERVED = 1,
	PVRSRV_PDUMP_MEM_FORMAT_TILED = 8,
	PVRSRV_PDUMP_MEM_FORMAT_TWIDDLED = 9,
	PVRSRV_PDUMP_MEM_FORMAT_HYBRID = 10,

	PVRSRV_PDUMP_MEM_FORMAT_FORCE_I32 = 0x7fffffff
} PDUMP_MEM_FORMAT;

typedef enum _PDUMP_POLL_OPERATOR
{
	PDUMP_POLL_OPERATOR_EQUAL = 0,
	PDUMP_POLL_OPERATOR_LESS = 1,
	PDUMP_POLL_OPERATOR_LESSEQUAL = 2,
	PDUMP_POLL_OPERATOR_GREATER = 3,
	PDUMP_POLL_OPERATOR_GREATEREQUAL = 4,
	PDUMP_POLL_OPERATOR_NOTEQUAL = 5,
} PDUMP_POLL_OPERATOR;


#endif
