// device.c : implementation related to hardware devices.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "kmd.h"
#include "statistics.h"
#include "device3380.h"
#include "device605_uart.h"
#include "device605_601.h"

BOOL DeviceReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	if(flags & PCILEECH_MEM_FLAG_RETRYONFAIL) {
		return DeviceReadDMA(ctx, qwAddr, pb, cb, 0) || DeviceReadDMA(ctx, qwAddr, pb, cb, 0);
	}
	return ctx->cfg->dev.pfnReadDMA ? ctx->cfg->dev.pfnReadDMA(ctx, qwAddr, pb, cb) : FALSE;
}

#define CHUNK_FAIL_DIVISOR	16
DWORD DeviceReadDMAEx_DoWork(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat, _In_ DWORD cbMaxSizeIo)
{
	DWORD cbRd, cbRdOff;
	DWORD cbChunk, cChunkTotal, cChunkSuccess = 0;
	DWORD i, cbSuccess = 0;
	// calculate current chunk sizes
	cbChunk = ~0xfff & min(cb, cbMaxSizeIo);
	cbChunk = (cbChunk > 0x3000) ? cbChunk : 0x1000;
	cChunkTotal = (cb / cbChunk) + ((cb % cbChunk) ? 1 : 0);
	// try read memory
	memset(pb, 0, cb);
	for(i = 0; i < cChunkTotal; i++) {
		cbRdOff = i * cbChunk;
		cbRd = ((i == cChunkTotal - 1) && (cb % cbChunk)) ? (cb % cbChunk) : cbChunk; // (last chunk may be smaller)
		if(DeviceReadDMA(ctx, qwAddr + cbRdOff, pb + cbRdOff, cbRd, 0)) {
			cbSuccess += cbRd;
			PageStatUpdate(pPageStat, qwAddr + cbRdOff + cbRd, cbRd / 0x1000, 0);
		} else if(cbRd == 0x1000) {
			PageStatUpdate(pPageStat, qwAddr + cbRdOff + cbRd, 0, 1);
		} else {
			cbSuccess += DeviceReadDMAEx_DoWork(ctx, qwAddr + cbRdOff, pb + cbRdOff, cbRd, pPageStat, cbRd / CHUNK_FAIL_DIVISOR);
		}
	}
	return cbSuccess;
}

DWORD DeviceReadDMAEx(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat)
{
	BYTE pbWorkaround[4096];
	DWORD cbWorkaround;
	if(cb != 0x1000) {
		return DeviceReadDMAEx_DoWork(ctx, qwAddr, pb, cb, pPageStat, (DWORD)ctx->cfg->qwMaxSizeDmaIo);
	}
	// why is this working ??? if not here console is screwed up... (threading issue?)
	cbWorkaround = DeviceReadDMAEx_DoWork(ctx, qwAddr, pbWorkaround, 0x1000, pPageStat, (DWORD)ctx->cfg->qwMaxSizeDmaIo);
	memcpy(pb, pbWorkaround, 0x1000);
	return cbWorkaround;
}

BOOL DeviceWriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	PBYTE pbV;
	BOOL result = FALSE;
	if(flags & PCILEECH_MEM_FLAG_RETRYONFAIL) {
		return DeviceWriteDMA(ctx, qwAddr, pb, cb, 0) || DeviceWriteDMA(ctx, qwAddr, pb, cb, 0);
	}
	result = ctx->cfg->dev.pfnWriteDMA ? ctx->cfg->dev.pfnWriteDMA(ctx, qwAddr, pb, cb) : FALSE;
	if(!result) { return FALSE; }
	if(flags & PCILEECH_MEM_FLAG_VERIFYWRITE) {
		pbV = LocalAlloc(0, cb + 0x2000);
		if(!pbV) { return FALSE; }
		result =
			DeviceReadDMA(ctx, qwAddr & ~0xfff, pbV, (cb + 0xfff + (qwAddr & 0xfff)) & ~0xfff, flags) &&
			(0 == memcmp(pb, pbV + (qwAddr & 0xfff), cb));
		LocalFree(pbV);
	}
	return result;
}

BOOL DeviceProbeDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ DWORD cPages, _Out_ __bcount(cPages) PBYTE pbResultMap)
{
	if(!ctx->cfg->dev.pfnProbeDMA) { return FALSE; }
	ctx->cfg->dev.pfnProbeDMA(ctx, qwAddr, cPages, pbResultMap);
	return TRUE;
}

BOOL DeviceWriteTlp(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb)
{
	if(!ctx->cfg->dev.pfnWriteTlp) { return FALSE; }
	return ctx->cfg->dev.pfnWriteTlp(ctx, pb, cb);
}

BOOL DeviceListenTlp(_Inout_ PPCILEECH_CONTEXT ctx, _In_ DWORD dwTime)
{
	if(!ctx->cfg->dev.pfnListenTlp) { return FALSE; }
	return ctx->cfg->dev.pfnListenTlp(ctx, dwTime);
}

VOID DeviceClose(_Inout_ PPCILEECH_CONTEXT ctx)
{
	if(ctx->hDevice && ctx->cfg->dev.pfnClose) {
		ctx->cfg->dev.pfnClose(ctx);
	}
}

BOOL DeviceOpen(_Inout_ PPCILEECH_CONTEXT ctx)
{
	BOOL result = FALSE;
	if(PCILEECH_DEVICE_USB3380 == ctx->cfg->dev.tp || PCILEECH_DEVICE_NA == ctx->cfg->dev.tp) {
		result = Device3380_Open(ctx);
	}
	if(PCILEECH_DEVICE_SP605_FT601 == ctx->cfg->dev.tp || PCILEECH_DEVICE_NA == ctx->cfg->dev.tp) {
		result = Device605_601_Open(ctx);
	}
	if(PCILEECH_DEVICE_SP605_UART == ctx->cfg->dev.tp) {
		result = Device605_UART_Open(ctx);
	}
	return result;
}

BOOL DeviceWriteMEM(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	if(ctx->phKMD) {
		return KMDWriteMemory(ctx, qwAddr, pb, cb);
	} else {
		return DeviceWriteDMA(ctx, qwAddr, pb, cb, flags);
	}
}

BOOL DeviceReadMEM(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	if(ctx->phKMD) {
		return KMDReadMemory(ctx, qwAddr, pb, cb);
	} else if(flags || cb == 0x1000) {
		return DeviceReadDMA(ctx, qwAddr, pb, cb, flags);
	} else {
		return cb == DeviceReadDMAEx(ctx, qwAddr, pb, cb, NULL);
	}
}
