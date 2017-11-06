// device.c : implementation related to hardware devices.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "kmd.h"
#include "statistics.h"
#include "device3380.h"
#include "device605_601.h"
#include "device605_tcp.h"

typedef struct tdREAD_DMA_EX_MEMORY_MAP {
	BOOL fProbeExecuted;
	QWORD qwAddrBase;
	DWORD cPages;
	PBYTE pb;
} READ_DMA_EX_MEMORY_MAP, *PREAD_DMA_EX_MEMORY_MAP;

BOOL DeviceReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	if(flags & PCILEECH_MEM_FLAG_RETRYONFAIL) {
		return DeviceReadDMA(ctx, qwAddr, pb, cb, 0) || DeviceReadDMA(ctx, qwAddr, pb, cb, 0);
	}
	return ctx->cfg->dev.pfnReadDMA ? ctx->cfg->dev.pfnReadDMA(ctx, qwAddr, pb, cb) : FALSE;
}

BOOL DeviceReadDMAEx_IsMemoryMapOK(_In_ PREAD_DMA_EX_MEMORY_MAP pMemoryMap, _In_ QWORD qwAddr, _In_ DWORD dwSize)
{
	DWORD i;
	DWORD cPages = (dwSize + 0xfff) / 0x1000;
	DWORD cPageStart = (DWORD)(((qwAddr + 0xfff) - pMemoryMap->qwAddrBase) / 0x1000);
	for(i = cPageStart; i < cPageStart + cPages; i++) {
		if(0 == pMemoryMap->pb[i]) { 
			return FALSE; 
		}
	}
	return TRUE;
}

#define CHUNK_FAIL_DIVISOR	16
DWORD DeviceReadDMAEx_DoWork(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat, _In_ DWORD cbMaxSizeIo, _Inout_ PREAD_DMA_EX_MEMORY_MAP pMemoryMap, _In_ QWORD flags)
{
	DWORD cbRd, cbRdOff;
	DWORD cbChunk, cChunkTotal, cChunkSuccess = 0;
	DWORD i, cbSuccess = 0;
	BOOL result;
	// calculate current chunk sizes
	cbChunk = ~0xfff & min(cb, cbMaxSizeIo);
	cbChunk = (cbChunk > 0x3000) ? cbChunk : 0x1000;
	cChunkTotal = (cb / cbChunk) + ((cb % cbChunk) ? 1 : 0);
	// try read memory
	memset(pb, 0, cb);
	for(i = 0; i < cChunkTotal; i++) {
		cbRdOff = i * cbChunk;
		cbRd = ((i == cChunkTotal - 1) && (cb % cbChunk)) ? (cb % cbChunk) : cbChunk; // (last chunk may be smaller)
		result =
			DeviceReadDMAEx_IsMemoryMapOK(pMemoryMap, qwAddr + cbRdOff, cbRd) &&
			DeviceReadDMA(ctx, qwAddr + cbRdOff, pb + cbRdOff, cbRd, 0);
		if(!result && !pMemoryMap->fProbeExecuted && ctx->cfg->dev.pfnProbeDMA) { // probe memory on 1st fail (if supported)
			DeviceProbeDMA(ctx, pMemoryMap->qwAddrBase, pMemoryMap->cPages, pMemoryMap->pb);
			pMemoryMap->fProbeExecuted = TRUE;
		}
		if(result) {
			cbSuccess += cbRd;
			PageStatUpdate(pPageStat, qwAddr + cbRdOff + cbRd, cbRd / 0x1000, 0);
		} else if(flags & PCILEECH_FLAG_MEM_EX_FASTFAIL) {
			PageStatUpdate(pPageStat, qwAddr + cb, 0, (cb - cbRdOff) / 0x1000);
			return cbSuccess;
		} else if(cbRd == 0x1000) {
			ZeroMemory(pb + cbRdOff, cbRd);
			PageStatUpdate(pPageStat, qwAddr + cbRdOff + cbRd, 0, 1);
		} else {
			cbSuccess += DeviceReadDMAEx_DoWork(ctx, qwAddr + cbRdOff, pb + cbRdOff, cbRd, pPageStat, cbRd / CHUNK_FAIL_DIVISOR, pMemoryMap, flags);
		}
	}
	return cbSuccess;
}

DWORD DeviceReadDMAEx(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat, _In_ QWORD flags)
{
	READ_DMA_EX_MEMORY_MAP oMemoryMap;
	BYTE pbWorkaround[4096];
	DWORD cbDataRead;
	// set probe memory map to all mem readable
	oMemoryMap.fProbeExecuted = FALSE;
	oMemoryMap.qwAddrBase = qwAddr & ~0xfff;
	oMemoryMap.cPages = (cb + 0xfff) / 0x1000;
	oMemoryMap.pb = LocalAlloc(0, oMemoryMap.cPages);
	if(!oMemoryMap.pb) { return 0; }
	memset(oMemoryMap.pb, 0x01, oMemoryMap.cPages);
	// read memory (with strange workaround for 1-page reads...)
	if(cb != 0x1000) {
		cbDataRead = DeviceReadDMAEx_DoWork(ctx, qwAddr, pb, cb, pPageStat, (DWORD)ctx->cfg->qwMaxSizeDmaIo, &oMemoryMap, flags);
	} else { 
		// why is this working ??? if not here console is screwed up... (threading issue?)
		cbDataRead = DeviceReadDMAEx_DoWork(ctx, qwAddr, pbWorkaround, 0x1000, pPageStat, (DWORD)ctx->cfg->qwMaxSizeDmaIo, &oMemoryMap, flags);
		memcpy(pb, pbWorkaround, 0x1000);
	}
	LocalFree(oMemoryMap.pb);
	return cbDataRead;
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
	if(PCILEECH_DEVICE_SP605_TCP == ctx->cfg->dev.tp) {
		result = Device605_TCP_Open(ctx);
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
		return cb == DeviceReadDMAEx(ctx, qwAddr, pb, cb, NULL, 0);
	}
}
