// device.c : implementation related to hardware devices.
//
// (c) Ulf Frisk, 2016-2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "kmd.h"
#include "statistics.h"
#include "device3380.h"
#include "devicefile.h"
#include "devicefpga.h"
#include "device605_tcp.h"

BOOL DeviceReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
    BOOL result;
    DMA_IO_SCATTER_HEADER pDMAs[0x30], *ppDMAs[0x30];
    DWORD cDMAs, cDMAsSuccess, o;
    // 1: Prefer scatter DMA (if existing)
    if(ctx->cfg->dev.pfnReadScatterDMA) {
        if((cb > ctx->cfg->dev.qwAddrMaxNative) || (cb > 0x24000)) { return FALSE; }
        ZeroMemory(pDMAs, 0x30 * sizeof(DMA_IO_SCATTER_HEADER));
        for(cDMAs = 0, o = 0; o < cb; cDMAs++, o += 0x1000) {
            pDMAs[cDMAs].qwA = qwAddr + o;
            pDMAs[cDMAs].cbMax = min(0x1000, cb - o);
            pDMAs[cDMAs].pb = pb + o;
            ppDMAs[cDMAs] = pDMAs + cDMAs;
        }
        DeviceReadScatterDMA(ctx, ppDMAs, cDMAs, &cDMAsSuccess);
        return (cDMAsSuccess == cDMAs);
    }
    // 2: Standard DMA
    if(!ctx->cfg->dev.pfnReadDMA) { return FALSE; }
    if(flags & PCILEECH_MEM_FLAG_RETRYONFAIL) {
        return DeviceReadDMA(ctx, qwAddr, pb, cb, 0) || DeviceReadDMA(ctx, qwAddr, pb, cb, 0);
    }
    EnterCriticalSection(&ctx->cfg->dev.LockDMA);
    result = ctx->cfg->dev.pfnReadDMA(ctx, qwAddr, pb, cb);
    LeaveCriticalSection(&ctx->cfg->dev.LockDMA);
    return result;
}

BOOL DeviceReadScatterDMA(_Inout_ PPCILEECH_CONTEXT ctx, _Inout_ PPDMA_IO_SCATTER_HEADER ppDMAs, _In_ DWORD cpDMAs, _Out_opt_ PDWORD pcpDMAsRead)
{
    if(!ctx->cfg->dev.pfnReadScatterDMA) { return FALSE; }
    EnterCriticalSection(&ctx->cfg->dev.LockDMA);
    ctx->cfg->dev.pfnReadScatterDMA(ctx, ppDMAs, cpDMAs, pcpDMAsRead);
    LeaveCriticalSection(&ctx->cfg->dev.LockDMA);
    return TRUE;
}

DWORD DeviceReadDMAEx_DoWork_Scatter(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat)
{
    PBYTE pbBuffer;
    PDMA_IO_SCATTER_HEADER pDMAs, *ppDMAs;
    DWORD i, o, cDMAs, cDMAsRead;
    cDMAs = cb >> 12;
    pbBuffer = (PBYTE)LocalAlloc(LMEM_ZEROINIT, cDMAs * (sizeof(PDMA_IO_SCATTER_HEADER) + sizeof(DMA_IO_SCATTER_HEADER)));
    if(!pbBuffer) { return 0; }
    ppDMAs = (PDMA_IO_SCATTER_HEADER*)pbBuffer;
    pDMAs = (PDMA_IO_SCATTER_HEADER)(pbBuffer + cDMAs * sizeof(PDMA_IO_SCATTER_HEADER));
    for(i = 0, o = 0; i < cDMAs; i++, o += 0x1000) {
        ppDMAs[i] = pDMAs + i;
        pDMAs[i].qwA = qwAddr + o;
        pDMAs[i].cbMax = min(0x1000, cb - o);
        pDMAs[i].pb = pb + o;
    }
    DeviceReadScatterDMA(ctx, ppDMAs, cDMAs, &cDMAsRead);
    for(i = 0; i < cDMAs; i++) {
        if(pDMAs[i].cb == 0x1000) {
            PageStatUpdate(pPageStat, pDMAs[i].qwA + 0x1000, 1, 0);
        } else {
            PageStatUpdate(pPageStat, pDMAs[i].qwA + 0x1000, 0, 1);
            ZeroMemory(pDMAs[i].pb, 0x1000);
        }
    }
    LocalFree(pbBuffer);
    return cDMAsRead << 12;
}

#define CHUNK_FAIL_DIVISOR    16
DWORD DeviceReadDMAEx_DoWork(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat, _In_ DWORD cbMaxSizeIo, _In_ QWORD flags)
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
        if(ctx->cfg->dev.fScatterReadSupported) {
            // scatter read, if available
            cbSuccess = DeviceReadDMAEx_DoWork_Scatter(ctx, qwAddr + cbRdOff, pb + cbRdOff, cbRd, pPageStat);
        } else {
            // traditional read
            result = DeviceReadDMA(ctx, qwAddr + cbRdOff, pb + cbRdOff, cbRd, 0);
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
                cbSuccess += DeviceReadDMAEx_DoWork(ctx, qwAddr + cbRdOff, pb + cbRdOff, cbRd, pPageStat, cbRd / CHUNK_FAIL_DIVISOR, flags);
            }
        }
    }
    return cbSuccess;
}

DWORD DeviceReadDMAEx(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat, _In_ QWORD flags)
{
    BYTE pbWorkaround[4096];
    DWORD cbDataRead;
    // read memory (with strange workaround for 1-page reads...)
    if(cb != 0x1000) {
        cbDataRead = DeviceReadDMAEx_DoWork(ctx, qwAddr, pb, cb, pPageStat, (DWORD)ctx->cfg->qwMaxSizeDmaIo, flags);
    } else { 
        // why is this working ??? if not here console is screwed up... (threading issue?)
        cbDataRead = DeviceReadDMAEx_DoWork(ctx, qwAddr, pbWorkaround, 0x1000, pPageStat, (DWORD)ctx->cfg->qwMaxSizeDmaIo, flags);
        memcpy(pb, pbWorkaround, 0x1000);
    }
    return cbDataRead;
}

BOOL DeviceWriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
    PBYTE pbV;
    BOOL result = FALSE;
    if(!ctx->cfg->dev.pfnWriteDMA) { return FALSE; }
    if(flags & PCILEECH_MEM_FLAG_RETRYONFAIL) {
        return DeviceWriteDMA(ctx, qwAddr, pb, cb, 0) || DeviceWriteDMA(ctx, qwAddr, pb, cb, 0);
    }
    EnterCriticalSection(&ctx->cfg->dev.LockDMA);
    result = ctx->cfg->dev.pfnWriteDMA(ctx, qwAddr, pb, cb);
    LeaveCriticalSection(&ctx->cfg->dev.LockDMA);
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

BOOL DeviceProbeDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_ __bcount(cPages) PBYTE pbResultMap)
{
    if(!ctx->cfg->dev.pfnProbeDMA) { return FALSE; }
    EnterCriticalSection(&ctx->cfg->dev.LockDMA);
    ctx->cfg->dev.pfnProbeDMA(ctx, qwAddr, cPages, pbResultMap);
    LeaveCriticalSection(&ctx->cfg->dev.LockDMA);
    return TRUE;
}

BOOL DeviceWriteTlp(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    if(!ctx->cfg->dev.pfnWriteTlp) { return FALSE; }
    EnterCriticalSection(&ctx->cfg->dev.LockDMA);
    result = ctx->cfg->dev.pfnWriteTlp(ctx, pb, cb);
    LeaveCriticalSection(&ctx->cfg->dev.LockDMA);
    return result;
}

BOOL DeviceListenTlp(_Inout_ PPCILEECH_CONTEXT ctx, _In_ DWORD dwTime)
{
    BOOL result;
    if(!ctx->cfg->dev.pfnListenTlp) { return FALSE; }
    LeaveCriticalSection(&ctx->cfg->dev.LockDMA);
    result = ctx->cfg->dev.pfnListenTlp(ctx, dwTime);
    LeaveCriticalSection(&ctx->cfg->dev.LockDMA);
    return result;
}

VOID DeviceClose(_Inout_ PPCILEECH_CONTEXT ctx)
{
    if(ctx->hDevice && ctx->cfg->dev.pfnClose) {
        DeleteCriticalSection(&ctx->cfg->dev.LockDMA);
        ctx->cfg->dev.pfnClose(ctx);
    }
}

BOOL DeviceOpen(_Inout_ PPCILEECH_CONTEXT ctx)
{
    BOOL result = FALSE;
    if(PCILEECH_DEVICE_USB3380 == ctx->cfg->dev.tp || PCILEECH_DEVICE_NA == ctx->cfg->dev.tp) {
        result = Device3380_Open(ctx);
    }
    if(PCILEECH_DEVICE_FPGA == ctx->cfg->dev.tp || PCILEECH_DEVICE_NA == ctx->cfg->dev.tp) {
        result = DeviceFPGA_Open(ctx);
    }
    if(PCILEECH_DEVICE_SP605_TCP == ctx->cfg->dev.tp) {
        result = Device605_TCP_Open(ctx);
    }
    if(PCILEECH_DEVICE_FILE == ctx->cfg->dev.tp) {
        result = DeviceFile_Open(ctx);
    }
    if(result) {
        ctx->cfg->dev.fScatterReadSupported = (ctx->cfg->dev.pfnReadScatterDMA != NULL);
        InitializeCriticalSection(&ctx->cfg->dev.LockDMA);
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
