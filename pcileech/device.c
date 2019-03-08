// device.c : implementation related to hardware devices.
//
// (c) Ulf Frisk, 2016-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "kmd.h"
#include "statistics.h"
#include "leechcore.h"

DWORD DeviceReadDMAEx(_In_ QWORD qwAddr, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat, _In_ QWORD flags)
{
    LEECHCORE_PAGESTAT_MINIMAL StatMin;
    StatMin.h = (HANDLE)pPageStat;
    StatMin.pfnPageStatUpdate = (VOID(*)(HANDLE, ULONG64, ULONG64, ULONG64))PageStatUpdate;
    return LeechCore_ReadEx(qwAddr, pb, cb, 0, &StatMin);
}

_Success_(return)
BOOL DeviceOpen2(_In_ LPSTR szDevice, _In_ BOOL fFailSilent)
{
    BOOL result;
    ZeroMemory(&ctxMain->dev, sizeof(ctxMain->dev));
    ctxMain->dev.magic = LEECHCORE_CONFIG_MAGIC;
    ctxMain->dev.version = LEECHCORE_CONFIG_VERSION;
    if(!fFailSilent) {
        // do not initially enable leechcore error messages / printouts if set to fail silent
        ctxMain->dev.flags =
            LEECHCORE_CONFIG_FLAG_PRINTF |
            (ctxMain->cfg.fVerbose ? LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_1 : 0) |
            (ctxMain->cfg.fVerboseExtra ? LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_2 : 0) |
            (ctxMain->cfg.fVerboseExtraTlp ? LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_3 : 0);
    }
    strcpy_s(ctxMain->dev.szDevice, MAX_PATH, szDevice);
    strcpy_s(ctxMain->dev.szRemote, MAX_PATH, ctxMain->cfg.szRemote);
    ctxMain->dev.paMax = ctxMain->cfg.qwAddrMax;
    result = LeechCore_Open(&ctxMain->dev);
    if(result) {
        if(fFailSilent) {
            // enable standard verbosity levels upon success
            LeechCore_SetOption(LEECHCORE_OPT_CORE_PRINTF_ENABLE, 1);
            LeechCore_SetOption(LEECHCORE_OPT_CORE_VERBOSE, (ctxMain->cfg.fVerbose ? 1 : 0));
            LeechCore_SetOption(LEECHCORE_OPT_CORE_VERBOSE_EXTRA, (ctxMain->cfg.fVerboseExtra ? 1 : 0));
            LeechCore_SetOption(LEECHCORE_OPT_CORE_VERBOSE_EXTRA_TLP, (ctxMain->cfg.fVerboseExtraTlp ? 1 : 0));
        }
    } else {
        ZeroMemory(&ctxMain->dev, sizeof(ctxMain->dev));
    }
    return result;
}

_Success_(return)
BOOL DeviceOpen()
{
    if(0 == ctxMain->cfg.szDevice[0]) {
        if(DeviceOpen2("FPGA", TRUE) || DeviceOpen2("USB3380", TRUE)) {
            strcpy_s(ctxMain->cfg.szDevice, MAX_PATH, ctxMain->dev.szDevice);
            return TRUE;
        }
        return FALSE;
    }
    return DeviceOpen2(ctxMain->cfg.szDevice, FALSE);
}

_Success_(return)
BOOL DeviceWriteMEM(_In_ QWORD qwAddr, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
    if(ctxMain->phKMD) {
        return KMDWriteMemory(qwAddr, pb, cb);
    } else {
        return LeechCore_Write(qwAddr, pb, cb);
    }
}

_Success_(return)
BOOL DeviceReadMEM(_In_ QWORD qwAddr, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
    DWORD fLeechCore;
    if(ctxMain->phKMD) {
        return KMDReadMemory(qwAddr, pb, cb);
    } else if(flags || cb == 0x1000) {
        fLeechCore = (flags & PCILEECH_MEM_FLAG_RETRYONFAIL) ? LEECHCORE_FLAG_READ_RETRY : 0;
        return cb == LeechCore_ReadEx(qwAddr, pb, cb, fLeechCore, NULL);
    } else {
        return cb == DeviceReadDMAEx(qwAddr, pb, cb, NULL, 0);
    }
}
