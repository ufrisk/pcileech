// device.c : implementation related to hardware devices.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <leechcore.h>
#include "device.h"
#include "kmd.h"
#include "statistics.h"
#include "vmmx.h"

_Success_(return)
BOOL DeviceReadDMA_Retry(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb)
{
    return LcRead(hLC, pa, cb, pb) || LcRead(hLC, pa, cb, pb);
}

_Success_(return)
BOOL DeviceWriteDMA_Retry(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _In_reads_(cb) PBYTE pb)
{
    return LcWrite(hLC, pa, cb, pb) || LcWrite(hLC, pa, cb, pb);
}

_Success_(return)
BOOL DeviceWriteDMA_Verify(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _In_reads_(cb) PBYTE pb)
{
    PBYTE pbBuffer = NULL;
    BOOL fResult =
        DeviceWriteDMA_Retry(hLC, pa, cb, pb) &&
        (pbBuffer = LocalAlloc(0, cb)) &&
        DeviceReadDMA_Retry(hLC, pa, cb, pbBuffer) &&
        (0 == memcmp(pb, pbBuffer, cb));
    LocalFree(pbBuffer);
    return fResult;
}

DWORD DeviceReadDMA(_In_ QWORD pa, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb, _Inout_opt_ PPAGE_STATISTICS pPageStat)
{
    PMEM_SCATTER pMEM, *ppMEMs = NULL;
    DWORD i, cMEMs, cbRead = 0;
    cMEMs = cb >> 12;
    if((pa & 0xfff) || !cb || (cb & 0xfff)) { return 0; }
    if(!LcAllocScatter2(cb, pb, cMEMs, &ppMEMs)) { return 0; }
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i]->qwA = pa + ((QWORD)i << 12);
    }
    LcReadScatter(ctxMain->hLC, cMEMs, ppMEMs);
    for(i = 0; i < cMEMs; i++) {
        pMEM = ppMEMs[i];
        if(pMEM->f) {
            cbRead += pMEM->cb;
        } else {
            ZeroMemory(pMEM->pb, pMEM->cb);
        }
        if(pPageStat) {
            PageStatUpdate(pPageStat, ppMEMs[i]->qwA + 0x1000, pMEM->f ? 1 : 0, pMEM->f ? 0 : 1);
        }
    }
    LcMemFree(ppMEMs);
    return cbRead;
}

/*
* Set a custom user-defined or auto-generated memory map either from:
* - command line argument
* - file: a user defined memory map text file.
* - auto: auto generated memory map retrieved using MemProcFS when target OS
*         is Windows and when PCILeech is running on Windows OS.
* -- return
*/
_Success_(return)
BOOL DeviceOpen2_SetCustomMemMap()
{
    BOOL fResult = FALSE;
    FILE *hFile = NULL;
    DWORD cb;
    PBYTE pb = NULL, pbResult = NULL;
    if(!(pb = LocalAlloc(LMEM_ZEROINIT, 0x01000000))) { goto fail; }
    if(0 == _stricmp("auto", ctxMain->cfg.szMemMap)) {
        if(!Vmmx_Initialize(FALSE, TRUE)) { goto fail; }
    } else {
        if(fopen_s(&hFile, ctxMain->cfg.szMemMap, "rb") || !hFile) { goto fail; }
        cb = (DWORD)fread(pb, 1, 0x01000000, hFile);
        if((cb == 0) || (cb > 0x01000000)) { goto fail; }
        if(!LcCommand(ctxMain->hLC, LC_CMD_MEMMAP_SET, cb, pb, NULL, NULL)) { goto fail; }
    }
    fResult =
        LcCommand(ctxMain->hLC, LC_CMD_MEMMAP_GET, 0, NULL, &pbResult, NULL) &&
        LcGetOption(ctxMain->hLC, LC_OPT_CORE_ADDR_MAX, &ctxMain->dev.paMax);
    if(fResult && ctxMain->cfg.fVerbose) {
        printf("TARGET SYSTEM MEMORY MAP:\n");
        printf("   #       RANGE_BASE          RANGE_TOP         RANGE_REMAP\n");
        printf("============================================================\n");
        printf("%s\n", (LPSTR)pbResult);
    }
fail:
    LocalFree(pb);
    LcMemFree(pbResult);
    Vmmx_Close();
    if(hFile) { fclose(hFile); }
    return fResult;
}

#ifdef _WIN32
_Success_(return)
BOOL DeviceOpen2_RequestUserInput()
{
    BOOL fResult;
    LPSTR szProto;
    DWORD i, cbRead = 0;
    CHAR szInput[33] = { 0 };
    CHAR szDevice[MAX_PATH] = { 0 };
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);     // must not be closed.
    // 1: read input
    printf("\n?> ");
    fResult = ReadConsoleA(hStdIn, szInput, 32, &cbRead, NULL);
    for(i = 0; i < _countof(szInput); i++) {
        if((szInput[i] == '\r') || (szInput[i] == '\n')) { szInput[i] = 0; }
    }
    cbRead = (DWORD)strlen(szInput);
    if(!cbRead) { return FALSE; }
    // 2: clear "userinput" option and update "device" option
    ctxMain->cfg.fUserInteract = FALSE;
    szProto = strstr(ctxMain->cfg.szDevice, "://");
    snprintf(
        szDevice,
        MAX_PATH - 1,
        "%s%s%sid=%s",
        ctxMain->cfg.szDevice,
        szProto ? "" : "://",
        szProto && szProto[3] ? "," : "",
        szInput);
    memcpy(ctxMain->cfg.szDevice, szDevice, MAX_PATH);
    // 3: try re-initialize with new user input
    return DeviceOpen();
}
#else /* _WIN32 */
_Success_(return)
BOOL DeviceOpen2_RequestUserInput()
{
    return FALSE;
}
#endif /* _WIN32 */

_Success_(return)
BOOL DeviceOpen2(_In_ LPSTR szDevice, _In_ BOOL fFailSilent)
{
    BOOL f;
    PLC_CONFIG_ERRORINFO pLcErrorInfo = NULL;
    ZeroMemory(&ctxMain->dev, sizeof(ctxMain->dev));
    ctxMain->dev.dwVersion = LC_CONFIG_VERSION;
    if(!fFailSilent) {
        // do not initially enable leechcore error messages / printouts if set to fail silent
        ctxMain->dev.dwPrintfVerbosity =
            LC_CONFIG_PRINTF_ENABLED |
            (ctxMain->cfg.fVerbose ? LC_CONFIG_PRINTF_V : 0) |
            (ctxMain->cfg.fVerboseExtra ? LC_CONFIG_PRINTF_VV : 0);
    }
    strcpy_s(ctxMain->dev.szDevice, MAX_PATH, szDevice);
    strcpy_s(ctxMain->dev.szRemote, MAX_PATH, ctxMain->cfg.szRemote);
    ctxMain->dev.paMax = ctxMain->cfg.qwAddrMax;
    ctxMain->hLC = LcCreateEx(&ctxMain->dev, &pLcErrorInfo);
    if(!ctxMain->hLC) {
        if(pLcErrorInfo && (pLcErrorInfo->dwVersion == LC_CONFIG_ERRORINFO_VERSION)) {
            if(pLcErrorInfo->cwszUserText) {
                wprintf(L"MESSAGE FROM MEMORY ACQUISITION DEVICE:\n=======================================\n%s\n", pLcErrorInfo->wszUserText);
            }
            if(ctxMain->cfg.fUserInteract && pLcErrorInfo->fUserInputRequest) {
                LcMemFree(pLcErrorInfo);
                return DeviceOpen2_RequestUserInput();
            }
        }
        ZeroMemory(&ctxMain->dev, sizeof(ctxMain->dev));
        LcMemFree(pLcErrorInfo);
        return FALSE;
    }
    // enable standard verbosity levels upon success (if not already set)
    if(fFailSilent) {
        LcSetOption(ctxMain->hLC, LC_OPT_CORE_PRINTF_ENABLE, 1);
        LcSetOption(ctxMain->hLC, LC_OPT_CORE_VERBOSE, (ctxMain->cfg.fVerbose ? 1 : 0));
        LcSetOption(ctxMain->hLC, LC_OPT_CORE_VERBOSE_EXTRA, (ctxMain->cfg.fVerboseExtra ? 1 : 0));
    }
    if(ctxMain->cfg.fVerboseExtraTlp) {
        LcSetOption(ctxMain->hLC, LC_OPT_CORE_VERBOSE_EXTRA_TLP, 1);
    }
    // enable custom memory map (if option is set)
    if(ctxMain->cfg.szMemMap[0]) {
        if(!DeviceOpen2_SetCustomMemMap()) {
            printf("PCILEECH: Invalid memory map: '%s'.\n", ctxMain->cfg.szMemMap);
            return FALSE;
        }
    }
    if(ctxMain->cfg.szMemMapStr[0]) {
        f = LcCommand(ctxMain->hLC, LC_CMD_MEMMAP_SET, (DWORD)strlen(ctxMain->cfg.szMemMapStr), ctxMain->cfg.szMemMapStr, NULL, NULL) &&
            LcGetOption(ctxMain->hLC, LC_OPT_CORE_ADDR_MAX, &ctxMain->dev.paMax);
        if(!f) {
            printf("PCILEECH: Invalid memory map given on command line option.\n");
            return FALSE;
        }
    }
    return TRUE;
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
BOOL DeviceWriteMEM(_In_ QWORD qwAddr, _In_ DWORD cb, _In_reads_(cb) PBYTE pb, _In_ BOOL fRetryOnFail)
{
    if(ctxMain->phKMD) {
        return KMDWriteMemory(qwAddr, pb, cb);
    }
    return LcWrite(ctxMain->hLC, qwAddr, cb, pb) || (fRetryOnFail && LcWrite(ctxMain->hLC, qwAddr, cb, pb));
}

_Success_(return)
BOOL DeviceReadMEM(_In_ QWORD qwAddr, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb, _In_ BOOL fRetryOnFail)
{
    if(ctxMain->phKMD) {
        return KMDReadMemory(qwAddr, pb, cb);
    }
    return LcRead(ctxMain->hLC, qwAddr, cb, pb) || (fRetryOnFail && LcRead(ctxMain->hLC, qwAddr, cb, pb));
}
