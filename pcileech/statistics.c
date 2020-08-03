// statistics.c : implementation of statistics related functionality.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "statistics.h"
#include "oscompatibility.h"

VOID _PageStatPrintMemMap(_Inout_ PPAGE_STATISTICS ps)
{
    QWORD i, qwAddrEnd;
    if(!ps->i.fIsFirstPrintCompleted) {
        printf(" Memory Map:                                     \n START              END               #PAGES   \n");
    }
    if(!ps->i.MemMapIdx) {
        printf("                                                 \n                                                 \n");
        return;
    }
    if(ps->i.MemMapIdx >= PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 2) {
        printf(" Maximum number of memory map entries reached.   \n                                                 \n");
        return;
    }
    for(i = max(1, ps->i.MemMapPrintIdx); i <= ps->i.MemMapIdx; i++) {
        if(!ps->i.MemMap[i].cPages) {
            break;
        }
        qwAddrEnd = ps->i.MemMap[i].qwAddrBase + ((QWORD)ps->i.MemMap[i].cPages << 12);
        printf(
            " %016llx - %016llx  %08x   \n",
            ps->i.MemMap[i].qwAddrBase,
            qwAddrEnd - 1,
            ps->i.MemMap[i].cPages);
    }
    ps->i.MemMapPrintIdx = ps->i.MemMapIdx;
    if(!ps->i.MemMap[1].cPages) { // print extra line for formatting reasons.
        printf(" (No memory successfully read yet)               \n");
    }
    printf("                                                 \n");
}

VOID _PageStatShowUpdate(_Inout_ PPAGE_STATISTICS ps)
{
    if(0 == ps->cPageTotal) { return; }
    QWORD qwPercentTotal = ((ps->cPageSuccess + ps->cPageFail) * 100) / ps->cPageTotal;
    QWORD qwPercentSuccess = (ps->cPageSuccess * 200 + 1) / (ps->cPageTotal * 2);
    QWORD qwPercentFail = (ps->cPageFail * 200 + 1) / (ps->cPageTotal * 2);
    QWORD qwTickCountElapsed = GetTickCount64() - ps->i.qwTickCountStart;
    QWORD qwSpeed = ((ps->cPageSuccess + ps->cPageFail) * 4) / (1 + (qwTickCountElapsed / 1000));
    HANDLE hConsole;
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    BOOL isMBs = qwSpeed >= 2048;
    if(ps->i.fIsFirstPrintCompleted) {
#ifdef WIN32
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
        consoleInfo.dwCursorPosition.Y -= ps->i.fMemMap ? 9 : 7;
        SetConsoleCursorPosition(hConsole, consoleInfo.dwCursorPosition);
#endif /* WIN32 */
#ifdef LINUX
        printf(ps->i.fMemMap ? "\033[9A" : "\033[7A"); // move cursor up 7/9 positions
#endif /* LINUX */
    }
    if(ps->i.fMemMap) {
        _PageStatPrintMemMap(ps);
    }
    if(ps->cPageTotal < 0x0000000fffffffff) {
        printf(
            " Current Action: %s                             \n" \
            " Access Mode:    %s                             \n" \
            " Progress:       %llu / %llu (%llu%%)           \n" \
            " Speed:          %llu %s                        \n" \
            " Address:        0x%016llX                      \n" \
            " Pages read:     %llu / %llu (%llu%%)           \n" \
            " Pages failed:   %llu (%llu%%)                  \n",
            ps->szAction,
            ps->fKMD ? "KMD (kernel module assisted DMA)" : "Normal                          ",
            (ps->cPageSuccess + ps->cPageFail) / 256,
            ps->cPageTotal / 256,
            qwPercentTotal,
            (isMBs ? qwSpeed >> 10 : qwSpeed),
            (isMBs ? "MB/s" : "kB/s"),
            ps->qwAddr,
            ps->cPageSuccess,
            ps->cPageTotal,
            qwPercentSuccess,
            ps->cPageFail,
            qwPercentFail);
    } else {
        printf(
            " Current Action: %s                             \n" \
            " Access Mode:    %s                             \n" \
            " Progress:       %llu / (unknown)               \n" \
            " Speed:          %llu %s                        \n" \
            " Address:        0x%016llX                      \n" \
            " Pages read:     %llu                           \n" \
            " Pages failed:   %llu                           \n",
            ps->szAction,
            ps->fKMD ? "KMD (kernel module assisted DMA)" : "Normal                          ",
            (ps->cPageSuccess + ps->cPageFail) / 256,
            (isMBs ? qwSpeed >> 10 : qwSpeed),
            (isMBs ? "MB/s" : "kB/s"),
            ps->qwAddr,
            ps->cPageSuccess,
            ps->cPageFail);
    }
    ps->i.fIsFirstPrintCompleted = TRUE;
}

VOID _PageStatThreadLoop(_In_ PPAGE_STATISTICS ps)
{
    while(!ps->i.fThreadExit) {
        Sleep(100);
        if(ps->i.fUpdate) {
            ps->i.fUpdate = FALSE;
            _PageStatShowUpdate(ps);
        }
    }
    ExitThread(0);
}

VOID PageStatClose(_In_opt_ PPAGE_STATISTICS *ppPageStat)
{
    BOOL status;
    DWORD dwExitCode;
    if(!ppPageStat || !*ppPageStat) { return; }
    (*ppPageStat)->i.fUpdate = TRUE;
    (*ppPageStat)->i.fThreadExit = TRUE;
    while((status = GetExitCodeThread((*ppPageStat)->i.hThread, &dwExitCode)) && STILL_ACTIVE == dwExitCode) {
        SwitchToThread();
    }
    if(!status) {
        Sleep(200);
    }
    CloseHandle((*ppPageStat)->i.hThread);
    LocalFree(*ppPageStat);
    *ppPageStat = NULL;
}

_Success_(return)
BOOL PageStatInitialize(_Out_ PPAGE_STATISTICS *ppPageStat, _In_ QWORD qwAddrBase, _In_ QWORD qwAddrMax, _In_ LPSTR szAction, _In_ BOOL fKMD, _In_ BOOL fMemMap)
{
    PPAGE_STATISTICS ps;
    ps = *ppPageStat = LocalAlloc(LMEM_ZEROINIT, sizeof(PAGE_STATISTICS));
    if(!ps) { return FALSE; }
    ps->qwAddr = qwAddrBase;
    ps->cPageTotal = (qwAddrMax - qwAddrBase + 1) / 4096;
    ps->szAction = szAction;
    ps->fKMD = fKMD;
    ps->i.fMemMap = fMemMap;
    ps->i.qwTickCountStart = GetTickCount64();
    ps->i.hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_PageStatThreadLoop, ps, 0, NULL);
    return TRUE;
}

VOID PageStatUpdate(_In_opt_ PPAGE_STATISTICS pPageStat, _In_ QWORD qwAddr, _In_ QWORD cPageSuccessAdd, _In_ QWORD cPageFailAdd)
{
    if(!pPageStat) { return; }
    pPageStat->qwAddr = qwAddr;
    pPageStat->cPageSuccess += cPageSuccessAdd;
    pPageStat->cPageFail += cPageFailAdd;
    // add to memory map
    if(cPageSuccessAdd && (pPageStat->i.MemMapIdx < PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 1)) {
        if(!pPageStat->i.MemMapIdx || (qwAddr - (cPageSuccessAdd << 12)) != (pPageStat->i.MemMap[pPageStat->i.MemMapIdx].qwAddrBase + ((QWORD)pPageStat->i.MemMap[pPageStat->i.MemMapIdx].cPages << 12))) {
            pPageStat->i.MemMapIdx++;
            pPageStat->i.MemMap[pPageStat->i.MemMapIdx].qwAddrBase = qwAddr - (cPageSuccessAdd << 12);
        }
        pPageStat->i.MemMap[pPageStat->i.MemMapIdx].cPages += (DWORD)cPageSuccessAdd;
    }
    pPageStat->i.fUpdate = TRUE;
}
