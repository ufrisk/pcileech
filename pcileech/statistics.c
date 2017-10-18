// statistics.c : implementation of statistics related functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "statistics.h"

VOID _PageStatPrintMemMap(_Inout_ PPAGE_STATISTICS ps)
{
	BOOL fIsLinePrinted = FALSE;
	QWORD i, qwAddrBase, qwAddrEnd;
	if(!ps->i.fIsFirstPrintCompleted) {
		printf(" Memory Map:                                  \n START              END               #PAGES\n");
	}
	if(!ps->i.MemMapIdx && !ps->i.MemMap[0]) {
		printf("                                              \n                                              \n");
		return;
	}
	if(ps->i.MemMapPrintCommitIdx >= PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 4) {
		printf(" Maximum number of memory map entries reached.\n                                              \n");
		return;
	}
	qwAddrBase = ps->i.qwAddrBase + ps->i.MemMapPrintCommitPages * 0x1000;
	for(i = ps->i.MemMapPrintCommitIdx; i < PAGE_STATISTICS_MEM_MAP_MAX_ENTRY; i++) {
		if(!ps->i.MemMap[i] && i == 0) {
			continue;
		}
		if(!ps->i.MemMap[i] || (i == PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 1)) {
			break;
		}
		qwAddrEnd = qwAddrBase + 0x1000 * (QWORD)ps->i.MemMap[i];
		if((i % 2) == 0) {
			fIsLinePrinted = TRUE;
			printf(
				" %016llx - %016llx  %08x\n",
				qwAddrBase,
				qwAddrEnd - 1,
				ps->i.MemMap[i]);
			if(i >= ps->i.MemMapPrintCommitIdx + 2) {
				ps->i.MemMapPrintCommitPages += ps->i.MemMap[ps->i.MemMapPrintCommitIdx++];
				ps->i.MemMapPrintCommitPages += ps->i.MemMap[ps->i.MemMapPrintCommitIdx++];

			}
		}
		qwAddrBase = qwAddrEnd;
	}
	if(!fIsLinePrinted) { // print extra line for formatting reasons.
		printf(" (No memory successfully read yet)            \n");
	}
	printf("                                              \n");
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
	BOOL isMBs = qwSpeed >= 1024;
	if(ps->i.fIsFirstPrintCompleted) {
#ifdef WIN32
		hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
		consoleInfo.dwCursorPosition.Y -= ps->i.fMemMap ? 9 : 7;
		SetConsoleCursorPosition(hConsole, consoleInfo.dwCursorPosition);
#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)
		printf(ps->i.fMemMap ? "\033[9A" : "\033[7A"); // move cursor up 7/9 positions
#endif /* LINUX || ANDROID */
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
			ps->fKMD ? "KMD (kernel module assisted DMA)" : "DMA (hardware only)             ",
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
			ps->fKMD ? "KMD (kernel module assisted DMA)" : "DMA (hardware only)             ",
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

VOID PageStatClose(_Inout_ PPAGE_STATISTICS ps)
{
	BOOL status;
	DWORD dwExitCode;
	ps->i.fUpdate = TRUE;
	ps->i.fThreadExit = TRUE;
	while((status = GetExitCodeThread(ps->i.hThread, &dwExitCode)) && STILL_ACTIVE == dwExitCode) {
		SwitchToThread();
	}
	if(!status) {
		Sleep(200);
	}
}

VOID PageStatInitialize(_Inout_ PPAGE_STATISTICS ps, _In_ QWORD qwAddrBase, _In_ QWORD qwAddrMax, _In_ LPSTR szAction, _In_ BOOL fKMD, _In_ BOOL fMemMap)
{
	memset(ps, 0, sizeof(PAGE_STATISTICS));
	ps->qwAddr = qwAddrBase;
	ps->cPageTotal = (qwAddrMax - qwAddrBase + 1) / 4096;
	ps->szAction = szAction;
	ps->fKMD = fKMD;
	ps->i.fMemMap = fMemMap;
	ps->i.qwAddrBase = qwAddrBase;
	ps->i.qwTickCountStart = GetTickCount64();
	ps->i.hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_PageStatThreadLoop, ps, 0, NULL);
}

VOID PageStatUpdate(_Inout_opt_ PPAGE_STATISTICS ps, _In_ QWORD qwAddr, _In_ QWORD cPageSuccessAdd, _In_ QWORD cPageFailAdd)
{
	if(!ps) { return; }
	ps->qwAddr = qwAddr;
	ps->cPageSuccess += cPageSuccessAdd;
	ps->cPageFail += cPageFailAdd;
	// add to memory map, even == success, odd = fail.
	if(ps->i.MemMapIdx < PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 2) {
		if(cPageSuccessAdd) {
			if(ps->i.MemMapIdx % 2 == 1) {
				ps->i.MemMapIdx++;
			}
			ps->i.MemMap[ps->i.MemMapIdx] += (DWORD)cPageSuccessAdd;
		}
		if(cPageFailAdd) {
			if(ps->i.MemMapIdx % 2 == 0) {
				ps->i.MemMapIdx++;
			}
			ps->i.MemMap[ps->i.MemMapIdx] += (DWORD)cPageFailAdd;
		}
	}
	ps->i.fUpdate = TRUE;
}
