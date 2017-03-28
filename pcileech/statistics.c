// statistics.c : implementation of statistics related functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "statistics.h"

VOID _PageStatShowUpdate(_Inout_ PPAGE_STATISTICS ps)
{
	QWORD qwPercentTotal = ((ps->cPageSuccess + ps->cPageFail) * 100) / ps->cPageTotal;
	QWORD qwPercentSuccess = (ps->cPageSuccess * 200 + 1) / (ps->cPageTotal * 2);
	QWORD qwPercentFail = (ps->cPageFail * 200 + 1) / (ps->cPageTotal * 2);
	QWORD qwTickCountElapsed = GetTickCount64() - ps->i.qwTickCountStart;
	QWORD qwSpeedMBs = ((ps->cPageSuccess + ps->cPageFail) * 4 / 1024) / (1 + (qwTickCountElapsed / 1000));
	QWORD qwLastUpdateCtrl = ps->qwAddr + ps->cPageSuccess + ps->cPageFail + (QWORD)ps->szAction;
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	if(qwLastUpdateCtrl == ps->i.qwLastUpdateCtrl) {
		return; // only refresh on updates
	}
	ps->i.qwLastUpdateCtrl = qwLastUpdateCtrl;
	if(ps->i.hConsole) {
		GetConsoleScreenBufferInfo(ps->i.hConsole, &consoleInfo);
		consoleInfo.dwCursorPosition.Y = ps->i.wConsoleCursorPosition;
		SetConsoleCursorPosition(ps->i.hConsole, consoleInfo.dwCursorPosition);
	} else {
		ps->i.hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		GetConsoleScreenBufferInfo(ps->i.hConsole, &consoleInfo);
		ps->i.wConsoleCursorPosition = consoleInfo.dwCursorPosition.Y;
	}
	printf(
		" Current Action: %s                             \n" \
		" Access Mode:    %s                             \n" \
		" Progress:       %i / %i (%i%%)                 \n" \
		" Speed:          %i MB/s                        \n" \
		" Address:        0x%016llX                      \n" \
		" Pages read:     %i / %i (%i%%)                 \n" \
		" Pages failed:   %i (%i%%)                      \n",
		ps->szAction,
		ps->fKMD ? "KMD (kernel module assisted DMA)" : "DMA (hardware only)             ",
		(ps->cPageSuccess + ps->cPageFail) / 256,
		ps->cPageTotal / 256,
		qwPercentTotal,
		qwSpeedMBs,
		ps->qwAddr,
		ps->cPageSuccess,
		ps->cPageTotal,
		qwPercentSuccess,
		ps->cPageFail,
		qwPercentFail);
}

VOID _PageStatPrintMemMap(_In_ PPAGE_STATISTICS ps)
{
	QWORD i, qwAddrBase, qwAddrEnd;
	if(!ps->i.MemMap[0] && !ps->i.MemMapIdx) { return; }
	printf(" Memory Map:     (displayed below)\n START              END               #PAGES\n");
	qwAddrBase = ps->i.qwAddrBase;
	for(i = 0; i < PAGE_STATISTICS_MEM_MAP_MAX_ENTRY; i++) {
		if(!ps->i.MemMap[i] && i == 0) {
			continue;
		}
		if(!ps->i.MemMap[i] || (i == PAGE_STATISTICS_MEM_MAP_MAX_ENTRY - 1)) {
			break;
		}
		qwAddrEnd = qwAddrBase + ps->i.MemMap[i] * 0x1000;
		if((i % 2) == 0) {
			printf(
				" %016llx - %016llx  %08x\n",
				qwAddrBase,
				qwAddrEnd - 1,
				ps->i.MemMap[i]);
		}
		qwAddrBase = qwAddrEnd;
	}
}

VOID _PageStatThreadLoop(_In_ PPAGE_STATISTICS ps)
{
	while(!ps->i.fThreadExit) {
		Sleep(100);
		_PageStatShowUpdate(ps);
	}
	ExitThread(0);
}

VOID PageStatClose(_Inout_ PPAGE_STATISTICS ps)
{
	DWORD dwExitCode;
	ps->i.fThreadExit = TRUE;
	while(GetExitCodeThread(ps->i.hThread, &dwExitCode) && STILL_ACTIVE == dwExitCode) {
		SwitchToThread();
	}
	if(ps->i.fMemMap) {
		_PageStatPrintMemMap(ps);
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
}
