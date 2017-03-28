// statistics.h : definitions of statistics related functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __STATISTICS_H__
#define __STATISTICS_H__
#include "pcileech.h"

#define PAGE_STATISTICS_MEM_MAP_MAX_ENTRY	256

typedef struct tdPageStatistics {
	QWORD qwAddr;
	QWORD cPageTotal;
	QWORD cPageSuccess;
	QWORD cPageFail;
	BOOL fKMD;
	LPSTR szAction;
	struct _InternalUseOnly {
		BOOL fThreadExit;
		BOOL fMemMap;
		HANDLE hThread;
		HANDLE hConsole;
		WORD wConsoleCursorPosition;
		QWORD qwTickCountStart;
		QWORD qwLastUpdateCtrl;
		QWORD qwAddrBase;
		QWORD MemMapIdx;
		DWORD MemMap[PAGE_STATISTICS_MEM_MAP_MAX_ENTRY];
	} i;
} PAGE_STATISTICS, *PPAGE_STATISTICS;

/*
* Initialize the page statistics. This will also start displaying the page statistics
* on the screen asynchronously. PageStatClose must be called to stop this.
* -- ps = ptr to the PAGE_STATISTICS struct to initialize.
* -- qwAddrBase = the base address that the statistics will be based upon.
* -- qwAddrMax = the maximum address.
* -- szAction = the text shown as action.
* -- fKMD = is KMD mode.
* -- fPageMap = display read memory map when PageStatClose is called.
*/
VOID PageStatInitialize(_Inout_ PPAGE_STATISTICS ps, _In_ QWORD qwAddrBase, _In_ QWORD qwAddrMax, _In_ LPSTR szAction, _In_ BOOL fKMD, _In_ BOOL fMemMap);

/*
* Do one last update of the on-screen page statistics, display the read memory map if
* previously set in PageStatInitialize and stop the on-screen updates.
* -- ps = ptr to the PAGE_STATISTICS struct to stop using.
*/
VOID PageStatClose(_Inout_ PPAGE_STATISTICS ps);

/*
* Update the page statistics with the current address and with successfully and failed
* pages. Should not be called before PageStatInitialize and not after PageStatClose.
* This function must be used if the memory map should be shown; otherwise it's possible
* to alter the PPAGE_STATISTICS struct members directly.
* -- ps = pointer to page statistics struct (optional).
* -- qwAddr = new address (after completed operation).
* -- cPageSuccessAdd = number of successfully read pages.
* -- cPageFailAdd = number of pages that failed.
*/
VOID PageStatUpdate(_Inout_opt_ PPAGE_STATISTICS ps, _In_ QWORD qwAddr, _In_ QWORD cPageSuccessAdd, _In_ QWORD cPageFailAdd);

#endif /* __STATISTICS_H__ */
