// wx64_pagesignature.c : kernel code to create a page signature from system module / driver.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_pagesignature.c
// ml64.exe wx64_common_a.asm /Fewx64_pagesignature.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_pagesignature.obj wx64_common.obj
// shellcode64.exe -o wx64_pagesignature.exe "MODULE SIGNATURE INFORMATION\n===========================================================\nSyntax: pcileech.exe -s <modulename.sys>\nGENERAL INFORMATION BELOW:\n  MODULE    : %s \n  BASE PHYS : %016llX\n  BASE VIRT : %016llX\n  SIZE      : %016llX\n  #CUNKS    : %i\n  MJ_CREATE : %016llX\nPAGING INFORMATION BELOW:\n  CR3       : %016llX\n  PML4E     : %016llX\n  PDPTE     : %016llX\n  PDE       : %016llX\n  PTE       : %016llX\nSIGNATURE IS SHOWN BELOW:\n"
//
#include "wx64_common.h"

typedef struct tdSignaturePTE {
	WORD cPages;
	WORD wSignature;
} SIGNATUREPTE, *PSIGNATUREPTE;

#define IRP_MJ_CREATE							0x00
#define IRP_MJ_MAXIMUM_FUNCTION					0x1b

typedef struct _DRIVER_EXTENSION {
	struct _DRIVER_OBJECT *DriverObject;
	PVOID AddDevice;
	ULONG Count;
	UNICODE_STRING ServiceKeyName;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

typedef struct _DRIVER_OBJECT {
	SHORT Type;
	SHORT Size;
	PVOID DeviceObject;
	ULONG Flags;
	PVOID DriverStart;
	ULONG DriverSize;
	PVOID DriverSection;
	PDRIVER_EXTENSION DriverExtension;
	UNICODE_STRING DriverName;
	PUNICODE_STRING HardwareDatabase;
	PVOID FastIoDispatch;
	PVOID DriverInit;
	PVOID DriverStartIo;
	PVOID DriverUnload;
	PVOID MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

//----------------------------------------------------------------------------------------------------------

#define OBJ_CASE_INSENSITIVE					0x00000040
#define H_ObReferenceObjectByName				0x92869205
#define H_IoDriverObjectType					0xc4d8b5e4

typedef struct tdKERNEL_FUNCTIONS2 {
	NTSTATUS(*ObReferenceObjectByName)(
		_In_ PUNICODE_STRING ObjectPath,
		_In_ ULONG Attributes,
		_In_ PVOID PassedAccessState,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ PVOID ObjectType,
		_In_ MODE AccessMode,
		_Inout_ PVOID ParseContext,
		_Out_ PVOID *ObjectPtr
		);
} KERNEL_FUNCTIONS2, *PKERNEL_FUNCTIONS2;

VOID InitializeKernelFunctions2(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS2 fnk2)
{
	QWORD FUNC2[][2] = {
		{ &fnk2->ObReferenceObjectByName,			H_ObReferenceObjectByName }
	};
	for(QWORD j = 0; j < (sizeof(FUNC2) / sizeof(QWORD[2])); j++) {
		*(PQWORD)FUNC2[j][0] = PEGetProcAddressH(qwNtosBase, (DWORD)FUNC2[j][1]);
	}
}

QWORD GetPTE(_In_ PKERNEL_FUNCTIONS fnk, _In_ QWORD qwVA, _Out_opt_ QWORD qwaPageInfo[5])
{
	//QWORD buf, paPML4, paPDPT, paPD, paPT, qwPTE;
	QWORD buf, qwCR3, qwPML4E, qwPDPTE, qwPDE, qwPTE;
	// pml4 -> pdpt
	qwCR3 = GetCR3();
	buf = (QWORD)fnk->MmMapIoSpace(qwCR3 & ~0xfff, 4096, 0);
	if(!buf) { return 0; }
	qwPML4E = *(PQWORD)(buf + (((qwVA >> 39) & 0x1FF) << 3));
	fnk->MmUnmapIoSpace((PVOID)buf, 4096);
	if(!(qwPML4E & ~0xFFF)) { return 0; }
	// pdpt -> pd
	buf = (QWORD)fnk->MmMapIoSpace(qwPML4E & ~0xFFF, 4096, 0);
	if(!buf) { return 0; }
	qwPDPTE = *(PQWORD)(buf + (((qwVA >> 30) & 0x1FF) << 3));
	fnk->MmUnmapIoSpace((PVOID)buf, 4096);
	if(!(qwPDPTE & ~0xFFF)) { return 0; }
	// pd -> pt
	buf = (QWORD)fnk->MmMapIoSpace(qwPDPTE & ~0xFFF, 4096, 0);
	if(!buf) { return 0; }
	qwPDE = *(PQWORD)(buf + (((qwVA >> 21) & 0x1FF) << 3));
	fnk->MmUnmapIoSpace((PVOID)buf, 4096);
	if(!(qwPDE & ~0xFFF)) { return 0; }
	// pt -> pte
	buf = (QWORD)fnk->MmMapIoSpace(qwPDE & ~0xFFF, 4096, 0);
	if(!buf) { return 0; }
	qwPTE = *(PQWORD)(buf + (((qwVA >> 12) & 0x1FF) << 3));
	fnk->MmUnmapIoSpace((PVOID)buf, 4096);
	if(qwaPageInfo) {
		qwaPageInfo[0] = qwCR3;
		qwaPageInfo[1] = qwPML4E;
		qwaPageInfo[2] = qwPDPTE;
		qwaPageInfo[3] = qwPDE;
		qwaPageInfo[4] = qwPTE;
	}
	return qwPTE;
}

//----------------------------------------------------------------------------------------------------------

VOID PageTable_CreateSignature(_In_ PKERNEL_FUNCTIONS fnk, _In_ QWORD qwAddressMin, _In_ QWORD qwAddressMax, _Out_ PSIGNATUREPTE pPTEs, _Inout_ PQWORD pcPTEs)
{
	PSIGNATUREPTE pPTE = pPTEs;
	QWORD cPTE = 0, qwAddress = 0, qwPTE = 0;
	WORD wSignature;
	qwAddressMin &= 0x0fffffffffffff000;
	qwAddressMax &= 0x0fffffffffffff000;
	for(qwAddress = qwAddressMin; qwAddress <= qwAddressMax; qwAddress += 0x1000) {
		qwPTE = GetPTE(fnk, qwAddress, NULL);
		wSignature = (qwPTE & 0x07) | ((qwPTE >> 48 ) & 0x8000);
		if(wSignature == pPTE->wSignature) { // same as previous
			pPTE->cPages++;
			continue;
		}
		if(pPTE->cPages) {
			cPTE++;
			if(cPTE >= *pcPTEs) {
				break;
			}
			pPTE = pPTEs + cPTE;
		}
		pPTE->cPages++;
		pPTE->wSignature = wSignature;
	}
	*pcPTEs = cPTE;
}

PVOID PageTable_GetAddrMajorFunction(_Inout_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, _In_ LPWSTR wszDriver)
{
	NTSTATUS nt;
	PDRIVER_OBJECT pDriver = NULL;
	PVOID* ppvIoDriverObjectType;
	UNICODE_STRING usDriver;
	UNREFERENCED_PARAMETER(pk);
	ppvIoDriverObjectType = PEGetProcAddressH(pk->AddrKernelBase, H_IoDriverObjectType);
	fnk->RtlInitUnicodeString(&usDriver, wszDriver);
	nt = fnk2->ObReferenceObjectByName(&usDriver, OBJ_CASE_INSENSITIVE, NULL, 0, *ppvIoDriverObjectType, KernelMode, NULL, &pDriver);
	if(NT_ERROR(nt)) { return nt; }
	return pDriver->MajorFunction[IRP_MJ_CREATE];
}

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	CHAR szDriverNtfs[] = { 'n', 't', 'f', 's', '.', 's', 'y', 's', 0 };
	CHAR szDriverFastFAT[] = { 'f', 'a', 's', 't', 'f', 'a', 't', '.', 's', 'y', 's', 0 };
	WCHAR wszDriverNtfs[] = { '\\', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e', 'm', '\\', 'N', 't', 'f', 's', 0 };
	WCHAR wszDriverFastFAT[] = { '\\', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e', 'm', '\\', 'F', 'a', 's', 't', 'F', 'A', 'T', 0 };
	KERNEL_FUNCTIONS fnk;
	KERNEL_FUNCTIONS2 fnk2;
	QWORD i, cSigPTEs = 32, qwModuleBase;
	PSIGNATUREPTE pSigPTEs = (PSIGNATUREPTE)(pk->DMAAddrVirtual + pk->dataOutExtraOffset);
	InitializeKernelFunctions(pk->AddrKernelBase, &fnk);
	InitializeKernelFunctions2(pk->AddrKernelBase, &fnk2);
	qwModuleBase = KernelGetModuleBase(&fnk, pk->dataInStr);
	if(qwModuleBase) {
		pk->dataOut[0] = fnk.MmGetPhysicalAddress((PVOID)qwModuleBase);
		pk->dataOut[1] = qwModuleBase;
		pk->dataOut[2] = PEGetImageSize(qwModuleBase);
		for(i = 0; i < cSigPTEs; i++) {
			pSigPTEs[i].cPages = 0;
			pSigPTEs[i].wSignature = 0;
		}
		PageTable_CreateSignature(
			&fnk,
			qwModuleBase,
			qwModuleBase + PEGetImageSize(qwModuleBase),
			pSigPTEs,
			&cSigPTEs);
		pk->dataOut[3] = cSigPTEs;
		if(0 == fnk._stricmp(szDriverNtfs, pk->dataInStr)) {
			pk->dataOut[4] = PageTable_GetAddrMajorFunction(pk, &fnk, &fnk2, wszDriverNtfs);
		} else if(0 == fnk._stricmp(szDriverFastFAT, pk->dataInStr)) {
			pk->dataOut[4] = PageTable_GetAddrMajorFunction(pk, &fnk, &fnk2, wszDriverFastFAT);
		}
		pk->dataOutExtraLength = cSigPTEs * sizeof(SIGNATUREPTE);
		fnk.RtlCopyMemory(pk->dataOutStr, pk->dataInStr, MAX_PATH);
		GetPTE(&fnk, qwModuleBase, &pk->dataOut[5]);
	}
}
