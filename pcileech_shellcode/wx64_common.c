// wx64_common.c : support functions used by Windows x64 KMDs started by stage3 EXEC.
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "wx64_common.h"

DWORD HashROR13A(_In_ LPCSTR sz)
{
	DWORD dwVal, dwHash = 0;
	while(*sz) {
		dwVal = (DWORD)*sz++;
		dwHash = (dwHash >> 13) | (dwHash << 19);
		dwHash += dwVal;
	}
	return dwHash;
}

QWORD PEGetProcAddressH(_In_ QWORD hModule, _In_ DWORD dwProcNameH)
{
	PDWORD pdwRVAAddrNames, pdwRVAAddrFunctions;
	PWORD pwNameOrdinals;
	DWORD i, dwFnIdx, dwHash;
	LPSTR sz;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule; // dos header.
	if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return 0; }
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(hModule + dosHeader->e_lfanew); // nt header
	if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { return 0; }
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + hModule);
	if(!exp || !exp->NumberOfNames || !exp->AddressOfNames) { return 0; }
	pdwRVAAddrNames = (PDWORD)(hModule + exp->AddressOfNames);
	pwNameOrdinals = (PWORD)(hModule + exp->AddressOfNameOrdinals);
	pdwRVAAddrFunctions = (PDWORD)(hModule + exp->AddressOfFunctions);
	for(i = 0; i < exp->NumberOfNames; i++) {
		sz = (LPSTR)(hModule + pdwRVAAddrNames[i]);
		dwHash = HashROR13A(sz);
		if(dwHash == dwProcNameH) {
			dwFnIdx = pwNameOrdinals[i];
			if(dwFnIdx >= exp->NumberOfFunctions) { return 0; }
			return (QWORD)(hModule + pdwRVAAddrFunctions[dwFnIdx]);
		}
	}
	return 0;
}

// see http://alter.org.ua/docs/nt_kernel/procaddr/
QWORD KernelGetModuleBase(_In_ PKERNEL_FUNCTIONS fnk, _In_ LPSTR szModuleName)
{
	PBYTE pbSystemInfoBuffer;
	SIZE_T cbSystemInfoBuffer = 0;
	PSYSTEM_MODULE_INFORMATION_ENTRY pSME;
	QWORD i, qwAddrModuleBase = 0;
	fnk->ZwQuerySystemInformation(11, NULL, 0, (PULONG)&cbSystemInfoBuffer);
	if(!cbSystemInfoBuffer) { return 0; }
	pbSystemInfoBuffer = (PBYTE)fnk->ExAllocatePool(0, cbSystemInfoBuffer);
	if(!pbSystemInfoBuffer) { return 0; }
	if(0 == fnk->ZwQuerySystemInformation(11, pbSystemInfoBuffer, (ULONG)cbSystemInfoBuffer, (PULONG)&cbSystemInfoBuffer)) {
		pSME = ((PSYSTEM_MODULE_INFORMATION)(pbSystemInfoBuffer))->Module;
		for(i = 0; i < ((PSYSTEM_MODULE_INFORMATION)(pbSystemInfoBuffer))->Count; i++) {
			if(0 == fnk->_stricmp(szModuleName, pSME[i].ImageName + pSME[i].PathLength)) {
				qwAddrModuleBase = pSME[i].Base;
			}
		}
	}
	if(pbSystemInfoBuffer) { fnk->ExFreePool(pbSystemInfoBuffer); }
	return qwAddrModuleBase;
}

VOID InitializeKernelFunctions(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS fnk)
{
	QWORD FUNC2[][2] = {
		{ &fnk->_stricmp,					H__stricmp },
		{ &fnk->ExAllocatePool,				H_ExAllocatePool },
		{ &fnk->ExFreePool,					H_ExFreePool },
		{ &fnk->IoCreateDriver,				H_IoCreateDriver },
		{ &fnk->KeDelayExecutionThread,		H_KeDelayExecutionThread },
		{ &fnk->KeGetCurrentIrql,			H_KeGetCurrentIrql },
		{ &fnk->MmGetPhysicalAddress,		H_MmGetPhysicalAddress },
		{ &fnk->MmLoadSystemImage,			H_MmLoadSystemImage },
		{ &fnk->MmMapIoSpace,				H_MmMapIoSpace },
		{ &fnk->MmUnloadSystemImage,		H_MmUnloadSystemImage },
		{ &fnk->MmUnmapIoSpace,				H_MmUnmapIoSpace },
		{ &fnk->RtlAnsiStringToUnicodeString, H_RtlAnsiStringToUnicodeString },
		{ &fnk->RtlCopyMemory,				H_RtlCopyMemory },
		{ &fnk->RtlFreeUnicodeString,		H_RtlFreeUnicodeString },
		{ &fnk->RtlInitAnsiString,			H_RtlInitAnsiString },
		{ &fnk->RtlInitUnicodeString,		H_RtlInitUnicodeString },
		{ &fnk->RtlInitUnicodeString,		H_RtlInitUnicodeString },
		{ &fnk->RtlZeroMemory,				H_RtlZeroMemory },
		{ &fnk->ZwClose,					H_ZwClose },
		{ &fnk->ZwCreateFile,				H_ZwCreateFile },
		{ &fnk->ZwOpenFile,					H_ZwOpenFile },
		{ &fnk->ZwReadFile,					H_ZwReadFile },
		{ &fnk->ZwQueryDirectoryFile,		H_ZwQueryDirectoryFile },
		{ &fnk->ZwQuerySystemInformation,	H_ZwQuerySystemInformation },
		{ &fnk->ZwSetSystemInformation,		H_ZwSetSystemInformation },
		{ &fnk->ZwWriteFile,				H_ZwWriteFile }
	};
	for(QWORD j = 0; j < (sizeof(FUNC2) / sizeof(QWORD[2])); j++) {
		*(PQWORD)FUNC2[j][0] = PEGetProcAddressH(qwNtosBase, (DWORD)FUNC2[j][1]);
	}
}

DWORD PEGetImageSize(_In_ QWORD hModule)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule; // dos header.
	if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return 0; }
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LONG_PTR)hModule + dosHeader->e_lfanew); // nt header
	if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { return 0; }
	return ntHeader->OptionalHeader.SizeOfImage;
}

VOID CommonSleep(_In_ PKERNEL_FUNCTIONS fnk, _In_ DWORD ms)
{
	LONGLONG llTimeToWait = -10000LL * ms;
	fnk->KeDelayExecutionThread(KernelMode, FALSE, &llTimeToWait);
}

BOOL _WriteLargeOutput_WaitForAck(_In_ PKERNEL_FUNCTIONS fnk, _In_ PKMDDATA pk)
{
	PEXEC_IO pis = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_IS);
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	while((pk->_op == KMD_CMD_EXEC_EXTENDED) && ((pis->magic != EXEC_IO_MAGIC) || (!pis->bin.fCompletedAck && (pis->bin.seqAck != pos->bin.seq)))) {
		CommonSleep(fnk, 25);
	}
	return (pk->_op == KMD_CMD_EXEC_EXTENDED) && !pis->bin.fCompletedAck;
}

BOOL WriteLargeOutput_WaitNext(_In_ PKERNEL_FUNCTIONS fnk, _In_ PKMDDATA pk)
{
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	pos->magic = EXEC_IO_MAGIC;
	CacheFlush();
	pos->bin.seq++;
	pk->_op = KMD_CMD_EXEC_EXTENDED;
	return _WriteLargeOutput_WaitForAck(fnk, pk);
}

VOID WriteLargeOutput_Finish(_In_ PKERNEL_FUNCTIONS fnk, _In_ PKMDDATA pk)
{
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	WriteLargeOutput_WaitNext(fnk, pk);
	pk->dataOutExtraLength = 0;
	CacheFlush();
	pos->bin.fCompleted = TRUE;
	pos->bin.seq++;
	_WriteLargeOutput_WaitForAck(fnk, pk);
	pk->_op = KMD_CMD_EXEC;
}
