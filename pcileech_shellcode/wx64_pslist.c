// wx64_pslist.c : kernel code to list running processes (name and PID).
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_pslist.c
// ml64 wx64_common_a.asm /Fewx64_pslist.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_pslist.obj wx64_common.obj
// shellcode64.exe -o wx64_pslist.exe "ACTIVE PROCESS LIST                                                        \n===========================================================================\nNTSTATUS: %s0x%08x                                                         \nIN TOTAL %i ENTRIES EXISTS, SEE BELOW FOR MORE INFORMATION                 \n===========================================================================\n"
//
#include "wx64_common.h"

typedef struct tdKERNEL_FUNCTIONS2 {
	LPSTR(*PsGetProcessImageFileName)(
		_In_  PEPROCESS Process
		);
	NTSTATUS(*PsLookupProcessByProcessId)(
		_In_  HANDLE    ProcessId,
		_Out_ PEPROCESS *Process
		);
	size_t(*strnlen)(
		const char *str,
		size_t numberOfElements
		);
} KERNEL_FUNCTIONS2, *PKERNEL_FUNCTIONS2;

VOID InitializeKernelFunctions2(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS2 fnk2)
{
	QWORD FUNC2[][2] = {
		{ &fnk2->PsGetProcessImageFileName,			H_PsGetProcessImageFileName },
		{ &fnk2->PsLookupProcessByProcessId,		H_PsLookupProcessByProcessId },
		{ &fnk2->strnlen,							H_strnlen }
	};
	for(QWORD j = 0; j < (sizeof(FUNC2) / sizeof(QWORD[2])); j++) {
		*(PQWORD)FUNC2[j][0] = PEGetProcAddressH(qwNtosBase, (DWORD)FUNC2[j][1]);
	}
}

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[68];
	LONG BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

NTSTATUS GetProcessNameFromPid(_In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, _In_ HANDLE pid, _In_ SIZE_T cb, _Out_ PBYTE pb)
{
	PEPROCESS Process;
	LPSTR sz;
	SIZE_T csz;
	NTSTATUS nt = fnk2->PsLookupProcessByProcessId(pid, &Process);
	if(NT_SUCCESS(nt)) {
		sz = fnk2->PsGetProcessImageFileName(Process);
		csz = fnk2->strnlen(sz, cb);
		fnk->RtlCopyMemory(pb, sz, csz);
	}
	return nt;
}

NTSTATUS ActionDefault(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2)
{
	CHAR ABET_HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	NTSTATUS nt;
	PBYTE pbSPIBuffer;
	ULONG cbSPIBuffer;
	PSYSTEM_PROCESS_INFORMATION pPI;
	QWORD qwAddrOut, qwPID;
	nt = fnk->ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &cbSPIBuffer);
	if(nt != 0xC0000004 || !cbSPIBuffer) {
		return nt;
	}
	pbSPIBuffer = (PBYTE)fnk->ExAllocatePool(0, cbSPIBuffer);
	if(!pbSPIBuffer) { 
		return E_OUTOFMEMORY; 
	}
	nt = fnk->ZwQuerySystemInformation(SystemProcessInformation, pbSPIBuffer, cbSPIBuffer, &cbSPIBuffer);
	if(NT_SUCCESS(nt)) {
		pPI = (PSYSTEM_PROCESS_INFORMATION)pbSPIBuffer;
		qwAddrOut = pk->DMAAddrVirtual + pk->dataOutExtraOffset + pk->dataOutExtraLength;
		do {
			pk->dataOut[1]++;
			qwAddrOut = pk->DMAAddrVirtual + pk->dataOutExtraOffset + pk->dataOutExtraLength;
			*(PQWORD)(qwAddrOut + 0x00) = 0x2020202020202020;
			*(PQWORD)(qwAddrOut + 0x08) = 0x2020202020202020;
			pk->dataOutExtraLength += 0x20;
			qwPID = pPI->UniqueProcessId;
			GetProcessNameFromPid(fnk, fnk2, (HANDLE)qwPID, 0x10, (PBYTE)qwAddrOut);
			*(PDWORD)(qwAddrOut + 0x10) = 0x3D444950;
			*(PBYTE)(qwAddrOut + 0x1f) = '\n';
			*(PBYTE)(qwAddrOut + 0x1e) = '\r';
			*(PBYTE)(qwAddrOut + 0x1d) = '0' + (qwPID % 10);
			*(PBYTE)(qwAddrOut + 0x1c) = '0' + ((qwPID / 10) % 10);
			*(PBYTE)(qwAddrOut + 0x1b) = '0' + ((qwPID / 100) % 10);
			*(PBYTE)(qwAddrOut + 0x1a) = '0' + ((qwPID / 1000) % 10);
			*(PBYTE)(qwAddrOut + 0x19) = '0' + ((qwPID / 10000) % 10);
			*(PBYTE)(qwAddrOut + 0x18) = '|';
			*(PBYTE)(qwAddrOut + 0x17) = ABET_HEX[qwPID & 0xf];
			*(PBYTE)(qwAddrOut + 0x16) = ABET_HEX[(qwPID >> 4) & 0xf];
			*(PBYTE)(qwAddrOut + 0x15) = ABET_HEX[(qwPID >> 8) & 0xf];
			*(PBYTE)(qwAddrOut + 0x14) = ABET_HEX[(qwPID >> 12) & 0xf];
			if(!pPI->NextEntryOffset) {
				break;
			}
			pPI = (PSYSTEM_PROCESS_INFORMATION)((QWORD)pPI + pPI->NextEntryOffset);
		} while(((QWORD)pPI >= (QWORD)pbSPIBuffer) && ((QWORD)pPI < (QWORD)pbSPIBuffer + cbSPIBuffer));
	}
	if(pbSPIBuffer) { fnk->ExFreePool(pbSPIBuffer); }
	return nt;
}

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	KERNEL_FUNCTIONS fnk;
	KERNEL_FUNCTIONS2 fnk2;
	InitializeKernelFunctions(pk->AddrKernelBase, &fnk);
	InitializeKernelFunctions2(pk->AddrKernelBase, &fnk2);
	pk->dataOut[0] = ActionDefault(pk, &fnk, &fnk2);
}