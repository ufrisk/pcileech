// wx64_pskill.c : kernel code to terminate running processes.
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_pskill.c
// ml64.exe wx64_common_a.asm /Fewx64_pskill.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_pskill.obj wx64_common.obj
// shellcode64.exe -o wx64_pskill.exe "TERMINATE/KILL PROCESS                                         \n===============================================================\nREQUIRED OPTIONS:                                              \n  -0   : Process PID to terminate. Example '-0 0x0fe0'.        \nOPTIONAL OPTIONS:                                              \n  -1   : Process exit status. Default: 0. Example:  '-0 0x01'. \n===== RESULT OF TERMINATE/KILL OPERATION ======================%s\nNTSTATUS  : 0x%08X                                             \n===============================================================\n"
//
#include "wx64_common.h"

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

//----------------------------------------------------------------------------------------------------------

#define H_ZwClose								0x5d044c61
#define H_ZwOpenProcess							0xf0d09d60
#define H_ZwTerminateProcess					0x792cbc53

typedef struct tdKERNEL_FUNCTIONS2 {
	NTSTATUS(*ZwClose)(
		_In_ HANDLE Handle
		);
	NTSTATUS(*ZwOpenProcess)(
		_Out_    PHANDLE            ProcessHandle,
		_In_     ACCESS_MASK        DesiredAccess,
		_In_     POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PCLIENT_ID         ClientId
		);
	NTSTATUS(*ZwTerminateProcess)(
		_In_opt_ HANDLE   ProcessHandle,
		_In_     NTSTATUS ExitStatus
		);
} KERNEL_FUNCTIONS2, *PKERNEL_FUNCTIONS2;

VOID InitializeKernelFunctions2(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS2 fnk2)
{
	QWORD FUNC2[][2] = {
		{ &fnk2->ZwClose,							H_ZwClose },
		{ &fnk2->ZwOpenProcess,						H_ZwOpenProcess },
		{ &fnk2->ZwTerminateProcess,				H_ZwTerminateProcess }
	};
	for(QWORD j = 0; j < (sizeof(FUNC2) / sizeof(QWORD[2])); j++) {
		*(PQWORD)FUNC2[j][0] = PEGetProcAddressH(qwNtosBase, (DWORD)FUNC2[j][1]);
	}
}

//----------------------------------------------------------------------------------------------------------

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	NTSTATUS nt;
	OBJECT_ATTRIBUTES ObjectAttributes;
	KERNEL_FUNCTIONS fnk;
	KERNEL_FUNCTIONS2 fnk2;
	HANDLE ZwProcessHandle;
	CLIENT_ID ClientId;
	// validate indata and create function maps
	if(!pk->dataIn[0]) {
		pk->dataOut[0] = STATUS_INVALID_PARAMETER;
		return;
	}
	InitializeKernelFunctions(pk->AddrKernelBase, &fnk);
	InitializeKernelFunctions2(pk->AddrKernelBase, &fnk2);
	// open process handle
	fnk.RtlZeroMemory(&ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
	fnk.RtlZeroMemory(&ClientId, sizeof(CLIENT_ID));
	ClientId.UniqueThread = 0;
	ClientId.UniqueProcess = (HANDLE)pk->dataIn[0];
	nt = fnk2.ZwOpenProcess(&ZwProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
	if(NT_ERROR(nt)) {
		pk->dataOut[0] = nt;
		return;
	}
	// terminate process and exit
	pk->dataOut[0] = fnk2.ZwTerminateProcess(ZwProcessHandle, (NTSTATUS)pk->dataIn[1]);
	fnk2.ZwClose(ZwProcessHandle);
}
