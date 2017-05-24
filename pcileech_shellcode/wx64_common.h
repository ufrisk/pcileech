// wx64_common.h : declarations of commonly used shellcode functions
// Compatible with Windows x64.
//
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __WX64_COMMON_H__
#define __WX64_COMMON_H__
#include <windows.h>
#include "statuscodes.h"

#pragma warning( disable : 4047 4055 4127 4200 4201 4204)

typedef unsigned __int64		QWORD, *PQWORD;
typedef UCHAR KIRQL;
typedef KIRQL *PKIRQL;
typedef struct _EPROCESS *PEPROCESS;
typedef struct _ETHREAD *PETHREAD;
//#define _bs64 _byteswap_uint64  
#define _bs32(x) ((x << 24) | (x >> 24) | ((x << 8) & 0x00ff0000 ) | ((x >> 8) & 0x0000ff00))
#define _bs16(x) ((x << 8) | (x >> 8))

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status) ((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page).
* This page/struct is used to communicate between the inserted kernel code and
* the pcileech program.
* VNR: 002
*/
typedef struct tdKMDDATA {
	QWORD MAGIC;					// [0x000] magic number 0x0ff11337711333377.
	QWORD AddrKernelBase;			// [0x008] pre-filled by stage2, virtual address of KERNEL HEADER (WINDOWS/OSX).
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
	QWORD dataOutExtraLength;		// [0x200] length of extra in-data.
	QWORD dataOutExtraOffset;		// [0x208] offset from DMAAddrPhysical/DMAAddrVirtual.
	QWORD dataOutExtraLengthMax;	// [0x210] maximum length of extra in-data. 
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

#define EXEC_IO_MAGIC					0x12651232dfef9521
#define EXEC_IO_CONSOLE_BUFFER_SIZE		0x800
#define EXEC_IO_DMAOFFSET_IS			0x80000
#define EXEC_IO_DMAOFFSET_OS			0x81000
typedef struct tdEXEC_IO {
	QWORD magic;
	struct {
		QWORD cbRead;
		QWORD cbReadAck;
		QWORD Reserved[10];
		BYTE  pb[800];
	} con;
	struct {
		QWORD seq;
		QWORD seqAck;
		QWORD fCompleted;
		QWORD fCompletedAck;
	} bin;
	QWORD Reserved[395];
} EXEC_IO, *PEXEC_IO;

// system information class 11
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	ULONG Unknown1;
	ULONG Unknown2;
	ULONG Unknown3;
	ULONG Unknown4;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	ULONG Unknown1;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
	QWORD Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	QWORD Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5, 
	SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef CCHAR KPROCESSOR_MODE;

typedef enum _MODE {
	KernelMode,
	UserMode,
	MaximumMode
} MODE;

typedef enum _MEMORY_CACHING_TYPE {
	MmNonCached = 0,
	MmCached = 1,
	MmWriteCombined = 2,
	MmHardwareCoherentCached = 3,
	MmNonCachedUnordered = 4,
	MmUSWCCached = 5,
	MmMaximumCacheType = 6
} MEMORY_CACHING_TYPE;

#undef RtlCopyMemory
#undef RtlZeroMemory
typedef struct tdKERNEL_FUNCTIONS {
	int(*_stricmp)(
		const char *string1,
		const char *string2);
	PVOID(*ExAllocatePool)(
		_In_ QWORD PoolType,
		_In_ SIZE_T NumberOfBytes);
	VOID(*ExFreePool)(
		_In_ PVOID P);
	NTSTATUS(*IoCreateDriver)(
		_In_opt_ PUNICODE_STRING DriverName,
		_In_ QWORD  PDriverEntry
		);
	NTSTATUS(*KeDelayExecutionThread)(
		_In_ KPROCESSOR_MODE WaitMode,
		_In_ BOOLEAN         Alertable,
		_In_ PINT64          pllInterval_Neg100ns
		);
	KIRQL(*KeGetCurrentIrql)(
		);
	QWORD(*MmGetPhysicalAddress)(
		_In_ PVOID BaseAddress
		);
	NTSTATUS(*MmLoadSystemImage)(
		_In_ PUNICODE_STRING  FileName,
		_In_opt_ PUNICODE_STRING NamePrefix,
		_In_opt_ PUNICODE_STRING LoadedName,
		_In_ ULONG  Flags,
		_Out_ PVOID *ModuleObject,
		_Out_ PVOID *ImageBaseAddress
		);
	PVOID(*MmMapIoSpace)(
		_In_  QWORD  PhysicalAddress,
		_In_  SIZE_T NumberOfBytes,
		_In_  MEMORY_CACHING_TYPE CacheType
		);
	NTSTATUS(*MmUnloadSystemImage)(
		_In_ PVOID *ModuleObject
		);
	VOID(*MmUnmapIoSpace)(
		_In_  PVOID  BaseAddress,
		_In_  SIZE_T NumberOfBytes
		);
	NTSTATUS(*RtlAnsiStringToUnicodeString)(
		_Inout_ PUNICODE_STRING DestinationString,
		_In_    PANSI_STRING    SourceString,
		_In_    BOOLEAN         AllocateDestinationString
		);
	VOID(*RtlCopyMemory)(
		_Out_ VOID UNALIGNED *Destination,
		_In_ const VOID UNALIGNED *Source,
		_In_ SIZE_T Length
		);
	VOID(*RtlFreeUnicodeString)(
		_Inout_ PUNICODE_STRING UnicodeString
		);
	VOID(*RtlInitAnsiString)(
		_Out_    PANSI_STRING DestinationString,
		_In_opt_ PCSTR         SourceString
		);
	VOID(*RtlInitUnicodeString)(
		_Out_ PUNICODE_STRING DestinationString,
		_In_opt_ PCWSTR SourceString
		);
	VOID(*RtlZeroMemory)(
		_Out_ VOID UNALIGNED *Destination,
		_In_ SIZE_T Length
		);
	NTSTATUS(*ZwClose)(
		_In_ HANDLE hObject
		);
	NTSTATUS(*ZwCreateFile)(
		_Out_	 PHANDLE			FileHandle, 
		_In_	 ACCESS_MASK		DesiredAccess, 
		_In_	 PVOID				ObjectAttributes, 
		_Out_	 PIO_STATUS_BLOCK	IoStatusBlock, 
		_In_opt_ PLARGE_INTEGER		AllocationSize, 
		_In_	 ULONG				FileAttributes, 
		_In_	 ULONG				ShareAccess, 
		_In_	 ULONG				CreateDisposition,
		_In_	 ULONG				CreateOptions, 
		_In_reads_bytes_opt_(EaLength) PVOID EaBuffer, 
		_In_	 ULONG				EaLength
		);
	NTSTATUS(*ZwOpenFile)(
		_Out_	 PHANDLE            FileHandle,
		_In_	 ACCESS_MASK        DesiredAccess,
		_In_	 POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_	 PIO_STATUS_BLOCK   IoStatusBlock,
		_In_	 ULONG              ShareAccess,
		_In_	 ULONG              OpenOptions
		);
	NTSTATUS(*ZwQueryDirectoryFile)(
		_In_	 HANDLE				FileHandle,
		_In_opt_ HANDLE				Event,
		_In_opt_ PVOID				ApcRoutine,
		_In_opt_ PVOID				ApcContext,
		_Out_	 PIO_STATUS_BLOCK	IoStatusBlock,
		_Out_	 PVOID				FileInformation,
		_In_	 ULONG				Length,
		_In_	 QWORD				FileInformationClass,
		_In_	 BOOLEAN			ReturnSingleEntry,
		_In_opt_ PUNICODE_STRING	FileName,
		_In_	 BOOLEAN			RestartScan
	);
	NTSTATUS(*ZwQuerySystemInformation)(
		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Inout_ PVOID SystemInformation,
		_In_ ULONG SystemInformationLength,
		_Out_opt_ PULONG ReturnLength);
	NTSTATUS(*ZwReadFile)(
		_In_     HANDLE           FileHandle,
		_In_opt_ HANDLE           Event,
		_In_opt_ PVOID			  ApcRoutine,
		_In_opt_ PVOID            ApcContext,
		_Out_    PIO_STATUS_BLOCK IoStatusBlock,
		_Out_    PVOID            Buffer,
		_In_     ULONG            Length,
		_In_opt_ PQWORD           ByteOffset,
		_In_opt_ PULONG           Key
		);
	NTSTATUS(*ZwSetSystemInformation)(
		_In_ QWORD SystemInformationClass,
		_In_ PVOID SystemInformation,
		_In_ ULONG SystemInformationLength
		);
	NTSTATUS(*ZwWriteFile)(
		_In_ HANDLE FileHandle, 
		_In_opt_ HANDLE Event,
		_In_opt_ PVOID ApcRoutine,
		_In_opt_ PVOID ApcContext,
		_Out_ PVOID IoStatusBlock, 
		_In_reads_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length, 
		_In_opt_ PLARGE_INTEGER ByteOffset, 
		_In_opt_ PULONG Key
		);
	PVOID pvStart;
} KERNEL_FUNCTIONS, *PKERNEL_FUNCTIONS;

// ----------------------------- ROR13 HASHES BELOW -----------------------------

#define H__stricmp								0xd73b454a
#define H_strnlen								0xe0fb3ba8
#define H_wcscat								0x690e4970
#define H_CiInitialize							0x0c2e8015
#define H_ExAllocatePool						0x3707e062
#define H_ExFreePool							0x9d489d1f
#define H_IoAllocateMdl							0xfb94c65d
#define H_IoCreateDriver						0xdccc7ba1
#define H_KeDelayExecutionThread				0x58586d92
#define H_KeGetCurrentIrql						0x4d90adce
#define H_KeInitializeApc						0x2b988da3
#define H_KeInsertQueueApc						0x88c695f9
#define H_KeStackAttachProcess					0x9e0047be
#define H_KeUnstackDetachProcess				0xf047dcf4
#define H_MmAllocateContiguousMemory			0x9f361ebc
#define H_MmFreeContiguousMemory				0x1345f592
#define H_MmGetPhysicalAddress					0x5a326357
#define H_MmGetPhysicalMemoryRanges				0x4977a56f
#define H_MmLoadSystemImage						0x6a6ab58f
#define H_MmMapIoSpace							0x05ddbef9
#define H_MmMapLockedPagesSpecifyCache			0xbceb1dcd
#define H_MmProbeAndLockPages					0x97d00e2b
#define H_MmUnloadSystemImage					0x9db338f7
#define H_MmUnmapIoSpace						0x6c6ec5c9
#define H_ObDereferenceObject					0x2e053fd6
#define H_PsCreateSystemThread					0x94a06b02
#define H_PsGetProcessImageFileName				0x8be7eeec
#define H_PsLookupProcessByProcessId			0xa3a0b82a
#define H_PsLookupThreadByThreadId				0x0e0b0e0d
#define H_RtlAnsiStringToUnicodeString			0xeb6c8389
#define H_RtlCompareMemory						0x770dcef6
#define H_RtlCopyMemory							0xcf64979b
#define H_RtlCreateUserThread					0x442f2041
#define H_RtlFreeUnicodeString					0xa8b2c02a
#define H_RtlInitAnsiString						0x7cc3283d
#define H_RtlInitUnicodeString					0x3035d02a
#define H_RtlZeroMemory							0xc53d4fdb
#define H_ZwAllocateVirtualMemory				0xd33d4aed
#define H_ZwClose								0x5d044c61
#define H_ZwCreateFile							0xc3a08f9d
#define H_ZwCreateKey							0x11c719c1
#define H_ZwDeleteFile							0xb6b0987d
#define H_ZwLoadDriver							0x0675aa53
#define H_ZwOpenFile							0x8829d4b8
#define H_ZwOpenProcess							0xf0d09d60
#define H_ZwReadFile							0x87fd3516
#define H_ZwQueryDirectoryFile					0x6fb06450
#define H_ZwQueryInformationFile				0xd7cd4118
#define H_ZwQuerySystemInformation				0xe661cae2
#define H_ZwSetSystemInformation				0xf7e624de
#define H_ZwSetValueKey							0x03a49be5
#define H_ZwUnloadDriver						0xf36cb1c0
#define H_ZwWriteFile							0x680e3136

// ----------------------------- FUNCTION DECLARATIONS BELOW -----------------------------

DWORD HashROR13A(_In_ LPCSTR sz);
QWORD PEGetProcAddressH(_In_ QWORD hModule, _In_ DWORD dwProcNameH);
QWORD KernelGetModuleBase(_In_ PKERNEL_FUNCTIONS fnk, _In_ LPSTR szModuleName);
VOID InitializeKernelFunctions(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS fnk);
DWORD PEGetImageSize(_In_ QWORD hModule);
VOID CommonSleep(_In_ PKERNEL_FUNCTIONS fnk, _In_ DWORD ms);
extern QWORD GetCR3();
extern VOID CacheFlush();

/*
* If a large output is to be written to PCILeech which won't fit in the DMA
* buffer - write as much as possible in the DMA buffer and then call this fn.
* When returned successfully write another chunk to this buffer and call again.
* WriteLargeOutput_Finish must be called after all data is written to clean up.
* -- fnk
* -- pk
* -- return
*/
BOOL WriteLargeOutput_WaitNext(_In_ PKERNEL_FUNCTIONS fnk, PKMDDATA pk);

/*
* Clean up function that must be called if WriteLargeOutput_WaitNext has
* previously been called.
* -- fnk
* -- pk
*/
VOID WriteLargeOutput_Finish(_In_ PKERNEL_FUNCTIONS fnk, PKMDDATA pk);

#endif /* __WX64_COMMON_H__ */