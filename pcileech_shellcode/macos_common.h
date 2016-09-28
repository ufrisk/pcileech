// macos_common.h : definitions of commonly used shellcode functions
// Compatible with macOS.
//
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __MACOS_COMMON_H__
#define __MACOS_COMMON_H__

#include "statuscodes.h"

typedef void					VOID, *PVOID;
typedef int						BOOL, *PBOOL;
typedef unsigned char			BYTE, *PBYTE;
typedef char					CHAR, *PCHAR;
typedef unsigned short			WORD, *PWORD;
typedef unsigned long			DWORD, *PDWORD;
typedef unsigned __int64		QWORD, *PQWORD;
typedef void					*HANDLE;
#define NULL					((void *)0)
#define MAX_PATH				260
#define TRUE					1
#define FALSE					0

typedef unsigned long			STATUS;
#define STATUS_SUCCESS			0
#define STATUS_FAIL_BASE		0xf0000000UL

extern QWORD SysVCall(QWORD fn, ...);
extern QWORD LookupFunctionMacOS(QWORD qwAddrKernelBase, CHAR szFunctionName[]);
extern VOID PageFlush();
extern QWORD GetCR3();

//-------------------------------------------------------------------------------
// General definitions below.
//-------------------------------------------------------------------------------

#define VM_MIN_KERNEL_ADDRESS				0xFFFFFF8000000000UL
#define VM_MIN_PHYSICALMAPPING_ADDRESS		0xFFFFEE8000000000UL

typedef struct tdPHYSICAL_MEMORY_RANGE {
	QWORD BaseAddress;
	QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef struct tdFNMACOS { // function pointers to macOS functions (used in main control program)
	QWORD _kernel_map;
	QWORD _PE_state;
	QWORD IOFree;
	QWORD IOFreeContiguous;
	QWORD IOMalloc;
	QWORD IOMallocContiguous;
	QWORD IOSleep;
	QWORD memcmp;
	QWORD memcpy;
	QWORD memset;
	QWORD vm_protect;
	QWORD ReservedFutureUse[21];
} FNMACOS, *PFNMACOS;

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page).
* This page/struct is used to communicate between the inserted kernel code and
* the pcileech program.
* VNR: 002
*/
typedef struct tdKMDDATA {
	QWORD MAGIC;					// [0x000] magic number 0x0ff11337711333377.
	QWORD AddrKernelBase;			// [0x008] pre-filled by stage2, virtual address of KERNEL HEADER (WINDOWS/MACOS).
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
	FNMACOS fn;						// [0x300] used by shellcode to store function pointers.
	CHAR dataInStr[MAX_PATH];		// [0x400] string in-data
	CHAR ReservedFutureUse2[252];
	CHAR dataOutStr[MAX_PATH];		// [0x600] string out-data
	CHAR ReservedFutureUse3[252];
	QWORD ReservedFutureUse4[255];	// [0x800]
	QWORD _op;						// [0xFF8] (op is last 8 bytes in 4k-page)
} KMDDATA, *PKMDDATA;

//-------------------------------------------------------------------------------
// Function definitions below.
//-------------------------------------------------------------------------------

/*
* Checks whether the qwBaseAddress+qwNumberOfBytes range is completely inside a
* valid range inside the memory map.
* -- pbMemoryRanges = address of the memory map.
* -- cbMemoryRanges = byte count of the memory map.
* -- qwBaseAddress = base address if range to verify.
* -- qwNumberOfBytes = byte count of the range to verify.
* -- return = TRUE (range in map) / FALSE (range not in map)
*
*/
BOOL IsRangeInPhysicalMap(PBYTE pbMemoryRanges, QWORD cbMemoryRanges, QWORD qwBaseAddress, QWORD qwNumberOfBytes);

/*
* Retrieve the EFI map and place the usable chunks in the supplied buffer.
* The chunks are in the format of PHYSICAL_MEMORY_RANGE.
* -- pk
* -- pbBuffer4k_PhysicalMemoryRange = buffer to place result in.
* -- pcbBuffer4k_PhysicalMemoryRange = bytes written to buffer.
* -- return = TRUE/FALSE
*/
BOOL GetMemoryMap(PKMDDATA pk, PBYTE pbBuffer4k_PhysicalMemoryRange, PQWORD pcbBuffer4k_PhysicalMemoryRange);

/*
* Map a maximum of 16MB physical memory starting at qwMemoryBase. The physical
* memory is mapped onto the virtual address 0xFFFFEE8000000000.
* -- pk
* -- qwMemoryBase = physical page aligned base address to map to virtual space.
* -- return = 0xFFFFEE8000000000 (mapped virtual address)
*/
QWORD MapMemoryPhysical(PKMDDATA pk, QWORD qwMemoryBase);

/*
* Retrive the maximum physical memory address in the system.
* -- pbMemoryRanges = address of the memory map.
* -- cbMemoryRanges = byte count of the memory map.
* -- return = the maximum memory address.
*/
QWORD GetMemoryPhysicalMaxAddress(PBYTE pbMemoryRanges, QWORD cbMemoryRanges);

#endif /* __MACOS_COMMON_H__ */