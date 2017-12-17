// macos_common.c : support functions used by macOS KMDs started by stage3 EXEC.
// Compatible with macOS.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "macos_common.h"

//-------------------------------------------------------------------------------
// EFI related defines below.
//-------------------------------------------------------------------------------

typedef struct PE_state {
	QWORD initialized;
	QWORD video_dummy[18];
	PVOID deviceTreeHead;
	PVOID bootArgs;
} PE_state_t, *PPE_state_t;

enum {
	EfiReservedMemoryType = 0,
	EfiLoaderCode = 1,
	EfiLoaderData = 2,
	EfiBootServicesCode = 3,
	EfiBootServicesData = 4,
	EfiRuntimeServicesCode = 5,
	EfiRuntimeServicesData = 6,
	EfiConventionalMemory = 7,
	EfiUnusableMemory = 8,
	EfiACPIReclaimMemory = 9,
	EfiACPIMemoryNVS = 10,
	EfiMemoryMappedIO = 11,
	EfiMemoryMappedIOPortSpace = 12,
	EfiPalCode = 13,
	EfiMaxMemoryType = 14
};

typedef struct tdEFI_MEMORY_RANGE {
	DWORD Type;
	DWORD Pad;
	QWORD PhysicalStart;
	QWORD VirtualStart;
	QWORD NumberOfPages;
	QWORD Attribute;
} EFI_MEMORY_RANGE, *PEFI_MEMORY_RANGE;

#define BOOT_LINE_LENGTH        1024

typedef struct tdBOOT_ARGS {
	QWORD RevisionAndVersion;
	CHAR  CommandLine[BOOT_LINE_LENGTH]; // Passed in command line 
	DWORD MemoryMap; // Physical address of memory map 
	DWORD MemoryMapSize;
	DWORD MemoryMapDescriptorSize;
	DWORD MemoryMapDescriptorVersion;
	// truncated struct members exists
} BOOT_ARGS, *PBOOT_ARGS;

//-------------------------------------------------------------------------------
// Kernel module functions below.
//-------------------------------------------------------------------------------

BOOL GetMemoryMap(PKMDDATA pk, PBYTE pbBuffer4k_PhysicalMemoryRange, PQWORD pcbBuffer4k_PhysicalMemoryRange)
{
	PBOOT_ARGS ba = ((PPE_state_t)pk->fn._PE_state)->bootArgs;
	PEFI_MEMORY_RANGE pEFIr;
	PPHYSICAL_MEMORY_RANGE pmr;
	QWORD cPmr = 0, o = 0;
	SysVCall(pk->fn.memset, pbBuffer4k_PhysicalMemoryRange, 0ULL, 4096ULL);
	pmr = (PPHYSICAL_MEMORY_RANGE)pbBuffer4k_PhysicalMemoryRange;
	while(o < ba->MemoryMapSize) {
		pEFIr = (PEFI_MEMORY_RANGE)(VM_MIN_KERNEL_ADDRESS + ba->MemoryMap + o);
		if(pEFIr->Type < EfiMaxMemoryType && pEFIr->Type != EfiReservedMemoryType && pEFIr->Type != EfiUnusableMemory && pEFIr->Type != EfiMemoryMappedIO && pEFIr->Type != EfiMemoryMappedIOPortSpace) {
			if(cPmr && (pEFIr->PhysicalStart == pmr[cPmr - 1].BaseAddress + pmr[cPmr - 1].NumberOfBytes)) {
				pmr[cPmr - 1].NumberOfBytes += pEFIr->NumberOfPages * 0x1000;
			} else {
				pmr[cPmr].BaseAddress = pEFIr->PhysicalStart;
				pmr[cPmr].NumberOfBytes = pEFIr->NumberOfPages * 0x1000;
				cPmr++;
			}
		}
		o += ba->MemoryMapDescriptorSize;
	}
	*pcbBuffer4k_PhysicalMemoryRange = cPmr * sizeof(PHYSICAL_MEMORY_RANGE);
	return TRUE;
}

QWORD MapMemoryPhysical(PKMDDATA pk, QWORD qwMemoryBase)
{
	for(DWORD i = 0; i < 512 * 8; i++) { // PT*8 -> Pages (16MB)
		((PQWORD)(pk->ReservedKMD[0] + 0x2000))[i] = 0x0000000000000003 | (qwMemoryBase + 0x1000 * i);
	}
	PageFlush();
	return 0xffffee8000000000;
}

BOOL IsRangeInPhysicalMap(PBYTE pbMemoryRanges, QWORD cbMemoryRanges, QWORD qwBaseAddress, QWORD qwNumberOfBytes)
{
	PPHYSICAL_MEMORY_RANGE ppmr;
	for(QWORD i = 0; i < cbMemoryRanges / sizeof(PHYSICAL_MEMORY_RANGE); i++) {
		ppmr = ((PPHYSICAL_MEMORY_RANGE)pbMemoryRanges) + i;
		if(((ppmr->BaseAddress <= qwBaseAddress) && (ppmr->BaseAddress + ppmr->NumberOfBytes > qwBaseAddress + qwNumberOfBytes))) {
			return TRUE;
		}
	}
	return FALSE;
}

QWORD GetMemoryPhysicalMaxAddress(PBYTE pbMemoryRanges, QWORD cbMemoryRanges)
{
	PPHYSICAL_MEMORY_RANGE pMemMap = (PPHYSICAL_MEMORY_RANGE)pbMemoryRanges;
	QWORD cMemMap = cbMemoryRanges / sizeof(PHYSICAL_MEMORY_RANGE);
	return pMemMap[cMemMap - 1].BaseAddress + pMemMap[cMemMap - 1].NumberOfBytes;
}


BOOL _WriteLargeOutput_WaitForAck(PKMDDATA pk)
{
	PEXEC_IO pis = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_IS);
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	while((pk->_op == KMD_CMD_EXEC_EXTENDED) && ((pis->magic != EXEC_IO_MAGIC) || (!pis->bin.fCompletedAck && (pis->bin.seqAck != pos->bin.seq)))) {
		SysVCall(pk->fn.IOSleep, 25);
	}
	return (pk->_op == KMD_CMD_EXEC_EXTENDED) && !pis->bin.fCompletedAck;
}

BOOL WriteLargeOutput_WaitNext(PKMDDATA pk)
{
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	pos->magic = EXEC_IO_MAGIC;
	CacheFlush();
	pos->bin.seq++;
	pk->_op = KMD_CMD_EXEC_EXTENDED;
	return _WriteLargeOutput_WaitForAck(pk);
}

VOID WriteLargeOutput_Finish(PKMDDATA pk)
{
	PEXEC_IO pos = (PEXEC_IO)(pk->DMAAddrVirtual + EXEC_IO_DMAOFFSET_OS);
	WriteLargeOutput_WaitNext(pk);
	pk->dataOutExtraLength = 0;
	CacheFlush();
	pos->bin.fCompleted = TRUE;
	pos->bin.seq++;
	_WriteLargeOutput_WaitForAck(pk);
	pk->_op = KMD_CMD_EXEC;
}
