// vmm.h : definitions related to virtual memory management support.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMM_H__
#define __VMM_H__
#include "pcileech.h"
#include "vfs.h"

#ifdef WIN32

// ----------------------------------------------------------------------------
// VMM configuration constants and struct definitions below:
// ----------------------------------------------------------------------------

#define VMM_PROCESSTABLE_ENTRIES_MAX    0x4000
#define VMM_PROCESS_OS_ALLOC_PTR_MAX    0x2    // max number of operating system specific pointers that must be free'd
#define VMM_MEMMAP_ENTRIES_MAX          0x4000

#define VMM_MEMMAP_FLAG_PAGE_W          0x0000000000000002
#define VMM_MEMMAP_FLAG_PAGE_NS         0x0000000000000004
#define VMM_MEMMAP_FLAG_PAGE_NX         0x8000000000000000
#define VMM_MEMMAP_FLAG_PAGE_MASK       0x8000000000000006

#define VMM_CACHE_TABLESIZE             0x4011  // (not even # to prevent clogging at specific table 'hash' buckets)
#define VMM_CACHE_TLB_ENTRIES           0x4000  // -> 64MB of cached data
#define VMM_CACHE_PHYS_ENTRIES          0x4000  // -> 64MB of cached data

typedef struct tdVMM_MEMMAP_ENTRY {
    QWORD AddrBase;
    QWORD cPages;
    QWORD fPage;
    CHAR  szName[32];
} VMM_MEMMAP_ENTRY, *PVMM_MEMMAP_ENTRY;

typedef struct tdVMM_PROCESS {
    DWORD dwPID;
    DWORD dwState;          // state of process, 0 = running
    QWORD paPML4;
    CHAR szName[16];
    BOOL _i_fMigrated;
    BOOL fUserOnly;
    BOOL fSpiderPageTableDone;
    // memmap related pointers (free must be called separately)
    QWORD cMemMap;
    PVMM_MEMMAP_ENTRY pMemMap;
    PBYTE pbMemMapDisplayCache;
    QWORD cbMemMapDisplayCache;
    QWORD Virt2Phys_VA;
    QWORD Virt2Phys_PA;
    union {
        struct{
            PVOID pvReserved[VMM_PROCESS_OS_ALLOC_PTR_MAX]; // os-specific buffer to be allocated if needed (free'd by VmmClose)
        } unk;
        struct {
            PBYTE pbLdrModulesDisplayCache;
            PVOID pbReserved[VMM_PROCESS_OS_ALLOC_PTR_MAX - 1];
            DWORD cbLdrModulesDisplayCache;
            QWORD vaEPROCESS;
            QWORD vaPEB;
            QWORD vaENTRY;
        } win;
    } os;
} VMM_PROCESS, *PVMM_PROCESS;

typedef struct tdVMM_PROCESS_TABLE {
    SIZE_T c;
    WORD iFLink;
    WORD iFLinkM[VMM_PROCESSTABLE_ENTRIES_MAX];
    PVMM_PROCESS M[VMM_PROCESSTABLE_ENTRIES_MAX];
    struct tdVMM_PROCESS_TABLE *ptNew;
} VMM_PROCESS_TABLE, *PVMM_PROCESS_TABLE;

#define VMM_CACHE_ENTRY_MAGIC 0x29d50298c4921034

typedef struct tdVMM_CACHE_ENTRY {
    QWORD qwMAGIC;
    struct tdVMM_CACHE_ENTRY *FLink;
    struct tdVMM_CACHE_ENTRY *BLink;
    struct tdVMM_CACHE_ENTRY *AgeFLink;
    struct tdVMM_CACHE_ENTRY *AgeBLink;
    QWORD tm;
    DMA_IO_SCATTER_HEADER h;
    BYTE pb[0x1000];
} VMM_CACHE_ENTRY, *PVMM_CACHE_ENTRY, **PPVMM_CACHE_ENTRY;

typedef struct tdVMM_CACHE_TABLE {
    PVMM_CACHE_ENTRY M[VMM_CACHE_TABLESIZE];
    PVMM_CACHE_ENTRY AgeFLink;
    PVMM_CACHE_ENTRY AgeBLink;
    PVMM_CACHE_ENTRY S;
} VMM_CACHE_TABLE, *PVMM_CACHE_TABLE;


typedef struct tdVMM_CONTEXT {
    PPCILEECH_CONTEXT ctxPcileech;
    CRITICAL_SECTION MasterLock;
    PVMM_PROCESS_TABLE ptPROC;
    PVMM_CACHE_TABLE ptTLB;
    PVMM_CACHE_TABLE ptPHYS;
    BOOL fReadOnly;
    // os specific below:
    BOOL fWin;
    BOOL fUnknownX64;
    struct {
        BOOL fEnabled;
        HANDLE hThread;
    } ThreadProcCache;
} VMM_CONTEXT, *PVMM_CONTEXT;

// ----------------------------------------------------------------------------
// VMM function definitions below:
// ----------------------------------------------------------------------------

/*
* Write a virtually contigious arbitrary amount of memory.
* -- ctxVmm
* -- pProcess
* -- qwVA
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
BOOL VmmWrite(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Read a virtually contigious arbitrary amount of memory.
* -- ctxVmm
* -- pProcess
* -- qwVA
* -- pb
* -- cb
* -- return
*/
BOOL VmmRead(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Read a virtually contigious arbitrary amount of memory and report the number
* of bytes read in pcbRead.
* -- ctxVmm
* -- pProcess
* -- qwVA
* -- pb
* -- cb
* -- pcbRead
*/
VOID VmmReadEx(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Inout_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt);

/*
* Read a single 4096-byte page of virtual memory.
* -- ctxVmm
* -- pProcess
* -- qwVA
* -- pbPage
* -- return
*/
BOOL VmmReadPage(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Scatter read virtual memory. Non contiguous 4096-byte pages.
* -- ctxVmm
* -- pProcess
* -- ppDMAsVirt
* -- cpDMAsVirt
*/
VOID VmmReadScatterVirtual(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _Inout_ PPDMA_IO_SCATTER_HEADER ppDMAsVirt, _In_ DWORD cpDMAsVirt);

/*
* Translate a virtual address to a physical address by walking the page tables.
* -- ctxVmm
* -- pProcess
* -- qwVA
* -- pqwPA
* -- return
*/
_Success_(return)
BOOL VmmVirt2Phys(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA, _Out_ PQWORD pqwPA);

/*
* Spider the TLB (page table cache) to load all page table pages into the cache.
* This is done to speed up various subsequent virtual memory accesses.
* NB! pages may fall out of the cache if it's in heavy use or doe to timing.
* -- ctxVmm
* -- qwPML4     = physical adderss of the Page Mapping Level 4 table to spider.
* -- fUserOnly  = only spider user-mode (ring3) pages, no kernel pages.
*/
VOID VmmTlbSpider(_Inout_ PVMM_CONTEXT ctxVmm, _In_ QWORD qwPML4, _In_ BOOL fUserOnly);

/*
* Try verify that a supplied page table in pb is valid by analyzing it.
* -- ctxVmm
* -- pb = 0x1000 bytes containing the page table page.
* -- pa = physical address if the page table page.
* -- fSelfRefReq = is a self referential entry required to be in the map? (PML4 for Windows).
*/
BOOL VmmTlbPageTableVerify(_Inout_ PVMM_CONTEXT ctxVmm, _Inout_ PBYTE pb, _In_ QWORD pa, _In_ BOOL fSelfRefReq);

/*
* Retrieve a page table (0x1000 bytes) via the TLB cache.
* -- ctxVmm
* -- qwPA
* -- fCacheOnly = if set do not make a request to underlying device if not in cache.
* -- return
*/
PBYTE VmmTlbGetPageTable(_In_ PVMM_CONTEXT ctxVmm, _In_ QWORD qwPA, _In_ BOOL fCacheOnly);

/*
* Initialize the memory map for a specific process. This may take some time
* especially for kernel/system processes.
* -- ctxVmm
* -- pProcess
*/
VOID VmmMapInitialize(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess);

/*
* Map a tag into the sorted memory map in O(log2) operations. Supply only one
* of szTag or wszTag. Tags are usually module/dll name.
* -- ctxVmm
* -- pProcess
* -- vaBase
* -- vaLimit = limit == vaBase + size (== top address in range +1)
* -- szTag
* -- wszTag
*/
VOID VmmMapTag(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaBase, _In_ QWORD vaLimit, _In_opt_ LPSTR szTag, _In_opt_ LPWSTR wszTag);

/*
* Retrieve a memory map entry info given a specific address.
* -- pProcess
* -- qwVA
* -- return = the memory map entry or NULL if not found.
*/
PVMM_MEMMAP_ENTRY VmmMapGetEntry(_In_ PVMM_PROCESS pProcess, _In_ QWORD qwVA);

/*
* Generate the human-readable text byte-buffer representing an already existing
* memory map in the process. This memory map must have been initialized with a
* separate call to VmmMapInitialize.
* -- pProcess
*/
VOID VmmMapDisplayBufferGenerate(_In_ PVMM_PROCESS pProcess);


/*
* Create or re-create the entire process table. This will clean the complete and
* all existing processes will be cleared.
* -- ctxVmm
* -- return
*/
BOOL VmmProcessCreateTable(_In_ PVMM_CONTEXT ctxVmm);

/*
* Retrieve an existing process given a process id (PID).
* -- ctxVmm
* -- dwPID
* -- return = a process struct, or NULL if not found.
*/
PVMM_PROCESS VmmProcessGet(_In_ PVMM_CONTEXT ctxVmm, _In_ DWORD dwPID);

/*
* Create a new process item. New process items are created in a separate data
* structure and won't become visible to the "Process" functions until after the
* VmmProcessCreateFinish have been called.
*/
PVMM_PROCESS VmmProcessCreateEntry(_In_ PVMM_CONTEXT ctxVmm, _In_ DWORD dwPID, _In_ DWORD dwState, _In_ QWORD paPML4, _In_ CHAR szName[16], _In_ BOOL fUserOnly, _In_ BOOL fSpiderPageTableDone);

/*
* Activate the pending, not yet active, processes added by VmmProcessCreateEntry.
* This will also clear any previous processes.
* -- ctxVmm
*/
VOID VmmProcessCreateFinish(_In_ PVMM_CONTEXT ctxVmm);

/*
* Clear the specified cache from all entries.
* -- ctxVmm
* -- fTLB
* -- fPHYS
*/
VOID VmmCacheClear(_Inout_ _In_ PVMM_CONTEXT ctxVmm, _In_ BOOL fTLB, _In_ BOOL fPHYS);

/*
* Initialize a new VMM context. This must always be done before calling any
* other VMM functions. An alternative way to do this is to call the function:
* VmmProcInitialize.
* -- ctx
* -- return
*/
BOOL VmmInitialize(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* WIN32 */

/*
* Close and clean up the VMM context inside the PCILeech context, if existing.
* -- ctxPcileech
*/
VOID VmmClose(_Inout_ PPCILEECH_CONTEXT ctxPcileech);

#endif /* __VMM_H__ */
