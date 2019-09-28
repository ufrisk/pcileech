// vmmdll.h : header file to include in projects that use vmm.dll either as
// stand anlone projects or as native plugins to vmm.dll.
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
// Header Version: 2.10
//

#include <windows.h>
#include "leechcore.h"

#ifndef __VMMDLL_H__
#define __VMMDLL_H__
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

//-----------------------------------------------------------------------------
// INITIALIZATION FUNCTIONALITY BELOW:
// Choose one way of initialzing the VMM / Memory Process File System.
//-----------------------------------------------------------------------------

/*
* Initialize VMM.DLL with command line parameters. For a more detailed info
* about the parameters please see github wiki for Memory Process File System
* and LeechCore. THIS IS THE PREFERED WAY OF INITIALIZING VMM.DLL
* Important parameters are:
*    -printf = show printf style outputs)
*    -v -vv -vvv = extra verbosity levels)
*    -device = device as on format for LeechCore - please see leechcore.h or
*              Github documentation for additional information. Some values
*              are: <file>, fpga, usb3380, hvsavedstate, totalmeltdown, pmem
*    -remote = remote LeechCore instance - please see leechcore.h or Github
*              documentation for additional information.
*    -norefresh = disable background refreshes (even if backing memory is
*              volatile memory).
*    -symbolserverdisable = disable symbol server until user change. This
*              parameter will take precedence over registry settings.
* -- argc
* -- argv
* -- return = success/fail
*/
_Success_(return)
BOOL VMMDLL_Initialize(_In_ DWORD argc, _In_ LPSTR argv[]);

/*
* Close an initialized instance of VMM.DLL and clean up all allocated resources
* including plugins, linked PCILeech.DLL and other memory resources.
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_Close();

/*
* Perform a force refresh of all internal caches including:
* - process listings
* - memory cache
* - page table cache
* WARNING: function may take some time to execute!
* -- dwReserved = reserved future use - must be zero
* -- return = sucess/fail
*/
_Success_(return)
BOOL VMMDLL_Refresh(_In_ DWORD dwReserved);

/*
* Free memory allocated by the VMMDLL.
* -- pvMem
*/
VOID VMMDLL_MemFree(_Frees_ptr_opt_ PVOID pvMem);


//-----------------------------------------------------------------------------
// CONFIGURATION SETTINGS BELOW:
// Configure the memory process file system or the underlying memory
// acquisition devices.
//-----------------------------------------------------------------------------

/*
* Options used together with the functions: VMMDLL_GetOption & VMMDLL_SetOption
* Options are defined with either: VMMDLL_OPT_* in this header file or as
* MEMDEVICE_OPT_* in memdevice.h
* For more detailed information check the sources for individual device types.
*/
#define VMMDLL_OPT_CORE_PRINTF_ENABLE                   0x80000001  // RW
#define VMMDLL_OPT_CORE_VERBOSE                         0x80000002  // RW
#define VMMDLL_OPT_CORE_VERBOSE_EXTRA                   0x80000003  // RW
#define VMMDLL_OPT_CORE_VERBOSE_EXTRA_TLP               0x80000004  // RW
#define VMMDLL_OPT_CORE_MAX_NATIVE_ADDRESS              0x80000005  // R
#define VMMDLL_OPT_CORE_MAX_NATIVE_IOSIZE               0x80000006  // R
#define VMMDLL_OPT_CORE_SYSTEM                          0x80000007  // R
#define VMMDLL_OPT_CORE_MEMORYMODEL                     0x80000008  // R

#define VMMDLL_OPT_CONFIG_IS_REFRESH_ENABLED            0x40000001  // R - 1/0
#define VMMDLL_OPT_CONFIG_TICK_PERIOD                   0x40000002  // RW - base tick period in ms
#define VMMDLL_OPT_CONFIG_READCACHE_TICKS               0x40000003  // RW - memory cache validity period (in ticks)
#define VMMDLL_OPT_CONFIG_TLBCACHE_TICKS                0x40000004  // RW - page table (tlb) cache validity period (in ticks)
#define VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL       0x40000005  // RW - process refresh (partial) period (in ticks)
#define VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_TOTAL         0x40000006  // RW - process refresh (full) period (in ticks)
#define VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR             0x40000007  // R
#define VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR             0x40000008  // R
#define VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION          0x40000009  // R
#define VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL       0x4000000A  // RW - enable function call statistics (.status/statistics_fncall file)
#define VMMDLL_OPT_CONFIG_IS_PAGING_ENABLED             0x4000000B  // RW - 1/0

#define VMMDLL_OPT_WIN_VERSION_MAJOR                    0x40000101  // R
#define VMMDLL_OPT_WIN_VERSION_MINOR                    0x40000102  // R
#define VMMDLL_OPT_WIN_VERSION_BUILD                    0x40000103  // R

static const LPSTR VMMDLL_MEMORYMODEL_TOSTRING[4] = { "N/A", "X86", "X86PAE", "X64" };

typedef enum tdVMMDLL_MEMORYMODEL_TP {
    VMMDLL_MEMORYMODEL_NA       = 0,
    VMMDLL_MEMORYMODEL_X86      = 1,
    VMMDLL_MEMORYMODEL_X86PAE   = 2,
    VMMDLL_MEMORYMODEL_X64      = 3
} VMMDLL_MEMORYMODEL_TP;

typedef enum tdVMMDLL_SYSTEM_TP {
    VMMDLL_SYSTEM_UNKNOWN_X64   = 1,
    VMMDLL_SYSTEM_WINDOWS_X64   = 2,
    VMMDLL_SYSTEM_UNKNOWN_X86   = 3,
    VMMDLL_SYSTEM_WINDOWS_X86   = 4
} VMMDLL_SYSTEM_TP;

/*
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- fOption
* -- pqwValue = pointer to ULONG64 to receive option value.
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_ConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);

/*
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- fOption
* -- qwValue
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_ConfigSet(_In_ ULONG64 fOption, _In_ ULONG64 qwValue);



//-----------------------------------------------------------------------------
// VFS - VIRTUAL FILE SYSTEM FUNCTIONALITY BELOW:
// This is the core of the memory process file system. All implementation and
// analysis towards the file system is possible by using functionality below. 
//-----------------------------------------------------------------------------

#define VMMDLL_STATUS_SUCCESS                       ((NTSTATUS)0x00000000L)
#define VMMDLL_STATUS_UNSUCCESSFUL                  ((NTSTATUS)0xC0000001L)
#define VMMDLL_STATUS_END_OF_FILE                   ((NTSTATUS)0xC0000011L)
#define VMMDLL_STATUS_FILE_INVALID                  ((NTSTATUS)0xC0000098L)
#define VMMDLL_STATUS_FILE_SYSTEM_LIMITATION        ((NTSTATUS)0xC0000427L)

#define VMMDLL_VFS_FILELIST_EXINFO_VERSION          1
#define VMMDLL_VFS_FILELIST_VERSION                 1

typedef struct tdVMMDLL_VFS_FILELIST_EXINFO {
    DWORD dwVersion;
    BOOL fCompressed;                   // set flag FILE_ATTRIBUTE_COMPRESSED - (no meaning but shows gui artifact in explorer.exe)
    union {
        FILETIME ftCreationTime;        // 0 = default time
        QWORD qwCreationTime;
    };
    union {
        FILETIME ftLastAccessTime;      // 0 = default time
        QWORD qwLastAccessTime;
    };
    union {
        FILETIME ftLastWriteTime;       // 0 = default time
        QWORD qwLastWriteTime;
    };
} VMMDLL_VFS_FILELIST_EXINFO, *PVMMDLL_VFS_FILELIST_EXINFO;

typedef struct tdVMMDLL_VFS_FILELIST {
    DWORD dwVersion;
    VOID(*pfnAddFile)     (_Inout_ HANDLE h, _In_opt_ LPSTR szName, _In_opt_ LPWSTR wszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
    VOID(*pfnAddDirectory)(_Inout_ HANDLE h, _In_opt_ LPSTR szName, _In_opt_ LPWSTR wszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
    HANDLE h;
} VMMDLL_VFS_FILELIST, *PVMMDLL_VFS_FILELIST;

/*
* Helper inline functions for callbacks into the VMM_VFS_FILELIST structure.
*/
inline VOID VMMDLL_VfsList_AddFile(_In_ HANDLE pFileList, _In_opt_ LPSTR szName, _In_ ULONG64 cb)
{
    ((PVMMDLL_VFS_FILELIST)pFileList)->pfnAddFile(((PVMMDLL_VFS_FILELIST)pFileList)->h, szName, NULL, cb, NULL);
}

inline VOID VMMDLL_VfsList_AddFileEx(_In_ HANDLE pFileList, _In_opt_ LPSTR szName, _In_opt_ LPWSTR wszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    ((PVMMDLL_VFS_FILELIST)pFileList)->pfnAddFile(((PVMMDLL_VFS_FILELIST)pFileList)->h, szName, wszName, cb, pExInfo);
}

inline VOID VMMDLL_VfsList_AddDirectory(_In_ HANDLE pFileList, _In_opt_ LPSTR szName)
{
    ((PVMMDLL_VFS_FILELIST)pFileList)->pfnAddDirectory(((PVMMDLL_VFS_FILELIST)pFileList)->h, szName, NULL, NULL);
}

inline VOID VMMDLL_VfsList_AddDirectoryEx(_In_ HANDLE pFileList, _In_opt_ LPSTR szName, _In_opt_ LPWSTR wszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    ((PVMMDLL_VFS_FILELIST)pFileList)->pfnAddDirectory(((PVMMDLL_VFS_FILELIST)pFileList)->h, szName, wszName, pExInfo);
}

inline BOOL VMMDLL_VfsList_IsHandleValid(_In_ HANDLE pFileList)
{
    return ((PVMMDLL_VFS_FILELIST)pFileList)->dwVersion == VMMDLL_VFS_FILELIST_VERSION;
}

/*
* List a directory of files in the memory process file system. Directories and
* files will be listed by callbacks into functions supplied in the pFileList
* parameter. If information of an individual file is needed it's neccessary
* to list all files in its directory.
* -- wcsPath
* -- pFileList
* -- return
*/
_Success_(return)
BOOL VMMDLL_VfsList(_In_ LPCWSTR wcsPath, _Inout_ PVMMDLL_VFS_FILELIST pFileList);

/*
* Read select parts of a file in the memory process file system.
* -- wcsFileName
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*
*/
NTSTATUS VMMDLL_VfsRead(_In_ LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);

/*
* Write select parts to a file in the memory process file system.
* -- wcsFileName
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
NTSTATUS VMMDLL_VfsWrite(_In_ LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);

/*
* Utility functions for memory process file system read/write towards different
* underlying data representations.
*/
NTSTATUS VMMDLL_UtilVfsReadFile_FromPBYTE(_In_ PBYTE pbFile, _In_ ULONG64 cbFile, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
NTSTATUS VMMDLL_UtilVfsReadFile_FromQWORD(_In_ ULONG64 qwValue, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix);
NTSTATUS VMMDLL_UtilVfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix);
NTSTATUS VMMDLL_UtilVfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
NTSTATUS VMMDLL_UtilVfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
NTSTATUS VMMDLL_UtilVfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset, _In_ DWORD dwMinAllow);


//-----------------------------------------------------------------------------
// PLUGIN MANAGER FUNCTIONALITY BELOW:
// Function and structures to initialize and use the memory process file system
// plugin functionality. The plugin manager is started by a call to function:
// VMM_VfsInitializePlugins. Each built-in plugin and external plugin of which
// the DLL name matches m_*.dll will receive a call to its InitializeVmmPlugin
// function. The plugin/module may decide to call pfnPluginManager_Register to
// register plugins in the form of different names one or more times.
// Example of registration function in a plugin DLL below: 
// 'VOID InitializeVmmPlugin(_In_ PVMM_PLUGIN_REGINFO pRegInfo)'
//-----------------------------------------------------------------------------

/*
* Initialize all potential plugins, both built-in and external, that maps into
* the memory process file system. Please note that plugins are not loaded by
* default - they have to be explicitly loaded by calling this function. They
* will be unloaded on a general close of the vmm dll.
* -- return
*/
_Success_(return)
BOOL VMMDLL_VfsInitializePlugins();

#define VMMDLL_PLUGIN_CONTEXT_MAGIC             0xc0ffee663df9301c
#define VMMDLL_PLUGIN_CONTEXT_VERSION           3
#define VMMDLL_PLUGIN_REGINFO_MAGIC             0xc0ffee663df9301d
#define VMMDLL_PLUGIN_REGINFO_VERSION           4

#define VMMDLL_PLUGIN_EVENT_VERBOSITYCHANGE     0x01
#define VMMDLL_PLUGIN_EVENT_TOTALREFRESH        0x02

typedef struct tdVMMDLL_PLUGIN_CONTEXT {
    ULONG64 magic;
    WORD wVersion;
    WORD wSize;
    DWORD dwPID;
    PVOID pProcess;
    LPWSTR wszModule;
    LPWSTR wszPath;
    PVOID pvReserved1;
    PVOID pvReserved2;
} VMMDLL_PLUGIN_CONTEXT, *PVMMDLL_PLUGIN_CONTEXT;

typedef struct tdVMMDLL_PLUGIN_REGINFO {
    ULONG64 magic;
    WORD wVersion;
    WORD wSize;
    VMMDLL_MEMORYMODEL_TP tpMemoryModel;
    VMMDLL_SYSTEM_TP tpSystem;
    HMODULE hDLL;
    HMODULE hReservedDllPython3X;   // not for general use (only used for python).
    BOOL(*pfnPluginManager_Register)(struct tdVMMDLL_PLUGIN_REGINFO *pPluginRegInfo);
    HMODULE hReservedDllPython3;   // not for general use (only used for python).
    PVOID pvReserved2;
    // general plugin registration info to be filled out by the plugin below:
    struct {
        WCHAR wszModuleName[32];
        BOOL fRootModule;
        BOOL fProcessModule;
        PVOID pvReserved1;
        PVOID pvReserved2;
    } reg_info;
    // function plugin registration info to be filled out by the plugin below:
    struct {
        BOOL(*pfnList)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Inout_ PHANDLE pFileList);
        NTSTATUS(*pfnRead)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead,  _In_ ULONG64 cbOffset);
        NTSTATUS(*pfnWrite)(_In_ PVMMDLL_PLUGIN_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
        VOID(*pfnNotify)(_In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent);
        VOID(*pfnClose)();
        PVOID pvReserved1;
        PVOID pvReserved2;
    } reg_fn;
} VMMDLL_PLUGIN_REGINFO, *PVMMDLL_PLUGIN_REGINFO;

//-----------------------------------------------------------------------------
// VMM CORE FUNCTIONALITY BELOW:
// Vmm core functaionlity such as read (and write) to both virtual and physical
// memory. NB! writing will only work if the target is supported - i.e. not a
// memory dump file...
// To read physical memory specify dwPID as (DWORD)-1
//-----------------------------------------------------------------------------

// FLAG used to supress the default read cache in calls to VMM_MemReadEx()
// which will lead to the read being fetched from the target system always.
// Cached page tables (used for translating virtual2physical) are still used.
#define VMMDLL_FLAG_NOCACHE                        0x0001  // do not use the data cache (force reading from memory acquisition device)
#define VMMDLL_FLAG_ZEROPAD_ON_FAIL                0x0002  // zero pad failed physical memory reads and report success if read within range of physical memory.
#define VMMDLL_FLAG_FORCECACHE_READ                0x0008  // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
#define VMMDLL_FLAG_NOPAGING                       0x0010  // do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible)

/*
* Read memory in various non-contigious locations specified by the pointers to
* the items in the ppDMAs array. Result for each unit of work will be given
* individually. No upper limit of number of items to read, but no performance
* boost will be given if above hardware limit. Max size of each unit of work is
* one 4k page (4096 bytes).
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- ppMEMs = array of scatter read headers.
* -- cpMEMs = count of ppDMAs.
* -- pcpDMAsRead = optional count of number of successfully read ppDMAs.
* -- flags = optional flags as given by VMMDLL_FLAG_*
* -- return = the number of successfully read items.
*/
DWORD VMMDLL_MemReadScatter(_In_ DWORD dwPID, _Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags);

/*
* Read a single 4096-byte page of memory.
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- qwA
* -- pbPage
* -- return = success/fail (depending if all requested bytes are read or not).
*/
_Success_(return)
BOOL VMMDLL_MemReadPage(_In_ DWORD dwPID, _In_ ULONG64 qwA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Read a contigious arbitrary amount of memory.
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- qwA
* -- pb
* -- cb
* -- return = success/fail (depending if all requested bytes are read or not).
*/
_Success_(return)
BOOL VMMDLL_MemRead(_In_ DWORD dwPID, _In_ ULONG64 qwA, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Read a contigious amount of memory and report the number of bytes read in pcbRead.
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- qwA
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMMDLL_FLAG_*
* -- return = success/fail. NB! reads may report as success even if 0 bytes are
*        read - it's recommended to verify pcbReadOpt parameter.
*/
_Success_(return)
BOOL VMMDLL_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags);

/*
* Prefetch a number of addresses (specified in the pA array) into the memory
* cache. This function is to be used to batch larger known reads into local
* cache before making multiple smaller reads - which will then happen from
* the cache. Function exists for performance reasons.
* -- dwPID = PID of target process, (DWORD)-1 for physical memory.
* -- pPrefetchAddresses = array of addresses to read into cache.
* -- cPrefetchAddresses
*/
_Success_(return)
BOOL VMMDLL_MemPrefetchPages(_In_ DWORD dwPID, _In_reads_(cPrefetchAddresses) PULONG64 pPrefetchAddresses, _In_ DWORD cPrefetchAddresses);

/*
* Write a contigious arbitrary amount of memory. Please note some virtual memory
* such as pages of executables (such as DLLs) may be shared between different
* virtual memory over different processes. As an example a write to kernel32.dll
* in one process is likely to affect kernel32 in the whole system - in all
* processes. Heaps and Stacks and other memory are usually safe to write to.
* Please take care when writing to memory!
* -- dwPID = PID of target process, (DWORD)-1 to read physical memory.
* -- qwA
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
_Success_(return)
BOOL VMMDLL_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwA, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Translate a virtual address to a physical address by walking the page tables
* of the specified process.
* -- dwPID
* -- qwVA
* -- pqwPA
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_MemVirt2Phys(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA);



//-----------------------------------------------------------------------------
// VMM PROCESS FUNCTIONALITY BELOW:
// Functionality below is mostly relating to Windows processes.
//-----------------------------------------------------------------------------

/*
* Retrieve an active process given it's name. Please note that if multiple
* processes with the same name exists only one will be returned. If required to
* parse all processes with the same name please iterate over the PID list by
* calling VMMDLL_PidList together with VMMDLL_ProcessGetInformation.
* -- szProcName = process name case insensitive.
* -- pdwPID = pointer that will receive PID on success.
* -- return
*/
_Success_(return)
BOOL VMMDLL_PidGetFromName(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID);

/*
* List the PIDs in the system.
* -- pPIDs = DWORD array of at least number of PIDs in system, or NULL.
* -- pcPIDs = size of (in number of DWORDs) pPIDs array on entry, number of PIDs in system on exit.
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_PidList(_Out_opt_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs);

// flags to check for existence in the fPage field of PCILEECH_VMM_MEMMAP_ENTRY
#define VMMDLL_MEMMAP_FLAG_PAGE_W          0x0000000000000002
#define VMMDLL_MEMMAP_FLAG_PAGE_NS         0x0000000000000004
#define VMMDLL_MEMMAP_FLAG_PAGE_NX         0x8000000000000000
#define VMMDLL_MEMMAP_FLAG_PAGE_MASK       0x8000000000000006

typedef struct tdVMMDLL_MEMMAP_ENTRY {
    ULONG64 AddrBase;
    ULONG64 cPages;
    ULONG64 fPage;
    BOOL  fWoW64;
    CHAR  szTag[32];
} VMMDLL_MEMMAP_ENTRY, *PVMMDLL_MEMMAP_ENTRY;

/*
* Retrieve memory map entries from the specified process. Memory map entries
* are copied into the user supplied buffer that must be at least of size:
* sizeof(VMMDLL_MEMMAP_ENTRY)*pcMemMapEntries bytes.
* If the pMemMapEntries is set to NULL the number of memory map entries will be
* given in the pcMemMapEntries parameter.
* -- dwPID
* -- pMemMapEntries = buffer of minimum length sizeof(VMMDLL_MEMMAP_ENTRY)*pcMemMapEntries, or NULL.
* -- pcMemMapEntries = pointer to number of memory map entries.
* -- fIdentifyModules = try identify modules as well (= slower)
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_ProcessGetMemoryMap(_In_ DWORD dwPID, _Out_opt_ PVMMDLL_MEMMAP_ENTRY pMemMapEntries, _Inout_ PULONG64 pcMemMapEntries, _In_ BOOL fIdentifyModules);

/*
* Retrieve a single memory map entry given a virtual address within that entrys
* range.
* -- dwPID
* -- pMemMapEntry
* -- va = virtual address in the memory map entry to retrieve.
* -- fIdentifyModules = try identify modules as well (= slower)
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_ProcessGetMemoryMapEntry(_In_ DWORD dwPID, _Out_ PVMMDLL_MEMMAP_ENTRY pMemMapEntry, _In_ ULONG64 va, _In_ BOOL fIdentifyModules);

typedef struct tdVMMDLL_MODULEMAP_ENTRY {
    ULONG64 BaseAddress;
    ULONG64 EntryPoint;
    DWORD SizeOfImage;
    BOOL  fWoW64;
    CHAR  szName[32];
} VMMDLL_MODULEMAP_ENTRY, *PVMMDLL_MODULEMAP_ENTRY;

/*
* Retrieve the module entries from the specified process. The module entries
* are copied into the user supplied buffer that must be at least of size:
* sizeof(VMMDLL_MODULEMAP_ENTRY)*pcModuleEntries bytes long. If the
* pcModuleEntries is set to NULL the number of module entries will be given
* in the pcModuleEntries parameter.
* -- dwPID
* -- pModuleEntries = buffer of minimum length sizeof(VMMDLL_MODULEMAP_ENTRY)*pcModuleEntries, or NULL.
* -- pcModuleEntries = pointer to number of memory map entries.
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_ProcessGetModuleMap(_In_ DWORD dwPID, _Out_opt_ PVMMDLL_MODULEMAP_ENTRY pModuleEntries, _Inout_ PULONG64 pcModuleEntries);

/*
* Retrieve a module (.exe or .dll or similar) given a module name.
* -- dwPID
* -- szModuleName
* -- pModuleEntry
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_ProcessGetModuleFromName(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _Out_ PVMMDLL_MODULEMAP_ENTRY pModuleEntry);

#define VMMDLL_PROCESS_INFORMATION_MAGIC        0xc0ffee663df9301e
#define VMMDLL_PROCESS_INFORMATION_VERSION      4

typedef struct tdVMMDLL_PROCESS_INFORMATION {
    ULONG64 magic;
    WORD wVersion;
    WORD wSize;
    VMMDLL_MEMORYMODEL_TP tpMemoryModel;    // as given by VMMDLL_MEMORYMODEL_* enum
    VMMDLL_SYSTEM_TP tpSystem;              // as given by VMMDLL_SYSTEM_* enum
    BOOL fUserOnly;                         // only user mode pages listed
    DWORD dwPID;
    DWORD dwPPID;
    DWORD dwState;
    CHAR szName[16];
    CHAR szNameLong[64];
    ULONG64 paDTB;
    ULONG64 paDTB_UserOpt;                  // may not exist
    union {
        struct {
            ULONG64 vaEPROCESS;
            ULONG64 vaPEB;
            ULONG64 vaENTRY;
            BOOL fWow64;
            DWORD vaPEB32;                  // WoW64 only
        } win;
    } os;
} VMMDLL_PROCESS_INFORMATION, *PVMMDLL_PROCESS_INFORMATION;

/*
* Retrieve various process information from a PID. Process information such as
* name, page directory bases and the process state may be retrieved.
* -- dwPID
* -- pProcessInformation = if null, size is given in *pcbProcessInfo
* -- pcbProcessInformation = size of pProcessInfo (in bytes) on entry and exit
* -- return = success/fail.
*/
_Success_(return)
BOOL VMMDLL_ProcessGetInformation(_In_ DWORD dwPID, _Inout_opt_ PVMMDLL_PROCESS_INFORMATION pProcessInformation, _In_ PSIZE_T pcbProcessInformation);

#define VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL           1
#define VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE       2
#define VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE               3

/*
* Retrieve a string value belonging to a process. The function allocates a new
* string buffer and returns the requested string in it. The string is always
* NULL terminated. On failure NULL is returned.
* NB! CALLER IS RESPONSIBLE FOR VMMDLL_MemFree return value!
* CALLER FREE: VMMDLL_MemFree(return)
* -- dwPID
* -- fOptionString = string value to retrieve as given by VMMDLL_PROCESS_INFORMATION_OPT_STRING_*
* -- return - fail: NULL, success: the string - NB! must be VMMDLL_MemFree'd by caller!
*/
LPSTR VMMDLL_ProcessGetInformationString(_In_ DWORD dwPID, _In_ DWORD fOptionString);

typedef struct tdVMMDLL_EAT_ENTRY {
    ULONG64 vaFunction;
    DWORD vaFunctionOffset;
    CHAR szFunction[40];
} VMMDLL_EAT_ENTRY, *PVMMDLL_EAT_ENTRY;

typedef struct tdVMMDLL_IAT_ENTRY {
    ULONG64 vaFunction;
    CHAR szFunction[40];
    CHAR szModule[64];
} VMMDLL_IAT_ENTRY, *PVMMDLL_IAT_ENTRY;

/*
* Retrieve information about: Data Directories, Sections, Export Address Table
* and Import Address Table (IAT).
* If the pData == NULL upon entry the number of entries of the pData array must
* have in order to be able to hold the data is returned.
* -- dwPID
* -- szModule
* -- pData
* -- cData
* -- pcData
* -- return = success/fail.
*/
_Success_(return) 
BOOL VMMDLL_ProcessGetDirectories(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_writes_(16) PIMAGE_DATA_DIRECTORY pData, _In_ DWORD cData, _Out_ PDWORD pcData);
_Success_(return)
BOOL VMMDLL_ProcessGetSections(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData);
_Success_(return)
BOOL VMMDLL_ProcessGetEAT(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_opt_ PVMMDLL_EAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData);
_Success_(return)
BOOL VMMDLL_ProcessGetIAT(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_opt_ PVMMDLL_IAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData);

/*
* Retrieve the virtual address of a given function inside a process/module.
* -- dwPID
* -- szModuleName
* -- szFunctionName
* -- return = virtual address of function, zero on fail.
*/
ULONG64 VMMDLL_ProcessGetProcAddress(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szFunctionName);

/*
* Retrieve the base address of a given module.
* -- dwPID
* -- szModuleName
* -- return = virtual address of module base, zero on fail.
*/
ULONG64 VMMDLL_ProcessGetModuleBase(_In_ DWORD dwPID, _In_ LPSTR szModuleName);



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Retrieve a symbol virtual address given a module name and a symbol name.
* NB! not all modules may exist - initially only module "nt" is available.
* NB! if multiple modules have the same name the 1st to be added will be used.
* -- szModule
* -- szSymbolName
* -- pvaSymbolAddress
* -- return
*/
_Success_(return)
BOOL VMMDLL_PdbSymbolAddress(_In_ LPSTR szModule, _In_ LPSTR szSymbolName, _Out_ PULONG64 pvaSymbolAddress);

/*
* Retrieve a type size given a module name and a type name.
* NB! not all modules may exist - initially only module "nt" is available.
* NB! if multiple modules have the same name the 1st to be added will be used.
* -- szModule
* -- szTypeName
* -- pcbTypeSize
* -- return
*/
_Success_(return)
BOOL VMMDLL_PdbTypeSize(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _Out_ PDWORD pcbTypeSize);

/*
* Locate the offset of a type child - typically a sub-item inside a struct.
* NB! not all modules may exist - initially only module "nt" is available.
* NB! if multiple modules have the same name the 1st to be added will be used.
* -- szModule
* -- szTypeName
* -- wszTypeChildName
* -- pcbTypeChildOffset
* -- return
*/
_Success_(return)
BOOL VMMDLL_PdbTypeChildOffset(_In_ LPSTR szModule, _In_ LPSTR szTypeName, _In_ LPWSTR wszTypeChildName, _Out_ PDWORD pcbTypeChildOffset);



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC REGISTRY FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#define VMMDLL_REGISTRY_HIVE_INFORMATION_MAGIC      0xc0ffee653df8d01e
#define VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION    1

typedef struct td_VMMDLL_REGISTRY_HIVE_INFORMATION {
    ULONG64 magic;
    WORD wVersion;
    WORD wSize;
    BYTE _FutureReserved1[0x14];
    ULONG64 vaCMHIVE;
    ULONG64 vaHBASE_BLOCK;
    DWORD cbLength;
    CHAR szName[136 + 1];
    WCHAR wszNameShort[32 + 1];
    WCHAR wszHiveRootPath[MAX_PATH];
    ULONG64 _FutureReserved2[0x10];
} VMMDLL_REGISTRY_HIVE_INFORMATION, *PVMMDLL_REGISTRY_HIVE_INFORMATION;

/*
* Retrieve information about the registry hives in the target system.
* -- pHives = buffer of cHives * sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION) to receive information about all hives. NULL to receive # hives in pcHives.
* -- cHives
* -- pcHives = if pHives == NULL: # total hives. if pHives: # read hives.
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinReg_HiveList(_Out_writes_(cHives) PVMMDLL_REGISTRY_HIVE_INFORMATION pHives, _In_ DWORD cHives, _Out_ PDWORD pcHives);

/*
* Read a contigious arbitrary amount of registry hive memory and report the
* number of bytes read in pcbRead.
* NB! Address space does not include regf registry hive file header!
* -- vaCMHive
* -- ra
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMMDLL_FLAG_*
* -- return = success/fail. NB! reads may report as success even if 0 bytes are
*        read - it's recommended to verify pcbReadOpt parameter.
*/
_Success_(return)
BOOL VMMDLL_WinReg_HiveReadEx(_In_ ULONG64 vaCMHive, _In_ DWORD ra, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags);

/*
* Write a virtually contigious arbitrary amount of memory to a registry hive.
* NB! Address space does not include regf registry hive file header!
* -- vaCMHive
* -- ra
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
_Success_(return)
BOOL VMMDLL_WinReg_HiveWrite(_In_ ULONG64 vaCMHive, _In_ DWORD ra, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Enumerate registry sub keys - similar to WINAPI function 'RegEnumKeyExW.'
* Please consult WINAPI function documentation for information.
* May be called with HKLM base or virtual address of CMHIVE base examples:
*   1) 'HKLM\SOFTWARE\Key\SubKey'
*   2) 'HKLM\ORPHAN\SAM\Key\SubKey'              (orphan key)
*   3) '0x<vaCMHIVE>\ROOT\Key\SubKey'
*   4) '0x<vaCMHIVE>\ORPHAN\Key\SubKey'          (orphan key)
* -- wszFullPathKey
* -- dwIndex
* -- lpName
* -- lpcchName
* -- lpftLastWriteTime
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinReg_EnumKeyExW(
    _In_ LPWSTR wszFullPathKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(*lpcchName) LPWSTR lpName,
    _Inout_ LPDWORD lpcchName,
    _Out_opt_ PFILETIME lpftLastWriteTime
);

/*
* Enumerate registry values given a registry key - similar to WINAPI function
* 'EnumValueW'. Please consult WINAPI function documentation for information.
* May be called in two ways:
* May be called with HKLM base or virtual address of CMHIVE base examples:
*   1) 'HKLM\SOFTWARE\Key\SubKey'
*   2) 'HKLM\ORPHAN\SAM\Key\SubKey'              (orphan key)
*   3) '0x<vaCMHIVE>\ROOT\Key\SubKey'
*   4) '0x<vaCMHIVE>\ORPHAN\Key\SubKey'          (orphan key)
* -- wszFullPathKey
* -- dwIndex
* -- lpValueName
* -- lpcchValueName
* -- lpType
* -- lpData
* -- lpcbData
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinReg_EnumValueW(
    _In_ LPWSTR wszFullPathKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(*lpcchValueName) LPWSTR lpValueName,
    _Inout_ LPDWORD lpcchValueName,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_opt_(*lpcbData) LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData
);

/*
* Query a registry value given a registry key/value path - similar to WINAPI
* function 'RegQueryValueEx'.
* Please consult WINAPI function documentation for information.
* May be called with HKLM base or virtual address of CMHIVE base examples:
*   1) 'HKLM\SOFTWARE\Key\SubKey\Value'
*   2) 'HKLM\ORPHAN\SAM\Key\SubKey\'             (orphan key and default value)
*   3) '0x<vaCMHIVE>\ROOT\Key\SubKey\Value'
*   4) '0x<vaCMHIVE>\ORPHAN\Key\SubKey\Value'    (orphan key value)
* -- wszFullPathKeyValue
* -- lpType
* -- lpData
* -- lpcbData
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinReg_QueryValueExW(
    _In_ LPWSTR wszFullPathKeyValue,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_opt_(*lpcbData) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
);



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC NETWORKING FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#define VMMDLL_WIN_TCPIP_MAGIC        0xc0ffee663df93685
#define VMMDLL_WIN_TCPIP_VERSION      1

typedef struct tdVMMDLL_WIN_TCPIP_ENTRY {   // SHARED WITH VMMWINTCPIP
    DWORD dwPID;
    DWORD dwState;
    CHAR szState[12];
    struct {    // address family (IPv4/IPv6)
        BOOL fValid;
        WORD wAF;
    } AF;
    struct {
        BOOL fValid;
        WORD wPort;
        BYTE pbA[16];   // ipv4 = 1st 4 bytes, ipv6 = all bytes
    } Src;
    struct {
        BOOL fValid;
        WORD wPort;
        BYTE pbA[16];   // ipv4 = 1st 4 bytes, ipv6 = all bytes
    } Dst;
    QWORD vaTcpE;
    QWORD qwTime;
    QWORD vaEPROCESS;
    QWORD _Reserved[2];
} VMMDLL_WIN_TCPIP_ENTRY, *PVMMDLL_WIN_TCPIP_ENTRY;

typedef struct tdVMMDLL_WIN_TCPIP {
    QWORD magic;
    DWORD dwVersion;
    DWORD cTcpE;
    VMMDLL_WIN_TCPIP_ENTRY pTcpE[];
} VMMDLL_WIN_TCPIP, *PVMMDLL_WIN_TCPIP;

/*
* Retrieve networking information about network connections related to Windows TCP/IP stack.
* NB! CALLER IS RESPONSIBLE FOR VMMDLL_MemFree return value!
* CALLER FREE: VMMDLL_MemFree(return)
* -- return - fail: NULL, success: a PVMMDLL_WIN_TCPIP struct scontaining the result - NB! Caller responsible for VMMDLL_MemFree!
*/
PVMMDLL_WIN_TCPIP VMMDLL_WinNet_Get();



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC UTILITY FUNCTIONS BELOW:
//-----------------------------------------------------------------------------

typedef struct tdVMMDLL_WIN_THUNKINFO_IAT {
    BOOL fValid;
    BOOL f32;               // if TRUE fn is a 32-bit/4-byte entry, otherwise 64-bit/8-byte entry.
    ULONG64 vaThunk;        // address of import address table 'thunk'.
    ULONG64 vaFunction;     // value if import address table 'thunk' == address of imported function.
    ULONG64 vaNameModule;   // address of name string for imported module.
    ULONG64 vaNameFunction; // address of name string for imported function.
} VMMDLL_WIN_THUNKINFO_IAT, *PVMMDLL_WIN_THUNKINFO_IAT;

typedef struct tdVMMDLL_WIN_THUNKINFO_EAT {
    BOOL fValid;
    DWORD valueThunk;       // value of export address table 'thunk'.
    ULONG64 vaThunk;        // address of import address table 'thunk'.
    ULONG64 vaNameFunction; // address of name string for exported function.
    ULONG64 vaFunction;     // address of exported function (module base + value parameter).
} VMMDLL_WIN_THUNKINFO_EAT, *PVMMDLL_WIN_THUNKINFO_EAT;

/*
* Retrieve information about the import address table IAT thunk for an imported
* function. This includes the virtual address of the IAT thunk which is useful
* for hooking.
* -- dwPID
* -- szModuleName
* -- szImportModuleName
* -- szImportFunctionName
* -- pThunkIAT
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinGetThunkInfoIAT(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT);

/*
* Retrieve information about the export address table EAT thunk for an exported
* function. This includes the virtual address of the EAT thunk which is useful
* for hooking.
* -- dwPID
* -- szModuleName
* -- pThunkEAT
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinGetThunkInfoEAT(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szExportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_EAT pThunkInfoEAT);



//-----------------------------------------------------------------------------
// VMM UTIL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Fill a human readable hex ascii memory dump into the caller supplied sz buffer.
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
* -- sz = buffer to fill, NULL to retrieve buffer size in pcsz parameter.
* -- pcsz = IF sz==NULL :: size of buffer (including space for terminating NULL) on exit
*           IF sz!=NULL :: size of buffer on entry, size of characters (excluding terminating NULL) on exit.
*/
_Success_(return)
BOOL VMMDLL_UtilFillHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset, _Out_opt_ LPSTR sz, _Inout_ PDWORD pcsz);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __VMMDLL_H__ */
