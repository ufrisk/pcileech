// vmmdll.h : header file to include in projects that use vmm.dll / vmm.so
// 
// Please also consult the guide at: https://github.com/ufrisk/MemProcFS/wiki
// 
// U/W functions
// =============
// Windows may access both UTF-8 *U and Wide-Char *W versions of functions
// while Linux may only access UTF-8 versions. Some functionality may also
// be degraded or unavailable on Linux.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
// Header Version: 5.14
//

#include "leechcore.h"

#ifndef __VMMDLL_H__
#define __VMMDLL_H__
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef _WIN32

#include <Windows.h>
#undef EXPORTED_FUNCTION
#define EXPORTED_FUNCTION
typedef unsigned __int64                    QWORD, *PQWORD;

#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#undef EXPORTED_FUNCTION
#define EXPORTED_FUNCTION                   __attribute__((visibility("default")))
typedef void                                VOID, *PVOID, *HANDLE, **PHANDLE, *HMODULE;
typedef long long unsigned int              QWORD, *PQWORD, ULONG64, *PULONG64;
typedef size_t                              SIZE_T, *PSIZE_T;
typedef uint64_t                            FILETIME, *PFILETIME;
typedef uint32_t                            DWORD, *PDWORD, *LPDWORD, BOOL, *PBOOL, NTSTATUS;
typedef uint16_t                            WORD, *PWORD;
typedef uint8_t                             BYTE, *PBYTE, *LPBYTE, UCHAR;
typedef char                                CHAR, *PCHAR, *LPSTR;
typedef const char                          *LPCSTR;
typedef uint16_t                            WCHAR, *PWCHAR, *LPWSTR;
typedef const uint16_t                      *LPCWSTR;
#define MAX_PATH                            260
#define _In_
#define _In_z_
#define _In_opt_
#define _In_reads_(x)
#define _In_reads_bytes_(x)
#define _In_reads_opt_(x)
#define _Inout_
#define _Inout_bytecount_(x)
#define _Inout_opt_
#define _Inout_updates_opt_(x)
#define _Out_
#define _Out_opt_
#define _Out_writes_(x)
#define _Out_writes_bytes_opt_(x)
#define _Out_writes_opt_(x)
#define _Out_writes_to_(x,y)
#define _When_(x,y)
#define _Frees_ptr_opt_
#define _Post_ptr_invalid_
#define _Check_return_opt_
#define _Printf_format_string_
#define _Success_(x)

#endif /* LINUX || MACOS */

typedef struct tdVMM_HANDLE     *VMM_HANDLE;
typedef struct tdVMMVM_HANDLE   *VMMVM_HANDLE;
typedef BYTE                    OPAQUE_OB_HEADER[0x40];



//-----------------------------------------------------------------------------
// INITIALIZATION FUNCTIONALITY BELOW:
// Choose one way of initializing the VMM / MemProcFS.
//-----------------------------------------------------------------------------

/*
* Initialize VMM.DLL with command line parameters. For a more detailed info
* about the parameters please see github wiki for MemProcFS and LeechCore.
* NB! LeechCore initialization parameters are _also_ valid to this function.
* Important parameters are:
*    -printf = show printf style outputs.
*    -v -vv -vvv = extra verbosity levels.
*    -device = device as on format for LeechCore - please see leechcore.h or
*              Github documentation for additional information. Some values
*              are: <file>, fpga, usb3380, hvsavedstate, totalmeltdown, pmem
*    -remote = remote LeechCore instance - please see leechcore.h or Github
*              documentation for additional information.
*    -norefresh = disable background refreshes (even if backing memory is
*              volatile memory).
*    -memmap = specify a physical memory map given by file or specify 'auto'.
*              example: -memmap c:\\temp\\my_custom_memory_map.txt
*              example: -memmap auto
*    -pagefile[0-9] = page file(s) to use in addition to physical memory.
*              Normally pagefile.sys have index 0 and swapfile.sys index 1.
*              Page files are in constant flux - do not use if time diff
*              between memory dump and page files are more than few minutes.
*              Example: 'pagefile0 swapfile.sys'
*    -disable-python = prevent the python plugin sub-system from loading.
*    -disable-symbolserver = disable symbol server until user change.
*              This parameter will take precedence over registry settings.
*    -disable-symbols = disable symbol lookups from .pdb files.
*    -disable-infodb = disable the infodb and any symbol lookups via it.
*    -waitinitialize = Wait for initialization to complete before returning.
*              Normal use is that some initialization is done asynchronously
*              and may not be completed when initialization call is completed.
*              This includes virtual memory compression, registry and more.
*              Example: '-waitinitialize'
*    -userinteract = allow vmm.dll to, on the console, query the user for
*              information such as, but not limited to, leechcore device options.
*              Default: user interaction = disabled.
*    -vm       = virtual machine (VM) parsing.
*    -vm-basic = virtual machine (VM) parsing (physical memory only).
*    -vm-nested = virtual machine (VM) parsing (including nested VMs).
*    -forensic-yara-rules = perfom a forensic yara scan with specified rules.
*              Full path to source or compiled yara rules should be specified.
*              Example: -forensic-yara-rules "C:\Temp\my_yara_rules.yar"
*    -forensic = start a forensic scan of the physical memory immediately after
*              startup if possible. Allowed parameter values range from 0-4.
*              Note! forensic mode is not available for live memory.
*              1 = forensic mode with in-memory sqlite database.
*              2 = forensic mode with temp sqlite database deleted upon exit.
*              3 = forensic mode with temp sqlite database remaining upon exit.
*              4 = forensic mode with static named sqlite database (vmm.sqlite3).
*              Example -forensic 4
*
* -- argc
* -- argv
* -- ppLcErrorInfo = optional pointer to receive a function allocated memory of
*              struct LC_CONFIG_ERRORINFO with extended error information upon
*              failure. Any memory received should be free'd by caller by
*              calling LcMemFree().
* -- return = VMM_HANDLE on success for usage in subsequent API calls. NULL=fail.
*/
EXPORTED_FUNCTION _Success_(return != NULL)
VMM_HANDLE VMMDLL_Initialize(_In_ DWORD argc, _In_ LPCSTR argv[]);

EXPORTED_FUNCTION _Success_(return != NULL)
VMM_HANDLE VMMDLL_InitializeEx(_In_ DWORD argc, _In_ LPCSTR argv[], _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcErrorInfo);

/*
* Close an instantiated version of VMM_HANDLE and free up any resources.
* -- hVMM
*/
EXPORTED_FUNCTION
VOID VMMDLL_Close(_In_opt_ _Post_ptr_invalid_ VMM_HANDLE hVMM);

/*
* Close all instantiated versions of VMM_HANDLE and free up all resources.
*/
EXPORTED_FUNCTION
VOID VMMDLL_CloseAll();

/*
* Query the size of memory allocated by the VMMDLL.
* -- pvMem
* -- return = number of bytes required to hold memory allocation.
*/
EXPORTED_FUNCTION _Success_(return != 0)
SIZE_T VMMDLL_MemSize(_In_ PVOID pvMem);

/*
* Free memory allocated by the VMMDLL.
* -- pvMem
*/
EXPORTED_FUNCTION
VOID VMMDLL_MemFree(_Frees_ptr_opt_ PVOID pvMem);



//-----------------------------------------------------------------------------
// CONFIGURATION SETTINGS BELOW:
// Configure MemProcFS or the underlying memory
// acquisition devices.
//-----------------------------------------------------------------------------

/*
* Options used together with the functions: VMMDLL_ConfigGet & VMMDLL_ConfigSet
* Options are defined with either: VMMDLL_OPT_* in this header file or as
* LC_OPT_* in leechcore.h
* For more detailed information check the sources for individual device types.
*/
#define VMMDLL_OPT_CORE_PRINTF_ENABLE                   0x4000000100000000  // RW
#define VMMDLL_OPT_CORE_VERBOSE                         0x4000000200000000  // RW
#define VMMDLL_OPT_CORE_VERBOSE_EXTRA                   0x4000000300000000  // RW
#define VMMDLL_OPT_CORE_VERBOSE_EXTRA_TLP               0x4000000400000000  // RW
#define VMMDLL_OPT_CORE_MAX_NATIVE_ADDRESS              0x4000000800000000  // R
#define VMMDLL_OPT_CORE_LEECHCORE_HANDLE                0x4000001000000000  // R - underlying leechcore handle (do not close).
#define VMMDLL_OPT_CORE_VMM_ID                          0x4000002000000000  // R - use with startup option '-create-from-vmmid' to create a thread-safe duplicate VMM instance.

#define VMMDLL_OPT_CORE_SYSTEM                          0x2000000100000000  // R
#define VMMDLL_OPT_CORE_MEMORYMODEL                     0x2000000200000000  // R

#define VMMDLL_OPT_CONFIG_IS_REFRESH_ENABLED            0x2000000300000000  // R - 1/0
#define VMMDLL_OPT_CONFIG_TICK_PERIOD                   0x2000000400000000  // RW - base tick period in ms
#define VMMDLL_OPT_CONFIG_READCACHE_TICKS               0x2000000500000000  // RW - memory cache validity period (in ticks)
#define VMMDLL_OPT_CONFIG_TLBCACHE_TICKS                0x2000000600000000  // RW - page table (tlb) cache validity period (in ticks)
#define VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_PARTIAL       0x2000000700000000  // RW - process refresh (partial) period (in ticks)
#define VMMDLL_OPT_CONFIG_PROCCACHE_TICKS_TOTAL         0x2000000800000000  // RW - process refresh (full) period (in ticks)
#define VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR             0x2000000900000000  // R
#define VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR             0x2000000A00000000  // R
#define VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION          0x2000000B00000000  // R
#define VMMDLL_OPT_CONFIG_STATISTICS_FUNCTIONCALL       0x2000000C00000000  // RW - enable function call statistics (.status/statistics_fncall file)
#define VMMDLL_OPT_CONFIG_IS_PAGING_ENABLED             0x2000000D00000000  // RW - 1/0
#define VMMDLL_OPT_CONFIG_DEBUG                         0x2000000E00000000  // W
#define VMMDLL_OPT_CONFIG_YARA_RULES                    0x2000000F00000000  // R

#define VMMDLL_OPT_WIN_VERSION_MAJOR                    0x2000010100000000  // R
#define VMMDLL_OPT_WIN_VERSION_MINOR                    0x2000010200000000  // R
#define VMMDLL_OPT_WIN_VERSION_BUILD                    0x2000010300000000  // R
#define VMMDLL_OPT_WIN_SYSTEM_UNIQUE_ID                 0x2000010400000000  // R

#define VMMDLL_OPT_FORENSIC_MODE                        0x2000020100000000  // RW - enable/retrieve forensic mode type [0-4].

// REFRESH OPTIONS:
#define VMMDLL_OPT_REFRESH_ALL                          0x2001ffff00000000  // W - refresh all caches
#define VMMDLL_OPT_REFRESH_FREQ_MEM                     0x2001100000000000  // W - refresh memory cache (excl. TLB) [fully]
#define VMMDLL_OPT_REFRESH_FREQ_MEM_PARTIAL             0x2001000200000000  // W - refresh memory cache (excl. TLB) [partial 33%/call]
#define VMMDLL_OPT_REFRESH_FREQ_TLB                     0x2001080000000000  // W - refresh page table (TLB) cache [fully]
#define VMMDLL_OPT_REFRESH_FREQ_TLB_PARTIAL             0x2001000400000000  // W - refresh page table (TLB) cache [partial 33%/call]
#define VMMDLL_OPT_REFRESH_FREQ_FAST                    0x2001040000000000  // W - refresh fast frequency - incl. partial process refresh
#define VMMDLL_OPT_REFRESH_FREQ_MEDIUM                  0x2001000100000000  // W - refresh medium frequency - incl. full process refresh
#define VMMDLL_OPT_REFRESH_FREQ_SLOW                    0x2001001000000000  // W - refresh slow frequency.

// PROCESS OPTIONS: [LO-DWORD: Process PID]
#define VMMDLL_OPT_PROCESS_DTB                          0x2002000100000000  // W - force set process directory table base.
#define VMMDLL_OPT_PROCESS_DTB_FAST_LOWINTEGRITY        0x2002000200000000  // W - force set process directory table base (fast, low integrity mode, with less checks) - use at own risk!.

static LPCSTR VMMDLL_MEMORYMODEL_TOSTRING[5] = { "N/A", "X86", "X86PAE", "X64", "ARM64" };

typedef enum tdVMMDLL_MEMORYMODEL_TP {
    VMMDLL_MEMORYMODEL_NA       = 0,
    VMMDLL_MEMORYMODEL_X86      = 1,
    VMMDLL_MEMORYMODEL_X86PAE   = 2,
    VMMDLL_MEMORYMODEL_X64      = 3,
    VMMDLL_MEMORYMODEL_ARM64    = 4,
} VMMDLL_MEMORYMODEL_TP;

typedef enum tdVMMDLL_SYSTEM_TP {
    VMMDLL_SYSTEM_UNKNOWN_PHYSICAL = 0,
    VMMDLL_SYSTEM_UNKNOWN_64    = 1,
    VMMDLL_SYSTEM_WINDOWS_64    = 2,
    VMMDLL_SYSTEM_UNKNOWN_32    = 3,
    VMMDLL_SYSTEM_WINDOWS_32    = 4,
    VMMDLL_SYSTEM_UNKNOWN_X64   = 1,    // deprecated - do not use!
    VMMDLL_SYSTEM_WINDOWS_X64   = 2,    // deprecated - do not use!
    VMMDLL_SYSTEM_UNKNOWN_X86   = 3,    // deprecated - do not use!
    VMMDLL_SYSTEM_WINDOWS_X86   = 4     // deprecated - do not use!
} VMMDLL_SYSTEM_TP;

/*
* Get a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- hVMM
* -- fOption
* -- pqwValue = pointer to ULONG64 to receive option value.
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_ConfigGet(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);

/*
* Set a device specific option value. Please see defines VMMDLL_OPT_* for infor-
* mation about valid option values. Please note that option values may overlap
* between different device types with different meanings.
* -- hVMM
* -- fOption
* -- qwValue
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_ConfigSet(_In_ VMM_HANDLE hVMM, _In_ ULONG64 fOption, _In_ ULONG64 qwValue);



//-----------------------------------------------------------------------------
// FORWARD DECLARATIONS:
//-----------------------------------------------------------------------------

typedef struct tdVMMDLL_MAP_PFN *PVMMDLL_MAP_PFN;



//-----------------------------------------------------------------------------
// LINUX SPECIFIC DEFINES:
//-----------------------------------------------------------------------------
#if defined(LINUX) || defined(MACOS)

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _SERVICE_STATUS {
    DWORD   dwServiceType;
    DWORD   dwCurrentState;
    DWORD   dwControlsAccepted;
    DWORD   dwWin32ExitCode;
    DWORD   dwServiceSpecificExitCode;
    DWORD   dwCheckPoint;
    DWORD   dwWaitHint;
} SERVICE_STATUS, *LPSERVICE_STATUS;
#endif /* LINUX || MACOS */



//-----------------------------------------------------------------------------
// VFS - VIRTUAL FILE SYSTEM FUNCTIONALITY BELOW:
// NB! VFS FUNCTIONALITY REQUIRES PLUGINS TO BE INITIALIZED
//     WITH CALL TO VMMDLL_InitializePlugins().
// This is the core of MemProcFS. All implementation and analysis towards
// the virtual file system (vfs) is possible by using functionality below. 
//-----------------------------------------------------------------------------

#define VMMDLL_STATUS_SUCCESS                       ((NTSTATUS)0x00000000L)
#define VMMDLL_STATUS_UNSUCCESSFUL                  ((NTSTATUS)0xC0000001L)
#define VMMDLL_STATUS_END_OF_FILE                   ((NTSTATUS)0xC0000011L)
#define VMMDLL_STATUS_FILE_INVALID                  ((NTSTATUS)0xC0000098L)
#define VMMDLL_STATUS_FILE_SYSTEM_LIMITATION        ((NTSTATUS)0xC0000427L)

#define VMMDLL_VFS_FILELIST_EXINFO_VERSION          1
#define VMMDLL_VFS_FILELIST_VERSION                 2
#define VMMDLL_VFS_FILELISTBLOB_VERSION             0xf88f0001

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

typedef struct tdVMMDLL_VFS_FILELIST2 {
    DWORD dwVersion;
    VOID(*pfnAddFile)     (_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
    VOID(*pfnAddDirectory)(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
    HANDLE h;
} VMMDLL_VFS_FILELIST2, *PVMMDLL_VFS_FILELIST2;

typedef struct tdVMMDLL_VFS_FILELISTBLOB_ENTRY {
    ULONG64 ouszName;                       // byte offset to string from VMMDLL_VFS_FILELISTBLOB.uszMultiText
    ULONG64 cbFileSize;                     // -1 == directory
    VMMDLL_VFS_FILELIST_EXINFO ExInfo;      // optional ExInfo
} VMMDLL_VFS_FILELISTBLOB_ENTRY, *PVMMDLL_VFS_FILELISTBLOB_ENTRY;

typedef struct tdVMMDLL_VFS_FILELISTBLOB {
    DWORD dwVersion;                        // VMMDLL_VFS_FILELISTBLOB_VERSION
    DWORD cbStruct;
    DWORD cFileEntry;
    DWORD cbMultiText;
    union {
        LPSTR uszMultiText;
        QWORD _Reserved;
    };
    DWORD _FutureUse[8];
    VMMDLL_VFS_FILELISTBLOB_ENTRY FileEntry[0];
} VMMDLL_VFS_FILELISTBLOB, *PVMMDLL_VFS_FILELISTBLOB;

/*
* Helper functions for callbacks into the VMM_VFS_FILELIST2 structure.
*/
EXPORTED_FUNCTION
VOID VMMDLL_VfsList_AddFile(_In_ HANDLE pFileList, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
VOID VMMDLL_VfsList_AddFileW(_In_ HANDLE pFileList, _In_ LPCWSTR wszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
EXPORTED_FUNCTION
VOID VMMDLL_VfsList_AddDirectory(_In_ HANDLE pFileList, _In_ LPCSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
VOID VMMDLL_VfsList_AddDirectoryW(_In_ HANDLE pFileList, _In_ LPCWSTR wszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);
EXPORTED_FUNCTION BOOL VMMDLL_VfsList_IsHandleValid(_In_ HANDLE pFileList);

/*
* List a directory of files in MemProcFS. Directories and files will be listed
* by callbacks into functions supplied in the pFileList parameter.
* If information of an individual file is needed it's neccessary to list all
* files in its directory.
* -- hVMM
* -- [uw]szPath
* -- pFileList
* -- return
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_VfsListU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR  uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList);
_Success_(return) BOOL VMMDLL_VfsListW(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList);

/*
* List a directory of files in MemProcFS and return a VMMDLL_VFS_FILELISTBLOB.
* CALLER FREE: VMMDLL_MemFree(return)
* -- hVMM
* -- uszPath
* -- return
*/
EXPORTED_FUNCTION
_Success_(return != NULL) PVMMDLL_VFS_FILELISTBLOB VMMDLL_VfsListBlobU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR uszPath);

/*
* Read select parts of a file in MemProcFS.
* -- hVMM
* -- [uw]szFileName
* -- pb
* -- cb
* -- pcbRead
* -- cbOffset
* -- return
*
*/
EXPORTED_FUNCTION
NTSTATUS VMMDLL_VfsReadU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR  uszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
NTSTATUS VMMDLL_VfsReadW(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszFileName, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);

/*
* Write select parts to a file in MemProcFS.
* -- hVMM
* -- [uw]szFileName
* -- pb
* -- cb
* -- pcbWrite
* -- cbOffset
* -- return
*/
EXPORTED_FUNCTION
NTSTATUS VMMDLL_VfsWriteU(_In_ VMM_HANDLE hVMM, _In_ LPCSTR  uszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
NTSTATUS VMMDLL_VfsWriteW(_In_ VMM_HANDLE hVMM, _In_ LPCWSTR wszFileName, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);

/*
* Utility functions for MemProcFS read/write towards different underlying data
* representations.
*/
EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsReadFile_FromPBYTE(_In_ PBYTE pbFile, _In_ ULONG64 cbFile, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsReadFile_FromQWORD(_In_ ULONG64 qwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix);
EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset, _In_ BOOL fPrefix);
EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ ULONG64 cbOffset);
EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsWriteFile_BOOL(_Inout_ PBOOL pfTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
EXPORTED_FUNCTION NTSTATUS VMMDLL_UtilVfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset, _In_ DWORD dwMinAllow);



//-----------------------------------------------------------------------------
// PLUGIN MANAGER FUNCTIONALITY BELOW:
// Function and structures to initialize and use MemProcFS plugin functionality.
// The plugin manager is started by a call to function:
// VMM_VfsInitializePlugins. Each built-in plugin and external plugin of which
// the DLL name matches m_*.dll will receive a call to its InitializeVmmPlugin
// function. The plugin/module may decide to call pfnPluginManager_Register to
// register plugins in the form of different names one or more times.
// Example of registration function in a plugin DLL below: 
// 'VOID InitializeVmmPlugin(_In_ VMM_HANDLE H, _In_ PVMM_PLUGIN_REGINFO pRegInfo)'
//-----------------------------------------------------------------------------

/*
* Initialize all potential plugins, both built-in and external, that maps into
* MemProcFS. Please note that plugins are not loaded by default - they have to
* be explicitly loaded by calling this function. They will be unloaded on a
* general close of the vmm dll.
* -- hVMM
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_InitializePlugins(_In_ VMM_HANDLE hVMM);

#define VMMDLL_PLUGIN_CONTEXT_MAGIC                 0xc0ffee663df9301c
#define VMMDLL_PLUGIN_CONTEXT_VERSION               5
#define VMMDLL_PLUGIN_REGINFO_MAGIC                 0xc0ffee663df9301d
#define VMMDLL_PLUGIN_REGINFO_VERSION               18
#define VMMDLL_FORENSIC_JSONDATA_VERSION            0xc0ee0002
#define VMMDLL_FORENSIC_INGEST_VIRTMEM_VERSION      0xc0dd0001
#define VMMDLL_FORENSIC_INGEST_OBJECT_VERSION       0xc0de0001

#define VMMDLL_PLUGIN_NOTIFY_VERBOSITYCHANGE        0x01
#define VMMDLL_PLUGIN_NOTIFY_REFRESH_FAST           0x05    // refresh fast event   - at partial process refresh.
#define VMMDLL_PLUGIN_NOTIFY_REFRESH_MEDIUM         0x02    // refresh medium event - at full process refresh.
#define VMMDLL_PLUGIN_NOTIFY_REFRESH_SLOW           0x04    // refresh slow event   - at registry refresh.

#define VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT          0x01000100
#define VMMDLL_PLUGIN_NOTIFY_FORENSIC_INIT_COMPLETE 0x01000200
#define VMMDLL_PLUGIN_NOTIFY_VM_ATTACH_DETACH       0x01000400

typedef DWORD                                       VMMDLL_MODULE_ID;
typedef HANDLE                                      *PVMMDLL_PLUGIN_INTERNAL_CONTEXT;
typedef struct tdVMMDLL_CSV_HANDLE                  *VMMDLL_CSV_HANDLE;

#define VMMDLL_MID_MAIN                             ((VMMDLL_MODULE_ID)0x80000001)
#define VMMDLL_MID_PYTHON                           ((VMMDLL_MODULE_ID)0x80000002)
#define VMMDLL_MID_DEBUG                            ((VMMDLL_MODULE_ID)0x80000003)
#define VMMDLL_MID_RUST                             ((VMMDLL_MODULE_ID)0x80000004)

typedef struct tdVMMDLL_PLUGIN_CONTEXT {
    ULONG64 magic;
    WORD wVersion;
    WORD wSize;
    DWORD dwPID;
    PVOID pProcess;
    LPSTR uszModule;
    LPSTR uszPath;
    PVOID pvReserved1;
    PVMMDLL_PLUGIN_INTERNAL_CONTEXT ctxM;       // optional internal module context.
    VMMDLL_MODULE_ID MID;
} VMMDLL_PLUGIN_CONTEXT, *PVMMDLL_PLUGIN_CONTEXT;

typedef struct tdVMMDLL_FORENSIC_JSONDATA {
    DWORD dwVersion;        // must equal VMMDLL_FORENSIC_JSONDATA_VERSION
    DWORD _FutureUse;
    LPSTR szjType;          // log type/name (json encoded)
    DWORD i;
    DWORD dwPID;
    QWORD vaObj;
    BOOL fva[2];            // log va even if zero
    QWORD va[2];
    BOOL fNum[2];           // log num even if zero
    QWORD qwNum[2];
    BOOL fHex[2];           // log hex even if zero
    QWORD qwHex[2];
    // str: will be prioritized in order: szu > wsz.
    LPCSTR usz[2];          // str: utf-8 encoded
    LPCWSTR wsz[2];         // str: wide
    BYTE _Reserved[0x4000+256];
} VMMDLL_FORENSIC_JSONDATA, *PVMMDLL_FORENSIC_JSONDATA;

typedef enum tdVMMDLL_FORENSIC_INGEST_OBJECT_TYPE {
    VMMDLL_FORENSIC_INGEST_OBJECT_TYPE_FILE = 1,
} VMMDLL_FORENSIC_INGEST_OBJECT_TYPE;

typedef struct tdVMMDLL_FORENSIC_INGEST_OBJECT {
    OPAQUE_OB_HEADER _Reserved;
    DWORD dwVersion;        // must equal VMMDLL_FORENSIC_INGEST_OBJECT_VERSION
    VMMDLL_FORENSIC_INGEST_OBJECT_TYPE tp;
    QWORD vaObject;
    LPSTR uszText;
    PBYTE pb;
    DWORD cb;
    DWORD cbReadActual;     // actual bytes read (may be spread out in pb)
} VMMDLL_FORENSIC_INGEST_OBJECT, *PVMMDLL_FORENSIC_INGEST_OBJECT;

typedef struct tdVMMDLL_FORENSIC_INGEST_PHYSMEM {
    BOOL fValid;
    QWORD pa;
    DWORD cb;
    PBYTE pb;
    DWORD cMEMs;
    PPMEM_SCATTER ppMEMs;
    PVMMDLL_MAP_PFN pPfnMap;
} VMMDLL_FORENSIC_INGEST_PHYSMEM, *PVMMDLL_FORENSIC_INGEST_PHYSMEM;

typedef struct tdVMMDLL_FORENSIC_INGEST_VIRTMEM {
    OPAQUE_OB_HEADER _Reserved;
    DWORD dwVersion;        // must equal VMMDLL_FORENSIC_INGEST_VIRTMEM_VERSION
    BOOL fPte;
    BOOL fVad;
    PVOID pvProcess;
    DWORD dwPID;
    QWORD va;
    PBYTE pb;
    DWORD cb;
    DWORD cbReadActual;     // actual bytes read (may be spread out in pb)
} VMMDLL_FORENSIC_INGEST_VIRTMEM, *PVMMDLL_FORENSIC_INGEST_VIRTMEM;

typedef struct tdVMMDLL_PLUGIN_REGINFO {
    ULONG64 magic;                          // VMMDLL_PLUGIN_REGINFO_MAGIC
    WORD wVersion;                          // VMMDLL_PLUGIN_REGINFO_VERSION
    WORD wSize;                             // size of struct
    VMMDLL_MEMORYMODEL_TP tpMemoryModel;
    VMMDLL_SYSTEM_TP tpSystem;
    HMODULE hDLL;
    BOOL(*pfnPluginManager_Register)(_In_ VMM_HANDLE H, struct tdVMMDLL_PLUGIN_REGINFO *pPluginRegInfo);
    LPSTR uszPathVmmDLL;
    DWORD _Reserved[30];
    // python plugin information - not for general use
    struct {
        BOOL fPythonStandalone;
        DWORD _Reserved;
        HMODULE hReservedDllPython3;
        HMODULE hReservedDllPython3X;
    } python;
    // general plugin registration info to be filled out by the plugin below:
    struct {
        PVMMDLL_PLUGIN_INTERNAL_CONTEXT ctxM;   // optional internal module context [must be cleaned by pfnClose() call].
        CHAR uszPathName[128];
        BOOL fRootModule;
        BOOL fProcessModule;
        BOOL fRootModuleHidden;
        BOOL fProcessModuleHidden;
        CHAR sTimelineNameShort[6];
        CHAR _Reserved[2];
        CHAR uszTimelineFile[32];
        CHAR _Reserved2[32];
    } reg_info;
    // function plugin registration info to be filled out by the plugin below:
    struct {
        BOOL(*pfnList)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Inout_ PHANDLE pFileList);
        NTSTATUS(*pfnRead)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead,  _In_ ULONG64 cbOffset);
        NTSTATUS(*pfnWrite)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset);
        VOID(*pfnNotify)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ DWORD fEvent, _In_opt_ PVOID pvEvent, _In_opt_ DWORD cbEvent);
        VOID(*pfnClose)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP);
        BOOL(*pfnVisibleModule)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP);
        PVOID pvReserved[10];
    } reg_fn;
    // Optional forensic plugin functionality for forensic (more comprehensive)
    // analysis of various data. Functions are optional.
    // Functions are called in the below order and way.
    // 1: pfnInitialize()            - multi-threaded (between plugins).
    // 2: (multiple types see below) - multi-threaded (between plugins).
    //    pfnLogCSV()
    //    pfnLogJSON()
    //    pfnFindEvil()
    //    pfnIngestPhysmem()
    //    pfnIngestVirtmem()
    // 3. pfnIngestFinalize()        - single-threaded. (pfnLogCSV/pfnLogJSON/pfnFindEvil may still be active).
    // 4. pfnTimeline()              - single-threaded. (pfnLogCSV/pfnLogJSON/pfnFindEvil may still be active).
    // 5. pfnFinalize()              - single-threaded.
    struct {
        PVOID(*pfnInitialize)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP);
        VOID(*pfnFinalize)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc);
        VOID(*pfnTimeline)(
            _In_ VMM_HANDLE H,
            _In_opt_ PVOID ctxfc,
            _In_ HANDLE hTimeline,
            _In_ VOID(*pfnAddEntry)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ QWORD ft, _In_ DWORD dwAction, _In_ DWORD dwPID, _In_ DWORD dwData32, _In_ QWORD qwData64, _In_ LPCSTR uszText),
            _In_ VOID(*pfnEntryAddBySql)(_In_ VMM_HANDLE H, _In_ HANDLE hTimeline, _In_ DWORD cEntrySql, _In_ LPCSTR *pszEntrySql));
        VOID(*pfnIngestObject)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc, _In_ PVMMDLL_FORENSIC_INGEST_OBJECT pIngestObject);
        VOID(*pfnIngestPhysmem)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc, _In_ PVMMDLL_FORENSIC_INGEST_PHYSMEM pIngestPhysmem);
        VOID(*pfnIngestVirtmem)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc, _In_ PVMMDLL_FORENSIC_INGEST_VIRTMEM pIngestVirtmem);
        VOID(*pfnIngestFinalize)(_In_ VMM_HANDLE H, _In_opt_ PVOID ctxfc);
        VOID(*pfnFindEvil)(_In_ VMM_HANDLE H, _In_ VMMDLL_MODULE_ID MID, _In_opt_ PVOID ctxfc);
        PVOID pvReserved[6];
        VOID(*pfnLogCSV)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VMMDLL_CSV_HANDLE hCSV);
        VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_PLUGIN_CONTEXT ctxP, _In_ VOID(*pfnLogJSON)(_In_ VMM_HANDLE H, _In_ PVMMDLL_FORENSIC_JSONDATA pData));
    } reg_fnfc;
    // Additional system information - read/only by the plugins.
    struct {
        BOOL f32;
        DWORD dwVersionMajor;
        DWORD dwVersionMinor;
        DWORD dwVersionBuild;
        DWORD _Reserved[32];
    } sysinfo;
} VMMDLL_PLUGIN_REGINFO, *PVMMDLL_PLUGIN_REGINFO;



//-----------------------------------------------------------------------------
// FORENSIC-MODE SPECIFIC FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Append text data to a memory-backed forensics file.
* All text should be UTF-8 encoded.
* -- H
* -- uszFileName
* -- uszFormat
* -- ..
* -- return = number of bytes appended (excluding terminating null).
*/
EXPORTED_FUNCTION _Success_(return != 0)
SIZE_T VMMDLL_ForensicFileAppend(
    _In_ VMM_HANDLE H,
    _In_ LPCSTR uszFileName,
    _In_z_ _Printf_format_string_ LPCSTR uszFormat,
    ...
);



//-----------------------------------------------------------------------------
// VMM LOG FUNCTIONALITY BELOW:
// It's possible for external code (primarily external plugins) to make use of
// the MemProcFS logging system.
// ----------------------------------------------------------------------------

typedef enum tdVMMDLL_LOGLEVEL {
    VMMDLL_LOGLEVEL_CRITICAL = 1,  // critical stopping error
    VMMDLL_LOGLEVEL_WARNING  = 2,  // severe warning error
    VMMDLL_LOGLEVEL_INFO     = 3,  // normal/info message
    VMMDLL_LOGLEVEL_VERBOSE  = 4,  // verbose message (visible with -v)
    VMMDLL_LOGLEVEL_DEBUG    = 5,  // debug message (visible with -vv)
    VMMDLL_LOGLEVEL_TRACE    = 6,  // trace message
    VMMDLL_LOGLEVEL_NONE     = 7,  // do not use!
} VMMDLL_LOGLEVEL;

/*
* Log a message using the internal MemProcFS vmm logging system. Log messages
* will be displayed/suppressed depending on current logging configuration.
* -- hVMM
* -- MID = module id supplied by plugin context PVMMDLL_PLUGIN_CONTEXT or
*          id given by VMMDLL_MID_*.
* -- dwLogLevel
* -- uszFormat
* -- ...
*/
EXPORTED_FUNCTION
VOID VMMDLL_Log(
    _In_ VMM_HANDLE hVMM,
    _In_opt_ VMMDLL_MODULE_ID MID,
    _In_ VMMDLL_LOGLEVEL dwLogLevel,
    _In_z_ _Printf_format_string_ LPCSTR uszFormat,
    ...
);

/*
* Log a message using the internal MemProcFS vmm logging system. Log messages
* will be displayed/suppressed depending on current logging configuration.
* -- hVMM
* -- MID = module id supplied by plugin context PVMMDLL_PLUGIN_CONTEXT or
*          id given by VMMDLL_MID_*.
* -- dwLogLevel
* -- uszFormat
* -- arglist
*/
EXPORTED_FUNCTION
VOID VMMDLL_LogEx(
    _In_ VMM_HANDLE hVMM,
    _In_opt_ VMMDLL_MODULE_ID MID,
    _In_ VMMDLL_LOGLEVEL dwLogLevel,
    _In_z_ _Printf_format_string_ LPCSTR uszFormat,
    va_list arglist
);



//-----------------------------------------------------------------------------
// VMM CORE FUNCTIONALITY BELOW:
// Vmm core functaionlity such as read (and write) to both virtual and physical
// memory. NB! writing will only work if the target is supported - i.e. not a
// memory dump file...
// To read physical memory specify dwPID as (DWORD)-1
//-----------------------------------------------------------------------------

#define VMMDLL_PID_PROCESS_WITH_KERNELMEMORY        0x80000000      // Combine with dwPID to enable process kernel memory (NB! use with extreme care).

// FLAG used to supress the default read cache in calls to VMM_MemReadEx()
// which will lead to the read being fetched from the target system always.
// Cached page tables (used for translating virtual2physical) are still used.
#define VMMDLL_FLAG_NOCACHE                         0x0001  // do not use the data cache (force reading from memory acquisition device)
#define VMMDLL_FLAG_ZEROPAD_ON_FAIL                 0x0002  // zero pad failed physical memory reads and report success if read within range of physical memory.
#define VMMDLL_FLAG_FORCECACHE_READ                 0x0008  // force use of cache - fail non-cached pages - only valid for reads, invalid with VMM_FLAG_NOCACHE/VMM_FLAG_ZEROPAD_ON_FAIL.
#define VMMDLL_FLAG_NOPAGING                        0x0010  // do not try to retrieve memory from paged out memory from pagefile/compressed (even if possible)
#define VMMDLL_FLAG_NOPAGING_IO                     0x0020  // do not try to retrieve memory from paged out memory if read would incur additional I/O (even if possible).
#define VMMDLL_FLAG_NOCACHEPUT                      0x0100  // do not write back to the data cache upon successful read from memory acquisition device.
#define VMMDLL_FLAG_CACHE_RECENT_ONLY               0x0200  // only fetch from the most recent active cache region when reading.
#define VMMDLL_FLAG_NO_PREDICTIVE_READ              0x0400  // (deprecated/unused).
#define VMMDLL_FLAG_FORCECACHE_READ_DISABLE         0x0800  // disable/override any use of VMMDLL_FLAG_FORCECACHE_READ. only recommended for local files. improves forensic artifact order.
#define VMMDLL_FLAG_SCATTER_PREPAREEX_NOMEMZERO     0x1000  // do not zero out the memory buffer when preparing a scatter read.
#define VMMDLL_FLAG_NOMEMCALLBACK                   0x2000  // do not call user-set memory callback functions when reading memory (even if active).
#define VMMDLL_FLAG_SCATTER_FORCE_PAGEREAD          0x4000  // force page-sized reads when using scatter functionality.

/*
* Read memory in various non-contigious locations specified by the pointers to
* the items in the ppMEMs array. Result for each unit of work will be given
* individually. No upper limit of number of items to read, but no performance
* boost will be given if above hardware limit. Max size of each unit of work is
* one 4k page (4096 bytes). Reads must not cross 4k page boundaries. Reads must
* start at even DWORDs (4-bytes).
* -- hVMM
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- ppMEMs = array of scatter read headers.
* -- cpMEMs = count of ppMEMs.
* -- flags = optional flags as given by VMMDLL_FLAG_*
* -- return = the number of successfully read items.
*/
EXPORTED_FUNCTION
DWORD VMMDLL_MemReadScatter(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Inout_ PPMEM_SCATTER ppMEMs, _In_ DWORD cpMEMs, _In_ DWORD flags);

/*
* Write memory in various non-contigious locations specified by the pointers to
* the items in the ppMEMs array. Result for each unit of work will be given
* individually. No upper limit of number of items to write Max size of each
* unit of work is one 4k page (4096 bytes). Writes must not cross 4k page boundaries.
* -- hVMM
* -- dwPID - PID of target process, (DWORD)-1 to write physical memory.
* -- ppMEMs = array of scatter read headers.
* -- cpMEMs = count of ppMEMs.
* -- return = the number of hopefully successfully written items.
*/
EXPORTED_FUNCTION
DWORD VMMDLL_MemWriteScatter(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Inout_ PPMEM_SCATTER ppMEMs, _In_ DWORD cpMEMs);

/*
* Read a single 4096-byte page of memory.
* -- hVMM
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- qwA
* -- pbPage
* -- return = success/fail (depending if all requested bytes are read or not).
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_MemReadPage(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ ULONG64 qwA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Read a contigious arbitrary amount of memory.
* -- hVMM
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- qwA
* -- pb
* -- cb
* -- return = success/fail (depending if all requested bytes are read or not).
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_MemRead(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ ULONG64 qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Read a contigious amount of memory and report the number of bytes read in pcbRead.
* -- hVMM
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- qwA
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMMDLL_FLAG_*
* -- return = success/fail. NB! reads may report as success even if 0 bytes are
*        read - it's recommended to verify pcbReadOpt parameter.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_MemReadEx(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ ULONG64 qwA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags);

/*
* Prefetch a number of addresses (specified in the pA array) into the memory
* cache. This function is to be used to batch larger known reads into local
* cache before making multiple smaller reads - which will then happen from
* the cache. Function exists for performance reasons.
* -- hVMM
* -- dwPID = PID of target process, (DWORD)-1 for physical memory.
* -- pPrefetchAddresses = array of addresses to read into cache.
* -- cPrefetchAddresses
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_MemPrefetchPages(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_reads_(cPrefetchAddresses) PULONG64 pPrefetchAddresses, _In_ DWORD cPrefetchAddresses);

/*
* Write a contigious arbitrary amount of memory. Please note some virtual memory
* such as pages of executables (such as DLLs) may be shared between different
* virtual memory over different processes. As an example a write to kernel32.dll
* in one process is likely to affect kernel32 in the whole system - in all
* processes. Heaps and Stacks and other memory are usually safe to write to.
* Please take care when writing to memory!
* -- hVMM
* -- dwPID = PID of target process, (DWORD)-1 to read physical memory.
* -- qwA
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_MemWrite(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ ULONG64 qwA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Translate a virtual address to a physical address by walking the page tables
* of the specified process.
* -- hVMM
* -- dwPID
* -- qwVA
* -- pqwPA
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_MemVirt2Phys(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA);



//-----------------------------------------------------------------------------
// SIMPLIFIED EASIER TO USE READ SCATTER MEMORY FUNCTIONALITY BELOW:
// The flow is as following:
// 1. Call VMMDLL_Scatter_Initialize to initialize handle.
// 2. Populate memory ranges with multiple calls to VMMDLL_Scatter_Prepare
//    and/or VMMDLL_Scatter_PrepareEx functions. The memory buffer given to
//    VMMDLL_Scatter_PrepareEx will be populated with contents in step (3).
// 3. Retrieve the memory by calling VMMDLL_Scatter_Execute function.
// 4. If VMMDLL_Scatter_Prepare was used (i.e. not VMMDLL_Scatter_PrepareEx)
//    then retrieve the memory read in (3).
// 5. Clear the handle for reuse by calling VMMDLL_Scatter_Clear alternatively
//    Close the handle to free resources with VMMDLL_Scatter_CloseHandle.
// NB! buffers given to VMMDLL_Scatter_PrepareEx must not be free'd before
//     handle is closed since it may be used internally.
// NB! VMMDLL_Scatter_ExecuteRead may be called at a later point in time to
//     update (re-read) previously read data.
// NB! larger reads (up to 1 GB max) are supported but not recommended.
//-----------------------------------------------------------------------------
typedef HANDLE      VMMDLL_SCATTER_HANDLE;

/*
* Initialize a scatter handle which is used to call VMMDLL_Scatter_* functions.
* CALLER CLOSE: VMMDLL_Scatter_CloseHandle(return)
* -- hVMM
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- flags = optional flags as given by VMMDLL_FLAG_*
* -- return = handle to be used in VMMDLL_Scatter_* functions.
*/
EXPORTED_FUNCTION _Success_(return != NULL)
VMMDLL_SCATTER_HANDLE VMMDLL_Scatter_Initialize(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ DWORD flags);

/*
* Prepare (add) a memory range for reading. The memory may after a call to
* VMMDLL_Scatter_Execute*() be retrieved with VMMDLL_Scatter_Read().
* -- hS
* -- va = start address of the memory range to read.
* -- cb = size of memory range to read.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_Prepare(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_ DWORD cb);

/*
* Prepare (add) a memory range for reading. The buffer pb and the read length
* *pcbRead will be populated when VMMDLL_Scatter_Execute*() is later called.
* NB! the buffer pb must not be deallocated before VMMDLL_Scatter_CloseHandle()
*     has been called since it's used internally by the scatter functionality!
* -- hS
* -- va = start address of the memory range to read.
* -- cb = size of memory range to read.
* -- pb = buffer to populate with read memory when calling VMMDLL_Scatter_ExecuteRead()
* -- pcbRead = optional pointer to be populated with number of bytes successfully read.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_PrepareEx(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead);

/*
* Prepare (add) a memory range for writing.
* The memory contents to write is processed when calling this function.
* Any changes to va/pb/cb after this call will not be reflected in the write.
* The memory is later written when calling VMMDLL_Scatter_Execute().
* Writing takes place before reading.
* -- hS
* -- va = start address of the memory range to write.
* -- pb = data to write.
* -- cb = size of memory range to write.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_PrepareWrite(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Prepare (add) a memory range for writing.
* Memory contents to write is processed when calling VMMDLL_Scatter_Execute().
* The buffer pb must be valid when VMMDLL_Scatter_Execute() is called.
* The memory is later written when calling VMMDLL_Scatter_Execute().
* Writing takes place before reading.
* -- hS
* -- va = start address of the memory range to write.
* -- pb = data to write. Buffer must be valid when VMMDLL_Scatter_Execute() is called.
* -- cb = size of memory range to write.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_PrepareWriteEx(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Retrieve and Write memory previously populated.
* Write any memory prepared with VMMDLL_Scatter_PrepareWrite function (1st).
* Retrieve the memory ranges previously populated with calls to the
* VMMDLL_Scatter_Prepare* functions (2nd).
* -- hS
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_Execute(_In_ VMMDLL_SCATTER_HANDLE hS);

/*
* Retrieve the memory ranges previously populated with calls to the
* VMMDLL_Scatter_Prepare* functions.
* -- hS
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_ExecuteRead(_In_ VMMDLL_SCATTER_HANDLE hS);

/*
* Read out memory in previously populated ranges. This function should only be
* called after the memory has been retrieved using VMMDLL_Scatter_ExecuteRead().
* -- hS
* -- va
* -- cb
* -- pb
* -- pcbRead
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_Read(_In_ VMMDLL_SCATTER_HANDLE hS, _In_ QWORD va, _In_ DWORD cb, _Out_writes_opt_(cb) PBYTE pb, _Out_opt_ PDWORD pcbRead);

/*
* Clear/Reset the handle for use in another subsequent read scatter operation.
* -- hS = the scatter handle to clear for reuse.
* -- dwPID = optional PID change.
* -- flags
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Scatter_Clear(_In_ VMMDLL_SCATTER_HANDLE hS, _In_opt_ DWORD dwPID, _In_ DWORD flags);

/*
* Close the scatter handle and free the resources it uses.
* -- hS = the scatter handle to close.
*/
EXPORTED_FUNCTION
VOID VMMDLL_Scatter_CloseHandle(_In_opt_ _Post_ptr_invalid_ VMMDLL_SCATTER_HANDLE hS);



//-----------------------------------------------------------------------------
// MEMORY CALLBACK FUNCTIONALITY:
// Allows for advanced memory access statistics and the creation of specialized
// custom memory views for physical memory or per-process virtual memory.
// Callback functions may be registered to modify memory reads and/or writes.
//-----------------------------------------------------------------------------

typedef enum tdVMMDLL_MEM_CALLBACK_TP {
    VMMDLL_MEM_CALLBACK_READ_PHYSICAL_PRE = 1,
    VMMDLL_MEM_CALLBACK_READ_PHYSICAL_POST = 2,
    VMMDLL_MEM_CALLBACK_WRITE_PHYSICAL_PRE = 3,
    VMMDLL_MEM_CALLBACK_READ_VIRTUAL_PRE = 4,
    VMMDLL_MEM_CALLBACK_READ_VIRTUAL_POST = 5,
    VMMDLL_MEM_CALLBACK_WRITE_VIRTUAL_PRE = 6,
} VMMDLL_MEM_CALLBACK_TP;

/*
* MEM callback function definition.
* -- ctxUser = user context pointer.
* -- dwPID = PID of target process, (DWORD)-1 for physical memory.
* -- cpMEMs = count of pMEMs.
* -- ppMEMs = array of pointers to MEM scatter read headers.
*/
typedef VOID(*VMMDLL_MEM_CALLBACK_PFN)(_In_opt_ PVOID ctxUser, _In_ DWORD dwPID, _In_ DWORD cpMEMs, _In_ PPMEM_SCATTER ppMEMs);

/*
* Register or unregister am optional memory access callback function.
* It's possible to have one callback function registered for each type.
* To clear an already registered callback function specify NULL as pfnCB.
* -- hVMM
* -- tp = type of callback to register / unregister - VMMDLL_MEM_CALLBACK_*.
* -- ctxUser = user context pointer to be passed to the callback function.
* -- pfnCB = callback function to register / unregister.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_MemCallback(_In_ VMM_HANDLE hVMM, _In_ VMMDLL_MEM_CALLBACK_TP tp, _In_opt_ PVOID ctxUser, _In_opt_ VMMDLL_MEM_CALLBACK_PFN pfnCB);



//-----------------------------------------------------------------------------
// VMM PROCESS MAP FUNCTIONALITY BELOW:
// Functionality for retrieving process related collections of items such as
// page table map (PTE), virtual address descriptor map (VAD), loaded modules,
// heaps and threads.
//-----------------------------------------------------------------------------

#define VMMDLL_MAP_PTE_VERSION              2
#define VMMDLL_MAP_VAD_VERSION              6
#define VMMDLL_MAP_VADEX_VERSION            4
#define VMMDLL_MAP_MODULE_VERSION           6
#define VMMDLL_MAP_UNLOADEDMODULE_VERSION   2
#define VMMDLL_MAP_EAT_VERSION              3
#define VMMDLL_MAP_IAT_VERSION              2
#define VMMDLL_MAP_HEAP_VERSION             4
#define VMMDLL_MAP_HEAPALLOC_VERSION        1
#define VMMDLL_MAP_THREAD_VERSION           4
#define VMMDLL_MAP_THREAD_CALLSTACK_VERSION 1
#define VMMDLL_MAP_HANDLE_VERSION           3
#define VMMDLL_MAP_POOL_VERSION             2
#define VMMDLL_MAP_KOBJECT_VERSION          1
#define VMMDLL_MAP_KDRIVER_VERSION          1
#define VMMDLL_MAP_KDEVICE_VERSION          1
#define VMMDLL_MAP_NET_VERSION              3
#define VMMDLL_MAP_PHYSMEM_VERSION          2
#define VMMDLL_MAP_USER_VERSION             2
#define VMMDLL_MAP_VM_VERSION               2
#define VMMDLL_MAP_SERVICE_VERSION          3

// flags to check for existence in the fPage field of VMMDLL_MAP_PTEENTRY
#define VMMDLL_MEMMAP_FLAG_PAGE_W           0x0000000000000002
#define VMMDLL_MEMMAP_FLAG_PAGE_NS          0x0000000000000004
#define VMMDLL_MEMMAP_FLAG_PAGE_NX          0x8000000000000000
#define VMMDLL_MEMMAP_FLAG_PAGE_MASK        0x8000000000000006

#define VMMDLL_POOLMAP_FLAG_ALL             0
#define VMMDLL_POOLMAP_FLAG_BIG             1

#define VMMDLL_MODULE_FLAG_NORMAL           0
#define VMMDLL_MODULE_FLAG_DEBUGINFO        1
#define VMMDLL_MODULE_FLAG_VERSIONINFO      2

typedef enum tdVMMDLL_PTE_TP {
    VMMDLL_PTE_TP_NA = 0,
    VMMDLL_PTE_TP_HARDWARE = 1,
    VMMDLL_PTE_TP_TRANSITION = 2,
    VMMDLL_PTE_TP_PROTOTYPE = 3,
    VMMDLL_PTE_TP_DEMANDZERO = 4,
    VMMDLL_PTE_TP_COMPRESSED = 5,
    VMMDLL_PTE_TP_PAGEFILE = 6,
    VMMDLL_PTE_TP_FILE = 7,
} VMMDLL_PTE_TP, *PVMMDLL_PTE_TP;

typedef struct tdVMMDLL_MAP_PTEENTRY {
    QWORD vaBase;
    QWORD cPages;
    QWORD fPage;
    BOOL  fWoW64;
    DWORD _FutureUse1;
    union { LPSTR  uszText; LPWSTR wszText; };              // U/W dependant
    DWORD _Reserved1;
    DWORD cSoftware;    // # software (non active) PTEs in region
} VMMDLL_MAP_PTEENTRY, *PVMMDLL_MAP_PTEENTRY;

typedef struct tdVMMDLL_MAP_VADENTRY {
    QWORD vaStart;
    QWORD vaEnd;
    QWORD vaVad;
    // DWORD 0
    DWORD VadType           : 3;   // Pos 0
    DWORD Protection        : 5;   // Pos 3
    DWORD fImage            : 1;   // Pos 8
    DWORD fFile             : 1;   // Pos 9
    DWORD fPageFile         : 1;   // Pos 10
    DWORD fPrivateMemory    : 1;   // Pos 11
    DWORD fTeb              : 1;   // Pos 12
    DWORD fStack            : 1;   // Pos 13
    DWORD fSpare            : 2;   // Pos 14
    DWORD HeapNum           : 7;   // Pos 16
    DWORD fHeap             : 1;   // Pos 23
    DWORD cwszDescription   : 8;   // Pos 24
    // DWORD 1
    DWORD CommitCharge      : 31;   // Pos 0
    DWORD MemCommit         : 1;    // Pos 31
    DWORD u2;
    DWORD cbPrototypePte;
    QWORD vaPrototypePte;
    QWORD vaSubsection;
    union { LPSTR  uszText; LPWSTR wszText; };              // U/W dependant
    DWORD _FutureUse1;
    DWORD _Reserved1;
    QWORD vaFileObject;             // only valid if fFile/fImage _and_ after wszText is initialized
    DWORD cVadExPages;              // number of "valid" VadEx pages in this VAD.
    DWORD cVadExPagesBase;          // number of "valid" VadEx pages in "previous" VADs
    QWORD _Reserved2;
} VMMDLL_MAP_VADENTRY, *PVMMDLL_MAP_VADENTRY;

#define VMMDLL_VADEXENTRY_FLAG_HARDWARE     0x01
#define VMMDLL_VADEXENTRY_FLAG_W            0x10
#define VMMDLL_VADEXENTRY_FLAG_K            0x40
#define VMMDLL_VADEXENTRY_FLAG_NX           0x80

typedef struct tdVMMDLL_MAP_VADEXENTRY {
    VMMDLL_PTE_TP tp;
    BYTE iPML;
    BYTE pteFlags;
    WORD _Reserved2;
    QWORD va;
    QWORD pa;
    QWORD pte;
    struct {
        DWORD _Reserved1;
        VMMDLL_PTE_TP tp;
        QWORD pa;
        QWORD pte;
    } proto;
    QWORD vaVadBase;
} VMMDLL_MAP_VADEXENTRY, *PVMMDLL_MAP_VADEXENTRY;

typedef enum tdVMMDLL_MODULE_TP {
    VMMDLL_MODULE_TP_NORMAL = 0,
    VMMDLL_MODULE_TP_DATA = 1,
    VMMDLL_MODULE_TP_NOTLINKED = 2,
    VMMDLL_MODULE_TP_INJECTED = 3,
} VMMDLL_MODULE_TP;

typedef struct tdVMMDLL_MAP_MODULEENTRY_DEBUGINFO {
    DWORD dwAge;
    DWORD _Reserved;
    BYTE Guid[16];
    union { LPSTR  uszGuid;             LPWSTR wszGuid;                 };
    union { LPSTR  uszPdbFilename;      LPWSTR wszPdbFilename;          };
} VMMDLL_MAP_MODULEENTRY_DEBUGINFO, *PVMMDLL_MAP_MODULEENTRY_DEBUGINFO;

typedef struct tdVMMDLL_MAP_MODULEENTRY_VERSIONINFO {
    union { LPSTR  uszCompanyName;      LPWSTR wszCompanyName;          };
    union { LPSTR  uszFileDescription;  LPWSTR wszFileDescription;      };
    union { LPSTR  uszFileVersion;      LPWSTR wszFileVersion;          };
    union { LPSTR  uszInternalName;     LPWSTR wszInternalName;         };
    union { LPSTR  uszLegalCopyright;   LPWSTR wszLegalCopyright;       };
    union { LPSTR  uszOriginalFilename; LPWSTR wszFileOriginalFilename; };
    union { LPSTR  uszProductName;      LPWSTR wszProductName;          };
    union { LPSTR  uszProductVersion;   LPWSTR wszProductVersion;       };
} VMMDLL_MAP_MODULEENTRY_VERSIONINFO, *PVMMDLL_MAP_MODULEENTRY_VERSIONINFO;

typedef struct tdVMMDLL_MAP_MODULEENTRY {
    QWORD vaBase;
    QWORD vaEntry;
    DWORD cbImageSize;
    BOOL  fWoW64;
    union { LPSTR  uszText; LPWSTR wszText; };              // U/W dependant
    DWORD _Reserved3;
    DWORD _Reserved4;
    union { LPSTR  uszFullName; LPWSTR wszFullName; };      // U/W dependant
    VMMDLL_MODULE_TP tp;
    DWORD cbFileSizeRaw;
    DWORD cSection;
    DWORD cEAT;
    DWORD cIAT;
    DWORD _Reserved2;
    QWORD _Reserved1[3];
    PVMMDLL_MAP_MODULEENTRY_DEBUGINFO pExDebugInfo;         // not included by default - use VMMDLL_MODULE_FLAG_DEBUGINFO to include.
    PVMMDLL_MAP_MODULEENTRY_VERSIONINFO pExVersionInfo;     // not included by default - use VMMDLL_MODULE_FLAG_VERSIONINFO to include.
} VMMDLL_MAP_MODULEENTRY, *PVMMDLL_MAP_MODULEENTRY;

typedef struct tdVMMDLL_MAP_UNLOADEDMODULEENTRY {
    QWORD vaBase;
    DWORD cbImageSize;
    BOOL  fWoW64;
    union { LPSTR  uszText; LPWSTR wszText; };              // U/W dependant
    DWORD _FutureUse1;
    DWORD dwCheckSum;               // user-mode only
    DWORD dwTimeDateStamp;          // user-mode only
    DWORD _Reserved1;
    QWORD ftUnload;                 // kernel-mode only
} VMMDLL_MAP_UNLOADEDMODULEENTRY, *PVMMDLL_MAP_UNLOADEDMODULEENTRY;

typedef struct tdVMMDLL_MAP_EATENTRY {
    QWORD vaFunction;
    DWORD dwOrdinal;
    DWORD oFunctionsArray;          // PIMAGE_EXPORT_DIRECTORY->AddressOfFunctions[oFunctionsArray]
    DWORD oNamesArray;              // PIMAGE_EXPORT_DIRECTORY->AddressOfNames[oNamesArray]
    DWORD _FutureUse1;
    union { LPSTR  uszFunction; LPWSTR wszFunction; };      // U/W dependant
    union { LPSTR  uszForwardedFunction; LPWSTR wszForwardedFunction; };    // U/W dependant (function or ordinal name if exists).
} VMMDLL_MAP_EATENTRY, *PVMMDLL_MAP_EATENTRY;

typedef struct tdVMMDLL_MAP_IATENTRY {
    QWORD vaFunction;
    union { LPSTR  uszFunction; LPWSTR wszFunction; };      // U/W dependant
    DWORD _FutureUse1;
    DWORD _FutureUse2;
    union { LPSTR  uszModule; LPWSTR wszModule; };          // U/W dependant
    struct {
        BOOL f32;
        WORD wHint;
        WORD _Reserved1;
        DWORD rvaFirstThunk;
        DWORD rvaOriginalFirstThunk;
        DWORD rvaNameModule;
        DWORD rvaNameFunction;
    } Thunk;
} VMMDLL_MAP_IATENTRY, *PVMMDLL_MAP_IATENTRY;

typedef enum tdVMMDLL_HEAP_TP {
    VMMDLL_HEAP_TP_NA   = 0,
    VMMDLL_HEAP_TP_NT   = 1,
    VMMDLL_HEAP_TP_SEG  = 2,
} VMMDLL_HEAP_TP, *PVMMDLL_HEAP_TP;

typedef enum tdVMMDLL_HEAP_SEGMENT_TP {
    VMMDLL_HEAP_SEGMENT_TP_NA           = 0,
    VMMDLL_HEAP_SEGMENT_TP_NT_SEGMENT   = 1,
    VMMDLL_HEAP_SEGMENT_TP_NT_LFH       = 2,
    VMMDLL_HEAP_SEGMENT_TP_NT_LARGE     = 3,
    VMMDLL_HEAP_SEGMENT_TP_NT_NA        = 4,
    VMMDLL_HEAP_SEGMENT_TP_SEG_HEAP     = 5,
    VMMDLL_HEAP_SEGMENT_TP_SEG_SEGMENT  = 6,
    VMMDLL_HEAP_SEGMENT_TP_SEG_LARGE    = 7,
    VMMDLL_HEAP_SEGMENT_TP_SEG_NA       = 8,
} VMMDLL_HEAP_SEGMENT_TP, *PVMMDLL_HEAP_SEGMENT_TP;

typedef struct tdVMMDLL_MAP_HEAP_SEGMENTENTRY {
    QWORD va;
    DWORD cb;
    VMMDLL_HEAP_SEGMENT_TP tp : 16;
    DWORD iHeap : 16;
} VMMDLL_MAP_HEAP_SEGMENTENTRY, *PVMMDLL_MAP_HEAP_SEGMENTENTRY;

typedef struct tdVMMDLL_MAP_HEAPENTRY {
    QWORD va;
    VMMDLL_HEAP_TP tp;
    BOOL f32;
    DWORD iHeap;
    DWORD dwHeapNum;
} VMMDLL_MAP_HEAPENTRY, *PVMMDLL_MAP_HEAPENTRY;

typedef enum tdVMMDLL_HEAPALLOC_TP {
    VMMDLL_HEAPALLOC_TP_NA          = 0,
    VMMDLL_HEAPALLOC_TP_NT_HEAP     = 1,
    VMMDLL_HEAPALLOC_TP_NT_LFH      = 2,
    VMMDLL_HEAPALLOC_TP_NT_LARGE    = 3,
    VMMDLL_HEAPALLOC_TP_NT_NA       = 4,
    VMMDLL_HEAPALLOC_TP_SEG_VS      = 5,
    VMMDLL_HEAPALLOC_TP_SEG_LFH     = 6,
    VMMDLL_HEAPALLOC_TP_SEG_LARGE   = 7,
    VMMDLL_HEAPALLOC_TP_SEG_NA      = 8,
} VMMDLL_HEAPALLOC_TP, *PVMMDLL_HEAPALLOC_TP;

typedef struct tdVMMDLL_MAP_HEAPALLOCENTRY {
    QWORD va;
    DWORD cb;
    VMMDLL_HEAPALLOC_TP tp;
} VMMDLL_MAP_HEAPALLOCENTRY, *PVMMDLL_MAP_HEAPALLOCENTRY;

typedef struct tdVMMDLL_MAP_THREADENTRY {
    DWORD dwTID;
    DWORD dwPID;
    DWORD dwExitStatus;
    UCHAR bState;
    UCHAR bRunning;
    UCHAR bPriority;
    UCHAR bBasePriority;
    QWORD vaETHREAD;
    QWORD vaTeb;
    QWORD ftCreateTime;
    QWORD ftExitTime;
    QWORD vaStartAddress;
    QWORD vaStackBaseUser;          // value from _NT_TIB / _TEB
    QWORD vaStackLimitUser;         // value from _NT_TIB / _TEB
    QWORD vaStackBaseKernel;
    QWORD vaStackLimitKernel;
    QWORD vaTrapFrame;
    QWORD vaRIP;                    // RIP register (if user mode)
    QWORD vaRSP;                    // RSP register (if user mode)
    QWORD qwAffinity;
    DWORD dwUserTime;
    DWORD dwKernelTime;
    UCHAR bSuspendCount;
    UCHAR bWaitReason;
    UCHAR _FutureUse1[2];
    DWORD _FutureUse2[11];
    QWORD vaImpersonationToken;
    QWORD vaWin32StartAddress;
} VMMDLL_MAP_THREADENTRY, *PVMMDLL_MAP_THREADENTRY;

typedef struct tdVMMDLL_MAP_THREAD_CALLSTACKENTRY {
    DWORD i;
    BOOL  fRegPresent;
    QWORD vaRetAddr;
    QWORD vaRSP;
    QWORD vaBaseSP;
    DWORD _FutureUse1;
    DWORD cbDisplacement;
    union { LPSTR uszModule; LPWSTR wszModule; };           // U/W dependant
    union { LPSTR uszFunction; LPWSTR wszFunction; };       // U/W dependant
} VMMDLL_MAP_THREAD_CALLSTACKENTRY, *PVMMDLL_MAP_THREAD_CALLSTACKENTRY;

typedef struct tdVMMDLL_MAP_HANDLEENTRY {
    QWORD vaObject;
    DWORD dwHandle;
    DWORD dwGrantedAccess : 24;
    DWORD iType : 8;
    QWORD qwHandleCount;
    QWORD qwPointerCount;
    QWORD vaObjectCreateInfo;
    QWORD vaSecurityDescriptor;
    union { LPSTR  uszText; LPWSTR wszText; };              // U/W dependant
    DWORD _FutureUse2;
    DWORD dwPID;
    DWORD dwPoolTag;
    DWORD _FutureUse[7];
    union { LPSTR  uszType; LPWSTR wszType; QWORD _Pad1; }; // U/W dependant
} VMMDLL_MAP_HANDLEENTRY, *PVMMDLL_MAP_HANDLEENTRY;

typedef enum tdVMMDLL_MAP_POOL_TYPE {
    VMMDLL_MAP_POOL_TYPE_Unknown         = 0,
    VMMDLL_MAP_POOL_TYPE_NonPagedPool    = 1,
    VMMDLL_MAP_POOL_TYPE_NonPagedPoolNx  = 2,
    VMMDLL_MAP_POOL_TYPE_PagedPool       = 3
} VMMDLL_MAP_POOL_TYPE;

typedef enum tdVMM_MAP_POOL_TYPE_SUBSEGMENT {
    VMM_MAP_POOL_TYPE_SUBSEGMENT_UNKNOWN = 0,
    VMM_MAP_POOL_TYPE_SUBSEGMENT_NA      = 1,
    VMM_MAP_POOL_TYPE_SUBSEGMENT_BIG     = 2,
    VMM_MAP_POOL_TYPE_SUBSEGMENT_LARGE   = 3,
    VMM_MAP_POOL_TYPE_SUBSEGMENT_VS      = 4,
    VMM_MAP_POOL_TYPE_SUBSEGMENT_LFH     = 5
} VMM_MAP_POOL_TYPE_SUBSEGMENT;

typedef struct tdVMMDLL_MAP_POOLENTRYTAG {
    union {
        CHAR szTag[5];
        struct {
            DWORD dwTag;
            DWORD _Filler;
            DWORD cEntry;
            DWORD iTag2Map;
        };
    };
} VMMDLL_MAP_POOLENTRYTAG, *PVMMDLL_MAP_POOLENTRYTAG;

typedef struct tdVMMDLL_MAP_POOLENTRY {
    QWORD va;
    union {
        CHAR szTag[5];
        struct {
            DWORD dwTag;
            BYTE _ReservedZero;
            BYTE fAlloc;
            BYTE tpPool;    // VMMDLL_MAP_POOL_TYPE
            BYTE tpSS;      // VMMDLL_MAP_POOL_TYPE_SUBSEGMENT
        };
    };
    DWORD cb;
    DWORD _Filler;
} VMMDLL_MAP_POOLENTRY, *PVMMDLL_MAP_POOLENTRY;

typedef struct tdVMMDLL_MAP_KDEVICEENTRY {
    QWORD va;                                       // Address of this object in memory.
    DWORD iDepth;                                   // Depth of the device object.
    DWORD dwDeviceType;                             // Device type according to FILE_DEVICE_*
    union { LPSTR  uszDeviceType; LPWSTR wszDeviceType; }; // Device type name.
    QWORD vaDriverObject;                           // Address of the driver object.
    QWORD vaAttachedDevice;                         // Address of the attached device object (if exists).
    QWORD vaFileSystemDevice;                       // Address of the file system device object (if exists).
    union { LPSTR  uszVolumeInfo; LPWSTR wszVolumeInfo; }; // Volume information (if exists) .
} VMMDLL_MAP_KDEVICEENTRY, *PVMMDLL_MAP_KDEVICEENTRY;

typedef struct tdVMMDLL_MAP_KDRIVERENTRY {
    QWORD va;                                       // Address of this object in memory.
    QWORD vaDriverStart;                            // Address of the loaded driver module in memory.
    QWORD cbDriverSize;                             // Size of the loaded driver module in memory.
    QWORD vaDeviceObject;                           // Address of the device object.
    union { LPSTR  uszName; LPWSTR wszName; };      // Driver name.
    union { LPSTR  uszPath; LPWSTR wszPath; };      // Driver path.
    union { LPSTR  uszServiceKeyName; LPWSTR wszServiceKeyName; }; // Service key name.
    QWORD MajorFunction[28];                        // Major function array.
} VMMDLL_MAP_KDRIVERENTRY, *PVMMDLL_MAP_KDRIVERENTRY;

typedef struct tdVMMDLL_MAP_KOBJECTENTRY {
    QWORD va;                                       // Address of this object in memory.
    QWORD vaParent;                                 // Address of parent object.
    DWORD _Filler;
    DWORD cvaChild;                                 // Number of child object addresses.
    PQWORD pvaChild;                                // Array of child object addresses.
    union { LPSTR uszName; LPWSTR wszName; };       // Object name.
    union { LPSTR uszType; LPWSTR wszType; };       // Object type
} VMMDLL_MAP_KOBJECTENTRY, *PVMMDLL_MAP_KOBJECTENTRY;

typedef struct tdVMMDLL_MAP_NETENTRY {
    DWORD dwPID;
    DWORD dwState;
    WORD _FutureUse3[3];
    WORD AF;                        // address family (IPv4/IPv6)
    struct {
        BOOL fValid;
        WORD _Reserved;
        WORD port;
        BYTE pbAddr[16];            // ipv4 = 1st 4 bytes, ipv6 = all bytes
        union { LPSTR  uszText; LPWSTR wszText; };          // U/W dependant
    } Src;
    struct {
        BOOL fValid;
        WORD _Reserved;
        WORD port;
        BYTE pbAddr[16];            // ipv4 = 1st 4 bytes, ipv6 = all bytes
        union { LPSTR  uszText; LPWSTR wszText; };          // U/W dependant
    } Dst;
    QWORD vaObj;
    QWORD ftTime;
    DWORD dwPoolTag;
    DWORD _FutureUse4;
    union { LPSTR  uszText; LPWSTR wszText; };              // U/W dependant
    DWORD _FutureUse2[4];
} VMMDLL_MAP_NETENTRY, *PVMMDLL_MAP_NETENTRY;

typedef struct tdVMMDLL_MAP_PHYSMEMENTRY {
    QWORD pa;
    QWORD cb;
} VMMDLL_MAP_PHYSMEMENTRY, *PVMMDLL_MAP_PHYSMEMENTRY;

typedef struct tdVMMDLL_MAP_USERENTRY {
    DWORD _FutureUse1[2];
    union { LPSTR  uszText; LPWSTR wszText; };              // U/W dependant
    ULONG64 vaRegHive;
    union { LPSTR  uszSID; LPWSTR wszSID; };                // U/W dependant
    DWORD _FutureUse2[2];
} VMMDLL_MAP_USERENTRY, *PVMMDLL_MAP_USERENTRY;

typedef enum tdVMMDLL_VM_TP {
    VMMDLL_VM_TP_UNKNOWN = 0,
    VMMDLL_VM_TP_HV      = 1,
    VMMDLL_VM_TP_HV_WHVP = 2
} VMMDLL_VM_TP;

typedef struct tdVMMDLL_MAP_VMENTRY {
    VMMVM_HANDLE hVM;
    union { LPSTR  uszName; LPWSTR wszName; };              // U/W dependant
    QWORD gpaMax;
    VMMDLL_VM_TP tp;
    BOOL fActive;
    BOOL fReadOnly;
    BOOL fPhysicalOnly;
    DWORD dwPartitionID;
    DWORD dwVersionBuild;
    VMMDLL_SYSTEM_TP tpSystem;
    DWORD dwParentVmmMountID;
    DWORD dwVmMemPID;
} VMMDLL_MAP_VMENTRY, *PVMMDLL_MAP_VMENTRY;

typedef struct tdVMMDLL_MAP_SERVICEENTRY {
    QWORD vaObj;
    DWORD dwOrdinal;
    DWORD dwStartType;
    SERVICE_STATUS ServiceStatus;
    union { LPSTR  uszServiceName; LPWSTR wszServiceName; QWORD _Reserved1; };  // U/W dependant
    union { LPSTR  uszDisplayName; LPWSTR wszDisplayName; QWORD _Reserved2; };  // U/W dependant
    union { LPSTR  uszPath;        LPWSTR wszPath;        QWORD _Reserved3; };  // U/W dependant
    union { LPSTR  uszUserTp;      LPWSTR wszUserTp;      QWORD _Reserved4; };  // U/W dependant
    union { LPSTR  uszUserAcct;    LPWSTR wszUserAcct;    QWORD _Reserved5; };  // U/W dependant
    union { LPSTR  uszImagePath;   LPWSTR wszImagePath;   QWORD _Reserved6; };  // U/W dependant
    DWORD dwPID;
    DWORD _FutureUse1;
    QWORD _FutureUse2;
} VMMDLL_MAP_SERVICEENTRY, *PVMMDLL_MAP_SERVICEENTRY;

typedef struct tdVMMDLL_MAP_PTE {
    DWORD dwVersion;                // VMMDLL_MAP_PTE_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // NULL or multi-wstr pointed into by VMMDLL_MAP_VADENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_PTEENTRY pMap[];     // map entries.
} VMMDLL_MAP_PTE, *PVMMDLL_MAP_PTE;

typedef struct tdVMMDLL_MAP_VAD {
    DWORD dwVersion;                // VMMDLL_MAP_VAD_VERSION
    DWORD _Reserved1[4];
    DWORD cPage;                    // # pages in vad map.
    PBYTE pbMultiText;              // NULL or multi-wstr pointed into by VMMDLL_MAP_VADENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_VADENTRY pMap[];     // map entries.
} VMMDLL_MAP_VAD, *PVMMDLL_MAP_VAD;

typedef struct tdVMMDLL_MAP_VADEX {
    DWORD dwVersion;                // VMMDLL_MAP_VADEX_VERSION
    DWORD _Reserved1[4];
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_VADEXENTRY pMap[];   // map entries.
} VMMDLL_MAP_VADEX, *PVMMDLL_MAP_VADEX;

typedef struct tdVMMDLL_MAP_MODULE {
    DWORD dwVersion;                // VMMDLL_MAP_MODULE_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMMDLL_MAP_MODULEENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_MODULEENTRY pMap[];  // map entries.
} VMMDLL_MAP_MODULE, *PVMMDLL_MAP_MODULE;

typedef struct tdVMMDLL_MAP_UNLOADEDMODULE {
    DWORD dwVersion;                // VMMDLL_MAP_UNLOADEDMODULE_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMMDLL_MAP_MODULEENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_UNLOADEDMODULEENTRY pMap[];  // map entries.
} VMMDLL_MAP_UNLOADEDMODULE, *PVMMDLL_MAP_UNLOADEDMODULE;

typedef struct tdVMMDLL_MAP_EAT {
    DWORD dwVersion;                // VMMDLL_MAP_EAT_VERSION
    DWORD dwOrdinalBase;
    DWORD cNumberOfNames;
    DWORD cNumberOfFunctions;
    DWORD cNumberOfForwardedFunctions;
    DWORD _Reserved1[3];
    QWORD vaModuleBase;
    QWORD vaAddressOfFunctions;
    QWORD vaAddressOfNames;
    PBYTE pbMultiText;              // multi-str pointed into by VMM_MAP_EATENTRY.wszFunction
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_EATENTRY pMap[];     // map entries.
} VMMDLL_MAP_EAT, *PVMMDLL_MAP_EAT;

typedef struct tdVMMDLL_MAP_IAT {
    DWORD dwVersion;                // VMMDLL_MAP_IAT_VERSION
    DWORD _Reserved1[5];
    QWORD vaModuleBase;
    PBYTE pbMultiText;              // multi-str pointed into by VMM_MAP_EATENTRY.[wszFunction|wszModule]
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_IATENTRY pMap[];     // map entries.
} VMMDLL_MAP_IAT, *PVMMDLL_MAP_IAT;

typedef struct tdVMMDLL_MAP_HEAP {
    DWORD dwVersion;                            // VMMDLL_MAP_HEAP_VERSION
    DWORD _Reserved1[7];
    PVMMDLL_MAP_HEAP_SEGMENTENTRY pSegments;    // heap segment entries.
    DWORD cSegments;                            // # heap segment entries.
    DWORD cMap;                                 // # map entries.
    VMMDLL_MAP_HEAPENTRY pMap[];                // map entries.
} VMMDLL_MAP_HEAP, *PVMMDLL_MAP_HEAP;

typedef struct tdVMMDLL_MAP_HEAPALLOC {
    DWORD dwVersion;                    // VMMDLL_MAP_HEAPALLOC_VERSION
    DWORD _Reserved1[7];
    PVOID _Reserved2[2];
    DWORD cMap;                         // # map entries.
    VMMDLL_MAP_HEAPALLOCENTRY pMap[];   // map entries.
} VMMDLL_MAP_HEAPALLOC, *PVMMDLL_MAP_HEAPALLOC;

typedef struct tdVMMDLL_MAP_THREAD {
    DWORD dwVersion;                // VMMDLL_MAP_THREAD_VERSION
    DWORD _Reserved[8];
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_THREADENTRY pMap[];  // map entries.
} VMMDLL_MAP_THREAD, *PVMMDLL_MAP_THREAD;

typedef struct tdVMMDLL_MAP_THREAD_CALLSTACK {
    DWORD dwVersion;                // VMMDLL_MAP_THREAD_CALLSTACK_VERSION
    DWORD _Reserved1[6];
    DWORD dwPID;
    DWORD dwTID;
    DWORD cbText;
    union { LPSTR  uszText; LPWSTR wszText; };  // U/W dependant
    PBYTE pbMultiText;              // multi-str pointed into by VMM_MAP_EATENTRY.[wszFunction|wszModule]
    DWORD cbMultiText;
    DWORD cMap;
    VMMDLL_MAP_THREAD_CALLSTACKENTRY pMap[0];
} VMMDLL_MAP_THREAD_CALLSTACK, *PVMMDLL_MAP_THREAD_CALLSTACK;

typedef struct tdVMMDLL_MAP_HANDLE {
    DWORD dwVersion;                // VMMDLL_MAP_HANDLE_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMMDLL_MAP_HANDLEENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_HANDLEENTRY pMap[];  // map entries.
} VMMDLL_MAP_HANDLE, *PVMMDLL_MAP_HANDLE;

typedef struct tdVMMDLL_MAP_POOL {
    DWORD dwVersion;                // VMMDLL_MAP_POOL_VERSION
    DWORD _Reserved1[6];
    DWORD cbTotal;                  // # bytes to represent this pool map object
    PDWORD piTag2Map;               // dword map array (size: cMap): tag index to map index.
    PVMMDLL_MAP_POOLENTRYTAG pTag;  // tag entries.
    DWORD cTag;                     // # tag entries.
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_POOLENTRY pMap[];    // map entries.
} VMMDLL_MAP_POOL, *PVMMDLL_MAP_POOL;

typedef struct tdVMMDLL_MAP_KOBJECT {
    DWORD dwVersion;                // VMMDLL_MAP_KOBJECT_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMM_MAP_NETENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_KOBJECTENTRY pMap[]; // map entries.
} VMMDLL_MAP_KOBJECT, *PVMMDLL_MAP_KOBJECT;

typedef struct tdVMMDLL_MAP_KDRIVER {
    DWORD dwVersion;                // VMMDLL_MAP_KDRIVER_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMM_MAP_NETENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_KDRIVERENTRY pMap[]; // map entries.
} VMMDLL_MAP_KDRIVER, *PVMMDLL_MAP_KDRIVER;

typedef struct tdVMMDLL_MAP_KDEVICE {
    DWORD dwVersion;                // VMMDLL_MAP_KDEVICE_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMM_MAP_NETENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_KDEVICEENTRY pMap[]; // map entries.
} VMMDLL_MAP_KDEVICE, *PVMMDLL_MAP_KDEVICE;

typedef struct tdVMMDLL_MAP_NET {
    DWORD dwVersion;                // VMMDLL_MAP_NET_VERSION
    DWORD _Reserved1;
    PBYTE pbMultiText;              // multi-wstr pointed into by VMM_MAP_NETENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_NETENTRY pMap[];     // map entries.
} VMMDLL_MAP_NET, *PVMMDLL_MAP_NET;

typedef struct tdVMMDLL_MAP_PHYSMEM {
    DWORD dwVersion;                // VMMDLL_MAP_PHYSMEM_VERSION
    DWORD _Reserved1[5];
    DWORD cMap;                     // # map entries.
    DWORD _Reserved2;
    VMMDLL_MAP_PHYSMEMENTRY pMap[]; // map entries.
} VMMDLL_MAP_PHYSMEM, *PVMMDLL_MAP_PHYSMEM;

typedef struct tdVMMDLL_MAP_USER {
    DWORD dwVersion;                // VMMDLL_MAP_USER_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMMDLL_MAP_USERENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_USERENTRY pMap[];    // map entries.
} VMMDLL_MAP_USER, *PVMMDLL_MAP_USER;

typedef struct tdVMMDLL_MAP_VM {
    DWORD dwVersion;                // VMMDLL_MAP_VM_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMMDLL_MAP_VMENTRY.wszText
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_VMENTRY pMap[];      // map entries.
} VMMDLL_MAP_VM, *PVMMDLL_MAP_VM;

typedef struct tdVMMDLL_MAP_SERVICE {
    DWORD dwVersion;                // VMMDLL_MAP_SERVICE_VERSION
    DWORD _Reserved1[5];
    PBYTE pbMultiText;              // multi-wstr pointed into by VMMDLL_MAP_SERVICEENTRY.wsz*
    DWORD cbMultiText;
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_SERVICEENTRY pMap[]; // map entries.
} VMMDLL_MAP_SERVICE, *PVMMDLL_MAP_SERVICE;

/*
* Retrieve the memory map entries based on hardware page tables (PTEs) for the process.
* Entries returned are sorted on VMMDLL_MAP_PTEENTRY.va
* CALLER FREE: VMMDLL_MemFree(*ppVadMap)
* -- hVMM
* -- dwPID
* -- fIdentifyModules = try identify modules as well (= slower)
* -- ppPteMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetPteU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ BOOL fIdentifyModules, _Out_ PVMMDLL_MAP_PTE *ppPteMap);
_Success_(return) BOOL VMMDLL_Map_GetPteW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ BOOL fIdentifyModules, _Out_ PVMMDLL_MAP_PTE *ppPteMap);

/*
* Retrieve memory map entries based on virtual address descriptor (VAD) for the process.
* Entries returned are sorted on VMMDLL_MAP_VADENTRY.vaStart
* CALLER FREE: VMMDLL_MemFree(*ppVadMap)
* -- hVMM
* -- dwPID
* -- fIdentifyModules = try identify modules as well (= slower)
* -- ppVadMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetVadU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ BOOL fIdentifyModules, _Out_ PVMMDLL_MAP_VAD *ppVadMap);
_Success_(return) BOOL VMMDLL_Map_GetVadW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ BOOL fIdentifyModules, _Out_ PVMMDLL_MAP_VAD *ppVadMap);

/*
* Retrieve extended memory map information about a sub-set of the memory map.
* CALLER FREE: VMMDLL_MemFree(*ppVadExMap)
* -- hVMM
* -- oPage = offset in number of pages from process start.
* -- cPage = number of pages to process from oPages base.
* -- ppVadExMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Map_GetVadEx(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ DWORD oPage, _In_ DWORD cPage, _Out_ PVMMDLL_MAP_VADEX *ppVadExMap);

/*
* Retrieve the modules (.dlls) for the specified process.
* CALLER FREE: VMMDLL_MemFree(*ppModuleMap)
* -- hVMM
* -- dwPID
* -- ppModuleMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- flags = optional flags as specified by VMMDLL_MODULE_FLAG_*
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetModuleU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Out_ PVMMDLL_MAP_MODULE *ppModuleMap, _In_ DWORD flags);
_Success_(return) BOOL VMMDLL_Map_GetModuleW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Out_ PVMMDLL_MAP_MODULE *ppModuleMap, _In_ DWORD flags);

/*
* Retrieve a module (.dll) entry given a process and module name.
* CALLER FREE: VMMDLL_MemFree(*ppModuleMapEntry)
* -- hVMM
* -- dwPID
* -- [uw]szModuleName = module name (or ""/NULL for 1st module entry).
* -- ppModuleMapEntry =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- flags = optional flags as specified by VMMDLL_MODULE_FLAG_*
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetModuleFromNameU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_opt_ LPCSTR  uszModuleName, _Out_ PVMMDLL_MAP_MODULEENTRY *ppModuleMapEntry, _In_ DWORD flags);
_Success_(return) BOOL VMMDLL_Map_GetModuleFromNameW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_opt_ LPCWSTR wszModuleName, _Out_ PVMMDLL_MAP_MODULEENTRY *ppModuleMapEntry, _In_ DWORD flags);

/*
* Retrieve the unloaded modules (.dll/.sys) for the specified process.
* CALLER FREE: VMMDLL_MemFree(*ppUnloadedModuleMap)
* -- hVMM
* -- dwPID
* -- ppUnloadedModuleMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetUnloadedModuleU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Out_ PVMMDLL_MAP_UNLOADEDMODULE *ppUnloadedModuleMap);
_Success_(return) BOOL VMMDLL_Map_GetUnloadedModuleW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Out_ PVMMDLL_MAP_UNLOADEDMODULE *ppUnloadedModuleMap);

/*
* Retrieve the module exported functions from the export address table (EAT).
* CALLER FREE: VMMDLL_MemFree(*ppEatMap)
* -- hVMM
* -- dwPID
* -- [uw]szModuleName
* -- ppEatMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetEATU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCSTR  uszModuleName, _Out_ PVMMDLL_MAP_EAT *ppEatMap);
_Success_(return) BOOL VMMDLL_Map_GetEATW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCWSTR wszModuleName, _Out_ PVMMDLL_MAP_EAT *ppEatMap);

/*
* Retrieve the module imported functions from the import address table (IAT).
* CALLER FREE: VMMDLL_MemFree(*ppIatMap)
* -- hVMM
* -- dwPID
* -- [uw]szModuleName
* -- ppIatMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetIATU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCSTR  uszModuleName, _Out_ PVMMDLL_MAP_IAT *ppIatMap);
_Success_(return) BOOL VMMDLL_Map_GetIATW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCWSTR wszModuleName, _Out_ PVMMDLL_MAP_IAT *ppIatMap);

/*
* Retrieve the heaps for the specified process.
* CALLER FREE: VMMDLL_MemFree(*ppHeapMap)
* -- hVMM
* -- dwPID
* -- ppHeapMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetHeap(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Out_ PVMMDLL_MAP_HEAP *ppHeapMap);

/*
* Retrieve heap allocations for the specified process heap.
* CALLER FREE: VMMDLL_MemFree(*ppHeapAllocMap)
* -- hVMM
* -- dwPID
* -- qwHeapNumOrAddress = number or virtual address of heap to retrieve allocations from.
* -- ppHeapAllocMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetHeapAlloc(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ QWORD qwHeapNumOrAddress, _Out_ PVMMDLL_MAP_HEAPALLOC *ppHeapAllocMap);

/*
* Retrieve the threads for the specified process.
* Entries returned are sorted on VMMDLL_MAP_THREADENTRY.dwTID
* CALLER FREE: VMMDLL_MemFree(*ppThreadMap)
* -- hVMM
* -- dwPID
* -- ppThreadMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetThread(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Out_ PVMMDLL_MAP_THREAD *ppThreadMap);

/*
* Retrieve the thread callstack for a specific thread.
* Callstack retrieval is:
* - supported for x64 user-mode threads.
* - a best-effort operation and may not always succeed.
* - may download a large amounts of pdb symbol data from Microsoft.
* CALLER FREE: VMMDLL_MemFree(*ppThreadCallstack)
* -- hVMM
* -- dwPID
* -- dwTID
* -- flags = 0, VMMDLL_FLAG_NOCACHE or VMM_FLAG_FORCECACHE_READ
* -- ppThreadCallstack
* -- return
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetThread_CallstackU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ DWORD dwTID, _In_ DWORD flags, _Out_ PVMMDLL_MAP_THREAD_CALLSTACK *ppThreadCallstack);
_Success_(return) BOOL VMMDLL_Map_GetThread_CallstackW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ DWORD dwTID, _In_ DWORD flags, _Out_ PVMMDLL_MAP_THREAD_CALLSTACK *ppThreadCallstack);

/*
* Retrieve the handles for the specified process.
* Entries returned are sorted on VMMDLL_MAP_HANDLEENTRY.dwHandle
* CALLER FREE: VMMDLL_MemFree(*ppHandleMap)
* -- hVMM
* -- dwPID
* -- ppHandleMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetHandleU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Out_ PVMMDLL_MAP_HANDLE *ppHandleMap);
_Success_(return) BOOL VMMDLL_Map_GetHandleW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _Out_ PVMMDLL_MAP_HANDLE *ppHandleMap);

/*
* Retrieve the physical memory ranges from the operating system physical memory map.
* CALLER FREE: VMMDLL_MemFree(*ppPhysMemMap)
* -- hVMM
* -- ppPhysMemMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree()
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetPhysMem(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_PHYSMEM *ppPhysMemMap);

/*
* Retrieve the kernel device map - consisting of kernel device objects.
* CALLER FREE: VMMDLL_MemFree(*ppKDeviceMap)
* -- hVMM
* -- ppKDeviceMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetKDeviceU(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_KDEVICE *ppKDeviceMap);
_Success_(return) BOOL VMMDLL_Map_GetKDeviceW(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_KDEVICE *ppKDeviceMap);

/*
* Retrieve the kernel driver map - consisting of kernel driver objects.
* CALLER FREE: VMMDLL_MemFree(*ppKDriverMap)
* -- hVMM
* -- ppKDriverMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetKDriverU(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_KDRIVER *ppKDriverMap);
_Success_(return) BOOL VMMDLL_Map_GetKDriverW(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_KDRIVER *ppKDriverMap);

/*
* Retrieve the kernel object map - consisting of kernel objects such as devices, drivers and other objects.
* CALLER FREE: VMMDLL_MemFree(*ppKObjectMap)
* -- hVMM
* -- ppKObjectMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetKObjectU(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_KOBJECT *ppKObjectMap);
_Success_(return) BOOL VMMDLL_Map_GetKObjectW(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_KOBJECT *ppKObjectMap);

/*
* Retrieve the pool map - consisting of kernel allocated pool entries.
* The pool map pMap is sorted by allocation virtual address.
* The pool map pTag is sorted by pool tag.
* NB! The pool map may contain both false negatives/positives.
* NB! The pool map relies on debug symbols. Please ensure supporting files
*     symsrv.dll, dbghelp.dll and info.db (found in the binary distribution)
*     is put alongside vmm.dll. (On Linux the .dll files aren't necessary).
* CALLER FREE: VMMDLL_MemFree(*ppPoolMap)
* -- hVMM
* -- ppPoolMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- flags = VMMDLL_POOLMAP_FLAG*
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetPool(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_POOL *ppPoolMap, _In_ DWORD flags);

/*
* Retrieve the network connection map - consisting of active network connections,
* listening sockets and other networking functionality.
* CALLER FREE: VMMDLL_MemFree(*ppNetMap)
* -- hVMM
* -- ppNetMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetNetU(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_NET *ppNetMap);
_Success_(return) BOOL VMMDLL_Map_GetNetW(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_NET *ppNetMap);

/*
* Retrieve the non well known users that are detected in the target system.
* NB! There may be more users in the system than the ones that are detected,
* only users with mounted registry hives may currently be detected - this is
* the normal behaviour for users with active processes.
* CALLER FREE: VMMDLL_MemFree(*ppUserMap)
* -- hVMM
* -- ppUserMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetUsersU(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_USER *ppUserMap);
_Success_(return) BOOL VMMDLL_Map_GetUsersW(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_USER *ppUserMap);

/*
* Retrieve a map of detected child virtual machines (VMs).
* NB! May fail if called shortly after vmm init unless option: -waitinitialize
* CALLER FREE: VMMDLL_MemFree(*ppVmMap)
* -- hVMM
* -- ppVmMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetVMU(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_VM *ppVmMap);
_Success_(return) BOOL VMMDLL_Map_GetVMW(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_VM *ppVmMap);

/*
* Retrieve the services currently known by the service control manager (SCM).
* CALLER FREE: VMMDLL_MemFree(*ppServiceMap)
* -- hVMM
* -- ppServiceMap = ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_Map_GetServicesU(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_SERVICE *ppServiceMap);
_Success_(return) BOOL VMMDLL_Map_GetServicesW(_In_ VMM_HANDLE hVMM, _Out_ PVMMDLL_MAP_SERVICE *ppServiceMap);



//-----------------------------------------------------------------------------
// MEMORY SEARCH FUNCTIONALITY:
//-----------------------------------------------------------------------------

#define VMMDLL_MEM_SEARCH_VERSION           0xfe3e0003
#define VMMDLL_MEM_SEARCH_MAXLENGTH         32

typedef struct tdVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY {
    DWORD cbAlign;                                  // byte-align at 2^x - 0, 1, 2, 4, 8, 16, .. bytes.
    DWORD cb;                                       // number of bytes to search (1-32).
    BYTE pb[VMMDLL_MEM_SEARCH_MAXLENGTH];
    BYTE pbSkipMask[VMMDLL_MEM_SEARCH_MAXLENGTH];   // skip bitmask '0' = match, '1' = wildcard.
} VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY, *PVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY;

/*
* Context to populate and use in the VMMDLL_MemSearch() function.
*/
typedef struct tdVMMDLL_MEM_SEARCH_CONTEXT {
    DWORD dwVersion;
    DWORD _Filler[2];
    BOOL fAbortRequested;       // may be set by caller to abort processing prematurely.
    DWORD cMaxResult;           // # max result entries. '0' = 1 entry. max 0x10000 entries.
    DWORD cSearch;              // number of search entries.
    PVMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY pSearch;     // pointer to an array of cSearch entries.
    QWORD vaMin;                // min address to search (page-aligned).
    QWORD vaMax;                // max address to search (page-aligned), if 0 max memory is assumed.
    QWORD vaCurrent;            // current address (may be read by caller).
    DWORD _Filler2;
    DWORD cResult;              // number of search hits.
    QWORD cbReadTotal;          // total number of bytes read.
    PVOID pvUserPtrOpt;         // optional pointer set by caller (used for context passing to callbacks)
    // optional result callback function.
    // use of callback function disable ordinary result in ppObAddressResult.
    // return = continue search(TRUE), abort search(FALSE).
    BOOL(*pfnResultOptCB)(_In_ struct tdVMMDLL_MEM_SEARCH_CONTEXT *ctx, _In_ QWORD va, _In_ DWORD iSearch);
    // non-recommended features:
    QWORD ReadFlags;            // read flags as in VMMDLL_FLAG_*
    BOOL fForcePTE;             // force PTE method for virtual address reads.
    BOOL fForceVAD;             // force VAD method for virtual address reads.
    // optional filter callback function for virtual address reads:
    // for ranges inbetween vaMin:vaMax callback with pte or vad entry.
    // return: read from range(TRUE), do not read from range(FALSE).
    BOOL(*pfnFilterOptCB)(_In_ struct tdVMMDLL_MEM_SEARCH_CONTEXT *ctx, _In_opt_ PVMMDLL_MAP_PTEENTRY pePte, _In_opt_ PVMMDLL_MAP_VADENTRY peVad);
} VMMDLL_MEM_SEARCH_CONTEXT, *PVMMDLL_MEM_SEARCH_CONTEXT;

/*
* Search for binary data in an address space specified by the supplied context.
* For more information about the different search parameters please see the
* struct definition: VMMDLL_MEM_SEARCH_CONTEXT
* Search may take a long time. It's not recommended to run this interactively.
* To cancel a search prematurely set the fAbortRequested flag in the context
* and wait a short while.
* CALLER FREE: VMMDLL_MemFree(*ppva)
* -- hVMM
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- ctx
* -- ppva = pointer to receive addresses found. Free'd with VMMDLL_MemFree().
* -- pcva = pointer to receive number of addresses in ppva. not bytes!
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_MemSearch(
    _In_ VMM_HANDLE hVMM,
    _In_ DWORD dwPID,
    _Inout_ PVMMDLL_MEM_SEARCH_CONTEXT ctx,
    _Out_opt_ PQWORD *ppva,
    _Out_opt_ PDWORD pcva
);



//-----------------------------------------------------------------------------
// MEMORY YARA SEARCH FUNCTIONALITY:
// The yara search functionality requires that vmmyara.[dll|so] is present.
// The vmmyara project is found at: https://github.com/ufrisk/vmmyara
//-----------------------------------------------------------------------------

// =========== START SHARED STRUCTS WITH <vmmdll.h/vmmyara.h> ===========
#ifndef VMMYARA_RULE_MATCH_DEFINED
#define VMMYARA_RULE_MATCH_DEFINED

#define VMMYARA_RULE_MATCH_VERSION          0xfedc0005
#define VMMYARA_RULE_MATCH_TAG_MAX          27
#define VMMYARA_RULE_MATCH_META_MAX         32
#define VMMYARA_RULE_MATCH_STRING_MAX       16
#define VMMYARA_RULE_MATCH_OFFSET_MAX       24

/*
* Struct with match information upon a match in VmmYara_RulesScanMemory().
*/
typedef struct tdVMMYARA_RULE_MATCH {
    DWORD dwVersion;                    // VMMYARA_RULE_MATCH_VERSION
    DWORD flags;
    LPSTR szRuleIdentifier;
    DWORD cTags;
    LPSTR szTags[VMMYARA_RULE_MATCH_TAG_MAX];
    DWORD cMeta;
    struct {
        LPSTR szIdentifier;
        LPSTR szString;
    } Meta[VMMYARA_RULE_MATCH_META_MAX];
    DWORD cStrings;
    struct {
        LPSTR szString;
        DWORD cMatch;
        SIZE_T cbMatchOffset[VMMYARA_RULE_MATCH_OFFSET_MAX];
    } Strings[VMMYARA_RULE_MATCH_STRING_MAX];
} VMMYARA_RULE_MATCH, *PVMMYARA_RULE_MATCH;

#endif /* VMMYARA_RULE_MATCH_DEFINED */

#ifndef VMMYARA_SCAN_MEMORY_CALLBACK_DEFINED
#define VMMYARA_SCAN_MEMORY_CALLBACK_DEFINED

/*
* Callback function to be called by VmmYara_RulesScanMemory() upon a match.
* -- pvContext = user context set in call to VmmYara_ScanMemory().
* -- pRuleMatch = pointer to match information.
* -- pbBuffer = the memory buffer that was scanned.
* -- cbBuffer = the size of the memory buffer that was scanned.
* -- return = return TRUE to continue scanning, FALSE to stop scanning.
*/
typedef BOOL(*VMMYARA_SCAN_MEMORY_CALLBACK)(
    _In_ PVOID pvContext,
    _In_ PVMMYARA_RULE_MATCH pRuleMatch,
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    _In_ SIZE_T cbBuffer
);

#endif /* VMMYARA_SCAN_MEMORY_CALLBACK_DEFINED */
// =========== END SHARED STRUCTS WITH <vmmdll.h/vmmyara.h> ===========

#define VMMDLL_YARA_CONFIG_VERSION                  0xdec30001
#define VMMDLL_YARA_MEMORY_CALLBACK_CONTEXT_VERSION 0xdec40002
#define VMMDLL_YARA_CONFIG_MAX_RESULT               0x00010000      // max 65k results.

typedef struct tdVMMDLL_YARA_CONFIG *PVMMDLL_YARA_CONFIG;           // forward declaration.

/*
* Callback function to tell whether a section of memory should be scanned or not.
* -- ctx = pointer to PVMMDLL_YARA_CONFIG context.
* -- pePte = pointer to PTE entry if the memory region is backed by PTE map. Otherwise NULL.
* -- peVad = pointer to VAD entry if the memory region is backed by VAD map. Otherwise NULL.
* -- return = return TRUE to scan the memory region, FALSE to skip it.
*/
typedef BOOL(*VMMYARA_SCAN_FILTER_CALLBACK)(
    _In_ PVMMDLL_YARA_CONFIG ctx,
    _In_opt_ PVMMDLL_MAP_PTEENTRY pePte,
    _In_opt_ PVMMDLL_MAP_VADENTRY peVad
);

/*
* Yara search configuration struct.
*/
typedef struct tdVMMDLL_YARA_CONFIG {
    DWORD dwVersion;            // VMMDLL_YARA_CONFIG_VERSION
    DWORD _Filler[2];
    BOOL fAbortRequested;       // may be set by caller to abort processing prematurely.
    DWORD cMaxResult;           // # max result entries. max 0x10000 entries. 0 = max entries.
    DWORD cRules;               // number of rules to use - if compiled rules only 1 is allowed.
    LPSTR *pszRules;            // array of rules to use - either filenames or in-memory rules.
    QWORD vaMin;
    QWORD vaMax;
    QWORD vaCurrent;            // current address (may be read by caller).
    DWORD _Filler2;
    DWORD cResult;              // number of search hits.
    QWORD cbReadTotal;          // total number of bytes read.
    PVOID pvUserPtrOpt;         // optional pointer set by caller (used for context passing to callbacks)
    // match callback function (recommended but optional).
    // return = continue search(TRUE), abort search(FALSE).
    VMMYARA_SCAN_MEMORY_CALLBACK pfnScanMemoryCB;
    // non-recommended features:
    QWORD ReadFlags;            // read flags as in VMMDLL_FLAG_*
    BOOL fForcePTE;             // force PTE method for virtual address reads.
    BOOL fForceVAD;             // force VAD method for virtual address reads.
    // optional filter callback function for virtual address reads:
    // for ranges inbetween vaMin:vaMax callback with pte or vad entry.
    // return: read from range(TRUE), do not read from range(FALSE).
    VMMYARA_SCAN_FILTER_CALLBACK pfnFilterOptCB;
    PVOID pvUserPtrOpt2;        // optional pointer set by caller (not used by MemProcFS).
    QWORD _Reserved;
} VMMDLL_YARA_CONFIG, *PVMMDLL_YARA_CONFIG;

/*
* Yara search callback struct which created by MemProcFS internally and is
* passed to the callback function supplied by the caller in VMMDLL_YaraSearch().
*/
typedef struct tdVMMDLL_YARA_MEMORY_CALLBACK_CONTEXT {
    DWORD dwVersion;
    DWORD dwPID;
    PVOID pUserContext;
    QWORD vaObject;
    QWORD va;
    PBYTE pb;
    DWORD cb;
    LPSTR uszTag[1];    // min 1 char (but may be more).
} VMMDLL_YARA_MEMORY_CALLBACK_CONTEXT, *PVMMDLL_YARA_MEMORY_CALLBACK_CONTEXT;

/*
* Perform a yara search in the address space of a process.
* NB! it may take a long time for this function to return.
* -- hVMM
* -- dwPID - PID of target process, (DWORD)-1 to read physical memory.
* -- pYaraConfig
* -- ppva = pointer to receive addresses found. Free'd with VMMDLL_MemFree().
* -- pcva = pointer to receive number of addresses in ppva. not bytes!
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_YaraSearch(
    _In_ VMM_HANDLE hVMM,
    _In_ DWORD dwPID,
    _In_ PVMMDLL_YARA_CONFIG pYaraConfig,
    _Out_opt_ PQWORD *ppva,
    _Out_opt_ PDWORD pcva
);



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC PAGE FRAME NUMBER (PFN) FUNCTIONALITY BELOW
//-----------------------------------------------------------------------------

#define VMMDLL_MAP_PFN_VERSION              1

#define VMMDLL_PFN_FLAG_NORMAL              0
#define VMMDLL_PFN_FLAG_EXTENDED            1

static LPCSTR VMMDLL_PFN_TYPE_TEXT[] = { "Zero", "Free", "Standby", "Modifiy", "ModNoWr", "Bad", "Active", "Transit" };
static LPCSTR VMMDLL_PFN_TYPEEXTENDED_TEXT[] = { "-", "Unused", "ProcPriv", "PageTable", "LargePage", "DriverLock", "Shareable", "File" };

typedef enum tdVMMDLL_MAP_PFN_TYPE {
    VmmDll_PfnTypeZero = 0,
    VmmDll_PfnTypeFree = 1,
    VmmDll_PfnTypeStandby = 2,
    VmmDll_PfnTypeModified = 3,
    VmmDll_PfnTypeModifiedNoWrite = 4,
    VmmDll_PfnTypeBad = 5,
    VmmDll_PfnTypeActive = 6,
    VmmDll_PfnTypeTransition = 7
} VMMDLL_MAP_PFN_TYPE;

typedef enum tdVMMDLL_MAP_PFN_TYPEEXTENDED {
    VmmDll_PfnExType_Unknown = 0,
    VmmDll_PfnExType_Unused = 1,
    VmmDll_PfnExType_ProcessPrivate = 2,
    VmmDll_PfnExType_PageTable = 3,
    VmmDll_PfnExType_LargePage = 4,
    VmmDll_PfnExType_DriverLocked = 5,
    VmmDll_PfnExType_Shareable = 6,
    VmmDll_PfnExType_File = 7,
} VMMDLL_MAP_PFN_TYPEEXTENDED;

typedef struct tdVMMDLL_MAP_PFNENTRY {
    DWORD dwPfn;
    VMMDLL_MAP_PFN_TYPEEXTENDED tpExtended;
    struct {        // Only valid if active non-prototype PFN
        union {
            DWORD dwPid;
            DWORD dwPfnPte[5];  // PFN of paging levels 1-4 (x64)
        };
        QWORD va;               // valid if non-zero
    } AddressInfo;
    QWORD vaPte;
    QWORD OriginalPte;
    union {
        DWORD _u3;
        struct {
            WORD ReferenceCount;
            // MMPFNENTRY
            BYTE PageLocation       : 3;    // Pos 0  - VMMDLL_MAP_PFN_TYPE
            BYTE WriteInProgress    : 1;    // Pos 3
            BYTE Modified           : 1;    // Pos 4
            BYTE ReadInProgress     : 1;    // Pos 5
            BYTE CacheAttribute     : 2;    // Pos 6
            BYTE Priority           : 3;    // Pos 0
            BYTE Rom_OnProtectedStandby : 1;// Pos 3
            BYTE InPageError        : 1;    // Pos 4
            BYTE KernelStack_SystemChargedPage : 1; // Pos 5
            BYTE RemovalRequested   : 1;    // Pos 6
            BYTE ParityError        : 1;    // Pos 7
        };
    };
    union {
        QWORD _u4;
        struct {
            DWORD PteFrame;
            DWORD PteFrameHigh      : 4;    // Pos 32
            DWORD _Reserved         : 21;   // Pos 36
            DWORD PrototypePte      : 1;    // Pos 57
            DWORD PageColor         : 6;    // Pos 58
        };
    };
    DWORD _FutureUse[6];
} VMMDLL_MAP_PFNENTRY, *PVMMDLL_MAP_PFNENTRY;

typedef struct tdVMMDLL_MAP_PFN {
    DWORD dwVersion;
    DWORD _Reserved1[5];
    DWORD cMap;                     // # map entries.
    VMMDLL_MAP_PFNENTRY pMap[];     // map entries.
} VMMDLL_MAP_PFN, *PVMMDLL_MAP_PFN;

/*
* Retrieve information about scattered PFNs. The PFNs are returned in order of
* in which they are stored in the pPfns set.
* -- hVMM
* -- pPfns
* -- cPfns
* -- pPfnMap = buffer of minimum byte length *pcbPfnMap or NULL.
* -- pcbPfnMap = pointer to byte count of pPhysMemMap buffer.
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Map_GetPfn(
    _In_ VMM_HANDLE hVMM,
    _In_reads_(cPfns) DWORD pPfns[],
    _In_ DWORD cPfns,
    _Out_writes_bytes_opt_(*pcbPfnMap) PVMMDLL_MAP_PFN pPfnMap,
    _Inout_ PDWORD pcbPfnMap
);

/*
* Retrieve PFN information:
* CALLER FREE: VMMDLL_MemFree(*ppPfnMap)
* -- hVMM
* -- pPfns = PFNs to retrieve.
* -- cPfns = number of PFNs to retrieve.
* -- ppPfnMap =  ptr to receive result on success. must be free'd with VMMDLL_MemFree().
* -- flags = optional flags as specified by VMMDLL_PFN_FLAG_*
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_Map_GetPfnEx(
    _In_ VMM_HANDLE hVMM,
    _In_reads_(cPfns) DWORD pPfns[],
    _In_ DWORD cPfns,
    _Out_ PVMMDLL_MAP_PFN *ppPfnMap,
    _In_ DWORD flags
);



//-----------------------------------------------------------------------------
// VMM PROCESS FUNCTIONALITY BELOW:
// Functionality below is mostly relating to Windows processes.
//-----------------------------------------------------------------------------

/*
* Retrieve an active process given it's name. Please note that if multiple
* processes with the same name exists only one will be returned. If required to
* parse all processes with the same name please iterate over the PID list by
* calling VMMDLL_PidList together with VMMDLL_ProcessGetInformation.
* -- hVMM
* -- szProcName = process name case insensitive.
* -- pdwPID = pointer that will receive PID on success.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_PidGetFromName(_In_ VMM_HANDLE hVMM, _In_ LPCSTR szProcName, _Out_ PDWORD pdwPID);

/*
* List the PIDs in the system.
* -- hVMM
* -- pPIDs = DWORD array of at least number of PIDs in system, or NULL.
* -- pcPIDs = size of (in number of DWORDs) pPIDs array on entry, number of PIDs in system on exit.
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_PidList(_In_ VMM_HANDLE hVMM, _Out_writes_opt_(*pcPIDs) PDWORD pPIDs, _Inout_ PSIZE_T pcPIDs);

#define VMMDLL_PROCESS_INFORMATION_MAGIC        0xc0ffee663df9301e
#define VMMDLL_PROCESS_INFORMATION_VERSION      7

typedef enum tdVMMDLL_PROCESS_INTEGRITY_LEVEL {
    VMMDLL_PROCESS_INTEGRITY_LEVEL_UNKNOWN      = 0,
    VMMDLL_PROCESS_INTEGRITY_LEVEL_UNTRUSTED    = 1,
    VMMDLL_PROCESS_INTEGRITY_LEVEL_LOW          = 2,
    VMMDLL_PROCESS_INTEGRITY_LEVEL_MEDIUM       = 3,
    VMMDLL_PROCESS_INTEGRITY_LEVEL_MEDIUMPLUS   = 4,
    VMMDLL_PROCESS_INTEGRITY_LEVEL_HIGH         = 5,
    VMMDLL_PROCESS_INTEGRITY_LEVEL_SYSTEM       = 6,
    VMMDLL_PROCESS_INTEGRITY_LEVEL_PROTECTED    = 7,
} VMMDLL_PROCESS_INTEGRITY_LEVEL;

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
    struct {
        ULONG64 vaEPROCESS;
        ULONG64 vaPEB;
        ULONG64 _Reserved1;
        BOOL fWow64;
        DWORD vaPEB32;                  // WoW64 only
        DWORD dwSessionId;
        ULONG64 qwLUID;
        CHAR szSID[MAX_PATH];
        VMMDLL_PROCESS_INTEGRITY_LEVEL IntegrityLevel;
    } win;
} VMMDLL_PROCESS_INFORMATION, *PVMMDLL_PROCESS_INFORMATION;

/*
* Retrieve various process information from a PID. Process information such as
* name, page directory bases and the process state may be retrieved.
* -- hVMM
* -- dwPID
* -- pProcessInformation = if null, size is given in *pcbProcessInfo
* -- pcbProcessInformation = size of pProcessInfo (in bytes) on entry and exit
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_ProcessGetInformation(
    _In_ VMM_HANDLE hVMM,
    _In_ DWORD dwPID,
    _Inout_opt_ PVMMDLL_PROCESS_INFORMATION pProcessInformation,
    _In_ PSIZE_T pcbProcessInformation
);

/*
* Retrieve various information from all processes (including terminated).
* CALLER FREE : VMMDLL_MemFree(*ppProcessInformationAll)
* -- hVMM
* -- ptr to receive result array of pcProcessInformation items on success.
*    Must be free'd with VMMDLL_MemFree().
* -- ptr to DWORD to receive number of items processes on success.
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_ProcessGetInformationAll(
    _In_ VMM_HANDLE hVMM,
    _Out_ PVMMDLL_PROCESS_INFORMATION *ppProcessInformationAll,
    _Out_ PDWORD pcProcessInformation
);

#define VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_KERNEL           1
#define VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE       2
#define VMMDLL_PROCESS_INFORMATION_OPT_STRING_CMDLINE               3

/*
* Retrieve a string value belonging to a process. The function allocates a new
* string buffer and returns the requested string in it. The string is always
* NULL terminated. On failure NULL is returned.
* NB! CALLER IS RESPONSIBLE FOR VMMDLL_MemFree return value!
* CALLER FREE: VMMDLL_MemFree(return)
* -- hVMM
* -- dwPID
* -- fOptionString = string value to retrieve as given by VMMDLL_PROCESS_INFORMATION_OPT_STRING_*
* -- return - fail: NULL, success: the string - NB! must be VMMDLL_MemFree'd by caller!
*/
EXPORTED_FUNCTION _Success_(return != NULL)
LPSTR VMMDLL_ProcessGetInformationString(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ DWORD fOptionString);

/*
* Retrieve information about: Data Directories, Sections, Export Address Table
* and Import Address Table (IAT).
* If the pData == NULL upon entry the number of entries of the pData array must
* have in order to be able to hold the data is returned.
* -- hVMM
* -- dwPID
* -- [uw]szModule
* -- pData
* -- cData
* -- pcData
* -- return = success/fail.
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_ProcessGetDirectoriesU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCSTR  uszModule, _Out_writes_(16) PIMAGE_DATA_DIRECTORY pDataDirectories);
_Success_(return) BOOL VMMDLL_ProcessGetDirectoriesW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCWSTR wszModule, _Out_writes_(16) PIMAGE_DATA_DIRECTORY pDataDirectories);
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_ProcessGetSectionsU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCSTR  uszModule, _Out_writes_opt_(cSections) PIMAGE_SECTION_HEADER pSections, _In_ DWORD cSections, _Out_ PDWORD pcSections);
_Success_(return) BOOL VMMDLL_ProcessGetSectionsW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCWSTR wszModule, _Out_writes_opt_(cSections) PIMAGE_SECTION_HEADER pSections, _In_ DWORD cSections, _Out_ PDWORD pcSections);

/*
* Retrieve the virtual address of a given function inside a process/module.
* -- hVMM
* -- dwPID
* -- [uw]szModuleName
* -- szFunctionName
* -- return = virtual address of function, zero on fail.
*/
EXPORTED_FUNCTION
_Success_(return != 0) ULONG64 VMMDLL_ProcessGetProcAddressU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCSTR  uszModuleName, _In_ LPCSTR szFunctionName);
_Success_(return != 0) ULONG64 VMMDLL_ProcessGetProcAddressW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCWSTR wszModuleName, _In_ LPCSTR szFunctionName);

/*
* Retrieve the base address of a given module.
* -- hVMM
* -- dwPID
* -- [uw]szModuleName
* -- return = virtual address of module base, zero on fail.
*/
EXPORTED_FUNCTION
_Success_(return != 0) ULONG64 VMMDLL_ProcessGetModuleBaseU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCSTR  uszModuleName);
_Success_(return != 0) ULONG64 VMMDLL_ProcessGetModuleBaseW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCWSTR wszModuleName);



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC DEBUGGING / SYMBOL FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Load a .pdb symbol file and return its associated module name upon success.
* -- hVMM
* -- dwPID
* -- vaModuleBase
* -- szModuleName = buffer to receive module name upon success.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_PdbLoad(
    _In_ VMM_HANDLE hVMM,
    _In_ DWORD dwPID,
    _In_ ULONG64 vaModuleBase,
    _Out_writes_(MAX_PATH) LPSTR szModuleName
);

/*
* Retrieve a symbol virtual address given a module name and a symbol name.
* NB! not all modules may exist - initially only module "nt" is available.
* NB! if multiple modules have the same name the 1st to be added will be used.
* -- hVMM
* -- szModule
* -- cbSymbolAddressOrOffset = symbol virtual address or symbol offset.
* -- szSymbolName = buffer to receive symbol name upon success.
* -- pdwSymbolDisplacement = displacement from the beginning of the symbol.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_PdbSymbolName(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCSTR szModule,
    _In_ QWORD cbSymbolAddressOrOffset,
    _Out_writes_(MAX_PATH) LPSTR szSymbolName,
    _Out_opt_ PDWORD pdwSymbolDisplacement
);

/*
* Retrieve a symbol virtual address given a module name and a symbol name.
* NB! not all modules may exist - initially only module "nt" is available.
* NB! if multiple modules have the same name the 1st to be added will be used.
* -- hVMM
* -- szModule
* -- szSymbolName
* -- pvaSymbolAddress
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_PdbSymbolAddress(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCSTR szModule,
    _In_ LPCSTR szSymbolName,
    _Out_ PULONG64 pvaSymbolAddress
);

/*
* Retrieve a type size given a module name and a type name.
* NB! not all modules may exist - initially only module "nt" is available.
* NB! if multiple modules have the same name the 1st to be added will be used.
* -- hVMM
* -- szModule
* -- szTypeName
* -- pcbTypeSize
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_PdbTypeSize(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCSTR szModule,
    _In_ LPCSTR szTypeName,
    _Out_ PDWORD pcbTypeSize
);

/*
* Locate the offset of a type child - typically a sub-item inside a struct.
* NB! not all modules may exist - initially only module "nt" is available.
* NB! if multiple modules have the same name the 1st to be added will be used.
* -- hVMM
* -- szModule
* -- uszTypeName
* -- uszTypeChildName
* -- pcbTypeChildOffset
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_PdbTypeChildOffset(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCSTR szModule,
    _In_ LPCSTR uszTypeName,
    _In_ LPCSTR uszTypeChildName,
    _Out_ PDWORD pcbTypeChildOffset
);



//-----------------------------------------------------------------------------
// WINDOWS SPECIFIC REGISTRY FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#define VMMDLL_REGISTRY_HIVE_INFORMATION_MAGIC      0xc0ffee653df8d01e
#define VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION    4

typedef struct td_VMMDLL_REGISTRY_HIVE_INFORMATION {
    ULONG64 magic;
    WORD wVersion;
    WORD wSize;
    BYTE _FutureReserved1[0x34];
    ULONG64 vaCMHIVE;
    ULONG64 vaHBASE_BLOCK;
    DWORD cbLength;
    CHAR uszName[128];
    CHAR uszNameShort[32 + 1];
    CHAR uszHiveRootPath[MAX_PATH];
    QWORD _FutureReserved[0x10];
} VMMDLL_REGISTRY_HIVE_INFORMATION, *PVMMDLL_REGISTRY_HIVE_INFORMATION;

/*
* Retrieve information about the registry hives in the target system.
* -- pHives = buffer of cHives * sizeof(VMMDLL_REGISTRY_HIVE_INFORMATION) to
              receive info about all hives. NULL to receive # hives in pcHives.
* -- cHives
* -- pcHives = if pHives == NULL: # total hives. if pHives: # read hives.
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_WinReg_HiveList(
    _In_ VMM_HANDLE hVMM,
    _Out_writes_(cHives) PVMMDLL_REGISTRY_HIVE_INFORMATION pHives,
    _In_ DWORD cHives,
    _Out_ PDWORD pcHives
);

/*
* Read a contigious arbitrary amount of registry hive memory and report the
* number of bytes read in pcbRead.
* NB! Address space does not include regf registry hive file header!
* -- hVMM
* -- vaCMHive
* -- ra
* -- pb
* -- cb
* -- pcbReadOpt
* -- flags = flags as in VMMDLL_FLAG_*
* -- return = success/fail. NB! reads may report as success even if 0 bytes are
*        read - it's recommended to verify pcbReadOpt parameter.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_WinReg_HiveReadEx(
    _In_ VMM_HANDLE hVMM,
    _In_ ULONG64 vaCMHive,
    _In_ DWORD ra,
    _Out_ PBYTE pb,
    _In_ DWORD cb,
    _Out_opt_ PDWORD pcbReadOpt,
    _In_ ULONG64 flags
);

/*
* Write a virtually contigious arbitrary amount of memory to a registry hive.
* NB! Address space does not include regf registry hive file header!
* -- hVMM
* -- vaCMHive
* -- ra
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_WinReg_HiveWrite(
    _In_ VMM_HANDLE hVMM,
    _In_ ULONG64 vaCMHive,
    _In_ DWORD ra,
    _In_ PBYTE pb,
    _In_ DWORD cb
);

/*
* Enumerate registry sub keys - similar to WINAPI function 'RegEnumKeyExW.'
* Please consult WINAPI function documentation for information.
* May be called with HKLM base or virtual address of CMHIVE base examples:
*   1) 'HKLM\SOFTWARE\Key\SubKey'
*   2) 'HKLM\ORPHAN\SAM\Key\SubKey'              (orphan key)
*   3) '0x<vaCMHIVE>\ROOT\Key\SubKey'
*   4) '0x<vaCMHIVE>\ORPHAN\Key\SubKey'          (orphan key)
* -- hVMM
* -- uszFullPathKey
* -- dwIndex = sub-key index 0..N (-1 for key).
* -- lpName
* -- lpcchName
* -- lpftLastWriteTime
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_WinReg_EnumKeyExU(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCSTR uszFullPathKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(*lpcchName) LPSTR lpName,
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
* -- hVMM
* -- uszFullPathKey
* -- dwIndex
* -- lpValueName
* -- lpcchValueName
* -- lpType
* -- lpData
* -- lpcbData
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_WinReg_EnumValueU(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCSTR uszFullPathKey,
    _In_ DWORD dwIndex,
    _Out_writes_opt_(*lpcchValueName) LPSTR lpValueName,
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
* -- hVMM
* -- uszFullPathKeyValue
* -- lpType
* -- lpData
* -- lpcbData
* -- return
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_WinReg_QueryValueExU(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCSTR uszFullPathKeyValue,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_opt_(*lpcbData) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
);

/*
* Enumerate registry sub keys - similar to WINAPI function 'RegEnumKeyExW.'
* Please consult WINAPI function documentation for information.
* May be called with HKLM base or virtual address of CMHIVE base examples:
*   1) 'HKLM\SOFTWARE\Key\SubKey'
*   2) 'HKLM\ORPHAN\SAM\Key\SubKey'              (orphan key)
*   3) '0x<vaCMHIVE>\ROOT\Key\SubKey'
*   4) '0x<vaCMHIVE>\ORPHAN\Key\SubKey'          (orphan key)
* -- hVMM
* -- wszFullPathKey
* -- dwIndex = sub-key index 0..N (-1 for key).
* -- lpName
* -- lpcchName
* -- lpftLastWriteTime
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinReg_EnumKeyExW(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCWSTR wszFullPathKey,
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
* -- hVMM
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
    _In_ VMM_HANDLE hVMM,
    _In_ LPCWSTR wszFullPathKey,
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
* -- hVMM
* -- wszFullPathKeyValue
* -- lpType
* -- lpData
* -- lpcbData
* -- return
*/
_Success_(return)
BOOL VMMDLL_WinReg_QueryValueExW(
    _In_ VMM_HANDLE hVMM,
    _In_ LPCWSTR wszFullPathKeyValue,
    _Out_opt_ LPDWORD lpType,
    _Out_writes_opt_(*lpcbData) LPBYTE lpData,
    _When_(lpData == NULL, _Out_opt_) _When_(lpData != NULL, _Inout_opt_) LPDWORD lpcbData
);



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

/*
* Retrieve information about the import address table IAT thunk for an imported
* function. This includes the virtual address of the IAT thunk which is useful
* for hooking.
* -- hVMM
* -- dwPID
* -- [uw]szModuleName
* -- szImportModuleName
* -- szImportFunctionName
* -- pThunkIAT
* -- return
*/
EXPORTED_FUNCTION
_Success_(return) BOOL VMMDLL_WinGetThunkInfoIATU(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCSTR  uszModuleName, _In_ LPCSTR szImportModuleName, _In_ LPCSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT);
_Success_(return) BOOL VMMDLL_WinGetThunkInfoIATW(_In_ VMM_HANDLE hVMM, _In_ DWORD dwPID, _In_ LPCWSTR wszModuleName, _In_ LPCSTR szImportModuleName, _In_ LPCSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT);



//-----------------------------------------------------------------------------
// VMM VM FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

/*
* Retrieve a VMM handle given a VM handle.
* This is not allowed on physical memory only VMs.
* This VMM handle should be closed by calling VMMDLL_Close().
* -- hVMM
* -- hVM
* -- return
*/
EXPORTED_FUNCTION _Success_(return != NULL)
VMM_HANDLE VMMDLL_VmGetVmmHandle(_In_ VMM_HANDLE hVMM, _In_ VMMVM_HANDLE hVM);

/*
* Initialize a scatter handle which is used to efficiently read/write memory in
* virtual machines (VMs).
* CALLER CLOSE: VMMDLL_Scatter_CloseHandle(return)
* -- hVMM
* -- hVM = virtual machine handle; acquired from VMMDLL_Map_GetVM*)
* -- flags = optional flags as given by VMMDLL_FLAG_*
* -- return = handle to be used in VMMDLL_Scatter_* functions.
*/
EXPORTED_FUNCTION _Success_(return != NULL)
VMMDLL_SCATTER_HANDLE VMMDLL_VmScatterInitialize(_In_ VMM_HANDLE hVMM, _In_ VMMVM_HANDLE hVM);

/*
* Read virtual machine (VM) guest physical address (GPA) memory.
* -- hVMM
* -- hVM = virtual machine handle.
* -- qwGPA
* -- pb
* -- cb
* -- return = success/fail (depending if all requested bytes are read or not).
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_VmMemRead(_In_ VMM_HANDLE hVMM, _In_ VMMVM_HANDLE hVM, _In_ ULONG64 qwGPA, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Write virtual machine (VM) guest physical address (GPA) memory.
* -- hVMM
* -- hVM = virtual machine handle.
* -- qwGPA
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_VmMemWrite(_In_ VMM_HANDLE hVMM, _In_ VMMVM_HANDLE hVM, _In_ ULONG64 qwGPA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Scatter read virtual machine (VM) guest physical address (GPA) memory.
* Non contiguous 4096-byte pages. Not cached.
* -- hVmm
* -- hVM = virtual machine handle.
* -- ppMEMsGPA
* -- cpMEMsGPA
* -- flags = (reserved future use).
* -- return = the number of successfully read items.
*/
EXPORTED_FUNCTION
DWORD VMMDLL_VmMemReadScatter(_In_ VMM_HANDLE hVMM, _In_ VMMVM_HANDLE hVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA, _In_ DWORD flags);

/*
* Scatter write virtual machine (VM) guest physical address (GPA) memory.
* Non contiguous 4096-byte pages. Not cached.
* -- hVmm
* -- hVM = virtual machine handle.
* -- ppMEMsGPA
* -- cpMEMsGPA
* -- return = the number of hopefully successfully written items.
*/
EXPORTED_FUNCTION
DWORD VMMDLL_VmMemWriteScatter(_In_ VMM_HANDLE hVMM, _In_ VMMVM_HANDLE hVM, _Inout_ PPMEM_SCATTER ppMEMsGPA, _In_ DWORD cpMEMsGPA);

/*
* Translate a virtual machine (VM) guest physical address (GPA) to:
* (1) Physical Address (PA) _OR_ (2) Virtual Address (VA) in 'vmmem' process.
* -- hVMM
* -- HVM
* -- qwGPA = guest physical address to translate.
* -- pPA = translated physical address (if exists).
* -- pVA = translated virtual address inside 'vmmem' process (if exists).
* -- return = success/fail.
*/
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_VmMemTranslateGPA(_In_ VMM_HANDLE H, _In_ VMMVM_HANDLE hVM, _In_ ULONG64 qwGPA, _Out_opt_ PULONG64 pPA, _Out_opt_ PULONG64 pVA);



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
EXPORTED_FUNCTION _Success_(return)
BOOL VMMDLL_UtilFillHexAscii(
    _In_reads_opt_(cb) PBYTE pb,
    _In_ DWORD cb,
    _In_ DWORD cbInitialOffset,
    _Out_writes_opt_(*pcsz) LPSTR sz,
    _Inout_ PDWORD pcsz
);



//-----------------------------------------------------------------------------
// DEFAULT (WINDOWS ONLY) COMPATIBILITY FUNCTION DEFINITIONS BELOW:
//-----------------------------------------------------------------------------

#ifdef _WIN32
#define VMMDLL_VfsList                  VMMDLL_VfsListW
#define VMMDLL_VfsRead                  VMMDLL_VfsReadW
#define VMMDLL_VfsWrite                 VMMDLL_VfsWriteW
#define VMMDLL_ProcessGetDirectories    VMMDLL_ProcessGetDirectoriesW
#define VMMDLL_ProcessGetSections       VMMDLL_ProcessGetSectionsW
#define VMMDLL_ProcessGetProcAddress    VMMDLL_ProcessGetProcAddressW
#define VMMDLL_ProcessGetModuleBase     VMMDLL_ProcessGetModuleBaseW
#define VMMDLL_Map_GetPte               VMMDLL_Map_GetPteW
#define VMMDLL_Map_GetVad               VMMDLL_Map_GetVadW
#define VMMDLL_Map_GetModule            VMMDLL_Map_GetModuleW
#define VMMDLL_Map_GetModuleFromName    VMMDLL_Map_GetModuleFromNameW
#define VMMDLL_Map_GetUnloadedModule    VMMDLL_Map_GetUnloadedModuleW
#define VMMDLL_Map_GetEAT               VMMDLL_Map_GetEATW
#define VMMDLL_Map_GetIAT               VMMDLL_Map_GetIATW
#define VMMDLL_Map_GetHandle            VMMDLL_Map_GetHandleW
#define VMMDLL_Map_GetNet               VMMDLL_Map_GetNetW
#define VMMDLL_Map_GetUsers             VMMDLL_Map_GetUsersW
#define VMMDLL_Map_GetServices          VMMDLL_Map_GetServicesW
#define VMMDLL_WinGetThunkInfoIAT       VMMDLL_WinGetThunkInfoIATW
#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __VMMDLL_H__ */
