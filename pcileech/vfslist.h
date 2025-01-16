// vfslist.h : definitions related to virtual file system support.
//
// (c) Ulf Frisk, 2018-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VFSLIST_H__
#define __VFSLIST_H__

#ifdef _WIN32
#include <Windows.h>
typedef unsigned __int64                QWORD, *PQWORD;
#else
#include "oscompatibility.h"
#endif /* _WIN32 */
#include <vmmdll.h>

typedef struct tdVFS_ENTRY {
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    QWORD cbFileSize;
    DWORD dwFileAttributes;
    BOOL fDirectory;
    CHAR uszName[2 * MAX_PATH];
} VFS_ENTRY, *PVFS_ENTRY;

typedef void(*PFN_VFSLIST_CALLBACK)(_In_ PVFS_ENTRY pVfsEntry, _In_opt_ PVOID ctx);

/*
* Clear cached directory entries and/or files.
* -- uszPath = the directory path to clear including/excluding file name.
*/
VOID VfsList_Clear(_In_ LPSTR uszPath);

/*
* Retrieve information about a single entry inside a directory.
* -- uszPath
* -- uszFile
* -- pVfsEntry
* -- pfPathValid = receives if wszPath is valid or not.
* -- return
*/
_Success_(return)
BOOL VfsList_GetSingle(_In_ LPSTR uszPath, _In_ LPSTR uszFile, _Out_ PVFS_ENTRY pVfsEntry, _Out_ PBOOL pfPathValid);

/*
* List a directory using a callback function
* -- uszPath
* -- ctx = optional context to pass along to callback function.
* -- pfnListCallback = callback function called one time per directory entry.
* -- return = TRUE if directory exists, otherwise FALSE.
*/
BOOL VfsList_ListDirectory(_In_ LPSTR uszPath, _In_opt_ PVOID ctx, _In_opt_ PFN_VFSLIST_CALLBACK pfnListCallback);

#ifdef _WIN32

typedef int(__stdcall *PFN_VFSLISTW_CALLBACK)(_In_ PWIN32_FIND_DATAW pFindData, _In_opt_ PVOID ctx);

/*
* Retrieve information about a single entry inside a directory (Windows WCHAR version).
* -- wszPath
* -- wszFile
* -- pFindData
* -- pfPathValid = receives if wszPath is valid or not.
* -- return
*/
_Success_(return)
BOOL VfsList_GetSingleW(_In_ LPWSTR wszPath, _In_ LPWSTR wszFile, _Out_ PWIN32_FIND_DATAW pFindData, _Out_ PBOOL pfPathValid);

/*
* List a directory using a callback function (Windows WCHAR version).
* -- wszPath
* -- ctx = optional context to pass along to callback function.
* -- pfnListCallback = callback function called one time per directory entry.
* -- return = TRUE if directory exists, otherwise FALSE.
*/
BOOL VfsList_ListDirectoryW(_In_ LPWSTR wszPath, _In_opt_ PVOID ctx, _In_opt_ PFN_VFSLISTW_CALLBACK pfnListCallback);

#endif /* _WIN32 */

/*
* typedef for VMMDLL_VfsListU function or any functions that may override it.
*/
typedef BOOL(*VFS_LIST_U_PFN)(_In_ LPSTR  uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList);

/*
* Initialize the vfs list functionality.
* -- pfnVfsListU
* -- dwCacheValidMs
* -- cCacheMaxEntries
* -- fSingleThread = pfnVfsListU is single-threaded
* -- return
*/
_Success_(return)
BOOL VfsList_Initialize(_In_ VFS_LIST_U_PFN pfnVfsListU, _In_ DWORD dwCacheValidMs, _In_ DWORD cCacheMaxEntries, _In_ BOOL fSingleThread);

/*
* Close and clean up the vfs list functionality.
*/
VOID VfsList_Close();

#endif /* __VFSLIST_H__ */
