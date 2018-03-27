// vmmvfs.h : definitions related to virtual memory management / virtual file system interfacing.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMVFS_H__
#define __VMMVFS_H__
#ifdef WIN32
#include "pcileech.h"
#include "vfs.h"

/*
* Allocate and populate the ppfi struct with "proc" data about directories and
* files.
* NB! The caller must LocalFree the ppfi struct which is allocated by this fn.
* -- ctx
* -- wcsFileName = full path file name
* -- ppfi        = output buffer
* -- pcfi        = count output buffer
* -- return
*/
BOOL VmmVfsListFiles(_Inout_ PPCILEECH_CONTEXT ctx, _In_ LPCWSTR wcsFileName, _Out_ PVFS_RESULT_FILEINFO *ppfi, _Out_ PQWORD pcfi);

/*
* Read the contents of a file into the caller supplied buffer. This file may be
* a memory file or any other file in the "proc" virtual file system.
* -- ctx
* -- wcsFileName = full path file name
* -- pb          = buffer
* -- cb          = bytes to read/size of pb
* -- pcbRead     = bytes actually read
* -- cbOffset    = offset where to start read compared to file start
*/
NTSTATUS VmmVfsReadFile(_Inout_ PPCILEECH_CONTEXT ctx, _In_ LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset);

/*
* Write the contents of a file into the caller supplied buffer. This file may be
* a memory file or any other file in the "proc" virtual file system.
* -- ctx
* -- wcsFileName = full path file name
* -- pb          = buffer
* -- cb          = bytes to read/size of pb
* -- pcbWrite    = bytes actually read
* -- cbOffset    = offset where to start read compared to file start
*/
NTSTATUS VmmVfsWriteFile(_Inout_ PPCILEECH_CONTEXT ctx, _In_ LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset);

#endif /* WIN32 */
#endif /* __VMMVFS_H__ */
