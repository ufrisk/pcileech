// vmmprx.h : definitions related to dynamically loaded memory process file system functionality.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMM_PRX_H__
#define __VMM_PRX_H__
#include "pcileech.h"

#ifdef WIN32
#include "vmmdll.h"

/*
* Load the memory process file system mode using the default LeechCore device.
* The memory process file system is initialized in either updating mode if the
* fRefresh flag is set and the LeechCore memory is volatile; otherwise it's
* started in non-updating mode.
*/
_Success_(return)
BOOL VmmPrx_Initialize(_In_ BOOL fRefresh);

/*
* Close any references to the memory process file system and perform necessary
* cleanup actions.
*/
VOID VmmPrx_Close();

/*
* Functions below are wrapped around functions in vmm.dll - please see the
* corresponding functions in vmmdll.h for additional information.
*/
_Success_(return)
BOOL VmmPrx_Refresh(_In_ DWORD dwReserved);

_Success_(return)
BOOL VmmPrx_MemRead(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb);

_Success_(return)
BOOL VmmPrx_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags);

_Success_(return)
BOOL VmmPrx_MemReadPage(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_bytecount_(4096) PBYTE pbPage);

_Success_(return)
BOOL VmmPrx_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb);

_Success_(return)
BOOL VmmPrx_MemVirt2Phys(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA);

ULONG64 VmmPrx_ProcessGetModuleBase(_In_ DWORD dwPID, _In_ LPSTR szModuleName);
ULONG64 VmmPrx_ProcessGetProcAddress(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szFunctionName);

_Success_(return)
BOOL VmmPrx_ProcessGetMemoryMap(_In_ DWORD dwPID, _Out_opt_ PVMMDLL_MEMMAP_ENTRY pMemMapEntries, _Inout_ PULONG64 pcMemMapEntries, _In_ BOOL fIdentifyModules);

_Success_(return)
BOOL VmmPrx_ProcessGetSections(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData);

_Success_(return)
BOOL VmmPrx_ProcessGetModuleFromName(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _Out_ PVMMDLL_MODULEMAP_ENTRY pModuleEntry);

_Success_(return)
BOOL VmmPrx_PidList(_Out_opt_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs);

_Success_(return)
BOOL VmmPrx_PidGetFromName(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID);

_Success_(return)
BOOL VmmPrx_ProcessGetInformation(_In_ DWORD dwPID, _Inout_opt_ PVMMDLL_PROCESS_INFORMATION pProcessInformation, _In_ PSIZE_T pcbProcessInformation);

_Success_(return)
BOOL VmmPrx_WinGetThunkInfoIAT(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT);

#endif /* WIN32 */
#ifdef LINUX

#define PVMMDLL_MEMMAP_ENTRY            PVOID
#define PIMAGE_SECTION_HEADER           PVOID
#define PVMMDLL_MODULEMAP_ENTRY         PVOID
#define PVMMDLL_PROCESS_INFORMATION     PVOID
#define VMMDLL_FLAG_NOCACHE            0x0001

BOOL VmmPrx_Initialize(_In_ BOOL fRefresh);
VOID VmmPrx_Close();
BOOL VmmPrx_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags);
BOOL VmmPrx_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb);

#endif /* LINUX */
#endif /* __VMM_PRX_H__ */
