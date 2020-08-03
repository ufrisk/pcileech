// vmmx.h : definitions related to memory process file system functionality.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMX_H__
#define __VMMX_H__
#include "pcileech.h"

#ifdef WIN32
#include <vmmdll.h>

/*
* Load the memory process file system mode using the default LeechCore device.
* The memory process file system is initialized in either updating mode if the
* fRefresh flag is set and the LeechCore memory is volatile; otherwise it's
* started in non-updating mode.
* -- fRefresh
* -- fMemMapAuto
* -- return
*/
_Success_(return)
BOOL Vmmx_Initialize(_In_ BOOL fRefresh, _In_ BOOL fMemMapAuto);

/*
* Close an open MemProcFS instance.
*/
VOID Vmmx_Close();



//-------------------------------------------------------------------------------
// Functions below are wrapper functions around VMM.DLL functions and
// exists primarily for Linux compatibility reasons (dummy functions).
//-------------------------------------------------------------------------------

_Success_(return)
inline BOOL Vmmx_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    return VMMDLL_MemReadEx(dwPID, qwVA, pb, cb, pcbReadOpt, flags);
}

_Success_(return)
inline BOOL Vmmx_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwA, _In_reads_(cb) PBYTE pb, _In_ DWORD cb)
{
    return VMMDLL_MemWrite(dwPID, qwA, pb, cb);
}

#endif /* WIN32 */
#ifdef LINUX

#include "pcileech.h"
#include "oscompatibility.h"
#define VMMDLL_FLAG_NOCACHE                        0x0001

BOOL Vmmx_Initialize(_In_ BOOL fRefresh, _In_ BOOL fMemMapAuto);
VOID Vmmx_Close();
BOOL Vmmx_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags);
BOOL Vmmx_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb);
BOOL Vmmx_PhysMemMapAsText(_Out_writes_bytes_(0x01000000) LPSTR sz);

#endif /* LINUX */
#endif /* __VMMX_H__ */
