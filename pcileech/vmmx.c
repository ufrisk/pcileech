// vmmx.h : implementation of external VMM/MemProcFS functionality with linux compatible dummy functions.
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef WIN32

#include <stdio.h>
#include <vmmdll.h>
#include "vmmx.h"
#include "pcileech.h"

/*
* Close an open MemProcFS instance.
*/
VOID Vmmx_Close()
{
    VMMDLL_Close();
    ctxMain->fVmmInitialized = FALSE;
}

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
BOOL Vmmx_Initialize(_In_ BOOL fRefresh,  _In_ BOOL fMemMapAuto)
{
    DWORD cParams = 3;
    LPSTR szParams[] = { "", "-device", "existing", "", "", "" };

    if(!ctxMain->fVmmInitialized) {
        if(fRefresh) {
            szParams[cParams++] = "-norefresh";
        }
        if(fMemMapAuto) {
            szParams[cParams++] = "-memmap";
            szParams[cParams++] = "auto";
        }
        ctxMain->fVmmInitialized = VMMDLL_Initialize(cParams, szParams);
        if(!ctxMain->fVmmInitialized) {
            printf("MemProcFS: Failed to initialize memory process file system in call to vmm.dll!VMMDLL_Initialize\n");
        }
    }
    return ctxMain->fVmmInitialized;
}

#endif /* WIN32 */
#ifdef LINUX

#include "vmmx.h"

#define VMMDLL_FLAG_NOCACHE                        0x0001

BOOL Vmmx_Initialize(_In_ BOOL fRefresh, _In_ BOOL fMemMapAuto) { return FALSE; }
VOID Vmmx_Close() { return; }
BOOL Vmmx_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags) { return FALSE; }
BOOL Vmmx_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb) { return FALSE; }

#endif /* LINUX */
