// memprocfs_prx.h : implementation related to dynamically loaded memory process file system functionality.
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef WIN32

#include "vmmprx.h"
#include "vmmdll.h"

typedef struct tdVMMPRX_CONTEXT {
    HMODULE hModuleVmm;
    struct {
        BOOL(*VMMDLL_Initialize)(_In_ DWORD argc, _In_ LPSTR argv[]);
        BOOL(*VMMDLL_Close)();
        BOOL(*VMMDLL_Refresh)(_In_ DWORD dwReserved);
        BOOL(*VMMDLL_MemRead)(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb);
        BOOL(*VMMDLL_MemReadEx)(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags);
        BOOL(*VMMDLL_MemReadPage)(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_bytecount_(4096) PBYTE pbPage);
        BOOL(*VMMDLL_MemWrite)(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb);
        BOOL(*VMMDLL_MemVirt2Phys)(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA);

        BOOL(*VMMDLL_ProcessGetSections)(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData);
        ULONG64(*VMMDLL_ProcessGetModuleBase)(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName);
        ULONG64(*VMMDLL_ProcessGetProcAddress)(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szFunctionName);
        BOOL(*VMMDLL_ProcessMap_GetPte)(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbPteMap) PVMMDLL_MAP_PTE pPteMap, _Inout_ PDWORD pcbPteMap, _In_ BOOL fIdentifyModules);
        BOOL(*VMMDLL_ProcessMap_GetModuleFromName)(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_ PVMMDLL_MAP_MODULEENTRY pModuleMapEntry);

        BOOL(*VMMDLL_PidList)(_Out_opt_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs);
        BOOL(*VMMDLL_PidGetFromName)(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID);
        BOOL(*VMMDLL_ProcessGetInformation)(_In_ DWORD dwPID, _Inout_opt_ PVMMDLL_PROCESS_INFORMATION pProcessInformation, _In_ PSIZE_T pcbProcessInformation);

        BOOL(*VMMDLL_WinGetThunkInfoIAT)(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT);
    } fn;
} VMMPRX_CONTEXT, *PVMMPRX_CONTEXT;

VOID VmmPrx_Close()
{
    PVMMPRX_CONTEXT ctx = (PVMMPRX_CONTEXT)ctxMain->hMemProcFS;
    if(ctx) {
        ctx->fn.VMMDLL_Close();
        FreeLibrary(ctx->hModuleVmm);
        LocalFree(ctx);
        ctxMain->hMemProcFS = NULL;
    }
}

_Success_(return)
BOOL VmmPrx_Initialize(_In_ BOOL fRefresh)
{
    BOOL result;
    QWORD i, va;
    PVMMPRX_CONTEXT ctx = NULL;
    LPCSTR szFUNCTIONS[] = {
        "VMMDLL_Initialize",
        "VMMDLL_Close",
        "VMMDLL_Refresh",
        "VMMDLL_MemRead",
        "VMMDLL_MemReadEx",
        "VMMDLL_MemReadPage",
        "VMMDLL_MemWrite",
        "VMMDLL_MemVirt2Phys",

        "VMMDLL_ProcessGetSections",
        "VMMDLL_ProcessGetModuleBase",
        "VMMDLL_ProcessGetProcAddress",
        "VMMDLL_ProcessMap_GetPte",
        "VMMDLL_ProcessMap_GetModuleFromName",

        "VMMDLL_PidList",
        "VMMDLL_PidGetFromName",
        "VMMDLL_ProcessGetInformation",

        "VMMDLL_WinGetThunkInfoIAT"
    };
    // 1: Allocate and dynamically retrieve function addresses
    ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(VMMPRX_CONTEXT));
    if(!ctx) { goto fail; }
    ctx->hModuleVmm = LoadLibraryA("vmm.dll");
    if(!ctx->hModuleVmm) {
        printf(
            "MemProcFS: Cannot load memory process file system 'vmm.dll'                 \n" \
            "           Ensure 'vmm.dll' in same directory as PCILeech.exe               \n" \
            "           Download 'vmm.dll' at: https://github.com/ufrisk/MemProcFS       \n" \
            "           Also ensure correct Visual Studio Redistributables are installed.\n" );
        goto fail;
    }
    for(i = 0; i < (sizeof(szFUNCTIONS) / sizeof(LPCSTR)); i++) {
        va = (QWORD)GetProcAddress(ctx->hModuleVmm, szFUNCTIONS[i]);
        if(!va) { goto fail; }
        *(PQWORD)((QWORD)&ctx->fn + i * sizeof(QWORD)) = va;
    }
    // 2: Initialize vmm.dll
    result = fRefresh ?
        ctx->fn.VMMDLL_Initialize(3, (LPSTR[]) { "", "-device", "existing" }) :
        ctx->fn.VMMDLL_Initialize(4, (LPSTR[]) { "", "-device", "existing", "-norefresh" });
    if(!result) {
        printf("MemProcFS: Failed to initialize memory process file system in call to vmm.dll!VMMDLL_Initialize\n");
        goto fail;
    }
    ctxMain->hMemProcFS = (HANDLE)ctx;
    return TRUE;
fail:
    if(ctx->hModuleVmm) { FreeLibrary(ctx->hModuleVmm); }
    LocalFree(ctx);
    return FALSE;
}

_Success_(return)
BOOL VmmPrx_Refresh(_In_ DWORD dwReserved)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_Refresh(dwReserved);
}

_Success_(return)
BOOL VmmPrx_MemRead(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_MemRead(dwPID, qwVA, pb, cb);
}

_Success_(return)
BOOL VmmPrx_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_MemReadEx(dwPID, qwVA, pb, cb, pcbReadOpt, flags);
}

_Success_(return)
BOOL VmmPrx_MemReadPage(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_bytecount_(4096) PBYTE pbPage)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_MemReadPage(dwPID, qwVA, pbPage);
}

_Success_(return)
BOOL VmmPrx_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_MemWrite(dwPID, qwVA, pb, cb);
}

_Success_(return)
BOOL VmmPrx_MemVirt2Phys(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_MemVirt2Phys(dwPID, qwVA, pqwPA);
}

ULONG64 VmmPrx_ProcessGetModuleBase(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_ProcessGetModuleBase(dwPID, wszModuleName);
}

ULONG64 VmmPrx_ProcessGetProcAddress(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szFunctionName)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_ProcessGetProcAddress(dwPID, wszModuleName, szFunctionName);
}

_Success_(return)
BOOL VmmPrx_ProcessMap_GetPte(_In_ DWORD dwPID, _Out_writes_bytes_opt_(*pcbPteMap) PVMMDLL_MAP_PTE pPteMap, _Inout_ PDWORD pcbPteMap, _In_ BOOL fIdentifyModules)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_ProcessMap_GetPte(dwPID, pPteMap, pcbPteMap, fIdentifyModules);
}

_Success_(return)
BOOL VmmPrx_ProcessMap_GetModuleFromName(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _Out_ PVMMDLL_MAP_MODULEENTRY pModuleMapEntry)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_ProcessMap_GetModuleFromName(dwPID, wszModuleName, pModuleMapEntry);
}

_Success_(return)
BOOL VmmPrx_ProcessGetSections(_In_ DWORD dwPID, _In_ LPWSTR wszModule, _Out_opt_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_ProcessGetSections(dwPID, wszModule, pData, cData, pcData);
}

_Success_(return)
BOOL VmmPrx_PidList(_Out_opt_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_PidList(pPIDs, pcPIDs);
}

_Success_(return)
BOOL VmmPrx_PidGetFromName(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_PidGetFromName(szProcName, pdwPID);
}

_Success_(return)
BOOL VmmPrx_ProcessGetInformation(_In_ DWORD dwPID, _Inout_opt_ PVMMDLL_PROCESS_INFORMATION pProcessInformation, _In_ PSIZE_T pcbProcessInformation)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_ProcessGetInformation(dwPID, pProcessInformation, pcbProcessInformation);
}

_Success_(return)
BOOL VmmPrx_WinGetThunkInfoIAT(_In_ DWORD dwPID, _In_ LPWSTR wszModuleName, _In_ LPSTR szImportModuleName, _In_ LPSTR szImportFunctionName, _Out_ PVMMDLL_WIN_THUNKINFO_IAT pThunkInfoIAT)
{
    return ((PVMMPRX_CONTEXT)ctxMain->hMemProcFS)->fn.VMMDLL_WinGetThunkInfoIAT(dwPID, wszModuleName, szImportModuleName, szImportFunctionName, pThunkInfoIAT);
}

#endif /* WIN32 */
#ifdef LINUX

#include "oscompatibility.h"
BOOL VmmPrx_Initialize(_In_ BOOL fRefresh) { return FALSE; }
VOID VmmPrx_Close() { return; }
BOOL VmmPrx_MemReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags) { return FALSE; }
BOOL VmmPrx_MemWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _In_ PBYTE pb, _In_ DWORD cb) { return FALSE; }

#endif /* LINUX */
