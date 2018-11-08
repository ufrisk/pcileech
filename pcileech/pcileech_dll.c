// pcileech.c : implementation of dynamic library (dll) functionality.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "pcileech_dll.h"
#include "pcileech.h"
#include "device.h"
#include "vmm.h"
#include "vmmproc.h"

#ifdef _WINDLL

// ----------------------------------------------------------------------------
// Synchronization macro below. The VMM isn't thread safe so it's important to
// serialize access to it over the VMM MasterLock. This master lock is shared
// with internal VMM housekeeping functionality.
// ----------------------------------------------------------------------------
#define CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(fn)   {                        \
    BOOL result;                                                            \
    PCRITICAL_SECTION pMasterLock;                                          \
    if(!g_ctx || !g_ctx->ctxPcileech || !g_ctx->ctxPcileech->hVMM) {        \
        return FALSE;                                                       \
    }                                                                       \
    pMasterLock = &((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM)->MasterLock;    \
    EnterCriticalSection(pMasterLock);                                      \
    result = g_ctx->ctxPcileech->hVMM && fn;                                \
    LeaveCriticalSection(pMasterLock);                                      \
    return result;                                                          \
}

// ----------------------------------------------------------------------------
// DLL housekeeping functionality below - incl. global context variable setup:
// ----------------------------------------------------------------------------

typedef struct tdPCILEECH_DLL_CONTEXT {
    PPCILEECH_CONTEXT ctxPcileech;
    BYTE pbDummyBuffer1M[0x00100000];
} PCILEECH_DLL_CONTEXT, *PPCILEECH_DLL_CONTEXT;

PPCILEECH_DLL_CONTEXT g_ctx = NULL;

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
    if((fdwReason == DLL_PROCESS_ATTACH) && !g_ctx) {
        g_pcileech_dll_printf_enabled = FALSE;
        g_ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(PCILEECH_DLL_CONTEXT));
        if(!g_ctx) { return FALSE; }
    }
    if((fdwReason == DLL_PROCESS_DETACH) && g_ctx) {
        PCILeechFreeContext(g_ctx->ctxPcileech);
        LocalFree(g_ctx);
        g_ctx = NULL;
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// CORE functionality below:
// ----------------------------------------------------------------------------

LPSTR PCILeech_GetVersion()
{
    return PCILEECH_VERSION_CURRENT;
}

BOOL PCILeech_InitializeFromFile(_In_ LPSTR szFileName, _In_opt_ LPSTR szPageTableBaseOpt)
{
    BOOL result = FALSE;
    if(!szFileName) { return FALSE; }
    if(!g_ctx || g_ctx->ctxPcileech) { return FALSE; }
    g_ctx->ctxPcileech = LocalAlloc(LMEM_ZEROINIT, sizeof(PCILEECH_CONTEXT));
    if(!g_ctx->ctxPcileech) { return FALSE; }
    result = PCILeechConfigIntialize(6, (LPSTR[]){ "", "dll_library_use", "-device", szFileName, "-cr3", (szPageTableBaseOpt ? szPageTableBaseOpt : "0")}, g_ctx->ctxPcileech);
    result = result && DeviceOpen(g_ctx->ctxPcileech);
    if(result) {
        PCILeechConfigFixup(g_ctx->ctxPcileech);
        return TRUE;
    } else {
        LocalFree(g_ctx->ctxPcileech);
        g_ctx->ctxPcileech = NULL;
        return FALSE;
    }
}

BOOL PCILeech_InitializeInternalReserved(_In_ DWORD argc, _In_ char* argv[])
{
    BOOL result = FALSE;
    if(!g_ctx || g_ctx->ctxPcileech) { return FALSE; }
    g_ctx->ctxPcileech = LocalAlloc(LMEM_ZEROINIT, sizeof(PCILEECH_CONTEXT));
    if(!g_ctx->ctxPcileech) { return FALSE; }
    result = PCILeechConfigIntialize(argc, argv, g_ctx->ctxPcileech);
    result = result && DeviceOpen(g_ctx->ctxPcileech);
    if(result) {
        PCILeechConfigFixup(g_ctx->ctxPcileech);
        return TRUE;
    }
    else {
        LocalFree(g_ctx->ctxPcileech);
        g_ctx->ctxPcileech = NULL;
        return FALSE;
    }
}

BOOL PCILeech_InitializeUSB3380()
{
    return PCILeech_InitializeInternalReserved(4, (LPSTR[]) { "", "dll_library_use", "-device", "usb3380" });
}

BOOL PCILeech_InitializeFPGA(_In_opt_ LPSTR szMaxPhysicalAddressOpt, _In_opt_ LPSTR szPageTableBaseOpt)
{
    return PCILeech_InitializeInternalReserved(8, (LPSTR[]) { "", "dll_library_use", "-device", "fpga", "-max", (szMaxPhysicalAddressOpt ? szMaxPhysicalAddressOpt : "0x0000008000000000"), "-cr3", (szPageTableBaseOpt ? szPageTableBaseOpt : "0") });
}

BOOL PCILeech_InitializeTotalMeltdown()
{
    return PCILeech_InitializeInternalReserved(4, (LPSTR[]) { "", "dll_library_use", "-device", "totalmeltdown" });
}

BOOL PCILeech_Close()
{
    if(!g_ctx || !g_ctx->ctxPcileech) { return FALSE; }
    PCILeechFreeContext(g_ctx->ctxPcileech);
    g_ctx->ctxPcileech = NULL;
    return TRUE;
}

BOOL PCILeech_DeviceWriteMEM(_In_ ULONG64 qwAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
    if(!g_ctx || !g_ctx->ctxPcileech) { return FALSE; }
    return DeviceWriteMEM(g_ctx->ctxPcileech, qwAddr, pb, cb, 0);
}

BOOL PCILeech_DeviceReadMEM(_In_ ULONG64 qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
    if(!g_ctx || !g_ctx->ctxPcileech) { return FALSE; }
    return DeviceReadMEM(g_ctx->ctxPcileech, qwAddr, pb, cb, 0);
}

DWORD PCILeech_DeviceReadScatterMEM(_Inout_ PPPCILEECH_MEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs)
{
	DWORD cpMEMsRead = 0;
	if (!g_ctx || !g_ctx->ctxPcileech) { return FALSE; }
	return DeviceReadScatterDMA(g_ctx->ctxPcileech, (PPDMA_IO_SCATTER_HEADER)ppMEMs, cpMEMs, &cpMEMsRead) ? cpMEMsRead : 0;
}

BOOL PCIleech_DeviceConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue)
{
    if(!g_ctx || !g_ctx->ctxPcileech || !pqwValue) { return FALSE; }
    if(fOption & 0x80000000) {
        switch(fOption) {
            case PCILEECH_DEVICE_CORE_PRINTF_ENABLE:
                *pqwValue = g_pcileech_dll_printf_enabled ? 1 : 0;
                return TRUE;
            case PCILEECH_DEVICE_CORE_VERBOSE:
                *pqwValue = g_ctx->ctxPcileech->cfg->fVerbose ? 1 : 0;
                return TRUE;
            case PCILEECH_DEVICE_CORE_VERBOSE_EXTRA:
                *pqwValue = g_ctx->ctxPcileech->cfg->fVerboseExtra ? 1 : 0;
                return TRUE;
            case PCILEECH_DEVICE_CORE_VERBOSE_EXTRA_TLP:
                *pqwValue = g_ctx->ctxPcileech->cfg->fVerboseExtraTlp ? 1 : 0;
                return TRUE;
            case PCILEECH_DEVICE_CORE_MAX_NATIVE_ADDRESS:
                *pqwValue = g_ctx->ctxPcileech->cfg->dev.qwAddrMaxNative;
                return TRUE;
            case PCILEECH_DEVICE_CORE_MAX_NATIVE_IOSIZE:
                *pqwValue = g_ctx->ctxPcileech->cfg->dev.qwMaxSizeDmaIo;
                return TRUE;
            default:
                return FALSE;
        }
    }
    return DeviceGetOption(g_ctx->ctxPcileech, fOption, pqwValue);
}

BOOL PCILeech_DeviceConfigSet(_In_ ULONG64 fOption, _In_ ULONG64 qwValue)
{
    if(fOption == PCILEECH_DEVICE_CORE_PRINTF_ENABLE) {
        g_pcileech_dll_printf_enabled = qwValue ? TRUE : FALSE;
        return TRUE;
    }
    if(!g_ctx || !g_ctx->ctxPcileech) { return FALSE; }
    if(fOption & 0x80000000) {
        switch(fOption) {
            case PCILEECH_DEVICE_CORE_VERBOSE:
                g_ctx->ctxPcileech->cfg->fVerbose = qwValue ? TRUE : FALSE;
                return TRUE;
            case PCILEECH_DEVICE_CORE_VERBOSE_EXTRA:
                g_ctx->ctxPcileech->cfg->fVerboseExtra = qwValue ? TRUE : FALSE;
                return TRUE;
            case PCILEECH_DEVICE_CORE_VERBOSE_EXTRA_TLP:
                g_ctx->ctxPcileech->cfg->fVerboseExtraTlp = qwValue ? TRUE : FALSE;
                return TRUE;
            default:
                return FALSE;
        }
    }
    return DeviceSetOption(g_ctx->ctxPcileech, fOption, qwValue);
}

// ----------------------------------------------------------------------------
// VMM functionality below:
// ----------------------------------------------------------------------------

BOOL PCILeech_VmmInitialize()
{
    BOOL result;
    if(!g_ctx || !g_ctx->ctxPcileech || g_ctx->ctxPcileech->hVMM) { return FALSE; }
    result = VmmInitialize(g_ctx->ctxPcileech) && VmmProcInitialize(g_ctx->ctxPcileech);
    if(!result) {
        VmmClose(g_ctx->ctxPcileech);
    }
    return result;
}

BOOL PCILeech_VmmClose()
{
    if(!g_ctx) { return FALSE; }
    if(!g_ctx->ctxPcileech || !g_ctx->ctxPcileech->hVMM) { return FALSE; }
    VmmClose(g_ctx->ctxPcileech);
    return TRUE;
}

BOOL PCILeech_VmmConfigGet_Impl(_In_ DWORD dwConfigOption, _Out_ PDWORD pdwConfigValue)
{
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM;
    if(!pdwConfigValue) { return FALSE; }
    switch(dwConfigOption) {
        case PCILEECH_VMM_CONFIG_IS_REFRESH_ENABLED:
            *pdwConfigValue = ctxVmm->ThreadProcCache.fEnabled ? 1 : 0;
            break;
        case PCILEECH_VMM_CONFIG_TICK_PERIOD:
            *pdwConfigValue = ctxVmm->ThreadProcCache.cMs_TickPeriod;
            break;
        case PCILEECH_VMM_CONFIG_READCACHE_TICKS:
            *pdwConfigValue = ctxVmm->ThreadProcCache.cTick_Phys;
            break;
        case PCILEECH_VMM_CONFIG_TLBCACHE_TICKS:
            *pdwConfigValue = ctxVmm->ThreadProcCache.cTick_TLB;
            break;
        case PCILEECH_VMM_CONFIG_PROCCACHE_TICKS_PARTIAL:
            *pdwConfigValue = ctxVmm->ThreadProcCache.cTick_ProcPartial;
            break;
        case PCILEECH_VMM_CONFIG_PROCCACHE_TICKS_TOTAL:
            *pdwConfigValue = ctxVmm->ThreadProcCache.cTick_ProcTotal;
            break;
        default:
            return FALSE;
    }
    return TRUE;
}

BOOL PCILeech_VmmConfigGet(_In_ DWORD dwConfigOption, _Out_ PDWORD pdwConfigValue)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmConfigGet_Impl(dwConfigOption, pdwConfigValue))
}

BOOL PCILeech_VmmConfigSet_Impl(_In_ DWORD dwConfigOption, _In_ DWORD dwConfigValue)
{
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM;
    switch(dwConfigOption) {
        case PCILEECH_VMM_CONFIG_TICK_PERIOD:
            ctxVmm->ThreadProcCache.cMs_TickPeriod = dwConfigValue;
            break;
        case PCILEECH_VMM_CONFIG_READCACHE_TICKS:
            ctxVmm->ThreadProcCache.cTick_Phys = dwConfigValue;
            break;
        case PCILEECH_VMM_CONFIG_TLBCACHE_TICKS:
            ctxVmm->ThreadProcCache.cTick_TLB = dwConfigValue;
            break;
        case PCILEECH_VMM_CONFIG_PROCCACHE_TICKS_PARTIAL:
            ctxVmm->ThreadProcCache.cTick_ProcPartial = dwConfigValue;
            break;
        case PCILEECH_VMM_CONFIG_PROCCACHE_TICKS_TOTAL:
            ctxVmm->ThreadProcCache.cTick_ProcTotal = dwConfigValue;
            break;
        default:
            return FALSE;
    }
    return TRUE;
}

BOOL PCILeech_VmmConfigSet(_In_ DWORD dwConfigOption, _In_ DWORD dwConfigValue)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmConfigSet_Impl(dwConfigOption, dwConfigValue))
}

BOOL PCILeech_VmmRead_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD dwRead;
    return PCILeech_VmmReadEx(dwPID, qwVA, pb, cb, &dwRead, 0) && (dwRead == cb);
}

BOOL PCILeech_VmmRead(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmRead_Impl(dwPID, qwVA, pb, cb))
}

BOOL PCILeech_VmmReadPage_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_bytecount_(4096) PBYTE pbPage)
{
    DWORD dwRead;
    return PCILeech_VmmReadEx(dwPID, qwVA, pbPage, 4096, &dwRead, 0) && (dwRead == 4096);
}

BOOL PCILeech_VmmReadPage(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_bytecount_(4096) PBYTE pbPage)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmReadPage_Impl(dwPID, qwVA, pbPage))
}

BOOL PCILeech_VmmReadEx_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    PVMM_PROCESS pProcess = VmmProcessGet((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, dwPID);
    if(!pProcess) { return FALSE; }
    VmmReadEx((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pProcess, qwVA, pb, cb, pcbReadOpt, flags);
    return TRUE;
}

BOOL PCILeech_VmmReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmReadEx_Impl(dwPID, qwVA, pb, cb, pcbReadOpt, flags))
}

BOOL PCILeech_VmmWrite_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    PVMM_PROCESS pProcess = VmmProcessGet((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, dwPID);
    if(!pProcess) { return FALSE; }
    return VmmWrite((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pProcess, qwVA, pb, cb);
}

BOOL PCILeech_VmmWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmWrite_Impl(dwPID, qwVA, pb, cb))
}

BOOL PCILeech_VmmVirt2Phys_Impl(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA)
{
    PVMM_PROCESS pProcess = VmmProcessGet((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, dwPID);
    if(!pProcess) { return FALSE; }
    return VmmVirt2Phys((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pProcess, qwVA, pqwPA);
}

BOOL PCILeech_VmmVirt2Phys(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmVirt2Phys_Impl(dwPID, qwVA, pqwPA))
}

BOOL PCILeech_VmmProcessGetMemoryMap_Impl(_In_ DWORD dwPID, _Out_ PPCILEECH_VMM_MEMMAP_ENTRY pMemMapEntries, _Inout_ PULONG64 pcMemMapEntries, _In_ BOOL fIdentifyModules)
{
    PVMM_PROCESS pProcess = VmmProcessGet((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, dwPID);
    if(!pProcess) { return FALSE; }
    if(!pProcess->pMemMap || !pProcess->cMemMap) {
        if(!pProcess->fSpiderPageTableDone) {
            VmmTlbSpider((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, 0, pProcess->fUserOnly);
            pProcess->fSpiderPageTableDone = TRUE;
        }
        VmmMapInitialize((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pProcess);
        if(fIdentifyModules) {
            VmmProc_InitializeModuleNames((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pProcess);
        }
    }
    if(!pMemMapEntries) {
        *pcMemMapEntries = pProcess->cMemMap;
    } else {
        if(!pProcess->pMemMap || (*pcMemMapEntries < pProcess->cMemMap)) { return FALSE; }
        memcpy(pMemMapEntries, pProcess->pMemMap, sizeof(PCILEECH_VMM_MEMMAP_ENTRY) * pProcess->cMemMap);
        *pcMemMapEntries = pProcess->cMemMap;
    }
    return TRUE;
}

BOOL PCILeech_VmmProcessGetMemoryMap(_In_ DWORD dwPID, _Out_ PPCILEECH_VMM_MEMMAP_ENTRY pMemMapEntries, _Inout_ PULONG64 pcMemMapEntries, _In_ BOOL fIdentifyModules)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessGetMemoryMap_Impl(dwPID, pMemMapEntries, pcMemMapEntries, fIdentifyModules))
}

BOOL PCILeech_VmmProcessGetModuleMap_Impl(_In_ DWORD dwPID, _Out_ PPCILEECH_VMM_MODULEMAP_ENTRY pModuleEntries, _Inout_ PULONG64 pcModuleEntries)
{
    ULONG64 i;
    PVMM_PROCESS pProcess = VmmProcessGet((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, dwPID);
    if(!pProcess) { return FALSE; }
    if(!pcModuleEntries) { return FALSE; }
    if(!pProcess->pModuleMap || !pProcess->cModuleMap) {
        if(!pProcess->fSpiderPageTableDone) {
            VmmTlbSpider((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, 0, pProcess->fUserOnly);
            pProcess->fSpiderPageTableDone = TRUE;
        }
        VmmProc_InitializeModuleNames((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pProcess);
    }
    if(!pModuleEntries) {
        *pcModuleEntries = pProcess->cModuleMap;
    } else {
        if(!pProcess->pModuleMap || (*pcModuleEntries < pProcess->cModuleMap)) { return FALSE; }
        for(i = 0; i < pProcess->cModuleMap; i++) {
            memcpy(pModuleEntries + i, pProcess->pModuleMap + i, sizeof(PCILEECH_VMM_MODULEMAP_ENTRY));
        }
        *pcModuleEntries = pProcess->cModuleMap;
    }
    return TRUE;
}

BOOL PCILeech_VmmProcessGetModuleMap(_In_ DWORD dwPID, _Out_ PPCILEECH_VMM_MODULEMAP_ENTRY pModuleEntries, _Inout_ PULONG64 pcModuleEntries)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessGetModuleMap_Impl(dwPID, pModuleEntries, pcModuleEntries))
}

BOOL PCILeech_VmmProcessGetModuleFromName_Impl(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _Out_ PPCILEECH_VMM_MODULEMAP_ENTRY pModuleEntry)
{
    BOOL result;
    ULONG64 i, cModuleEntries;
    PPCILEECH_VMM_MODULEMAP_ENTRY pModuleEntries = NULL;
    result = PCILeech_VmmProcessGetModuleMap_Impl(dwPID, NULL, &cModuleEntries);
    if(!result || !cModuleEntries) { return FALSE; }
    pModuleEntries = (PPCILEECH_VMM_MODULEMAP_ENTRY)LocalAlloc(0, sizeof(PCILEECH_VMM_MODULEMAP_ENTRY) * cModuleEntries);
    if(!pModuleEntries) { return FALSE; }
    result = PCILeech_VmmProcessGetModuleMap_Impl(dwPID, pModuleEntries, &cModuleEntries);
    if(result && cModuleEntries) {
        for(i = 0; i < cModuleEntries; i++) {
            if(!_strnicmp(szModuleName, pModuleEntries[i].szName, 31)) { 
                memcpy(pModuleEntry, pModuleEntries + i, sizeof(PCILEECH_VMM_MODULEMAP_ENTRY));
                LocalFree(pModuleEntries);
                return TRUE;
            }
        }
    }
    LocalFree(pModuleEntries);
    return FALSE;
}

BOOL PCILeech_VmmProcessGetModuleFromName(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _Out_ PPCILEECH_VMM_MODULEMAP_ENTRY pModuleEntry)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessGetModuleFromName_Impl(dwPID, szModuleName, pModuleEntry))
}

BOOL PCILeech_VmmProcessListPIDs_Impl(_Out_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs)
{
    VmmProcessListPIDs((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pPIDs, pcPIDs);
    return TRUE;
}

BOOL PCILeech_VmmProcessListPIDs(_Out_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessListPIDs_Impl(pPIDs, pcPIDs))
}

BOOL PCILeech_VmmProcessGetFromName_Impl(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID)
{
    DWORD i, pdwPIDs[1024];
    SIZE_T cPIDs = 1024;
    PVMM_PROCESS pProcess;
    VmmProcessListPIDs((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pdwPIDs, &cPIDs);
    for(i = 0; i < cPIDs; i++) {
        pProcess = VmmProcessGet((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, pdwPIDs[i]);
        if(!pProcess) { return FALSE; }
        if(_strnicmp(szProcName, pProcess->szName, 15)) { continue; }
        if(pProcess->dwState) { continue; }
        *pdwPID = pdwPIDs[i];
        return TRUE;
    }
    return FALSE;
}

BOOL PCILeech_VmmProcessGetFromName(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessGetFromName_Impl(szProcName, pdwPID))
}

BOOL PCIleech_VmmProcessInfo_Impl(_In_ DWORD dwPID, _Out_opt_ CHAR szNameOpt[16], _Out_opt_ PULONG64 pqwPageDirectoryBaseOpt, _Out_opt_ PULONG64 pqwPageDirectoryBaseUserOpt, _Out_opt_ PDWORD pdwStateOpt)
{
    PVMM_PROCESS pProcess = VmmProcessGet((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, dwPID);
    if(!pProcess) { return FALSE; }
    if(szNameOpt) {
        memcpy(szNameOpt, pProcess->szName, 16);
    }
    if(pqwPageDirectoryBaseOpt) {
        *pqwPageDirectoryBaseOpt = pProcess->paPML4;
    }
    if(pqwPageDirectoryBaseUserOpt) {
        *pqwPageDirectoryBaseUserOpt = pProcess->paPML4_UserOpt;
    }
    if(pdwStateOpt) {
        *pdwStateOpt = pProcess->dwState;
    }
    return TRUE;
}

BOOL PCIleech_VmmProcessInfo(_In_ DWORD dwPID, _Out_opt_ CHAR szNameOpt[16], _Out_opt_ PULONG64 pqwPageDirectoryBaseOpt, _Out_opt_ PULONG64 pqwPageDirectoryBaseUserOpt, _Out_opt_ PDWORD pdwStateOpt)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCIleech_VmmProcessInfo_Impl(dwPID, szNameOpt, pqwPageDirectoryBaseOpt, pqwPageDirectoryBaseUserOpt, pdwStateOpt))
}

BOOL PCILeech_VmmProcessGet_Directories_Sections_IAT_EAT_Impl(
    _In_ DWORD dwPID, 
    _In_ LPSTR szModule, 
    _In_ DWORD cData, 
    _Out_ PDWORD pcData, 
    _Out_opt_ PIMAGE_DATA_DIRECTORY pDataDirectory, 
    _Out_opt_ PIMAGE_SECTION_HEADER pSections,
    _Out_opt_ PPCILEECH_VMM_EAT_ENTRY pEAT,
    _Out_opt_ PVOID pIAT,
    BOOL _In_ fDataDirectory,
    BOOL _In_ fSections,
    BOOL _In_ fEAT,
    BOOL _In_ fIAT
)
{
    DWORD i;
    PVMM_MODULEMAP_ENTRY pModule = NULL;
    PVMM_PROCESS pProcess = VmmProcessGet((PVMM_CONTEXT)g_ctx->ctxPcileech->hVMM, dwPID);
    PVMM_CONTEXT ctxVmm = g_ctx->ctxPcileech->hVMM;
    if(!pProcess) { return FALSE; }
    // genereate module map (if required)
    if(!pProcess->pModuleMap || !pProcess->cModuleMap) {
        if(!pProcess->fSpiderPageTableDone) {
            VmmTlbSpider(ctxVmm, 0, pProcess->fUserOnly);
            pProcess->fSpiderPageTableDone = TRUE;
        }
        VmmProc_InitializeModuleNames(ctxVmm, pProcess);
        if(!pProcess->pModuleMap || !pProcess->cModuleMap) { return FALSE; }
    }
    // fetch requested module
    for(i = 0; i < pProcess->cModuleMap; i++) {
        if(!_stricmp(pProcess->pModuleMap[i].szName, szModule)) {
            pModule = &pProcess->pModuleMap[i];
        }
    }
    if(!pModule) { return FALSE; }
    // data directories
    if(fDataDirectory) {
        if(!pDataDirectory) { *pcData = 16; return TRUE; }
        if(cData < 16) { return FALSE; }
        VmmProcWindows_PE_DIRECTORY_DisplayBuffer(ctxVmm, pProcess, pModule, NULL, 0, NULL, pDataDirectory);
        *pcData = 16;
        return TRUE;
    }
    // sections
    if(fSections) {
        i = VmmProcWindows_PE_GetNumberOfSection(ctxVmm, pProcess, pModule, NULL, FALSE);
        if(!pSections) { *pcData = i; return TRUE; }
        if(cData < i) { return FALSE; }
        VmmProcWindows_PE_SECTION_DisplayBuffer(ctxVmm, pProcess, pModule, NULL, 0, NULL, pSections);
        *pcData = i;
        return TRUE;
    }
    // export address table (EAT)
    if(fEAT) {
        i = VmmProcWindows_PE_GetNumberOfEAT(ctxVmm, pProcess, pModule, NULL, FALSE);
        if(!pEAT) { *pcData = i; return TRUE; }
        if(cData < i) { return FALSE; }
        VmmProcWindows_PE_LoadEAT_DisplayBuffer(ctxVmm, pProcess, pModule, FALSE, (PVMMPROC_WINDOWS_EAT_ENTRY)pEAT, cData);
        *pcData = i;
        return TRUE;
    }
    // import address table (IAT)
    if(fIAT) {
        i = VmmProcWindows_PE_GetNumberOfIAT(ctxVmm, pProcess, pModule, NULL, FALSE);
        if(!pIAT) { *pcData = i; return TRUE; }
        if(cData < i) { return FALSE; }
        VmmProcWindows_PE_LoadIAT_DisplayBuffer(ctxVmm, pProcess, pModule, FALSE, (PVMMPROC_WINDOWS_IAT_ENTRY)pIAT, cData);
        *pcData = i;
        return TRUE;
    }
    return FALSE;
}

BOOL PCIleech_VmmProcess_GetDirectories(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_ PIMAGE_DATA_DIRECTORY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, szModule, cData, pcData, pData, NULL, NULL, NULL, TRUE, FALSE, FALSE, FALSE))
}

BOOL PCIleech_VmmProcess_GetSections(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, szModule, cData, pcData, NULL, pData, NULL, NULL, FALSE, TRUE, FALSE, FALSE))
}

BOOL PCIleech_VmmProcess_GetEAT(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_ PPCILEECH_VMM_EAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, szModule, cData, pcData, NULL, NULL, pData, NULL, FALSE, FALSE, TRUE, FALSE))
}

BOOL PCIleech_VmmProcess_GetIAT(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_ PPCILEECH_VMM_IAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData)
{
    CALL_SYNCHRONIZED_IMPLEMENTATION_VMM(PCILeech_VmmProcessGet_Directories_Sections_IAT_EAT_Impl(dwPID, szModule, cData, pcData, NULL, NULL, NULL, pData, FALSE, FALSE, FALSE, TRUE))
}

#endif /* _WINDLL */
