// vfsproc.c : implementation of functions related to operating system and process parsing of virtual memory
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef WIN32
#include "vmmproc.h"
#include "vmm.h"
#include "device.h"
#include "util.h"
#include <Winternl.h>

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC PROCESS RELATED FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

typedef struct _LDR_MODULE {
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    PVOID               BaseAddress;
    PVOID               EntryPoint;
    ULONG               SizeOfImage;
    UNICODE_STRING      FullDllName;
    UNICODE_STRING      BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    LIST_ENTRY          HashTableEntry;
    ULONG               TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct tdVMMPROC_WIN_LDRMODULES {
    QWORD BaseAddress;
    QWORD EntryPoint;
    DWORD SizeOfImage;
    WCHAR wszName[32];
} VMMPROC_WIN_LDRMODULES, *PVMMPROC_WIN_LDRMODULES;

QWORD VmmProcWindows_GetProcAddress(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModule, _In_ LPSTR lpProcName);

VOID VmmProcWindows_ScanLdrModules(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _Inout_ PVMMPROC_WIN_LDRMODULES pModules, _Out_ PDWORD pcModules, _In_ DWORD cModulesMax)
{
    DWORD cModules = 0;
    QWORD vaModuleLdrFirst, vaModuleLdr = 0;
    BYTE pbPEB[sizeof(PEB)], pbPEBLdrData[sizeof(PEB_LDR_DATA)], pbLdrModule[sizeof(LDR_MODULE)];
    PPEB pPEB = (PPEB)pbPEB;
    PPEB_LDR_DATA pPEBLdrData = (PPEB_LDR_DATA)pbPEBLdrData;
    PLDR_MODULE pLdrModule = (PLDR_MODULE)pbLdrModule;
    PVMMPROC_WIN_LDRMODULES pModule;
    BOOL fVerboseExtra = ctxVmm->ctxPcileech->cfg->fVerboseExtra;
    *pcModules = 0;
    if(!pProcess->os.win.vaPEB) { return; }
    if(!VmmRead(ctxVmm, pProcess, pProcess->os.win.vaPEB, pbPEB, sizeof(PEB))) { return; }
    if(!VmmRead(ctxVmm, pProcess, (QWORD)pPEB->Ldr, pbPEBLdrData, sizeof(PEB_LDR_DATA))) { return; }
    vaModuleLdr = vaModuleLdrFirst = (QWORD)pPEBLdrData->InMemoryOrderModuleList.Flink - 0x10; // InLoadOrderModuleList == InMemoryOrderModuleList - 0x10
    do {
        if(!VmmRead(ctxVmm, pProcess, vaModuleLdr, pbLdrModule, sizeof(LDR_MODULE))) { break; }
        pModule = pModules + cModules;
        pModule->BaseAddress = (QWORD)pLdrModule->BaseAddress;
        pModule->EntryPoint = (QWORD)pLdrModule->EntryPoint;
        pModule->SizeOfImage = (DWORD)pLdrModule->SizeOfImage;
        if(pLdrModule->FullDllName.Length) {
            if(!VmmRead(ctxVmm, pProcess, (QWORD)pLdrModule->BaseDllName.Buffer, (PBYTE)pModule->wszName, 2 * min(31, pLdrModule->BaseDllName.Length))) { break; }
        }
        cModules++;
        if(fVerboseExtra) {
            printf("vmmproc.c!VmmProcWindows_ScanLdrModules: %016llx %016llx %016llx %08x %S\n", vaModuleLdr, pModule->BaseAddress, pModule->EntryPoint, pModule->SizeOfImage, pModule->wszName);
        }
        vaModuleLdr = (QWORD)pLdrModule->InLoadOrderModuleList.Flink;
    } while((vaModuleLdr != vaModuleLdrFirst) && (cModules < cModulesMax));
    *pcModules = cModules;
}

VOID VmmProcWindows_InitializeLdrModules(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess)
{
    PVMMPROC_WIN_LDRMODULES pModules, pModule;
    PBYTE pbResult;
    DWORD i, o, cModules;
    // clear out any previous data
    if(pProcess->os.win.pbLdrModulesDisplayCache) { 
        LocalFree(pProcess->os.win.pbLdrModulesDisplayCache);
        pProcess->os.win.pbLdrModulesDisplayCache = NULL;
        pProcess->os.win.cbLdrModulesDisplayCache = 0;
    }
    pProcess->os.win.vaENTRY = 0;
    // allocate and enumerate
    pModules = (PVMMPROC_WIN_LDRMODULES)LocalAlloc(LMEM_ZEROINIT, 512 * sizeof(VMMPROC_WIN_LDRMODULES));
    if(!pModules) { goto fail; }
    VmmProcWindows_ScanLdrModules(ctxVmm, pProcess, pModules, &cModules, 512);
    if(!cModules) { goto fail; }
    // generate display cache
    pProcess->os.win.vaENTRY = pModules[0].EntryPoint;
    pbResult = pProcess->os.win.pbLdrModulesDisplayCache = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 86 * cModules);
    if(!pbResult) { goto fail; }
    for(i = 0, o = 0; i < cModules; i++) {
        pModule = pModules + i;
        if(!pModule->BaseAddress) { continue; }
        o += snprintf(
            pbResult + o,
            86,
            "%04x %8x %016llx-%016llx      %S\n",
            i,
            pModule->SizeOfImage >> 12,
            pModule->BaseAddress,
            pModule->BaseAddress + pModule->SizeOfImage - 1,
            pModule->wszName
        );
    }
    // update memory map with names
    for(i = 0; i < cModules; i++) {
        pModule = pModules + i;
        VmmMapTag(ctxVmm, pProcess, pModule->BaseAddress, pModule->BaseAddress + pModule->SizeOfImage, NULL, pModule->wszName);
    }
    pProcess->os.win.cbLdrModulesDisplayCache = o;
fail:
    LocalFree(pModules);
}

/*
* Locate the virtual base address of ntoskrnl.exe given any address inside the
* kernel. Localization will be done by a scan-back method. A maximum of 16MB
* will be scanned back.
*/
QWORD VmmProcWindows_FindNtoskrnl(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pSystemProcess, _In_ QWORD vaKernelEntry)
{
    PBYTE pb;
    QWORD vaBase, oPage, o, vaNtosBase = 0;
    BOOL fINITKDBG, fPOOLCODE;
    DWORD cbRead;
    pb = LocalAlloc(0, 0x200000);
    if(!pb) { goto cleanup; }
    // Scan back in 2MB chunks a time, (ntoskrnl.exe is loaded in 2MB pages).
    for(vaBase = vaKernelEntry & ~0x1fffff; vaBase + 0x02000000 > vaKernelEntry; vaBase -= 0x200000) {
        VmmReadEx(ctxVmm, pSystemProcess, vaBase, pb, 0x200000, &cbRead);
        // only fail here if all virtual memory in read fails. reason is that kernel is
        // properly mapped in memory (with NX MZ header in separate page) with empty
        // space before next valid kernel pages when running Virtualization Based Security.
        if(!cbRead) { goto cleanup; }
        for(oPage = 0; oPage < 0x200000; oPage += 0x1000) {
            if(*(PWORD)(pb + oPage) == 0x5a4d) { // MZ header
                fINITKDBG = FALSE;
                fPOOLCODE = FALSE;
                for(o = 0; o < 0x1000; o += 8) {
                    if(*(PQWORD)(pb + oPage + o) == 0x4742444B54494E49) { // INITKDBG
                        fINITKDBG = TRUE;
                    }
                    if(*(PQWORD)(pb + oPage + o) == 0x45444F434C4F4F50) { // POOLCODE
                        fPOOLCODE = TRUE;
                    }
                    if(fINITKDBG && fPOOLCODE) {
                        vaNtosBase = vaBase + oPage;
                        goto cleanup;
                    }
                }
            }
        }
    }
cleanup:
    LocalFree(pb);
    return vaNtosBase;
}

/*
* Perform GetProcAddress given a PE header.
* NB! very messy code due to lots of sanity checks on untrusted data.
*/
QWORD VmmProcWindows_GetProcAddress(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModule, _In_ LPSTR lpProcName)
{
    PDWORD pdwRVAAddrNames, pdwRVAAddrFunctions;
    PWORD pwNameOrdinals;
    DWORD i, cbProcName, cbExportDirectoryOffset;
    LPSTR sz;
    QWORD vaFnPtr;
    QWORD vaExportDirectory;
    DWORD cbExportDirectory;
    PBYTE pbExportDirectory = NULL;
    BYTE pbModuleHeader[0x1000];
    QWORD vaRVAAddrNames, vaNameOrdinals, vaRVAAddrFunctions;
    if(!VmmReadPage(ctxVmm, pProcess, vaModule, pbModuleHeader)) { goto cleanup; }
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pbModuleHeader; // dos header.
    if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { goto cleanup; }
    if(dosHeader->e_lfanew > 0x800) { goto cleanup; }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(pbModuleHeader + dosHeader->e_lfanew); // nt header
    if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { goto cleanup; }
    vaExportDirectory = vaModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    cbExportDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if((cbExportDirectory < sizeof(IMAGE_EXPORT_DIRECTORY)) || (cbExportDirectory > 0x01000000) || (vaExportDirectory == vaModule) || (vaExportDirectory > vaModule + 0x80000000)) { goto cleanup; }
    if(!(pbExportDirectory = LocalAlloc(0, cbExportDirectory))) { goto cleanup; }
    if(!VmmRead(ctxVmm, pProcess, vaExportDirectory, pbExportDirectory, cbExportDirectory)) { goto cleanup; }
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    if(!exp || !exp->NumberOfNames || !exp->AddressOfNames) { goto cleanup; }
    vaRVAAddrNames = vaModule + exp->AddressOfNames;
    vaNameOrdinals = vaModule + exp->AddressOfNameOrdinals;
    vaRVAAddrFunctions = vaModule + exp->AddressOfFunctions;
    if((vaRVAAddrNames < vaExportDirectory) || (vaRVAAddrNames > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(DWORD))) { goto cleanup; }
    if((vaNameOrdinals < vaExportDirectory) || (vaNameOrdinals > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(WORD))) { goto cleanup; }
    if((vaRVAAddrFunctions < vaExportDirectory) || (vaRVAAddrFunctions > vaExportDirectory + cbExportDirectory - exp->NumberOfNames * sizeof(DWORD))) { goto cleanup; }
    cbProcName = (DWORD)strnlen_s(lpProcName, MAX_PATH) + 1;
    cbExportDirectoryOffset = (DWORD)(vaExportDirectory - vaModule);
    pdwRVAAddrNames = (PDWORD)(pbExportDirectory + exp->AddressOfNames - cbExportDirectoryOffset);
    pwNameOrdinals = (PWORD)(pbExportDirectory + exp->AddressOfNameOrdinals - cbExportDirectoryOffset);
    pdwRVAAddrFunctions = (PDWORD)(pbExportDirectory + exp->AddressOfFunctions - cbExportDirectoryOffset);
    for(i = 0; i < exp->NumberOfNames; i++) {
        if(pdwRVAAddrNames[i] - cbExportDirectoryOffset + cbProcName > cbExportDirectory) { continue; }
        sz = (LPSTR)(pbExportDirectory + pdwRVAAddrNames[i] - cbExportDirectoryOffset);
        if(0 == memcmp(sz, lpProcName, cbProcName)) {
            if(pwNameOrdinals[i] >= exp->NumberOfFunctions) { goto cleanup; }
            vaFnPtr = (QWORD)(vaModule + pdwRVAAddrFunctions[pwNameOrdinals[i]]);
            LocalFree(pbExportDirectory);
            return vaFnPtr;
        }
    }
cleanup:
    LocalFree(pbExportDirectory);
    return 0;
}

/*
* Retrieve PE module name given a PE header.
* NB! very messy code due to lots of sanity checks on untrusted data.
*/
_Success_(return)
BOOL VmmProcWindows_GetModuleName(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ QWORD vaModule, _Out_ CHAR pbModuleName[MAX_PATH], _Out_ PDWORD pdwSize, _In_opt_ PBYTE pbPageMZHeaderPreCacheOpt, _In_ BOOL fDummyPENameOnExportDirectoryFail)
{
    QWORD vaExportDirectory;
    DWORD cbExportDirectory;
    BYTE pbModuleHeader[0x1000], pbExportDirectory[sizeof(IMAGE_EXPORT_DIRECTORY)];
    if(pbPageMZHeaderPreCacheOpt) {
        memcpy(pbModuleHeader, pbPageMZHeaderPreCacheOpt, 0x1000);
    } else {
        if(!VmmReadPage(ctxVmm, pProcess, vaModule, pbModuleHeader)) { return FALSE; }
    }
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pbModuleHeader; // dos header.
    if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return FALSE; }
    if(dosHeader->e_lfanew > 0x800) { return FALSE; }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(pbModuleHeader + dosHeader->e_lfanew); // nt header
    if(!ntHeader || ntHeader->Signature != IMAGE_NT_SIGNATURE) { return FALSE; }
    *pdwSize = ntHeader->OptionalHeader.SizeOfImage;
    vaExportDirectory = vaModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    cbExportDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if((cbExportDirectory < sizeof(IMAGE_EXPORT_DIRECTORY)) || (vaExportDirectory == vaModule)) { goto fail; }
    if(!VmmRead(ctxVmm, pProcess, vaExportDirectory, pbExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY))) { goto fail; }
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)pbExportDirectory;
    if(!exp || !exp->Name || exp->Name > ntHeader->OptionalHeader.SizeOfImage) { goto fail; }
    pbModuleName[MAX_PATH - 1] = 0;
    if(!VmmRead(ctxVmm, pProcess, vaModule + exp->Name, pbModuleName, MAX_PATH - 1)) { goto fail; }
    return TRUE;
fail:
    if(fDummyPENameOnExportDirectoryFail) {
        memcpy(pbModuleName, "UNKNOWN", 8);
        return TRUE;
    }
    return FALSE;
}

/*
* Load module proc names into memory map list if possible.
* NB! this function parallelize reads of MZ header candidates to speed things up.
*/
VOID VmmProcWindows_ScanHeaderPE(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess)
{
    typedef struct tdMAP {
        DMA_IO_SCATTER_HEADER dma;
        PVMM_MEMMAP_ENTRY mme;
        BYTE pb[0x1000];
    } MAP, *PMAP;
    PMAP pMap, pMaps;
    PPDMA_IO_SCATTER_HEADER ppDMAs;
    PBYTE pbBuffer;
    DWORD i, cDMAs = 0, cbImageSize;
    BOOL result;
    CHAR szBuffer[MAX_PATH];
    // 1: checks and allocate buffers for parallell read of MZ header candidates
    if(!pProcess->cMemMap || !pProcess->pMemMap) { return; }
    pbBuffer = LocalAlloc(LMEM_ZEROINIT, 0x400 * (sizeof(PDMA_IO_SCATTER_HEADER) + sizeof(MAP)));
    if(!pbBuffer) { return; }
    ppDMAs = (PPDMA_IO_SCATTER_HEADER)pbBuffer;
    pMaps = (PMAP)(pbBuffer + 0x400 * sizeof(PDMA_IO_SCATTER_HEADER));
    // 2: scan memory map for MZ header candidates and put them on list for read
    for(i = 0; i < pProcess->cMemMap - 1; i++) {
        if(
            (pProcess->pMemMap[i].cPages == 1) &&                           // PE header is only 1 page
            !(pProcess->pMemMap[i].AddrBase & 0xffff) &&                    // starts at even 0x10000 offset
            !pProcess->pMemMap[i].szName[0] &&                              // name not already set
            (pProcess->pMemMap[i].fPage & VMM_MEMMAP_FLAG_PAGE_NX) &&       // no-execute
            !(pProcess->pMemMap[i + 1].fPage & VMM_MEMMAP_FLAG_PAGE_NX))    // next page is executable
        {
            pMap = pMaps + cDMAs;
            pMap->mme = pProcess->pMemMap + i;
            pMap->dma.cbMax = 0x1000;
            pMap->dma.qwA = pProcess->pMemMap[i].AddrBase;
            pMap->dma.pb = pMap->pb;
            ppDMAs[cDMAs] = &pMap->dma;
            cDMAs++;
            if(cDMAs == 0x400) { break; }
        }
    }
    // 3: read all MZ header candicates previously selected and try load name from them (after read is successful)
    VmmReadScatterVirtual(ctxVmm, pProcess, ppDMAs, cDMAs);
    for(i = 0; i < cDMAs; i++) {
        if(pMaps[i].dma.cb == 0x1000) {
            pMap = pMaps + i;
            result = VmmProcWindows_GetModuleName(ctxVmm, pProcess, pMap->mme->AddrBase, szBuffer, &cbImageSize, pMap->pb, TRUE);
            if(result && (cbImageSize < 0x01000000)) {
                VmmMapTag(ctxVmm, pProcess, pMap->mme->AddrBase, pMap->mme->AddrBase + cbImageSize, szBuffer, NULL);
            }
        }
    }
    LocalFree(pbBuffer);
}

#define VMMPROC_EPROCESS_MAX_SIZE 0x500

/*
* Very ugly hack that tries to locate some offsets required withn the EPROCESS struct.
*/
_Success_(return)
BOOL VmmProcWindows_OffsetLocatorEPROCESS(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pSystemProcess, 
    _Out_ PDWORD pdwoState, _Out_ PDWORD pdwoPML4, _Out_ PDWORD pdwoName, _Out_ PDWORD pdwoPID, _Out_ PDWORD pdwoFLink, _Out_ PDWORD pdwoPEB)
{
    BOOL f;
    DWORD i;
    QWORD va1;
    BYTE pb0[VMMPROC_EPROCESS_MAX_SIZE], pb1[VMMPROC_EPROCESS_MAX_SIZE];
    if(!VmmRead(ctxVmm, pSystemProcess, pSystemProcess->os.win.vaEPROCESS, pb0, 0x500)) { return FALSE; }
    if(ctxVmm->ctxPcileech->cfg->fVerboseExtra) {
        printf("vmmproc.c!VmmProcWindows_OffsetLocatorEPROCESS: %016llx %016llx\n", pSystemProcess->paPML4, pSystemProcess->os.win.vaEPROCESS);
        Util_PrintHexAscii(pb0, VMMPROC_EPROCESS_MAX_SIZE, 0);
    }
    // find offset State (static for now)
    if(*(PDWORD)(pb0 + 0x04)) { return FALSE; }
    *pdwoState = 0x04;
    // find offset PML4 (static for now)
    if(pSystemProcess->paPML4 != (0xfffffffffffff000 & *(PQWORD)(pb0 + 0x28))) { return FALSE; }
    *pdwoPML4 = 0x28;
    // find offset for Name
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pb0 + i) == 0x00006D6574737953) {
            *pdwoName = i;
            f = TRUE;
            break; 
        }
    }
    if(!f) { return FALSE; }
    // find offset for PID, FLink, BLink (assumed to be following eachother)
    for(i = 0, f = FALSE; i < VMMPROC_EPROCESS_MAX_SIZE - 8; i += 8) {
        if(*(PQWORD)(pb0 + i) == 4) {
            // PID = correct, this is a candidate
            if(0xffff000000000000 != (0xffff000000000003 & *(PQWORD)(pb0 + i + 8))) { continue; }    // FLink not valid kernel pointer
            va1 = *(PQWORD)(pb0 + i + 8) - i - 8;
            f = VmmRead(ctxVmm, pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
            if(!f) { continue; }
            f = FALSE;
            if( (*(PQWORD)(pb1 + *pdwoName) != 0x6578652e73736d73) && // smss.exe
                (*(PQWORD)(pb1 + *pdwoName) != 0x5320657275636553))   // Secure System
            {
                continue;
            }
            if((*(PQWORD)(pb1 + i + 16) - i - 8) != pSystemProcess->os.win.vaEPROCESS) { 
                continue;
            }
            *pdwoPID = i;
            *pdwoFLink = i + 8;
            f = TRUE;
            break;
        }
    }
    if(!f) { return FALSE; }
    // find offset for PEB (in EPROCESS)
    if(*(PQWORD)(pb1 + *pdwoName) == 0x5320657275636553) { 
        // Secure System have no PEB -> move forward in EPROCESS list to resolve!
        va1 = *(PQWORD)(pb1 + *pdwoFLink) - *pdwoFLink;
        f = VmmRead(ctxVmm, pSystemProcess, va1, pb1, VMMPROC_EPROCESS_MAX_SIZE);
        if(!f) { return FALSE; }
    }
    for(i = 0x300, f = FALSE; i < 0x480; i += 8) {
        if(*(PQWORD)(pb0 + i)) { continue; }
        if(!*(PQWORD)(pb1 + i)) { continue; }
        if(*(PQWORD)(pb1 + i) & 0xffffff0000000fff) { continue; }
        *pdwoPEB = i;
        f = TRUE;
        break;
    }
    return f;
}

/*
* Try walk the EPROCESS list in the Windows kernel to enumerate processes into
* the VMM/PROC file system.
* NB! This may be done to refresh an existing PID cache hence migration code.
* -- ctxVmm
* -- pSystemProcess
* -- return
*/
BOOL VmmProcWindows_EnumerateEPROCESS(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pSystemProcess)
{
    DWORD dwoState, dwoPML4, dwoName, dwoPID, dwoFLink, dwoPEB, dwoMax;
    PQWORD pqwPML4, pqwFLink, pqwPEB;
    PDWORD pdwState, pdwPID;
    LPSTR szName;
    BYTE pb[VMMPROC_EPROCESS_MAX_SIZE];
    BOOL result, fSystem;
    PVMM_PROCESS pVmmProcess;
    QWORD vaSystemEPROCESS, vaEPROCESS, cPID = 0;
    // retrieve offsets
    vaSystemEPROCESS = pSystemProcess->os.win.vaEPROCESS;
    result = VmmProcWindows_OffsetLocatorEPROCESS(ctxVmm, pSystemProcess, &dwoState, &dwoPML4, &dwoName, &dwoPID, &dwoFLink, &dwoPEB);
    if(!result) { 
        printf("VmmProc: Unable to locate EPROCESS offsets.\n");
        return FALSE;
    }
    if(ctxVmm->ctxPcileech->cfg->fVerboseExtra) {
        printf("vmmproc.c!VmmProcWindows_EnumerateEPROCESS: %016llx %016llx\n", pSystemProcess->paPML4, vaSystemEPROCESS);
    }
    dwoMax = min(VMMPROC_EPROCESS_MAX_SIZE, 16 + max(max(dwoState, dwoPID), max(max(dwoPML4, dwoFLink), max(dwoName, dwoPEB))));
    pdwState = (PDWORD)(pb + dwoState);
    pdwPID = (PDWORD)(pb + dwoPID);
    pqwPML4 = (PQWORD)(pb + dwoPML4);
    pqwFLink = (PQWORD)(pb + dwoFLink);
    szName = (LPSTR)(pb + dwoName);
    pqwPEB = (PQWORD)(pb + dwoPEB);
    // SCAN!
    if(!VmmRead(ctxVmm, pSystemProcess, vaSystemEPROCESS, pb, dwoMax)) { return FALSE; }
    vaEPROCESS = vaSystemEPROCESS;
    while(TRUE) {
        cPID++;
        fSystem = (*pdwPID == 4);
        // NB! Windows/Dokany does not support full 64-bit sizes on files, hence
        // the max value 0x0001000000000000 for kernel space. Top 16-bits (ffff)
        // are sign extended anyway so this should be fine if user skips them.
        pVmmProcess = VmmProcessCreateEntry(
            ctxVmm,
            *pdwPID,
            *pdwState,
            ~0xfff & *pqwPML4,
            szName,
            !fSystem,
            fSystem);
        if(pVmmProcess) {
            pVmmProcess->os.win.vaEPROCESS = vaEPROCESS;
            pVmmProcess->os.win.vaPEB = *pqwPEB;
            if(ctxVmm->ctxPcileech->cfg->fVerboseExtra) {
                printf("vmmproc.c!VmmProcWindows_EnumerateEPROCESS: %016llx %016llx %016llx %08x %s\n",
                    pVmmProcess->paPML4,
                    pVmmProcess->os.win.vaEPROCESS,
                    pVmmProcess->os.win.vaPEB,
                    pVmmProcess->dwPID,
                    pVmmProcess->szName);
            }
        } else {
            szName[14] = 0; // in case of bad string data ...
            printf("VMM: Skipping process due to parsing error.\n     PML4: %016llx PID: %i STATE: %i EPROCESS: %016llx NAME: %s\n", ~0xfff & *pqwPML4, *pdwPID, *pdwState, vaEPROCESS, szName);
        }
        vaEPROCESS = *pqwFLink - dwoFLink;
        if(vaEPROCESS == vaSystemEPROCESS) {
            break;
        }
        if(!VmmRead(ctxVmm, pSystemProcess, vaEPROCESS, pb, dwoMax)) {
            break;
        }
        if(*pqwPML4 & 0xffffff0000000000) {
            break;
        }
        if(0xffff000000000000 != (0xffff000000000003 & *pqwFLink)) {
            break;
        }
    }
    VmmProcessCreateFinish(ctxVmm);
    return (cPID > 10);
}

// ----------------------------------------------------------------------------
// WINDOWS SPECIFIC IMAGE IDENTIFYING BELOW
// ----------------------------------------------------------------------------

/*
* Find and validate the low stub (loaded <1MB if exists).   The low stub almost
* always exists on real hardware. It may be missing on virtual machines though.
* Upon success the PML4 and ntoskrnl.ese KernelEntry point are returned.
* NB! KernelEntry != Kernel Base
*/
_Success_(return)
BOOL VmmProcWindows_FindValidateLowStub(_Inout_ PPCILEECH_CONTEXT ctx, _Out_ PQWORD ppaPML4, _Out_ PQWORD pvaKernelEntry)
{
    PBYTE pbLowStub;
    DWORD o;
    if(!(pbLowStub = LocalAlloc(LMEM_ZEROINIT, 0x100000))) { return FALSE; }
    DeviceReadDMAEx(ctx, 0, pbLowStub, 0x100000, NULL, 0);
    o = 0;
    while(o < 0x100000) {
        o += 0x1000;
        if(0x00000001000600E9 != (0xffffffffffff00ff & *(PQWORD)(pbLowStub + o + 0x000))) { continue; } // START BYTES
        if(0xfffff80000000000 != (0xfffff80000000000 & *(PQWORD)(pbLowStub + o + 0x070))) { continue; } // KERNEL ENTRY
        if(0xffffff0000000fff & *(PQWORD)(pbLowStub + o + 0x0a0)) { continue; }                         // PML4
        *ppaPML4 = *(PQWORD)(pbLowStub + o + 0x0a0);
        *pvaKernelEntry = *(PQWORD)(pbLowStub + o + 0x070);
        LocalFree(pbLowStub);
        return TRUE;
    }
    LocalFree(pbLowStub);
    return FALSE;
}

/*
* see VmmProcPHYS_ScanWindowsKernel_LargePages for more information!
* Scan a page table hierarchy between virtual addresses between vaMin and vaMax
* for the first occurence of large 2MB pages. This is usually the ntoskrnl.exe
* if the OS is Windows. Ntoskrnl.exe is loaded between the virtual addresses:
* 0xFFFFF80000000000-0xFFFFF803FFFFFFFF
* -- ctxVmm,
* -- paTable = set to: physical address of PML4
* -- vaBase = set to 0
* -- vaMin = 0xFFFFF80000000000 (if windows kernel)
* -- vaMax = 0xFFFFF803FFFFFFFF (if windows kernel)
* -- cPML = set to 4
* -- pvaBase
* -- pcbSize
*/
VOID VmmProcPHYS_ScanWindowsKernel_LargePages_PageTableWalk(_Inout_ PVMM_CONTEXT ctxVmm, _In_ QWORD paTable, _In_ QWORD vaBase, _In_ QWORD vaMin, _In_ QWORD vaMax, _In_ BYTE cPML, _Inout_ PQWORD pvaBase, _Inout_ PQWORD pcbSize)
{
    const QWORD PML_REGION_SIZE[5] = { 0, 12, 21, 30, 39 };
    QWORD i, pte, *ptes, vaCurrent, vaSizeRegion;
    ptes = (PQWORD)VmmTlbGetPageTable(ctxVmm, paTable, FALSE);
    if(!ptes) { return; }
    if(cPML == 4) {
        *pvaBase = 0;
        *pcbSize = 0;
        if(!VmmTlbPageTableVerify(ctxVmm, (PBYTE)ptes, paTable, TRUE)) { return; }
        vaBase = 0;
    }
    for(i = 0; i < 512; i++) {
        // address in range
        vaSizeRegion = 1ULL << PML_REGION_SIZE[cPML];
        vaCurrent = vaBase + (i << PML_REGION_SIZE[cPML]);
        vaCurrent |= (vaCurrent & 0x0000800000000000) ? 0xffff000000000000 : 0; // sign extend
        if(*pvaBase && (vaCurrent >(*pvaBase + *pcbSize))) { return; }
        if(vaCurrent < vaMin) { continue; }
        if(vaCurrent > vaMax) { return; }
        // check PTEs
        pte = ptes[i];
        if(!(pte & 0x01)) { continue; }     // NOT VALID
        if(cPML == 2) {
            if(!(pte & 0x80)) { continue; }
            if(!*pvaBase) { *pvaBase = vaCurrent; }
            *pcbSize += 0x200000;
            continue;
        } else {
            if(pte & 0x80) { continue; }    // PS = 1
            VmmProcPHYS_ScanWindowsKernel_LargePages_PageTableWalk(ctxVmm, pte & 0x0000fffffffff000, vaCurrent, vaMin, vaMax, cPML - 1, pvaBase, pcbSize);
        }
    }
}

/*
* Sometimes the PageDirectoryBase (PML4) is known, but the kernel location may
* be unknown. This functions walks the page table in the area in which ntorkrnl
* is loaded (0xFFFFF80000000000-0xFFFFF803FFFFFFFF) looking for 2MB large pages
* If an area in 2MB pages are found it is scanned for the ntoskrnl.exe base.
* -- ctxVmm
* -- paPML4
* -- return = virtual address of ntoskrnl.exe base if successful, otherwise 0.
*/
QWORD VmmProcPHYS_ScanWindowsKernel_LargePages(_Inout_ PVMM_CONTEXT ctxVmm, _In_ QWORD paPML4)
{
    PBYTE pbBuffer;
    QWORD p, o, vaCurrentMin, vaBase, cbSize;
    PVMM_PROCESS pSystemProcess = NULL;
    BOOL fINITKDBG, fPOOLCODE;
    vaCurrentMin = 0xFFFFF80000000000;     // base of windows kernel possible location
    while(TRUE) {
        VmmProcPHYS_ScanWindowsKernel_LargePages_PageTableWalk(ctxVmm, paPML4, 0, vaCurrentMin, 0xFFFFF803FFFFFFFF, 4, &vaBase, &cbSize);
        if(!vaBase) { return 0; }
        vaCurrentMin = vaBase + cbSize;
        if(cbSize <= 0x00400000) { continue; }  // too small
        if(cbSize >= 0x01000000) { continue; }  // too big
        if(!pSystemProcess) {
            pSystemProcess = VmmProcessCreateEntry(ctxVmm, 4, 0, paPML4, "System", FALSE, FALSE);
            if(!pSystemProcess) { return 0; }
            VmmProcessCreateFinish(ctxVmm);
        }
        // try locate ntoskrnl.exe base inside suggested area
        pbBuffer = (PBYTE)LocalAlloc(0, cbSize);
        if(!pbBuffer) { return 0; }
        VmmReadEx(ctxVmm, pSystemProcess, vaBase, pbBuffer, (DWORD)cbSize, NULL);
        for(p = 0; p < cbSize; p += 0x1000) {
            if(*(PWORD)(pbBuffer + p) != 0x5a4d) { continue; }
            // check if module header contains INITKDBG and POOLCODE
            fINITKDBG = FALSE;
            fPOOLCODE = FALSE;
            for(o = 0; o < 0x1000; o += 8) {
                if(*(PQWORD)(pbBuffer + p + o) == 0x4742444B54494E49) { // INITKDBG
                    fINITKDBG = TRUE;
                }
                if(*(PQWORD)(pbBuffer + p + o) == 0x45444F434C4F4F50) { // POOLCODE
                    fPOOLCODE = TRUE;
                }
                if(fINITKDBG && fPOOLCODE) {
                    LocalFree(pbBuffer);
                    return vaBase + p;
                }
            }
        }
        LocalFree(pbBuffer);
    }
}

/*
* Try initialize the VMM from scratch with new WINDOWS support.
*/
BOOL VmmProcWindows_TryInitialize(_Inout_ PPCILEECH_CONTEXT ctx, _In_opt_ QWORD paPML4Opt, _In_opt_ QWORD vaKernelBaseOpt)
{
    BOOL result;
    PVMM_PROCESS pSystemProcess;
    QWORD paPML4, vaKernelEntry, vaKernelBase, vaPsInitialSystemProcess, vaSystemEPROCESS;
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    // Fetch Directory Base (PML4) and Kernel Entry (if optional hints not supplied)
    if(!paPML4Opt || !vaKernelBaseOpt) {
        result = VmmProcWindows_FindValidateLowStub(ctx, &paPML4, &vaKernelEntry);
        if(!result) {
            if(ctx->cfg->fVerbose) { printf("VmmProc: Initialization Failed. Bad data #1.\n"); }
            return FALSE;
        }
        vaKernelBase = 0;
    } else {
        paPML4 = paPML4Opt;
        vaKernelBase = vaKernelBaseOpt; // not entry here, but at least inside kernel ...
    }
    // Spider PML4 to speed things up
    VmmTlbSpider(ctxVmm, paPML4, FALSE);
    // Pre-initialize System PID (required by VMM)
    pSystemProcess = VmmProcessCreateEntry(ctxVmm, 4, 0, paPML4, "System", FALSE, TRUE);
    VmmProcessCreateFinish(ctxVmm);
    if(!pSystemProcess) {
        if(ctx->cfg->fVerbose) { printf("VmmProc: Initialization Failed. #4.\n"); }
        return FALSE;
    }
    // Locate Kernel Base (if required)
    if(!vaKernelBase) {
        vaKernelBase = VmmProcWindows_FindNtoskrnl(ctxVmm, pSystemProcess, vaKernelEntry);
        if(!vaKernelBase) {
            if(ctx->cfg->fVerbose)      { printf("VmmProc: Initialization Failed. Unable to locate kernel #5\n"); }
            if(ctx->cfg->fVerboseExtra) { printf("VmmProc: PML4: 0x%016llx PTR: %016llx\n", pSystemProcess->paPML4, vaKernelEntry); }
            return FALSE;
        }
    }
    if(ctx->cfg->fVerboseExtra) { printf("VmmProc: INFO: Kernel Base located at %016llx.\n", vaKernelBase); }
    // Locate System EPROCESS
    vaPsInitialSystemProcess = VmmProcWindows_GetProcAddress(ctxVmm, pSystemProcess, vaKernelBase, "PsInitialSystemProcess");
    result = VmmRead(ctxVmm, pSystemProcess, vaPsInitialSystemProcess, (PBYTE)&vaSystemEPROCESS, 8);
    if(!result) {
        if(ctx->cfg->fVerbose) { printf("VmmProc: Initialization Failed. Unable to locate EPROCESS. #6\n"); }
        return FALSE;
    }
    pSystemProcess->os.win.vaEPROCESS = vaSystemEPROCESS;
    if(ctx->cfg->fVerboseExtra) { printf("VmmProc: INFO: PsInitialSystemProcess located at %016llx.\n", vaPsInitialSystemProcess); }
    if(ctx->cfg->fVerboseExtra) { printf("VmmProc: INFO: EPROCESS located at %016llx.\n", vaSystemEPROCESS); }
    // Enumerate processes
    result = VmmProcWindows_EnumerateEPROCESS(ctxVmm, pSystemProcess);
    if(!result) {
        if(ctx->cfg->fVerbose) { printf("VmmProc: Initialization Failed. Unable to walk EPROCESS. #7\n"); }
        return FALSE;
    }
    ctxVmm->fWin = TRUE;
    return TRUE;
}

// ----------------------------------------------------------------------------
// GENERIC PROCESS RELATED FUNCTIONALITY BELOW:
// ----------------------------------------------------------------------------

/*
* Try initialize from user supplied CR3/PML4 supplied in parameter at startup.
* -- ctx
* -- return
*/
BOOL VmmProcUserCR3TryInitialize(_Inout_ PVMM_CONTEXT ctxVmm)
{
    PVMM_PROCESS pProcess;
    pProcess = VmmProcessCreateEntry(ctxVmm, 0, 0, ctxVmm->ctxPcileech->cfg->qwCR3, "unknown_process", FALSE, TRUE);
    VmmProcessCreateFinish(ctxVmm);
    if(!pProcess) {
        if(ctxVmm->ctxPcileech->cfg->fVerbose) { printf("VmmProc: FAIL: Initialization of Process failed from user-defined CR3 %016llx. #4.\n", ctxVmm->ctxPcileech->cfg->qwCR3); }
        return FALSE;
    }
    VmmTlbSpider(ctxVmm, pProcess->paPML4, FALSE);
    ctxVmm->fUnknownX64 = TRUE;
    return TRUE;
}

#define VMMPROC_UPDATERTHREAD_PERIOD                50
#define VMMPROC_UPDATERTHREAD_PHYSCACHE             (500 / VMMPROC_UPDATERTHREAD_PERIOD)            // 0.5s
#define VMMPROC_UPDATERTHREAD_PROC_REFRESHLIST      (5 * 1000 / VMMPROC_UPDATERTHREAD_PERIOD)       // 5s
#define VMMPROC_UPDATERTHREAD_TLB                   (15 * 1000 / VMMPROC_UPDATERTHREAD_PERIOD)      // 15s
#define VMMPROC_UPDATERTHREAD_PROC_REFRESHTOTAL     (15 * 1000 / VMMPROC_UPDATERTHREAD_PERIOD)      // 15s

DWORD VmmProcCacheUpdaterThread(_Inout_ PVMM_CONTEXT ctxVmm)
{
    QWORD i = 0;
    BOOL fPHYS, fTLB, fProcList, fProcTotal;
    PVMM_PROCESS pSystemProcess;
    QWORD paSystemPML4, vaSystemEPROCESS;
    if(ctxVmm->ctxPcileech->cfg->fVerbose) { 
        printf("VmmProc: Start periodic cache flushing.\n"); 
    }
    while(ctxVmm->ThreadProcCache.fEnabled) {
        Sleep(VMMPROC_UPDATERTHREAD_PERIOD);
        i++;
        fTLB = !(i % VMMPROC_UPDATERTHREAD_PHYSCACHE);
        fPHYS = !(i % VMMPROC_UPDATERTHREAD_PHYSCACHE);
        fProcTotal = !(i % VMMPROC_UPDATERTHREAD_PROC_REFRESHTOTAL);
        fProcList = !(i % VMMPROC_UPDATERTHREAD_PROC_REFRESHLIST) && !fProcTotal;
        EnterCriticalSection(&ctxVmm->MasterLock);
        // PHYS / TLB cache clear
        if(fPHYS || fTLB) {
            VmmCacheClear(ctxVmm, fTLB, fPHYS);
        }
        // refresh proc list
        if(fProcList) {
            // Windows OS
            if(ctxVmm->fWin) {
                pSystemProcess = VmmProcessGet(ctxVmm, 4);
                if(pSystemProcess) {
                    VmmProcWindows_EnumerateEPROCESS(ctxVmm, pSystemProcess);
                    if(ctxVmm->ctxPcileech->cfg->fVerboseExtra) {
                        printf("VmmProc: vmmproc.c!VmmProcCacheUpdaterThread FlushProcessList\n");
                    }
                }
            }
        }
        // total refresh of entire proc cache
        if(fProcTotal) {
            // Windows OS
            if(ctxVmm->fWin) {
                pSystemProcess = VmmProcessGet(ctxVmm, 4);
                if(pSystemProcess) {
                    paSystemPML4 = pSystemProcess->paPML4;
                    vaSystemEPROCESS = pSystemProcess->os.win.vaEPROCESS;
                    // purge existing process entries
                    VmmProcessCreateTable(ctxVmm);
                    // spider TLB and set up initial system process and enumerate EPROCESS
                    VmmTlbSpider(ctxVmm, paSystemPML4, FALSE);
                    pSystemProcess = VmmProcessCreateEntry(ctxVmm, 4, 0, paSystemPML4, "System", FALSE, TRUE);
                    VmmProcessCreateFinish(ctxVmm);
                    pSystemProcess->os.win.vaEPROCESS = vaSystemEPROCESS;
                    VmmProcWindows_EnumerateEPROCESS(ctxVmm, pSystemProcess);
                    if(ctxVmm->ctxPcileech->cfg->fVerboseExtra) {
                        printf("VmmProc: vmmproc.c!VmmProcCacheUpdaterThread FlushProcessListAndBuffers\n");
                    }
                }
            }
            // Single user-defined X64 process
            if(ctxVmm->fUnknownX64) {
                VmmProcessCreateTable(ctxVmm);
                VmmProcUserCR3TryInitialize(ctxVmm);
            }
        }
        LeaveCriticalSection(&ctxVmm->MasterLock);
    }
    if(ctxVmm->ctxPcileech->cfg->fVerbose) {
        printf("VmmProc: Exit periodic cache flushing.\n");
    }
    ctxVmm->ThreadProcCache.hThread = NULL;
    return 0;
}

VmmProc_InitializeModuleNames(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess)
{
    if(ctxVmm->fWin) {
        VmmProcWindows_InitializeLdrModules(ctxVmm, pProcess);
        VmmProcWindows_ScanHeaderPE(ctxVmm, pProcess);
    }
}

BOOL VmmProcInitialize(_Inout_ PPCILEECH_CONTEXT ctx)
{
    BOOL result;
    QWORD vaKernelBase;
    PVMM_CONTEXT ctxVmm;
    if(!VmmInitialize(ctx)) { return FALSE; }
    // user supplied a CR3 - use it!
    if(ctx->cfg->qwCR3) {
        // if VmmProcPHYS_ScanWindowsKernel_LargePages returns a value this is a
        // Windows system - initialize it, otherwise initialize the generic x64
        // single process more basic mode.
        result = FALSE;
        vaKernelBase = VmmProcPHYS_ScanWindowsKernel_LargePages((PVMM_CONTEXT)ctx->hVMM, ctx->cfg->qwCR3);
        if(vaKernelBase) {
            result = VmmProcWindows_TryInitialize(ctx, ctx->cfg->qwCR3, vaKernelBase);
        }
        if(!vaKernelBase) {
            result = VmmProcUserCR3TryInitialize((PVMM_CONTEXT)ctx->hVMM);
            if(!result) {
                VmmInitialize(ctx); // re-initialize VMM to clear state
            }
        }
        if(!result) {
            result = VmmProcUserCR3TryInitialize((PVMM_CONTEXT)ctx->hVMM);
        }
    } else {
        // no page directory was found, so try initialize it by looking if the
        // "low stub" exists on a Windows sytem and use it. Otherwise fail.
        result = VmmProcWindows_TryInitialize(ctx, 0, 0);
        if(!result) {
            printf(
                "VmmProc: Unable to auto-identify operating system for PROC file system mount.   \n" \
                "         Please specify PageDirectoryBase (CR3/PML4) in the -cr3 option if value\n" \
                "         is known. If unknown it may be recoverable with command 'identify'.    \n");
        }
    }
    // set up cache mainenance in the form of a separate worker thread in case
    // the backend is a writeable device (FPGA). File devices are read-only so
    // far so full caching is enabled since they are considered to be read-only.
    ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    if(result && !ctxVmm->fReadOnly) {
        ctxVmm->ThreadProcCache.fEnabled = TRUE;
        ctxVmm->ThreadProcCache.hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VmmProcCacheUpdaterThread, ctxVmm, 0, NULL);
        if(!ctxVmm->ThreadProcCache.hThread) { ctxVmm->ThreadProcCache.fEnabled = FALSE; }
    }
    return result;
}

// ----------------------------------------------------------------------------
// SCAN/SEARCH TO IDENTIFY IMAGE:
// - Currently Windows PageDirectoryBase/CR3/PML4 detection is supported only
// ----------------------------------------------------------------------------

_Success_(return)
BOOL VmmProcPHYS_VerifyWindowsEPROCESS(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PBYTE pb, _In_ QWORD cb, _In_ QWORD cbOffset, _Out_ PQWORD ppaPML4)
{
    QWORD i;
    if(cb < cbOffset + 8) { return FALSE; }
    if((cb & 0x07) || (cb < 0x500) || (cbOffset < 0x500)) { return FALSE; }
    if(*(PQWORD)(pb + cbOffset) != 0x00006D6574737953) { return FALSE; }        // not matching System00
    if(*(PQWORD)(pb + cbOffset + 8) & 0x00ffffffffffffff) { return FALSE; }     // not matching 0000000
    // maybe we have EPROCESS struct here, scan back to see if we can find
    // 4 kernel addresses in a row and a potential PML4 after that and zero
    // DWORD before that. (EPROCESS HDR).
    for(i = cbOffset; i > cbOffset - 0x500; i -= 8) {
        if((*(PQWORD)(pb + i - 0x00) & 0xfffff00000000000)) { continue; };                          // DirectoryTableBase
        if(!*(PQWORD)(pb + i - 0x00)) { continue; };                                                // DirectoryTableBase
        if((*(PQWORD)(pb + i - 0x08) & 0xffff800000000000) != 0xffff800000000000) { continue; };    // PTR
        if((*(PQWORD)(pb + i - 0x10) & 0xffff800000000000) != 0xffff800000000000) { continue; };    // PTR
        if((*(PQWORD)(pb + i - 0x18) & 0xffff800000000000) != 0xffff800000000000) { continue; };    // PTR
        if((*(PQWORD)(pb + i - 0x20) & 0xffff800000000000) != 0xffff800000000000) { continue; };    // PTR
        if((*(PDWORD)(pb + i - 0x24) != 0x00000000)) { continue; };                                 // SignalState
        *ppaPML4 = *(PQWORD)(pb + i - 0x00);
        return TRUE;
    }
    return FALSE;
}

_Success_(return)
BOOL VmmProcPHYS_ScanForKernel(_Inout_ PPCILEECH_CONTEXT ctx, _Out_ PQWORD ppaPML4)
{
    QWORD o, i, paMax, paCurrent;
    PAGE_STATISTICS pageStat;
    PBYTE pbBuffer8M;
    BOOL result;
    // initialize / allocate memory
    if(!(pbBuffer8M = LocalAlloc(0, 0x800000))) { return FALSE; }
    ZeroMemory(&pageStat, sizeof(PAGE_STATISTICS));
    paMax = min(ctx->cfg->qwAddrMax, ctx->cfg->dev.qwAddrMaxNative);
    paCurrent = max(0x100000, ctx->cfg->qwAddrMin);
    PageStatInitialize(&pageStat, paCurrent, paMax, "Scanning to identify ...", FALSE, FALSE);
    // loop kmd-find
    for(; paCurrent < paMax; paCurrent += 0x00800000) {
        if(!DeviceReadDMAEx(ctx, paCurrent, pbBuffer8M, 0x00800000, &pageStat, 0)) { continue; }
        for(o = 0; o < 0x00800000; o += 0x1000) {
            // Scan for windows EPROCESS (to get DirectoryBase/PML4)
            for(i = 0; i < 0x1000; i += 8) {
                if(*(PQWORD)(pbBuffer8M + o + i) == 0x00006D6574737953) {
                    result = VmmProcPHYS_VerifyWindowsEPROCESS(ctx, pbBuffer8M, 0x00800000, o + i, ppaPML4);
                    if(result) {
                        pageStat.szAction = "Windows System PageDirectoryBase/PML4 located";
                        LocalFree(pbBuffer8M);
                        PageStatClose(&pageStat);
                        return TRUE;
                    }
                }
            }
        }
    }
    LocalFree(pbBuffer8M);
    pageStat.szAction = "Scanning to identify ... FAILED!";
    PageStatClose(&pageStat);
    *ppaPML4 = 0;
    return FALSE;
}

VOID ActionIdentify(_Inout_ PPCILEECH_CONTEXT ctx)
{
    BOOL result;
    QWORD paPML4;
    printf(
        "IDENTIFY: Scanning to identify target operating system and page directories...\n"
        "  Currently supported oprerating systems:\n"
        "     - Windows (64-bit).\n");
    result = VmmProcPHYS_ScanForKernel(ctx, &paPML4);
    if(result) {
        printf("IDENTIFY: Succeeded: Windows System page directory base is located at: 0x%llx\n", paPML4);
    } else {
        printf("IDENTIFY: Failed. No fully supported operating system detected.\n");
    }
}

#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)

#include "vmmproc.h"

VOID ActionIdentify(_Inout_ PPCILEECH_CONTEXT ctx)
{
    printf("IDENTIFY; Functionality currently only supported in PCILeech for WIndows.\n");
}

#endif /* LINUX || ANDROID */
