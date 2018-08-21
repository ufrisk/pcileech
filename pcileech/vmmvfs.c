// vmmvfs.c : implementation related to virtual memory management / virtual file system interfacing.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vmmvfs.h"
#include "vmm.h"
#include "vmmproc.h"
#include "vfs.h"
#include "util.h"

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_END_OF_FILE               ((NTSTATUS)0xC0000011L)
#define STATUS_FILE_INVALID              ((NTSTATUS)0xC0000098L)

typedef struct tdVMMVFS_PATH {
    CHAR _sz[MAX_PATH];
    BOOL fRoot;
    BOOL fNamePID;
    DWORD dwPID;
    QWORD qwPath2;
    LPSTR szPath1;
    LPSTR szPath2;
    LPSTR szPath3;
} VMMVFS_PATH, *PVMMVFS_PATH;

BOOL VmmVfs_UtilVmmGetPidDirFile(_In_ LPCWSTR wcsFileName, _Inout_ PVMMVFS_PATH pPath)
{
    DWORD i = 0, iPID, iPath1 = 0, iPath2 = 0, iPath3 = 0;
    // 1: convert to ascii string
    ZeroMemory(pPath, sizeof(VMMVFS_PATH));
    while(TRUE) {
        if(i >= MAX_PATH) { return FALSE; }
        if(wcsFileName[i] > 255) { return FALSE; }
        pPath->_sz[i] = (CHAR)wcsFileName[i];
        if(wcsFileName[i] == 0) { break; }
        i++;
    }
    // 1: Check for root only item
    pPath->fNamePID = !_stricmp(pPath->_sz, "\\proc\\name");
    pPath->fRoot = pPath->fNamePID || !_stricmp(pPath->_sz, "\\proc\\pid");
    if(pPath->fRoot) { return TRUE; }
    // 2: Check if starting with PID or NAME and move start index
    if(!strncmp(pPath->_sz, "\\proc\\pid\\", 10)) { i = 10; }
    if(!strncmp(pPath->_sz, "\\proc\\name\\", 11)) { i = 11; }
    if(i == 0) { return FALSE; }
    // 3: Locate start of PID number and 1st Path item (if any)
    while((i < MAX_PATH) && pPath->_sz[i] && (pPath->_sz[i] != '\\')) { i++; }
    if(pPath->_sz[i]) { iPath1 = i + 1; }
    pPath->_sz[i] = 0;
    i--;
    while((i > 0) && (pPath->_sz[i] >= '0') && (pPath->_sz[i] <= '9')) { i--; }
    iPID = i + 1;
    pPath->dwPID = (DWORD)Util_GetNumeric(&pPath->_sz[iPID]);
    if(!iPath1) { return TRUE; }
    // 4: Locate 2nd Path item (if any)
    i = iPath1;
    while((i < MAX_PATH) && pPath->_sz[i] && (pPath->_sz[i] != '\\')) { i++; }
    if(pPath->_sz[i]) {
        iPath2 = i + 1;
        pPath->_sz[i] = 0;
    }
    // 5: Locate 3rd Path item (if any)
    if(iPath2) {
        i = iPath2;
        while((i < MAX_PATH) && pPath->_sz[i] && (pPath->_sz[i] != '\\')) { i++; }
        if(pPath->_sz[i]) {
            iPath3 = i + 1;
            pPath->_sz[i] = 0;
            // 6: Fixups
            i++;
            while((i < MAX_PATH) && pPath->_sz[i] && (pPath->_sz[i] != '\\')) { i++; }
            if(i < MAX_PATH) { pPath->_sz[i] = 0; }
        }
    }
    // 7: Finish
    pPath->szPath1 = &pPath->_sz[iPath1];
    if(iPath2) {
        pPath->szPath2 = &pPath->_sz[iPath2];
        pPath->qwPath2 = Util_GetNumeric(pPath->szPath2);
    }
    if(iPath3) {
        pPath->szPath3 = &pPath->_sz[iPath3];
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: READ
// ----------------------------------------------------------------------------

NTSTATUS VmmVfsReadFile_FromBuffer(_In_ PBYTE pbFile, _In_ QWORD cbFile, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(cbOffset > cbFile) { return STATUS_END_OF_FILE; }
    *pcbRead = (DWORD)min(cb, cbFile - cbOffset);
    memcpy(pb, pbFile + cbOffset, *pcbRead);
    return *pcbRead ? STATUS_SUCCESS : STATUS_END_OF_FILE;
}

NTSTATUS VmmVfsReadFile_FromQWORD(_In_ QWORD qwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix)
{
    BYTE pbBuffer[32];
    DWORD cbBuffer;
    cbBuffer = snprintf(pbBuffer, 32, (fPrefix ? "0x%016llx" : "%016llx"), qwValue);
    return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmVfsReadFile_FromDWORD(_In_ DWORD dwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset, _In_ BOOL fPrefix)
{
    BYTE pbBuffer[32];
    DWORD cbBuffer;
    cbBuffer = snprintf(pbBuffer, 32, (fPrefix ? "0x%08x" : "%08x"), dwValue);
    return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmVfsReadFile_FromBOOL(_In_ BOOL fValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE pbBuffer[1];
    pbBuffer[0] = fValue ? '1' : '0';
    return VmmVfsReadFile_FromBuffer(pbBuffer, 1, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmVfsReadFile_Virt2Phys(PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ LPSTR szFile, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE iPML = 0;
    DWORD cbBuffer;
    PBYTE pbSourceData;
    BYTE pbBuffer[0x1000];
    if(!_stricmp(szFile, "virt")) {
        return VmmVfsReadFile_FromQWORD(pProcess->virt2phys.va, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(szFile, "phys")) {
        return VmmVfsReadFile_FromQWORD(pProcess->virt2phys.pas[0], pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(szFile, "map")) {
        cbBuffer = snprintf(
            pbBuffer,
            0x1000,
            "PML4 %016llx +%03x %016llx\n" \
            "PDPT %016llx +%03x %016llx\n" \
            "PD   %016llx +%03x %016llx\n" \
            "PT   %016llx +%03x %016llx\n" \
            "PAGE %016llx\n",
            pProcess->virt2phys.pas[4], pProcess->virt2phys.iPTEs[4] << 3, pProcess->virt2phys.PTEs[4],
            pProcess->virt2phys.pas[3], pProcess->virt2phys.iPTEs[3] << 3, pProcess->virt2phys.PTEs[3],
            pProcess->virt2phys.pas[2], pProcess->virt2phys.iPTEs[2] << 3, pProcess->virt2phys.PTEs[2],
            pProcess->virt2phys.pas[1], pProcess->virt2phys.iPTEs[1] << 3, pProcess->virt2phys.PTEs[1],
            pProcess->virt2phys.pas[0]
        );
        return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    // "page table" or data page
    if(!_stricmp(szFile, "pt_pml4")) { iPML = 4; }
    if(!_stricmp(szFile, "pt_pdpt")) { iPML = 3; }
    if(!_stricmp(szFile, "pt_pd"))   { iPML = 2; }
    if(!_stricmp(szFile, "pt_pt"))   { iPML = 1; }
    ZeroMemory(pbBuffer, 0x1000);
    pbSourceData = pbBuffer;
    if(iPML && (pProcess->virt2phys.pas[iPML] & ~0xfff)) {
        pbSourceData = VmmTlbGetPageTable(ctxVmm, pProcess->virt2phys.pas[iPML] & ~0xfff, FALSE);
    }
    if(!_stricmp(szFile, "page") && (pProcess->virt2phys.pas[0] & ~0xfff)) {
        VmmReadPhysicalPage(ctxVmm, pProcess->virt2phys.pas[0] & ~0xfff, pbBuffer);
    }
    if(iPML || !_stricmp(szFile, "page")) {
        return VmmVfsReadFile_FromBuffer(pbSourceData, 0x1000, pb, cb, pcbRead, cbOffset);
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS VmmVfsReadFileDo(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PVMMVFS_PATH pPath, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    PVMM_MEMMAP_ENTRY pMapEntry;
    PVMM_PROCESS pProcess;
    BYTE pbBuffer[0x800];
    DWORD cbBuffer;
    QWORD cbMax, i;
    ZeroMemory(pbBuffer, 48);
    if(!ctxVmm) { return STATUS_FILE_INVALID; }
    pProcess = VmmProcessGet(ctxVmm, pPath->dwPID);
    if(!pProcess) { return STATUS_FILE_INVALID; }
    // read memory from "vmem" file
    if(!_stricmp(pPath->szPath1, "vmem")) {
        VmmReadEx(ctxVmm, pProcess, cbOffset, pb, cb, NULL, 0);
        *pcbRead = cb;
        return STATUS_SUCCESS;
    }
    // read memory from "vmemd" directory file
    if(!_stricmp(pPath->szPath1, "vmemd")) {
        pMapEntry = VmmMapGetEntry(pProcess, pPath->qwPath2);
        if(!pMapEntry) { return STATUS_FILE_INVALID; }
        if(pPath->qwPath2 & 0xfff) { return STATUS_FILE_INVALID; }
        *pcbRead = 0;
        if(pMapEntry->AddrBase + (pMapEntry->cPages << 12) <= pPath->qwPath2 + cbOffset) { return STATUS_END_OF_FILE; }
        cbMax = min((pMapEntry->AddrBase + (pMapEntry->cPages << 12)), (pPath->qwPath2 + cb + cbOffset)) - (pPath->qwPath2 - cbOffset);   // min(entry_top_addr, request_top_addr) - request_start_addr
        //QWORD tmFreq, tmStart, tmNow;
        //QueryPerformanceFrequency((PLARGE_INTEGER)&tmFreq);
        //QueryPerformanceCounter((PLARGE_INTEGER)&tmStart);
        VmmReadEx(ctxVmm, pProcess, pPath->qwPath2 + cbOffset, pb, (DWORD)min(cb, cbMax), pcbRead, (pProcess->fFileCacheDisabled ? VMM_FLAG_NOCACHE : 0));
        //QueryPerformanceCounter((PLARGE_INTEGER)&tmNow);
        //printf("Time uS VmmReadEx: %i\n", (((tmNow - tmStart) * 1000 * 1000) / tmFreq));
        return (*pcbRead) ? STATUS_SUCCESS : STATUS_END_OF_FILE;
    }
    // read the memory map
    if(!_stricmp(pPath->szPath1, "map")) {
        if(!pProcess->pbMemMapDisplayCache) {
            VmmMapDisplayBufferGenerate(pProcess);
            if(!pProcess->pbMemMapDisplayCache) {
                return STATUS_FILE_INVALID;
            }
        }
        return VmmVfsReadFile_FromBuffer(pProcess->pbMemMapDisplayCache, pProcess->cbMemMapDisplayCache, pb, cb, pcbRead, cbOffset);
    }
    // read from modules
    if(!_stricmp(pPath->szPath1, "modules") && pPath->szPath2) {
        // locate module
        for(i = 0; i < pProcess->cModuleMap; i++) {
            //TODO: COMPARE HERE !!!
        }
    }
    // read genereal numeric values from files, pml4, pid, name, virt, virt2phys
    if(!_stricmp(pPath->szPath1, "pml4")) {
        return VmmVfsReadFile_FromQWORD(pProcess->paPML4, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(pPath->szPath1, "pml4-user")) {
        return VmmVfsReadFile_FromQWORD(pProcess->paPML4_UserOpt, pb, cb, pcbRead, cbOffset, FALSE);
    }
    if(!_stricmp(pPath->szPath1, "pid")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwPID);
        return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(pPath->szPath1, "name")) {
        cbBuffer = snprintf(pbBuffer, 32, "%s", pProcess->szName);
        return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(pPath->szPath1, "virt2phys") && pPath->szPath2) {
        return VmmVfsReadFile_Virt2Phys(ctxVmm, pProcess, pPath->szPath2, pb, cb, pcbRead, cbOffset);
    }
    // windows specific reads below:
    if(ctxVmm->fWin) {
        if(!_stricmp(pPath->szPath1, "win-eprocess")) {
            return VmmVfsReadFile_FromQWORD(pProcess->os.win.vaEPROCESS, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-entry")) {
            return VmmVfsReadFile_FromQWORD(pProcess->os.win.vaENTRY, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-peb")) {
            return VmmVfsReadFile_FromQWORD(pProcess->os.win.vaPEB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath1, "win-modules") && pProcess->os.win.pbLdrModulesDisplayCache) {
            return VmmVfsReadFile_FromBuffer(pProcess->os.win.pbLdrModulesDisplayCache, pProcess->os.win.cbLdrModulesDisplayCache, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(pPath->szPath1, "win-peb32")) {
            return VmmVfsReadFile_FromDWORD(pProcess->os.win.vaPEB32, pb, cb, pcbRead, cbOffset, FALSE);
        }
    }
    // file in modules directory
    if(!_stricmp(pPath->szPath1, "modules") && pPath->szPath2[0] && pPath->szPath3[0]) {
        for(i = 0; i < pProcess->cModuleMap; i++) {
            if(0 == strncmp(pPath->szPath2, pProcess->pModuleMap[i].szName, MAX_PATH)) {
                if(!_stricmp(pPath->szPath3, "base")) {
                    return VmmVfsReadFile_FromQWORD(pProcess->pModuleMap[i].BaseAddress, pb, cb, pcbRead, cbOffset, FALSE);
                }
                if(!_stricmp(pPath->szPath3, "entry")) {
                    return VmmVfsReadFile_FromQWORD(pProcess->pModuleMap[i].EntryPoint, pb, cb, pcbRead, cbOffset, FALSE);
                }
                if(!_stricmp(pPath->szPath3, "size")) {
                    return VmmVfsReadFile_FromDWORD(pProcess->pModuleMap[i].SizeOfImage, pb, cb, pcbRead, cbOffset, FALSE);
                }
                if(!_stricmp(pPath->szPath3, "directories")) {
                    VmmProcWindows_PE_DIRECTORY_DisplayBuffer(ctxVmm, pProcess, pProcess->pModuleMap + i, pbBuffer, 0x400, &cbBuffer, NULL);
                    return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
                }
                if(!_stricmp(pPath->szPath3, "export")) {
                    VmmProcWindows_PE_LoadEAT_DisplayBuffer(ctxVmm, pProcess, pProcess->pModuleMap + i, TRUE, NULL, 0);
                    if(!memcmp(pProcess->os.win.szDisplayCacheEAT, pProcess->pModuleMap[i].szName, 32)) {
                        return VmmVfsReadFile_FromBuffer(pProcess->os.win.pbDisplayCacheEAT, pProcess->pModuleMap[i].cbDisplayBufferEAT, pb, cb, pcbRead, cbOffset);
                    }
                }
                if(!_stricmp(pPath->szPath3, "import")) {
                    VmmProcWindows_PE_LoadIAT_DisplayBuffer(ctxVmm, pProcess, pProcess->pModuleMap + i, TRUE, NULL, 0);
                    if(!memcmp(pProcess->os.win.szDisplayCacheIAT, pProcess->pModuleMap[i].szName, 32)) {
                        return VmmVfsReadFile_FromBuffer(pProcess->os.win.pbDisplayCacheIAT, pProcess->pModuleMap[i].cbDisplayBufferIAT, pb, cb, pcbRead, cbOffset);
                    }
                }
                if(!_stricmp(pPath->szPath3, "sections")) {
                    VmmProcWindows_PE_SECTION_DisplayBuffer(ctxVmm, pProcess, pProcess->pModuleMap + i, pbBuffer, 0x800, &cbBuffer, NULL);
                    return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
                }
                return STATUS_FILE_INVALID;
            }
        }
        return STATUS_FILE_INVALID;
    }
    // read file in .config directory
    if(!_stricmp(pPath->szPath1, ".config")) {
        *pcbRead = 0;
        // file: cache_file_enable
        if(!_stricmp(pPath->szPath2, "cache_file_enable")) {
            return VmmVfsReadFile_FromBOOL(!pProcess->fFileCacheDisabled, pb, cb, pcbRead, cbOffset);
        }
        // files: global_refresh*
        if(!_stricmp(pPath->szPath2, "global_refresh_enable")) {
            return VmmVfsReadFile_FromBOOL(ctxVmm->ThreadProcCache.fEnabled, pb, cb, pcbRead, cbOffset);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_tick_period_ms")) {
            return VmmVfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cMs_TickPeriod, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_read")) {
            return VmmVfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_Phys, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_tlb")) {
            return VmmVfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_TLB, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_proc_partial")) {
            return VmmVfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_ProcPartial, pb, cb, pcbRead, cbOffset, FALSE);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_proc_total")) {
            return VmmVfsReadFile_FromDWORD(ctxVmm->ThreadProcCache.cTick_ProcTotal, pb, cb, pcbRead, cbOffset, FALSE);
        }
        return STATUS_FILE_INVALID;
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS VmmVfsReadFile(_Inout_ PPCILEECH_CONTEXT ctx, LPCWSTR wcsFileName, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    VMMVFS_PATH path;
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    if(!ctxVmm || !ctxVmm->ptPROC) { return STATUS_FILE_INVALID; }
    if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path)) { return STATUS_FILE_INVALID; }
    EnterCriticalSection(&ctxVmm->MasterLock);
    nt = VmmVfsReadFileDo(ctx, &path, pb, cb, pcbRead, cbOffset);
    LeaveCriticalSection(&ctxVmm->MasterLock);
    return nt;
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: WRITE
// ----------------------------------------------------------------------------

NTSTATUS VmmVfsWriteFile_DWORD(_Inout_ PDWORD pdwTarget, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset, _In_ DWORD dwMinAllow)
{
    BYTE pbBuffer[9];
    DWORD dw;
    if(cbOffset < 8) {
        *pcbWrite = cb;
        snprintf(pbBuffer, 9, "%08x", *pdwTarget);
        cb = (DWORD)min(8 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[8] = 0;
        dw = strtoul(pbBuffer, NULL, 16);
        dw = max(dw, dwMinAllow);
        *pdwTarget = dw;
    } else {
        *pcbWrite = 0;
    }
    return STATUS_SUCCESS;
}

NTSTATUS VmmVfsWriteFile_Virt2PhysVA(PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BYTE pbBuffer[17];
    if(cbOffset < 16) {
        *pcbWrite = cb;
        snprintf(pbBuffer, 17, "%016llx", pProcess->virt2phys.va);
        cb = (DWORD)min(16 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[16] = 0;
        pProcess->virt2phys.va = strtoull(pbBuffer, NULL, 16);
        VmmVirt2PhysUpdateProcess(ctxVmm, pProcess);
    } else {
        *pcbWrite = 0;
    }
    return STATUS_SUCCESS;
}

NTSTATUS VmmVfsWriteFile_Virt2Phys(PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ LPSTR szFile, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    DWORD i;
    if(!_stricmp(szFile, "virt")) {
        return VmmVfsWriteFile_Virt2PhysVA(ctxVmm, pProcess, pb, cb, pcbWrite, cbOffset);
    }
    i = 0xff;
    if(!_stricmp(szFile, "pt_pml4")) { i = 4; }
    if(!_stricmp(szFile, "pt_pdpt")) { i = 3; }
    if(!_stricmp(szFile, "pt_pd"))   { i = 2; }
    if(!_stricmp(szFile, "pt_pt"))   { i = 1; }
    if(!_stricmp(szFile, "page"))    { i = 0; }
    if(i > 4) { return STATUS_FILE_INVALID; }
    if(pProcess->virt2phys.pas[i] < 0x1000) { return STATUS_FILE_INVALID; }
    if(cbOffset > 0x1000) { return STATUS_END_OF_FILE; }
    *pcbWrite = (DWORD)min(cb, 0x1000 - cbOffset);
    VmmWritePhysical(ctxVmm, pProcess->virt2phys.pas[i] + cbOffset, pb, *pcbWrite);
    return *pcbWrite ? STATUS_SUCCESS : STATUS_END_OF_FILE;

}

NTSTATUS VmmVfsWriteFileDo(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PVMMVFS_PATH pPath, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    PVMM_MEMMAP_ENTRY pMapEntry;
    PVMM_PROCESS pProcess;
    BOOL fFound, result;
    QWORD cbMax;
    if(!pPath->szPath1) { return STATUS_FILE_INVALID; }
    pProcess = VmmProcessGet(ctxVmm, pPath->dwPID);
    if(!pProcess) { return STATUS_FILE_INVALID; }
    // read only files - report zero bytes written
    fFound =
        !_stricmp(pPath->szPath1, "map") ||
        !_stricmp(pPath->szPath1, "pml4") ||
        !_stricmp(pPath->szPath1, "pid") ||
        !_stricmp(pPath->szPath1, "name") ||
        (!_stricmp(pPath->szPath1, "vmemd") && (pPath->qwPath2 == (QWORD)-1));
    if(fFound) {
        *pcbWrite = 0;
        return STATUS_SUCCESS;
    }
    // windows specific writes below:
    if(ctxVmm->fWin) {
        fFound =
            !_stricmp(pPath->szPath1, "win-eprocess") ||
            !_stricmp(pPath->szPath1, "win-peb") ||
            !_stricmp(pPath->szPath1, "win-entry") ||
            !_stricmp(pPath->szPath1, "win-modules");
        if(fFound) {
            *pcbWrite = 0;
            return STATUS_SUCCESS;
        }
    }
    // write virt2phys
    if(!_stricmp(pPath->szPath1, "virt2phys")) {
        return VmmVfsWriteFile_Virt2Phys(ctxVmm, pProcess, pPath->szPath2, pb, cb, pcbWrite, cbOffset);
    }
    // write memory to "vmem" file
    if(!_stricmp(pPath->szPath1, "vmem")) {
        result = VmmWrite(ctxVmm, pProcess, cbOffset, pb, cb);
        *pcbWrite = cb;
        return STATUS_SUCCESS;
    }
    // write memory from "vmemd" directory file
    if(!_stricmp(pPath->szPath1, "vmemd")) {
        pMapEntry = VmmMapGetEntry(pProcess, pPath->qwPath2);
        if(!pMapEntry) { return STATUS_FILE_INVALID; }
        if(pPath->qwPath2 & 0xfff) { return STATUS_FILE_INVALID; }
        *pcbWrite = 0;
        if(pMapEntry->AddrBase + (pMapEntry->cPages << 12) <= pPath->qwPath2 + cbOffset) { return STATUS_END_OF_FILE; }
        cbMax = min((pMapEntry->AddrBase + (pMapEntry->cPages << 12)), (pPath->qwPath2 + cb + cbOffset)) - (pPath->qwPath2 - cbOffset);   // min(entry_top_addr, request_top_addr) - request_start_addr
        VmmWrite(ctxVmm, pProcess, pPath->qwPath2 + cbOffset, pb, (DWORD)min(cb, cbMax));
        *pcbWrite = cb;
        return STATUS_SUCCESS;
    }
    // write file in .config directory
    if(!_stricmp(pPath->szPath1, ".config")) {
        // file: cache_file_enable
        if(!_stricmp(pPath->szPath2, "cache_file_enable")) {
            if((cbOffset == 0) && (cb > 0)) {
                if(((PCHAR)pb)[0] == '1') { pProcess->fFileCacheDisabled = FALSE; }
                if(((PCHAR)pb)[0] == '0') { pProcess->fFileCacheDisabled = TRUE; }
            }
            *pcbWrite = cb;
            return STATUS_SUCCESS;
        }
        // files: global_refresh*
        if(!_stricmp(pPath->szPath2, "global_refresh_tick_period_ms")) {
            return VmmVfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cMs_TickPeriod, pb, cb, pcbWrite, cbOffset, 50);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_read")) {
            return VmmVfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_Phys, pb, cb, pcbWrite, cbOffset, 1);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_tlb")) {
            return VmmVfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_TLB, pb, cb, pcbWrite, cbOffset, 1);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_proc_partial")) {
            return VmmVfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_ProcPartial, pb, cb, pcbWrite, cbOffset, 1);
        }
        if(!_stricmp(pPath->szPath2, "global_refresh_proc_total")) {
            return VmmVfsWriteFile_DWORD(&ctxVmm->ThreadProcCache.cTick_ProcTotal, pb, cb, pcbWrite, cbOffset, 1);
        }
        return STATUS_FILE_INVALID;
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS VmmVfsWriteFile(_Inout_ PPCILEECH_CONTEXT ctx, LPCWSTR wcsFileName, _In_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    VMMVFS_PATH path;
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    if(!ctxVmm || !ctxVmm->ptPROC) { return STATUS_FILE_INVALID; }
    if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path)) { return STATUS_FILE_INVALID; }
    EnterCriticalSection(&ctxVmm->MasterLock);
    nt = VmmVfsWriteFileDo(ctx, &path, pb, cb, pcbWrite, cbOffset);
    LeaveCriticalSection(&ctxVmm->MasterLock);
    return nt;
}

// ----------------------------------------------------------------------------
// FUNCTIONALITY RELATED TO: LIST
// ----------------------------------------------------------------------------

VOID VmmVfsListFiles_PopulateResultFileInfo(_Inout_ PVFS_RESULT_FILEINFO pfi, _In_ LPSTR szName, _In_ QWORD cb, _In_ QWORD flags)
{
    DWORD i = 0;
    while(i < MAX_PATH && szName[i]) {
        pfi->wszFileName[i] = szName[i];
        i++;
    }
    pfi->wszFileName[i] = 0;
    pfi->flags = flags;
    pfi->cb = cb;
}

VOID VmmVfsListFiles_OsSpecific(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _Inout_ PVFS_RESULT_FILEINFO *ppfi, _Inout_ PQWORD pcfi, _In_ QWORD cfiMax)
{
    // WINDOWS
    if(ctxVmm->fWin) {
        if(*pcfi >= cfiMax) { return; }
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-eprocess", 16, VFS_FLAGS_FILE_NORMAL);
        *pcfi = *pcfi + 1;
        if(*pcfi >= cfiMax) { return; }
        if(pProcess->os.win.vaENTRY) {
            VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-entry", 16, VFS_FLAGS_FILE_NORMAL);
            *pcfi = *pcfi + 1;
            if(*pcfi >= cfiMax) { return; }
        }
        // 64-bit PEB and modules
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-peb", 16, VFS_FLAGS_FILE_NORMAL);
        *pcfi = *pcfi + 1;
        if(*pcfi >= cfiMax) { return; }
        if(pProcess->os.win.cbLdrModulesDisplayCache) {
            VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-modules", pProcess->os.win.cbLdrModulesDisplayCache, VFS_FLAGS_FILE_NORMAL);
            *pcfi = *pcfi + 1;
            if(*pcfi >= cfiMax) { return; }
        }
        // 32-bit PEB and modules
        if(pProcess->os.win.vaPEB32) {
            VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-peb32", 8, VFS_FLAGS_FILE_NORMAL);
            *pcfi = *pcfi + 1;
            if(*pcfi >= cfiMax) { return; }
        }
    }
}

_Success_(return)
BOOL VmmVfsListFilesDo(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PVMMVFS_PATH pPath, _Out_ PVFS_RESULT_FILEINFO *ppfi, _Out_ PQWORD pcfi)
{
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    PVFS_RESULT_FILEINFO pfi;
    PVMM_PROCESS pProcess;
    WORD iProcess;
    DWORD i, cMax;
    if(!ctxVmm || !ctxVmm->ptPROC) { return FALSE; }
    // populate root node - list processes as directories
    if(pPath->fRoot) {
        *ppfi = LocalAlloc(LMEM_ZEROINIT, ctxVmm->ptPROC->c * sizeof(VFS_RESULT_FILEINFO));
        if(!*ppfi) { return FALSE; }
        *pcfi = 0;
        iProcess = ctxVmm->ptPROC->iFLink;
        pProcess = ctxVmm->ptPROC->M[iProcess];
        while(pProcess) {
            {
                pfi = *ppfi + *pcfi;
                if(pPath->fNamePID) {
                    if(pProcess->dwState) {
                        swprintf(pfi->wszFileName, MAX_PATH - 1, L"%S-(%x)-%i", pProcess->szName, pProcess->dwState, pProcess->dwPID);
                    } else {
                        swprintf(pfi->wszFileName, MAX_PATH - 1, L"%S-%i", pProcess->szName, pProcess->dwPID);
                    }
                } else {
                    swprintf(pfi->wszFileName, MAX_PATH - 1, L"%i", pProcess->dwPID);
                }
                pfi->flags = VFS_FLAGS_FILE_DIRECTORY;
                *pcfi = *pcfi + 1;
            }
            iProcess = ctxVmm->ptPROC->iFLinkM[iProcess];
            pProcess = ctxVmm->ptPROC->M[iProcess];
            if(!iProcess || iProcess == ctxVmm->ptPROC->iFLink) { break; }
        }
        return TRUE;
    }
    // generate memmap, if not already done. required by following steps
    pProcess = VmmProcessGet(ctxVmm, pPath->dwPID);
    if(!pProcess) { return FALSE; }
    if(!pProcess->pMemMap || !pProcess->cMemMap) {
        if(!pProcess->fSpiderPageTableDone) {
            VmmTlbSpider(ctxVmm, 0, pProcess->fUserOnly);
            pProcess->fSpiderPageTableDone = TRUE;
        }
        VmmMapInitialize(ctxVmm, pProcess);
        VmmProc_InitializeModuleNames(ctxVmm, pProcess);
        VmmMapDisplayBufferGenerate(pProcess);
    }
    // populate process directory - list standard files and subdirectories
    if(!pPath->szPath1) {
        i = 0, cMax = 15;
        if(!(*ppfi = LocalAlloc(LMEM_ZEROINIT, cMax * sizeof(VFS_RESULT_FILEINFO)))) { return FALSE; }
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "map", pProcess->cbMemMapDisplayCache, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "name", 16, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "pid", 10, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "pml4", 16, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "vmem", 0x0001000000000000, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "modules", 0, VFS_FLAGS_FILE_DIRECTORY);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "virt2phys", 0, VFS_FLAGS_FILE_DIRECTORY);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "vmemd", 0, VFS_FLAGS_FILE_DIRECTORY);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, ".config", 0, VFS_FLAGS_FILE_DIRECTORY);
        if(pProcess->paPML4_UserOpt) {
            VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i++, "pml4-user", 16, VFS_FLAGS_FILE_NORMAL);
        }
        *pcfi = i;
        VmmVfsListFiles_OsSpecific(ctxVmm, pProcess, ppfi, pcfi, cMax);
        return TRUE;
    }
    // populate memory map directory
    if(!_stricmp(pPath->szPath1, "vmemd") && pProcess->pMemMap) {
        *pcfi = pProcess->cMemMap;
        *ppfi = LocalAlloc(LMEM_ZEROINIT, pProcess->cMemMap * sizeof(VFS_RESULT_FILEINFO));
        if(pProcess->cMemMap > 0) {
            if(!*ppfi) { return FALSE; }
            for(i = 0; i < pProcess->cMemMap; i++) {
                pfi = *ppfi + i;
                swprintf(
                    pfi->wszFileName,
                    MAX_PATH - 1,
                    L"0x%016llx%s%S.vmem",
                    pProcess->pMemMap[i].AddrBase,
                    pProcess->pMemMap[i].szName[0] ? L"-" : L"",
                    pProcess->pMemMap[i].szName[0] ? pProcess->pMemMap[i].szName : "");
                pfi->cb = pProcess->pMemMap[i].cPages << 12;
                pfi->flags = VFS_FLAGS_FILE_NORMAL;
            }
        }
        return TRUE;
    }
    // populate virt2phys directory
    if(!_stricmp(pPath->szPath1, "virt2phys")) {
        *pcfi = 8;
        *ppfi = LocalAlloc(LMEM_ZEROINIT, *pcfi * sizeof(VFS_RESULT_FILEINFO));
        if(!*ppfi) { return FALSE; }
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 0, "virt", 16, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 1, "phys", 16, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 2, "map", 198, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 3, "page", 0x1000, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 4, "pt_pml4", 0x1000, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 5, "pt_pdpt", 0x1000, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 6, "pt_pd", 0x1000, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 7, "pt_pt", 0x1000, VFS_FLAGS_FILE_NORMAL);
        return TRUE;
    }
    // populate modules directory
    if(!_stricmp(pPath->szPath1, "modules") && pProcess->cModuleMap) {
        // modules directory -> list all modules
        if(!pPath->szPath2) {
            *pcfi = pProcess->cModuleMap;
            *ppfi = LocalAlloc(LMEM_ZEROINIT, pProcess->cModuleMap * sizeof(VFS_RESULT_FILEINFO));
            if(!*ppfi) { return FALSE; }
            for(i = 0; i < pProcess->cModuleMap; i++) {
                VmmVfsListFiles_PopulateResultFileInfo(*ppfi + i, pProcess->pModuleMap[i].szName, 0, VFS_FLAGS_FILE_DIRECTORY);
            }
            return TRUE;
        }
        // individual module directory -> list files
        if(!pPath->szPath3) {
            for(i = 0; i < pProcess->cModuleMap; i++) {
                if(0 == strncmp(pPath->szPath2, pProcess->pModuleMap[i].szName, MAX_PATH)) {
                    *pcfi = 7;
                    *ppfi = LocalAlloc(LMEM_ZEROINIT, *pcfi * sizeof(VFS_RESULT_FILEINFO));
                    if(!*ppfi) { return FALSE; }
                    VmmProcWindows_PE_SetSizeSectionIATEAT_DisplayBuffer(ctxVmm, pProcess, pProcess->pModuleMap + i);
                    VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 0, "base", 16, VFS_FLAGS_FILE_NORMAL);
                    VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 1, "entry", 16, VFS_FLAGS_FILE_NORMAL);
                    VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 2, "size", 8, VFS_FLAGS_FILE_NORMAL);
                    VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 3, "directories", 864, VFS_FLAGS_FILE_NORMAL);
                    VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 4, "export", pProcess->pModuleMap[i].cbDisplayBufferEAT, VFS_FLAGS_FILE_NORMAL);
                    VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 5, "import", pProcess->pModuleMap[i].cbDisplayBufferIAT, VFS_FLAGS_FILE_NORMAL);
                    VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 6, "sections", pProcess->pModuleMap[i].cbDisplayBufferSections, VFS_FLAGS_FILE_NORMAL);
                    return TRUE;
                }
            }
            return FALSE;
        }
        printf("DEBUG PATH: %s :: %s \n", pPath->szPath2, pPath->szPath3);
    }
    // populate .config directory
    if(!_stricmp(pPath->szPath1, ".config")) {
        *pcfi = 7;
        *ppfi = LocalAlloc(LMEM_ZEROINIT, *pcfi * sizeof(VFS_RESULT_FILEINFO));
        if(!*ppfi) { return FALSE; }
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 0, "cache_file_enable", 1, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 1, "global_refresh_enable", 1, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 2, "global_refresh_tick_period_ms", 8, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 3, "global_refresh_read", 8, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 4, "global_refresh_tlb", 8, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 5, "global_refresh_proc_partial", 8, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 6, "global_refresh_proc_total", 8, VFS_FLAGS_FILE_NORMAL);
        return TRUE;
    }
    // no hit - return false
    return FALSE;
}

BOOL VmmVfsListFiles(_Inout_ PPCILEECH_CONTEXT ctx, _In_ LPCWSTR wcsFileName, _Out_ PVFS_RESULT_FILEINFO *ppfi, _Out_ PQWORD pcfi)
{
    BOOL result;
    VMMVFS_PATH path;
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    if(!ctxVmm || !ctxVmm->ptPROC) { return FALSE; }
    if(!VmmVfs_UtilVmmGetPidDirFile(wcsFileName, &path)) { return FALSE; }
    EnterCriticalSection(&ctxVmm->MasterLock);
    result = VmmVfsListFilesDo(ctx, &path, ppfi, pcfi);
    LeaveCriticalSection(&ctxVmm->MasterLock);
    return result;
}
