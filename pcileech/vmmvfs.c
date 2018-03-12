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

NTSTATUS VmmVfsReadFile_FromBuffer(_In_ PBYTE pbFile, _In_ QWORD cbFile, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(cbOffset > cbFile) { return STATUS_END_OF_FILE; }
    *pcbRead = (DWORD)min(cb, cbFile - cbOffset);
    memcpy(pb, pbFile + cbOffset, *pcbRead);
    return *pcbRead ? STATUS_SUCCESS : STATUS_END_OF_FILE;
}

NTSTATUS VmmVfsReadFile_FromQWORD(_In_ QWORD qwValue, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BYTE pbBuffer[32];
    DWORD cbBuffer;
    cbBuffer = snprintf(pbBuffer, 32, "0x%016llx", qwValue);
    return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
}

NTSTATUS VmmVfsReadFileDo(_Inout_ PPCILEECH_CONTEXT ctx, _In_opt_ DWORD dwPID, _In_opt_ LPWSTR wszPath1, _In_opt_ QWORD qwPath2, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    PVMM_MEMMAP_ENTRY pMapEntry;
    PVMM_PROCESS pProcess;
    BYTE pbBuffer[48];
    DWORD cbBuffer;
    QWORD cbMax;
    ZeroMemory(pbBuffer, 48);
    if(!ctxVmm) { return STATUS_FILE_INVALID; }
    pProcess = VmmProcessGet(ctxVmm, dwPID);
    if(!pProcess) { return STATUS_FILE_INVALID; }
    // read memory from "vmem" file
    if(!_wcsicmp(wszPath1, L"vmem")) {
        VmmReadEx(ctxVmm, pProcess, cbOffset, pb, cb, NULL);
        *pcbRead = cb;
        return STATUS_SUCCESS;
    }
    // read memory from "vmemd" directory file
    if(!_wcsicmp(wszPath1, L"vmemd")) {
        pMapEntry = VmmMapGetEntry(pProcess, qwPath2);
        if(!pMapEntry) { return STATUS_FILE_INVALID; }
        if(qwPath2 & 0xfff) { return STATUS_FILE_INVALID; }
        *pcbRead = 0;
        if(pMapEntry->AddrBase + (pMapEntry->cPages << 12) <= qwPath2 + cbOffset) { return STATUS_END_OF_FILE; }
        cbMax = min((pMapEntry->AddrBase + (pMapEntry->cPages << 12)), (qwPath2 + cb + cbOffset)) - (qwPath2 - cbOffset);   // min(entry_top_addr, request_top_addr) - request_start_addr
        VmmReadEx(ctxVmm, pProcess, qwPath2 + cbOffset, pb, (DWORD)min(cb, cbMax), pcbRead);
        return (*pcbRead) ? STATUS_SUCCESS : STATUS_END_OF_FILE;
    }
    // read the memory map
    if(!_wcsicmp(wszPath1, L"map")) {
        if(!pProcess->pbMemMapDisplayCache) {
            VmmMapDisplayBufferGenerate(pProcess);
            if(!pProcess->pbMemMapDisplayCache) {
                return STATUS_FILE_INVALID;
            }
        }
        return VmmVfsReadFile_FromBuffer(pProcess->pbMemMapDisplayCache, pProcess->cbMemMapDisplayCache, pb, cb, pcbRead, cbOffset);
    }
    // read genereal numeric values from files, pml4, pid, name, virt, virt2phys
    if(!_wcsicmp(wszPath1, L"pml4")) {
        return VmmVfsReadFile_FromQWORD(pProcess->paPML4, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(wszPath1, L"pid")) {
        cbBuffer = snprintf(pbBuffer, 32, "%i", pProcess->dwPID);
        return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(wszPath1, L"name")) {
        cbBuffer = snprintf(pbBuffer, 32, "%s", pProcess->szName);
        return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    if(!_wcsicmp(wszPath1, L"virt2phys")) {
        cbBuffer = snprintf(pbBuffer, 48, "0x%016llx 0x%016llx", pProcess->Virt2Phys_VA, pProcess->Virt2Phys_PA);
        return VmmVfsReadFile_FromBuffer(pbBuffer, cbBuffer, pb, cb, pcbRead, cbOffset);
    }
    // windows specific reads below:
    if(ctxVmm->fWin) {
        if(!_wcsicmp(wszPath1, L"win-eprocess")) {
            return VmmVfsReadFile_FromQWORD(pProcess->os.win.vaEPROCESS, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(wszPath1, L"win-peb")) {
            return VmmVfsReadFile_FromQWORD(pProcess->os.win.vaPEB, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(wszPath1, L"win-entry")) {
            return VmmVfsReadFile_FromQWORD(pProcess->os.win.vaENTRY, pb, cb, pcbRead, cbOffset);
        }
        if(!_wcsicmp(wszPath1, L"win-modules") && pProcess->os.win.pbLdrModulesDisplayCache) {
            return VmmVfsReadFile_FromBuffer(pProcess->os.win.pbLdrModulesDisplayCache, pProcess->os.win.cbLdrModulesDisplayCache, pb, cb, pcbRead, cbOffset);
        }
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS VmmVfsReadFile(_Inout_ PPCILEECH_CONTEXT ctx, _In_opt_ DWORD dwPID, _In_opt_ LPWSTR wszPath1, _In_opt_ QWORD qwPath2, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    EnterCriticalSection(&ctxVmm->MasterLock);
    nt = VmmVfsReadFileDo(ctx, dwPID, wszPath1, qwPath2, pb, cb, pcbRead, cbOffset);
    LeaveCriticalSection(&ctxVmm->MasterLock);
    return nt;
}


NTSTATUS VmmVfsWriteFile_Virt2Phys(PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    BYTE pbBuffer[48];
    if(cbOffset < 18) {
        *pcbWrite = cb;
        snprintf(pbBuffer, 48, "0x%016llx 0x%016llx", pProcess->Virt2Phys_VA, pProcess->Virt2Phys_PA);
        cb = (DWORD)min(18 - cbOffset, cb);
        memcpy(pbBuffer + cbOffset, pb, cb);
        pbBuffer[18] = 0;
        pProcess->Virt2Phys_VA = Util_GetNumeric((LPSTR)pbBuffer);
        VmmVirt2Phys(ctxVmm, pProcess, pProcess->Virt2Phys_VA, &pProcess->Virt2Phys_PA);
    } else {
        *pcbWrite = 0;
    }
    return STATUS_SUCCESS;
}

NTSTATUS VmmVfsWriteFileDo(_Inout_ PPCILEECH_CONTEXT ctx, _In_opt_ DWORD dwPID, _In_opt_ LPWSTR wszPath1, _In_opt_ QWORD qwPath2, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    PVMM_MEMMAP_ENTRY pMapEntry;
    PVMM_PROCESS pProcess;
    BOOL fFound, result;
    QWORD cbMax;
    if(!wszPath1) { return STATUS_FILE_INVALID; }
    pProcess = VmmProcessGet(ctxVmm, dwPID);
    if(!pProcess) { return STATUS_FILE_INVALID; }
    // read only files - report zero bytes written
    fFound =
        !_wcsicmp(wszPath1, L"map") ||
        !_wcsicmp(wszPath1, L"pml4") ||
        !_wcsicmp(wszPath1, L"pid") ||
        !_wcsicmp(wszPath1, L"name") ||
        (!_wcsicmp(wszPath1, L"vmemd") && (qwPath2 == (QWORD)-1));
    if(fFound) {
        *pcbWrite = 0;
        return STATUS_SUCCESS;
    }
    // windows specific writes below:
    if(ctxVmm->fWin) {
        fFound =
            !_wcsicmp(wszPath1, L"win-eprocess") ||
            !_wcsicmp(wszPath1, L"win-peb") ||
            !_wcsicmp(wszPath1, L"win-entry") ||
            !_wcsicmp(wszPath1, L"win-modules");
        if(fFound) {
            *pcbWrite = 0;
            return STATUS_SUCCESS;
        }
    }
    // write: virt file
    if(!_wcsicmp(wszPath1, L"virt2phys")) {
        return VmmVfsWriteFile_Virt2Phys(ctxVmm, pProcess, pb, cb, pcbWrite, cbOffset);
    }
    // write memory to "vmem" file
    if(!_wcsicmp(wszPath1, L"vmem")) {
        result = VmmWrite(ctxVmm, pProcess, cbOffset, pb, cb);
        *pcbWrite = cb;
        return STATUS_SUCCESS;
    }
    // write memory from "vmemd" directory file
    if(!_wcsicmp(wszPath1, L"vmemd")) {
        pMapEntry = VmmMapGetEntry(pProcess, qwPath2);
        if(!pMapEntry) { return STATUS_FILE_INVALID; }
        if(qwPath2 & 0xfff) { return STATUS_FILE_INVALID; }
        *pcbWrite = 0;
        if(pMapEntry->AddrBase + (pMapEntry->cPages << 12) <= qwPath2 + cbOffset) { return STATUS_END_OF_FILE; }
        cbMax = min((pMapEntry->AddrBase + (pMapEntry->cPages << 12)), (qwPath2 + cb + cbOffset)) - (qwPath2 - cbOffset);   // min(entry_top_addr, request_top_addr) - request_start_addr
        VmmWrite(ctxVmm, pProcess, qwPath2 + cbOffset, pb, (DWORD)min(cb, cbMax));
        *pcbWrite = cb;
        return STATUS_SUCCESS;
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS VmmVfsWriteFile(_Inout_ PPCILEECH_CONTEXT ctx, _In_opt_ DWORD dwPID, _In_opt_ LPWSTR wszPath1, _In_opt_ QWORD qwPath2, _Out_ LPVOID pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    NTSTATUS nt;
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    EnterCriticalSection(&ctxVmm->MasterLock);
    nt = VmmVfsWriteFileDo(ctx, dwPID, wszPath1, qwPath2, pb, cb, pcbWrite, cbOffset);
    LeaveCriticalSection(&ctxVmm->MasterLock);
    return nt;
}

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
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-eprocess", 18, VFS_FLAGS_FILE_NORMAL);
        *pcfi = *pcfi + 1;
        if(*pcfi >= cfiMax) { return; }
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-peb", 18, VFS_FLAGS_FILE_NORMAL);
        *pcfi = *pcfi + 1;
        if(*pcfi >= cfiMax) { return; }
        if(pProcess->os.win.vaENTRY) {
            VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-entry", 18, VFS_FLAGS_FILE_NORMAL);
            *pcfi = *pcfi + 1;
            if(*pcfi >= cfiMax) { return; }
        }
        if(pProcess->os.win.cbLdrModulesDisplayCache) {
            VmmVfsListFiles_PopulateResultFileInfo(*ppfi + *pcfi, "win-modules", pProcess->os.win.cbLdrModulesDisplayCache, VFS_FLAGS_FILE_NORMAL);
            *pcfi = *pcfi + 1;
            if(*pcfi >= cfiMax) { return; }
        }
    }
}

_Success_(return)
BOOL VmmVfsListFilesDo(_Inout_ PPCILEECH_CONTEXT ctx, _In_ BOOL fRoot, _In_ BOOL fNamesPid, _In_opt_ DWORD dwPID, _In_opt_ LPWSTR wszPath1, _In_opt_ QWORD qwPath2, _Out_ PVFS_RESULT_FILEINFO *ppfi, _Out_ PQWORD pcfi)
{
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    PVFS_RESULT_FILEINFO pfi;
    PVMM_PROCESS pProcess;
    WORD iProcess;
    DWORD i, cMax;
    if(!ctxVmm) { return FALSE; }
    // populate root node - list processes as directories
    if(fRoot) {
        *ppfi = LocalAlloc(LMEM_ZEROINIT, ctxVmm->ptPROC->c * sizeof(VFS_RESULT_FILEINFO));
        if(!*ppfi) { return FALSE; }
        *pcfi = 0;
        iProcess = ctxVmm->ptPROC->iFLink;
        pProcess = ctxVmm->ptPROC->M[iProcess];
        while(pProcess) {
            {
                pfi = *ppfi + *pcfi;
                if(fNamesPid) {
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
    pProcess = VmmProcessGet(ctxVmm, dwPID);
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
    // populate process directory - list standard files and memd subdirectory
    if(!wszPath1) {
        cMax = 12;
        *pcfi = 7;
        *ppfi = LocalAlloc(LMEM_ZEROINIT, cMax * sizeof(VFS_RESULT_FILEINFO));
        if(!*ppfi) { return FALSE; }
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 0, "map", pProcess->cbMemMapDisplayCache, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 1, "vmem", 0x0001000000000000, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 2, "vmemd", 0, VFS_FLAGS_FILE_DIRECTORY);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 3, "name", 16, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 4, "pid", 10, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 5, "pml4", 18, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_PopulateResultFileInfo(*ppfi + 6, "virt2phys", 37, VFS_FLAGS_FILE_NORMAL);
        VmmVfsListFiles_OsSpecific(ctxVmm, pProcess, ppfi, pcfi, cMax);
        return TRUE;
    }
    // populate memory map directory
    if(!_wcsicmp(wszPath1, L"vmemd") && pProcess->pMemMap) {
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
    return FALSE;
}

BOOL VmmVfsListFiles(_Inout_ PPCILEECH_CONTEXT ctx, _In_ BOOL fRoot, _In_ BOOL fNamesPid, _In_opt_ DWORD dwPID, _In_opt_ LPWSTR wszPath1, _In_opt_ QWORD qwPath2, _Out_ PVFS_RESULT_FILEINFO *ppfi, _Out_ PQWORD pcfi)
{
    BOOL result;
    PVMM_CONTEXT ctxVmm = (PVMM_CONTEXT)ctx->hVMM;
    EnterCriticalSection(&ctxVmm->MasterLock);
    result = VmmVfsListFilesDo(ctx, fRoot, fNamesPid, dwPID, wszPath1, qwPath2, ppfi, pcfi);
    LeaveCriticalSection(&ctxVmm->MasterLock);
    return result;
}
