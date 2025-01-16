// vfs.c : implementation of functions related to virtual file system support.
//
// (c) Ulf Frisk, 2017-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "vfs.h"
#include "vfslist.h"
#include "device.h"
#include "executor.h"
#include "charutil.h"
#include "util.h"
#include <vmmdll.h>

#ifdef WIN32
#pragma warning( push )  
#pragma warning( disable : 4005 )   
#include <dokan.h>
#pragma warning( pop )
#endif /* WIN32 */
#if defined(LINUX) || defined(MACOS)
#define FUSE_USE_VERSION 30
#include <fuse.h>
#include "oscompatibility.h"
#endif /* LINUX || LINUX */



//-------------------------------------------------------------------------------
// Defines and Typedefs (shared with shellcode) below:
//-------------------------------------------------------------------------------

#define VFS_OP_MAGIC                    0x79e720ad93aa130f
#define VFS_OP_CMD_LIST_DIRECTORY       1
#define VFS_OP_CMD_WRITE                2
#define VFS_OP_CMD_READ                 3
#define VFS_OP_CMD_CREATE               4
#define VFS_OP_CMD_DELETE               5
#define VFS_OP_CMD_LIST_DRIVES          6

typedef struct tdVFS_OPERATION {
    QWORD magic;
    QWORD op;
    QWORD flags;
    CHAR szFileName[MAX_PATH];
    WCHAR wszFileName[MAX_PATH];
    QWORD offset;
    QWORD cb;
    BYTE pb[];
} VFS_OPERATION, *PVFS_OPERATION;

typedef struct tdVFS_GLOBAL_STATE {
    QWORD cbKmd;
    QWORD cbNative;
    CRITICAL_SECTION Lock;
    QWORD PCILeechOperatingSystem;
    CHAR szNameVfsShellcode[32];
    // dokan only below:
    FILETIME ftDefaultTime;
    NTSTATUS(*DokanNtStatusFromWin32)(DWORD Error);
} VFS_GLOBAL_STATE, *PVFS_GLOBAL_STATE;

static PVFS_GLOBAL_STATE g_vfs = NULL;

/*
* Helper function to initialize a file operation
* -- pop
* -- qwOperation = VFS_OP_CMD_*
* -- uszPath = full path incl. file name starting with '\files\'
* -- return
*/
_Success_(return)
BOOL VfsInitOperation(_Out_ PVFS_OPERATION pop, _In_ QWORD qwOperation, _In_ LPSTR uszPath)
{
    DWORD o;
    ZeroMemory(pop, sizeof(VFS_OPERATION));
    pop->magic = VFS_OP_MAGIC;
    pop->op = qwOperation;
    if(g_vfs->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_WINDOWS) {
        if(uszPath[0] == '\\' && ((uszPath[1] >= 'a' && uszPath[1] <= 'z') || (uszPath[1] >= 'A' && uszPath[1] <= 'Z'))) {
            CharUtil_UtoW("\\??\\C:\\", -1, (PBYTE)pop->wszFileName, sizeof(pop->wszFileName), NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY);
            pop->wszFileName[4] = uszPath[1];
            if(uszPath[2] == '\\') {
                CharUtil_UtoW(uszPath + 3, -1, (PBYTE)pop->wszFileName + 14, sizeof(pop->wszFileName) - 16, NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR);
            }
            pop->flags = VFS_FLAGS_UNICODE;
            return TRUE;
        }
    } else {
        pop->szFileName[0] = '/';
        o = (uszPath[0] == '\\') ? 0 : 1;
        CharUtil_UtoU(uszPath, -1, (PBYTE)pop->szFileName + o, (DWORD)sizeof(pop->szFileName) - o, NULL, NULL, CHARUTIL_FLAG_STR_BUFONLY | CHARUTIL_FLAG_TRUNCATE_ONFAIL_NULLSTR);
        CharUtil_ReplaceAllA(pop->szFileName, '\\', '/');
        return TRUE;
    }
    return FALSE;
}

VOID VfsListDirectory(_In_ LPSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    BOOL fResult;
    VFS_OPERATION op = { 0 };
    PVFS_RESULT_FILEINFO pe, pfi = NULL;
    PBYTE pbAllDrive = NULL;
    CHAR szDrive[] = { '-' , 0 };
    QWORD i, cfi, cbfi, cbAllDrive = 0;
    VMMDLL_VFS_FILELIST_EXINFO eExInfo = { 0 };
    LPSTR uszResult;
    BYTE pbBuffer[3 * MAX_PATH];
    // sanity check:
    if(_strnicmp(uszPath, "\\files", 6)) { return; }
    uszPath += 6;
    // initialize vfs operation:
    if((g_vfs->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_WINDOWS) && (!uszPath[0] || !uszPath[1])) {
        // list windows target drive letters:
        VfsInitOperation(&op, VFS_OP_CMD_LIST_DRIVES, "");
        EnterCriticalSection(&g_vfs->Lock);
        fResult = Exec_ExecSilent(g_vfs->szNameVfsShellcode, (PBYTE)&op, sizeof(VFS_OPERATION), &pbAllDrive, &cbAllDrive);
        LeaveCriticalSection(&g_vfs->Lock);
        if(fResult && pbAllDrive && (cbAllDrive == 26)) {
            for(i = 0; i < cbAllDrive; i++) {
                szDrive[0] = pbAllDrive[i];
                if((szDrive[0] >= 'a') && (szDrive[0] <= 'z')) {
                    pFileList->pfnAddDirectory(pFileList->h, szDrive, NULL);
                }
            }
        }
        LocalFree(pbAllDrive);
        return;
    }
    VfsInitOperation(&op, VFS_OP_CMD_LIST_DIRECTORY, uszPath);
    // perform operation:
    EnterCriticalSection(&g_vfs->Lock);
    fResult = Exec_ExecSilent(g_vfs->szNameVfsShellcode, (PBYTE)&op, sizeof(VFS_OPERATION), (PBYTE*)&pfi, &cbfi);
    LeaveCriticalSection(&g_vfs->Lock);
    if(!fResult) { return; }
    // interprete result:
    eExInfo.dwVersion = VMMDLL_VFS_FILELIST_EXINFO_VERSION;
    cfi = cbfi / sizeof(VFS_RESULT_FILEINFO);
    for(i = 0; i < cfi; i++) {
        pe = pfi + i;
        if(CharUtil_WtoU(pe->wszFileName, -1, pbBuffer, sizeof(pbBuffer), &uszResult, NULL, 0)) {
            eExInfo.qwCreationTime = pfi->tCreateOpt;
            eExInfo.qwLastAccessTime = pfi->tAccessOpt;
            eExInfo.qwLastWriteTime = pfi->tModifyOpt;
            if(pe->flags & VFS_FLAGS_FILE_DIRECTORY) {
                pFileList->pfnAddDirectory(pFileList->h, uszResult, &eExInfo);
            } else {
                pFileList->pfnAddFile(pFileList->h, uszResult, pe->cb, &eExInfo);
            }
        }
    }
    LocalFree(pfi);
}

BOOL VfsListU(_In_ LPSTR uszPath, _Inout_ PVMMDLL_VFS_FILELIST2 pFileList)
{
    // root directory:
    if(!strcmp(uszPath, "\\")) {
        if(g_vfs->cbNative) {
            pFileList->pfnAddFile(pFileList->h, "liveram-native.raw", g_vfs->cbNative, NULL);
        }
        if(g_vfs->cbKmd) {
            pFileList->pfnAddFile(pFileList->h, "liveram-kmd.raw", g_vfs->cbKmd, NULL);
            pFileList->pfnAddDirectory(pFileList->h, "files", NULL);
        }
    }
    // files directory:
    if(!_strnicmp(uszPath, "\\files", 6) && g_vfs->cbKmd) {
        VfsListDirectory(uszPath, pFileList);
    }
    return TRUE;
}

BOOL VfsIsBlackList(_In_ LPSTR uszPathFull)
{
    if(g_vfs->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_LINUX) {
        return !strncmp(uszPathFull, "\\dev\\watchdog", 13);
    }
    return FALSE;
}

NTSTATUS VfsReadFile(_In_ LPSTR uszPathFull, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL result;
    VFS_OPERATION op;
    PBYTE pbBufferDma = NULL;
    QWORD cbBufferDma;
    QWORD qwBaseOffset, qwBase, qwSize;
    if(VfsIsBlackList(uszPathFull)) { return STATUS_ACCESS_DENIED; }
    *pcbRead = cb;
    result = VfsInitOperation(&op, VFS_OP_CMD_READ, uszPathFull);
    if(!result) { return STATUS_DATA_ERROR; }
    qwBaseOffset = cbOffset % 0x00100000; // 1MB
    qwBase = cbOffset - qwBaseOffset;
    qwSize = (cb + qwBaseOffset + 0x1fffff) & ~0x1fffff;
    op.offset = qwBase;
    op.cb = qwSize;
    EnterCriticalSection(&g_vfs->Lock);
    // TODO OP FIXES!
    result = Exec_ExecSilent(g_vfs->szNameVfsShellcode, (PBYTE)&op, sizeof(VFS_OPERATION), &pbBufferDma, &cbBufferDma);
    LeaveCriticalSection(&g_vfs->Lock);
    if(result && (qwBaseOffset <= cbBufferDma)) {
        *pcbRead = (DWORD)min(*pcbRead, cbBufferDma - qwBaseOffset);
        memcpy(pb, pbBufferDma + qwBaseOffset, *pcbRead);
        LocalFree(pbBufferDma);
        return STATUS_SUCCESS;
    }
    return STATUS_DATA_ERROR;
}

NTSTATUS VfsReadMemory(_In_ BOOL fKMD, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    BOOL result = FALSE;
    QWORD cbRead2, cbMaxMemorySize, qwCfgAddrMaxOrig;
    cbMaxMemorySize = fKMD ? g_vfs->cbKmd : g_vfs->cbNative;
    if(cbOffset >= cbMaxMemorySize) {
        *pcbRead = 0;
        return STATUS_FILE_INVALID;
    }
    *pcbRead = (DWORD)min(cb, cbMaxMemorySize - cbOffset);
    if(fKMD) {
        qwCfgAddrMaxOrig = ctxMain->cfg.paAddrMax;    // TODO: REMOVE UGLY HACK WITH ADDRMAX...
        EnterCriticalSection(&g_vfs->Lock);
        if(!DeviceReadMEM(cbOffset, *pcbRead, pb, TRUE)) {
            ZeroMemory(pb, *pcbRead);
        }
        LeaveCriticalSection(&g_vfs->Lock);
        ctxMain->cfg.paAddrMax = qwCfgAddrMaxOrig;
    } else {
        cbRead2 = DeviceReadDMA(cbOffset, *pcbRead, pb, NULL);
        if(cbRead2 < *pcbRead) {
            ZeroMemory(pb + cbRead2, *pcbRead - cbRead2);
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS VfsRead(_In_ LPSTR uszPathFull, _Out_writes_to_(cb, *pcbRead) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbRead, _In_ QWORD cbOffset)
{
    if(!_stricmp(uszPathFull, "\\liveram-kmd.raw") && g_vfs->cbKmd) { // kernel module backed RAM file
        return VfsReadMemory(TRUE, pb, cb, pcbRead, cbOffset);
    }
    if(!_stricmp(uszPathFull, "\\liveram-native.raw") && g_vfs->cbNative) { // native backed RAM file
        return VfsReadMemory(FALSE, pb, cb, pcbRead, cbOffset);
    }
    if(!_strnicmp(uszPathFull, "\\files\\", 7) && g_vfs->cbKmd) {
        return VfsReadFile(uszPathFull + 6, pb, cb, pcbRead, cbOffset);
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS VfsWriteFile(_In_ BOOL fAppend, _In_ LPSTR uszPathFull, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ QWORD cbOffset)
{
    PVFS_OPERATION pop = NULL;
    if(VfsIsBlackList(uszPathFull)) { return STATUS_ACCESS_DENIED; }
    pop = (PVFS_OPERATION)LocalAlloc(LMEM_ZEROINIT, sizeof(VFS_OPERATION) + cb);
    if(!pop) { return STATUS_MEMORY_NOT_ALLOCATED; }
    if(!VfsInitOperation(pop, VFS_OP_CMD_WRITE, uszPathFull)) { return STATUS_DATA_ERROR; }
    if(fAppend) {
        pop->flags |= VFS_FLAGS_APPEND_ON_WRITE;
    }
    if(0 == cbOffset) {
        // TODO: find when to truncate and when not to... if 0th byte is written file is truncated now...
        pop->flags |= VFS_FLAGS_TRUNCATE_ON_WRITE;
    }
    memcpy(pop->pb, pb, cb);
    pop->offset = cbOffset;
    pop->cb = cb;
    EnterCriticalSection(&g_vfs->Lock);
    Exec_ExecSilent(g_vfs->szNameVfsShellcode, (PBYTE)pop, sizeof(VFS_OPERATION) + cb, NULL, NULL);
    LeaveCriticalSection(&g_vfs->Lock);
    VfsList_Clear(uszPathFull);
    *pcbWrite = cb;
    LocalFree(pop);
    return STATUS_SUCCESS;
}

NTSTATUS VfsWriteMemory(_In_ BOOL fKMD, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    BOOL result;
    if(fKMD) {  // kernel module backed RAM file
        EnterCriticalSection(&g_vfs->Lock);
        result = DeviceWriteMEM(cbOffset, cb, pb, TRUE);
        LeaveCriticalSection(&g_vfs->Lock);
    } else {    // native DMA backed RAM file
        result = LcWrite(ctxMain->hLC, cbOffset, cb, pb);
    }
    *pcbWrite = cb;
    return result ? STATUS_SUCCESS : STATUS_FILE_SYSTEM_LIMITATION;
}

NTSTATUS VfsWrite(_In_ BOOL fAppend, _In_ LPSTR uszPathFull, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcbWrite, _In_ ULONG64 cbOffset)
{
    if(!_stricmp(uszPathFull, "\\liveram-kmd.raw") && g_vfs->cbKmd) { // kernel module backed RAM file
        return VfsWriteMemory(TRUE, pb, cb, pcbWrite, cbOffset);
    }
    if(!_stricmp(uszPathFull, "\\liveram-native.raw") && g_vfs->cbNative) { // native backed RAM file
        return VfsWriteMemory(FALSE, pb, cb, pcbWrite, cbOffset);
    }
    if(!_strnicmp(uszPathFull, "\\files\\", 7) && g_vfs->cbKmd) {
        return VfsWriteFile(fAppend, uszPathFull + 6, pb, cb, pcbWrite, cbOffset);
    }
    return STATUS_FILE_INVALID;
}

VOID VfsDelete(_In_ LPSTR uszPathFull)
{
    VFS_OPERATION op;
    if(!_strnicmp(uszPathFull, "\\files\\", 7)) {
        if(!VfsInitOperation(&op, VFS_OP_CMD_DELETE, uszPathFull + 6)) { return; }
        EnterCriticalSection(&g_vfs->Lock);
        Exec_ExecSilent(g_vfs->szNameVfsShellcode, (PBYTE)&op, sizeof(VFS_OPERATION), NULL, NULL);
        LeaveCriticalSection(&g_vfs->Lock);
        VfsList_Clear(uszPathFull);
    }
}



#ifdef _WIN32

//-------------------------------------------------------------------------------
// WINDOWS-ONLY functions including DOKAN CALLBACK functions.
//-------------------------------------------------------------------------------

NTSTATUS
VfsDokanCallback_CreateFile_Impl(_In_ LPSTR uszFullPath, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    VFS_ENTRY VfsEntry;
    CHAR uszPath[MAX_PATH];
    LPSTR uszFile;
    BOOL fIsDirectoryExisting = FALSE;
    UNREFERENCED_PARAMETER(SecurityContext);
    UNREFERENCED_PARAMETER(FileAttributes);
    // root directory
    if(!strcmp(uszFullPath, "\\")) {
        if(CreateDisposition == CREATE_ALWAYS) { return g_vfs->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED); }
        DokanFileInfo->IsDirectory = TRUE;
        return STATUS_SUCCESS;
    }
    // other files
    if(CreateDisposition == CREATE_ALWAYS) { return g_vfs->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED); }
    uszFile = CharUtil_PathSplitLastEx(uszFullPath, uszPath, sizeof(uszPath));
    if(!VfsList_GetSingle(uszPath[0] ? uszPath : "\\", uszFile, &VfsEntry, &fIsDirectoryExisting)) {
        return fIsDirectoryExisting ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_PATH_NOT_FOUND;
    }
    DokanFileInfo->Nocache = TRUE;
    if(!DokanFileInfo->IsDirectory && (CreateOptions & FILE_DIRECTORY_FILE)) { return STATUS_NOT_A_DIRECTORY; }     // fail upon open normal file as directory
    return (CreateDisposition == OPEN_ALWAYS) ? STATUS_OBJECT_NAME_COLLISION : STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_CreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    LPSTR uszPathFull;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU((LPWSTR)FileName, -1, pbBuffer, sizeof(pbBuffer), &uszPathFull, NULL, 0)) { return STATUS_OBJECT_NAME_NOT_FOUND; }
    return VfsDokanCallback_CreateFile_Impl(uszPathFull, SecurityContext, DesiredAccess, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, DokanFileInfo);
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_GetFileInformation_Impl(_In_ LPSTR uszFullPath, _Inout_ LPBY_HANDLE_FILE_INFORMATION hfi, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    VFS_ENTRY VfsEntry;
    CHAR uszPath[MAX_PATH];
    LPSTR uszFile;
    BOOL fIsDirectoryExisting = FALSE;
    // matches: root directory
    if(!strcmp(uszFullPath, "\\")) {
        hfi->ftCreationTime = g_vfs->ftDefaultTime;
        hfi->ftLastWriteTime = g_vfs->ftDefaultTime;
        hfi->ftLastAccessTime = g_vfs->ftDefaultTime;
        hfi->nFileSizeHigh = 0;
        hfi->nFileSizeLow = 0;
        hfi->dwFileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        return STATUS_SUCCESS;
    }
    uszFile = CharUtil_PathSplitLastEx(uszFullPath, uszPath, sizeof(uszPath));

    if(!VfsList_GetSingle((uszPath[0] ? uszPath : "\\"), uszFile, &VfsEntry, &fIsDirectoryExisting)) {
        return STATUS_FILE_NOT_AVAILABLE;
    }
    hfi->dwFileAttributes = VfsEntry.dwFileAttributes;
    hfi->ftCreationTime = VfsEntry.ftCreationTime;
    hfi->ftLastAccessTime = VfsEntry.ftLastAccessTime;
    hfi->ftLastWriteTime = VfsEntry.ftLastWriteTime;
    hfi->nFileSizeHigh = (DWORD)(VfsEntry.cbFileSize >> 32);
    hfi->nFileSizeLow = (DWORD)(VfsEntry.cbFileSize);
    hfi->nFileIndexHigh = CharUtil_Hash32U(uszFullPath, TRUE);
    hfi->nFileIndexLow = CharUtil_Hash32U(VfsEntry.uszName, TRUE);
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_GetFileInformation(_In_ LPCWSTR wcsFileName, _Inout_ LPBY_HANDLE_FILE_INFORMATION hfi, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    LPSTR uszPathFull;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU((LPWSTR)wcsFileName, -1, pbBuffer, sizeof(pbBuffer), &uszPathFull, NULL, 0)) { return STATUS_FILE_INVALID; }
    return VfsDokanCallback_GetFileInformation_Impl(uszPathFull, hfi, DokanFileInfo);
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_FindFiles(LPCWSTR wcsFileName, PFillFindData FillFindData, PDOKAN_FILE_INFO DokanFileInfo)
{
    VfsList_ListDirectoryW((LPWSTR)wcsFileName, DokanFileInfo, (PFN_VFSLISTW_CALLBACK)FillFindData);
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_ReadFile(LPCWSTR wcsFileName, LPVOID Buffer, DWORD BufferLength, LPDWORD ReadLength, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
    LPSTR uszPathFull;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU((LPWSTR)wcsFileName, -1, pbBuffer, sizeof(pbBuffer), &uszPathFull, NULL, 0)) { return STATUS_FILE_INVALID; }
    return VfsRead(uszPathFull, Buffer, BufferLength, ReadLength, Offset);
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_WriteFile(LPCWSTR wcsFileName, LPCVOID Buffer, DWORD NumberOfBytesToWrite, LPDWORD NumberOfBytesWritten, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
    LPSTR uszPathFull;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU((LPWSTR)wcsFileName, -1, (PBYTE)pbBuffer, sizeof(pbBuffer), &uszPathFull, NULL, 0)) { return STATUS_FILE_INVALID; }
    return VfsWrite(DokanFileInfo->WriteToEndOfFile, uszPathFull, (PBYTE)Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, Offset);
}

NTSTATUS DOKAN_CALLBACK
VfsDokanCallback_DeleteFile(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo)
{
    LPSTR uszPathFull;
    BYTE pbBuffer[3 * MAX_PATH];
    if(!CharUtil_WtoU((LPWSTR)wcsFileName, -1, pbBuffer, sizeof(pbBuffer), &uszPathFull, NULL, 0)) { return STATUS_FILE_INVALID; }
    VfsDelete(uszPathFull);
    return STATUS_SUCCESS;
}

VOID DOKAN_CALLBACK
VfsDokanCallback_Cleanup(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo)
{
    LPSTR uszPathFull;
    BYTE pbBuffer[3 * MAX_PATH];
    if(DokanFileInfo->DeleteOnClose && !DokanFileInfo->IsDirectory) {
        if(!CharUtil_WtoU((LPWSTR)wcsFileName, -1, pbBuffer, sizeof(pbBuffer), &uszPathFull, NULL, 0)) { return; }
        VfsDelete(uszPathFull);
    }
}

VOID ActionUnMount()
{
    if(ctxMain->vfs.fInitialized) {
        ctxMain->vfs.fInitialized = FALSE;
        if(ctxMain->vfs.pfnDokanUnmount) {
            ctxMain->vfs.pfnDokanUnmount(ctxMain->vfs.wchMountPoint);
            Sleep(50);
        }
    }
}

VOID ActionMount()
{
    int status;
    HMODULE hModuleDokan = NULL;
    PVFS_GLOBAL_STATE pVfsState = NULL;
    PDOKAN_OPTIONS pDokanOptions = NULL;
    PDOKAN_OPERATIONS pDokanOperations = NULL;
    WCHAR wszMountPoint[] = { 'K', ':', '\\', 0 };
    VOID(WINAPI *pfnDokanInit)();
    int(WINAPI *pfnDokanMain)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS);
    VOID(WINAPI *pfnDokanShutdown)();
    // sanity checks
    if(!ctxMain->phKMD && (PCILEECH_DEVICE_EQUALS("usb3380") || (ctxMain->cfg.paAddrMax > 0x0000040000000000) || (ctxMain->cfg.paAddrMax < 0x00400000))) {
        printf(
            "MOUNT: Failed. Please see below for possible reasons:               \n" \
            "   - Mounting file system requires an active kernel module (KMD).   \n" \
            "   - Mounting kernel backed RAM of target system requires a KMD.    \n" \
            "   - Mounting native RAM of target system requires FPGA hardware    \n" \
            "     and KMD or valid -max option set.                              \n"
        );
        goto fail;
    }
    if(!ctxMain->phKMD) { printf("MOUNT: INFO: FILES folder not mounted. (No kernel module loaded).\n"); }
    // allocate
    hModuleDokan = LoadLibraryExA("dokan2.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    pfnDokanInit = (VOID(WINAPI*)())GetProcAddress(hModuleDokan, "DokanInit");
    pfnDokanMain = (int(WINAPI*)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS))GetProcAddress(hModuleDokan, "DokanMain");
    pfnDokanShutdown = (VOID(WINAPI*)())GetProcAddress(hModuleDokan, "DokanShutdown");
    if(!hModuleDokan || !pfnDokanMain || !pfnDokanInit || !pfnDokanShutdown) {
        printf("MOUNT: Failed. The required DOKANY file system library is not installed. \n");
        printf("Please download from : https://github.com/dokan-dev/dokany/releases/latest\n");
        goto fail;
    }
    pVfsState = (PVFS_GLOBAL_STATE)LocalAlloc(LMEM_ZEROINIT, sizeof(VFS_GLOBAL_STATE));
    pDokanOptions = (PDOKAN_OPTIONS)LocalAlloc(LMEM_ZEROINIT, sizeof(DOKAN_OPTIONS));
    pDokanOperations = (PDOKAN_OPERATIONS)LocalAlloc(LMEM_ZEROINIT, sizeof(DOKAN_OPERATIONS));
    if(!pVfsState || !pDokanOptions || !pDokanOperations) {
        printf("MOUNT: Failed (out of memory).\n");
        goto fail;
    }
    // set global state
    pVfsState->cbKmd = ctxMain->phKMD ? (ctxMain->phKMD->pPhysicalMap[ctxMain->phKMD->cPhysicalMap - 1].BaseAddress + ctxMain->phKMD->pPhysicalMap[ctxMain->phKMD->cPhysicalMap - 1].NumberOfBytes) : 0;
    pVfsState->cbNative = PCILEECH_DEVICE_EQUALS("usb3380") ? 0 : (ctxMain->phKMD ? pVfsState->cbKmd : ctxMain->cfg.paAddrMax);
    pVfsState->DokanNtStatusFromWin32 = (NTSTATUS(*)(DWORD))GetProcAddress(hModuleDokan, "DokanNtStatusFromWin32");
    pVfsState->PCILeechOperatingSystem = ctxMain->phKMD ? ctxMain->pk->OperatingSystem : 0;
    if(pVfsState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_WINDOWS) {
        strcpy_s(pVfsState->szNameVfsShellcode, 32, "DEFAULT_WINX64_VFS_KSH");
    } else if(pVfsState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_LINUX) {
        strcpy_s(pVfsState->szNameVfsShellcode, 32, "DEFAULT_LINUX_X64_VFS_KSH");
    } else if(pVfsState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_MACOS) {
        strcpy_s(pVfsState->szNameVfsShellcode, 32, "DEFAULT_MACOS_VFS_KSH");
    } else if(ctxMain->phKMD) {
        printf("MOUNT: Operating system not supported.\n");
        goto fail;
    }
    InitializeCriticalSection(&pVfsState->Lock);
    SYSTEMTIME SystemTimeNow;
    GetSystemTime(&SystemTimeNow);
    SystemTimeToFileTime(&SystemTimeNow, &pVfsState->ftDefaultTime);
    g_vfs = pVfsState;
    // set options
    pDokanOptions->Version = DOKAN_VERSION;
    pDokanOptions->Options |= DOKAN_OPTION_NETWORK;
    pDokanOptions->UNCName = L"PCILeechFileSystem";
    if((ctxMain->cfg.szMount[0] >= 'a' && ctxMain->cfg.szMount[0] <= 'z') || (ctxMain->cfg.szMount[0] >= 'A' && ctxMain->cfg.szMount[0] <= 'Z')) {
        wszMountPoint[0] = ctxMain->cfg.szMount[0];
    }
    pDokanOptions->MountPoint = wszMountPoint;
    pDokanOptions->Timeout = 60000;
    // set callbacks
    pDokanOperations->ZwCreateFile = VfsDokanCallback_CreateFile;
    pDokanOperations->Cleanup = VfsDokanCallback_Cleanup;
    pDokanOperations->DeleteFileW = VfsDokanCallback_DeleteFile;
    pDokanOperations->GetFileInformation = VfsDokanCallback_GetFileInformation;
    pDokanOperations->FindFiles = VfsDokanCallback_FindFiles;
    pDokanOperations->ReadFile = VfsDokanCallback_ReadFile;
    pDokanOperations->WriteFile = VfsDokanCallback_WriteFile;
    // enable directory caching sub-system
    if(!VfsList_Initialize(VfsListU, 500, 0x1000, TRUE)) {
        printf("MOUNT: Unable to initialize directory cache.\n");
        goto fail;
    }
    // enable
    printf(
        "MOUNTING PCILEECH FILE SYSTEM:                                                 \n" \
        "===============================================================================\n");
    if(ctxMain->phKMD) {
        printf(
            "PCILeech DMA attack target file system is mounted in the /files/ folder.       \n" \
            "Please see limitations below:                                                  \n" \
            " - Kernel module is required and is supported on: Windows, Linux and macOS.    \n" \
            " - Create file: not implemented.                                               \n" \
            " - Write to files may be buggy and may in rare cases corrupt the target file.  \n" \
            " - Delete file will most often work, but with errors.                          \n" \
            " - Delete directory, rename/move file and other features may not be supported. \n" \
            "===============================================================================\n");
    }
    printf("MOUNT: Mounting as drive %S\n", pDokanOptions->MountPoint);
    ctxMain->vfs.pfnDokanUnmount = (BOOL(WINAPI*)(WCHAR))GetProcAddress(hModuleDokan, "DokanUnmount");
    ctxMain->vfs.wchMountPoint = wszMountPoint[0];
    ctxMain->vfs.fInitialized = TRUE;
    pfnDokanInit();
    status = pfnDokanMain(pDokanOptions, pDokanOperations);
    while(ctxMain && ctxMain->vfs.fInitialized && (status == DOKAN_SUCCESS)) {
        printf("MOUNT: ReMounting as drive %S\n", pDokanOptions->MountPoint);
        status = pfnDokanMain(pDokanOptions, pDokanOperations);
    }
    pfnDokanShutdown();
    printf("MOUNT: Failed. Status Code: %i\n", status);
    DeleteCriticalSection(&pVfsState->Lock);
fail:
    if(hModuleDokan) { FreeLibrary(hModuleDokan); }
    g_vfs = NULL;
    if(pVfsState) {
        DeleteCriticalSection(&pVfsState->Lock);
        LocalFree(pVfsState);
    }
    LocalFree(pDokanOptions);
    LocalFree(pDokanOperations);
}

#endif /* _WIN32 */



#if defined(LINUX) || defined(MACOS)

//-------------------------------------------------------------------------------
// LINUX-ONLY functions including FUSE CALLBACK functions.
//-------------------------------------------------------------------------------

#define FILETIME_TO_UNIX(ft)        (time_t)((ft) / 10000000ULL - 11644473600ULL)
#define VER_OSARCH                  "Linux"

static int vfs_getattr(const char* uszPathFull, struct stat *st)
{
    DWORD i = 0;
    CHAR c = 0, uszPathCopy[3 * MAX_PATH] = { 0 };
    CHAR uszPath[3 * MAX_PATH];
    LPSTR uszFile;
    BOOL result, fIsDirectoryExisting;
    VFS_ENTRY e;
    // 1: replace forward slash with backward slash
    strncpy_s(uszPathCopy, sizeof(uszPathCopy), uszPathFull, _TRUNCATE);
    while((c = uszPathCopy[i++])) {
        if(c == '/') { uszPathCopy[i - 1] = '\\'; }
    }
    // 2: set common values:
    st->st_uid = getuid();
    st->st_gid = getgid();
    // 3: matches: root directory
    if(!strcmp(uszPathCopy, "\\")) {
        st->st_ctime = time(NULL);
        st->st_mtime = time(NULL);
        st->st_atime = time(NULL);
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }
    // 4: matches vfs file/directory:
    uszFile = CharUtil_PathSplitLastEx(uszPathCopy, uszPath, sizeof(uszPath));
    result = VfsList_GetSingle((uszPath[0] ? uszPath : "\\"), uszFile, &e, &fIsDirectoryExisting);
    if(result) {
        st->st_ctime = FILETIME_TO_UNIX(e.ftCreationTime);
        st->st_mtime = FILETIME_TO_UNIX(e.ftLastWriteTime);
        st->st_atime = FILETIME_TO_UNIX(e.ftLastAccessTime);
        if(e.fDirectory) {
            st->st_mode = S_IFDIR | 0755;
            st->st_nlink = 2;
        } else {
            st->st_mode = S_IFREG | 0644;
            st->st_nlink = 1;
            st->st_size = e.cbFileSize;
        }
    }
    return 0;
}

typedef struct td_readdir_cb_ctx {
    void* buffer;
    fuse_fill_dir_t filler;
} readdir_cb_ctx, * preaddir_cb_ctx;

static void vfs_readdir_cb(_In_ PVFS_ENTRY pVfsEntry, _In_opt_ preaddir_cb_ctx ctx)
{
    ctx->filler(ctx->buffer, pVfsEntry->uszName, NULL, 0);
}

static int vfs_readdir(const char* uszPath, void* buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    DWORD i = 0;
    CHAR c = 0, uszPathCopy[3 * MAX_PATH] = { 0 };
    UNREFERENCED_PARAMETER(offset);
    UNREFERENCED_PARAMETER(fi);
    // 1: replace forward slash with backward slash
    strncpy_s(uszPathCopy, sizeof(uszPathCopy), uszPath, _TRUNCATE);
    while((c = uszPathCopy[i++])) {
        if(c == '/') { uszPathCopy[i - 1] = '\\'; }
    }
    // 2: do work
    readdir_cb_ctx ctx;
    ctx.buffer = buffer;
    ctx.filler = filler;
    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);
    VfsList_ListDirectory(uszPathCopy, &ctx, (void(*)(PVFS_ENTRY, PVOID))vfs_readdir_cb);
    return 0;
}

static int vfs_read(const char* uszPath, char* buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
    NTSTATUS nt;
    DWORD i = 0, readlength = 0;
    CHAR c = 0, uszPathCopy[3 * MAX_PATH] = { 0 };
    UNREFERENCED_PARAMETER(fi);
    // 1: replace forward slash with backward slash
    strncpy_s(uszPathCopy, sizeof(uszPathCopy), uszPath, _TRUNCATE);
    while((c = uszPathCopy[i++])) {
        if(c == '/') { uszPathCopy[i - 1] = '\\'; }
    }
    // 2: read
    nt = VfsRead(uszPathCopy, (PBYTE)buffer, size, &readlength, offset);
    return ((nt == STATUS_SUCCESS) || (nt == STATUS_END_OF_FILE)) ? (int)readlength : 0;
}

static int vfs_truncate(const char* path, off_t size)
{
    // dummy function - required and called before vfs_write().
    UNREFERENCED_PARAMETER(path);
    UNREFERENCED_PARAMETER(size);
    return 0;
}

static int vfs_write(const char* uszPath, const char* buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
    NTSTATUS nt;
    DWORD i = 0, writelength = 0;
    CHAR c = 0, uszPathCopy[3 * MAX_PATH] = { 0 };
    UNREFERENCED_PARAMETER(fi);
    // 1: replace forward slash with backward slash
    strncpy_s(uszPathCopy, sizeof(uszPathCopy), uszPath, _TRUNCATE);
    while((c = uszPathCopy[i++])) {
        if(c == '/') { uszPathCopy[i - 1] = '\\'; }
    }
    // 2: write
    nt = VfsWrite(FALSE, uszPathCopy, (PBYTE)buffer, size, &writelength, offset);
    return ((nt == STATUS_SUCCESS) || (nt == STATUS_END_OF_FILE)) ? (int)size : 0;
}

static struct fuse_operations vfs_operations = {
    .readdir = vfs_readdir,
    .getattr = vfs_getattr,
    .read = vfs_read,
    .write = vfs_write,
    .truncate = vfs_truncate,
};

void vfs_initialize_and_mount_displayinfo()
{
    PVFS_GLOBAL_STATE pVfsState = NULL;
    void* hlibfuse2 = NULL;
    int(*pfn_fuse_main_real)(int argc, char** argv, const struct fuse_operations* op, size_t op_size, void* private_data);
    // sanity check
    if(ctxMain->cfg.szMount[0] != '/') {
        printf("MOUNT: Failed - missing required option '-mount <fullpath>' or not full mount path given.\n");
        goto fail;
    }
    // set global state
    pVfsState = (PVFS_GLOBAL_STATE)LocalAlloc(LMEM_ZEROINIT, sizeof(VFS_GLOBAL_STATE));
    if(!pVfsState) {
        printf("MOUNT: Failed (out of memory).\n");
        goto fail;
    }
    pVfsState->cbKmd = ctxMain->phKMD ? (ctxMain->phKMD->pPhysicalMap[ctxMain->phKMD->cPhysicalMap - 1].BaseAddress + ctxMain->phKMD->pPhysicalMap[ctxMain->phKMD->cPhysicalMap - 1].NumberOfBytes) : 0;
    pVfsState->cbNative = PCILEECH_DEVICE_EQUALS("usb3380") ? 0 : (ctxMain->phKMD ? pVfsState->cbKmd : ctxMain->cfg.paAddrMax);
    pVfsState->PCILeechOperatingSystem = ctxMain->phKMD ? ctxMain->pk->OperatingSystem : 0;
    if(pVfsState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_WINDOWS) {
        strcpy_s(pVfsState->szNameVfsShellcode, 32, "DEFAULT_WINX64_VFS_KSH");
    } else if(pVfsState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_LINUX) {
        strcpy_s(pVfsState->szNameVfsShellcode, 32, "DEFAULT_LINUX_X64_VFS_KSH");
    } else if(pVfsState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_MACOS) {
        strcpy_s(pVfsState->szNameVfsShellcode, 32, "DEFAULT_MACOS_VFS_KSH");
    } else if(ctxMain->phKMD) {
        printf("MOUNT: Operating system not supported.\n");
        goto fail;
    }
    InitializeCriticalSection(&pVfsState->Lock);
    pVfsState->ftDefaultTime = (time(NULL) * 10000000) + 116444736000000000;
    g_vfs = pVfsState;
    // enable directory caching sub-system
    if(!VfsList_Initialize(VfsListU, 500, 0x1000, TRUE)) {
        printf("MOUNT: Unable to initialize directory cache.\n");
        goto fail;
    }
    // dynamically load fuse (to avoid runtime dependency)
#ifdef LINUX
    hlibfuse2 = dlopen("libfuse.so.2", RTLD_NOW);
    if(!hlibfuse2) {
        printf("MOUNT: Unable to load required FUSE file system library libfuse.so.2\n");
        goto fail;
    }
#endif /* LINUX */
#ifdef MACOS
    hlibfuse2 = dlopen("libfuse.2.dylib", RTLD_NOW);
    if(!hlibfuse2) {
        hlibfuse2 = dlopen("/usr/local/lib/libfuse.2.dylib", RTLD_NOW);
    }
    if(!hlibfuse2) {
        printf("MOUNT: Unable to load required FUSE file system library libfuse.2.dylib\n");
        goto fail;
    }
#endif /* MACOS */
    pfn_fuse_main_real = dlsym(hlibfuse2, "fuse_main_real");
    if(!pfn_fuse_main_real) {
        printf("MOUNT: Unable to load fetch required function pfn_fuse_main_real from FUSE file system library\n");
        goto fail;
    }
    // enable
    printf(
        "MOUNTING PCILEECH FILE SYSTEM:                                                 \n" \
        "===============================================================================\n");
    if(ctxMain->phKMD) {
        printf(
            "PCILeech DMA attack target file system is mounted in the <mnt>/files/ folder.  \n" \
            "Please see limitations below:                                                  \n" \
            " - Kernel module is required and is supported on: Windows, Linux and macOS.    \n" \
            " - Create file: not implemented.                                               \n" \
            " - Write to files may be buggy and may in rare cases corrupt the target file.  \n" \
            " - Delete file will most often work, but with errors.                          \n" \
            " - Delete directory, rename/move file and other features may not be supported. \n" \
            "===============================================================================\n");
    }
    printf("MOUNT: Mounting at path '%s'\n", ctxMain->cfg.szMount);
    // hand over control to FUSE.
#ifdef LINUX
    LPSTR szArgListFuse[] = { ctxMain->argv[0], ctxMain->cfg.szMount, "-f" };
#endif /* LINUX */
#ifdef MACOS
    LPSTR szArgListFuse[] = { ctxMain->argv[0], ctxMain->cfg.szMount, "-f", "-o", "local,volname=PCILeech", "-o", "volicon=pcileech.icns" };
#endif /* MACOS */
    int cArgListFuse = sizeof(szArgListFuse) / sizeof(LPSTR);
    pfn_fuse_main_real(cArgListFuse, szArgListFuse, &vfs_operations, sizeof(vfs_operations), NULL);
fail:
    g_vfs = NULL;
    if(pVfsState) {
        DeleteCriticalSection(&pVfsState->Lock);
        LocalFree(pVfsState);
    }
    if(hlibfuse2) {
        dlclose(hlibfuse2);
    }
}

VOID ActionUnMount()
{
    return;
}

VOID ActionMount()
{
    vfs_initialize_and_mount_displayinfo();
}

#endif /* LINUX || MACOS */
