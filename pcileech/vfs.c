// vfs.c : implementation of functions related to virtual file system support.
//
// (c) Ulf Frisk, 2017-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef WIN32

#include "vfs.h"
#include "device.h"
#include "executor.h"
#include "util.h"
#pragma warning( push )  
#pragma warning( disable : 4005 )   
#include <dokan.h>
#pragma warning( pop )

//-------------------------------------------------------------------------------
// Defines and Typedefs (shared with shellcode) below:
//-------------------------------------------------------------------------------

#define VFS_OP_MAGIC                    0x79e720ad93aa130f
#define VFS_OP_CMD_LIST_DIRECTORY       1
#define VFS_OP_CMD_WRITE                2
#define VFS_OP_CMD_READ                 3
#define VFS_OP_CMD_CREATE               4
#define VFS_OP_CMD_DELETE               5

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

//-------------------------------------------------------------------------------
// Defines and Typedefs (not shared with shellcode) below:
//-------------------------------------------------------------------------------

#define VFS_RAM_TP_KMD                      0
#define VFS_RAM_TP_NATIVE                   1
#define VFS_RAM_TP_MAX                      1

#define CACHE_MEM_ENTRIES                   32
#define CACHE_MEM_SIZE                      0x00400000
#define CACHE_MEM_LIFETIME_MS               2000
#define CACHE_FILE_ENTRIES                  32
#define CACHE_FILE_SIZE                     0x00200000
#define CACHE_FILE_LIFETIME_MS              10000
#define CACHE_DIRECTORY_ENTRIES             32
#define CACHE_DIRECTORY_LIFETIME_FILE_MS    5000
#define CACHE_DIRECTORY_LIFETIME_PROC_MS    10

typedef struct tdVfsCacheMem {
    QWORD qwTickCount64;
    QWORD qwA;
    BYTE pb[CACHE_MEM_SIZE];
} VFS_CACHE_MEM, *PVFS_CACHE_MEM;

typedef struct tdVfsCacheFile {
    QWORD qwTickCount64;
    WCHAR wszFileName[MAX_PATH];
    QWORD cbOffset;
    QWORD cb;
    BYTE pb[CACHE_FILE_SIZE];
} VFS_CACHE_FILE, *PVFS_CACHE_FILE;

typedef struct tdVfsCacheDirectory {
    QWORD qwExpireTickCount64;
    WCHAR wszDirectoryName[MAX_PATH];
    QWORD cfi;
    PVFS_RESULT_FILEINFO pfi;
} VFS_CACHE_DIRECTORY, *PVFS_CACHE_DIRECTORY;

typedef struct tdVFS_STAT_ELEM {
    QWORD hit;
    QWORD miss;
} VFS_STAT_ELEM;

typedef struct tdVFS_STATISTICS {
    VFS_STAT_ELEM cRAM;
    VFS_STAT_ELEM cbRAM;
    VFS_STAT_ELEM cLISTDIR;
    VFS_STAT_ELEM cLISTFILE;
    VFS_STAT_ELEM cFILE;
    VFS_STAT_ELEM cbFILE;
    BOOL fThreadExit;
    HANDLE hThread;
    HANDLE hConsole;
    WORD wConsoleCursorPosition;
} VFS_STATISTICS, *PVFS_STATISTICS;

typedef struct tdVFS_GLOBAL_STATE {
    SYSTEMTIME time;
    QWORD cbRAM[VFS_RAM_TP_MAX+1];
    VFS_STATISTICS Statistics;
    CRITICAL_SECTION LockDma;
    CRITICAL_SECTION LockCache;
    NTSTATUS(*DokanNtStatusFromWin32)(DWORD Error);
    QWORD PCILeechOperatingSystem;
    CHAR szNameVfsShellcode[32];
    BYTE pbDMA16M[0x01000000];
    QWORD CacheMemIndex;
    VFS_CACHE_MEM CacheMem[VFS_RAM_TP_MAX+1][CACHE_MEM_ENTRIES];
    QWORD CacheFileIndex;
    VFS_CACHE_FILE CacheFile[CACHE_FILE_ENTRIES];
    QWORD CacheDirectoryIndex;
    VFS_CACHE_DIRECTORY CacheDirectory[CACHE_DIRECTORY_ENTRIES];
    BOOL fKMD;
} VFS_GLOBAL_STATE, *PVFS_GLOBAL_STATE;

VOID Vfs_UtilSplitPathFile(_Out_writes_(MAX_PATH) LPWSTR wszPath, _Out_ LPWSTR *pwcsFile, _In_ LPCWSTR wcsFileName);

//-------------------------------------------------------------------------------
// Read cache functionality below.
// (file and memory accesses are become extremely slow without caching).
//-------------------------------------------------------------------------------

_Success_(return)
BOOL VfsCache_DirectoryGetSingle(_Out_ PVFS_RESULT_FILEINFO pfi, _Out_ PBOOL isExisting, _In_ LPCWSTR wcsPath, _In_ LPCWSTR wcsFile, _In_ PVFS_GLOBAL_STATE pds)
{
    QWORD i, j, qwCurrentTickCount;
    qwCurrentTickCount = GetTickCount64();
    EnterCriticalSection(&pds->LockCache);
    for(i = 0; i < CACHE_DIRECTORY_ENTRIES; i++) {
        if(wcscmp(wcsPath, pds->CacheDirectory[i].wszDirectoryName)) {
            continue;
        }
        if(qwCurrentTickCount > pds->CacheDirectory[i].qwExpireTickCount64) {
            continue;
        }
        for(j = 0; j < pds->CacheDirectory[i].cfi; j++) {
            if(!wcscmp(wcsFile, pds->CacheDirectory[i].pfi[j].wszFileName)) {
                memcpy(pfi, &pds->CacheDirectory[i].pfi[j], sizeof(VFS_RESULT_FILEINFO));
                LeaveCriticalSection(&pds->LockCache);
                *isExisting = TRUE;
                pds->Statistics.cLISTFILE.hit++;
                return TRUE;
            }
        }
        LeaveCriticalSection(&pds->LockCache);
        *isExisting = FALSE;
        pds->Statistics.cLISTFILE.miss++;
        return TRUE;
    }
    LeaveCriticalSection(&pds->LockCache);
    pds->Statistics.cLISTFILE.miss++;
    return FALSE;
}

BOOL VfsCache_DirectoryGetDirectory(_Out_ PVFS_RESULT_FILEINFO *ppfi, _Out_ PQWORD pcfi, _In_ LPCWSTR wcsPathFileName, _In_ PVFS_GLOBAL_STATE pds)
{
    QWORD i, qwCurrentTickCount;
    qwCurrentTickCount = GetTickCount64();
    EnterCriticalSection(&pds->LockCache);
    for(i = 0; i < CACHE_DIRECTORY_ENTRIES; i++) {
        if(wcscmp(wcsPathFileName, pds->CacheDirectory[i].wszDirectoryName)) {
            continue;
        }
        if(qwCurrentTickCount > pds->CacheDirectory[i].qwExpireTickCount64) {
            continue;
        }
        *pcfi = pds->CacheDirectory[i].cfi;
        *ppfi = (PVFS_RESULT_FILEINFO)LocalAlloc(0, *pcfi * sizeof(VFS_RESULT_FILEINFO));
        if(!*ppfi) { goto fail; }
        memcpy(*ppfi, pds->CacheDirectory[i].pfi, *pcfi * sizeof(VFS_RESULT_FILEINFO));
        LeaveCriticalSection(&pds->LockCache);
        pds->Statistics.cLISTDIR.hit++;
        return TRUE;
    }
    fail:
    LeaveCriticalSection(&pds->LockCache);
    pds->Statistics.cLISTDIR.miss++;
    return FALSE;
}

VOID VfsCache_DirectoryPut(_In_ LPCWSTR wcsDirectoryName, _In_ PVFS_RESULT_FILEINFO pfi, _In_ QWORD cfi, _In_ PVFS_GLOBAL_STATE pds, _In_ QWORD qwCacheValidMs)
{
    PVFS_CACHE_DIRECTORY cd;
    EnterCriticalSection(&pds->LockCache);
    cd = &pds->CacheDirectory[pds->CacheDirectoryIndex];
    cd->qwExpireTickCount64 = 0;
    LocalFree(cd->pfi);
    cd->pfi = NULL;
    cd->pfi = (PVFS_RESULT_FILEINFO)LocalAlloc(0, cfi * sizeof(VFS_RESULT_FILEINFO));
    if(!cd->pfi) {
        LeaveCriticalSection(&pds->LockCache);
        return;
    }
    cd->qwExpireTickCount64 = GetTickCount64() + qwCacheValidMs;
    memcpy(cd->pfi, pfi, cfi * sizeof(VFS_RESULT_FILEINFO));
    cd->cfi = cfi;
    wcscpy_s(cd->wszDirectoryName, MAX_PATH, wcsDirectoryName);
    pds->CacheDirectoryIndex = (pds->CacheDirectoryIndex + 1) % CACHE_DIRECTORY_ENTRIES;
    LeaveCriticalSection(&pds->LockCache);
}

VOID VfsCache_DirectoryDel(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo, _In_ BOOL isDeleteAll)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    WCHAR wszPath[MAX_PATH];
    LPWSTR wszFile;
    QWORD i;
    Vfs_UtilSplitPathFile(wszPath, &wszFile, wcsFileName);
    EnterCriticalSection(&pds->LockCache);
    for(i = 0; i < CACHE_DIRECTORY_ENTRIES; i++) {
        if(isDeleteAll || !wcscmp(wszPath, pds->CacheDirectory[i].wszDirectoryName)) {
            pds->CacheDirectory[i].qwExpireTickCount64 = 0;
            LocalFree(pds->CacheDirectory[i].pfi);
            pds->CacheDirectory[i].pfi = NULL;
        }
    }
    LeaveCriticalSection(&pds->LockCache);
}

_Success_(return)
BOOL VfsCache_MemGet(_In_ BYTE tp, _Out_ LPVOID pbBuffer, _In_ QWORD qwA, _In_ DWORD cbLength, _In_ PVFS_GLOBAL_STATE pds)
{
    QWORD i, qwOffset, qwCurrentTickCount;
    qwCurrentTickCount = GetTickCount64();
    EnterCriticalSection(&pds->LockCache);
    for(i = 0; i < CACHE_MEM_ENTRIES; i++) {
        if(qwCurrentTickCount - pds->CacheMem[tp][i].qwTickCount64 > CACHE_MEM_LIFETIME_MS) {
            continue;
        }
        qwOffset = qwA - pds->CacheMem[tp][i].qwA;
        if((qwOffset > CACHE_MEM_SIZE) || (qwOffset + cbLength > CACHE_MEM_SIZE)) {
            continue;
        }
        memcpy(pbBuffer, pds->CacheMem[tp][i].pb + qwOffset, cbLength);
        LeaveCriticalSection(&pds->LockCache);
        pds->Statistics.cRAM.hit++;
        pds->Statistics.cbRAM.hit += cbLength;
        return TRUE;
    }
    LeaveCriticalSection(&pds->LockCache);
    pds->Statistics.cRAM.miss++;
    pds->Statistics.cbRAM.miss += cbLength;
    return FALSE;
}

VOID VfsCache_MemDel(_In_ BYTE tp, _In_ QWORD qwA, _In_ DWORD cbLength, _In_ PVFS_GLOBAL_STATE pds)
{
    QWORD i;
    EnterCriticalSection(&pds->LockCache);
    for(i = 0; i < CACHE_MEM_ENTRIES; i++) {
        if((qwA > pds->CacheMem[tp][i].qwA) && (qwA < pds->CacheMem[tp][i].qwA + CACHE_MEM_SIZE)) {
            pds->CacheMem[tp][i].qwTickCount64 = 0;
        }
        if((qwA + cbLength > pds->CacheMem[tp][i].qwA) && (qwA + cbLength < pds->CacheMem[tp][i].qwA + CACHE_MEM_SIZE)) {
            pds->CacheMem[tp][i].qwTickCount64 = 0;
        }
    }
    LeaveCriticalSection(&pds->LockCache);
}

VOID VfsCache_MemPut(_In_ BYTE tp, _In_ LPVOID pbBuffer, _In_ QWORD qwA, _In_ PVFS_GLOBAL_STATE pds)
{
    EnterCriticalSection(&pds->LockCache);
    pds->CacheMem[tp][pds->CacheMemIndex].qwTickCount64 = GetTickCount64();
    pds->CacheMem[tp][pds->CacheMemIndex].qwA = qwA;
    memcpy(pds->CacheMem[tp][pds->CacheMemIndex].pb, pbBuffer, CACHE_MEM_SIZE);
    pds->CacheMemIndex = (pds->CacheMemIndex + 1) % CACHE_MEM_ENTRIES;
    LeaveCriticalSection(&pds->LockCache);
}

_Success_(return)
BOOL VfsCache_FileGet(_In_ LPCWSTR wcsFileName, _In_ QWORD cbOffset, _Out_ LPVOID pb, _In_ DWORD cb, _In_ PVFS_GLOBAL_STATE pds)
{
    QWORD i, qwCurrentTickCount;
    qwCurrentTickCount = GetTickCount64();
    EnterCriticalSection(&pds->LockCache);
    for(i = 0; i < CACHE_FILE_ENTRIES; i++) {
        if(wcscmp(wcsFileName, pds->CacheFile[i].wszFileName)) {
            continue;
        }
        if(qwCurrentTickCount - pds->CacheFile[i].qwTickCount64 > CACHE_FILE_LIFETIME_MS) {
            continue;
        }
        if((cbOffset < pds->CacheFile[i].cbOffset) || (cbOffset + cb) > pds->CacheFile[i].cbOffset + pds->CacheFile[i].cb) {
            continue;
        }
        memcpy(pb, pds->CacheFile[i].pb + cbOffset - pds->CacheFile[i].cbOffset, cb);
        LeaveCriticalSection(&pds->LockCache);
        pds->Statistics.cFILE.hit++;
        pds->Statistics.cbFILE.hit += cb;
        return TRUE;
    }
    LeaveCriticalSection(&pds->LockCache);
    pds->Statistics.cFILE.miss++;
    pds->Statistics.cbFILE.miss += cb;
    return FALSE;
}

VOID VfsCache_FileDel(_In_ LPCWSTR wcsFileName, _In_ QWORD cbOffset, _In_ DWORD cb, _In_ PVFS_GLOBAL_STATE pds)
{
    QWORD i, qwCurrentTickCount;
    qwCurrentTickCount = GetTickCount64();
    EnterCriticalSection(&pds->LockCache);
    for(i = 0; i < CACHE_FILE_ENTRIES; i++) {
        if(_wcsicmp(wcsFileName, pds->CacheFile[i].wszFileName)) {
            continue;
        }
        if(qwCurrentTickCount - pds->CacheFile[i].qwTickCount64 > CACHE_FILE_LIFETIME_MS) {
            continue;
        }
        if((cbOffset < pds->CacheFile[i].cbOffset) || (cbOffset + cb) > pds->CacheFile[i].cbOffset + pds->CacheFile[i].cb) {
            continue;
        }
        pds->CacheFile[i].qwTickCount64 = 0;
    }
    LeaveCriticalSection(&pds->LockCache);
}

VOID VfsCache_FilePut(_In_ LPCWSTR wcsFileName, _In_ QWORD cbOffset, _In_ PBYTE pb, _In_ QWORD cb, _In_ PVFS_GLOBAL_STATE pds)
{
    EnterCriticalSection(&pds->LockCache);
    cb = min(cb, CACHE_FILE_SIZE);
    pds->CacheFile[pds->CacheFileIndex].qwTickCount64 = GetTickCount64();
    pds->CacheFile[pds->CacheFileIndex].cb = cb;
    pds->CacheFile[pds->CacheFileIndex].cbOffset = cbOffset;
    wcscpy_s(pds->CacheFile[pds->CacheFileIndex].wszFileName, MAX_PATH, wcsFileName);
    memcpy(pds->CacheFile[pds->CacheFileIndex].pb, pb, cb);
    pds->CacheFileIndex = (pds->CacheFileIndex + 1) % CACHE_FILE_ENTRIES;
    LeaveCriticalSection(&pds->LockCache);
}

//-------------------------------------------------------------------------------
// Utility functions below:
//-------------------------------------------------------------------------------

#define _VFS_SET_FILETIME_OPT(p_ft_dst, p_ft_src, p_st_src) (*(PQWORD)p_ft_dst = (p_ft_src && *(PQWORD)p_ft_src) ? *(PQWORD)p_ft_src : (SystemTimeToFileTime(p_st_src, p_ft_dst) ? *(PQWORD)p_ft_dst : 0))

_Success_(return)
BOOL UnicodeToAscii(_Out_writes_(cDst) LPSTR szDst, _In_ SIZE_T cDst, _In_ LPCWSTR wcsSrc)
{
    DWORD i = 0;
    while(TRUE) {
        if(i >= cDst) { return FALSE; }
        if(wcsSrc[i] > 255) { return FALSE; }
        szDst[i] = (CHAR)wcsSrc[i];
        if(wcsSrc[i] == 0) { return TRUE; }
        i++;
    }
}

VOID Vfs_UtilSplitPathFile(_Out_writes_(MAX_PATH) LPWSTR wszPath, _Out_ LPWSTR *pwcsFile, _In_ LPCWSTR wcsFileName)
{
    DWORD i, iSplitFilePath = 0;
    wcsncpy_s(wszPath, MAX_PATH, wcsFileName, _TRUNCATE);
    for(i = 0; i < MAX_PATH; i++) {
        if(wszPath[i] == '\\') {
            iSplitFilePath = i;
        }
        if(wszPath[i] == 0) {
            break;
        }
    }
    wszPath[iSplitFilePath] = 0;
    *pwcsFile = wszPath + iSplitFilePath + 1;
}

BOOL Vfs_ConvertFilenameToUnix(LPSTR szFileNameUnix, LPCWSTR wcsFileNameVfs) {
    DWORD i;
    CHAR sz[MAX_PATH];
    if(!UnicodeToAscii(sz, MAX_PATH, wcsFileNameVfs)) {
        return FALSE;
    }
    for(i = 0; i < MAX_PATH; i++) {
        if(sz[i] == '\\') {
            sz[i] = '/';
        }
    }
    strcpy_s(szFileNameUnix, MAX_PATH, sz + 6);
    if(szFileNameUnix[0] == 0) {
        szFileNameUnix[0] = '/';
        szFileNameUnix[1] = 0;
    }
    return TRUE;
}

BOOL Vfs_InitVfsOperation(_Out_ PVFS_OPERATION pop, _In_ QWORD op, _In_ LPCWSTR wcsFileName, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    ZeroMemory(pop, sizeof(VFS_OPERATION));
    pop->magic = VFS_OP_MAGIC;
    pop->op = op;
    if(pds->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_WINDOWS) {
        wcscpy_s(pop->wszFileName, MAX_PATH, _wcsicmp(wcsFileName, L"\\files") ? wcsFileName : L"\\??\\C:\\");
        memcpy(pop->wszFileName, L"\\??\\C:", 6 * sizeof(WCHAR));
        pop->flags = VFS_FLAGS_UNICODE;
        return TRUE;
    }
    return Vfs_ConvertFilenameToUnix(pop->szFileName, wcsFileName);
}

BOOL Vfs_ListDirectory(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo, _Out_ PVFS_RESULT_FILEINFO *ppfi, _Out_ PQWORD pcfi)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    BOOL result;
    VFS_OPERATION op;
    QWORD cbfi;
    result = VfsCache_DirectoryGetDirectory(ppfi, pcfi, wcsFileName, pds);
    if(result) { return TRUE; }
    // matches: \files*
    if(!_wcsnicmp(wcsFileName, L"\\files", 6) && pds->fKMD) {
        result = Vfs_InitVfsOperation(&op, VFS_OP_CMD_LIST_DIRECTORY, wcsFileName, DokanFileInfo);
        if(!result) { return FALSE; }
        EnterCriticalSection(&pds->LockDma);
        result = VfsCache_DirectoryGetDirectory(ppfi, pcfi, wcsFileName, pds);
        if(result) {
            LeaveCriticalSection(&pds->LockDma);
            return TRUE;
        }
        result = Exec_ExecSilent(pds->szNameVfsShellcode, (PBYTE)&op, sizeof(VFS_OPERATION), (PBYTE*)ppfi, &cbfi);
        if(!result) {
            LeaveCriticalSection(&pds->LockDma);
            return FALSE;
        }
        *pcfi = cbfi / sizeof(VFS_RESULT_FILEINFO);
        VfsCache_DirectoryPut(wcsFileName, *ppfi, *pcfi, pds, CACHE_DIRECTORY_LIFETIME_FILE_MS);
        LeaveCriticalSection(&pds->LockDma);
        return TRUE;
    }
    return FALSE;
}

BOOL Vfs_ListSingle(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo, _Out_ PVFS_RESULT_FILEINFO pfi)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    BOOL result, isExisting;
    WCHAR wszPath[MAX_PATH];
    LPWSTR wszFile;
    QWORD cfiDma;
    PVFS_RESULT_FILEINFO pfiDma = NULL;
    Vfs_UtilSplitPathFile(wszPath, &wszFile, wcsFileName);
    result = VfsCache_DirectoryGetSingle(pfi, &isExisting, wszPath, wszFile, pds);
    if(result) { return isExisting; }
    result = Vfs_ListDirectory(wszPath, DokanFileInfo, &pfiDma, &cfiDma);
    if(!result) { return FALSE; }
    LocalFree(pfiDma);
    result = VfsCache_DirectoryGetSingle(pfi, &isExisting, wszPath, wszFile, pds);
    if(result) { 
        return isExisting; 
    }
    return FALSE;
}

VOID Vfs_Delete(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    VFS_OPERATION op;
    BOOL result;
    if(!_wcsnicmp(wcsFileName, L"\\files\\", 7)) {
        result = Vfs_InitVfsOperation(&op, VFS_OP_CMD_DELETE, wcsFileName, DokanFileInfo);
        EnterCriticalSection(&pds->LockDma);
        Exec_ExecSilent(pds->szNameVfsShellcode, (PBYTE)&op, sizeof(VFS_OPERATION), NULL, NULL);
        LeaveCriticalSection(&pds->LockDma);
        VfsCache_DirectoryDel(wcsFileName, DokanFileInfo, FALSE);
    }
}

BOOL Vfs_IsFileInBlackList(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    if(pds->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_LINUX) {
        return !wcsncmp(wcsFileName, L"\\files\\dev\\watchdog", 19);
    }
    return FALSE;
}

VOID Vfs_SetFileTime(_Out_ PFILETIME ptDst, _In_opt_ PFILETIME ptSrcOpt, _In_ PSYSTEMTIME pSrcSystemTime)
{
    if(ptSrcOpt && *(PQWORD)ptSrcOpt) {
        *(PQWORD)ptDst = *(PQWORD)ptSrcOpt;
    } else {
        SystemTimeToFileTime(pSrcSystemTime, ptDst);
    }
}

VOID Vfs_FindFilesManualEntry(_In_ LPCWSTR wcsEntryName, _In_ QWORD cb, _In_ DWORD dwFileAttributes, _In_ PFillFindData FillFindData, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    WIN32_FIND_DATAW findData;
    ZeroMemory(&findData, sizeof(WIN32_FIND_DATAW));
    wcscpy_s(findData.cFileName, MAX_PATH, wcsEntryName);
    findData.nFileSizeHigh = (DWORD)(cb >> 32);
    findData.nFileSizeLow = (DWORD)cb;
    findData.dwFileAttributes = dwFileAttributes;
    SystemTimeToFileTime(&pds->time, &findData.ftCreationTime);
    SystemTimeToFileTime(&pds->time, &findData.ftLastWriteTime);
    SystemTimeToFileTime(&pds->time, &findData.ftLastAccessTime);
    FillFindData(&findData, DokanFileInfo);
}

VOID Vfs_StatisticsShowUpdate(_In_ PVFS_STATISTICS s)
{
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    if(s->hConsole) {
        GetConsoleScreenBufferInfo(s->hConsole, &consoleInfo);
        consoleInfo.dwCursorPosition.Y = s->wConsoleCursorPosition;
        SetConsoleCursorPosition(s->hConsole, consoleInfo.dwCursorPosition);
    }
    printf(
        " CACHE STATISTICS            CACHE HIT /   CACHE MISS /        TOTAL       \n" \
        " RAM ACCESS COUNT:   %12lli %3lli%% / %12lli / %12lli       \n" \
        " RAM BYTES READ:     %12lli %3lli%% / %12lli / %12lli       \n" \
        " FILE ACCESS COUNT:  %12lli %3lli%% / %12lli / %12lli       \n" \
        " FILE BYTES READ:    %12lli %3lli%% / %12lli / %12lli       \n" \
        " DIR LIST COUNT:     %12lli %3lli%% / %12lli / %12lli       \n" \
        " FILE LIST COUNT:    %12lli %3lli%% / %12lli / %12lli       \n",
        s->cRAM.hit,      100 * s->cRAM.hit / max(1, s->cRAM.hit + s->cRAM.miss),                s->cRAM.miss,      s->cRAM.hit + s->cRAM.miss,
        s->cbRAM.hit,     100 * s->cbRAM.hit / max(1, s->cbRAM.hit + s->cbRAM.miss),             s->cbRAM.miss,     s->cbRAM.hit + s->cbRAM.miss,
        s->cFILE.hit,     100 * s->cFILE.hit / max(1, s->cFILE.hit + s->cFILE.miss),             s->cFILE.miss,     s->cFILE.hit + s->cFILE.miss,
        s->cbFILE.hit,    100 * s->cbFILE.hit / max(1, s->cbFILE.hit + s->cbFILE.miss),          s->cbFILE.miss,    s->cbFILE.hit + s->cbFILE.miss,
        s->cLISTDIR.hit,  100 * s->cLISTDIR.hit / max(1, s->cLISTDIR.hit + s->cLISTDIR.miss),    s->cLISTDIR.miss,  s->cLISTDIR.hit + s->cLISTDIR.miss,
        s->cLISTFILE.hit, 100 * s->cLISTFILE.hit / max(1, s->cLISTFILE.hit + s->cLISTFILE.miss), s->cLISTFILE.miss, s->cLISTFILE.hit + s->cLISTFILE.miss
        );
    if(!s->hConsole) {
        s->hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        GetConsoleScreenBufferInfo(s->hConsole, &consoleInfo);
        s->wConsoleCursorPosition = consoleInfo.dwCursorPosition.Y - 7;
    }
}

VOID Vfs_StatisticsThread(_In_ PVFS_STATISTICS s)
{
    while(!s->fThreadExit) {
        Sleep(100);
        Vfs_StatisticsShowUpdate(s);
    }
    ExitThread(0);
}

//-------------------------------------------------------------------------------
// Dokan Callback functions below:
//-------------------------------------------------------------------------------

NTSTATUS DOKAN_CALLBACK
VfsCallback_CreateFile(LPCWSTR wcsFileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext, ACCESS_MASK DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    BOOL result;
    VFS_RESULT_FILEINFO fi;
    //VFS_OPERATION op;
    UNREFERENCED_PARAMETER(SecurityContext);
    UNREFERENCED_PARAMETER(FileAttributes);
    UNREFERENCED_PARAMETER(CreateOptions);
    // root, file or proc directory
    if(!wcscmp(wcsFileName, L"\\") || (pds->fKMD && !_wcsicmp(wcsFileName, L"\\files"))) {
        if(CreateDisposition != CREATE_NEW && CreateDisposition != OPEN_ALWAYS && CreateDisposition != OPEN_EXISTING) {
            return pds->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED);
        }
        DokanFileInfo->IsDirectory = TRUE;
        return STATUS_SUCCESS;
    }
    // ram dump file
    if(!_wcsicmp(wcsFileName, L"\\liveram-raw.raw") || !_wcsicmp(wcsFileName, L"\\liveram-native.raw")) {
        if(DokanFileInfo->IsDirectory) {
            return STATUS_NOT_A_DIRECTORY;
        }
        if(CreateDisposition != CREATE_NEW && CreateDisposition != OPEN_ALWAYS && CreateDisposition != OPEN_EXISTING) {
            return pds->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED);
        }
        DokanFileInfo->Nocache = TRUE;
        if(CreateDisposition == OPEN_ALWAYS) {
            return STATUS_OBJECT_NAME_COLLISION;
        }
        return STATUS_SUCCESS;
    }
    // matches: \files*
    if(!_wcsnicmp(wcsFileName, L"\\files", 6) && pds->fKMD) {
        if(CreateDisposition != CREATE_NEW && CreateDisposition != OPEN_ALWAYS && CreateDisposition != OPEN_EXISTING) {
            pds->DokanNtStatusFromWin32(ERROR_ACCESS_DENIED);
        }
        result = Vfs_ListSingle(wcsFileName, DokanFileInfo, &fi);
        /*
        TODO: allow create new files some time in the future.
        if(!result) {
            if(CreateDisposition == CREATE_NEW || CreateDisposition == OPEN_ALWAYS) {
                result = _Vfs_InitVfsOperation(&op, VFS_OP_CMD_CREATE, wcsFileName, DokanFileInfo);
                if(!result) { return STATUS_FILE_INVALID; }
                EnterCriticalSection(&pds->LockDma);
                Exec_ExecSilent(pds->pCfg, pds->pDeviceData, pds->szNameVfsShellcode, (PBYTE)&op, sizeof(VFS_OPERATION), NULL, NULL);
                LeaveCriticalSection(&pds->LockDma);
                VfsCache_DirectoryDel(wcsFileName, DokanFileInfo, FALSE);
            }
            result = _Vfs_ListSingle(wcsFileName, DokanFileInfo, &fi);
        }
        */
        if(!result) { 
            return STATUS_FILE_INVALID; 
        }
        DokanFileInfo->IsDirectory = (fi.flags & VFS_FLAGS_FILE_DIRECTORY) ? TRUE : FALSE;
        DokanFileInfo->Nocache = TRUE;
        return (CreateDisposition == OPEN_ALWAYS) ? STATUS_OBJECT_NAME_COLLISION : STATUS_SUCCESS;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_GetFileInformation(_In_ LPCWSTR wcsFileName, _Inout_ LPBY_HANDLE_FILE_INFORMATION hfi, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    WIN32_FIND_DATA;
    BOOL result;
    VFS_RESULT_FILEINFO fi;
    BYTE tp;
    // root,files and proc directories
    if(!wcscmp(wcsFileName, L"\\") || (pds->fKMD && (!_wcsicmp(wcsFileName, L"\\files") || !_wcsicmp(wcsFileName, L"\\files\\")))) {
        SystemTimeToFileTime(&pds->time, &hfi->ftCreationTime);
        SystemTimeToFileTime(&pds->time, &hfi->ftLastWriteTime);
        SystemTimeToFileTime(&pds->time, &hfi->ftLastAccessTime);
        hfi->nFileSizeHigh = 0;
        hfi->nFileSizeLow = 0;
        hfi->dwFileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        return STATUS_SUCCESS;
    }
    // RAM images.
    if(!_wcsicmp(wcsFileName, L"\\liveram-kmd.raw") || !_wcsicmp(wcsFileName, L"\\liveram-native.raw")) { // ram dump file
        SystemTimeToFileTime(&pds->time, &hfi->ftCreationTime);
        SystemTimeToFileTime(&pds->time, &hfi->ftLastWriteTime);
        SystemTimeToFileTime(&pds->time, &hfi->ftLastAccessTime);
        tp = !_wcsicmp(wcsFileName, L"\\liveram-kmd.raw") ? VFS_RAM_TP_KMD : VFS_RAM_TP_NATIVE;
        hfi->nFileSizeHigh = (DWORD)(pds->cbRAM[tp] >> 32);
        hfi->nFileSizeLow = (DWORD)pds->cbRAM[tp];
        hfi->dwFileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        return STATUS_SUCCESS;
    }
    // matches: \files* or \proc*
    if((!_wcsnicmp(wcsFileName, L"\\files", 6) && pds->fKMD)) {
        result = Vfs_ListSingle(wcsFileName, DokanFileInfo, &fi);
        if(!result) { return STATUS_FILE_INVALID; }
        _VFS_SET_FILETIME_OPT(&hfi->ftCreationTime, &fi.tCreateOpt, &pds->time);
        _VFS_SET_FILETIME_OPT(&hfi->ftLastAccessTime, &fi.tAccessOpt, &pds->time);
        _VFS_SET_FILETIME_OPT(&hfi->ftLastWriteTime, &fi.tModifyOpt, &pds->time);
        hfi->nFileSizeHigh = (DWORD)(fi.cb >> 32);
        hfi->nFileSizeLow = (DWORD)fi.cb;
        hfi->dwFileAttributes |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        hfi->dwFileAttributes |= (fi.flags & VFS_FLAGS_FILE_NORMAL) ? FILE_ATTRIBUTE_NORMAL : 0;
        hfi->dwFileAttributes |= (fi.flags & VFS_FLAGS_FILE_DIRECTORY) ? FILE_ATTRIBUTE_DIRECTORY : 0;
        return STATUS_SUCCESS;
    }
    return STATUS_FILE_NOT_AVAILABLE;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_FindFiles(LPCWSTR wcsFileName, PFillFindData FillFindData, PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    WIN32_FIND_DATAW findData;
    BOOL result;
    QWORD i, cfi;
    PVFS_RESULT_FILEINFO pfi, pfiBase = NULL;
    if(!wcscmp(wcsFileName, L"\\")) {
        if(pds->cbRAM[VFS_RAM_TP_KMD]) {
            Vfs_FindFilesManualEntry(L"liveram-kmd.raw", pds->cbRAM[VFS_RAM_TP_KMD], FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FillFindData, DokanFileInfo);
        }
        if(pds->cbRAM[VFS_RAM_TP_NATIVE]) {
            Vfs_FindFilesManualEntry(L"liveram-native.raw", pds->cbRAM[VFS_RAM_TP_NATIVE], FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FillFindData, DokanFileInfo);
        }
        if(pds->fKMD) {
            Vfs_FindFilesManualEntry(L"files", 0, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FillFindData, DokanFileInfo);
        }
        return STATUS_SUCCESS;
    }
    if(!_wcsicmp(wcsFileName, L"\\liveram-kmd.raw") && pds->cbRAM[VFS_RAM_TP_KMD]) {
        Vfs_FindFilesManualEntry(L"liveram-kmd.raw", pds->cbRAM[VFS_RAM_TP_KMD], FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FillFindData, DokanFileInfo);
        return STATUS_SUCCESS;
    }
    if(!_wcsicmp(wcsFileName, L"\\liveram-native.raw") && pds->cbRAM[VFS_RAM_TP_NATIVE]) {
        Vfs_FindFilesManualEntry(L"liveram-native.raw", pds->cbRAM[VFS_RAM_TP_NATIVE], FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FillFindData, DokanFileInfo);
        return STATUS_SUCCESS;
    }
    // matches: \files*
    if(!_wcsnicmp(wcsFileName, L"\\files", 6) && pds->fKMD) {
        result = Vfs_ListDirectory(wcsFileName, DokanFileInfo, &pfiBase, &cfi);
        if(!result) { return STATUS_SUCCESS; }
        for(i = 0; i < cfi; i++) {
            pfi = pfiBase + i;
            memset(&findData, 0, sizeof(WIN32_FIND_DATAW));
            _VFS_SET_FILETIME_OPT(&findData.ftCreationTime, &pfi->tCreateOpt, &pds->time);
            _VFS_SET_FILETIME_OPT(&findData.ftLastAccessTime, &pfi->tAccessOpt, &pds->time);
            _VFS_SET_FILETIME_OPT(&findData.ftLastWriteTime, &pfi->tModifyOpt, &pds->time);
            wcscpy_s(findData.cFileName, MAX_PATH, pfi->wszFileName);
            findData.nFileSizeHigh = (DWORD)(pfi->cb >> 32);
            findData.nFileSizeLow = (DWORD)pfi->cb;
            findData.dwFileAttributes |= FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
            findData.dwFileAttributes |= (pfi->flags & VFS_FLAGS_FILE_NORMAL) ? FILE_ATTRIBUTE_NORMAL : 0;
            findData.dwFileAttributes |= (pfi->flags & VFS_FLAGS_FILE_DIRECTORY) ? FILE_ATTRIBUTE_DIRECTORY : 0;
            FillFindData(&findData, DokanFileInfo);
        }
        LocalFree(pfiBase);
    }
    return STATUS_SUCCESS;
}

NTSTATUS _VfsReadFile_RAM(_In_ BYTE tp, _Out_ LPVOID Buffer, _In_ DWORD BufferLength, _Out_ LPDWORD ReadLength, _In_ LONGLONG Offset, _In_ PVFS_GLOBAL_STATE pds)
{
    BOOL result;
    QWORD qwBaseOffset, qwBase, qwSize, qwCfgAddrMaxOrig;
    qwBaseOffset = Offset % 0x1000;
    qwBase = Offset - qwBaseOffset;
    qwSize = (BufferLength + qwBaseOffset + 0xfff) & ~0xfff;
    if(qwBase >= pds->cbRAM[tp]) {
        *ReadLength = 0;
        return STATUS_FILE_INVALID;
    }
    if(qwBase + qwSize > pds->cbRAM[tp]) {
        qwSize -= pds->cbRAM[tp] - qwBase;
    }
    if(qwSize > 0x01000000) {
        qwSize = 0x01000000;
    }
    *ReadLength = (DWORD)min(BufferLength, qwSize - qwBaseOffset);
    result = VfsCache_MemGet(tp, Buffer, Offset, *ReadLength, pds);
    if(result) {
        return STATUS_SUCCESS;
    }
    qwSize = CACHE_MEM_SIZE;
    EnterCriticalSection(&pds->LockDma);
    switch(tp) {
        case VFS_RAM_TP_KMD:
            qwCfgAddrMaxOrig = ctxMain->cfg.qwAddrMax;    // TODO: REMOVE UGLY HACK WITH ADDRMAX...
            ctxMain->cfg.qwAddrMax = min(pds->cbRAM[tp], qwBase + qwSize);
            result = Util_Read16M(pds->pbDMA16M, qwBase, NULL);
            ctxMain->cfg.qwAddrMax = qwCfgAddrMaxOrig;
            break;
        case VFS_RAM_TP_NATIVE:
            result = (0 != DeviceReadDMA(qwBase, 0x01000000, pds->pbDMA16M, NULL));
            break;
    }
    memcpy(Buffer, pds->pbDMA16M + qwBaseOffset, *ReadLength);
    VfsCache_MemPut(tp, pds->pbDMA16M, qwBase, pds);
    LeaveCriticalSection(&pds->LockDma);
    return STATUS_SUCCESS;
}

NTSTATUS _VfsReadFile_File(_In_ LPCWSTR wcsFileName, _Out_ LPVOID Buffer, _In_ DWORD BufferLength, _In_ LPDWORD ReadLength, _In_ LONGLONG Offset, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    BOOL result;
    VFS_OPERATION op;
    PBYTE pbBufferDma = NULL;
    QWORD cbBufferDma;
    QWORD qwBaseOffset, qwBase, qwSize;
    if(Vfs_IsFileInBlackList(wcsFileName, DokanFileInfo)) { return STATUS_ACCESS_DENIED; }
    *ReadLength = BufferLength;
    result = VfsCache_FileGet(wcsFileName, Offset, Buffer, BufferLength, pds);
    if(result) {
        return STATUS_SUCCESS; 
    }
    result = Vfs_InitVfsOperation(&op, VFS_OP_CMD_READ, wcsFileName, DokanFileInfo);
    if(!result) { return STATUS_DATA_ERROR; }
    qwBaseOffset = Offset % 0x00100000; // 1MB
    qwBase = Offset - qwBaseOffset;
    qwSize = (BufferLength + qwBaseOffset + 0x1fffff) & ~0x1fffff;
    op.offset = qwBase;
    op.cb = qwSize;
    EnterCriticalSection(&pds->LockDma);
    // TODO OP FIXES!
    result = Exec_ExecSilent(pds->szNameVfsShellcode, (PBYTE)&op, sizeof(VFS_OPERATION), &pbBufferDma, &cbBufferDma);
    if(result && (qwBaseOffset <= cbBufferDma)) {
        VfsCache_FilePut(wcsFileName, qwBase, pbBufferDma, cbBufferDma, pds);
        *ReadLength = (DWORD)min(*ReadLength, cbBufferDma - qwBaseOffset);
        memcpy(Buffer, pbBufferDma + qwBaseOffset, *ReadLength);
        LocalFree(pbBufferDma);
        LeaveCriticalSection(&pds->LockDma);
        return STATUS_SUCCESS;
    }
    LeaveCriticalSection(&pds->LockDma);
    return STATUS_DATA_ERROR;
}

NTSTATUS _VfsWriteFile_File(_In_ LPCWSTR wcsFileName, _In_ LPCVOID Buffer, _In_ DWORD NumberOfBytesToWrite, _In_ LPDWORD NumberOfBytesWritten, _In_ LONGLONG Offset, _In_ PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    BOOL result;
    PVFS_OPERATION pop = NULL;
    if(Vfs_IsFileInBlackList(wcsFileName, DokanFileInfo)) { return STATUS_ACCESS_DENIED; }
    pop = (PVFS_OPERATION)LocalAlloc(LMEM_ZEROINIT, sizeof(VFS_OPERATION) + NumberOfBytesToWrite);
    if(!pop) { return STATUS_MEMORY_NOT_ALLOCATED; }
    result = Vfs_InitVfsOperation(pop, VFS_OP_CMD_WRITE, wcsFileName, DokanFileInfo);
    pop->offset = (QWORD)Offset;
    if(!result) { return STATUS_DATA_ERROR; }
    if(DokanFileInfo->WriteToEndOfFile) { pop->flags |= VFS_FLAGS_APPEND_ON_WRITE; }
    if(0 == Offset) {
        pop->flags |= VFS_FLAGS_TRUNCATE_ON_WRITE; // TODO: find when to truncate and when not to... if 0th byte is written file is truncated now...
    }
    memcpy(pop->pb, Buffer, NumberOfBytesToWrite);
    pop->cb = NumberOfBytesToWrite;
    EnterCriticalSection(&pds->LockDma);
    Exec_ExecSilent(pds->szNameVfsShellcode, (PBYTE)pop, sizeof(VFS_OPERATION) + NumberOfBytesToWrite, NULL, NULL);
    LeaveCriticalSection(&pds->LockDma);
    VfsCache_FileDel(wcsFileName, Offset, NumberOfBytesToWrite, pds);
    VfsCache_DirectoryDel(wcsFileName, DokanFileInfo, FALSE);
    // TODO: UGLY BUT WORKS - PLEASE FIX THIS!!!
    *NumberOfBytesWritten = NumberOfBytesToWrite;
    LocalFree(pop);
    return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_ReadFile(LPCWSTR wcsFileName, LPVOID Buffer, DWORD BufferLength, LPDWORD ReadLength, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    if(!_wcsicmp(wcsFileName, L"\\liveram-kmd.raw") && pds->cbRAM[VFS_RAM_TP_KMD]) { // kernel module backed RAM file
        return _VfsReadFile_RAM(VFS_RAM_TP_KMD, Buffer, BufferLength, ReadLength, Offset, pds);
    }
    if(!_wcsicmp(wcsFileName, L"\\liveram-native.raw") && pds->cbRAM[VFS_RAM_TP_NATIVE]) { // kernel module backed RAM file
        return _VfsReadFile_RAM(VFS_RAM_TP_NATIVE, Buffer, BufferLength, ReadLength, Offset, pds);
    }
    if(!_wcsnicmp(wcsFileName, L"\\files\\", 7) && pds->fKMD) {
        return _VfsReadFile_File(wcsFileName, Buffer, BufferLength, ReadLength, Offset, DokanFileInfo);
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_WriteFile(LPCWSTR wcsFileName, LPCVOID Buffer, DWORD NumberOfBytesToWrite, LPDWORD NumberOfBytesWritten, LONGLONG Offset, PDOKAN_FILE_INFO DokanFileInfo)
{
    PVFS_GLOBAL_STATE pds = (PVFS_GLOBAL_STATE)DokanFileInfo->DokanOptions->GlobalContext;
    BOOL result;
    if(!_wcsicmp(wcsFileName, L"\\liveram-kmd.raw") && pds->cbRAM[VFS_RAM_TP_KMD]) { // kernel module backed RAM file
        EnterCriticalSection(&pds->LockDma);
        result = DeviceWriteMEM(Offset, NumberOfBytesToWrite, (PBYTE)Buffer, TRUE);
        LeaveCriticalSection(&pds->LockDma);
        VfsCache_MemDel(VFS_RAM_TP_KMD, Offset, NumberOfBytesToWrite, pds);
        *NumberOfBytesWritten = NumberOfBytesToWrite;
        return result ? STATUS_SUCCESS : STATUS_FILE_SYSTEM_LIMITATION;
    }
    if(!_wcsicmp(wcsFileName, L"\\liveram-native.raw") && pds->cbRAM[VFS_RAM_TP_NATIVE]) { // native DMA backed RAM file
        EnterCriticalSection(&pds->LockDma);
        result = LcWrite(ctxMain->hLC, Offset, NumberOfBytesToWrite, (PBYTE)Buffer);
        LeaveCriticalSection(&pds->LockDma);
        VfsCache_MemDel(VFS_RAM_TP_NATIVE, Offset, NumberOfBytesToWrite, pds);
        *NumberOfBytesWritten = NumberOfBytesToWrite;
        return result ? STATUS_SUCCESS : STATUS_FILE_SYSTEM_LIMITATION;
    }
    if(!_wcsnicmp(wcsFileName, L"\\files\\", 7) && pds->fKMD) {
        return _VfsWriteFile_File(wcsFileName, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, Offset, DokanFileInfo);
    }
    return STATUS_FILE_INVALID;
}

NTSTATUS DOKAN_CALLBACK
VfsCallback_DeleteFile(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo) {
    Vfs_Delete(wcsFileName, DokanFileInfo);
    return STATUS_SUCCESS;
}

VOID DOKAN_CALLBACK 
VfsCallback_Cleanup(LPCWSTR wcsFileName, PDOKAN_FILE_INFO DokanFileInfo) {
    if(DokanFileInfo->DeleteOnClose) {
        if(!DokanFileInfo->IsDirectory) {
            Vfs_Delete(wcsFileName, DokanFileInfo);
        }
    }
}

VOID ActionMount()
{
    int status;
    HMODULE hModuleDokan = NULL;
    PVFS_GLOBAL_STATE pDokanState = NULL;
    PDOKAN_OPTIONS pDokanOptions = NULL;
    PDOKAN_OPERATIONS pDokanOperations = NULL;
    WCHAR wszMountPoint[] = { 'K', ':', '\\', 0 };
    int(*fnDokanMain)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS);
    // sanity checks
    if(!ctxMain->phKMD && (PCILEECH_DEVICE_EQUALS("usb3380") || (ctxMain->cfg.qwAddrMax > 0x0000040000000000) || (ctxMain->cfg.qwAddrMax < 0x00400000))) {
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
    hModuleDokan = LoadLibraryExA("dokan1.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    fnDokanMain = (int(*)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS))GetProcAddress(hModuleDokan, "DokanMain");
    if(!hModuleDokan || !fnDokanMain) {
        printf("MOUNT: Failed. The required DOKANY file system library is not installed. \n");
        printf("Please download from : https://github.com/dokan-dev/dokany/releases/latest\n");
        goto fail;
    }
    pDokanState = (PVFS_GLOBAL_STATE)LocalAlloc(LMEM_ZEROINIT, sizeof(VFS_GLOBAL_STATE));
    pDokanOptions = (PDOKAN_OPTIONS)LocalAlloc(LMEM_ZEROINIT, sizeof(DOKAN_OPTIONS));
    pDokanOperations = (PDOKAN_OPERATIONS)LocalAlloc(LMEM_ZEROINIT, sizeof(DOKAN_OPERATIONS));
    if(!pDokanState || !pDokanOptions || !pDokanOperations) {
        printf("MOUNT: Failed (out of memory).\n");
        goto fail;
    }
    // set global state
    GetSystemTime(&pDokanState->time);
    pDokanState->fKMD = (ctxMain->phKMD != NULL);
    pDokanState->cbRAM[VFS_RAM_TP_KMD] = pDokanState->fKMD ? (ctxMain->phKMD->pPhysicalMap[ctxMain->phKMD->cPhysicalMap - 1].BaseAddress + ctxMain->phKMD->pPhysicalMap[ctxMain->phKMD->cPhysicalMap - 1].NumberOfBytes) : 0;
    pDokanState->cbRAM[VFS_RAM_TP_NATIVE] = PCILEECH_DEVICE_EQUALS("usb3380") ? 0 : (pDokanState->fKMD ? pDokanState->cbRAM[VFS_RAM_TP_KMD] : ctxMain->cfg.qwAddrMax);
    InitializeCriticalSection(&pDokanState->LockDma);
    InitializeCriticalSection(&pDokanState->LockCache);
    pDokanState->DokanNtStatusFromWin32 = (NTSTATUS(*)(DWORD))GetProcAddress(hModuleDokan, "DokanNtStatusFromWin32");
    pDokanState->PCILeechOperatingSystem = pDokanState->fKMD ? ctxMain->pk->OperatingSystem : 0;
    if(pDokanState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_WINDOWS) {
        strcpy_s(pDokanState->szNameVfsShellcode, 32, "DEFAULT_WINX64_VFS_KSH");
    } else if(pDokanState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_LINUX) {
        strcpy_s(pDokanState->szNameVfsShellcode, 32, "DEFAULT_LINUX_X64_VFS_KSH");
    } else if(pDokanState->PCILeechOperatingSystem == KMDDATA_OPERATING_SYSTEM_MACOS) {
        strcpy_s(pDokanState->szNameVfsShellcode, 32, "DEFAULT_MACOS_VFS_KSH");
    } else if(pDokanState->fKMD) {
        printf("MOUNT: Operating system not supported.\n");
        goto fail;
    }
    // set options
    pDokanOptions->Version = DOKAN_VERSION;
    pDokanOptions->Options |= DOKAN_OPTION_NETWORK;
    pDokanOptions->UNCName = L"PCILeechFileSystem";
    if((ctxMain->cfg.szInS[0] >= 'a' && ctxMain->cfg.szInS[0] <= 'z') || (ctxMain->cfg.szInS[0] >= 'A' && ctxMain->cfg.szInS[0] <= 'Z')) {
        wszMountPoint[0] = ctxMain->cfg.szInS[0];
    }
    pDokanOptions->MountPoint = wszMountPoint;
    pDokanOptions->GlobalContext = (ULONG64)pDokanState;
    pDokanOptions->Timeout = 60000;
    // set callbacks
    pDokanOperations->ZwCreateFile = VfsCallback_CreateFile;
    pDokanOperations->Cleanup = VfsCallback_Cleanup;
    pDokanOperations->DeleteFileW = VfsCallback_DeleteFile;
    pDokanOperations->GetFileInformation = VfsCallback_GetFileInformation;
    pDokanOperations->FindFiles = VfsCallback_FindFiles;
    pDokanOperations->ReadFile = VfsCallback_ReadFile;
    pDokanOperations->WriteFile = VfsCallback_WriteFile;
    // enable
    printf(
        "MOUNTING PCILEECH FILE SYSTEM:                                                 \n" \
        "===============================================================================\n");
    if(pDokanState->fKMD) {
        printf(
            "PCILeech DMA attack target file system is mounted in the /files/ folder.       \n" \
            "Please see limitations below:                                                  \n" \
            " - Kernel module is required and is supported on: Windows, Linux and macOS.    \n" \
            " - Create file: not implemented.                                               \n" \
            " - Write to files may be buggy and may in rare cases corrupt the target file.  \n" \
            " - Delete file will most often work, but with errors.                          \n" \
            " - Delete directory, rename/move file and other features may not be supported. \n" \
            " - Only the C:\\ drive is mounted on Windows target systems.                   \n" \
            "===============================================================================\n");
    }
    printf("MOUNT: Mounting as drive %S\n", pDokanOptions->MountPoint);
    if(ctxMain->cfg.fVerbose) {
        pDokanState->Statistics.hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Vfs_StatisticsThread, &pDokanState->Statistics, 0, NULL);
    }
    status = fnDokanMain(pDokanOptions, pDokanOperations);
    while(status == DOKAN_SUCCESS) {
        printf("MOUNT: ReMounting as drive %S\n", pDokanOptions->MountPoint);
        status = fnDokanMain(pDokanOptions, pDokanOperations);
    }
    printf("MOUNT: Failed. Status Code: %i\n", status);
    DeleteCriticalSection(&pDokanState->LockDma);
    DeleteCriticalSection(&pDokanState->LockCache);
fail:
    if(pDokanState) {
        pDokanState->Statistics.fThreadExit = TRUE;
        Sleep(150);
        LocalFree(pDokanState);
    }
    if(hModuleDokan) { FreeLibrary(hModuleDokan); }
    LocalFree(pDokanOptions);
    LocalFree(pDokanOperations);
}

#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)

#include "vfs.h"

VOID ActionMount()
{
    printf("MOUNT: Failed. Operation only supported in PCILeech for Windows.\n");
}

#endif /* LINUX || ANDROID */
