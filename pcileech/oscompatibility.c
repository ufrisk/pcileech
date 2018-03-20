// oscompatibility.c : pcileech windows/linux/android compatibility layer.
//
// (c) Ulf Frisk, 2017-2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifdef WIN32

#include "oscompatibility.h"

VOID usleep(_In_ DWORD us)
{
    QWORD tmFreq, tmStart, tmNow, tmThreshold;
    if(us == 0) { return; }
    QueryPerformanceFrequency((PLARGE_INTEGER)&tmFreq);
    tmThreshold = tmFreq * us / (1000 * 1000);  // dw_uS uS
    QueryPerformanceCounter((PLARGE_INTEGER)&tmStart);
    while(QueryPerformanceCounter((PLARGE_INTEGER)&tmNow) && ((tmNow - tmStart) < tmThreshold)) {
        ;
    }
}

#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)

#include "oscompatibility.h"
#include <fcntl.h>
#include <sys/ioctl.h>

#define INTERNAL_HANDLE_TYPE_THREAD        0xdeadbeeffedfed01

typedef struct tdINTERNAL_HANDLE {
    QWORD type;
    HANDLE handle;
} INTERNAL_HANDLE, *PINTERNAL_HANDLE;

HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes)
{
    HANDLE h = malloc(uBytes);
    if(h && (uFlags & LMEM_ZEROINIT)) {
        memset(h, 0, uBytes);
    }
    return h;
}

VOID LocalFree(HANDLE hMem)
{
    free(hMem);
}

QWORD GetTickCount64()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / (1000 * 1000);
}

HANDLE CreateThread(
    PVOID     lpThreadAttributes,
    SIZE_T    dwStackSize,
    PVOID     lpStartAddress,
    PVOID     lpParameter,
    DWORD     dwCreationFlags,
    PDWORD    lpThreadId
) {
    PINTERNAL_HANDLE ph;
    pthread_t thread;
    int status;
    status = pthread_create(&thread, NULL, lpStartAddress, lpParameter);
    if(status) { return NULL;}
    ph = malloc(sizeof(INTERNAL_HANDLE));
    ph->type = INTERNAL_HANDLE_TYPE_THREAD;
    ph->handle = (HANDLE)thread;
    return ph;
}

VOID GetLocalTime(LPSYSTEMTIME lpSystemTime)
{
    time_t curtime;
    struct tm *t;
    curtime = time(NULL);
    t = localtime(&curtime);
    lpSystemTime->wYear = t->tm_year;
    lpSystemTime->wMonth = t->tm_mon;
    lpSystemTime->wDayOfWeek = t->tm_wday;
    lpSystemTime->wDay = t->tm_yday;
    lpSystemTime->wHour = t->tm_hour;
    lpSystemTime->wMinute = t->tm_min;
    lpSystemTime->wSecond = t->tm_sec;
    lpSystemTime->wMilliseconds = 0;
}

HANDLE FindFirstFileA(LPSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    DWORD i;
    DIR *hDir;
    CHAR szDirName[MAX_PATH];
    memset(szDirName, 0, MAX_PATH);
    strcpy_s(lpFindFileData->__cExtension, 5, lpFileName + strlen(lpFileName) - 4);
    strcpy_s(szDirName, MAX_PATH, lpFileName);
    for(i = strlen(szDirName) - 1; i > 0; i--) {
        if(szDirName[i] == '/') {
            szDirName[i] = 0;
            break;
        }
    }
    hDir = opendir(szDirName);
    if(!hDir) { return NULL; }
    return FindNextFileA((HANDLE)hDir, lpFindFileData) ? (HANDLE)hDir : INVALID_HANDLE_VALUE;
}

BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    DIR *hDir = (DIR*)hFindFile;
    struct dirent *dir;
    char* sz;
    if(!hDir) { return FALSE; }
    while ((dir = readdir(hDir)) != NULL) {
        sz = dir->d_name;
        if((strlen(sz) > 4) && !strcasecmp(sz + strlen(sz) - 4, lpFindFileData->__cExtension)) {
            strcpy_s(lpFindFileData->cFileName, MAX_PATH, sz);
            return TRUE;
        }
    }
    closedir(hDir);
    return FALSE;
}

BOOL __WinUsb_ReadWritePipe(
    WINUSB_INTERFACE_HANDLE InterfaceHandle,
    UCHAR    PipeID,
    PUCHAR    Buffer,
    ULONG    BufferLength,
    PULONG    LengthTransferred,
    PVOID    Overlapped
) {
    int result, cbTransferred;
    result = libusb_bulk_transfer(
        InterfaceHandle,
        PipeID,
        Buffer,
        BufferLength,
        &cbTransferred,
        500);
    *LengthTransferred = (ULONG)cbTransferred;
    return result ? FALSE : TRUE;
}

BOOL WinUsb_Free(WINUSB_INTERFACE_HANDLE InterfaceHandle)
{
    if(!InterfaceHandle) { return TRUE; }
    libusb_release_interface(InterfaceHandle, 0);
    libusb_reset_device(InterfaceHandle);
    libusb_close(InterfaceHandle);
    return TRUE;
}

DWORD InterlockedAdd(DWORD *Addend, DWORD Value)
{
    return __sync_add_and_fetch(Addend, Value);
}

// ----------------------------------------------------------------------------
// Facade implementation of FTDI functions using functionality provided by
// kernel driver ft60x by @key2fr in the backend. NB! functionality below
// is by no way complete - only minimal functionality required by PCILeech
// use is implemented ...
// ----------------------------------------------------------------------------

ULONG FT60x_FT_Create(PVOID pvArg, DWORD dwFlags, HANDLE *pftHandle)
{
    int i, result;
    // NB! underlying driver will create a device object at /dev/ft60x[0-3]
    //     when loaded. Iterate through possible combinations at load time.
    CHAR szDevice[12] = { '/', 'd', 'e', 'v', '/', 'f', 't', '6', '0', 'x', '0', 0 };
    for(i = 0; i < 4; i++) {
        szDevice[10] = '0' + i;
        result = open(szDevice, O_RDWR | O_CLOEXEC);
        if(result > 0) {
            *pftHandle = (HANDLE)(QWORD)result;
            return 0;
        }
    }
    return 0x20;
}

ULONG FT60x_FT_Close(HANDLE ftHandle)
{
    close((int)(QWORD)ftHandle);
    return 0;
}

ULONG FT60x_FT_GetChipConfiguration(HANDLE ftHandle, PVOID pvConfiguration)
{
    return ioctl((int)(QWORD)ftHandle, 0, pvConfiguration) ? 0x20 : 0;
}

ULONG FT60x_FT_SetChipConfiguration(HANDLE ftHandle, PVOID pvConfiguration)
{
    return ioctl((int)(QWORD)ftHandle, 1, pvConfiguration) ? 0x20 : 0;
}

ULONG FT60x_FT_AbortPipe(HANDLE ftHandle, UCHAR ucPipeID)
{
    // dummy function, only here for compatibility in Linux case
    return 0;
}

ULONG FT60x_FT_WritePipe(HANDLE ftHandle, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
{
    int result, cbTxTotal = 0;
    // NB! underlying ft60x driver cannot handle more than 0x800 bytes per write,
    //     split larger writes into smaller writes if required.
    while(cbTxTotal < ulBufferLength) {
        result = write((int)(QWORD)ftHandle, pucBuffer + cbTxTotal, min(0x800, ulBufferLength - cbTxTotal));
        if(!result) { return 0x20; } // no bytes transmitted -> error
        cbTxTotal += result;
    }
    *pulBytesTransferred = cbTxTotal;
    return 0;
}

ULONG FT60x_FT_ReadPipe2(HANDLE ftHandle, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
{
    int result;
    *pulBytesTransferred = 0;
    // NB! underlying driver have a max tranfer size in one go, multiple reads may be
    //     required to retrieve all data - hence the loop.
    do {
        result = read((int)(QWORD)ftHandle, pucBuffer + *pulBytesTransferred, ulBufferLength - *pulBytesTransferred);
        if(result > 0) {
            *pulBytesTransferred += result;
        }
    } while((result > 0) && (0 == (result % 0x1000)) && (ulBufferLength > *pulBytesTransferred));
    return (result > 0) ? 0 : 0x20;
}

ULONG FT60x_FT_ReadPipe(HANDLE ftHandle, UCHAR ucPipeID, PUCHAR pucBuffer, ULONG ulBufferLength, PULONG pulBytesTransferred, PVOID pOverlapped)
{
    // NB! underlying driver won't return all data on the USB core queue in first
    //     read so we have to read two times.
    ULONG i, result, cbRx, cbRxTotal = 0;
    for(i = 0; i < 2; i++) {
        result = FT60x_FT_ReadPipe2(ftHandle, ucPipeID, pucBuffer + cbRxTotal, ulBufferLength - cbRxTotal, &cbRx, pOverlapped);
        cbRxTotal += cbRx;
    }
    *pulBytesTransferred = cbRxTotal;
    return result;
}

// ----------------------------------------------------------------------------
// LoadLibrary / GetProcAddress facades (for FPGA functionality) below:
// ----------------------------------------------------------------------------

#define MAGIC_HMODULE_FTD3XX    0x00eeffee81635432

HMODULE LoadLibrary(LPWSTR lpFileName)
{
    if(lpFileName && (0 == memcmp(lpFileName, L"FTD3XX.dll", 20))) {
        return (HMODULE)MAGIC_HMODULE_FTD3XX;
    }
    return NULL;
}

FARPROC GetProcAddress(HMODULE hModule, LPSTR lpProcName)
{
    if(MAGIC_HMODULE_FTD3XX != (QWORD)hModule)              { return NULL; }
    if(0 == strcmp("FT_AbortPipe", lpProcName))             { return (FARPROC)FT60x_FT_AbortPipe; }
    if(0 == strcmp("FT_Close", lpProcName))                 { return (FARPROC)FT60x_FT_Close; }
    if(0 == strcmp("FT_Create", lpProcName))                { return (FARPROC)FT60x_FT_Create; }
    if(0 == strcmp("FT_GetChipConfiguration", lpProcName))  { return (FARPROC)FT60x_FT_GetChipConfiguration; }
    if(0 == strcmp("FT_SetChipConfiguration", lpProcName))  { return (FARPROC)FT60x_FT_SetChipConfiguration; }
    if(0 == strcmp("FT_ReadPipe", lpProcName))              { return (FARPROC)FT60x_FT_ReadPipe; }
    if(0 == strcmp("FT_WritePipe", lpProcName))             { return (FARPROC)FT60x_FT_WritePipe; }
    return NULL;
}

#endif /* LINUX || ANDROID */
#ifdef LINUX

BOOL GetExitCodeThread(HANDLE hThread, PDWORD lpExitCode)
{
    PINTERNAL_HANDLE ph = (PINTERNAL_HANDLE)hThread;
    if(ph->type != INTERNAL_HANDLE_TYPE_THREAD) { return FALSE; }
    *lpExitCode = (pthread_tryjoin_np((pthread_t)ph->handle, NULL) == EBUSY) ? STILL_ACTIVE : 0;
    return TRUE;
}

#endif /* LINUX */
#ifdef ANDROID

BOOL GetExitCodeThread(HANDLE hThread, PDWORD lpExitCode)
{
    return FALSE;
}

#endif /* ANDROID */
