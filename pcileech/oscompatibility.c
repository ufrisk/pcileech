// oscompatibility.c : pcileech windows/linux compatibility layer.
//
// (c) Ulf Frisk, 2017-2020
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifdef _WIN32

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

#endif /* _WIN32 */
#ifdef LINUX

#include "oscompatibility.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include "util.h"

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

BOOL QueryPerformanceFrequency(_Out_ LARGE_INTEGER *lpFrequency)
{
    *lpFrequency = 1000 * 1000;
    return TRUE;
}

BOOL QueryPerformanceCounter(_Out_ LARGE_INTEGER *lpPerformanceCount)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    *lpPerformanceCount = (ts.tv_sec * 1000 * 1000) + (ts.tv_nsec / 1000);  // uS resolution
    return TRUE;
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
    strcpy_s(lpFindFileData->__cExtension, 5, lpFileName + strlen(lpFileName) - 3);
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
        if((strlen(sz) > 3) && !strcasecmp(sz + strlen(sz) - 3, lpFindFileData->__cExtension)) {
            strcpy_s(lpFindFileData->cFileName, MAX_PATH, sz);
            return TRUE;
        }
    }
    closedir(hDir);
    return FALSE;
}

DWORD InterlockedAdd(DWORD *Addend, DWORD Value)
{
    return __sync_add_and_fetch(Addend, Value);
}

// ----------------------------------------------------------------------------
// LoadLibrary / GetProcAddress facades (for FPGA functionality) below:
// ----------------------------------------------------------------------------

HMODULE LoadLibraryA(LPSTR lpFileName)
{
    return dlopen(lpFileName, RTLD_NOW);
}

BOOL FreeLibrary(_In_ HMODULE hLibModule)
{
    dlclose(hLibModule);
}

FARPROC GetProcAddress(HMODULE hModule, LPSTR lpProcName)
{
    return dlsym(hModule, lpProcName);
}

BOOL GetExitCodeThread(HANDLE hThread, PDWORD lpExitCode)
{
    PINTERNAL_HANDLE ph = (PINTERNAL_HANDLE)hThread;
    if(ph->type != INTERNAL_HANDLE_TYPE_THREAD) { return FALSE; }
    *lpExitCode = (pthread_tryjoin_np((pthread_t)ph->handle, NULL) == EBUSY) ? STILL_ACTIVE : 0;
    return TRUE;
}

// ----------------------------------------------------------------------------
// CRITICAL_SECTION functionality below:
// ----------------------------------------------------------------------------

VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    memset(lpCriticalSection, 0, sizeof(CRITICAL_SECTION));
    pthread_mutexattr_init(&lpCriticalSection->mta);
    pthread_mutexattr_settype(&lpCriticalSection->mta, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&lpCriticalSection->mutex, &lpCriticalSection->mta);
}

VOID DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    pthread_mutex_destroy(&lpCriticalSection->mutex);
    memset(lpCriticalSection, 0, sizeof(CRITICAL_SECTION));
}

VOID EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    pthread_mutex_lock(&lpCriticalSection->mutex);
}

VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
    pthread_mutex_unlock(&lpCriticalSection->mutex);
}

// ----------------------------------------------------------------------------
// _kbhit functionality below:
// ----------------------------------------------------------------------------

VOID terminal_enable_raw_mode()
{
    struct termios term;
    tcgetattr(0, &term);
    term.c_lflag &= ~(ICANON | ECHO); // Disable echo as well
    tcsetattr(0, TCSANOW, &term);
}

VOID terminal_disable_raw_mode()
{
    struct termios term;
    tcgetattr(0, &term);
    term.c_lflag |= ICANON | ECHO;
    tcsetattr(0, TCSANOW, &term);
}

BOOL _kbhit()
{
    int byteswaiting;
    terminal_enable_raw_mode();
    ioctl(0, FIONREAD, &byteswaiting);
    terminal_disable_raw_mode();
    tcflush(0, TCIFLUSH);
    return byteswaiting > 0;
}

#endif /* LINUX */
