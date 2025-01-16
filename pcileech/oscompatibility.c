// oscompatibility.c : pcileech windows/linux compatibility layer.
//
// (c) Ulf Frisk, 2017-2025
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

#if defined(LINUX) || defined(MACOS)

#include "oscompatibility.h"
#include <stdatomic.h>
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

#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE CLOCK_MONOTONIC
#endif /* CLOCK_MONOTONIC_COARSE */

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
    UNREFERENCED_PARAMETER(lpThreadAttributes);
    UNREFERENCED_PARAMETER(dwStackSize);
    UNREFERENCED_PARAMETER(dwCreationFlags);
    UNREFERENCED_PARAMETER(lpThreadId);
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
    return TRUE;
}

FARPROC GetProcAddress(HMODULE hModule, LPSTR lpProcName)
{
    return dlsym(hModule, lpProcName);
}

#ifdef MACOS

// pthread_tryjoin_np does not exist on MacOS, so we need to implement it ourselves.
static int pthread_tryjoin_np(pthread_t thread, void **retval)
{
    // If pthread_kill(thread, 0) == ESRCH, the thread has exited (or doesn't exist).
    // In that case, we can call pthread_join safely. Otherwise, return EBUSY.
    int kill_rc = pthread_kill(thread, 0);
    if(kill_rc == ESRCH) {
        // The thread is done, so do a normal join.
        return pthread_join(thread, retval);
    } else if(kill_rc == 0) {
        // The thread is still running.
        return EBUSY;
    } else {

        return kill_rc;
    }
}

#endif /* MACOS */

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

#endif /* LINUX || MACOS */



// ----------------------------------------------------------------------------
// SRWLock functionality below:
// ----------------------------------------------------------------------------

#ifdef LINUX

#include <sys/syscall.h>
#include <linux/futex.h>

static int futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

VOID InitializeSRWLock(PSRWLOCK pSRWLock)
{
    ZeroMemory(pSRWLock, sizeof(SRWLOCK));
}

BOOL AcquireSRWLockExclusive_Try(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwZero = 0;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
        return TRUE;
    }
    __sync_sub_and_fetch_4(&pSRWLock->c, 1);
    return FALSE;
}

VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwZero;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
            return;
        }
        futex(&pSRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0);
    }
}

_Success_(return)
BOOL AcquireSRWLockExclusive_Timeout(_Inout_ PSRWLOCK pSRWLock, _In_ DWORD dwMilliseconds)
{
    DWORD dwZero;
    struct timespec ts;
    __sync_fetch_and_add_4(&pSRWLock->c, 1);
    while(TRUE) {
        dwZero = 0;
        if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwZero, 1)) {
            return TRUE;
        }
        if((dwMilliseconds != 0) && (dwMilliseconds != 0xffffffff)) {
            ts.tv_sec = dwMilliseconds / 1000;
            ts.tv_nsec = (dwMilliseconds % 1000) * 1000 * 1000;
            if((-1 == futex(&pSRWLock->xchg, FUTEX_WAIT, 1, &ts, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&pSRWLock->c, 1);
                return FALSE;
            }
        } else {
            if((-1 == futex(&pSRWLock->xchg, FUTEX_WAIT, 1, NULL, NULL, 0)) && (errno != EAGAIN)) {
                __sync_sub_and_fetch_4(&pSRWLock->c, 1);
                return FALSE;
            }
        }
    }
}

VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    DWORD dwOne = 1;
    if(atomic_compare_exchange_strong((atomic_uint *)&pSRWLock->xchg, &dwOne, 0)) {
        if(__sync_sub_and_fetch_4(&pSRWLock->c, 1)) {
            futex(&pSRWLock->xchg, FUTEX_WAKE, 1, NULL, NULL, 0);
        }
    }
}

#endif /* LINUX */

#ifdef MACOS

VOID InitializeSRWLock(PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) {
        pSRWLock->sem = dispatch_semaphore_create(1);
    }
}

BOOL AcquireSRWLockExclusive_Try(_Inout_ PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    return (0 == dispatch_semaphore_wait(pSRWLock->sem, DISPATCH_TIME_NOW));
}

VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    dispatch_semaphore_wait(pSRWLock->sem, DISPATCH_TIME_FOREVER);
}

_Success_(return)
BOOL AcquireSRWLockExclusive_Timeout(_Inout_ PSRWLOCK pSRWLock, _In_ DWORD dwMilliseconds)
{
    if(!pSRWLock->valid) { InitializeSRWLock(pSRWLock); }
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, dwMilliseconds * NSEC_PER_MSEC);
    return (0 == dispatch_semaphore_wait(pSRWLock->sem, timeout));
}

VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock)
{
    if(pSRWLock->valid) {
        dispatch_semaphore_signal(pSRWLock->sem);
    }
}

#endif /* MACOS */



// ----------------------------------------------------------------------------
// GetModule*() functionality below:
// ----------------------------------------------------------------------------

#ifdef LINUX

#include <link.h>

DWORD GetModuleFileNameA(_In_opt_ HMODULE hModule, _Out_ LPSTR lpFilename, _In_ DWORD nSize)
{
    struct link_map *lm = NULL;
    if(hModule && ((SIZE_T)hModule & 0xfff)) {
        dlinfo(hModule, RTLD_DI_LINKMAP, &lm);
        if(lm) {
            strncpy(lpFilename, lm->l_name, nSize);
            lpFilename[nSize - 1] = 0;
            return strlen(lpFilename);
        }
    }
    return readlink("/proc/self/exe", lpFilename, nSize);
}

#endif /* LINUX */

#ifdef MACOS

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>

DWORD GetModuleFileNameA(_In_opt_ HMODULE hModule, _Out_ LPSTR lpFilename, _In_ DWORD nSize)
{
    int ret;
    char resolvedPath[MAX_PATH];
    // ----------------------------------------------------------------------
    // 1) Handle the case hModule == NULL => main executable path
    // ----------------------------------------------------------------------
    if(hModule == NULL) {
        // macOS function to get the path of the main executable
        uint32_t bufSize = (uint32_t)nSize;
        ret = _NSGetExecutablePath(lpFilename, &bufSize);
        if(ret == 0) {
            // If you want to resolve symlinks and get an absolute path:
            // (optional: remove if you just want the raw path from dyld)
            if(realpath(lpFilename, resolvedPath)) {
                strncpy(lpFilename, resolvedPath, nSize);
                lpFilename[nSize - 1] = '\0';
            } else {
                // realpath failed, but we still have _NSGetExecutablePath
                // fallback to leaving lpFilename as-is
            }
            return (DWORD)strlen(lpFilename);
        } else {
            // _NSGetExecutablePath indicates buffer too small
            // or some other error
            // Ideally you handle this more gracefully by re-allocating
            // or returning an error code.
            if(bufSize > 0 && bufSize <= nSize) {
                // The function might have written a partial path, but typically
                // ret != 0 means not enough space. Return 0 or handle error.
            }
            return 0;
        }
    }
    // ----------------------------------------------------------------------
    // 2) hModule != NULL => look up the corresponding Mach-O image
    // ----------------------------------------------------------------------
    uint32_t imageCount = _dyld_image_count();
    for(uint32_t i = 0; i < imageCount; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        // Base address of this Mach-O image
        uintptr_t baseAddr = (uintptr_t)header + (uintptr_t)slide;
        if((uintptr_t)hModule == baseAddr) {
            // Found the matching Mach-O
            const char *imagePath = _dyld_get_image_name(i);
            if(imagePath) {
                strncpy(lpFilename, imagePath, nSize);
                lpFilename[nSize - 1] = '\0';
                return (DWORD)strlen(lpFilename);
            } else {
                // If for some reason there's no name
                return 0;
            }
        }
    }
    // ----------------------------------------------------------------------
    // 3) If we didn't find a matching image, return 0 or some error code
    // ----------------------------------------------------------------------
    return 0;
}

#endif /* MACOS */