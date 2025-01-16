// oscompatibility.h : pcileech windows/linux compatibility layer.
//
// (c) Ulf Frisk, 2017-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OSCOMPATIBILITY_H__
#define __OSCOMPATIBILITY_H__
#include <leechcore.h>

#ifdef _WIN32

#include <Windows.h>
#include <stdio.h>
#include <winusb.h>
#include <setupapi.h>
#include <bcrypt.h>
#include <conio.h>

#pragma comment (lib, "winusb.lib")
#pragma comment (lib, "setupapi.lib")
#pragma comment (lib, "bcrypt.lib")

typedef unsigned __int64                    QWORD, *PQWORD;
#define PCILEECH_LIBRARY_FILETYPE           ".dll"

#pragma warning( disable : 4477)

VOID usleep(_In_ DWORD us);

#endif /* _WIN32 */

#ifdef LINUX
#define PCILEECH_LIBRARY_FILETYPE           ".so"
#endif /* LINUX */

#ifdef MACOS
#define PCILEECH_LIBRARY_FILETYPE           ".dylib"
#endif /* MACOS */

#if defined(LINUX) || defined(MACOS)

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef void                                VOID, *PVOID, *LPVOID;
typedef void*                               HANDLE, **PHANDLE, *HMODULE, *FARPROC;
typedef uint32_t                            BOOL, *PBOOL;
typedef uint8_t                             BYTE, *PBYTE, *LPBYTE;
typedef uint8_t                             UCHAR, *PUCHAR;
typedef char                                CHAR, *PCHAR, *PSTR, *LPSTR;
typedef const char                          *LPCSTR;
typedef int16_t                             SHORT, *PSHORT;
typedef int32_t                             LONG;
typedef int64_t                             LONGLONG;
typedef uint16_t                            WORD, *PWORD, USHORT, *PUSHORT;
typedef uint16_t                            WCHAR, *PWCHAR, *LPWSTR;
typedef const uint16_t                      *LPCWSTR;
typedef uint32_t                            UINT, DWORD, *PDWORD, *LPDWORD, NTSTATUS, ULONG, *PULONG, ULONG32;
typedef long long unsigned int              QWORD, *PQWORD, ULONG64, *PULONG64, ULONG_PTR;
typedef uint64_t                            DWORD64, *PDWORD64, LARGE_INTEGER, *PLARGE_INTEGER, ULONGLONG, FILETIME, *PFILETIME;
typedef size_t                              SIZE_T, *PSIZE_T;
typedef struct _M128A { ULONGLONG Low; LONGLONG High; } M128A, *PM128A;
typedef void* OVERLAPPED, *LPOVERLAPPED;
typedef struct tdEXCEPTION_RECORD32 { CHAR sz[80]; } EXCEPTION_RECORD32;
typedef struct tdEXCEPTION_RECORD64 { CHAR sz[152]; } EXCEPTION_RECORD64;
typedef struct tdSID { BYTE pb[12]; } SID, *PSID;
typedef DWORD(*PTHREAD_START_ROUTINE)(PVOID);
typedef DWORD(*LPTHREAD_START_ROUTINE)(PVOID);
typedef int(*_CoreCrtNonSecureSearchSortCompareFunction)(void const*, void const*);
#define errno_t                             int
#define CONST                               const
#define TRUE                                1
#define FALSE                               0
#define MAX_PATH                            260
#define LMEM_ZEROINIT                       0x0040
#define INVALID_HANDLE_VALUE                ((HANDLE)-1)
#define STD_INPUT_HANDLE                    ((DWORD)-10)
#define STD_OUTPUT_HANDLE                   ((DWORD)-11)
#define GENERIC_WRITE                       (0x40000000L)
#define GENERIC_READ                        (0x80000000L)
#define FILE_SHARE_READ                     (0x00000001L)
#define CREATE_NEW                          (0x00000001L)
#define OPEN_EXISTING                       (0x00000003L)
#define FILE_ATTRIBUTE_NORMAL               (0x00000080L)
#define STILL_ACTIVE                        (0x00000103L)
#define CRYPT_STRING_HEX_ANY                (0x00000008L)
#define CRYPT_STRING_HEXASCIIADDR           (0x00000008L)
#define STILL_ACTIVE                        (0x00000103L)
#define INVALID_FILE_SIZE                   (0xffffffffL)
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_MEM_WRITE                 0x80000000
#define _TRUNCATE                           ((SIZE_T)-1LL)
#define LPTHREAD_START_ROUTINE              PVOID
#define WINUSB_INTERFACE_HANDLE             libusb_device_handle*
#define PIPE_TRANSFER_TIMEOUT               0x03
#define CONSOLE_SCREEN_BUFFER_INFO          PVOID    // TODO: remove this dummy
#define SOCKET                              int
#define INVALID_SOCKET	                    -1
#define SOCKET_ERROR	                    -1
#define WSAEWOULDBLOCK                      10035L
#define MAXIMUM_WAIT_OBJECTS                64
#define WAIT_OBJECT_0                       (0x00000000UL)
#define WAIT_FAILED                         (0xFFFFFFFFUL)
#define WAIT_TIMEOUT                        (258L)
#define INFINITE                            (0xFFFFFFFFUL)
#define SID_MAX_SUB_AUTHORITIES             (15)
#define SECURITY_MAX_SID_SIZE               (sizeof(SID) - sizeof(DWORD) + (SID_MAX_SUB_AUTHORITIES * sizeof(DWORD)))
#define CP_ACP                              0
#define CP_UTF8                             65001
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define STATUS_SUCCESS                      ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED                ((NTSTATUS)0xC0000022L)
#define STATUS_DATA_ERROR                   ((NTSTATUS)0xC000003EL)
#define STATUS_UNSUCCESSFUL                 ((NTSTATUS)0xC0000001L)
#define STATUS_END_OF_FILE                  ((NTSTATUS)0xC0000011L)
#define STATUS_FILE_INVALID                 ((NTSTATUS)0xC0000098L)
#define STATUS_MEMORY_NOT_ALLOCATED         ((NTSTATUS)0xC00000A0L)
#define STATUS_FILE_SYSTEM_LIMITATION       ((NTSTATUS)0xC0000427L)
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010 
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800  
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000

//-----------------------------------------------------------------------------
// SAL DEFINES BELOW:
//-----------------------------------------------------------------------------
#define _In_
#define _In_z_
#define _Out_
#define _Inout_
#define _Inout_opt_
#define _In_opt_
#define _In_opt_z_
#define _Out_opt_
#define _Check_return_opt_
#define _Frees_ptr_opt_
#define _Post_ptr_invalid_
#define _Printf_format_string_
#define _In_reads_(x)
#define _In_reads_opt_(x)
#define _Out_writes_(x)
#define __bcount(x)
#define _Inout_bytecount_(x)
#define _Inout_count_(x)
#define _Inout_updates_(x)
#define _Inout_updates_opt_(x)
#define _Inout_updates_bytes_(x)
#define _Out_writes_bytes_opt_(x)
#define _Inout_updates_bytes_opt_(x)
#define _Out_writes_opt_(x)
#define _Out_writes_to_(x,y)
#define _Out_writes_z_(x)
#define _Maybenull_
#define _Success_(x)
#define _When_(x,y)
#define _Writable_bytes_(x)

#define WINAPI
#define UNREFERENCED_PARAMETER(x)           (void)(x)

#define max(a, b)                           (((a) > (b)) ? (a) : (b))
#define min(a, b)                           (((a) < (b)) ? (a) : (b))
#define _byteswap_ushort(v)                 (__builtin_bswap16(v))
#define _byteswap_ulong(v)                  (__builtin_bswap32(v))
#define _byteswap_uint64(v)                 (__builtin_bswap64(v))
#ifndef _rotr
#define _rotr(v,c)                          ((((DWORD)v) >> ((DWORD)c) | (DWORD)((DWORD)v) << (32 - (DWORD)c)))
#endif /* _rotr */
#define _rotr16(v,c)                        ((((WORD)v) >> ((WORD)c) | (WORD)((WORD)v) << (16 - (WORD)c)))
#define _rotr64(v,c)                        ((((QWORD)v) >> ((QWORD)c) | (QWORD)((QWORD)v) << (64 - (QWORD)c)))
#define _rotl64(v,c)                        ((QWORD)(((QWORD)v) << ((QWORD)c)) | (((QWORD)v) >> (64 - (QWORD)c)))
#define _countof(_Array)                    (sizeof(_Array) / sizeof(_Array[0]))
#define sprintf_s(s, maxcount, ...)         (snprintf(s, maxcount, __VA_ARGS__))
#define strnlen_s(s, maxcount)              (strnlen(s, maxcount))
#define strcpy_s(dst, len, src)             (strncpy(dst, src, len))
#define strncpy_s(dst, len, src, srclen)    (strncpy(dst, src, min((QWORD)(max(1, len)) - 1, (QWORD)(srclen))))
#define strncat_s(dst, dstlen, src, srclen) (strncat(dst, src, min((((strlen(dst) + 1 >= (QWORD)(dstlen)) || ((QWORD)(dstlen) == 0)) ? 0 : ((QWORD)(dstlen) - strlen(dst) - 1)), (QWORD)(srclen))))
#define strcat_s(dst, dstlen, src)          (strncat_s(dst, dstlen, src, _TRUNCATE))
#define _vsnprintf_s(dst, len, cnt, fmt, a) (vsnprintf(dst, min((QWORD)(len), (QWORD)(cnt)), fmt, a))
#define _stricmp(s1, s2)                    (strcasecmp(s1, s2))
#define _strnicmp(s1, s2, maxcount)         (strncasecmp(s1, s2, maxcount))
#define strtok_s(s, d, c)                   (strtok_r(s, d, c))
#define _snprintf_s(s,l,c,...)              (snprintf(s,min((QWORD)(l), (QWORD)(c)),__VA_ARGS__))
#define sscanf_s(s, f, ...)                 (sscanf(s, f, __VA_ARGS__))
#define SwitchToThread()                    (sched_yield())
#define ExitThread(dwExitCode)              (pthread_exit(dwExitCode))
#define ExitProcess(c)                      (exit(c ? EXIT_SUCCESS : EXIT_FAILURE))
#define Sleep(dwMilliseconds)               (usleep(1000*dwMilliseconds))
#define fopen_s(ppFile, szFile, szAttr)     ((*ppFile = fopen(szFile, szAttr)) ? 0 : 1)
#define ZeroMemory(pb, cb)                  (memset(pb, 0, cb))
#define WinUsb_SetPipePolicy(h, p, t, cb, pb)   // TODO: implement this for better USB2 performance.
#define CloseHandle(h)                          // TODO: remove this dummy implementation & replace with WARN.
#define _ftelli64(f)                        (ftello(f))
#define _fseeki64(f, o, w)                  (fseeko(f, o, w))
#define _chsize_s(fd, cb)                   (ftruncate(fd, cb))
#define _fileno(f)                          (fileno(f))
#define InterlockedAdd64(p, v)              (__sync_add_and_fetch(p, v))
#define InterlockedIncrement64(p)           (__sync_add_and_fetch(p, 1))
#define InterlockedIncrement(p)             (__sync_add_and_fetch_4(p, 1))
#define InterlockedDecrement(p)             (__sync_sub_and_fetch_4(p, 1))
#define GetCurrentProcess()					((HANDLE)-1)

typedef struct tdCRITICAL_SECTION {
    pthread_mutex_t mutex;
    pthread_mutexattr_t mta;
} CRITICAL_SECTION, *LPCRITICAL_SECTION;
VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection);
VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection);

typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct _WIN32_FIND_DATAA {
    CHAR __cExtension[5];
    CHAR cFileName[MAX_PATH];
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

HANDLE FindFirstFileA(LPSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
HANDLE LocalAlloc(DWORD uFlags, SIZE_T uBytes);
VOID LocalFree(HANDLE hMem);
DWORD GetModuleFileNameA(_In_opt_ HMODULE hModule, _Out_ LPSTR lpFilename, _In_ DWORD nSize);
QWORD GetTickCount64();
BOOL QueryPerformanceFrequency(_Out_ LARGE_INTEGER *lpFrequency);
BOOL QueryPerformanceCounter(_Out_ LARGE_INTEGER *lpPerformanceCount);
VOID GetLocalTime(LPSYSTEMTIME lpSystemTime);
DWORD InterlockedAdd(DWORD *Addend, DWORD Value);

HANDLE CreateThread(
    PVOID    lpThreadAttributes,
    SIZE_T    dwStackSize,
    PVOID    lpStartAddress,
    PVOID    lpParameter,
    DWORD    dwCreationFlags,
    PDWORD    lpThreadId
);

BOOL GetExitCodeThread(
    HANDLE    hThread,
    PDWORD    lpExitCode
);

HMODULE LoadLibraryA(LPSTR lpFileName);
BOOL FreeLibrary(_In_ HMODULE hLibModule);
FARPROC GetProcAddress(HMODULE hModule, LPSTR lpProcName);

BOOL _kbhit();

// SRWLOCK
#ifdef LINUX
typedef struct tdSRWLOCK {
    uint32_t xchg;
    int c;
} SRWLOCK, *PSRWLOCK;
#endif /* LINUX */
#ifdef MACOS
#include <dispatch/dispatch.h>
typedef struct tdSRWLOCK {
    union {
        QWORD valid;
        dispatch_semaphore_t sem;
    };
} SRWLOCK, *PSRWLOCK;
#endif /* MACOS */
VOID InitializeSRWLock(PSRWLOCK pSRWLock);
VOID AcquireSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock);
VOID ReleaseSRWLockExclusive(_Inout_ PSRWLOCK pSRWLock);
#define AcquireSRWLockShared    AcquireSRWLockExclusive
#define ReleaseSRWLockShared    ReleaseSRWLockExclusive
#define SRWLOCK_INIT            { 0 }

#endif /* LINUX || MACOS */

#endif /* __OSCOMPATIBILITY_H__ */
