// oscompatibility.h : pcileech windows/linux/android compatibility layer.
//
// (c) Ulf Frisk, 2017-2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __OSCOMPATIBILITY_H__
#define __OSCOMPATIBILITY_H__

#ifdef WIN32

#include <Windows.h>
#include <stdio.h>
#include <winusb.h>
#include <setupapi.h>
#include <bcrypt.h>
#include <conio.h>

#pragma comment (lib, "winusb.lib")
#pragma comment (lib, "setupapi.lib")
#pragma comment (lib, "bcrypt.lib")

typedef unsigned __int64					QWORD, *PQWORD;

#pragma warning( disable : 4477)

VOID usleep(_In_ DWORD us);

#endif /* WIN32 */
#ifdef LINUX

#include <libusb-1.0/libusb.h>

#endif /* LINUX */
#ifdef ANDROID

#include <libusb.h>

#endif /* ANDROID */
#if defined(LINUX) || defined(ANDROID)

#define _GNU_SOURCE

#include <byteswap.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

typedef void								VOID, *PVOID;
typedef void								*HANDLE, **PHANDLE;
typedef uint32_t							BOOL, *PBOOL;
typedef uint8_t								BYTE, *PBYTE;
typedef uint8_t								UCHAR, *PUCHAR;
typedef char								CHAR, *PCHAR, *PSTR, *LPSTR;
typedef uint16_t							WORD, *PWORD;
typedef wchar_t								WCHAR, *PWCHAR, *LPWSTR;
typedef uint32_t							DWORD, *PDWORD;
typedef uint32_t							ULONG, *PULONG;
typedef long long unsigned int				QWORD, *PQWORD;
typedef uint64_t							SIZE_T, *PSIZE_T;
#define TRUE								1
#define FALSE								0
#define MAX_PATH							260
#define LMEM_ZEROINIT						0x0040
#define INVALID_HANDLE_VALUE				((HANDLE)-1)
#define STD_INPUT_HANDLE					((DWORD)-10)
#define STD_OUTPUT_HANDLE					((DWORD)-11)
#define GENERIC_WRITE						(0x40000000L)
#define GENERIC_READ						(0x80000000L)
#define FILE_SHARE_READ						(0x00000001L)
#define CREATE_NEW							(0x00000001L)
#define OPEN_EXISTING						(0x00000003L)
#define FILE_ATTRIBUTE_NORMAL				(0x00000080L)
#define STILL_ACTIVE						(0x00000103L)
#define CRYPT_STRING_HEX_ANY				(0x00000008L)
#define CRYPT_STRING_HEXASCIIADDR			(0x00000008L)
#define STILL_ACTIVE						(0x00000103L)
#define INVALID_FILE_SIZE					(0xffffffffL)
#define _TRUNCATE							((SIZE_T)-1LL)
#define LPTHREAD_START_ROUTINE				PVOID
#define WINUSB_INTERFACE_HANDLE				libusb_device_handle*
#define PIPE_TRANSFER_TIMEOUT				0x03
#define CONSOLE_SCREEN_BUFFER_INFO			PVOID	// TODO: remove this dummy
#define CRITICAL_SECTION					HANDLE

#define _In_
#define _Out_
#define _Inout_
#define _Inout_opt_
#define _In_opt_
#define _Out_opt_
#define __bcount(x)
#define _Inout_bytecount_(x)
#define _Inout_updates_bytes_(x)
#define _Success_(return)


#define max(a, b)							(((a) > (b)) ? (a) : (b))
#define min(a, b)		 					(((a) < (b)) ? (a) : (b))
#define _byteswap_ulong(v)					(bswap_32(v))
#define strnlen_s(s, maxcount)				(strnlen(s, maxcount))
#define strcpy_s(dst, len, src)				(strncpy(dst, src, len))
#define _stricmp(s1, s2)					(strcasecmp(s1, s2))
#define _strnicmp(s1, s2, maxcount)			(strncasecmp(s1, s2, maxcount))
#define strtok_s(s, d, c)					(strtok_r(s, d, c))
#define _snprintf_s(s, l, _l, f, ...)		(snprintf(s, l, f, __VA_ARGS__))
#define sscanf_s(s, f, ...)					(sscanf(s, f, __VA_ARGS__))
#define SwitchToThread()					(sched_yield())
#define ExitThread(dwExitCode)				(pthread_exit(dwExitCode))
#define ExitProcess(c)						(exit(c ? EXIT_SUCCESS : EXIT_FAILURE))
#define Sleep(dwMilliseconds)				(usleep(1000*dwMilliseconds))
#define fopen_s(ppFile, szFile, szAttr)		((*ppFile = fopen(szFile, szAttr)) ? 0 : 1)
#define GetModuleFileNameA(m, f, l)			(readlink("/proc/self/exe", f, l))
#define ZeroMemory(pb, cb)					(memset(pb, 0, cb))
#define WinUsb_SetPipePolicy(h, p, t, cb, pb)	// TODO: implement this for better USB2 performance.
#define CloseHandle(h)							// TODO: remove this dummy implementation & replace with WARN.
#define _ftelli64(f)						(ftello(f))
#define _fseeki64(f, o, w)					(fseeko(f, o, w))

#define InitializeCriticalSection(x)		// no dma transfer critical section in linux yet
#define DeleteCriticalSection(x)			// no dma transfer critical section in linux yet
#define EnterCriticalSection(x)				// no dma transfer critical section in linux yet
#define LeaveCriticalSection(x)				// no dma transfer critical section in linux yet

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
QWORD GetTickCount64();
VOID GetLocalTime(LPSYSTEMTIME lpSystemTime);
DWORD InterlockedAdd(DWORD *Addend, DWORD Value);
BOOL WinUsb_Free(WINUSB_INTERFACE_HANDLE InterfaceHandle);

HANDLE CreateThread(
	PVOID	lpThreadAttributes,
	SIZE_T	dwStackSize,
	PVOID	lpStartAddress,
	PVOID	lpParameter,
	DWORD	dwCreationFlags,
	PDWORD	lpThreadId
);

BOOL GetExitCodeThread(
	HANDLE	hThread,
	PDWORD	lpExitCode
);

BOOL __WinUsb_ReadWritePipe(
	WINUSB_INTERFACE_HANDLE InterfaceHandle,
	UCHAR	PipeID,
	PUCHAR	Buffer,
	ULONG	BufferLength,
	PULONG	LengthTransferred,
	PVOID	Overlapped
);
#define WinUsb_ReadPipe(h, p, b, l, t, o)	(__WinUsb_ReadWritePipe(h, p, b, l, t, o))
#define WinUsb_WritePipe(h, p, b, l, t, o)	(__WinUsb_ReadWritePipe(h, p, b, l, t, o))

#endif /* LINUX || ANDROID */

#endif /* __OSCOMPATIBILITY_H__ */
