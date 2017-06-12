// oscompatibility.c : pcileech windows/linux/android compatibility layer.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#if defined(LINUX) || defined(ANDROID)

#include "oscompatibility.h"

#define INTERNAL_HANDLE_TYPE_THREAD		0xdeadbeeffedfed01

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
	UCHAR	PipeID,
	PUCHAR	Buffer,
	ULONG	BufferLength,
	PULONG	LengthTransferred,
	PVOID	Overlapped
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
