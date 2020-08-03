// executor.h : definitions related to 'code execution' and 'console redirect' functionality.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __EXECUTOR_H__
#define __EXECUTOR_H__
#include "pcileech.h"
#include "oscompatibility.h"
#include "kmd.h"

/*
* Execute a console redirect
* -- ConsoleBufferAddr_InputStream = physical or virtual address.
* -- ConsoleBufferAddr_OutputStream = physical or virtual address.
* -- dwPID = zero if physical address read, non-zero if virtual address read.
*/
VOID Exec_ConsoleRedirect(_In_ QWORD ConsoleBufferAddr_InputStream, _In_ QWORD ConsoleBufferAddr_OutputStream, _In_ DWORD dwPID);

/*
* Callback for when kernel executable code is in "extended execution mode".
* This will allow the kernel executable code running on the target machine to
* communicate interactively with this executable to deliver large files.
* -- phCallback = ptr to handle; handle must be null on first entry.
*/
VOID Exec_Callback(_Inout_ PHANDLE phCallback);

/*
* Close handle opened/used in Exec_Callback.
* -- hCallback = handle to close.
*/
VOID Exec_CallbackClose(_In_opt_ HANDLE hCallback);

/*
* Execute specified shellcode silently (do not display anything on-screen).
* This function is to be called internally by PCILeech functionality that
* require more advanced kernel functionality than the core implant is able
* to provide.
* -- szShellcodeName
* -- pbIn = binary data to send to shellcode executing on the target.
* -- cbIn
* -- ppbOut = ptr to receive allocated buffer containing the result.
*      Callers responsibility to call LocalFree(*ppbOut).
* -- pcbOut
* -- result
*/
_Success_(return)
BOOL Exec_ExecSilent(_In_ LPSTR szShellcodeName, _In_ PBYTE pbIn, _In_ QWORD cbIn, _Out_opt_ PBYTE *ppbOut, _Out_opt_ PQWORD pcbOut);

/*
* Try to execute a shellcode module in the target system kernel. This function
* requires a KMD to be loaded. The KMD is then used to load and execute the
* code supplied in the target system!
*/
VOID ActionExecShellcode();

/*
* Try execute python code on a remote host in the context of the LeechSvc.
*/
VOID ActionSvcExecPy();

#endif /* __EXECUTOR_H__ */
