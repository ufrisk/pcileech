// executor.h : definitions related to 'code execution' and 'console redirect' functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __EXECUTOR_H__
#define __EXECUTOR_H__
#include "pcileech.h"
#include "kmd.h"

/*
* Callback for when kernel executable code is in "extended execution mode".
* This will allow the kernel executable code running on the target machine to
* communicate interactively with this executable to deliver large files.
* -- ctx
* -- phCallback = ptr to handle; handle must be null on first entry.
*/
VOID Exec_Callback(_Inout_ PPCILEECH_CONTEXT ctx, _Inout_ PHANDLE phCallback);

/*
* Close handle opened/used in Exec_Callback.
* -- hCallback = handle to close.
*/
VOID Exec_CallbackClose(_In_ HANDLE hCallback);

/*
* Execute specified shellcode silently (do not display anything on-screen).
* This function is to be called internally by PCILeech functionality that
* require more advanced kernel functionality than the core implant is able
* to provide.
* -- ctx
* -- szShellcodeName
* -- pbIn = binary data to send to shellcode executing on the target.
* -- cbIn
* -- ppbOut = ptr to receive allocated buffer containing the result.
*      Callers responsibility to call LocalFree(*ppbOut).
* -- pcbOut
* -- result
*/
BOOL Exec_ExecSilent(_Inout_ PPCILEECH_CONTEXT ctx, _In_ LPSTR szShellcodeName, _In_ PBYTE pbIn, _In_ QWORD cbIn, _Out_ PBYTE *ppbOut, _Out_ PQWORD pcbOut);

/*
* Try to execute a shellcode module in the target system kernel. This function
* requires a KMD to be loaded. The KMD is then used to load and execute the
* code supplied in the target system!
* -- ctx
*/
VOID ActionExecShellcode(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __EXECUTOR_H__ */
