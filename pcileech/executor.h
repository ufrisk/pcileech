// executor.h : definitions related to 'code execution' and 'console redirect' functionality.
//
// (c) Ulf Frisk, 2016
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
* -- pCfg
* -- pDeviceData
* -- pk
* -- phCallback = ptr to handle; handle must be null on first entry.
*/
VOID Exec_Callback(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ PKMDDATA pk, _Inout_ PHANDLE phCallback);

/*
* Close handle opened/used in Exec_Callback.
* -- hCallback = handle to close.
*/
VOID Exec_CallbackClose(_In_ HANDLE hCallback);

/*
* Try to execute a shellcode module in the target system kernel. This function
* requires a KMD to be loaded. The KMD is then used to load and execute the
* code supplied in the target system!
* -- pCfg
* -- pDeviceData
*/
VOID ActionExecShellcode(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

#endif /* __EXECUTOR_H__ */
