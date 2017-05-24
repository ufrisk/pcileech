// kmd.h : definitions related to operating systems kernel modules functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __KMD_H__
#define __KMD_H__
#include "pcileech.h"

/*
* Open a kernel module (KMD). This can be done in multiple ways as specified in
* the configuration data.
* -- ctx
* -- return
*/
BOOL KMDOpen(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Unload an active kernel module from the target system and perform various
* cleanup tasks.
* -- ctx
*/
VOID KMDUnload(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Clean up and free memory related to a kernel module without unloading the
* kernel module from the target system.
* -- ctx
*/
VOID KMDClose(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Read physical memory from the target system using an active KMD as a proxy.
* -- ctx
* -- qwAddress = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
* -- return
*/
BOOL KMDReadMemory(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Write physical memory to the target system using an active KMD as a proxy.
* -- ctx
* -- qwAddress = the physical address to write to in the target system.
* -- pb = bytes to write
* -- cb = number of bytes to write.
* -- return TRUE on success, otherwise FALSE.
*/
BOOL KMDWriteMemory(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddress, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Submit a command to an already loaded kernel module.
* -- ctx
* -- op = the command (opcode) to submit for processing.
* -- return TRUE on success, otherwise FALSE.
*/
BOOL KMD_SubmitCommand(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD op);

#endif /* __KMD_H__ */