// kmd.h : definitions related to operating systems kernel modules functionality.
//
// (c) Ulf Frisk, 2016-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __KMD_H__
#define __KMD_H__
#include "pcileech.h"

/*
* Open a kernel module (KMD). This can be done in multiple ways as specified in
* the configuration data.
* -- return
*/
_Success_(return)
BOOL KMDOpen();

/*
* Unload an active kernel module from the target system and perform various
* cleanup tasks.
*/
VOID KMDUnload();

/*
* Clean up and free memory related to a kernel module without unloading the
* kernel module from the target system.
*/
VOID KMDClose();

/*
* Read physical memory from the target system using an active KMD as a proxy.
* -- qwAddress = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
* -- return
*/
_Success_(return)
BOOL KMDReadMemory(_In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Write physical memory to the target system using an active KMD as a proxy.
* -- qwAddress = the physical address to write to in the target system.
* -- pb = bytes to write
* -- cb = number of bytes to write.
* -- return TRUE on success, otherwise FALSE.
*/
_Success_(return)
BOOL KMDWriteMemory(_In_ QWORD qwAddress, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Submit a command to an already loaded kernel module.
* -- op = the command (opcode) to submit for processing.
* -- return TRUE on success, otherwise FALSE.
*/
_Success_(return)
BOOL KMD_SubmitCommand(_In_ QWORD op);

#endif /* __KMD_H__ */
