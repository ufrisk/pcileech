// kmd.h : definitions related to operating systems kernel modules functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __KMD_H__
#define __KMD_H__
#include "pcileech.h"

/*
* Open a kernel module (KMD). This can be done in multiple ways as specified in
* the configuration data.
* -- pCfg
* -- pDeviceData
* -- return
*/
BOOL KMDOpen(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

/*
* Close an active kernel module - perform various cleanup tasks, both on this
* system and the target system.
* -- pDeviceData
*/
VOID KMDClose(_In_ PDEVICE_DATA pDeviceData);

/*
* Read physical memory from the target system using an active KMD as a proxy.
* -- pDeviceData
* -- qwAddress = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
* -- return
*/
BOOL KMDReadMemory(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Write physical memory to the target system using an active KMD as a proxy.
* -- pDeviceData
* -- qwAddress = the physical address to write to in the target system.
* -- pb = bytes to write
* -- cb = number of bytes to write.
* -- return TRUE on success, otherwise FALSE.
*/
BOOL KMDWriteMemory(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddress, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Submit a command to an already loaded kernel module.
* -- pCfg
* -- pDeviceData
* -- phKMD = ptr to the kmd handle.
* -- op = the command (opcode) to submit for processing.
* -- return TRUE on success, otherwise FALSE.
*/
BOOL KMD_SubmitCommand(_In_opt_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PKMDHANDLE phKMD, _In_ QWORD op);

#endif /* __KMD_H__ */