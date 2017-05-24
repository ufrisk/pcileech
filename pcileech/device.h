// device.h : definitions related to the hardware devices.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_H__
#define __DEVICE_H__
#include "pcileech.h"

#define PCILEECH_MEM_FLAG_RETRYONFAIL			0x01
#define PCILEECH_MEM_FLAG_VERIFYWRITE			0x02

/*
* Open a USB connection to the target device.
* -- ctx
* -- result
*/
BOOL DeviceOpen(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Clean up various device related stuff and deallocate memory buffers.
* -- ctx
*/
VOID DeviceClose(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Read data from the target system using DMA.
* -- ctx
* -- qwAddr
* -- pb
* -- cb
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Write data to the target system using DMA.
* -- ctx
* -- qwAddr
* -- pb
* -- cb
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL, PCILEECH_MEM_FLAG_VERIFYWRITE
* -- return
*/
BOOL DeviceWriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Write target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to write the memory, otherwise the memory will be written
* with standard DMA. Minimum granularity: byte.
* -- ctx
* -- qwAddress = the physical address to write to in the target system.
* -- pb = bytes to write
* -- cb = number of bytes to write.
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceWriteMEM(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Read target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to read the memory, otherwise the memory will be read with
* standard DMA. Minimum granularity: page (4kB)
* -- ctx
* -- qwAddress = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceReadMEM(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

#endif /* __DEVICE_H__ */