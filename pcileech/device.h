// device.h : definitions related to the hardware devices.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_H__
#define __DEVICE_H__
#include "pcileech.h"
#include "statistics.h"

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
* Try read memory with DMA in a fairly optimal way considering device limits.
* The number of total successfully read bytes is returned. Failed reads will
* be zeroed out the he returned memory.
* -- ctx
* -- qwAddr
* -- pb
* -- cb
* -- pPageStat = optional page statistics
* -- return = the number of bytes successfully read.
*
*/
DWORD DeviceReadDMAEx(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat);

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
* Probe the memory of the target system to check whether it's readable or not.
* Please note that not all hardwares are supported (USB3380).
* -- ctx
* -- qwAddr = address to start probe from.
* -- cPages = number of 4kB pages to probe.
* -- pbResultMap = result map, 1 byte represents 1 page, 0 = fail, 1 = success.
* -- return = FALSE if not supported by underlying hardware, TRUE if supported.
*/
BOOL DeviceProbeDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ DWORD cPages, _Out_ __bcount(cPages) PBYTE pbResultMap);

/*
* Write target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to write the memory, otherwise the memory will be written
* with standard DMA. Minimum granularity: byte.
* -- ctx
* -- qwAddr = the physical address to write to in the target system.
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
* -- qwAddr = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceReadMEM(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Write PCIe Transaction Layer Packets (TLPs) to the device.
* -- ctx
* -- pb = PCIe TLP/TLPs to send.
* -- cb =
* -- return
*/
BOOL DeviceWriteTlp(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Listen for incoming PCIe Transaction Layer Packets (TLPs) for a specific
* amount of time.
* -- ctx
* -- dwTime = time in ms
* -- return
*/
BOOL DeviceListenTlp(_Inout_ PPCILEECH_CONTEXT ctx, _In_ DWORD dwTime);

#endif /* __DEVICE_H__ */