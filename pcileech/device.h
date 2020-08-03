// device.h : definitions related to the hardware devices.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_H__
#define __DEVICE_H__
#include "pcileech.h"
#include "oscompatibility.h"
#include "statistics.h"

/*
* Open a connection to the target device.
* -- result
*/
_Success_(return)
BOOL DeviceOpen();

/*
* Try read memory with DMA in a fairly optimal way considering device limits.
* The number of total successfully read bytes is returned. Failed reads will
* be zeroed out the he returned memory.
* -- pa
* -- cb
* -- pb
* -- pPageStat = optional page statistics
* -- return = the number of bytes successfully read.
*
*/
DWORD DeviceReadDMA(_In_ QWORD pa, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb, _Inout_opt_ PPAGE_STATISTICS pPageStat);

/*
* Write target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to write the memory, otherwise the memory will be written
* with standard DMA. Minimum granularity: byte.
* -- qwAddr = the physical address to write to in the target system.
* -- cb = number of bytes to write.
* -- pb = bytes to write
* -- fRetryOnFail
* -- return
*/
_Success_(return)
BOOL DeviceWriteMEM(_In_ QWORD qwAddr, _In_ DWORD cb, _In_reads_(cb) PBYTE pb, _In_ BOOL fRetryOnFail);

/*
* Read target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to read the memory, otherwise the memory will be read with
* standard DMA. Minimum granularity: page (4kB)
* -- qwAddr = physical address in target system to read.
* -- cb = length of data to read, must not be larger than pb.
* -- pb = pre-allocated buffer to place result in.
* -- fRetryOnFail
* -- return
*/
_Success_(return)
BOOL DeviceReadMEM(_In_ QWORD qwAddr, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb, _In_ BOOL fRetryOnFail);

/*
* LcRead with a single retry on fail.
*/
_Success_(return)
BOOL DeviceReadDMA_Retry(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _Out_writes_(cb) PBYTE pb);

/*
* LeechCore LcWrite with a single retry on fail.
*/
_Success_(return)
BOOL DeviceWriteDMA_Retry(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _In_reads_(cb) PBYTE pb);

/*
* Write to target physical memory using DMA and read back the same memory and
* thus verifying that the write was successful indeed.
* -- hLC
* -- pa
* -- cb
* -- pb
*/
_Success_(return)
BOOL DeviceWriteDMA_Verify(_In_ HANDLE hLC, _In_ QWORD pa, _In_ DWORD cb, _In_reads_(cb) PBYTE pb);

#endif /* __DEVICE_H__ */
