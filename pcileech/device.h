// device.h : definitions related to the hardware devices.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_H__
#define __DEVICE_H__
#include "pcileech.h"
#include "statistics.h"

#define PCILEECH_MEM_FLAG_RETRYONFAIL            0x01
#define PCILEECH_MEM_FLAG_VERIFYWRITE            0x02

/*
* Open a USB connection to the target device.
* -- result
*/
_Success_(return)
BOOL DeviceOpen();

/*
* Try read memory with DMA in a fairly optimal way considering device limits.
* The number of total successfully read bytes is returned. Failed reads will
* be zeroed out the he returned memory.
* -- qwAddr
* -- pb
* -- cb
* -- pPageStat = optional page statistics
* -- flags = PCILEECH_FLAG_MEM_EX_* flags
* -- return = the number of bytes successfully read.
*
*/
DWORD DeviceReadDMAEx(_In_ QWORD qwAddr, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _Inout_opt_ PPAGE_STATISTICS pPageStat, _In_ QWORD flags);

/*
* Write target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to write the memory, otherwise the memory will be written
* with standard DMA. Minimum granularity: byte.
* -- qwAddr = the physical address to write to in the target system.
* -- pb = bytes to write
* -- cb = number of bytes to write.
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
_Success_(return)
BOOL DeviceWriteMEM(_In_ QWORD qwAddr, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Read target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to read the memory, otherwise the memory will be read with
* standard DMA. Minimum granularity: page (4kB)
* -- qwAddr = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
_Success_(return)
BOOL DeviceReadMEM(_In_ QWORD qwAddr, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

#endif /* __DEVICE_H__ */
