// device.h : definitions related to the USB3380 hardware device.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_H__
#define __DEVICE_H__
#include "pcileech.h"

#define CSR_BYTE0							0x01
#define CSR_BYTE1							0x02
#define CSR_BYTE2							0x04
#define CSR_BYTE3							0x08
#define CSR_BYTEALL							0x0f
#define CSR_CONFIGSPACE_PCIE				0x00
#define CSR_CONFIGSPACE_MEMM				0x10
#define CSR_CONFIGSPACE_8051				0x20
#define REG_DMACTL_0						0x180
#define REG_DMASTAT_0						0x184
#define REG_DMACOUNT_0						0x190
#define REG_DMAADDR_0						0x194
#define REG_FIFOSTAT_0						0x32c
#define REG_DMACTL_1						0x1a0
#define REG_DMASTAT_1						0x1a4
#define REG_DMACOUNT_1						0x1b0
#define REG_DMAADDR_1						0x1b4
#define REG_DMACTL_2						0x1c0
#define REG_DMASTAT_2						0x1c4
#define REG_DMACOUNT_2						0x1d0
#define REG_DMAADDR_2						0x1d4
#define REG_DMACTL_3						0x1e0
#define REG_DMASTAT_3						0x1e4
#define REG_DMACOUNT_3						0x1f0
#define REG_DMAADDR_3						0x1f4
#define REGPCI_STATCMD						0x04
#define DEVICE_READ_DMA_FLAG_CONTINUE		1

/*
* Open a USB connection to the target USB3380 device.
* -- pDeviceData = ptr to DeviceData to receive values on success.
* -- result
*/
BOOL DeviceOpen(_In_ PCONFIG pCfg, _Out_ PDEVICE_DATA pDeviceData);

/*
* Clean up various device related stuff and deallocate some meoory buffers.
* -- pDeviceData
*/
VOID DeviceClose(_Inout_ PDEVICE_DATA pDeviceData);

/*
* Flash a new firmware into the onboard memory of the USB3380 card.
* This may be dangerious and the device may stop working after a reflash!
* -- pDeviceData
* -- pbEEPROM = EEPROM data to flash.
* -- cbEEPROM = length of EEPROM data to flash.
* -- return
*/
BOOL DeviceFlashEEPROM(_In_ PDEVICE_DATA pDeviceData, _In_ PBYTE pbEEPROM, _In_ DWORD cbEEPROM);

/*
* Load a program into the 8051 CPU and start executing it.
* -- pDeviceData
* -- pbProgram8051 = the 8051 binary to execute.
* -- cbProgram8051 = the length of the 8051 binary to execute.
* -- return
*/
BOOL Device8051Start(_In_ PDEVICE_DATA pDeviceData, _In_ PBYTE pbProgram8051, _In_ DWORD cbProgram8051);

/*
* Stop the onboard 8051 CPU if its running.
* -- pDeviceData
*/
VOID Device8051Stop(_In_ PDEVICE_DATA pDeviceData);

/*
* Read data from the target system using DMA.
* -- pDeviceData
* -- dwAddrPci32
* -- pb
* -- cb
* -- return
*/
BOOL DeviceReadDMA(_In_ PDEVICE_DATA pDeviceData, _In_ DWORD dwAddrPci32, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Exactly the same as DeviceReadDMA except that if the call fail another
* attempt will be performed.
* -- pDeviceData
* -- dwAddrPci32
* -- pb
* -- cb
* -- return
*/
BOOL DeviceReadDMARetryOnFail(_In_ PDEVICE_DATA pDeviceData, _In_ DWORD dwAddrPci32, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Write data to the target system using DMA.
* -- pDeviceData
* -- dwAddrPci32
* -- pb
* -- cb
* -- return
*/
BOOL DeviceWriteDMA(_In_ PDEVICE_DATA pDeviceData, _In_ DWORD dwAddrPci32, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Exactly the same as DeviceWriteDMA except that if the call fail another
* attempt will be performed.
* -- pDeviceData
* -- dwAddrPci32
* -- pb
* -- cb
* -- return
*/
BOOL DeviceWriteDMA_Retry(_In_ PDEVICE_DATA pDeviceData, _In_ DWORD dwAddrPci32, _In_ PBYTE pb, _In_ DWORD cb);

/*
* First write data using DMA, then verify the data has been correctly written
* by reading the data. NB! If the running target system changes the data
* between the write and the read this call will fail.
* -- pDeviceData
* -- dwAddrPci32
* -- pb
* -- cb
* -- return
*/
BOOL DeviceWriteDMAVerify(_In_ PDEVICE_DATA pDeviceData, _In_ DWORD dwAddrPci32, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Write target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to read the memory, otherwise the memory will be written
* withstandard DMA. Minimum granularity: byte.
* -- pDeviceData
* -- qwAddress = the physical address to write to in the target system.
* -- pb = bytes to write
* -- cb = number of bytes to write.
* -- return TRUE on success, otherwise FALSE.
*/
BOOL DeviceWriteMEM(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Read target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to read the memory, otherwise the memory will be read with
* standard DMA. Minimum granularity: page (4kB)
* -- pDeviceData
* -- qwAddress = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
*/
BOOL DeviceReadMEM(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb);

#endif /* __DEVICE_H__ */