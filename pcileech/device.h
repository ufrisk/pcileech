// device.h : definitions related to the USB3380 hardware device.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_H__
#define __DEVICE_H__
#include "pcileech.h"

#define PCILEECH_MEM_FLAG_RETRYONFAIL			0x01

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
* -- qwAddr - max supported address = 0x100000000 - cb - (32-bit address space)
* -- pb
* -- cb
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceReadDMA(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Write data to the target system using DMA.
* -- pDeviceData
* -- qwAddr - max supported address = 0x100000000 - cb - (32-bit address space)
* -- pb
* -- cb
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceWriteDMA(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* First write data using DMA, then verify the data has been correctly written
* by reading the data. NB! If the running target system changes the data
* between the write and the read this call will fail.
* -- pDeviceData
* -- qwAddr - max supported address = 0x100000000 - cb - (32-bit address space)
* -- pb
* -- cb
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceWriteDMAVerify(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Write target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to read the memory, otherwise the memory will be written
* withstandard DMA. Minimum granularity: byte.
* -- pDeviceData
* -- qwAddress = the physical address to write to in the target system.
* -- pb = bytes to write
* -- cb = number of bytes to write.
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceWriteMEM(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

/*
* Read target physical memory. If an KMD is inserted in the target kernel the
* KMD will be used to read the memory, otherwise the memory will be read with
* standard DMA. Minimum granularity: page (4kB)
* -- pDeviceData
* -- qwAddress = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
* -- flags - supported flags: 0, PCILEECH_MEM_FLAG_RETRYONFAIL
* -- return
*/
BOOL DeviceReadMEM(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags);

#endif /* __DEVICE_H__ */