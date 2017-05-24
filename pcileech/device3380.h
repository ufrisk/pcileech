// device3380.h : definitions related to the USB3380 hardware device.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE3380_H__
#define __DEVICE3380_H__
#include "pcileech.h"

/*
* Open a connection to the USB3380 PCILeech flashed device.
* -- ctx
* -- result
*/
BOOL Device3380_Open(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Clean up various device related stuff and deallocate memory buffers.
* -- ctx
*/
VOID Device3380_Close(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Read data from the target system using DMA.
* -- ctx
* -- qwAddr - max supported address = 0x100000000 - cb - (32-bit address space)
* -- pb
* -- cb
* -- return
*/
BOOL Device3380_ReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Write data to the target system using DMA.
* -- ctx
* -- qwAddr - max supported address = 0x100000000 - cb - (32-bit address space)
* -- pb
* -- cb
* -- return
*/
BOOL Device3380_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Flash a new firmware into the onboard memory of the USB3380 card.
* This may be dangerious and the device may stop working after a reflash!
* -- ctx
*/
VOID Action_Device3380_Flash(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Load a program into the 8051 CPU and start executing it.
* -- ctx
*/
VOID Action_Device3380_8051Start(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Stop the onboard 8051 CPU if its running.
* -- ctx
*/
VOID Action_Device3380_8051Stop(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __DEVICE3380_H__ */
