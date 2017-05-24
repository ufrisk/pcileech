// device605.h : definitions related to the Xilinx SP605 dev board flashed with @d_olex early access bitstream. (UART communication).
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE605_H__
#define __DEVICE605_H__
#include "pcileech.h"

/*
* Open a connection to the SP605 PCILeech flashed device.
* -- ctx
* -- result
*/
BOOL Device605_Open(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Clean up various device related stuff and deallocate memory buffers.
* -- ctx
*/
VOID Device605_Close(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Read data from the target system using DMA.
* -- ctx
* -- qwAddr
* -- pb
* -- cb
* -- return
*/
BOOL Device605_ReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Write data to the target system using DMA.
* -- ctx
* -- qwAddr
* -- pb
* -- cb
* -- return
*/
BOOL Device605_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Transmit a raw PCIe TLP.
* -- ctx
*/
VOID Action_Device605_TlpTx(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __DEVICE605_H__ */
