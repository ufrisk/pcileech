// device605_uart.h : definitions related to the Xilinx SP605 dev board flashed with @d_olex early access bitstream. (UART communication).
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE605_UART_H__
#define __DEVICE605_UART_H__
#include "pcileech.h"

/*
* Open a connection to the SP605/UART PCILeech flashed device.
* -- ctx
* -- result
*/
BOOL Device605_UART_Open(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __DEVICE605_UART_H__ */
