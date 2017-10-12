// device605_601.h : definitions related to the Xilinx SP605 dev board flashed with bitstream for FTDI UMFT601X-B addon-board.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE605_601_H__
#define __DEVICE605_601_H__
#include "pcileech.h"

/*
* Open a connection to the SP605/FT601 PCILeech flashed device.
* -- ctx
* -- result
*/
BOOL Device605_601_Open(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __DEVICE605_601_H__ */
