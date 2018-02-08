// devicefpga.h : definitions related to the:
//     - Xilinx SP605 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - Xilinx AC701 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - PCIeScreamer board flashed with PCILeech bitstream.
//
// (c) Ulf Frisk, 2017-2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICEFPGA_H__
#define __DEVICEFPGA_H__
#include "pcileech.h"

/*
* Open a connection to the PCILeech flashed FPGA device.
* -- ctx
* -- result
*/
BOOL DeviceFPGA_Open(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __DEVICEFPGA_H__ */
