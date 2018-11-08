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

/*
* Device specific options - to be used together with the device GetOption and
* SetOption functions. For more detailed information please check sources for
* devicefpga.c
*/
#define DEVICE_OPT_FPGA_PROBE_MAXPAGES         0x01   // RW
#define DEVICE_OPT_FPGA_RX_FLUSH_LIMIT         0x02   // RW
#define DEVICE_OPT_FPGA_MAX_SIZE_RX            0x03   // RW
#define DEVICE_OPT_FPGA_MAX_SIZE_TX            0x04   // RW
#define DEVICE_OPT_FPGA_DELAY_PROBE_READ       0x05   // RW uS
#define DEVICE_OPT_FPGA_DELAY_PROBE_WRITE      0x06   // RW uS
#define DEVICE_OPT_FPGA_DELAY_WRITE            0x07   // RW uS
#define DEVICE_OPT_FPGA_DELAY_READ             0x08   // RW uS
#define DEVICE_OPT_FPGA_RETRY_ON_ERROR         0x09   // RW
#define DEVICE_OPT_FPGA_DEVICE_ID              0x80   // R
#define DEVICE_OPT_FPGA_FPGA_ID                0x81   // R
#define DEVICE_OPT_FPGA_VERSION_MAJOR          0x82   // R
#define DEVICE_OPT_FPGA_VERSION_MINOR          0x83   // R

#endif /* __DEVICEFPGA_H__ */
