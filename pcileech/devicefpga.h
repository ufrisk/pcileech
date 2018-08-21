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
#define DEVICE_OPT_FPGA_PROBE_MAXPAGES          1   // RW
#define DEVICE_OPT_FPGA_RX_FLUSH_LIMIT          2   // RW
#define DEVICE_OPT_FPGA_MAX_SIZE_RX             3   // RW
#define DEVICE_OPT_FPGA_MAX_SIZE_TX             4   // RW
#define DEVICE_OPT_FPGA_DELAY_PROBE_READ        5   // RW uS
#define DEVICE_OPT_FPGA_DELAY_PROBE_WRITE       6   // RW uS
#define DEVICE_OPT_FPGA_DELAY_WRITE             7   // RW uS
#define DEVICE_OPT_FPGA_DELAY_READ              8   // RW uS
#define DEVICE_OPT_FPGA_RETRY_ON_ERROR          9   // RW
#define DEVICE_OPT_FPGA_DEVICE_ID              80   // R
#define DEVICE_OPT_FPGA_FPGA_ID                81   // R
#define DEVICE_OPT_FPGA_VERSION_MAJOR          82   // R
#define DEVICE_OPT_FPGA_VERSION_MINOR          83   // R

#endif /* __DEVICEFPGA_H__ */
