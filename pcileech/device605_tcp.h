// device605_tcp.h : definitions related to the Xilinx SP605 dev board flashed with @d_olex bitstream.
//
// (c) Ulf Frisk & @d_olex, 2017
//
#ifndef __DEVICE605_TCP_H__
#define __DEVICE605_TCP_H__
#include "pcileech.h"

/*
* Open a connection to the SP605/MicroBlaze PCILeech flashed device.
* -- ctx
* -- result
*/
BOOL Device605_TCP_Open(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __DEVICE605_TCP_H__ */
