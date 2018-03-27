// devicetmd.h : definitions related to the "total meltdown" memory acquisition "device".
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICE_TMD_H__
#define __DEVICE_TMD_H__
#include "pcileech.h"

/*
* Open a connection to the "total meltdown" memory acquisition "device" (if exploitable).
* -- ctx
* -- result
*/
BOOL DeviceTMD_Open(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __DEVICE_TMD_H__ */
