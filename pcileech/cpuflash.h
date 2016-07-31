// cpuflash.h : definitions related to 8051 CPU and EEPROM flashing.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __CPUFLASH_H__
#define __CPUFLASH_H__
#include "pcileech.h"

/*
* Flash a new firmware into the onboard memory of the USB3380 card.
* This may be dangerious and the device may stop working after a reflash!
* -- pCfg = The configuration data containing the flash image filename.
* -- pDeviceData
*/
VOID ActionFlash(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

/*
* Load a program into the 8051 CPU and start executing it.
* -- pCfg = The configuration data containing the program image filename.
* -- pDeviceData
*/
VOID Action8051Start(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

/*
* Stop the onboard 8051 CPU if its running.
* -- pCfg
* -- pDeviceData
*/
VOID Action8051Stop(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

#endif /* __CPUFLASH_H__ */