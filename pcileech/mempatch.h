// mempatch.h : definitions related to memory patch / operating system unlock functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MEMPATCH_H__
#define __MEMPATCH_H__
#include "pcileech.h"

/*
* Patch the memory of the target system. Alternatively search the memory of the
* target system. This includes the unlock operating system functionality.
* -- pCfg
* -- pDeviceData
*/
VOID ActionPatchAndSearch(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

#endif /* __MEMPATCH_H__ */