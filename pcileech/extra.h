// extra.h : definitions related to various extra functionality such as exploits.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __EXTRA_H__
#define __EXTRA_H__
#include "pcileech.h"
#include "kmd.h"

/*
* Recover the Filevault 2 password on locked macOS systems prior or equal to 10.12.2
* -- pCfg
* -- pDeviceData
*/
VOID Action_MacFilevaultRecover(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

#endif /* __EXTRA_H__ */
