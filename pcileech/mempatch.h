// mempatch.h : definitions related to memory patch / operating system unlock functionality.
//
// (c) Ulf Frisk, 2016-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MEMPATCH_H__
#define __MEMPATCH_H__
#include "pcileech.h"

/*
* Patch the memory of the target system. Alternatively search the memory of the
* target system. This includes the unlock operating system functionality.
*/
VOID ActionPatchAndSearchPhysical();

/*
* Patch the virtual memory of a target system process (Windows only).
* Alternatively search the memory of the target system process.
* This includes the unlock operating system functionality.
*/
VOID ActionPatchAndSearchVirtual();

#endif /* __MEMPATCH_H__ */
