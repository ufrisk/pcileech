// mempatch.h : definitions related to memory patch / operating system unlock functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MEMPATCH_H__
#define __MEMPATCH_H__
#include "pcileech.h"

/*
* Patch the memory of the target system. Alternatively search the memory of the
* target system. This includes the unlock operating system functionality.
* -- ctx
*/
VOID ActionPatchAndSearch(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __MEMPATCH_H__ */