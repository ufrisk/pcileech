// vmmx.h : definitions related to external memory process file system functionality.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMX_H__
#define __VMMX_H__
#include <vmmdll.h>
#include "pcileech.h"
#include "oscompatibility.h"

/*
* Load the memory process file system mode using the default LeechCore device.
* The memory process file system is initialized in either updating mode if the
* fRefresh flag is set and the LeechCore memory is volatile; otherwise it's
* started in non-updating mode.
* -- fRefresh
* -- fMemMapAuto
* -- return
*/
_Success_(return)
BOOL Vmmx_Initialize(_In_ BOOL fRefresh, _In_ BOOL fMemMapAuto);

/*
* Close an open MemProcFS instance.
*/
VOID Vmmx_Close();

#endif /* __VMMX_H__ */
