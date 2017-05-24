// vfs.h : definitions related to virtual file system support.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VFS_H__
#define __VFS_H__
#include "pcileech.h"

/*
* Mount a drive backed by PCILeech virtual file system. The mounted file system
* will contain both a memory mapped ram files and the file system as seen from
* the target system kernel. NB! This action requires a loaded kernel module and
* that the Dokany file system library and driver have been installed. Please
* see: https://github.com/dokan-dev/dokany/releases
* -- pCfg
* -- pDeviceData
*/
VOID ActionMount(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __VFS_H__ */
