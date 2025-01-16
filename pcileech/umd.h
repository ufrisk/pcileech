// umd.c : implementation related to various user-mode functionality supported
//         by the Memory Process File System / MemProcFS / vmm.dll integration.
//
// (c) Ulf Frisk, 2020-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __UMD_H__
#define __UMD_H__
#include "pcileech.h"

/*
* List all processes in the target system memory by using the MemProcFS integration.
*/
VOID Action_UmdPsList();

/*
* Translate a virtual address into a physical address for a given process id (pid).
*/
VOID Action_UmdPsVirt2Phys();

/*
* Execute user-mode code by injecting code into a user-mode process. This
* requires integration with the Windows-only MemProcFS/'vmm.dll'.
*/
VOID ActionExecUserMode();

#endif /* __UMD_H__ */
