// vmmproc.h : definitions related to operating system and process parsing of virtual memory
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __VMMPROC_H__
#define __VMMPROC_H__
#include "pcileech.h"
#include "vmm.h"

#ifdef WIN32

/*
* Load operating system dependant module names, such as parsed from PE or ELF
* into the proper display caches, and also into the memory map.
*/
VmmProc_InitializeModuleNames(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess);

/*
* Tries to automatically identify the operating system given by the supplied
* memory device (fpga hardware or file). If an operating system is successfully
* identified a VMM_CONTEXT will be created and stored within the PCILEECH_CONTEXT.
* If the VMM fails to identify an operating system FALSE is returned.
* -- ctx
* -- return
*/
BOOL VmmProcInitialize(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* WIN32 */

/*
* Scans the memory for supported operating system structures, such as Windows
* page directory bases and reports them if found.
* -- ctx
*/
VOID ActionIdentify(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __VMMPROC_H__ */
