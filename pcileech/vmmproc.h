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
* Load the size of the required display buffer for sections, imports and export
* into the pModule struct. The size is a direct consequence of the number of
* functions since fixed line sizes are used for all these types. Loading is
* done in a recource efficient way to minimize I/O as much as possible.
* -- ctxVmm
* -- pProcess
* -- pModule
*/
VOID VmmProcWindows_PE_SetSizeSectionIATEAT_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule);

/*
* Set up the export address table display buffer and cache it into the pProcess
* Any previously cached EAT display buffer will be discarded.
* -- ctxVmm
* -- pProcess
* -- pModule
*/
VOID VmmProcWindows_PE_LoadEAT_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule);

/*
* Set up the import address table display buffer and cache it into the pProcess
* Any previously cached IAT display buffer will be discarded.
* -- ctxVmm
* -- pProcess
* -- pModule
*/
VOID VmmProcWindows_PE_LoadIAT_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule);

/*
* Fill the pbDisplayBuffer with a human readable version of the data directories.
* This is guaranteed to be exactly 864 bytes (excluding NULL terminator).
* -- ctxVmm
* -- pProcess
* -- pModule
* -- pbDisplayBuffer
* -- cbDisplayBufferMax
* -- pcbDisplayBuffer
*/
VOID VmmProcWindows_PE_DIRECTORY_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PBYTE pbDisplayBuffer, _In_ DWORD cbDisplayBufferMax, _Out_ PDWORD pcbDisplayBuffer);

/*
* Fill the pbDisplayBuffer with a human readable version of the PE sections.
* -- ctxVmm
* -- pProcess
* -- pModule
* -- pbDisplayBuffer
* -- cbDisplayBufferMax
* -- pcbDisplayBuffer
*/
VOID VmmProcWindows_PE_SECTION_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_ PBYTE pbDisplayBuffer, _In_ DWORD cbDisplayBufferMax, _Out_ PDWORD pcbDisplayBuffer);

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
