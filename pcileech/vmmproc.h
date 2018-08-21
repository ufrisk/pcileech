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

typedef struct tdVMMPROC_WINDOWS_EAT_ENTRY {
    DWORD vaFunctionOffset;
    CHAR szFunction[40];
} VMMPROC_WINDOWS_EAT_ENTRY, *PVMMPROC_WINDOWS_EAT_ENTRY;

typedef struct tdVMMPROC_WINDOWS_IAT_ENTRY {
    ULONG64 vaFunction;
    CHAR szFunction[40];
    CHAR szModule[64];
} VMMPROC_WINDOWS_IAT_ENTRY, *PVMMPROC_WINDOWS_IAT_ENTRY;

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
* Alternatively fill the pEATs with all the EATs.
* -- ctxVmm
* -- pProcess
* -- pModule
* -- fLoadDisplayBuffer
* -- pEATs
* -- cEATs
*/
VOID VmmProcWindows_PE_LoadEAT_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_ BOOL fLoadDisplayBuffer, _Out_opt_ PVMMPROC_WINDOWS_EAT_ENTRY pEATs, _In_opt_ DWORD cEATs);

/*
* Set up the import address table display buffer and cache it into the pProcess
* Any previously cached IAT display buffer will be discarded.
* Alternatively fill the IEATs with all the IATs.
* -- ctxVmm
* -- pProcess
* -- pModule
* -- fLoadDisplayBuffer
* -- pIATs
* -- cIATs
*/
VOID VmmProcWindows_PE_LoadIAT_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _Inout_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_ BOOL fLoadDisplayBuffer, _Out_opt_ PVMMPROC_WINDOWS_IAT_ENTRY pIATs, _In_opt_ DWORD cIATs);

/*
* Fill the pbDisplayBuffer with a human readable version of the data directories.
* This is guaranteed to be exactly 864 bytes (excluding NULL terminator).
* Alternatively copy the 16 data directories into pDataDirectoryOpt.
* -- ctxVmm
* -- pProcess
* -- pModule
* -- pbDisplayBufferOpt
* -- cbDisplayBufferMax
* -- pcbDisplayBuffer
* -- pDataDirectoryOpt
*/
VOID VmmProcWindows_PE_DIRECTORY_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_ PDWORD pcbDisplayBuffer, _Out_opt_ PIMAGE_DATA_DIRECTORY pDataDirectoryOpt);

/*
* Fill the pbDisplayBuffer with a human readable version of the PE sections.
* Alternatively copy the sections into the pSectionsOpt buffer.
* -- ctxVmm
* -- pProcess
* -- pModule
* -- pbDisplayBufferOpt
* -- cbDisplayBufferMax
* -- pcbDisplayBuffer
* -- pSectionsOpt
*/
VOID VmmProcWindows_PE_SECTION_DisplayBuffer(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _In_ PVMM_MODULEMAP_ENTRY pModule, _Out_opt_ PBYTE pbDisplayBufferOpt, _In_ DWORD cbDisplayBufferMax, _Out_ PDWORD pcbDisplayBuffer, _Out_opt_ PIMAGE_SECTION_HEADER pSectionsOpt);

/*
* Retrieve the number of: sections, EAT entries or IAT entries depending on the
* function that is called.
* -- ctxVmm
* -- pProcess
* -- pModule
* -- pbModuleHeaderOpt = optional PIMAGE_NT_HEADERS structure (either 32 or 64-bit)
* -- fHdr32 = specified whether pbModuleHeaderOpt is a 32-bit or 64-bit header. 
* -- return = the number of entries
*/
WORD  VmmProcWindows_PE_GetNumberOfSection(_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32);
DWORD VmmProcWindows_PE_GetNumberOfEAT    (_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32);
DWORD VmmProcWindows_PE_GetNumberOfIAT    (_Inout_ PVMM_CONTEXT ctxVmm, _In_ PVMM_PROCESS pProcess, _Inout_ PVMM_MODULEMAP_ENTRY pModule, _In_opt_ PIMAGE_NT_HEADERS pbModuleHeaderOpt, _In_opt_ BOOL fHdr32);

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
