// util.h : definitions of various utility functions.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __UTIL_H__
#define __UTIL_H__
#include "pcileech.h"

/*
* Retrieve a page table entry (PTE). (4kB pages only).
* -- pCfg
* -- pDeviceData
* -- qwCR3 = the contents of the CPU register CR3 (= physical address of PML4)
* -- qwAddressLinear = the virtual address for which the PTE should be retrieved
* -- pqwPTE = ptr to receive the PTE
* -- pqwPTEAddrPhysOpt = ptr to receive the physical address of the PTE (optional)
* -- return
*/
BOOL Util_PageTable_ReadPTE(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwCR3, _In_ QWORD qwAddressLinear, _Out_ PQWORD pqwPTE, _Out_opt_ PQWORD pqwPTEAddrPhysOpt);

/*
* Find a module base given a page signature. Please note that this is a best
* effort search. Multiple modules may have the same signature or parts of the
* paging structures may be outside the 32-bit addressing scope >4GiB.
* -- pCfg
* -- pDeviceData
* -- pqwCR3 = the contents of the CPU register CR3 (= physical address of PML4) (may be zero on entry if page table base should be searched as well)
* -- pPTEs = paging signature of the module to find
* -- cPTEs = number of entries in pPTEs
* -- pqwSignatureBase = ptr to receive the module base
* -- return
*/
BOOL Util_PageTable_FindSignatureBase(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Inout_ PQWORD pqwCR3, _In_ PSIGNATUREPTE pPTEs, _In_ QWORD cPTEs, _Out_ PQWORD pqwSignatureBase);

/*
* Load KMD and Unlock signatures.
* -- szSignatureName
* -- szFileExtension
* -- pSignatures = ptr to receive the signatures.
* -- cSignatures = max # of signatures referenced by pSignatures ptr.
* -- cSignatureChunks = # of chunks in signature lines to parse.
* -- return
*/
BOOL Util_LoadSignatures(_In_ LPSTR szSignatureName, _In_ LPSTR szFileExtension, _Out_ PSIGNATURE pSignatures, _In_ PDWORD cSignatures, _In_ DWORD cSignatureChunks);

/*
* Retrieve the full file path to the file name specified. Path is relative to
* directory of running executable.
* -- szPath = buffer to receive the full path result.
* -- szFileName = a file name in the current directory.
*/
VOID Util_GetFileInDirectory(_Out_ CHAR szPath[MAX_PATH], _In_ LPSTR szFileName);

/*
* Create a SHA256 hash
* -- pb = the data to hash
* -- cb = length of data to hash
* -- pbHash = 32 byte buffer to receive the SHA256 hash
*/
VOID Util_SHA256(_In_ PBYTE pb, _In_ DWORD cb, _Out_ __bcount(32) PBYTE pbHash);

/*
* Return the index+1 of the 1st character that differes between buffers.
* If buffers are equal 0 is returned.
*/
DWORD Util_memcmpEx(_In_ PBYTE pb1, _In_ PBYTE pb2, _In_ DWORD cb);

/*
* Simple random number function.
* -- pb = buffer to receive random data.
* -- cb = length of random data to create.
*/
VOID Util_GenRandom(_Out_ PBYTE pb, _In_ DWORD cb);

/*
* Load a kernel shellcode file (used in conjunction with the execshellcode cmd.
* NB! verification of the shellcode file is a bit lax - code execution within
* pcileech is probably possible - but is not considered an issue.
* -- szKmdExecName = name of module to load without file name suffix.
* -- pKmdExec = function will allocate and return a valid ptr to KMDEXEC struct
*    on success. Caller is responsible to call LocalFree.
* -- return
*/
BOOL Util_LoadKmdExecShellcode(_In_ LPSTR szKmdExecName, _Out_ PKMDEXEC* ppKmdExec);

/*
* Parse an input line consisting of either builtin, hexascii or file name to
* data buffer.
*/
BOOL Util_ParseHexFileBuiltin(_In_ LPSTR sz, _Out_ PBYTE pb, _In_ DWORD cb, _Out_ PDWORD pcb);

/*
* Parse a string returning the QWORD representing the string. The string may
* consist of a decimal or hexadecimal integer string. Hexadecimals must begin
* with 0x.
* -- sz
* -- return
*/
QWORD Util_GetNumeric(_In_ LPSTR sz);

/*
* "Create" a static signature for Linux given the supplied parameters. The
* function formats the paramerters and put them into the supplied pSignature.
* -- paBase = memory physical offset to paSzKallsyms
* -- paSzKallsyms = physical offset to 'kallsyms_looup_name' text string.
* -- vaSzKallsyms = virtual address of 'kallsyms_looup_name' text string.
* -- vaFnKallsyms = virtual address of the kallsyms_lookup_name function.
* -- vaFnHijack = virtual address of the function to hijack.
* -- pSignature = ptr to signature struct to place the result in.
*/
VOID Util_CreateSignatureLinuxGeneric(_In_ DWORD paBase, _In_ DWORD paSzKallsyms, _In_ QWORD vaSzKallsyms, _In_ QWORD vaFnKallsyms, _In_ QWORD vaFnHijack, _Out_ PSIGNATURE pSignature);

/*
* "Create" a static signature for FreeBSD given the supplied parameters. The
* function formats the paramerters and put them into the supplied pSignature.
* -- paStrTab = physical address of the strtab found.
* -- paFnHijack = physical address of the function to hijack.
* -- pSignature = ptr to signature struct to place the result in.
*/
VOID Util_CreateSignatureFreeBSDGeneric(_In_ DWORD paStrTab, _In_ DWORD paFnHijack, _Out_ PSIGNATURE pSignature);

/*
* "Create" a static signature for MacOS given the supplied parameters. The
* function formats the paramerters and put them into the supplied pSignature.
* -- paKernelBase = memory physical address of kernel macho-o header.
* -- paFunctionHook = memory physical address of the hook function.
* -- paStage2 = memory physical address where to place the stage2 shellcode.
* -- pSignature = ptr to signature struct to place the result in.
*/
VOID Util_CreateSignatureMacOSGeneric(_In_ DWORD paKernelBase, _In_ DWORD paFunctionHook, _In_ DWORD paStage2, _Out_ PSIGNATURE pSignature);


/*
* Load the stage2 and stage3 code for the Hal.dll injection technique into
* the supplied signature.
* -- pSignature = ptr to signature struct to place the result in.
*/
VOID Util_CreateSignatureWindowsHalGeneric(_Out_ PSIGNATURE pSignature);

/*
* Create a search signature that searches all memory for the signature given in
* the supplied pb and cb parameters.
* -- pb = signature.
* -- cb
* -- pSignature = ptr to signature struct to place the result in.
*/
VOID Util_CreateSignatureSearchAll(_In_ PBYTE pb, _In_ DWORD cb, _Out_ PSIGNATURE pSignature);

/*
* Read a 16MB data chunk from the target and place it in the pbBuffer16M buffer.
* Any data that failed to read within the 16MB buffer is set to zero.
* -- pCfg
* -- pDeviceData
* -- pbBuffer16M = the already allocated 16MB buffer to place the content in.
* -- qwBaseAddress = the base address to start reading from.
* -- pPageStat = statistics struct to update on progress (pages success/fail).
* -- return = TRUE if at least one 4k page could be read; FALSE if all pages failed.
*/
BOOL Util_Read16M(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _Out_ PBYTE pbBuffer16M, _In_ QWORD qwBaseAddress, _Inout_ PPAGE_STATISTICS pPageStat);

#endif /* __UTIL_H__ */