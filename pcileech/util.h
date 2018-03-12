// util.h : definitions of various utility functions.
//
// (c) Ulf Frisk, 2016-2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __UTIL_H__
#define __UTIL_H__
#include "pcileech.h"
#include "statistics.h"

/*
* Retrieve a page table entry (PTE). (4kB pages only).
* -- ctx
* -- qwCR3 = the contents of the CPU register CR3 (= physical address of PML4)
* -- qwAddressLinear = the virtual address for which the PTE should be retrieved
* -- pqwPTE = ptr to receive the PTE
* -- pqwPTEAddrPhysOpt = ptr to receive the physical address of the PTE
* -- return
*/
BOOL Util_PageTable_ReadPTE(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwCR3, _In_ QWORD qwAddressLinear, _Out_ PQWORD pqwPTE, _Out_ PQWORD pqwPTEAddrPhys);

/*
* Change the mode of the mapped address to executable.
* -- ctx
* -- qwCR3
* -- qwAddressLinear
* -- fSetX = TRUE if virtual address should be executable.
* -- return
*/
BOOL Util_PageTable_SetMode(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwCR3, _In_ QWORD qwAddressLinear, _In_ BOOL fSetX);

/*
* Find a module base given a page signature. Please note that this is a best
* effort search. Multiple modules may have the same signature or parts of the
* paging structures may be outside the 32-bit addressing scope >4GiB.
* -- ctx
* -- pqwCR3 = the contents of the CPU register CR3 (= physical address of PML4) (may be zero on entry if page table base should be searched as well)
* -- pPTEs = paging signature of the module to find
* -- cPTEs = number of entries in pPTEs
* -- pqwSignatureBase = ptr to receive the module base
* -- return
*/
BOOL Util_PageTable_FindSignatureBase(_Inout_ PPCILEECH_CONTEXT ctx, _Inout_ PQWORD pqwCR3, _In_ PSIGNATUREPTE pPTEs, _In_ QWORD cPTEs, _Out_ PQWORD pqwSignatureBase);

/*
* Search the page tables for a given physical address. The first occurrence for
* this address will be returned.
* -- ctx
* -- qwCR3 = the physical address of PML4.
* -- qwAddrPhys = the physical address to search for.
* -- pqwAddrVirt = ptr to receive virtual address.
* -- pqwPTE = ptr to optionally receive value of PTE
* -- pqwPDE = ptr to optionally receive value of PDE
* -- pqwPDPTE = ptr to optionally receive value of PDPTE
* -- pqwPML4E = ptr to optionally receive value of PML4E
* -- return
*/
BOOL Util_PageTable_FindMappedAddress(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwCR3, _In_ QWORD qwAddrPhys, _Out_ PQWORD pqwAddrVirt, _Out_opt_ PQWORD pqwPTE, _Out_opt_ PQWORD pqwPDE, _Out_opt_ PQWORD pqwPDPTE, _Out_opt_ PQWORD pqwPML4E);

/*
* Walk the page table to translate a virtual address into a physical.
* -- ctx
* -- qwCR3 = the physical address of PML4.
* -- qwVA = the virtual address.
* -- pqwPA = ptr to receive physical address.
* -- pqwPageBase = ptr to receive the page base of the physical address.
* -- pqwPageSize = ptr to receive size of physical page in bytes.
* -- return
*/
BOOL Util_PageTable_Virtual2Physical(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwCR3, _In_ QWORD qwVA, _Out_ PQWORD pqwPA, _Out_ PQWORD pqwPageBase, _Out_ PQWORD pqwPageSize);

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
* Retrieve the file size of the file. If the file isn't found 0 is returned.
* -- sz = file to retrieve size of.
* -- return = file size, or 0 on fail.
*/
DWORD Util_GetFileSize(_In_ LPSTR sz);

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
* This will only work for kernels prior to 4.8.
* -- paBase = memory physical offset to paSzKallsyms
* -- paSzKallsyms = physical offset (from base) to 'kallsyms_lookup_name' text string.
* -- vaSzKallsyms = virtual address of 'kallsyms_lookup_name' text string.
* -- vaFnKallsyms = virtual address of 'kallsyms_lookup_name' function.
* -- paSzFnHijack = physical offset (from base) to 'function to hijack' text string.
* -- vaSzFnHijack = virtual address text string 'of function to hijack' test string.
* -- vaFnHijack = virtual address of function to hijack.
* -- pSignature = ptr to signature struct to place the result in.
*/
VOID Util_CreateSignatureLinuxGeneric(_In_ QWORD paBase,
    _In_ DWORD paSzKallsyms, _In_ QWORD vaSzKallsyms, _In_ QWORD vaFnKallsyms,
    _In_ DWORD paSzFnHijack, _In_ QWORD vaSzFnHijack, _In_ QWORD vaFnHijack, _Out_ PSIGNATURE pSignature);
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
* Load the stage2 and stage3 code for the EFI Runtime Sertives hijack technique
* into the supplied signature.
* -- pSignature = ptr to signature struct to place the result in.
*/
VOID Util_CreateSignatureLinuxEfiRuntimeServices(_Out_ PSIGNATURE pSignature);

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
* -- ctx
* -- pbBuffer16M = the already allocated 16MB buffer to place the content in.
* -- qwBaseAddress = the base address to start reading from.
* -- pPageStat = statistics struct to update on progress (pages success/fail).
* -- return = TRUE if at least one 4k page could be read; FALSE if all pages failed.
*/
BOOL Util_Read16M(_Inout_ PPCILEECH_CONTEXT ctx, _Out_ PBYTE pbBuffer16M, _In_ QWORD qwBaseAddress, _Inout_opt_ PPAGE_STATISTICS pPageStat);

/*
* Wait for the connected PCILeech device to be power cycled. This function will
* sleep until a power cycle event is detected on the connected PCILeech device.
* The connected device needs to first be powered down and then powered up before
* this function will exit.
* -- ctx
*/
VOID Util_WaitForPowerCycle(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Wait for a PCILeech device to be powered on and for it to complete a dummy
* memory read. The pDeviceData will be initialized upon success - in which
* the function will exit.
* -- ctx
*/
VOID Util_WaitForPowerOn(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Print a maximum of 8192 bytes of binary data as hexascii on the screen.
* -- pb
* -- cb
* -- cbInitialOffset = offset, must be max 0x1000 and multiple of 0x10.
*/
VOID Util_PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset);

#endif /* __UTIL_H__ */
