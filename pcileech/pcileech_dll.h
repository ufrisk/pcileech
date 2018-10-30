// pcileech_dll.h : defines related to dynamic link library (dll) functionality.
// Please use together with pcileech.dll in other projects.
// Please see pcileech_dll_example.c for integration examples.
//
// Version 3.5
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __PCILEECH_DLL_H__
#define __PCILEECH_DLL_H__
#ifdef _WINDLL

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
* Retrieve the current version of PCILeech.
* -- return = the current version of PCILeech in ascii text.
*/
LPSTR PCILeech_GetVersion();

/*
* Initialize PCILeech from a memory dump file in raw format. PCILeech will be
* initialized in read-only mode. It's possible to optionally specify the page
* table base of the windows kernel (for full vmm features) or the page table
* base of a single 64-bit process in any x64 operating system. NB! usually it
* is not necessary to specify the PageTableBase - it will be auto-identified
* most often if the target is Windows.
* -- szFileName = the file name of the raw memory dump to use.
* -- szPageTableBaseOpt = optionally the Page Table Base of kernel or process
*        as hex string. NB! this is usally not required. Example: "0x1ab000".
* -- return = success/fail.
*/
BOOL PCILeech_InitializeFromFile(_In_ LPSTR szFileName, _In_opt_ LPSTR szPageTableBaseOpt);

/*
* Intiailize PCILeech from a supported FPGA device over USB. PCIleech will be
* initialized in read/write mode upon success. Optionally it will be possible
* to specify the max physical address and the page table base of the kernel or
* process that should be investigated.
* -- szMaxPhysicalAddressOpt = max physical address of the target system as a
*        hex string. Example: "0x8000000000".
* -- szPageTableBaseOpt = optionally the Page Table Base of kernel or process
*        as hex string. NB! this is usally not required. Example: "0x1ab000".
* -- return = success/fail.
*/
BOOL PCILeech_InitializeFPGA(_In_opt_ LPSTR szMaxPhysicalAddressOpt, _In_opt_ LPSTR szPageTableBaseOpt);

/*
* Intiailize PCILeech from a the "Total Meltdown" CVE-2018-1038 vulnerability.
* initialized in read/write mode upon success.
* -- return = success/fail.
*/
BOOL PCILeech_InitializeTotalMeltdown();

/*
* Initialize PCIleech from a USB3380 device. The functionality of a USB3380
* device is limited to DMA in the 32-bit physical address space below 4GB.
* As such the USB3380 cannot be used together with the VMM functionality.
* Furthermore; if undreadable memory such as memory holes or PCIe space is to
* be read the USB3380 device will freeze and require a complete power cycle.
* Despite limitations the USB330 will work together with the functions:
* PCILeech_DeviceReadMEM and PCILeech_DeviceWriteMEM.
*/
BOOL PCILeech_InitializeUSB3380();

/*
* Shut down the PCILeech functionality and clean up allocated resources. This
* should always be called before the DLL is unloaded (unless upon process exit)
* to ensure resources are cleaned up.
*/
BOOL PCILeech_Close();

/*
* For internal use only - do not use!
*/
BOOL PCILeech_InitializeInternalReserved(_In_ DWORD argc, _In_ char* argv[]);

/*
* Device specific options used together with the PCILeech_DeviceGetOption and
* PCILeech_DeviceSetOption functions. For more detailed information check the
* sources for the individual device types.
*/
#define PCILEECH_DEVICE_OPT_FPGA_PROBE_MAXPAGES           0x01   // RW
#define PCILEECH_DEVICE_OPT_FPGA_RX_FLUSH_LIMIT           0x02   // RW
#define PCILEECH_DEVICE_OPT_FPGA_MAX_SIZE_RX              0x03   // RW
#define PCILEECH_DEVICE_OPT_FPGA_MAX_SIZE_TX              0x04   // RW
#define PCILEECH_DEVICE_OPT_FPGA_DELAY_PROBE_READ         0x05   // RW uS
#define PCILEECH_DEVICE_OPT_FPGA_DELAY_PROBE_WRITE        0x06   // RW uS
#define PCILEECH_DEVICE_OPT_FPGA_DELAY_WRITE              0x07   // RW uS
#define PCILEECH_DEVICE_OPT_FPGA_DELAY_READ               0x08   // RW uS
#define PCILEECH_DEVICE_OPT_FPGA_RETRY_ON_ERROR           0x09   // RW
#define PCILEECH_DEVICE_OPT_FPGA_DEVICE_ID                0x80   // R
#define PCILEECH_DEVICE_OPT_FPGA_FPGA_ID                  0x81   // R
#define PCILEECH_DEVICE_OPT_FPGA_VERSION_MAJOR            0x82   // R
#define PCILEECH_DEVICE_OPT_FPGA_VERSION_MINOR            0x83   // R

#define PCILEECH_DEVICE_CORE_PRINTF_ENABLE          0x80000001   // RW
#define PCILEECH_DEVICE_CORE_VERBOSE                0x80000002   // RW
#define PCILEECH_DEVICE_CORE_VERBOSE_EXTRA          0x80000003   // RW
#define PCILEECH_DEVICE_CORE_VERBOSE_EXTRA_TLP      0x80000004   // RW
#define PCILEECH_DEVICE_CORE_MAX_NATIVE_ADDRESS     0x80000005   // R
#define PCILEECH_DEVICE_CORE_MAX_NATIVE_IOSIZE      0x80000006   // R

/*
* Set a device specific option value. Please see defines PCILEECH_DEVICE_OPT_*
* for information about valid option values. Please note that option values
* may overlap between different device types with different meanings.
* -- fOption
* -- pqwValue = pointer to ULONG64 to receive option value.
* -- return = success/fail.
*/
BOOL PCIleech_DeviceConfigGet(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);

/*
* Set a device specific option value. Please see defines PCILEECH_DEVICE_OPT_*
* for information about valid option values. Please note that option values
* may overlap between different device types with different meanings.
* -- fOption
* -- qwValue
* -- return = success/fail.
*/
BOOL PCILeech_DeviceConfigSet(_In_ ULONG64 fOption, _In_ ULONG64 qwValue);

/*
* Write target physical memory. Minimum granularity: byte.
* -- qwAddr = the physical address to write to in the target system.
* -- pb = bytes to write
* -- cb = number of bytes to write.
* -- return = success/fail.
*/
BOOL PCILeech_DeviceWriteMEM(_In_ ULONG64 qwAddr, _In_ PBYTE pb, _In_ DWORD cb);

/*
* Read target physical memory. Minimum granularity: page (4kB).
* -- qwAddr = physical address in target system to read.
* -- pb = pre-allocated buffer to place result in.
* -- cb = length of data to read, must not be larger than pb.
* -- return = success/fail.
*/
BOOL PCILeech_DeviceReadMEM(_In_ ULONG64 qwAddr, _Out_ PBYTE pb, _In_ DWORD cb);

typedef struct tdPCILEECH_MEM_IO_SCATTER_HEADER {
	ULONG64 qwA;            // base address (DWORD boundry).
	DWORD cbMax;            // bytes to read (DWORD boundry, max 0x1000); pbResult must have room for this.
	DWORD cb;               // bytes read into result buffer.
    PBYTE pb;               // ptr to 0x1000 sized buffer to receive read bytes.
	PVOID pvReserved1;      // reserved for use by caller.
	PVOID pvReserved2;      // reserved for use by caller.
    struct {
        PVOID pvReserved1;
        PVOID pvReserved2;
        BYTE pbReserved[32];
    } sReserved;            // reserved for future use.
} PCILEECH_MEM_IO_SCATTER_HEADER, *PPCILEECH_MEM_IO_SCATTER_HEADER, **PPPCILEECH_MEM_IO_SCATTER_HEADER;

/*
* Read memory in various non-contigious locations specified by the pointers to
* the items in the ppDMAs array. Result for each unit of work will be given
* individually. No upper limit of number of items to read, but no performance
* boost will be given if above hardware limit. Max size of each unit of work is
* one 4k page (4096 bytes).
* -- ppMEMs = array of scatter read headers.
* -- cpMEMs = count of ppDMAs.
* -- pcpDMAsRead = optional count of number of successfully read ppDMAs.
* -- return = the number of successfully read items.
*/
DWORD PCILeech_DeviceReadScatterMEM(_Inout_ PPPCILEECH_MEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs);

/*
* Initialize the Virtual Memory Manager (VMM). This will try to auto-identify
* the operating system, parse and enumerate its processes in order to make it
* available through the PCILeech_VMM* functions.
* If auto-identifying of a Windows sytem fails please try initialize PCILeech
* with the address of the kernel page table in the szPageTableBaseOpt parameter
* in a call to the PCIleech_Initialize* functions. The page table base may be
* obtained (sometimes) from pcileech.exe by running the identify command.
* -- return = success/fail.
*/
BOOL PCILeech_VmmInitialize();

/*
* Close the Virtual Memory Manager (VMM) and clean up resources. This must be
* done before PCILeech_VmmInitialize() is called again. This is not necessary
* if PCILeech is completely closed by a call to PCILeech_Close() - which will
* take care of all necessary cleanup activitities.
*/
BOOL PCILeech_VmmClose();

#define PCILEECH_VMM_CONFIG_IS_REFRESH_ENABLED          1   // read-only, 1/0
#define PCILEECH_VMM_CONFIG_TICK_PERIOD                 2   // read-write, base tick period in ms
#define PCILEECH_VMM_CONFIG_READCACHE_TICKS             3   // read-write, memory cache validity period (in ticks)
#define PCILEECH_VMM_CONFIG_TLBCACHE_TICKS              4   // read-write, page table (tlb) cache validity period (in ticks)
#define PCILEECH_VMM_CONFIG_PROCCACHE_TICKS_PARTIAL     5   // read-write, process refresh (partial) period (in ticks)
#define PCILEECH_VMM_CONFIG_PROCCACHE_TICKS_TOTAL       6   // read-write, process refresh (full) period (in ticks)

/*
* Retrieve a configuration value from the PCILeech DLL.
* -- dwConfigOption = configuration option as specified by PCILEECH_VMM_CONFIG*
* -- pdwConfigValue = pointer to DWORD that will receive configuration value.
* -- return = success/fail.
*/
BOOL PCILeech_VmmConfigGet(_In_ DWORD dwConfigOption, _Out_ PDWORD pdwConfigValue);

/*
* Set a configuration value in the PCILeech DLL. Note that not all values are
* possible to set - some are read-only. Setting a read-only value will result
* in fuction returning failure.
* -- dwConfigOption = configuration option as specified by PCILEECH_VMM_CONFIG*
* -- dwConfigValue = configuration value to set.
* -- return = success/fail.
*/
BOOL PCILeech_VmmConfigSet(_In_ DWORD dwConfigOption, _In_ DWORD dwConfigValue);

// FLAG used to supress the default read cache in calls to PCILeech_VmmReadEx()
// which will lead to the read being fetched from the target system always.
// Cached page tables (used for translating virtual2physical) are still used.
#define VMM_FLAG_NOCACHE                0x0001

/*
* Read a single 4096-byte page of virtual memory.
* -- dwPID
* -- qwVA
* -- pbPage
* -- return = success/fail (depending if all requested bytes are read or not).
*/
BOOL PCILeech_VmmReadPage(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_bytecount_(4096) PBYTE pbPage);

/*
* Read a virtually contigious arbitrary amount of memory.
* -- dwPID
* -- qwVA
* -- pb
* -- cb
* -- return = success/fail (depending if all requested bytes are read or not).
*/
BOOL PCILeech_VmmRead(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Read a virtually contigious amount of memory and report the number of bytes
* read in pcbRead.
* -- dwPID
* -- qwVA
* -- pb
* -- cb
* -- pcbRead
* -- flags = flags as in VMM_FLAG_*
* -- return = success/fail. NB! reads may report as success even if 0 bytes are
*        read - it's recommended to verify pcbReadOpt parameter.
*/
BOOL PCILeech_VmmReadEx(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Inout_ PBYTE pb, _In_ DWORD cb, _Out_opt_ PDWORD pcbReadOpt, _In_ ULONG64 flags);

/*
* Write a virtually contigious arbitrary amount of memory. Please note some
* virtual memory - such as pages of executables (such as DLLs) may be shared
* between different virtual memory over different processes. As an example a
* write to kernel32.dll in one process is likely to affect kernel32 in the
* whole system - in all processes. Heaps and Stacks and other memory are
* usually safe to write to. Please take care when writing to memory!
* -- dwPID
* -- qwVA
* -- pb
* -- cb
* -- return = TRUE on success, FALSE on partial or zero write.
*/
BOOL PCILeech_VmmWrite(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PBYTE pb, _In_ DWORD cb);

/*
* Translate a virtual address to a physical address by walking the page tables
* of the specified process.
* -- dwPID
* -- qwVA
* -- pqwPA
* -- return = success/fail.
*/
BOOL PCILeech_VmmVirt2Phys(_In_ DWORD dwPID, _In_ ULONG64 qwVA, _Out_ PULONG64 pqwPA);

// flags to check for existence in the fPage field of PCILEECH_VMM_MEMMAP_ENTRY
#define PCIEECH_VMM_MEMMAP_FLAG_PAGE_W          0x0000000000000002
#define PCIEECH_VMM_MEMMAP_FLAG_PAGE_NS         0x0000000000000004
#define PCIEECH_VMM_MEMMAP_FLAG_PAGE_NX         0x8000000000000000
#define PCIEECH_VMM_MEMMAP_FLAG_PAGE_MASK       0x8000000000000006

typedef struct tdPCILEECH_VMM_MEMMAP_ENTRY {
    ULONG64 AddrBase;
    ULONG64 cPages;
    ULONG64 fPage;
    BOOL  fWoW64;
    CHAR  szName[32];
} PCILEECH_VMM_MEMMAP_ENTRY, *PPCILEECH_VMM_MEMMAP_ENTRY;

/*
* Retrieve memory map entries from the specified process. Memory map entries
* are copied into the user supplied buffer that must be at least of size:
* sizeof(PCILEECH_VMM_MEMMAP_ENTRY)*pcMemMapEntries bytes.
* If the pMemMapEntries is set to NULL the number of memory map entries will be
* given in the pcMemMapEntries parameter.
* -- dwPID
* -- pMemMapEntries = buffer of minimum length sizeof(PCILEECH_VMM_MEMMAP_ENTRY)*pcMemMapEntries, or NULL.
* -- pcMemMapEntries = pointer to number of memory map entries.
* -- fIdentifyModules = try identify modules as well (= slower)
* -- return = success/fail.
*/
BOOL PCILeech_VmmProcessGetMemoryMap(_In_ DWORD dwPID, _Out_ PPCILEECH_VMM_MEMMAP_ENTRY pMemMapEntries, _Inout_ PULONG64 pcMemMapEntries, _In_ BOOL fIdentifyModules);

typedef struct tdPCILEECH_VMM_MODULEMAP_ENTRY {
    ULONG64 BaseAddress;
    ULONG64 EntryPoint;
    DWORD SizeOfImage;
    BOOL  fWoW64;
    CHAR  szName[32];
} PCILEECH_VMM_MODULEMAP_ENTRY, *PPCILEECH_VMM_MODULEMAP_ENTRY;

/*
* Retrieve the module entries from the specified process. The module entries
* are copied into the user supplied buffer that must be at least of size:
* sizeof(PCILEECH_VMM_MODULEMAP_ENTRY)*pcModuleEntries bytes long. If the
* pcModuleEntries is set to NULL the number of module entries will be given
* in the pcModuleEntries parameter.
* -- dwPID
* -- pModuleEntries = buffer of minimum length sizeof(PCILEECH_VMM_MODULEMAP_ENTRY)*pcModuleEntries, or NULL.
* -- pcModuleEntries = pointer to number of memory map entries.
* -- return = success/fail.
*/
BOOL PCILeech_VmmProcessGetModuleMap(_In_ DWORD dwPID, _Out_ PPCILEECH_VMM_MODULEMAP_ENTRY pModuleEntries, _Inout_ PULONG64 pcModuleEntries);

/*
* Retrieve a module (.exe or .dll or similar) given a module name.
* -- dwPID
* -- szModuleName
* -- pModuleEntry
* -- return = success/fail.
*/
BOOL PCILeech_VmmProcessGetModuleFromName(_In_ DWORD dwPID, _In_ LPSTR szModuleName, _Out_ PPCILEECH_VMM_MODULEMAP_ENTRY pModuleEntry);

/*
* Retrieve an active process given it's name. Please note that if multiple
* processes with the same name exists only one will be returned. If required to
* parse all processes with the same name please iterate over the PID list by
* calling PCILeech_VmmProcessListPIDs together with PCIleech_VmmProcessInfo.
* -- szProcName = process name (truncated max 15 chars) case insensitive.
* -- pdwPID = pointer that will receive PID on success.
* -- return
*/
BOOL PCILeech_VmmProcessGetFromName(_In_ LPSTR szProcName, _Out_ PDWORD pdwPID);

/*
* List the PIDs in the system.
* -- pPIDs = DWORD array of at least number of PIDs in system, or NULL.
* -- pcPIDs = size of (in number of DWORDs) pPIDs array on entry, number of PIDs in system on exit.
* -- return = success/fail.
*/
BOOL PCILeech_VmmProcessListPIDs(_Out_ PDWORD pPIDs, _Inout_ PULONG64 pcPIDs);

/*
* Retrieve various process information from a PID. Process information such as
* name, page directory bases and the process state may be retrieved. Parameters,
* except for dwPID are optional.
* -- dwPID
* -- szNameOpt
* -- pqwPageDirectoryBaseOpt
* -- pqwPageDirectoryBaseUserOpt
* -- pdwStateOpt
* -- return = success/fail.
*/
BOOL PCIleech_VmmProcessInfo(_In_ DWORD dwPID, _Out_opt_ CHAR szNameOpt[16], _Out_opt_ PULONG64 pqwPageDirectoryBaseOpt, _Out_opt_ PULONG64 pqwPageDirectoryBaseUserOpt, _Out_opt_ PDWORD pdwStateOpt);

typedef struct tdPCILEECH_VMM_EAT_ENTRY {
    DWORD vaFunctionOffset;
    CHAR szFunction[40];
} PCILEECH_VMM_EAT_ENTRY, *PPCILEECH_VMM_EAT_ENTRY;

typedef struct tdPCILEECH_VMM_IAT_ENTRY {
    ULONG64 vaFunction;
    CHAR szFunction[40];
    CHAR szModule[64];
} PCILEECH_VMM_IAT_ENTRY, *PPCILEECH_VMM_IAT_ENTRY;

/*
* Retrieve information about: Data Directories, Sections, Export Address Table
* and Import Address Table (IAT).
* If the pData == NULL upon entry the number of entries of the pData array must
* have in order to be able to hold the data is returned.
* -- dwPID
* -- szModule
* -- pData
* -- cData
* -- pcData
* -- return = success/fail.
*/
BOOL PCIleech_VmmProcess_GetDirectories(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_ PIMAGE_DATA_DIRECTORY pData, _In_ DWORD cData, _Out_ PDWORD pcData);
BOOL PCIleech_VmmProcess_GetSections(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_ PIMAGE_SECTION_HEADER pData, _In_ DWORD cData, _Out_ PDWORD pcData);
BOOL PCIleech_VmmProcess_GetEAT(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_ PPCILEECH_VMM_EAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData);
BOOL PCIleech_VmmProcess_GetIAT(_In_ DWORD dwPID, _In_ LPSTR szModule, _Out_ PPCILEECH_VMM_IAT_ENTRY pData, _In_ DWORD cData, _Out_ PDWORD pcData);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _WINDLL */
#endif /* __PCILEECH_DLL_H__ */
