// pcileech_dll_example.c - PCILeech DLL API usage examples
//
// Note that this is not a complete list of the PCILeech API. For the complete
// list please consult the pcileech_dll.h header file.
//
// Please also note that the pre-compiled version of pcileech.dll is compiled
// for 64-bit (x64). 32-bit (x86) is not officially supported.
//
// (c) Ulf Frisk, 2017-2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#define _WINDLL
#include "pcileech_dll.h"

#pragma comment(lib, "pcileech")

// ----------------------------------------------------------------------------
// Utility functions below:
// ----------------------------------------------------------------------------

VOID ShowKeyPress()
{
    printf("PRESS ANY KEY TO CONTINUE ...\n");
    Sleep(250);
    _getch();
}

VOID PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbInitialOffset)
{
    DWORD i, j;
    cb += cbInitialOffset;
    for(i = cbInitialOffset; i < cb + ((cb % 16) ? (16 - cb % 16) : 0); i++) {
        // address
        if(0 == i % 16) {
            printf("%04x    ", i % 0x10000);
        } else if(0 == i % 8) {
            putchar(' ');
        }
        // hex
        if(i < cb) {
            printf("%02x ", pb[i]);
        } else {
            printf("   ");
        }
        // ascii
        if(15 == i % 16) {
            printf("  ");
            for(j = i - 15; j <= i; j++) {
                if(j >= cb) {
                    putchar(' ');
                } else {
                    putchar(isprint(pb[j]) ? pb[j] : '.');
                }
            }
            putchar('\n');
        }
    }
}


// ----------------------------------------------------------------------------
// Initialize from type of device, FILE, FPGA or USB3380.
// Ensure only one is active below at one single time!
// INITIALIZE_FROM_FILE contains file name to a raw memory dump.
// ----------------------------------------------------------------------------
//#define _INITIALIZE_FROM_FILE    "z:\\media\\vm\\memdump\\WIN10-17134-48-1.raw"
#define _INITIALIZE_FROM_FPGA
//#define _INITIALIZE_FROM_USB3380

// ----------------------------------------------------------------------------
// Main entry point which contains various sample code how to use PCILeech DLL.
// Please walk though for different API usage examples. To select device ensure
// one device type only is uncommented in the #defines above.
// ----------------------------------------------------------------------------
int main(_In_ int argc, _In_ char* argv[])
{
    BOOL result;
    DWORD i, dwPID;
    CHAR sz[256];
    BYTE pbPage1[0x1000], pbPage2[0x1000];

#ifdef _INITIALIZE_FROM_FILE
    // Initialize PCILeech DLL with a memory dump file.
    ShowKeyPress();
    printf("CALL:    PCILeech_InitializeFromFile\n");
    result = PCILeech_InitializeFromFile(_INITIALIZE_FROM_FILE, NULL);
    if(result) {
        printf("SUCCESS: PCILeech_InitializeFromFile\n");
    } else {
        printf("FAIL:    PCILeech_InitializeFromFile\n");
        return 1;
    }
#endif /* _INITIALIZE_FROM_FILE */

#ifdef _INITIALIZE_FROM_USB3380
    // Initialize PCILeech DLL with a memory dump file.
    ShowKeyPress();
    printf("CALL:    PCILeech_InitializeUSB3380\n");
    result = PCILeech_InitializeUSB3380();
    if(result) {
        printf("SUCCESS: PCILeech_InitializeUSB3380\n");
    } else {
        printf("FAIL:    PCILeech_InitializeUSB3380\n");
        return 1;
    }
#endif /* _INITIALIZE_FROM_USB3380 */

#ifdef _INITIALIZE_FROM_FPGA
    // Initialize PCILeech DLL with a FPGA hardware device
    // !!!IMPORTANT PCILeech_InitializeFPGA is dependent on the 64-bit version
    // of FTD3XX.dll to be placed alongside pcileech.dll. Please consult the
    // PCILeech documentation on github on where to find FTD3XX.dll.
    ShowKeyPress();
    printf("CALL:    PCILeech_InitializeFPGA\n");
    result = PCILeech_InitializeFPGA(NULL, NULL);
    if(result) {
        printf("SUCCESS: PCILeech_InitializeFPGA\n");
    } else {
        printf("FAIL:    PCILeech_InitializeFPGA\n");
        return 1;
    }
    // Retrieve the ID of the FPPA (SP605/PCIeScreamer/AC701 ...) and the bitstream version
    ULONG64 qwID, qwVersionMajor, qwVersionMinor;
    ShowKeyPress();
    printf("CALL:    PCIleech_DeviceConfigGet\n");
    result =
        PCIleech_DeviceConfigGet(PCILEECH_DEVICE_OPT_FPGA_FPGA_ID, &qwID) &&
        PCIleech_DeviceConfigGet(PCILEECH_DEVICE_OPT_FPGA_VERSION_MAJOR, &qwVersionMajor) &&
        PCIleech_DeviceConfigGet(PCILEECH_DEVICE_OPT_FPGA_VERSION_MINOR, &qwVersionMinor);
    if(result) {
        printf("SUCCESS: PCIleech_DeviceConfigGet\n");
        printf("         ID = %lli\n", qwID);
        printf("         VERSION = %lli.%lli\n", qwVersionMajor, qwVersionMinor);
    } else {
        printf("FAIL:    PCIleech_DeviceConfigGet\n");
        return 1;
    }
    // Retrieve the read delay value (in microseconds uS) that is used by the
    // FPGA to pause in every read. Sometimes it may be a good idea to adjust
    // this (and other related values) to lower versions if the FPGA device
    // still works stable without errors. Use PCIleech_DeviceConfigSet to set
    // values.
    ULONG64 qwReadDelay;
    ShowKeyPress();
    printf("CALL:    PCIleech_DeviceConfigGet\n");
    result = PCIleech_DeviceConfigGet(PCILEECH_DEVICE_OPT_FPGA_DELAY_READ, &qwReadDelay);
    if(result) {
        printf("SUCCESS: PCIleech_DeviceConfigGet\n");
        printf("         FPGA Read Delay in microseconds (uS) = %lli\n", qwReadDelay);
    } else {
        printf("FAIL:    PCIleech_DeviceConfigGet\n");
        return 1;
    }
#endif /* _INITIALIZE_FROM_FPGA */


    // Read physical memory at physical address 0x1000 and display the first
    // 0x100 bytes on-screen.
    ShowKeyPress();
    printf("CALL:    PCILeech_DeviceReadMEM\n");
    result = PCILeech_DeviceReadMEM(0x1000, pbPage1, 0x1000);
    if(result) {
        printf("SUCCESS: PCILeech_DeviceReadMEM\n");
        PrintHexAscii(pbPage1, 0x100, 0);
    } else {
        printf("FAIL:    PCILeech_DeviceReadMEM\n");
        return 1;
    }


    // Initialize VMM (required to use subsequent VMM functionality)
    ShowKeyPress();
    printf("CALL:    PCILeech_VmmInitialize\n");
    result = PCILeech_VmmInitialize();
    if(result) {
        printf("SUCCESS: PCILeech_VmmInitialize\n");
    } else {
        printf("FAIL:    PCILeech_VmmInitialize\n");
        return 1;
    }
    

    // Retrieve PID of explorer.exe
    // NB! if multiple explorer.exe exists only one will be returned by this
    // specific function call. Please see .h file for additional information
    // about how to retrieve the complete list of PIDs in the system by using
    // the function PCILeech_VmmProcessListPIDs instead.
    ShowKeyPress();
    printf("CALL:    PCILeech_VmmProcessGetFromName\n");
    result = PCILeech_VmmProcessGetFromName("explorer.exe", &dwPID);
    if(result) {
        printf("SUCCESS: PCILeech_VmmProcessGetFromName\n");
        printf("         PID = %i\n", dwPID);
    } else {
        printf("FAIL:    PCILeech_VmmProcessGetFromName\n");
        return 1;
    }


    // Retrieve additional process information such as: name of the process,
    // PML4 (PageDirectoryBase) PML4-USER (if exists) and Process State.
    DWORD dwProcessState;
    ULONG64 qwPageDirectoryBase, qwPageDirectoryBaseUser;
    ShowKeyPress();
    printf("CALL:    PCIleech_VmmProcessInfo\n");
    result = PCIleech_VmmProcessInfo(dwPID, sz, &qwPageDirectoryBase, &qwPageDirectoryBaseUser, &dwProcessState);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcessInfo\n");
        printf("         Name = %s\n", sz);
        printf("         PageDirectoryBase = 0x%016llx\n", qwPageDirectoryBase);
        printf("         PageDirectoryBaseUser = 0x%016llx\n", qwPageDirectoryBaseUser);
        printf("         ProcessState = 0x%08x\n", dwProcessState);
    } else {
        printf("FAIL:    PCIleech_VmmProcessInfo\n");
        return 1;
    }


    // Retrieve the memory map from the page table. This function also tries to
    // make additional parsing to identify modules and tag the memory map with
    // them. This is done by multiple methods internally and may sometimes be
    // more resilient against anti-reversing techniques that may be employed in
    // some processes.
    ULONG64 cMemMapEntries;
    PPCILEECH_VMM_MEMMAP_ENTRY pMemMapEntries;
    ShowKeyPress();
    printf("CALL:    PCILeech_VmmProcessGetMemoryMap #1\n");
    result = PCILeech_VmmProcessGetMemoryMap(dwPID, NULL, &cMemMapEntries, TRUE);
    if(result) {
        printf("SUCCESS: PCILeech_VmmProcessGetMemoryMap #1\n");
        printf("         Count = %lli\n", cMemMapEntries);
    } else {
        printf("FAIL:    PCILeech_VmmProcessGetMemoryMap #1\n");
        return 1;
    }
    pMemMapEntries = (PPCILEECH_VMM_MEMMAP_ENTRY)LocalAlloc(0, cMemMapEntries * sizeof(PCILEECH_VMM_MEMMAP_ENTRY));
    if(!pMemMapEntries) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    PCILeech_VmmProcessGetMemoryMap #2\n");
    result = PCILeech_VmmProcessGetMemoryMap(dwPID, pMemMapEntries, &cMemMapEntries, TRUE);
    if(result) {
        printf("SUCCESS: PCILeech_VmmProcessGetMemoryMap #2\n");
        printf("         #      #PAGES ADRESS_RANGE                      SRWX\n");
        printf("         ====================================================\n");
        for(i = 0; i < cMemMapEntries; i++) {
            printf(
                "         %04x %8x %016llx-%016llx %sr%s%s%s%s\n",
                i,
                (DWORD)pMemMapEntries[i].cPages,
                pMemMapEntries[i].AddrBase,
                pMemMapEntries[i].AddrBase + (pMemMapEntries[i].cPages << 12) - 1,
                pMemMapEntries[i].fPage & PCIEECH_VMM_MEMMAP_FLAG_PAGE_NS ? "-" : "s",
                pMemMapEntries[i].fPage & PCIEECH_VMM_MEMMAP_FLAG_PAGE_W ? "w" : "-",
                pMemMapEntries[i].fPage & PCIEECH_VMM_MEMMAP_FLAG_PAGE_NX ? "-" : "x",
                pMemMapEntries[i].szName[0] ? (pMemMapEntries[i].fWoW64 ? " 32 " : "    ") : "",
                pMemMapEntries[i].szName
            );
        }
    } else {
        printf("FAIL:    PCILeech_VmmProcessGetMemoryMap #2\n");
        return 1;
    }


    // Retrieve the list of loaded DLLs from the process. Please note that this
    // list is retrieved by parsing in-process memory structures such as the
    // process environment block (PEB) which may be partly destroyed in some
    // processes due to obfuscation and anti-reversing. If that is the case the
    // memory map may use alternative parsing techniques to list DLLs.
    ULONG64 cModules;
    PPCILEECH_VMM_MODULEMAP_ENTRY pModules;
    ShowKeyPress();
    printf("CALL:    PCILeech_VmmProcessGetModuleMap #1\n");
    result = PCILeech_VmmProcessGetModuleMap(dwPID, NULL, &cModules);
    if(result) {
        printf("SUCCESS: PCILeech_VmmProcessGetModuleMap #1\n");
        printf("         Count = %lli\n", cModules);
    } else {
        printf("FAIL:    PCILeech_VmmProcessGetModuleMap #1\n");
        return 1;
    }
    pModules = (PPCILEECH_VMM_MODULEMAP_ENTRY)LocalAlloc(0, cModules * sizeof(PCILEECH_VMM_MODULEMAP_ENTRY));
    if(!pModules) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    PCILeech_VmmProcessGetModuleMap #2\n");
    result = PCILeech_VmmProcessGetModuleMap(dwPID, pModules, &cModules);
    if(result) {
        printf("SUCCESS: PCILeech_VmmProcessGetModuleMap #2\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        for(i = 0; i < cModules; i++) {
            printf(
                "         %-40.40s %i %016llx %08x %016llx\n",
                pModules[i].szName,
                pModules[i].fWoW64 ? 32 : 64,
                pModules[i].BaseAddress,
                pModules[i].SizeOfImage,
                pModules[i].EntryPoint           
            );
        }
    } else {
        printf("FAIL:    PCILeech_VmmProcessGetModuleMap #2\n");
        return 1;
    }


    // Retrieve the module of crypt32.dll by its name. Note it is also possible
    // to retrieve it by retrieving the complete module map (list) and iterate
    // over it. But if the name of the module is known this is more convenient.
    // This required that the PEB and LDR list in-process haven't been tampered
    // with ...
    PCILEECH_VMM_MODULEMAP_ENTRY oModuleEntry;
    ShowKeyPress();
    printf("CALL:    PCILeech_VmmProcessGetModuleFromName\n");
    result = PCILeech_VmmProcessGetModuleFromName(dwPID, "crypt32.dll", &oModuleEntry);
    if(result) {
        printf("SUCCESS: PCILeech_VmmProcessGetModuleFromName\n");
        printf("         MODULE_NAME                                 BASE             SIZE     ENTRY\n");
        printf("         ======================================================================================\n");
        printf(
            "         %-40.40s %i %016llx %08x %016llx\n",
            oModuleEntry.szName,
            oModuleEntry.fWoW64 ? 32 : 64,
            oModuleEntry.BaseAddress,
            oModuleEntry.SizeOfImage,
            oModuleEntry.EntryPoint
        );
    } else {
        printf("FAIL:    PCILeech_VmmProcessGetModuleFromName\n");
        return 1;
    }


    // Retrieve the memory at the base of crylt32.dll previously fetched and
    // display the first 0x200 bytes of it. This read is fetched from the cache
    // by default (if possible). If reads should be forced from the DMA device
    // please specify the flag: VMM_FLAG_NOCACHE
    DWORD cRead;
    ShowKeyPress();
    printf("CALL:    PCILeech_VmmReadEx\n");
    result = PCILeech_VmmReadEx(dwPID, oModuleEntry.BaseAddress, pbPage2, 0x1000, &cRead, 0);                   // standard cached read
    //result = PCILeech_VmmReadEx(dwPID, oModuleEntry.BaseAddress, pbPage2, 0x1000, &cRead, VMM_FLAG_NOCACHE);  // uncached read
    if(result) {
        printf("SUCCESS: PCILeech_VmmReadEx\n");
        PrintHexAscii(pbPage2, min(cRead, 0x200), 0);
    } else {
        printf("FAIL:    PCILeech_VmmReadEx\n");
        return 1;
    }


    // List the sections from the module of crypt32.dll.
    DWORD cSections;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    ShowKeyPress();
    printf("CALL:    PCIleech_VmmProcess_GetSections #1\n");
    result = PCIleech_VmmProcess_GetSections(dwPID, "crypt32.dll", NULL, 0, &cSections);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetSections #1\n");
        printf("         Count = %lli\n", cModules);
    } else {
        printf("FAIL:    PCIleech_VmmProcess_GetSections #1\n");
        return 1;
    }
    pSectionHeaders = (PIMAGE_SECTION_HEADER)LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER));
    if(!pModules) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    PCIleech_VmmProcess_GetSections #2\n");
    result = PCIleech_VmmProcess_GetSections(dwPID, "crypt32.dll", pSectionHeaders, cSections, &cSections);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetSections #2\n");
        printf("         #  NAME     OFFSET   SIZE     RWX\n");
        printf("         =================================\n");
        for(i = 0; i < cSections; i++) {
            printf(
                "         %02lx %-8.8s %08x %08x %c%c%c\n",
                i,
                pSectionHeaders[i].Name,
                pSectionHeaders[i].VirtualAddress,
                pSectionHeaders[i].Misc.VirtualSize,
                (pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_READ) ? 'r' : '-',
                (pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? 'w' : '-',
                (pSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'x' : '-'
            );
        }
    } else {
        printf("FAIL:    PCIleech_VmmProcess_GetSections #2\n");
        return 1;
    }


    // Retrieve and display the data directories of crypt32.dll. The number of
    // data directories in a PE is always 16 - so this can be used to simplify
    // calling the functionality somewhat.
    LPCSTR DIRECTORIES[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED" };
    DWORD cDirectories;
    IMAGE_DATA_DIRECTORY pDirectories[16];
    ShowKeyPress();
    printf("CALL:    PCIleech_VmmProcess_GetDirectories\n");
    result = PCIleech_VmmProcess_GetDirectories(dwPID, "crypt32.dll", pDirectories, 16, &cDirectories);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetDirectories\n");
        printf("         #  NAME             OFFSET   SIZE\n");
        printf("         =====================================\n");
        for(i = 0; i < 16; i++) {
            printf(
                "         %02lx %-16.16s %08x %08x\n",
                i,
                DIRECTORIES[i],
                pDirectories[i].VirtualAddress,
                pDirectories[i].Size
            );
        }
    } else {
        printf("FAIL:    PCIleech_VmmProcess_GetDirectories\n");
        return 1;
    }


    // Retrieve the export address table (EAT) of crypt32.dll
    DWORD cEATs;
    PPCILEECH_VMM_EAT_ENTRY pEATs;
    ShowKeyPress();
    printf("CALL:    PCIleech_VmmProcess_GetEAT #1\n");
    result = PCIleech_VmmProcess_GetEAT(dwPID, "crypt32.dll", NULL, 0, &cEATs);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetEAT #1\n");
        printf("         Count = %i\n", cEATs);
    } else {
        printf("FAIL:    PCIleech_VmmProcess_GetEAT #1\n");
        return 1;
    }
    pEATs = (PPCILEECH_VMM_EAT_ENTRY)LocalAlloc(LMEM_ZEROINIT, cEATs * sizeof(PCILEECH_VMM_EAT_ENTRY));
    if(!pEATs) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    PCIleech_VmmProcess_GetEAT #2\n");
    result = PCIleech_VmmProcess_GetEAT(dwPID, "crypt32.dll", pEATs, cEATs, &cEATs);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetEAT #2\n");
        printf("         #    OFFSET   NAME\n");
        printf("         =================================\n");
        for(i = 0; i < cEATs; i++) {
            printf(
                "         %04lx %08x %s\n",
                i,
                pEATs[i].vaFunctionOffset,
                pEATs[i].szFunction
            );
        }
    } else {
        printf("FAIL:    PCIleech_VmmProcess_GetEAT #2\n");
        return 1;
    }


    // Retrieve the import address table (IAT) of crypt32.dll
    DWORD cIATs;
    PPCILEECH_VMM_IAT_ENTRY pIATs;
    ShowKeyPress();
    printf("CALL:    PCIleech_VmmProcess_GetIAT #1\n");
    result = PCIleech_VmmProcess_GetIAT(dwPID, "crypt32.dll", NULL, 0, &cIATs);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetIAT #1\n");
        printf("         Count = %i\n", cIATs);
    } else {
        printf("FAIL:    PCIleech_VmmProcess_GetIAT #1\n");
        return 1;
    }
    pIATs = (PPCILEECH_VMM_IAT_ENTRY)LocalAlloc(LMEM_ZEROINIT, cIATs * sizeof(PCILEECH_VMM_IAT_ENTRY));
    if(!pIATs) {
        printf("FAIL:    OutOfMemory\n");
        return 1;
    }
    printf("CALL:    PCIleech_VmmProcess_GetIAT #2\n");
    result = PCIleech_VmmProcess_GetIAT(dwPID, "crypt32.dll", pIATs, cIATs, &cIATs);
    if(result) {
        printf("SUCCESS: PCIleech_VmmProcess_GetIAT #2\n");
        printf("         #    VIRTUAL_ADDRESS    MODULE!NAME\n");
        printf("         ===================================\n");
        for(i = 0; i < cIATs; i++) {
            printf(
                "         %04lx %016llx   %s!%s\n",
                i,
                pIATs[i].vaFunction,
                pIATs[i].szModule,
                pIATs[i].szFunction
            );
        }
    } else {
        printf("FAIL:    PCIleech_VmmProcess_GetIAT #2\n");
        return 1;
    }


    // Exit the test program.
    printf("!!! EXIT !!! \n");
    ShowKeyPress();
    PCILeech_Close();
    return 0;
}
