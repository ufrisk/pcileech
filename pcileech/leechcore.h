// leechcore.h : header file for the leechcore module - which purpose is to
// expose low-level device physical memory functionality.
//
// This library is thread-safe in all functions with the notable exceptions  of
// the LeechCore_Open() and LeechCore_Close() functions. Some devices may allow
// multi-threaded access while in reality most devices are single-threaded  and
// will control synchronization where necessary with locks.
//
// The library is initialized by calling LeechCore_Open with a LEECHCORE_CONFIG
// struct containing the correct configuration paramters. Note that the version
// and magic values must be set in addition to the szDevice configuration value
// Also, it may be possible to optionally connect to a remote leechcore service
// or instance over RPC by specifying a szRemote configuration value.
//
// ----------------------------------------------------------------------------
//
// Remote instance: szRemote configuration value. Connect to a remote leechcore
// instance by specifying a configuration value in the szRemote parameter. If a
// loaded already valid instance exists remotely this will be prioritized above
// the value in szDevice.    If the acquisition device is not yet loaded by the
// remote instance the value in szDevice will be used. Normally, the connection
// will take place as a mutually authenticated encrypted connection secured  by
// kerberos. If not possible or desirable the 'insecure' value may be specified
// to disable authentication and security.
// Syntax:
//    rpc://<remote_spn>:<host>[:<options>] (remote_spn = kerberos SPN of     )
//                                          (remote service or 'insecure'     )
//
// Valid options:                           (optional comma-separated list    )
//    port=<port>                           (RPC TCP port of the remote system)
//    nocompress                            (disable transport compression    )
//    
// Examples:
//    rpc://insecure:remotehost.example.com (connect insecure to remote host  )
//    rpc://user@ad.domain.com:192.0.0.5    (connect   secure to remote host  )
//    rpc://insecure:127.0.0.0:6666         (connect insecure non-default port)
//
// The remote connector may also connect to pipe handles provided in the config
// string. This is only used internally by the LeechAgent for communication for
// parent/child process and may not be used by external applications. Syntax is
// pipe://<handle_id_input>:<handle_id_output>.
//
// ----------------------------------------------------------------------------
//
// Device to connect to: szDevice contains the device to capture memory from.
// Supported memory acquisition devices are:
// USB3380 : hardware, read/write, 32-bit (4GB) addressing only. Requires a
//           PCILeech flashed USB3380 device connected over USB and Google
//           Android WinUSB drivers to be installed. Download and install from:
//           http://developer.android.com/sdk/win-usb.html#download
//           Syntax:
//           USB3380
//           USB3380://USB2                       (force USB2 connection speed)
//
// FPGA :    hardware, read/write - requires a PCILeech FPGA flashed hardware
//           device as shown at: https://github.com/ufrisk/pcileech-fpga
//           Also requires the FTD3XX.DLL from ftdichip to be placed in the
//           same directory as the executable. Download from ftdichip at:
//           http://www.ftdichip.com/Drivers/D3XX/FTD3XXLibrary_v1.2.0.6.zip
//           Syntax:
//           FGPA
//           FPGA://<read_uS>[:<write_uS>[:<probe_uS>]]   (values are optional)
//
// SP605TCP : hardware, read/write - connect to a remote SP605 FPGA over the
//           network using the implementation created by @d_olex.
//           https://github.com/Cr4sh/s6_pcie_microblaze
//           Syntax:
//           SP605TCP://<target_ip>[:<target_port>]          (port is optional)
//
// RAWTCP :  read/write - connect to a remote raw tcp device - such as HPE iLO
//           that have been patched to support DMA as per blog entry below:
//           https://www.synacktiv.com/posts/exploit/using-your-bmc-as-a-dma-device-plugging-pcileech-to-hpe-ilo-4.html
//           Syntax:
//           RAWTCP://<target_ip>[:<target_port>]            (port is optional)
//
// HvSavedState : read-only - connect to a Hyper-V saved state file. In order
//           to do so the .dll file 'vmsavedstatedumpprovider.dll' must be
//           placed in same directory as the executable file.
//
// PMEM :    load the rekall winpmem driver into the kernel and connect to it
//           to acquire memory. The signed driver `.sys` file may be found at:
//           https://github.com/Velocidex/c-aff4/tree/master/tools/pmem/resources/winpmem
//           Download the driver file `att_winpmem_64.sys` and copy it to the
//           directory of leechcore.dll and run executable as elevated admin
//           using syntax below:
//           Syntax:
//           PMEM              (use att_winpmem_64.sys in directory of executable)
//           PMEM://<non_default_path_to_file_winpmem_64.sys>
//
// TOTALMELTDOWN : read/write - requires a Windows 7 system vulnerable to the
//           "Total Meltdown" vulnerability - CVE-2018-1038.
//           Syntax:
//           TOTALMELTDOWN
//
// FILE :    use dump file, either a raw linear memory dump or full crash dump.
//           Which format to use is auto-detected. If it looks like a full cash
//           dump that format will be used, otherwise it will be assumed that a
//           raw linear memory dump is to be used.
//           Syntax:
//           <filename>        (no device-type prefix - just use the file name)
//           FILE://<filename>
//
// DumpIt :  DumpIt is a "virtual" device. It's only possible to use the DumpIt
//           device if the main process containing LeechCore has been started
//           with DumpIt in LiveKD mode.
//           Example 1:
//           DumpIt.exe /LIVEKD /A MemProcFS.exe
//           Example 2:
//           DumpIt.exe /LIVEKD /A LeechSvc.exe /C "interactive insecure"
//           and then connect to remote service by:
//           MemProcFS.exe -remote rpc://insecure:192.168.x.x -device DumpIt
//
// EXISTING : Attach to existing already loaded configuration. This is done
//           instead of the default behaviour of closing any existing devices
//           and initializing the new requested device. If no existing device
//           exists the call to LeechCore_Open will fail.
//           Syntax:
//           EXISTING
//
// EXISTINGREMOTE : Same as EXISTING but applying the EXISTING device on the
//           remote system. Use only in conjunction with a remote system.
//           Syntax:
//           EXISTINGREMOTE
//
//
// (c) Ulf Frisk, 2018-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
// Header Version: 1.2.0
//
#ifndef __LEECHCORE_H__
#define __LEECHCORE_H__
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

//-----------------------------------------------------------------------------
// WINDOWS / LINUX COMPATIBILITY BELOW:
//-----------------------------------------------------------------------------

#ifdef _WIN32
#include <Windows.h>
typedef unsigned __int64                    QWORD, *PQWORD;
#define DLLEXPORT                           __declspec(dllexport)
#ifdef _WIN64
#define ARCH_64
#endif /* _WIN64 */
#endif /* _WIN32 */
#ifdef LINUX
#define ARCH_X64
#include <stdint.h>
#include <stddef.h>
typedef void                                VOID, *PVOID, *LPVOID;
typedef void                                *HANDLE, **PHANDLE;
typedef uint32_t                            BOOL, *PBOOL;
typedef uint8_t                             BYTE, *PBYTE;
typedef char                                CHAR, *PCHAR, *PSTR, *LPSTR;
typedef uint16_t                            WORD, *PWORD, USHORT, *PUSHORT;
typedef uint32_t                            DWORD, *PDWORD;
typedef long long unsigned int              QWORD, *PQWORD, ULONG64, *PULONG64;
#define MAX_PATH                            260
#define DLLEXPORT                           __attribute__((visibility("default")))
#define _In_
#define _Out_
#define _In_z_
#define _Inout_
#define _In_opt_
#define _Out_opt_
#define _Out_writes_(x)
#define _Check_return_opt_
#define _Printf_format_string_
#define _Inout_updates_bytes_(x)
#define _In_reads_(cbDataIn)
#define _Out_writes_opt_(x)
#define _Success_(return)
#endif /* LINUX */

//-----------------------------------------------------------------------------
// GENERAL HEADER DEFINES BELOW:
//-----------------------------------------------------------------------------

#define MEM_IO_SCATTER_HEADER_MAGIC                     0xffff6548
#define MEM_IO_SCATTER_HEADER_VERSION                   0x0003

#ifdef ARCH_64
typedef struct tdMEM_IO_SCATTER_HEADER {
    DWORD magic;            // magic
    WORD version;           // version
    WORD Future1;
    ULONG64 qwA;            // base address.
    DWORD cbMax;            // bytes to read (DWORD boundry, max 0x1000); pb must have room for this.
    DWORD cb;               // bytes read into result buffer.
    PBYTE pb;               // ptr to 0x1000 sized buffer to receive read bytes.
    PVOID pvReserved1;      // reserved for use by caller.
    PVOID pvReserved2;      // reserved for use by caller.
    PVOID Future2[8];
} MEM_IO_SCATTER_HEADER, *PMEM_IO_SCATTER_HEADER, **PPMEM_IO_SCATTER_HEADER;
#endif /* ARCH_64 */

#ifndef ARCH_64
typedef struct tdMEM_IO_SCATTER_HEADER {
    DWORD magic;            // magic
    WORD version;           // version
    WORD Future1;
    ULONG64 qwA;            // base address.
    DWORD cbMax;            // bytes to read (DWORD boundry, max 0x1000); pb must have room for this.
    DWORD cb;               // bytes read into result buffer.
    PBYTE pb;               // ptr to 0x1000 sized buffer to receive read bytes.
    DWORD dwFiller64_1;
    PVOID pvReserved1;      // reserved for use by caller.
    DWORD dwFiller64_2;
    PVOID pvReserved2;      // reserved for use by caller.
    DWORD dwFiller64_3;
    PVOID Future2[8];
    DWORD dwFiller64_4[8];
} MEM_IO_SCATTER_HEADER, *PMEM_IO_SCATTER_HEADER, **PPMEM_IO_SCATTER_HEADER;
#endif /* ARCH_64 */

//-----------------------------------------------------------------------------
// LEECHCORE INITIALIZATION / CLOSE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

typedef enum tdLEECHCORE_DEVICE {
    LEECHCORE_DEVICE_NA = 0,
    LEECHCORE_DEVICE_FILE = 1,
    LEECHCORE_DEVICE_PMEM = 2,
    LEECHCORE_DEVICE_FPGA = 3,
    LEECHCORE_DEVICE_SP605_TCP = 4,
    LEECHCORE_DEVICE_USB3380 = 5,
    LEECHCORE_DEVICE_TOTALMELTDOWN = 6,
    LEECHCORE_DEVICE_HVSAVEDSTATE = 7,
    LEECHCORE_DEVICE_RAWTCP = 8,
} LEECHCORE_DEVICE;

#define LEECHCORE_CONFIG_MAGIC                          0xffff6549
#define LEECHCORE_CONFIG_VERSION                        0x0001

#define LEECHCORE_CONFIG_FLAG_PRINTF                    0x0001
#define LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_1          0x0002
#define LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_2          0x0004
#define LEECHCORE_CONFIG_FLAG_PRINTF_VERBOSE_3          0x0008
#define LEECHCORE_CONFIG_FLAG_REMOTE_NO_COMPRESS        0x0010

typedef struct tdLEECHCORE_CONFIG {
    DWORD magic;                // set by caller.
    WORD version;               // set by caller.
    WORD flags;                 // set by caller, updated by device.
    ULONG64 paMax;              // set by caller, updated by device.
    ULONG64 cbMaxSizeMemIo;     // set by caller, updated by device.
    ULONG64 paMaxNative;        // set by device.
    LEECHCORE_DEVICE tpDevice;  // set by device.
    BOOL fWritable;             // set by device. (is device writable?)
    BOOL fVolatile;             // set by device. (is device volatile / memory may change?)
    BOOL fVolatileMaxAddress;   // set by device. (is max address volatile? - poll changes with LEECHCORE_OPT_MEMORYINFO_ADDR_MAX)
    BOOL fRemote;               // set by device.
    WORD VersionMajor;          // set by device.
    WORD VersionMinor;          // set by device.
    WORD VersionRevision;       // set by device.
    CHAR szDevice[MAX_PATH];    // set by caller.
    CHAR szRemote[MAX_PATH];    // set by caller.
    // optional 'printf' function pointer. if set to non null value 'printf'
    // calls will be redirected. useful when logging to files.
    _Check_return_opt_ int(*pfn_printf_opt)(_In_z_ _Printf_format_string_ char const* const _Format, ...);  // set by caller.
#ifndef ARCH_64
    DWORD dwFiller64_1;
#endif /* ARCH_64 */
} LEECHCORE_CONFIG, *PLEECHCORE_CONFIG;

#ifdef ARCH_64
typedef struct tdLEECHCORE_PAGESTAT_MINIMAL {
    HANDLE h;
    VOID(*pfnPageStatUpdate)(HANDLE h, ULONG64 pa, ULONG64 cPageSuccessAdd, ULONG64 cPageFailAdd);
} LEECHCORE_PAGESTAT_MINIMAL, *PLEECHCORE_PAGESTAT_MINIMAL;
#endif /* ARCH_64 */

#ifndef ARCH_64
typedef struct tdLEECHCORE_PAGESTAT_MINIMAL {
    HANDLE h;
    DWORD dwFiller64_1;
    VOID(*pfnPageStatUpdate)(HANDLE h, ULONG64 pa, ULONG64 cPageSuccessAdd, ULONG64 cPageFailAdd);
    DWORD dwFiller64_2;
} LEECHCORE_PAGESTAT_MINIMAL, *PLEECHCORE_PAGESTAT_MINIMAL;
#endif /* ARCH_64 */

/*
* Open a connection to the target device. The LeechCore initialization may fail
* if the underlying device cannot be opened or if the LeechCore is already
* initialized. If already initialized please connect with device EXISTING or
* call LeechCore_Close() before opening a new device.
* -- pInformation
* -- result
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_Open(_Inout_ PLEECHCORE_CONFIG pConfig);

/*
* Clean up various device related stuff and deallocate memory buffers.
*/
DLLEXPORT VOID LeechCore_Close();



//-----------------------------------------------------------------------------
// LEECHCORE CORE READ AND WRITE FUNCTIONALITY BELOW:
//-----------------------------------------------------------------------------

#define LEECHCORE_FLAG_READ_RETRY           0x01
#define LEECHCORE_FLAG_WRITE_RETRY          0x01
#define LEECHCORE_FLAG_WRITE_VERIFY         0x02

/*
* Allocate a scatter buffer containing empty 0x1000-sized ppMEMs with address
* set to zero. Caller is responsible for calling LocalFree(ppMEMs).
* -- cMEMs
* -- pppMEMs = pointer to receive ppMEMs on success.
* -- return
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_AllocScatterEmpty(_In_ DWORD cMEMs, _Out_ PPMEM_IO_SCATTER_HEADER *pppMEMs);

/*
* Read memory in various non-contigious locations specified by the items in the
* phDMAs array. Result for each unit of work will be given individually. No upper
* limit of number of items to read, but no performance boost will be given if
* above hardware limit. Max size of each unit of work is one 4k page (4096 bytes).
* -- ppMEMs = array of scatter read headers.
* -- cpMEMs = count of ppDMAs.
*/
DLLEXPORT VOID LeechCore_ReadScatter(_Inout_ PPMEM_IO_SCATTER_HEADER ppMEMs, _In_ DWORD cpMEMs);

/*
* Try read memory in a fairly optimal way considering device limits. The number
* of total successfully read bytes is returned. Failed reads will be zeroed out
* in the returned memory.
* -- pa
* -- pb
* -- cb
* -- return = the number of bytes successfully read.
*/
DLLEXPORT DWORD LeechCore_Read(_In_ ULONG64 pa, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Try read memory in a fairly optimal way considering device limits. The number
* of total successfully read bytes is returned. Failed reads will be zeroed out
* in the returned memory.
* -- pa
* -- pb
* -- cb
* -- flags = 0 or LEECHCORE_FLAG_READ_RETRY
* -- pPageStat = optional minimal statistic struct to update.
* -- return = the number of bytes successfully read.
*/
DLLEXPORT DWORD LeechCore_ReadEx(_In_ ULONG64 pa, _Out_writes_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD flags, _In_opt_ PLEECHCORE_PAGESTAT_MINIMAL pPageStat);

/*
* Write data to the target system if supported by the device.
* -- pa
* -- pb
* -- cb
* -- return
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_Write(_In_ ULONG64 pa, _In_reads_(cb) PBYTE pb, _In_ DWORD cb);

/*
* Write data to the target system if supported by the device.
* -- pa
* -- pb
* -- cb
* -- flags = 0 or LEECHCORE_FLAG_WRITE_*
* -- return
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_WriteEx(_In_ ULONG64 pa, _In_reads_(cb) PBYTE pb, _In_ DWORD cb, _In_ DWORD flags);

/*
* Probe the memory of the target system to check whether it's readable or not.
* Please note that not all devices support this natively.
* -- pa = address to start probe from.
* -- cPages = number of 4kB pages to probe.
* -- pbResultMap = result map, 1 byte represents 1 page, 0 = fail, 1 = success.
*       (individual page elements in pbResultMap must be set to 0 [fail] on call
*       for probe to take place on individual page).
* -- return = FALSE if not supported by underlying hardware, TRUE if supported.
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_Probe(_In_ QWORD pa, _In_ DWORD cPages, _Inout_updates_bytes_(cPages) PBYTE pbResultMap);



//-----------------------------------------------------------------------------
// GET/SET DEVICE OPTIONS BELOW. SOME OPTIONS ARE GENERAL LEECHCORE OPTIONS
// WHILE OTHER ARE DEVICE SPECIFIC. USE FUNCTIONS:
// LeechCore_GetOption() AND LeechCore_GetOption() TO GET/SET OPTIONS.
// FOR DEVICE-SPECIFIC OPTIONS PLEASE SEE INDIVIDUAL DEVICE FILES FOR MORE
// DETAILED INFORMATION.
//-----------------------------------------------------------------------------

#define LEECHCORE_OPT_CORE_PRINTF_ENABLE                0x80000001  // RW
#define LEECHCORE_OPT_CORE_VERBOSE                      0x80000002  // RW
#define LEECHCORE_OPT_CORE_VERBOSE_EXTRA                0x80000003  // RW
#define LEECHCORE_OPT_CORE_VERBOSE_EXTRA_TLP            0x80000004  // RW

#define LEECHCORE_OPT_CORE_VERSION_MAJOR                0x01000001  // R
#define LEECHCORE_OPT_CORE_VERSION_MINOR                0x01000002  // R
#define LEECHCORE_OPT_CORE_VERSION_REVISION             0x01000003  // R
#define LEECHCORE_OPT_CORE_FLAG_BACKEND_FUNCTIONS       0x01000004  // R

#define LEECHCORE_OPT_MEMORYINFO_VALID                  0x02000001  // R
#define LEECHCORE_OPT_MEMORYINFO_ADDR_MAX               0x02000002  // R
#define LEECHCORE_OPT_MEMORYINFO_FLAG_32BIT             0x02000003  // R
#define LEECHCORE_OPT_MEMORYINFO_FLAG_PAE               0x02000004  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_VERSION_MINOR       0x02000005  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_VERSION_MAJOR       0x02000006  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_DTB                 0x02000007  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_PFN                 0x02000008  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_PsLoadedModuleList  0x02000009  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_PsActiveProcessHead 0x0200000a  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP    0x0200000b  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_NUM_PROCESSORS      0x0200000c  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_SYSTEMTIME          0x0200000d  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_UPTIME              0x0200000e  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_KERNELBASE          0x0200000f  // R
#define LEECHCORE_OPT_MEMORYINFO_OS_KERNELHINT          0x02000010  // R

#define LEECHCORE_OPT_FPGA_PROBE_MAXPAGES               0x03000001  // RW
#define LEECHCORE_OPT_FPGA_RX_FLUSH_LIMIT               0x03000002  // RW
#define LEECHCORE_OPT_FPGA_MAX_SIZE_RX                  0x03000003  // RW
#define LEECHCORE_OPT_FPGA_MAX_SIZE_TX                  0x03000004  // RW
#define LEECHCORE_OPT_FPGA_DELAY_PROBE_READ             0x03000005  // RW - uS
#define LEECHCORE_OPT_FPGA_DELAY_PROBE_WRITE            0x03000006  // RW - uS
#define LEECHCORE_OPT_FPGA_DELAY_WRITE                  0x03000007  // RW - uS
#define LEECHCORE_OPT_FPGA_DELAY_READ                   0x03000008  // RW - uS
#define LEECHCORE_OPT_FPGA_RETRY_ON_ERROR               0x03000009  // RW
#define LEECHCORE_OPT_FPGA_DEVICE_ID                    0x03000080  // R
#define LEECHCORE_OPT_FPGA_FPGA_ID                      0x03000081  // R
#define LEECHCORE_OPT_FPGA_VERSION_MAJOR                0x03000082  // R
#define LEECHCORE_OPT_FPGA_VERSION_MINOR                0x03000083  // R

/*
* Set a device specific option value.
* -- fOption
* -- pqwValue = pointer to QWORD to receive option value.
* -- return
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_GetOption(_In_ ULONG64 fOption, _Out_ PULONG64 pqwValue);

/*
* Set a device specific option value.
* -- fOption
* -- qwValue
* -- return
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_SetOption(_In_ ULONG64 fOption, _In_ ULONG64 qwValue);



//-----------------------------------------------------------------------------
// TRANSFER DEVICE DEPENDANT COMMANDS OR DATA TO/FROM UNDERLYING DEVICES AND
// PERFORM ACTIONS USING THE LeechCore_CommandData() FUNCTION.
//-----------------------------------------------------------------------------

#define LEECHCORE_COMMANDDATA_FPGA_WRITE_TLP            0x00000101  // R
#define LEECHCORE_COMMANDDATA_FPGA_LISTEN_TLP           0x00000102  // R
#define LEECHCORE_COMMANDDATA_STATISTICS_GET            0x80000100  // R

#define LEECHCORE_STATISTICS_MAGIC                      0xffff6550
#define LEECHCORE_STATISTICS_VERSION                        0x0001
#define LEECHCORE_STATISTICS_ID_OPEN                          0x00
#define LEECHCORE_STATISTICS_ID_READSCATTER                   0x01
#define LEECHCORE_STATISTICS_ID_WRITE                         0x02
#define LEECHCORE_STATISTICS_ID_PROBE                         0x03
#define LEECHCORE_STATISTICS_ID_GETOPTION                     0x04
#define LEECHCORE_STATISTICS_ID_SETOPTION                     0x05
#define LEECHCORE_STATISTICS_ID_COMMANDDATA                   0x06
#define LEECHCORE_STATISTICS_ID_COMMANDSVC                    0x07
#define LEECHCORE_STATISTICS_ID_MAX                           0x07

static const LPSTR LEECHCORE_STATISTICS_NAME[] = {
    "LeechCore_Open",
    "LeechCore_ReadScatter",
    "LeechCore_Write",
    "LeechCore_Probe",
    "LeechCore_GetOption",
    "LeechCore_SetOption",
    "LeechCore_CommandData",
    "LeechCore_CommandSvc"
};

typedef struct tdLEECHCORE_STATISTICS {
    DWORD magic;
    WORD version;
    WORD Reserved0;
    DWORD Reserved1;
    QWORD qwFreq;
    struct {
        QWORD c;
        QWORD tm;   // total time in qwFreq ticks
    } Call[0x10];
} LEECHCORE_STATISTICS, *PLEECHCORE_STATISTICS;

/*
* Transfer device dependant commands/data to/from the underlying device and
* perform device dependant actions.
* -- fOption
* -- cbDataIn
* -- pbDataIn
* -- pbDataOut
* -- cbDataOut
* -- pcbDataOut
* -- return
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_CommandData(
    _In_ ULONG64 fOption,
    _In_reads_(cbDataIn) PBYTE pbDataIn,
    _In_ DWORD cbDataIn,
    _Out_writes_opt_(cbDataOut) PBYTE pbDataOut,
    _In_ DWORD cbDataOut,
    _Out_opt_ PDWORD pcbDataOut
);

#define LEECHCORE_AGENTCOMMAND_EXEC_PYTHON_INMEM    0x1166000000000001
#define LEECHCORE_AGENTCOMMAND_EXITPROCESS          0x1166000000000010

/*
* Transfer commands/data to/from the remote agent (if it exists).
* NB! USER-FREE: ppbDataOut (LocalFree)
* -- fCommand = the option / command to the remote service as defined in LEECHCORE_AGENTCOMMAND_*
* -- fDataIn = optional 64-bit tiny input value
* -- cbDataIn
* -- pbDataIn
* -- ppbDataOut =  ptr to receive function allocated output - must be LocalFree'd by caller!
* -- pcbDataOut = ptr to receive length of *pbDataOut.
* -- return
*/
_Success_(return)
DLLEXPORT BOOL LeechCore_AgentCommand(
    _In_ ULONG64 fCommand,
    _In_ ULONG64 fDataIn,
    _In_reads_(cbDataIn) PBYTE pbDataIn,
    _In_ DWORD cbDataIn,
    _Out_writes_opt_(*pcbDataOut) PBYTE *ppbDataOut,
    _Out_opt_ PDWORD pcbDataOut
);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __LEECHCORE_H__ */
