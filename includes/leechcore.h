// leechcore.h : external header of the LeechCore library.
//
// LeechCore is a library which abstracts away reading and writing to various
// software and hardware acquisition sources. Sources ranges from memory dump
// files to driver backed live memory to hardware (FPGA) DMA backed memory.
//
// LeechCore built-in device support may be extended with external plugin
// device drivers placed as .dll or .so files in the same folder as LeechCore.
//
// For more information please consult the LeechCore information on Github:
// - README: https://github.com/ufrisk/LeechCore
// - GUIDE:  https://github.com/ufrisk/LeechCore/wiki
//
// (c) Ulf Frisk, 2020
// Author: Ulf Frisk, pcileech@frizk.net
//
// Header Version: 2.1
//

#ifndef __LEECHCORE_H__
#define __LEECHCORE_H__
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

//-----------------------------------------------------------------------------
// OS COMPATIBILITY BELOW:
//-----------------------------------------------------------------------------

#ifdef _WIN32
#include <Windows.h>

#define EXPORTED_FUNCTION                   __declspec(dllexport)
typedef ULONG64                             QWORD, *PQWORD;
#endif /* _WIN32 */
#ifdef LINUX
#include <inttypes.h>
#include <stdlib.h>

#define EXPORTED_FUNCTION                   __attribute__((visibility("default")))
typedef void                                VOID, *PVOID, *HANDLE;
typedef long long unsigned int              QWORD, *PQWORD, ULONG64;
typedef uint32_t                            DWORD, *PDWORD, BOOL;
typedef uint8_t                             BYTE, *PBYTE;
typedef char                                CHAR, *LPSTR;
typedef const char                          *LPCSTR;
typedef wchar_t                             WCHAR, *PWCHAR, *LPWSTR;
#define MAX_PATH                            260
#define _In_
#define _In_z_
#define _In_opt_
#define _In_reads_(x)
#define _In_reads_opt_(x)
#define _Inout_
#define _Out_
#define _Out_opt_
#define _Out_writes_(x)
#define _Out_writes_opt_(x)
#define _Inout_updates_opt_(x)
#define _Frees_ptr_opt_
#define _Post_ptr_invalid_
#define _Check_return_opt_
#define _Printf_format_string_
#define _Success_(x)
#endif /* LINUX */



//-----------------------------------------------------------------------------
// Create and Close LeechCore devices:
// It's possible to create multiple LeechCore devices in parallel and also of
// different types if the underlying device will allow this. LeechCore will
// automatically take care of and abstract away any hardware/software issues
// with regards to the underlying devices.
//
// For more information about supported devices please check out the LeechCore
// guide at: https://github.com/ufrisk/LeechCore/wiki
//-----------------------------------------------------------------------------

#define LC_CONFIG_VERSION                       0xc0fd0002
#define LC_CONFIG_ERRORINFO_VERSION             0xc0fe0002

#define LC_CONFIG_PRINTF_ENABLED                0x01
#define LC_CONFIG_PRINTF_V                      0x02
#define LC_CONFIG_PRINTF_VV                     0x04
#define LC_CONFIG_PRINTF_VVV                    0x08

typedef struct LC_CONFIG {
    // below are set by caller
    DWORD dwVersion;                        // must equal LC_CREATE_VERSION
    DWORD dwPrintfVerbosity;                // printf verbosity according to LC_PRINTF_*
    CHAR szDevice[MAX_PATH];                // device connection string - see wiki for additional info.
    CHAR szRemote[MAX_PATH];                // remote connection striLC_CONFIG_VERSIONng - see wiki for additional info.
    _Check_return_opt_ int(*pfn_printf_opt)(_In_z_ _Printf_format_string_ char const *const _Format, ...);
    // below are set by caller, updated by LeecCore
    QWORD paMax;                            // max physical address (disables any max address auto-detect).
    // below are set by LeechCore
    BOOL fVolatile;
    BOOL fWritable;
    BOOL fRemote;
    BOOL fRemoteDisableCompress;
    CHAR szDeviceName[MAX_PATH];            // device name - such as 'fpga' or 'file'.
} LC_CONFIG, *PLC_CONFIG;

typedef struct tdLC_CONFIG_ERRORINFO {
    DWORD dwVersion;                        // must equal LC_CONFIG_ERRORINFO_VERSION
    DWORD cbStruct;
    DWORD _FutureUse[16];
    BOOL fUserInputRequest;
    DWORD cwszUserText;
    WCHAR wszUserText[];
} LC_CONFIG_ERRORINFO, *PLC_CONFIG_ERRORINFO, **PPLC_CONFIG_ERRORINFO;

/*
* Create a new LeechCore device according to the supplied configuration.
* CALLER LcMemFree: ppLcCreateErrorInfo
* -- pLcCreateConfig
* -- ppLcCreateErrorInfo = ptr to receive function allocated struct with error
*       information upon function failure. This info may contain a user message
*       requesting user action as an example. Any returned struct should be
*       free'd by a call to LcMemFree().
* -- return
*/
_Success_(return != NULL)
EXPORTED_FUNCTION HANDLE LcCreate(
    _Inout_ PLC_CONFIG pLcCreateConfig
);

_Success_(return != NULL)
EXPORTED_FUNCTION HANDLE LcCreateEx(
    _Inout_ PLC_CONFIG pLcCreateConfig,
    _Out_opt_ PPLC_CONFIG_ERRORINFO ppLcCreateErrorInfo
);

/*
* Close a LeechCore handle and free any resources no longer needed.
*/
EXPORTED_FUNCTION VOID LcClose(
    _In_opt_ _Post_ptr_invalid_ HANDLE hLC
);



//-----------------------------------------------------------------------------
// Read and Write memory from underlying device either using contiguous method
// or more recommended scatter method.
//
// The MEM_SCATTER struct allows reading and writing of discontiguous memory
// chunks which must adhere to the following rules:
// - maximum size = 0x1000 (4096) bytes = recommended size.
// - minimum size = 2 DWORDs (8 bytes).
// - must be DWORD (4 byte) aligned.
// - must never cross 0x1000 page boundary.
// - max value of iStack = MEM_SCATTER_STACK_SIZE - 2.
//-----------------------------------------------------------------------------

#define MEM_SCATTER_VERSION                 0xc0fe0002
#define MEM_SCATTER_STACK_SIZE              12

typedef struct tdMEM_SCATTER {
    DWORD version;                          // MEM_SCATTER_VERSION
    BOOL f;                                 // TRUE = success data in pb, FALSE = fail or not yet read.
    QWORD qwA;                              // address of memory to read
    PBYTE pb;                               // buffer to hold memory contents
    DWORD cb;                               // size of buffer to hold memory contents.
    DWORD iStack;                           // internal stack pointer
    QWORD vStack[MEM_SCATTER_STACK_SIZE];   // internal stack
} MEM_SCATTER, *PMEM_SCATTER, **PPMEM_SCATTER;

#define MEM_SCATTER_ADDR_INVALID            ((QWORD)-1)
#define MEM_SCATTER_ADDR_ISINVALID(pMEM)    (pMEM->qwA == (QWORD)-1)
#define MEM_SCATTER_ADDR_ISVALID(pMEM)      (pMEM->qwA != (QWORD)-1)
#define MEM_SCATTER_STACK_PUSH(pMEM, v)     (pMEM->vStack[pMEM->iStack++] = (QWORD)v)
#define MEM_SCATTER_STACK_PEEK(pMEM, i)     (pMEM->vStack[pMEM->iStack - i])
#define MEM_SCATTER_STACK_SET(pMEM, i, v)   (pMEM->vStack[pMEM->iStack - i] = (QWORD)v)
#define MEM_SCATTER_STACK_ADD(pMEM, i, v)   (pMEM->vStack[pMEM->iStack - i] += (QWORD)v)
#define MEM_SCATTER_STACK_POP(pMEM)         (pMEM->vStack[--pMEM->iStack])

/*
* Free LeechCore allocated memory such as memory allocated by the
* LcAllocScatter / LcCommand functions.
* -- pv
*/
EXPORTED_FUNCTION VOID LcMemFree(
    _Frees_ptr_opt_ PVOID pv
);

/*
* Allocate and pre-initialize empty MEMs including a 0x1000 buffer for each
* pMEM. The result should be freed by LcFree when its no longer needed.
* -- cMEMs
* -- pppMEMs = pointer to receive ppMEMs
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcAllocScatter1(
    _In_ DWORD cMEMs,
    _Out_ PPMEM_SCATTER *pppMEMs
);

/*
* Allocate and pre-initialize empty MEMs excluding the 0x1000 buffer which
* will be accounted towards the pbData buffer in a contiguous way.
* The result should be freed by LcFree when its no longer needed.
* -- cbData = size of pbData (must be cMEMs * 0x1000)
* -- pbData = buffer used for MEM.pb
* -- cMEMs
* -- pppMEMs = pointer to receive ppMEMs
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcAllocScatter2(
    _In_ DWORD cbData,
    _Inout_updates_opt_(cbData) PBYTE pbData,
    _In_ DWORD cMEMs,
    _Out_ PPMEM_SCATTER *pppMEMs
);

/*
* Allocate and pre-initialize empty MEMs excluding the 0x1000 buffer which
* will be accounted towards the pbData buffer in a contiguous way.
* -- pbDataFirstPage = optional buffer of first page
* -- pbDataLastPage = optional buffer of last page
* -- cbData = size of pbData
* -- pbData = buffer used for MEM.pb except first/last if exists
* -- cMEMs
* -- pppMEMs = pointer to receive ppMEMs
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcAllocScatter3(
    _Inout_updates_opt_(0x1000) PBYTE pbDataFirstPage,
    _Inout_updates_opt_(0x1000) PBYTE pbDataLastPage,
    _In_ DWORD cbData,
    _Inout_updates_opt_(cbData) PBYTE pbData,
    _In_ DWORD cMEMs,
    _Out_ PPMEM_SCATTER *pppMEMs
);

/*
* Read memory in a scattered non-contiguous way. This is recommended for reads.
* -- hLC
* -- cMEMs
* -- ppMEMs
*/
EXPORTED_FUNCTION VOID LcReadScatter(
    _In_ HANDLE hLC,
    _In_ DWORD cMEMs,
    _Inout_ PPMEM_SCATTER ppMEMs
);

/*
* Read memory in a contiguous way. Note that if multiple memory segments are
* to be read LcReadScatter() may be more efficient.
* -- hLC,
* -- pa
* -- cb
* -- pb
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcRead(
    _In_ HANDLE hLC,
    _In_ QWORD pa,
    _In_ DWORD cb,
    _Out_writes_(cb) PBYTE pb
);

/*
* Write memory in a scattered non-contiguous way.
* -- hLC
* -- cMEMs
* -- ppMEMs
*/
EXPORTED_FUNCTION VOID LcWriteScatter(
    _In_ HANDLE hLC,
    _In_ DWORD cMEMs,
    _Inout_ PPMEM_SCATTER ppMEMs
);

/*
* Write memory in a contiguous way.
* -- hLC
* -- pa
* -- cb
* -- pb
* -- return
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcWrite(
    _In_ HANDLE hLC,
    _In_ QWORD pa,
    _In_ DWORD cb,
    _In_reads_(cb) PBYTE pb
);



//-----------------------------------------------------------------------------
// Get/Set/Command functionality may be used to query and/or update LeechCore
// or its devices in various ways.
//-----------------------------------------------------------------------------

#define LC_OPT_CORE_PRINTF_ENABLE                   0x4000000100000000  // RW
#define LC_OPT_CORE_VERBOSE                         0x4000000200000000  // RW
#define LC_OPT_CORE_VERBOSE_EXTRA                   0x4000000300000000  // RW
#define LC_OPT_CORE_VERBOSE_EXTRA_TLP               0x4000000400000000  // RW
#define LC_OPT_CORE_VERSION_MAJOR                   0x4000000500000000  // R
#define LC_OPT_CORE_VERSION_MINOR                   0x4000000600000000  // R
#define LC_OPT_CORE_VERSION_REVISION                0x4000000700000000  // R
#define LC_OPT_CORE_ADDR_MAX                        0x1000000800000000  // R

#define LC_OPT_MEMORYINFO_VALID                     0x0200000100000000  // R
#define LC_OPT_MEMORYINFO_FLAG_32BIT                0x0200000300000000  // R
#define LC_OPT_MEMORYINFO_FLAG_PAE                  0x0200000400000000  // R
#define LC_OPT_MEMORYINFO_OS_VERSION_MINOR          0x0200000500000000  // R
#define LC_OPT_MEMORYINFO_OS_VERSION_MAJOR          0x0200000600000000  // R
#define LC_OPT_MEMORYINFO_OS_DTB                    0x0200000700000000  // R
#define LC_OPT_MEMORYINFO_OS_PFN                    0x0200000800000000  // R
#define LC_OPT_MEMORYINFO_OS_PsLoadedModuleList     0x0200000900000000  // R
#define LC_OPT_MEMORYINFO_OS_PsActiveProcessHead    0x0200000a00000000  // R
#define LC_OPT_MEMORYINFO_OS_MACHINE_IMAGE_TP       0x0200000b00000000  // R
#define LC_OPT_MEMORYINFO_OS_NUM_PROCESSORS         0x0200000c00000000  // R
#define LC_OPT_MEMORYINFO_OS_SYSTEMTIME             0x0200000d00000000  // R
#define LC_OPT_MEMORYINFO_OS_UPTIME                 0x0200000e00000000  // R
#define LC_OPT_MEMORYINFO_OS_KERNELBASE             0x0200000f00000000  // R
#define LC_OPT_MEMORYINFO_OS_KERNELHINT             0x0200001000000000  // R
#define LC_OPT_MEMORYINFO_OS_KdDebuggerDataBlock    0x0200001100000000  // R

#define LC_OPT_FPGA_PROBE_MAXPAGES                  0x0300000100000000  // RW
#define LC_OPT_FPGA_MAX_SIZE_RX                     0x0300000300000000  // RW
#define LC_OPT_FPGA_MAX_SIZE_TX                     0x0300000400000000  // RW
#define LC_OPT_FPGA_DELAY_PROBE_READ                0x0300000500000000  // RW - uS
#define LC_OPT_FPGA_DELAY_PROBE_WRITE               0x0300000600000000  // RW - uS
#define LC_OPT_FPGA_DELAY_WRITE                     0x0300000700000000  // RW - uS
#define LC_OPT_FPGA_DELAY_READ                      0x0300000800000000  // RW - uS
#define LC_OPT_FPGA_RETRY_ON_ERROR                  0x0300000900000000  // RW
#define LC_OPT_FPGA_DEVICE_ID                       0x0300008000000000  // R
#define LC_OPT_FPGA_FPGA_ID                         0x0300008100000000  // R
#define LC_OPT_FPGA_VERSION_MAJOR                   0x0300008200000000  // R
#define LC_OPT_FPGA_VERSION_MINOR                   0x0300008300000000  // R
#define LC_OPT_FPGA_ALGO_TINY                       0x0300008400000000  // RW - 1/0 use tiny 128-byte/tlp read algorithm.
#define LC_OPT_FPGA_ALGO_SYNCHRONOUS                0x0300008500000000  // RW - 1/0 use synchronous (old) read algorithm.

#define LC_CMD_FPGA_WRITE_TLP                       0x0000010100000000  // R
#define LC_CMD_FPGA_LISTEN_TLP                      0x0000010200000000  // R
#define LC_CMD_FPGA_PCIECFGSPACE                    0x0000010300000000  // R
#define LC_CMD_FPGA_CFGREGPCIE                      0x0000010400000000  // RW - [lo-dword: register address]
#define LC_CMD_FPGA_CFGREGCFG                       0x0000010500000000  // RW - [lo-dword: register address]
#define LC_CMD_FPGA_CFGREGDRP                       0x0000010600000000  // RW - [lo-dword: register address]
#define LC_CMD_FPGA_CFGREGCFG_MARKWR                0x0000010700000000  // W  - write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask]
#define LC_CMD_FPGA_CFGREGPCIE_MARKWR               0x0000010800000000  // W  - write with mask [lo-dword: register address] [bytes: 0-1: data, 2-3: mask]
#define LC_CMD_FPGA_PCIECFGSPACE_WR                 0x0000010900000000  // W
#define LC_CMD_FPGA_CFGREG_DEBUGPRINT               0x0000010a00000000  // N/A
#define LC_CMD_FPGA_PROBE                           0x0000010b00000000  // RW

#define LC_CMD_FILE_DUMPHEADER_GET                  0x0000020100000000  // R

#define LC_CMD_STATISTICS_GET                       0x4000010000000000  // R
#define LC_CMD_MEMMAP_GET                           0x4000020000000000  // R
#define LC_CMD_MEMMAP_SET                           0x4000030000000000  // W

#define LC_CMD_AGENT_EXEC_PYTHON                    0x8000000100000000  // RW - [lo-dword: optional timeout in ms]
#define LC_CMD_AGENT_EXIT_PROCESS                   0x8000000200000000  // N/A - [lo-dword: process exit code]

#define LC_STATISTICS_VERSION                       0xe1a10002
#define LC_STATISTICS_ID_OPEN                       0x00
#define LC_STATISTICS_ID_READ                       0x01
#define LC_STATISTICS_ID_READSCATTER                0x02
#define LC_STATISTICS_ID_WRITE                      0x03
#define LC_STATISTICS_ID_WRITESCATTER               0x04
#define LC_STATISTICS_ID_GETOPTION                  0x05
#define LC_STATISTICS_ID_SETOPTION                  0x06
#define LC_STATISTICS_ID_COMMAND                    0x07
#define LC_STATISTICS_ID_MAX                        0x07

static LPCSTR LC_STATISTICS_NAME[] = {
    "LcOpen",
    "LcRead",
    "LcReadScatter",
    "LcWrite",
    "LcWriteScatter",
    "LcGetOption",
    "LcSetOption",
    "LcCommand",
};

typedef struct tdLC_STATISTICS {
    DWORD dwVersion;
    DWORD _Reserved;
    QWORD qwFreq;
    struct {
        QWORD c;
        QWORD tm;   // total time in qwFreq ticks
    } Call[LC_STATISTICS_ID_MAX + 1];
} LC_STATISTICS, *PLC_STATISTICS;

/*
* Set an option as defined by LC_OPT_*.  (R option).
* -- hLC
* -- fOption
* -- cbData
* -- pbData
* -- pcbData
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcGetOption(
    _In_ HANDLE hLC,
    _In_ QWORD fOption,
    _Out_ PQWORD pqwValue
);

/*
* Get an option as defined by LC_OPT_*.  (W option).
* -- hLC
* -- fOption
* -- cbData
* -- pbData
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcSetOption(
    _In_ HANDLE hLC,
    _In_ QWORD fOption,
    _In_ QWORD qwValue
);

/*
* Execute a command and retrieve a result (if any) at the same time.
* NB! If *ppbDataOut contains a memory allocation on exit this should be free'd
*     by calling LcMemFree().
* CALLER LcFreeMem: *ppbDataOut
* -- hLC
* -- fOption
* -- cbDataIn
* -- pbDataIn
* -- ppbDataOut
* -- pcbDataOut
*/
_Success_(return)
EXPORTED_FUNCTION BOOL LcCommand(
    _In_ HANDLE hLC,
    _In_ QWORD fOption,
    _In_ DWORD cbDataIn,
    _In_reads_opt_(cbDataIn) PBYTE pbDataIn,
    _Out_opt_ PBYTE *ppbDataOut,
    _Out_opt_ PDWORD pcbDataOut
);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __LEECHCORE_H__ */
