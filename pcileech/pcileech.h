// pcileech.h : definitions for pcileech - dump memory and unlock computers with a USB3380 device using DMA.
//
// (c) Ulf Frisk, 2016-2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PCILEECH_H__
#define __PCILEECH_H__
#include "oscompatibility.h"

#define SIZE_PAGE_ALIGN_4K(x)                ((x + 0xfff) & ~0xfff)
#define CONFIG_MAX_SIGNATURES                16

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct tdSignaturePTE {
    WORD cPages;
    WORD wSignature;
} SIGNATUREPTE, *PSIGNATUREPTE;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

typedef struct tdPCILEECH_CONTEXT        PCILEECH_CONTEXT, *PPCILEECH_CONTEXT;

typedef enum tdActionType {
    NA,
    INFO,
    DUMP,
    WRITE,
    PATCH,
    SEARCH,
    USB3380_FLASH,
    USB3380_START8051,
    USB3380_STOP8051,
    DISPLAY,
    PAGEDISPLAY,
    TESTMEMREAD,
    TESTMEMREADWRITE,
    KMDLOAD,
    KMDEXIT,
    EXEC,
    MOUNT,
    MAC_FVRECOVER,
    MAC_FVRECOVER2,
    MAC_DISABLE_VTD,
    PT_PHYS2VIRT,
    PT_VIRT2PHYS,
    TLP,
    PROBE,
    IDENTIFY
} ACTION_TYPE;

typedef enum tdPCILEECH_DEVICE_TYPE {
    PCILEECH_DEVICE_NA,
    PCILEECH_DEVICE_USB3380,
    PCILEECH_DEVICE_FPGA,
    PCILEECH_DEVICE_SP605_TCP,
    PCILEECH_DEVICE_FILE
} PCILEECH_DEVICE_TYPE;

typedef struct tdDMA_IO_SCATTER_HEADER {
    QWORD qwA;              // base address (DWORD boundry).
    DWORD cbMax;            // bytes to read (DWORD boundry, max 0x1000); pbResult must have room for this.
    DWORD cb;               // bytes read into result buffer.
    PVOID pvReserved1;      // reserved for use by caller.
    PVOID pvReserved2;      // reserved for use by caller.
    PBYTE pb;               // ptr to 0x1000 sized buffer to receive read bytes.
} DMA_IO_SCATTER_HEADER, *PDMA_IO_SCATTER_HEADER, **PPDMA_IO_SCATTER_HEADER;

typedef struct tdDeviceConfig {
    QWORD qwMaxSizeDmaIo;
    QWORD qwAddrMaxNative;
    PCILEECH_DEVICE_TYPE tp;
    CHAR szFileNameOptTpFile[MAX_PATH];
    BOOL fPartialPageReadSupported;
    BOOL fScatterReadSupported;
    CRITICAL_SECTION LockDMA;
    BOOL(*pfnReadDMA)(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb);
    VOID(*pfnReadScatterDMA)(_Inout_ PPCILEECH_CONTEXT ctx, _Inout_ PPDMA_IO_SCATTER_HEADER ppDMAs, _In_ DWORD cpDMAs, _Out_opt_ PDWORD pcpDMAsRead);
    BOOL(*pfnWriteDMA)(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb);
    VOID(*pfnProbeDMA)(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_ __bcount(cPages) PBYTE pbResultMap);
    BOOL(*pfnWriteTlp)(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PBYTE pb, _In_ DWORD cb);
    BOOL(*pfnListenTlp)(_Inout_ PPCILEECH_CONTEXT ctx, _In_ DWORD dwTime);
    VOID(*pfnClose)(_Inout_ PPCILEECH_CONTEXT ctx);
} DEVICE_CONFIG;

typedef struct tdCONFIG_OPTION {
    QWORD isValid;
    QWORD qwValue;
} CONFIG_OPTION;

typedef struct tdConfig {
    QWORD qwAddrMin;
    QWORD qwAddrMax;
    QWORD qwCR3;
    QWORD qwEFI_IBI_SYST;
    QWORD qwKMD;
    CHAR szFileOut[MAX_PATH];
    PBYTE pbIn;
    QWORD cbIn;
    CHAR szInS[MAX_PATH];
    QWORD qwDataIn[10];
    CONFIG_OPTION DeviceOpt[4];
    ACTION_TYPE tpAction;
    CHAR szSignatureName[MAX_PATH];
    CHAR szKMDName[MAX_PATH];
    CHAR szShellcodeName[MAX_PATH];
    QWORD qwMaxSizeDmaIo;
    DWORD dwListenTlpTimeMs;
    DWORD TcpAddr;
    WORD TcpPort;
    // flags below
    BOOL fPageTableScan;
    BOOL fPatchAll;
    BOOL fForceRW;
    BOOL fShowHelp;
    BOOL fOutFile;
    BOOL fForceUsb2;        // USB3380
    BOOL fForcePCIeGen1;    // FPGA
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
    BOOL fDebug;
    BOOL fPartialPageReadSupported;
    BOOL fAddrKMDSetByArgument;
    // device information below
    DEVICE_CONFIG dev;
} CONFIG, *PCONFIG;

#define SIGNATURE_CHUNK_TP_OFFSET_FIXED     0
#define SIGNATURE_CHUNK_TP_OFFSET_RELATIVE  1
#define SIGNATURE_CHUNK_TP_OFFSET_ANY       2
typedef struct tdSignatureChunk {
    QWORD qwAddress;
    DWORD cbOffset;
    DWORD cb;
    BYTE tpOffset;
    BYTE pb[4096];
} SIGNATURE_CHUNK, *PSIGNATURE_CHUNK;

typedef struct tdSignature {
    // in unlock mode:
    //   chunk[0] = signature chunk 1 (required)
    //   chunk[1] = signature chunk 2 (optional)
    //   chunk[2] = patch chunk (required)
    //   chunk[3..5] = (not used)
    // in kmd mode:
    //   chunk[0] = signature 1/page 1/SHA256(page1) (required)
    //   chunk[1] = signature 2/page 2/SHA256(page2) (required)
    //   chunk[2] = shellcode 1
    //   chunk[3] = shellcode 2
    //   chunk[4] = shellcode 3
    //   chunk[5] = PTE signature (only needed in PTE mode)
    SIGNATURE_CHUNK chunk[6];
} SIGNATURE, *PSIGNATURE;

#define KMDEXEC_MAGIC 0x3cec1337
#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct tdKmdExec {
    DWORD dwMagic;
    BYTE pbChecksumSHA256[32];
    QWORD qwVersion;
    LPSTR szOutFormatPrintf;
    QWORD cbShellcode;
    PBYTE pbShellcode;
    QWORD filler[4];
} KMDEXEC, *PKMDEXEC;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

#define KMDDATA_OPERATING_SYSTEM_WINDOWS    0x01
#define KMDDATA_OPERATING_SYSTEM_LINUX      0x02
#define KMDDATA_OPERATING_SYSTEM_MACOS      0x04
#define KMDDATA_OPERATING_SYSTEM_FREEBSD    0x08
#define KMDDATA_OPERATING_SYSTEM_UEFI       0x10

#define KMDDATA_MAGIC                       0xff11337711333377
#define KMDDATA_MAGIC_PARTIAL               0xff11337711333388

#define KMD_CMD_VOID                        0xffff
#define KMD_CMD_COMPLETED                   0
#define KMD_CMD_READ                        1
#define KMD_CMD_WRITE                       2
#define KMD_CMD_TERMINATE                   3
#define KMD_CMD_MEM_INFO                    4
#define KMD_CMD_EXEC                        5
#define KMD_CMD_READ_VA                     6
#define KMD_CMD_WRITE_VA                    7
#define KMD_CMD_EXEC_EXTENDED               8

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page).
* This page/struct is used to communicate between the inserted kernel code and
* the pcileech program.
* VNR: 003
*/
typedef struct tdKMDDATA {
    QWORD MAGIC;                    // [0x000] magic number 0x0ff11337711333377.
    QWORD AddrKernelBase;           // [0x008] pre-filled by stage2, virtual address of kernel header (WINDOWS/MACOS).
    QWORD AddrKallsymsLookupName;   // [0x010] pre-filled by stage2, virtual address of kallsyms_lookup_name (LINUX).
    QWORD DMASizeBuffer;            // [0x018] size of DMA buffer.
    QWORD DMAAddrPhysical;          // [0x020] physical address of DMA buffer.
    QWORD DMAAddrVirtual;           // [0x028] virtual address of DMA buffer.
    QWORD _status;                  // [0x030] status of operation
    QWORD _result;                  // [0x038] result of operation TRUE|FALSE
    QWORD _address;                 // [0x040] address to operate on.
    QWORD _size;                    // [0x048] size of operation / data in DMA buffer.
    QWORD OperatingSystem;          // [0x050] operating system type
    QWORD ReservedKMD[8];           // [0x058] reserved for specific kmd data (dependant on KMD version).
    QWORD ReservedFutureUse1[13];   // [0x098] reserved for future use.
    QWORD dataInExtraLength;        // [0x100] length of extra in-data.
    QWORD dataInExtraOffset;        // [0x108] offset from DMAAddrPhysical/DMAAddrVirtual.
    QWORD dataInExtraLengthMax;     // [0x110] maximum length of extra in-data.
    QWORD dataInConsoleBuffer;      // [0x118] physical address of 1-page console buffer.
    QWORD dataIn[28];               // [0x120]
    QWORD dataOutExtraLength;       // [0x200] length of extra out-data.
    QWORD dataOutExtraOffset;       // [0x208] offset from DMAAddrPhysical/DMAAddrVirtual.
    QWORD dataOutExtraLengthMax;    // [0x210] maximum length of extra out-data.
    QWORD dataOutConsoleBuffer;     // [0x218] physical address of 1-page console buffer.
    QWORD dataOut[28];              // [0x220]
    PVOID fn[32];                   // [0x300] used by shellcode to store function pointers.
    CHAR dataInStr[MAX_PATH];       // [0x400] string in-data
    CHAR ReservedFutureUse2[252];
    CHAR dataOutStr[MAX_PATH];      // [0x600] string out-data
    CHAR ReservedFutureUse3[252];
    QWORD ReservedFutureUse4[255];  // [0x800]
    QWORD _op;                      // [0xFF8] (op is last 8 bytes in 4k-page)
} KMDDATA, *PKMDDATA;

typedef struct _PHYSICAL_MEMORY_RANGE {
    QWORD BaseAddress;
    QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef struct tdKMDHANDLE {
    DWORD dwPageAddr32;
    QWORD cPhysicalMap;
    PPHYSICAL_MEMORY_RANGE pPhysicalMap;
    PKMDDATA pk;
    BYTE pbPageData[4096];
} KMDHANDLE, *PKMDHANDLE;

struct tdPCILEECH_CONTEXT {
    PCONFIG cfg;
    HANDLE hDevice;
    HANDLE hVMM;
    PKMDHANDLE phKMD;
    PKMDDATA pk;
};

#endif /* __PCILEECH_H__ */
