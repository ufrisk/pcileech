// pcileech.h : definitions for pcileech - dump memory and unlock computers with a USB3380 device using DMA.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
// Header Version: 4.5
//
#ifndef __PCILEECH_H__
#define __PCILEECH_H__
#include <leechcore.h>

#ifdef _WIN32
typedef unsigned __int64                    QWORD, *PQWORD;
#endif /* _WIN32 */
#ifdef LINUX
typedef uint16_t                            WORD, *PWORD, USHORT, *PUSHORT;
typedef long long unsigned int              QWORD, *PQWORD, ULONG64, *PULONG64;
#endif /* LINUX */

#define SIZE_PAGE_ALIGN_4K(x)                ((x + 0xfff) & ~0xfff)
#define CONFIG_MAX_SIGNATURES                16
#define PCILEECH_DEVICE_EQUALS(name)         (0 == _stricmp(ctxMain->dev.szDeviceName, name))

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
    DISPLAY,
    PAGEDISPLAY,
    TESTMEMREAD,
    TESTMEMREADWRITE,
    KMDLOAD,
    KMDEXIT,
    EXEC_KMD,
    EXEC_UMD,
    MOUNT,
    MAC_FVRECOVER,
    MAC_FVRECOVER2,
    MAC_DISABLE_VTD,
    PT_PHYS2VIRT,
    PT_VIRT2PHYS,
    TLP,
    TLPLOOP,
    PROBE,
    PSLIST,
    PSVIRT2PHYS,
    AGENT_EXEC_PY,
    EXTERNAL_COMMAND_MODULE
} ACTION_TYPE;

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
    CHAR szDevice[MAX_PATH];
    CHAR szRemote[MAX_PATH];
    CHAR szMemMap[MAX_PATH];
    CHAR szMemMapStr[2048];
    CHAR szFileOut[MAX_PATH];
    PBYTE pbIn;
    QWORD cbIn;
    CHAR szInS[MAX_PATH];
    QWORD qwDataIn[10];
    ACTION_TYPE tpAction;
    CHAR szSignatureName[MAX_PATH];
    CHAR szKMDName[MAX_PATH];
    CHAR szShellcodeName[MAX_PATH];
    CHAR szHook[MAX_PATH];
    DWORD dwListenTlpTimeMs;
    CHAR szExternalCommandModule[MAX_PATH];
    // flags below
    BOOL fPageTableScan;
    BOOL fPatchAll;
    BOOL fForceRW;
    BOOL fShowHelp;
    BOOL fOutFile;
    BOOL fVerbose;
    BOOL fVerboseExtra;
    BOOL fVerboseExtraTlp;
    BOOL fDebug;
    BOOL fPartialPageReadSupported;
    BOOL fAddrKMDSetByArgument;
    BOOL fLoop;
    BOOL fUserInteract;
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

#define PCILEECH_CONTEXT_MAGIC              0xfeefd00d
#define PCILEECH_CONTEXT_VERSION                  0x45

/*
* The main PCILeech context as found in the ctxMain global variable.
* Any external command module using this struct or any of its sub-
* structs must check the fields magic and version against the defines
* PCILEECH_CONTEXT_MAGIC and PCILEECH_CONTEXT_VERSION to determine
* compatibility before taking any actions on the struct.
*/
struct tdPCILEECH_CONTEXT {
    DWORD magic;
    DWORD version;
    CONFIG cfg;
    HANDLE hLC;
    LC_CONFIG dev;
    BOOL fVmmInitialized;
    HANDLE hDevice;
    PKMDHANDLE phKMD;
    PKMDDATA pk;
};

BOOL PCILeechConfigIntialize(_In_ DWORD argc, _In_ char* argv[]);
VOID PCILeechConfigFixup();
VOID PCILeechFreeContext();

// ----------------------------------------------------------------------------
// PCILeech global variables below:
// ----------------------------------------------------------------------------

extern PPCILEECH_CONTEXT ctxMain;

#endif /* __PCILEECH_H__ */
