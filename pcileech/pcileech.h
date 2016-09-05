// pcileech.h : definitions for pcileech - dump memory and unlock computers with a USB3380 device using DMA.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __PCILEECH_H__
#define __PCILEECH_H__
#include <windows.h>
#include <stdio.h>
#include <winusb.h>
#include <setupapi.h>

#pragma comment (lib, "winusb.lib")
#pragma comment (lib, "setupapi.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "bcrypt.lib")

#pragma warning( disable : 4477)

#define CONFIG_MAX_SIGNATURES		        16
typedef unsigned __int64					QWORD;
typedef QWORD near							*PQWORD;

// Device Interface GUID. Must match "DeviceInterfaceGUIDs" registry value specified in the INF file.
// F72FE0D4-CBCB-407d-8814-9ED673D0DD6B
DEFINE_GUID(GUID_DEVINTERFACE_android, 0xF72FE0D4, 0xCBCB, 0x407d, 0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B);

typedef struct _DEVICE_DATA {
	BOOL HandlesOpen;
	BOOL IsAllowedMultiThreadDMA;
	BOOL IsAllowedAccessReservedAddress;
	WINUSB_INTERFACE_HANDLE WinusbHandle;
	HANDLE DeviceHandle;
	WCHAR DevicePath[MAX_PATH];
	UCHAR PipePciIn;
	UCHAR PipePciOut;
	UCHAR PipeCsrIn;
	UCHAR PipeCsrOut;
	UCHAR PipeDmaOut;	//GPEP0
	UCHAR PipeDmaIn1;	//GPEP1
	UCHAR PipeDmaIn2;	//GPEP2
	UCHAR PipeDmaIn3;	//GPEP3
	HANDLE KMDHandle;
} DEVICE_DATA, *PDEVICE_DATA;

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct tdPipeSendCsrWrite {
	UCHAR u1;
	UCHAR u2;
	UCHAR u3;
	UCHAR u4;
	DWORD dwRegValue;
} PIPE_SEND_CSR_WRITE;

typedef struct tdSignaturePTE {
	WORD cPages;
	WORD wSignature;
} SIGNATUREPTE, *PSIGNATUREPTE;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

typedef enum tdActionType {
	NA,
	INFO,
	DUMP,
	WRITE,
	PATCH,
	SEARCH,
	FLASH,
	START8051,
	STOP8051,
	PAGEDISPLAY,
	TESTMEMREAD,
	TESTMEMREADWRITE,
	KMDLOAD,
	KMDEXIT,
	EXEC
} ACTION_TYPE, PACTION_TYPE;

#define CONFIG_MAX_INSIZE 0x400000 // 4MB
typedef struct tdConfig {
	QWORD qwAddrMin;
	QWORD qwAddrMax;
	QWORD qwCR3;
	QWORD qwKMD;
	CHAR szFileOut[MAX_PATH];
	BYTE  pbIn[CONFIG_MAX_INSIZE]; 
	QWORD cbIn;
	CHAR szInS[MAX_PATH];
	QWORD qwDataIn[10];
	ACTION_TYPE tpAction;
	CHAR szSignatureName[MAX_PATH];
	CHAR szKMDName[MAX_PATH];
	CHAR szShellcodeName[MAX_PATH];
	BOOL fPageStat;
	BOOL fPageTableScan;
	BOOL fPatchAll;
	BOOL fForceRW;
	BOOL fShowHelp;
} CONFIG, *PCONFIG;

typedef struct tdPageStatistics {
	QWORD cPageTotal;
	QWORD cPageSuccess;
	QWORD cPageFail;
	QWORD qwTickCountStart;
	BOOL isAccessModeKMD;
	LPSTR szCurrentAction;
} PAGE_STATISTICS, *PPAGE_STATISTICS;

#define SIGNATURE_CHUNK_TP_OFFSET_FIXED		0
#define SIGNATURE_CHUNK_TP_OFFSET_RELATIVE	1
#define SIGNATURE_CHUNK_TP_OFFSET_ANY		2
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

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
#define KMDEXEC_MAGIC 0x3cec1337
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

VOID ShowUpdatePageRead(_In_ PCONFIG pCfg, _In_ QWORD qwCurrentAddress, _Inout_ PPAGE_STATISTICS pPageStat);

#endif /* __PCILEECH_H__ */