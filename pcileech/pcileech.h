// pcileech.h : definitions for pcileech - dump memory and unlock computers with a USB3380 device using DMA.
//
// (c) Ulf Frisk, 2016, 2017
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

#define SIZE_PAGE_ALIGN_4K(x)				((x + 0xfff) & ~0xfff)
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
	QWORD MaxSizeDmaIo;
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
	EXEC,
	MOUNT,
	MAC_FVRECOVER,
	PT_PHYS2VIRT
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
	QWORD qwMaxSizeDmaIo;
	BOOL fPageTableScan;
	BOOL fPatchAll;
	BOOL fForceRW;
	BOOL fShowHelp;
	BOOL fOutFile;
	BOOL fForceUsb2;
	BOOL fVerbose;
} CONFIG, *PCONFIG;

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

#define KMDDATA_OPERATING_SYSTEM_WINDOWS		0x01
#define KMDDATA_OPERATING_SYSTEM_LINUX			0x02
#define KMDDATA_OPERATING_SYSTEM_MACOS			0x04
#define KMDDATA_OPERATING_SYSTEM_FREEBSD		0x08

#define KMDDATA_MAGIC							0xff11337711333377
#define KMDDATA_MAGIC_PARTIAL					0xff11337711333388

#define KMD_CMD_VOID							0xffff
#define KMD_CMD_COMPLETED						0
#define KMD_CMD_READ							1
#define KMD_CMD_WRITE							2
#define KMD_CMD_TERMINATE						3
#define KMD_CMD_MEM_INFO						4
#define KMD_CMD_EXEC							5
#define KMD_CMD_READ_VA							6
#define KMD_CMD_WRITE_VA						7
#define KMD_CMD_EXEC_EXTENDED					8

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page).
* This page/struct is used to communicate between the inserted kernel code and
* the pcileech program.
* VNR: 002
*/
typedef struct tdKMDDATA {
	QWORD MAGIC;					// [0x000] magic number 0x0ff11337711333377.
	QWORD AddrKernelBase;			// [0x008] pre-filled by stage2, virtual address of kernel header (WINDOWS/MACOS).
	QWORD AddrKallsymsLookupName;	// [0x010] pre-filled by stage2, virtual address of kallsyms_lookup_name (LINUX).
	QWORD DMASizeBuffer;			// [0x018] size of DMA buffer.
	QWORD DMAAddrPhysical;			// [0x020] physical address of DMA buffer.
	QWORD DMAAddrVirtual;			// [0x028] virtual address of DMA buffer.
	QWORD _status;					// [0x030] status of operation
	QWORD _result;					// [0x038] result of operation TRUE|FALSE
	QWORD _address;					// [0x040] virtual address to operate on.
	QWORD _size;					// [0x048] size of operation / data in DMA buffer.
	QWORD OperatingSystem;			// [0x050] operating system type
	QWORD ReservedKMD;				// [0x058] reserved for specific kmd data (dependant on KMD version).
	QWORD ReservedFutureUse1[20];	// [0x060] reserved for future use.
	QWORD dataInExtraLength;		// [0x100] length of extra in-data.
	QWORD dataInExtraOffset;		// [0x108] offset from DMAAddrPhysical/DMAAddrVirtual.
	QWORD dataInExtraLengthMax;		// [0x110] maximum length of extra in-data. 
	QWORD dataInConsoleBuffer;		// [0x118] physical address of 1-page console buffer.
	QWORD dataIn[28];				// [0x120]
	QWORD dataOutExtraLength;		// [0x200] length of extra out-data.
	QWORD dataOutExtraOffset;		// [0x208] offset from DMAAddrPhysical/DMAAddrVirtual.
	QWORD dataOutExtraLengthMax;	// [0x210] maximum length of extra out-data. 
	QWORD dataOutConsoleBuffer;		// [0x218] physical address of 1-page console buffer.
	QWORD dataOut[28];				// [0x220]
	PVOID fn[32];					// [0x300] used by shellcode to store function pointers.
	CHAR dataInStr[MAX_PATH];		// [0x400] string in-data
	CHAR ReservedFutureUse2[252];
	CHAR dataOutStr[MAX_PATH];		// [0x600] string out-data
	CHAR ReservedFutureUse3[252];
	QWORD ReservedFutureUse4[255];	// [0x800]
	QWORD _op;						// [0xFF8] (op is last 8 bytes in 4k-page)
} KMDDATA, *PKMDDATA;

typedef struct _PHYSICAL_MEMORY_RANGE {
	QWORD BaseAddress;
	QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

typedef struct tdKMDHANDLE {
	DWORD dwPageAddr32;
	QWORD cPhysicalMap;
	PPHYSICAL_MEMORY_RANGE pPhysicalMap;
	PKMDDATA status;
	BYTE pbPageData[4096];
} KMDHANDLE, *PKMDHANDLE;

#endif /* __PCILEECH_H__ */