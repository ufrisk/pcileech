// uefi_common.h : declarations of commonly used shellcode functions
// Compatible with UEFI.
//
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __UEFI_COMMON_H__
#define __UEFI_COMMON_H__

#include "statuscodes.h"

#undef memset

typedef void					VOID, *PVOID;
typedef int						BOOL, *PBOOL;
typedef unsigned char			BYTE, *PBYTE;
typedef char					CHAR, *PCHAR;
typedef unsigned short			WCHAR, *PWCHAR;
typedef unsigned short			WORD, *PWORD;
typedef unsigned long			DWORD, *PDWORD;
typedef unsigned __int64		QWORD, *PQWORD;
typedef void					*HANDLE;
typedef unsigned long			STATUS;
#define NULL					((void *)0)
#define MAX_PATH				260
#define TRUE					1
#define FALSE					0
#define UNREFERENCED_PARAMETER(P) (P)
#define LOOKUP_FUNCTION(pk, szFn) (SysVCall(pk->AddrKallsymsLookupName, szFn))

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page)
* at the most. This data struct is used to communicate between the inserted
* kernel code and the DMA reader/writer.
* VNR: 002
*/
typedef struct tdKMDDATA {
	QWORD MAGIC;					// [0x000] magic number 0x0ff11337711333377.
	QWORD AddrKernelBase;			// [0x008] pre-filled by stage2, virtual address of KERNEL HEADER (WINDOWS/OSX).
	QWORD AddrKallsymsLookupName;	// [0x010] pre-filled by stage2, virtual address of kallsyms_lookup_name (LINUX).
	QWORD DMASizeBuffer;			// [0x018] size of DMA buffer.
	QWORD DMAAddrPhysical;			// [0x020] physical address of DMA buffer.
	QWORD DMAAddrVirtual;			// [0x028] virtual address of DMA buffer.
	QWORD _status;					// [0x030]
	QWORD _result;					// [0x038]
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
	QWORD dataOutExtraLength;		// [0x200] length of extra in-data.
	QWORD dataOutExtraOffset;		// [0x208] offset from DMAAddrPhysical/DMAAddrVirtual.
	QWORD dataOutExtraLengthMax;	// [0x210] maximum length of extra in-data. 
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

//-------------------------------------------------------------------------------
// UEFI functionality below:
//-------------------------------------------------------------------------------

typedef struct _EFI_GUID {
	DWORD d;
	WORD w[2];
	BYTE b[8];
} EFI_GUID;

extern QWORD GetMemoryMap(
	QWORD *MemoryMapSize,
	QWORD *MemoryMap,
	QWORD *MapKey,
	QWORD *DescriptorSize,
	QWORD *DescriptorVersion);

extern QWORD AllocatePages(
	QWORD Type,
	QWORD MemoryType,
	QWORD Pages,
	QWORD *Memory);

extern QWORD FreePages(
	QWORD Memory,
	QWORD Pages);

extern VOID SetMem(
	QWORD *Buffer,
	QWORD Size,
	QWORD Value);

extern VOID CopyMem(
	QWORD *Destination,
	QWORD *Source,
	QWORD Length);

extern QWORD LocateProtocol(
	EFI_GUID *Protocol,
	QWORD *Registration,
	QWORD **Interface);

#define EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL_GUID	{0xdd9e7534,0x7762,0x4698,{0x8c,0x14,0xf5,0x85,0x17,0xa6,0x25,0xaa}}
#define EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID	{0x387477c2,0x69c7,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}}

#define EFI_BLACK					0x00
#define EFI_BLUE					0x01
#define EFI_GREEN					0x02
#define EFI_CYAN					0x03
#define EFI_RED						0x04
#define EFI_MAGENTA					0x05
#define EFI_BROWN					0x06
#define EFI_LIGHTGRAY				0x07
#define EFI_BRIGHT					0x08
#define EFI_DARKGRAY				0x08
#define EFI_LIGHTBLUE				0x09
#define EFI_LIGHTGREEN				0x0A
#define EFI_LIGHTCYAN				0x0B
#define EFI_LIGHTRED				0x0C
#define EFI_LIGHTMAGENTA			0x0D
#define EFI_YELLOW					0x0E
#define EFI_WHITE					0x0F
#define EFI_BACKGROUND_BLACK		0x00
#define EFI_BACKGROUND_BLUE			0x10
#define EFI_BACKGROUND_GREEN		0x20
#define EFI_BACKGROUND_CYAN			0x30
#define EFI_BACKGROUND_RED			0x40
#define EFI_BACKGROUND_MAGENTA		0x50
#define EFI_BACKGROUND_BROWN		0x60
#define EFI_BACKGROUND_LIGHTGRAY	0x70

typedef struct _EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL {
	QWORD Reset;
	QWORD ReadKeyStrokeEx;
	QWORD WaitForKeyEx;
	QWORD SetState;
	QWORD RegisterKeyNotify;
	QWORD UnregisterKeyNotify;
} EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL;

typedef struct {
	DWORD MaxMode;
	// current settings
	DWORD Mode;
	DWORD Attribute;
	DWORD CursorColumn;
	DWORD CursorRow;
	BOOL CursorVisible;
} SIMPLE_TEXT_OUTPUT_MODE;

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
	QWORD Reset;
	QWORD(*OutputString)(QWORD *This, WCHAR *String);
	QWORD TestString;
	QWORD QueryMode;
	QWORD SetMode;
	QWORD(*SetAttribute)(QWORD *This, QWORD Attribute);
	QWORD(*ClearScreen)(QWORD *This);
	QWORD SetCursorPosition;
	QWORD EnableCursor;
	SIMPLE_TEXT_OUTPUT_MODE *Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

#endif /* __UEFI_COMMON_H__ */
