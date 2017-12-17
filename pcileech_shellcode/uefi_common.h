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
typedef char					CHAR, *PCHAR, *LPSTR;
typedef unsigned short			WCHAR, *PWCHAR;
typedef unsigned short			WORD, *PWORD;
typedef unsigned long			DWORD, *PDWORD, LONG;
typedef __int64					LONGLONG;
typedef unsigned __int64		QWORD, *PQWORD, ULONGLONG;
typedef void					*HANDLE;
typedef unsigned long			STATUS;
#define NULL					((void *)0)
#define MAX_PATH				260
#define TRUE					1
#define FALSE					0
#define UNREFERENCED_PARAMETER(P) (P)
#define LOOKUP_FUNCTION(pk, szFn) (SysVCall(pk->AddrKallsymsLookupName, szFn))
#define min(a, b)				((a < b) ? a : b)
#define max(a, b)				((a > b) ? a : b)

/*
* KMD DATA struct. This struct must be contained in a 4096 byte section (page).
* This page/struct is used to communicate between the inserted kernel code and
* the pcileech program.
* VNR: 003
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
	QWORD _address;					// [0x040] address to operate on.
	QWORD _size;					// [0x048] size of operation / data in DMA buffer.
	QWORD OperatingSystem;			// [0x050] operating system type
	QWORD ReservedKMD[8];			// [0x058] reserved for specific kmd data (dependant on KMD version).
	QWORD ReservedFutureUse1[13];	// [0x098] reserved for future use.
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
	VOID *Destination,
	VOID *Source,
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
	QWORD(*Reset)(QWORD *This, QWORD *ExtendedVerification);
	QWORD(*OutputString)(QWORD *This, WCHAR *String);
	QWORD(*TestString)(QWORD *This, WCHAR *String);
	QWORD(*QueryMode)(QWORD *This, QWORD ModeNumber, QWORD *Columns, QWORD *Rows);
	QWORD(*SetMode)(QWORD *This, QWORD ModeNumber);
	QWORD(*SetAttribute)(QWORD *This, QWORD Attribute);
	QWORD(*ClearScreen)(QWORD *This);
	QWORD(*SetCursorPosition)(QWORD *This, QWORD Column, QWORD Row);
	QWORD(*EnableCursor)(QWORD *This, QWORD Visible);
	SIMPLE_TEXT_OUTPUT_MODE *Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

//-------------------------------------------------------------------------------
// PE / Windows defines below:
//-------------------------------------------------------------------------------

#define IMAGE_DIRECTORY_ENTRY_EXPORT        0			// Export Directory
#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define PIMAGE_NT_HEADERS					PIMAGE_NT_HEADERS64

typedef struct _IMAGE_DOS_HEADER {
	WORD   e_magic;
	WORD   e_cblp;
	WORD   e_cp;
	WORD   e_crlc;
	WORD   e_cparhdr;
	WORD   e_minalloc;
	WORD   e_maxalloc;
	WORD   e_ss;
	WORD   e_sp;
	WORD   e_csum;
	WORD   e_ip;
	WORD   e_cs;
	WORD   e_lfarlc;
	WORD   e_ovno;
	WORD   e_res[4];
	WORD   e_oemid;
	WORD   e_oeminfo;
	WORD   e_res2[10];
	LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;
	DWORD   AddressOfNames;
	DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#endif /* __UEFI_COMMON_H__ */
