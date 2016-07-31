// lx64_common.h : declarations of commonly used shellcode functions
// Compatible with Linux x64.
//
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __LX64_COMMON_H__
#define __LX64_COMMON_H__

typedef void					VOID, *PVOID;
typedef int						BOOL, *PBOOL;
typedef unsigned char			BYTE, *PBYTE;
typedef char					CHAR, *PCHAR;
typedef unsigned short			WORD, *PWORD;
typedef unsigned long			DWORD, *PDWORD;
typedef unsigned __int64		QWORD, *PQWORD;
typedef void					*HANDLE;
typedef unsigned long			STATUS;
#define NULL					((void *)0)
#define MAX_PATH				260
#define TRUE					1
#define FALSE					0

extern QWORD SysVCall(QWORD fn, ...);
extern BOOL  LookupFunctions(QWORD qwAddr_KallsymsLookupName, QWORD pqwNameTable, QWORD pqwFnTable, QWORD cFunctions);
extern QWORD m_phys_to_virt(QWORD p1);
extern QWORD m_page_to_phys(QWORD p1);

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

#define STATUS_FAIL_FUNCTION_LOOKUP			0xf0000001
#define STATUS_FAIL_FILE_CANNOT_OPEN		0xf0000002
#define STATUS_FAIL_FILE_SIZE				0xf0000003
#define STATUS_FAIL_INPPARAMS_BAD			0xf0000004
#define STATUS_FAIL_ACTION					0xf0000005

#endif /* __LX64_COMMON_H__ */