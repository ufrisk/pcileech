// lx64_common.h : declarations of commonly used shellcode functions
// Compatible with Linux x64.
//
// Author: Ulf Frisk, pcileech@frizk.net
//

#ifndef __LX64_COMMON_H__
#define __LX64_COMMON_H__

#include "statuscodes.h"

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

extern QWORD SysVCall(QWORD fn, ...);
extern QWORD WinCall(QWORD p1, ...);
extern VOID WinCallSetFunction(QWORD pfn);
extern BOOL  LookupFunctions(QWORD qwAddr_KallsymsLookupName, QWORD pqwNameTable, QWORD pqwFnTable, QWORD cFunctions);
extern QWORD m_phys_to_virt(QWORD p1);
extern QWORD m_page_to_phys(QWORD p1);
extern VOID CacheFlush();

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

#define EXEC_IO_MAGIC					0x12651232dfef9521
#define EXEC_IO_CONSOLE_BUFFER_SIZE		0x800
#define EXEC_IO_DMAOFFSET_IS			0x80000
#define EXEC_IO_DMAOFFSET_OS			0x81000
typedef struct tdEXEC_IO {
	QWORD magic;
	struct {
		QWORD cbRead;
		QWORD cbReadAck;
		QWORD Reserved[10];
		BYTE  pb[800];
	} con;
	struct {
		QWORD seq;
		QWORD seqAck;
		QWORD fCompleted;
		QWORD fCompletedAck;
	} bin;
	QWORD Reserved[395];
} EXEC_IO, *PEXEC_IO;

/*
* If a large output is to be written to PCILeech which won't fit in the DMA
* buffer - write as much as possible in the DMA buffer and then call this fn.
* When returned successfully write another chunk to this buffer and call again.
* WriteLargeOutput_Finish must be called after all data is written to clean up.
* -- pk
* -- return
*/
BOOL WriteLargeOutput_WaitNext(PKMDDATA pk);

/*
* Clean up function that must be called if WriteLargeOutput_WaitNext has
* previously been called.
* -- pk
*/
VOID WriteLargeOutput_Finish(PKMDDATA pk);

#endif /* __LX64_COMMON_H__ */