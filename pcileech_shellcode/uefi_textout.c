// uefi_textout.c : prints some text on the screen.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel uefi_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel uefi_textout.c
// ml64.exe uefi_common_a.asm /Feuefi_textout.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main uefi_textout.obj uefi_common.obj
// shellcode64.exe -o uefi_textout.exe "UEFI TEST PROGRAM - PRINT STUFF ON THE SCREEN\n===========================================================\nSyntax: pcileech.exe -s <text_to_print>\nGENERAL INFORMATION BELOW:\n  TEXT      : %s\n"
//
#include "uefi_common.h"

VOID c_EntryPoint(PKMDDATA pk)
{
	WCHAR szPrint[MAX_PATH];
	CHAR *szSrc, szPrintDefault[] = { ' ', ' ', ' ', 'U', 'E', 'F', 'I', ' ', 'E', 'V', 'I', 'L', ' ', 'I', 'N', ' ', 'B', 'O', 'O', 'T', ' ', 'S', 'E', 'R', 'V', 'I', 'C', 'E', 'S', '!', ' ', ' ', ' ', 0 };
	EFI_GUID GUID_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL = EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID;
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL oOut;
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *pOut = &oOut;
	QWORD i, efi_status;
	szSrc = pk->dataInStr[0] ? pk->dataInStr : szPrintDefault;
	for(i = 0; i < MAX_PATH - 1; i++) {
		// read overflow here if default, but doesn't matter...
		szPrint[i] = szSrc[i];
		pk->dataOutStr[i] = szSrc[i];
	}
	pk->dataOut[0] = efi_status = LocateProtocol(&GUID_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL, NULL, (QWORD**)&pOut);
	if(!efi_status) {
		pOut->SetAttribute((QWORD*)pOut, EFI_BACKGROUND_RED | EFI_CYAN);
		pOut->OutputString((QWORD*)pOut, szPrint);
	}
}
