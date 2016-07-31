// wx64_driverunload.c : kernel code to unload already loaded drivers.
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_driverunload.c
// ml64.exe wx64_common_a.asm /Fewx64_driverunload.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_driverunload.obj wx64_common.obj
// shellcode64 -o wx64_driverunload.exe "KERNEL MODULE UNLOADER - UNLOAD DRIVERS BY SERVICE NAME!             \n=====================================================================\nUnloads unsigned or signed drivers by registry service name.         \nNB! Unloading a driver may cause the system to become unstable and   \nmay trigger a bluescreen!                                            \nREQUIRED OPTIONS:                                                    \n  -s : service name.                                                 \n       Example:                                                      \n       "\Registry\Machine\System\CurrentControlSet\Services\mydriver"\n===== MODULE LOAD STATUS (RESULT) ===================================\nLOAD NTSTATUS : %s0x%08X                                             \n=====================================================================\n"
//  
#include "wx64_common.h"

//----------------------------------------------------------------------------------------------------------

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	ANSI_STRING saDriverServiceName;
	UNICODE_STRING suDriverServiceName;
	NTSTATUS(*fnZwUnloadDriver)(_In_ PUNICODE_STRING DriverServiceName);
	KERNEL_FUNCTIONS ofnk;
	// initialize kernel functions
	InitializeKernelFunctions(pk->AddrKernelBase, &ofnk);
	fnZwUnloadDriver = PEGetProcAddressH(pk->AddrKernelBase, H_ZwUnloadDriver);
	// try unload driver
	ofnk.RtlInitAnsiString(&saDriverServiceName, pk->dataInStr);
	ofnk.RtlAnsiStringToUnicodeString(&suDriverServiceName, &saDriverServiceName, TRUE);
	pk->dataOut[0] = fnZwUnloadDriver(&suDriverServiceName);
	ofnk.RtlFreeUnicodeString(&suDriverServiceName);
}