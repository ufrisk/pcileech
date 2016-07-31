// wx64_driverinfo.c : kernel code to list loaded drivers
// Compatible with Windows x64.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_driverinfo.c
// ml64 wx64_common_a.asm /Fewx64_driverinfo.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_driverinfo.obj wx64_common.obj
// shellcode64.exe -o wx64_driverinfo.exe "LOADED KERNEL MODULES AND INFORMATION                          \n===============================================================\nDEFAULT: listing of all kernel modules                         \n   Default listing is as follows:                              \n   BYTES      DATA                                             \n   0x00-17    module name                                      \n   0x18-1d    ----->                                           \n   0xe1-1f    module index                                     \nDETAILS: show detailed module information                      \n   Use -s <module_name> OR -0 0x<module_index> to show         \n   details for specific module.                                \n===== MODULE DETAILED INFORMATION =============================\nMODULE NAME   : %s                                             \nBASE ADDR VIRT: 0x%016llX                                      \nBASE ADDR PHYS: 0x%016llX                                      \nSIZE          : 0x%08X                                         \nFLAGS         : 0x%08X                                         \nLOAD COUNT    : 0x%04X                                         \nINDEX         : 0x%04X                                         \n===============================================================\nIN TOTAL %i ENTRIES EXISTS, SEE BELOW FOR MORE INFORMATION     \n(information not shown when module details are shown)\n"
//
#include "wx64_common.h"

VOID ActionDefault(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk)
{
	PBYTE pbSystemInfoBuffer;
	SIZE_T cbSystemInfoBuffer = 0;
	PSYSTEM_MODULE_INFORMATION_ENTRY pSME;
	QWORD b, i, j, qwAddrOut;
	fnk->ZwQuerySystemInformation(11, NULL, 0, (PULONG)&cbSystemInfoBuffer);
	if(!cbSystemInfoBuffer) { return; }
	pbSystemInfoBuffer = (PBYTE)fnk->ExAllocatePool(0, cbSystemInfoBuffer);
	if(!pbSystemInfoBuffer) { return; }
	if(0 == fnk->ZwQuerySystemInformation(SystemModuleInformation, pbSystemInfoBuffer, (ULONG)cbSystemInfoBuffer, (PULONG)&cbSystemInfoBuffer)) {
		pk->dataOut[6] = ((PSYSTEM_MODULE_INFORMATION)(pbSystemInfoBuffer))->Count;
		pSME = ((PSYSTEM_MODULE_INFORMATION)(pbSystemInfoBuffer))->Module;
		qwAddrOut = pk->DMAAddrVirtual + pk->dataOutExtraOffset + pk->dataOutExtraLength;
		for(i = 0; i < ((PSYSTEM_MODULE_INFORMATION)(pbSystemInfoBuffer))->Count; i++) {
			qwAddrOut = pk->DMAAddrVirtual + pk->dataOutExtraOffset + pk->dataOutExtraLength;
			pk->dataOutExtraLength += 0x20;
			b = 1;
			for(j = 0; j < 24; j++) {
				if(b) {
					b = *(PBYTE)(qwAddrOut + j) = pSME[i].ImageName[pSME[i].PathLength + j];
				} else {
					*(PBYTE)(qwAddrOut + j) = 0;
				}
			}
			*(PQWORD)(qwAddrOut + 0x18) = 0x00003e2d2d2d2d2d;
			*(PBYTE)(qwAddrOut + 0x1E) = pSME[i].Index >> 8;
			*(PBYTE)(qwAddrOut + 0x1F) = pSME[i].Index & 0xff;
		}
	}
	if(pbSystemInfoBuffer) { fnk->ExFreePool(pbSystemInfoBuffer); }
}

VOID ActionDetails(_In_ PKMDDATA pk, _In_ PKERNEL_FUNCTIONS fnk)
{
	PBYTE pbSystemInfoBuffer;
	SIZE_T cbSystemInfoBuffer = 0;
	PSYSTEM_MODULE_INFORMATION_ENTRY pSME;
	QWORD i;
	fnk->ZwQuerySystemInformation(11, NULL, 0, (PULONG)&cbSystemInfoBuffer);
	if(!cbSystemInfoBuffer) { return; }
	pbSystemInfoBuffer = (PBYTE)fnk->ExAllocatePool(0, cbSystemInfoBuffer);
	if(!pbSystemInfoBuffer) { return; }
	if(0 == fnk->ZwQuerySystemInformation(SystemModuleInformation, pbSystemInfoBuffer, (ULONG)cbSystemInfoBuffer, (PULONG)&cbSystemInfoBuffer)) {
		pSME = ((PSYSTEM_MODULE_INFORMATION)(pbSystemInfoBuffer))->Module;
		for(i = 0; i < ((PSYSTEM_MODULE_INFORMATION)(pbSystemInfoBuffer))->Count; i++) {
			if(0 == fnk->_stricmp(pk->dataInStr, pSME[i].ImageName + pSME[i].PathLength) ||
				(!pk->dataInStr[0] && pSME[i].Index == pk->dataIn[0])) {
				// image name
				fnk->RtlCopyMemory(pk->dataOutStr, pSME[i].ImageName + pSME[i].PathLength, MAX_PATH - pSME[i].PathLength);
				pk->dataOut[0] = pSME[i].Base;
				pk->dataOut[1] = fnk->MmGetPhysicalAddress(pSME[i].Base);
				pk->dataOut[2] = pSME[i].Size;
				pk->dataOut[3] = pSME[i].Flags;
				pk->dataOut[4] = pSME[i].LoadCount;
				pk->dataOut[5] = pSME[i].Index;
				goto cleanup;
			}
		}
	}
cleanup:
	if(pbSystemInfoBuffer) { fnk->ExFreePool(pbSystemInfoBuffer); }
}

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	KERNEL_FUNCTIONS fnk;
	InitializeKernelFunctions(pk->AddrKernelBase, &fnk);
	ActionDetails(pk, &fnk);
	if(!pk->dataIn[0] && !pk->dataInStr[0]) {
		ActionDefault(pk, &fnk);
	}
}