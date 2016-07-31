// cpuflash.c : implementation related to 8051 CPU and EEPROM flashing.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "cpuflash.h"
#include "device.h"

VOID ActionFlash(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	BOOL result;
	printf("Flashing firmware ... \n");
	if(!pCfg->cbIn || pCfg->cbIn > 32768) {
		printf("Flash failed: failed to open file or invalid size\n");
		return;
	}
	if(pCfg->pbIn[0] != 0x5a || *(WORD*)(pCfg->pbIn + 2) > (DWORD)pCfg->cbIn - 1) {
		printf("Flash failed: invalid firmware signature or size\n");
		return;
	}
	result = DeviceFlashEEPROM(pDeviceData, pCfg->pbIn, (DWORD)pCfg->cbIn);
	if(!result) {
		printf("Flash failed: failed to write firmware to device\n");
		return;
	}
	printf("SUCCESS!\n");
}

VOID Action8051Start(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	BOOL result;
	printf("Loading 8051 executable and starting ... \n");
	if(!pCfg->cbIn || pCfg->cbIn > 32768) {
		printf("8051 startup failed: failed to open file or invalid size\n");
		return;
	}
	result = Device8051Start(pDeviceData, pCfg->pbIn, (DWORD)pCfg->cbIn);
	if(!result) {
		printf("8051 startup failed: failed to write executable to device or starting 8051\n");
		return;
	}
	printf("SUCCESS!\n");
}

VOID Action8051Stop(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	printf("Stopping 8051 ... \n");
	Device8051Stop(pDeviceData);
	printf("SUCCESS!\n");
}