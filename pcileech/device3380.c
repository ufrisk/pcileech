// device.c : implementation related to the USB3380 hardware device.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device3380.h"
#include "device.h"

#define CSR_BYTE0							0x01
#define CSR_BYTE1							0x02
#define CSR_BYTE2							0x04
#define CSR_BYTE3							0x08
#define CSR_BYTEALL							0x0f
#define CSR_CONFIGSPACE_PCIE				0x00
#define CSR_CONFIGSPACE_MEMM				0x10
#define CSR_CONFIGSPACE_8051				0x20
#define REG_USBSTAT							0x90
#define REG_USBCTL2							0xc8
#define REG_DMACTL_0						0x180
#define REG_DMASTAT_0						0x184
#define REG_DMACOUNT_0						0x190
#define REG_DMAADDR_0						0x194
#define REG_FIFOSTAT_0						0x32c
#define REG_DMACTL_1						0x1a0
#define REG_DMASTAT_1						0x1a4
#define REG_DMACOUNT_1						0x1b0
#define REG_DMAADDR_1						0x1b4
#define REG_DMACTL_2						0x1c0
#define REG_DMASTAT_2						0x1c4
#define REG_DMACOUNT_2						0x1d0
#define REG_DMAADDR_2						0x1d4
#define REG_DMACTL_3						0x1e0
#define REG_DMASTAT_3						0x1e4
#define REG_DMACOUNT_3						0x1f0
#define REG_DMAADDR_3						0x1f4
#define REG_PCI_STATCMD						0x04
#define USB_EP_PCIIN						0x8e
#define USB_EP_PCIOUT						0x0e
#define USB_EP_CSRIN						0x8d
#define USB_EP_CSROUT						0x0d
#define USB_EP_DMAOUT						0x02
#define USB_EP_DMAIN1						0x84
#define USB_EP_DMAIN2						0x86
#define USB_EP_DMAIN3						0x88

typedef struct _DEVICE_DATA {
	BOOL HandlesOpen;
	BOOL IsAllowedMultiThreadDMA;
	QWORD MaxSizeDmaIo;
	WINUSB_INTERFACE_HANDLE WinusbHandle;
	HANDLE DeviceHandle;
	WCHAR DevicePath[MAX_PATH];
} DEVICE_DATA, *PDEVICE_DATA;

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct tdPipeSendCsrWrite {
	UCHAR u1;
	UCHAR u2;
	UCHAR u3;
	UCHAR u4;
	DWORD dwRegValue;
} PIPE_SEND_CSR_WRITE;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

typedef struct tdEP_INFO {
	UCHAR pipe;
	WORD rCTL;
	WORD rSTAT;
	WORD rCOUNT;
	WORD rADDR;
} EP_INFO, *PEP_INFO;

EP_INFO CEP_INFO[3] = {
	{ .pipe = USB_EP_DMAIN1,.rCTL = REG_DMACTL_1,.rSTAT = REG_DMASTAT_1,.rCOUNT = REG_DMACOUNT_1,.rADDR = REG_DMAADDR_1 },
	{ .pipe = USB_EP_DMAIN2,.rCTL = REG_DMACTL_2,.rSTAT = REG_DMASTAT_2,.rCOUNT = REG_DMACOUNT_2,.rADDR = REG_DMAADDR_2 },
	{ .pipe = USB_EP_DMAIN3,.rCTL = REG_DMACTL_3,.rSTAT = REG_DMASTAT_3,.rCOUNT = REG_DMACOUNT_3,.rADDR = REG_DMAADDR_3 }
};

typedef struct tdThreadDataReadEP {
	PDEVICE_DATA pDeviceData;
	QWORD qwAddr;
	PBYTE pb;
	DWORD cb;
	BOOL isFinished;
	BOOL result;
	PEP_INFO pep;
} THREAD_DATA_READ_EP, *PTHREAD_DATA_READ_EP;

typedef struct _DEVICE_MEMORY_RANGE {
	DWORD BaseAddress;
	DWORD TopAddress;
} DEVICE_MEMORY_RANGE, *PDEVICE_MEMORY_RANGE;

#define NUMBER_OF_DEVICE_RESERVED_MEMORY_RANGES 2
DEVICE_MEMORY_RANGE CDEVICE_RESERVED_MEMORY_RANGES[NUMBER_OF_DEVICE_RESERVED_MEMORY_RANGES] = {
	{ .BaseAddress = 0x000A0000,.TopAddress = 0x000FFFFF }, // SMM LOWER
	{ .BaseAddress = 0xF0000000,.TopAddress = 0xFFFFFFFF }, // PCI SPACE
};

BOOL Device3380_IsInReservedMemoryRange(_In_ QWORD qwAddr, _In_ DWORD cb)
{
	DWORD i;
	PDEVICE_MEMORY_RANGE pmr;
	for(i = 0; i < NUMBER_OF_DEVICE_RESERVED_MEMORY_RANGES; i++) {
		pmr = &CDEVICE_RESERVED_MEMORY_RANGES[i];
		if(!((qwAddr > pmr->TopAddress) || (qwAddr + cb <= pmr->BaseAddress))) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL Device3380_WriteCsr(_In_ PDEVICE_DATA pDeviceData, _In_ WORD wRegAddr, _In_ DWORD dwRegValue, _In_ BYTE fCSR)
{
	DWORD cbTransferred;
	PIPE_SEND_CSR_WRITE ps = { .u1 = fCSR | 0x40, .u2 = 0, .u3 = wRegAddr & 0xFF, .u4 = (wRegAddr >> 8) & 0xFF, .dwRegValue = dwRegValue };
	if(wRegAddr & 0x03) { return FALSE; } // must be dword aligned
	return WinUsb_WritePipe(pDeviceData->WinusbHandle, USB_EP_CSROUT, (PUCHAR)&ps, sizeof(ps), &cbTransferred, NULL);
}

BOOL Device3380_ReadCsr(_In_ PDEVICE_DATA pDeviceData, _In_ WORD wRegAddr, _Out_ PDWORD pdwRegValue, _In_ BYTE fCSR)
{
	DWORD cbTransferred;
	PIPE_SEND_CSR_WRITE ps = { .u1 = fCSR | 0xcf, .u2 = 0, .u3 = wRegAddr & 0xff, .u4 = (wRegAddr >> 8) & 0xff, .dwRegValue = 0 };
	if(wRegAddr & 0x03) { return FALSE; } // must be dword aligned
	return
		WinUsb_WritePipe(pDeviceData->WinusbHandle, USB_EP_CSROUT, (PUCHAR)&ps, sizeof(ps), &cbTransferred, NULL) &&
		WinUsb_ReadPipe(pDeviceData->WinusbHandle, USB_EP_CSRIN, (PUCHAR)pdwRegValue, 4, &cbTransferred, NULL);
}

BOOL Device3380_ReadDMA_Retry(PTHREAD_DATA_READ_EP ptd)
{
	BOOL result;
	DWORD cbTransferred;
	Device3380_WriteCsr(ptd->pDeviceData, ptd->pep->rCTL, 0xc2, CSR_CONFIGSPACE_MEMM | CSR_BYTE0); // DMA_ENABLE
	Device3380_WriteCsr(ptd->pDeviceData, ptd->pep->rADDR, (DWORD)ptd->qwAddr, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
	Device3380_WriteCsr(ptd->pDeviceData, ptd->pep->rCOUNT, 0x40000000 | ptd->cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
	Device3380_WriteCsr(ptd->pDeviceData, ptd->pep->rSTAT, 0x080000c1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
	Device3380_WriteCsr(ptd->pDeviceData, REG_PCI_STATCMD, 0x07, CSR_CONFIGSPACE_PCIE | CSR_BYTE0); // BUS_MASTER ??? needed ???
	result = WinUsb_ReadPipe(ptd->pDeviceData->WinusbHandle, ptd->pep->pipe, ptd->pb, ptd->cb, &cbTransferred, NULL);
	return result;
}

VOID Device3380_ReadDMA2(PTHREAD_DATA_READ_EP ptd)
{
	DWORD dwTimeout, cbTransferred;
	if(ptd->cb > ptd->pDeviceData->MaxSizeDmaIo) {
		ptd->result = FALSE;
		ptd->isFinished = TRUE;
		return;
	}
	// set EP timeout value on conservative usb2 assumptions (3 parallel reads, 35MB/s total speed)
	// (XMB * 1000 * 3) / (35 * 1024 * 1024) -> 0x2fc9 ~> 0x3000 :: 4k->64ms, 5.3M->520ms
	dwTimeout = 64 + ptd->cb / 0x3000;
	WinUsb_SetPipePolicy(ptd->pDeviceData->WinusbHandle, ptd->pep->pipe, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &dwTimeout);
	// perform memory read
	Device3380_WriteCsr(ptd->pDeviceData, ptd->pep->rADDR, (DWORD)ptd->qwAddr, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
	Device3380_WriteCsr(ptd->pDeviceData, ptd->pep->rCOUNT, 0x40000000 | ptd->cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
	Device3380_WriteCsr(ptd->pDeviceData, ptd->pep->rSTAT, 0x080000c1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
	ptd->result = WinUsb_ReadPipe(ptd->pDeviceData->WinusbHandle, ptd->pep->pipe, ptd->pb, ptd->cb, &cbTransferred, NULL);
	if(!ptd->result) {
		ptd->result = Device3380_ReadDMA_Retry(ptd);
	}
	ptd->isFinished = TRUE;
}

BOOL Device3380_ReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
	THREAD_DATA_READ_EP td[3];
	DWORD i, dwChunk;
	PDEVICE_DATA pDeviceData = (PDEVICE_DATA)ctx->hDevice;
	if(cb % 0x1000) { return FALSE; }
	if(cb > 0x01000000) { return FALSE; }
	if(qwAddr + cb > 0x100000000) { return FALSE; }
	if(Device3380_IsInReservedMemoryRange(qwAddr, cb) && !ctx->cfg->fForceRW) { return FALSE; }
	ZeroMemory(td, sizeof(THREAD_DATA_READ_EP) * 3);
	if(cb < 0x3000 || !pDeviceData->IsAllowedMultiThreadDMA) {
		if(cb > 0x00800000) { // read max 8MB at a time.
			return
				Device3380_ReadDMA(ctx, qwAddr, pb, 0x00800000) &&
				Device3380_ReadDMA(ctx, qwAddr + 0x00800000, pb + 0x00800000, cb - 0x00800000);
		}
		td[0].pDeviceData = pDeviceData;
		td[0].pep = &CEP_INFO[0];
		td[0].qwAddr = qwAddr;
		td[0].pb = pb;
		td[0].cb = cb;
		Device3380_ReadDMA2(&td[0]);
		return td[0].result;
	} else {
		dwChunk = (cb / 3) & 0xfffff000;
		for(i = 0; i < 3; i++) {
			td[i].pDeviceData = pDeviceData;
			td[i].pep = &CEP_INFO[i];
			td[i].qwAddr = qwAddr; qwAddr += dwChunk;
			td[i].pb = pb; pb += dwChunk;
			if(i == 2) {
				td[i].cb = cb - 2 * dwChunk;
				Device3380_ReadDMA2(&td[i]);
			}
			else {
				td[i].cb = dwChunk;
				CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Device3380_ReadDMA2, &td[i], 0, NULL);
			}
		}
		while(!td[0].isFinished || !td[1].isFinished || !td[2].isFinished) {
			SwitchToThread();
		}
		return td[0].result && td[1].result && td[2].result;
	}
}

BOOL Device3380_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
	BOOL result;
	DWORD cbTransferred;
	PDEVICE_DATA pDeviceData = (PDEVICE_DATA)ctx->hDevice;
	if(qwAddr + cb > 0x100000000) { return FALSE; }
	Device3380_WriteCsr(pDeviceData, REG_FIFOSTAT_0, 0xffffffff, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // USB_FIFO0 FLUSH
	Device3380_WriteCsr(pDeviceData, REG_DMACTL_0, 0xc2, CSR_CONFIGSPACE_MEMM | CSR_BYTE0); // DMA_ENABLE
	Device3380_WriteCsr(pDeviceData, REG_DMAADDR_0, (DWORD)qwAddr, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_ADDRESS
	Device3380_WriteCsr(pDeviceData, REG_DMACOUNT_0, 0x00000000 | cb, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL); // DMA_COUNT
	Device3380_WriteCsr(pDeviceData, REG_DMASTAT_0, 0x080000d1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT
	Device3380_WriteCsr(pDeviceData, REG_PCI_STATCMD, 0x07, CSR_CONFIGSPACE_PCIE | CSR_BYTE0); // BUS_MASTER ??? needed ???
	result = WinUsb_WritePipe(pDeviceData->WinusbHandle, USB_EP_DMAOUT, pb, cb, &cbTransferred, NULL);
	Device3380_WriteCsr(pDeviceData, REG_DMASTAT_0, 0x080000d1, CSR_CONFIGSPACE_MEMM | CSR_BYTE0 | CSR_BYTE3); // DMA_START & DMA_CLEAR_ABORT - must be here for 1st transfer to work.
	return result;
}

BOOL Device3380_WriteDMAVerify(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	PBYTE pbV;
	BOOL result = DeviceWriteDMA(ctx, qwAddr, pb, cb, flags);
	if(!result) { return FALSE; }
	pbV = LocalAlloc(0, cb + 0x2000);
	if(!pbV) { return FALSE; }
	result = 
		DeviceReadDMA(ctx, qwAddr & ~0xfff, pbV, (cb + 0xfff + (qwAddr & 0xfff)) & ~0xfff, flags) &&
		(0 == memcmp(pb, pbV + (qwAddr & 0xfff), cb));
	LocalFree(pbV);
	return result;
}

BOOL Device3380_8051Start(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PBYTE pbProgram8051, _In_ DWORD cbProgram8051)
{
	WORD wAddr = 0;
	DWORD dwWriteValue;
	PDEVICE_DATA pDeviceData = (PDEVICE_DATA)ctx->hDevice;
	if(!pbProgram8051 || !cbProgram8051 || cbProgram8051 > 0x7FFF) { return FALSE; }
	while(wAddr < cbProgram8051) {
		dwWriteValue = *(DWORD*)(pbProgram8051 + wAddr); // TODO: may read out-of-buffer by max 3 bytes
		Device3380_WriteCsr(pDeviceData, wAddr, dwWriteValue, CSR_CONFIGSPACE_8051 | CSR_BYTEALL); // write 8051 program memory (page 253).
		Device3380_ReadCsr(pDeviceData, wAddr, &dwWriteValue, CSR_CONFIGSPACE_8051);
		wAddr += 4;
	}
	Device3380_ReadCsr(pDeviceData, 0x00, &dwWriteValue, CSR_CONFIGSPACE_MEMM); // enable 8051
	dwWriteValue &= 0xFE;
	Device3380_WriteCsr(pDeviceData, 0x00, dwWriteValue, CSR_CONFIGSPACE_MEMM | CSR_BYTE0); //DEVINIT - START 8051
	return TRUE;
}

VOID Device3380_8051Stop(_Inout_ PPCILEECH_CONTEXT ctx)
{
	DWORD dwWriteValue;
	Device3380_ReadCsr((PDEVICE_DATA)ctx->hDevice, 0x00, &dwWriteValue, CSR_CONFIGSPACE_MEMM);
	dwWriteValue |= 0x01;
	Device3380_WriteCsr((PDEVICE_DATA)ctx->hDevice, 0x00, dwWriteValue, CSR_CONFIGSPACE_MEMM | CSR_BYTE0);
}

BOOL Device3380_FlashEEPROM(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PBYTE pbEEPROM, _In_ DWORD cbEEPROM)
{
	WORD wAddr = 0;
	DWORD dwWriteValue;
	PDEVICE_DATA pDeviceData = (PDEVICE_DATA)ctx->hDevice;
	if(cbEEPROM < 3 || cbEEPROM > 0x7FFF) {
		return FALSE; // too small or too large for 2 byte addressing mode
	}
	while(wAddr < cbEEPROM) {
		// initialize EEPROM for writing
		Device3380_WriteCsr(pDeviceData, 0x260, 0x0000c000, CSR_CONFIGSPACE_PCIE | CSR_BYTE1); // write enable
		Device3380_WriteCsr(pDeviceData, 0x260, 0x00000000, CSR_CONFIGSPACE_PCIE | CSR_BYTE1); // off
																						  // write data
		dwWriteValue = *(DWORD*)(pbEEPROM + wAddr);
		Device3380_WriteCsr(pDeviceData, 0x264, dwWriteValue, CSR_CONFIGSPACE_PCIE | CSR_BYTEALL);
		// write control register and wait for action to finish
		dwWriteValue = 0x03004000 | (wAddr >> 2);
		Device3380_WriteCsr(pDeviceData, 0x260, dwWriteValue, CSR_CONFIGSPACE_PCIE | CSR_BYTE0 | CSR_BYTE1 | CSR_BYTE3); // write serial EEPROM buffer (page 250).
		while(dwWriteValue & 0xFF000000) { // wait write finish
			Device3380_ReadCsr(pDeviceData, 0x260, &dwWriteValue, CSR_CONFIGSPACE_PCIE);
		}
		wAddr += 4;
	}
	return TRUE;
}

VOID Action_Device3380_Flash(_Inout_ PPCILEECH_CONTEXT ctx)
{
	BOOL result;
	if(ctx->cfg->dev.tp != PCILEECH_DEVICE_USB3380) {
		printf("Flash failed: unsupported device.\n");
		return;
	}
	printf("Flashing firmware ... \n");
	if(!ctx->cfg->cbIn || ctx->cfg->cbIn > 32768) {
		printf("Flash failed: failed to open file or invalid size\n");
		return;
	}
	if(!ctx->cfg->fForceRW && (ctx->cfg->pbIn[0] != 0x5a || *(WORD*)(ctx->cfg->pbIn + 2) > (DWORD)ctx->cfg->cbIn - 1)) {
		printf("Flash failed: invalid firmware signature or size\n");
		return;
	}
	result = Device3380_FlashEEPROM(ctx, ctx->cfg->pbIn, (DWORD)ctx->cfg->cbIn);
	if(!result) {
		printf("Flash failed: failed to write firmware to device\n");
		return;
	}
	printf("SUCCESS!\n");
}

VOID Action_Device3380_8051Start(_Inout_ PPCILEECH_CONTEXT ctx)
{
	BOOL result;
	if(ctx->cfg->dev.tp != PCILEECH_DEVICE_USB3380) {
		printf("8051 startup failed: unsupported device.\n");
		return;
	}
	printf("Loading 8051 executable and starting ... \n");
	if(!ctx->cfg->cbIn || ctx->cfg->cbIn > 32768) {
		printf("8051 startup failed: failed to open file or invalid size\n");
		return;
	}
	result = Device3380_8051Start(ctx, ctx->cfg->pbIn, (DWORD)ctx->cfg->cbIn);
	if(!result) {
		printf("8051 startup failed: failed to write executable to device or starting 8051\n");
		return;
	}
	printf("SUCCESS!\n");
}

VOID Action_Device3380_8051Stop(_Inout_ PPCILEECH_CONTEXT ctx)
{
	if(ctx->cfg->dev.tp != PCILEECH_DEVICE_USB3380) {
		printf("Stopping 8051 failed: unsupported device.\n");
		return;
	}
	printf("Stopping 8051 ... \n");
	Device3380_8051Stop(ctx);
	printf("SUCCESS!\n");
}

BOOL DevicePciOutWriteDma(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
	DWORD cbTransferred;
	BYTE data[4 + 4 + 64 * 4];
	if(((cb % 4) != 0) || (cb > 256)) { return FALSE; }
	if((qwAddr & 0x03) || ((qwAddr + cb) > 0x100000000)) { return FALSE; }
	*(PDWORD)(data + 0) = 0x0000004f | (cb >> 2) << 24;
	*(PDWORD)(data + 4) = (DWORD)qwAddr;
	memcpy(data + 8, pb, cb);
	return WinUsb_WritePipe(pDeviceData->WinusbHandle, USB_EP_PCIOUT, data, 8 + cb, &cbTransferred, NULL);
}

BOOL DevicePciInReadDma(_In_ PDEVICE_DATA pDeviceData, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
	DWORD cbTransferred;
	BYTE data[4 + 4];
	if(((cb % 4) != 0) || (cb > 256)) { return FALSE; }
	if((qwAddr & 0x03) || ((qwAddr + cb) > 0x100000000)) { return FALSE; }
	*(PDWORD)(data + 0) = 0x000000cf | (cb >> 2) << 24;
	*(PDWORD)(data + 4) = (DWORD)qwAddr;
	return
		WinUsb_WritePipe(pDeviceData->WinusbHandle, USB_EP_PCIOUT, data, 8, &cbTransferred, NULL) &&
		WinUsb_ReadPipe(pDeviceData->WinusbHandle, USB_EP_PCIIN, pb, cb, &cbTransferred, NULL) &&
		cb == cbTransferred;
}

BOOL Device3380_Open2(_Inout_ PPCILEECH_CONTEXT ctx);

VOID Device3380_Close(_Inout_ PPCILEECH_CONTEXT ctx)
{
	PDEVICE_DATA pDeviceData = (PDEVICE_DATA)ctx->hDevice;
	if(!pDeviceData) { return; }
	if(!pDeviceData->HandlesOpen) { return; }
	WinUsb_Free(pDeviceData->WinusbHandle);
	if(pDeviceData->DeviceHandle) { CloseHandle(pDeviceData->DeviceHandle); }
	pDeviceData->HandlesOpen = FALSE;
	LocalFree(ctx->hDevice);
	ctx->hDevice = 0;
}

BOOL Device3380_Open(_Inout_ PPCILEECH_CONTEXT ctx)
{
	BOOL result;
	DWORD dwReg;
	result = Device3380_Open2(ctx);
	if(!result) { return FALSE; }
	Device3380_ReadCsr((PDEVICE_DATA)ctx->hDevice, REG_USBSTAT, &dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL);
	if(ctx->cfg->fForceUsb2 && (dwReg & 0x0100 /* Super-Speed(USB3) */)) {
		printf("Device Info: USB3380 running at USB3 speed; downgrading to USB2 ...\n");
		dwReg = 0x04; // USB2=ENABLE, USB3=DISABLE
		Device3380_WriteCsr((PDEVICE_DATA)ctx->hDevice, REG_USBCTL2, dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTE0);
		Device3380_Close(ctx);
		Sleep(1000);
		result = Device3380_Open2(ctx);
		if(!result) { return FALSE; }
		Device3380_ReadCsr((PDEVICE_DATA)ctx->hDevice, REG_USBSTAT, &dwReg, CSR_CONFIGSPACE_MEMM | CSR_BYTEALL);
	}
	if(dwReg & 0xc0 /* Full-Speed(USB1)|High-Speed(USB2) */) {
		printf("Device Info: USB3380 running at USB2 speed.\n");
	} else if(ctx->cfg->fVerbose) {
		printf("Device Info: USB3380 running at USB3 speed.\n");
	}
	if(ctx->cfg->fVerbose) { printf("Device Info: USB3380.\n"); }
	// set callback functions and fix up config
	ctx->cfg->dev.tp = PCILEECH_DEVICE_USB3380;
	ctx->cfg->dev.qwMaxSizeDmaIo = 0x01000000;
	ctx->cfg->dev.qwAddrMaxNative = 0x00000000ffffffff;
	ctx->cfg->dev.fPartialPageReadSupported = TRUE;
	ctx->cfg->dev.pfnClose = Device3380_Close;
	ctx->cfg->dev.pfnReadDMA = Device3380_ReadDMA;
	ctx->cfg->dev.pfnWriteDMA = Device3380_WriteDMA;
	return TRUE;
}

#ifdef WIN32

#include <versionhelpers.h>

// Device Interface GUID. Must match "DeviceInterfaceGUIDs" registry value specified in the INF file.
// F72FE0D4-CBCB-407d-8814-9ED673D0DD6B
DEFINE_GUID(GUID_DEVINTERFACE_android, 0xF72FE0D4, 0xCBCB, 0x407d, 0x88, 0x14, 0x9E, 0xD6, 0x73, 0xD0, 0xDD, 0x6B);

BOOL Device3380_RetrievePath(_Out_bytecap_(BufLen) LPWSTR wszDevicePath, _In_ ULONG BufLen)
{
	BOOL result;
	HDEVINFO deviceInfo;
	SP_DEVICE_INTERFACE_DATA interfaceData;
	PSP_DEVICE_INTERFACE_DETAIL_DATA detailData = NULL;
	ULONG length, requiredLength = 0;
	deviceInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_android, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if(deviceInfo == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
	result = SetupDiEnumDeviceInterfaces(deviceInfo, NULL, &GUID_DEVINTERFACE_android, 0, &interfaceData);
	if(!result) {
		SetupDiDestroyDeviceInfoList(deviceInfo);
		return FALSE;
	}
	result = SetupDiGetDeviceInterfaceDetail(deviceInfo, &interfaceData, NULL, 0, &requiredLength, NULL);
	if(!result && ERROR_INSUFFICIENT_BUFFER != GetLastError()) {
		SetupDiDestroyDeviceInfoList(deviceInfo);
		return FALSE;
	}
	detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)LocalAlloc(LMEM_FIXED, requiredLength);
	if(!detailData) {
		SetupDiDestroyDeviceInfoList(deviceInfo);
		return FALSE;
	}
	detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
	length = requiredLength;
	result = SetupDiGetDeviceInterfaceDetail(deviceInfo, &interfaceData, detailData, length, &requiredLength, NULL);
	if(!result) {
		LocalFree(detailData);
		SetupDiDestroyDeviceInfoList(deviceInfo);
		return FALSE;
	}
	wcscpy_s(wszDevicePath, BufLen, (LPWSTR)detailData->DevicePath);
	LocalFree(detailData);
	SetupDiDestroyDeviceInfoList(deviceInfo);
	return TRUE;
}

VOID Device3380_Open_SetPipePolicy(_In_ PDEVICE_DATA pDeviceData)
{
	BOOL boolTRUE = TRUE;
	ULONG ulTIMEOUT = 500; // ms
	WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAOUT, AUTO_CLEAR_STALL, (ULONG)sizeof(BOOL), &boolTRUE);
	WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAOUT, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &ulTIMEOUT);
	WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN1, AUTO_CLEAR_STALL, (ULONG)sizeof(BOOL), &boolTRUE);
	WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN1, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &ulTIMEOUT);
	WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN2, AUTO_CLEAR_STALL, (ULONG)sizeof(BOOL), &boolTRUE);
	WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN2, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &ulTIMEOUT);
	WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN3, AUTO_CLEAR_STALL, (ULONG)sizeof(BOOL), &boolTRUE);
	WinUsb_SetPipePolicy(pDeviceData->WinusbHandle, USB_EP_DMAIN3, PIPE_TRANSFER_TIMEOUT, (ULONG)sizeof(BOOL), &ulTIMEOUT);
}

BOOL Device3380_Open2(_Inout_ PPCILEECH_CONTEXT ctx)
{
	BOOL result;
	PDEVICE_DATA pDeviceData;
	if(!ctx->hDevice) {
		ctx->hDevice = (HANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_DATA));
		if(!ctx->hDevice) { return FALSE; }
	}
	pDeviceData = (PDEVICE_DATA)ctx->hDevice;
	result = Device3380_RetrievePath(pDeviceData->DevicePath, MAX_PATH);
	if(!result) { return FALSE; }
	pDeviceData->DeviceHandle = CreateFile(pDeviceData->DevicePath,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);
	if(INVALID_HANDLE_VALUE == pDeviceData->DeviceHandle) {
		return FALSE;
	}
	result = WinUsb_Initialize(pDeviceData->DeviceHandle, &pDeviceData->WinusbHandle);
	if(!result) {
		CloseHandle(pDeviceData->DeviceHandle);
		return FALSE;
	}
	Device3380_Open_SetPipePolicy(pDeviceData);
	pDeviceData->HandlesOpen = TRUE;
	pDeviceData->IsAllowedMultiThreadDMA = IsWindows8OrGreater(); // multi threaded DMA read fails on WIN7.
	pDeviceData->MaxSizeDmaIo = ctx->cfg->qwMaxSizeDmaIo;
	return TRUE;
}

#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)

BOOL Device3380_Open2(_Inout_ PPCILEECH_CONTEXT ctx)
{
	PDEVICE_DATA pDeviceData;
	if(libusb_init(NULL)) { return FALSE; }
	if(!ctx->hDevice) {
		ctx->hDevice = (HANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_DATA));
		if(!ctx->hDevice) { return FALSE; }
	}
	pDeviceData = (PDEVICE_DATA)ctx->hDevice;
	pDeviceData->WinusbHandle = libusb_open_device_with_vid_pid(NULL, 0x18d1, 0x9001);
	if(!pDeviceData->WinusbHandle) { 
		libusb_exit(NULL);
		LocalFree(ctx->hDevice);
		ctx->hDevice = NULL;
		return FALSE;
	}
	libusb_claim_interface(pDeviceData->WinusbHandle, 0);
	pDeviceData->HandlesOpen = TRUE;
	// synchronous libusb bulk read/write doesn't seem to support multi threaded accesses.
	pDeviceData->IsAllowedMultiThreadDMA = FALSE;
	pDeviceData->MaxSizeDmaIo = ctx->cfg->qwMaxSizeDmaIo;
	return TRUE;
}

#endif /* LINUX || ANDROID */
