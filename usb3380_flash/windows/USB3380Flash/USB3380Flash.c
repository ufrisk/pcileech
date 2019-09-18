// installer.c : implementation of the PCILeech UMDF2 flash driver.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "USB3380Flash.h"

// -----------------------------------------------------------------------------
// START SHARED CODE WITH WINDOWS/LINUX FLASH PCILEECH FIRMWARE
// -----------------------------------------------------------------------------

#define msleep						Sleep
#define OFFSET_USBREG_GPIO			0x50
#define OFFSET_PCIREG_VEN_DEV		0x1000
#define OFFSET_PCIREG_SUBSYS		0x102c
#define OFFSET_PCIREG_EEPROM_CTL	0x1260
#define OFFSET_PCIREG_EEPROM_DATA	0x1264
#define DEVICE_WAIT_TIME			10
#define SET_LED(v)					*(unsigned int*)(pbar0 + OFFSET_USBREG_GPIO) = (0x0000000f & v) | 0xf0

// Assumes the USB3380 is in Legacy Adapter mode (which is the suggested default config in the manual)
//	Enhanced/Legacy mode selected by STRAP_LEGACY (pin 66, PU)
//	Adapter/RootComplex selected by STRAP_RC_MODE (pin 57, PD)
// Meaning of "block" targets:
//	PCI: USB Controller PCI Configuration registers (Type 0)
//	USB: USB Controller Configuration registers
static const unsigned char g_firmware_pcileech[] = {
    0x5a,                               // validation signature
    0x00,                               // reg_load=true, mem_load=false, uc_unreset=false
    0x2a, 0x00,                         // REG_BYTE_COUNT=7*sizeof(REGADDR+REGDATA)
    0x23, 0x10, 0x49, 0x38, 0x00, 0x00,	// block=USB, reg=USBCTL, val=0x00003849
                                        //	SelfPoweredStatus=1,RemoteWakeEn=0,PcieWakeEn=0,UsbDetectEn=1,
                                        //	RemoteWakeSupport=0,SelfPoweredUsb=1,ImmediateSuspend=0,
                                        //	TimedDisconnect=0,VbusPin=0,UsbRootPortWakeEn=1,VIDStringEn=1,
                                        //	PIDStringEn=1
    0x00, 0x00, 0xe4, 0x14, 0xbc, 0x16,	// block=PCI, reg=VID/DID, val=0x16bc14e4
                                        //	VID=0x14e4,DID=0x16bc (BCM57765/57785 SDXC/MMC Card Reader)
                                        //	PCIe device target sees
    0xc8, 0x10, 0x02, 0x06, 0x04, 0x00,	// block=USB, reg=EP_CFG GPEP0, val=0x00040602
                                        //	Number=2,Dir=OUT,Type=Bulk,Enable=true,FIFOWidth=4
    0xd0, 0x10, 0x84, 0x06, 0x04, 0x00,	// block=USB, reg=EP_CFG GPEP1, val=0x00040684
                                        //	Number=4,Dir=IN,Type=Bulk,Enable=true,FIFOWidth=4
    0xd8, 0x10, 0x86, 0x06, 0x04, 0x00,	// block=USB, reg=EP_CFG GPEP2, val=0x00040686
                                        //	Number=6,Dir=IN,Type=Bulk,Enable=true,FIFOWidth=4
    0xe0, 0x10, 0x88, 0x06, 0x04, 0x00,	// block=USB, reg=EP_CFG GPEP3, val=0x00040688
                                        //	Number=8,Dir=IN,Type=Bulk,Enable=true,FIFOWidth=4
    0x21, 0x10, 0xd1, 0x18, 0x01, 0x90,	// block=USB, reg=PRODVENDID, val=0x900118d1
                                        //	VID=0x18d1,PID=0x9001 (Google Glass)
                                        //	USB device host sees
                                        //	This is just to load a signed WinUSB driver
    0x00, 0x00                          // padding
};

static int _action_flash_verify(unsigned char *pbar0)
{
	unsigned int dwdata, dwaddr = 0;
	while(dwaddr < sizeof(g_firmware_pcileech)) {
		// write to CTL register to start EEPROM read (and wait for device)
		dwdata = *(unsigned int*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL);
		dwdata = (0x00ff0000 & dwdata) | 0x00006000 | (dwaddr >> 2);
		*(unsigned int*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL) = dwdata;
		msleep(DEVICE_WAIT_TIME);
		if(*(unsigned int*)(pbar0 + OFFSET_PCIREG_EEPROM_DATA) != *(unsigned int*)(g_firmware_pcileech + dwaddr)) {
			return -1;
		}
		dwaddr += 4;
	}
	return 0;
}

static void _action_flash_write(unsigned char *pbar0)
{
	unsigned int dwdata, dwaddr = 0;
	while(dwaddr < sizeof(g_firmware_pcileech)) {
		// write enable latch (and wait for device)
		*(unsigned char*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL + 1) = 0xc0;
		msleep(DEVICE_WAIT_TIME);
		*(unsigned char*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL + 1) = 0x00;
		msleep(DEVICE_WAIT_TIME);
		// write EEPROM data
		dwdata = *(unsigned int*)(g_firmware_pcileech + dwaddr);
		*(unsigned int*)(pbar0 + OFFSET_PCIREG_EEPROM_DATA) = dwdata;
		// write to CTL register to start EEPROM write (and wait for device)
		dwdata = *(unsigned int*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL);
		dwdata = (0x00ff0000 & dwdata) | 0x03004000 | (dwaddr >> 2);
		*(unsigned int*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL) = dwdata;
		msleep(DEVICE_WAIT_TIME);
		// next DWORD
		dwaddr += 4;
	}
}

static int _action_flash_writeverify(unsigned char *pbar0)
{
	// 1: check if this is a valid device / memory range.
	if(*(unsigned int*)(pbar0 + OFFSET_PCIREG_SUBSYS) != 0x338010B5) {
		return -2;
	}
	if(*(unsigned int*)(pbar0 + OFFSET_PCIREG_VEN_DEV) != 0x338010B5 && *(unsigned int*)(pbar0 + OFFSET_PCIREG_VEN_DEV) != 0x16BC14E4) {
		return -2;
	}
	// 2: check if EEPROM exists
	if((*(unsigned int*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL) & 0x00030000) == 0) {
		return -3;
	}
	// 4: is firmware already flashed?
	if(0 == _action_flash_verify(pbar0)) {
		SET_LED(0xf); // success -> blue+red led
		return 0;
	}
	// 4: flash firmware.
	_action_flash_write(pbar0);
	// 5: verify flashed firmware.
	if(0 == _action_flash_verify(pbar0)) {
		SET_LED(0x8); // success -> blue led
		return 0;
	}
	SET_LED(0x7); // fail -> red led
	return -1;
}

// -----------------------------------------------------------------------------
// END SHARED CODE WITH WINDOWS/LINUX FLASH PCILEECH FIRMWARE
// -----------------------------------------------------------------------------

NTSTATUS _EvtDevicePrepareHardware(_In_ WDFDEVICE Device, _In_ WDFCMRESLIST ResourcesRaw, _In_ WDFCMRESLIST ResourcesTranslated)
{
	ULONG i;
	NTSTATUS status;
	PBYTE BaseAddress;
	PVOID PseudoBaseAddress;
	PCM_PARTIAL_RESOURCE_DESCRIPTOR desc;
	UNREFERENCED_PARAMETER(ResourcesTranslated);
	for(i = 0; i < WdfCmResourceListGetCount(ResourcesRaw); i++) {
		desc = WdfCmResourceListGetDescriptor(ResourcesRaw, i);
		if(desc->Type != CmResourceTypeMemory || desc->u.Generic.Length != 0x2000) {
			continue;
		}
		status = WdfDeviceMapIoSpace(Device, desc->u.Generic.Start, desc->u.Generic.Length, MmNonCached, &PseudoBaseAddress);
		if(NT_ERROR(status)) {
			continue;
		}
		BaseAddress = (PBYTE)WdfDeviceGetHardwareRegisterMappedAddress(Device, PseudoBaseAddress);
		status = _action_flash_writeverify(BaseAddress);
		if(status) {
			// try force 1-byte addressing and make another flash attempt.
			*(unsigned char*)(BaseAddress + OFFSET_PCIREG_EEPROM_CTL + 2) =
				0x60 | (0x1f & *(unsigned char*)(BaseAddress + OFFSET_PCIREG_EEPROM_CTL + 2));
			status = _action_flash_writeverify(BaseAddress);
		}
		if(status) {
			// try force 2-byte addressing and make another flash attempt.
			*(unsigned char*)(BaseAddress + OFFSET_PCIREG_EEPROM_CTL + 2) =
				0xa0 | (0x1f & *(unsigned char*)(BaseAddress + OFFSET_PCIREG_EEPROM_CTL + 2));
			status = _action_flash_writeverify(BaseAddress);
		}
		WdfDeviceUnmapIoSpace(Device, PseudoBaseAddress, desc->u.Generic.Length);
		return (status == 0) ? STATUS_SUCCESS : STATUS_DEVICE_CONFIGURATION_ERROR;
	}
	return STATUS_BAD_DEVICE_TYPE;
}

NTSTATUS _EvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
	WDFDEVICE device;
	WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
	UNREFERENCED_PARAMETER(Driver);
	WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
	pnpPowerCallbacks.EvtDevicePrepareHardware = _EvtDevicePrepareHardware;
	WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);
	return WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
}

NTSTATUS _EvtDeviceAdd_FlashDisable(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
	UNREFERENCED_PARAMETER(Driver);
	UNREFERENCED_PARAMETER(DeviceInit);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	WDFKEY regKey;
	ULONG regDisable = 0;
	UNICODE_STRING usDisable;
	// check if flash disable reg entry is set
	RtlInitUnicodeString(&usDisable, L"disable");
	status = WdfRegistryOpenKey(NULL, RegistryPath, GENERIC_READ, NULL, &regKey);
	if(NT_SUCCESS(status)) {
		WdfRegistryQueryULong(regKey, &usDisable, &regDisable);
		WdfRegistryClose(regKey);
	}
	// initialize driver
	if(regDisable == 1) {
		WDF_DRIVER_CONFIG_INIT(&config, _EvtDeviceAdd_FlashDisable);
	} else {
		WDF_DRIVER_CONFIG_INIT(&config, _EvtDeviceAdd);
	}
	return WdfDriverCreate(DriverObject,
		RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES,
		&config,
		WDF_NO_HANDLE
	);
}
