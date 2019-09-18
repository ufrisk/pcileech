// pcileech_flash.c : Linux kernel module to flash the USB3380 into a PCILeech device.
//
// (c) Ulf Frisk, 2016. 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
// Compiling:
//  - In order to compile the required flash kernel module please go to the folder with
//    this file and type make. GCC and kernel headers are required.  If successful read
//    the usage section below.
// Usage:
//  - Insert PCILeech card in computer via PCIe/mPCIe/ExpressCard/Thunderbolt (not USB)
//  - run 'insmod pcileech_flash.ko'.   If the module is successfully inserted then the
//    flash operation was successful.   If flashing the USB3380-EVB device the blue LED
//    will be lit upon success.  Run 'rmmod pcileech_flash' to clean up the module from
//    the kernel.      In order to enable the PCILeech functionality the device must be
//    removed from (re-inserted into) the computer.
//  - If flashing fails; please check 'dmesg' for logs.  If you are flashing the PP3380
//    please ensure that the J3 jumper is bridged.  If it fails for unknown reasons try
//    rebooting and try again.
// Warning:
//    Flashing hardware may result in bricked hardware. The author of this module takes
//    no responsiblity for this code. The code is provided as is. Use at your own risk.
//

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ulf Frisk");
MODULE_DESCRIPTION("PCILeech Firmware Automatic Flasher");

// -----------------------------------------------------------------------------
// START SHARED CODE WITH WINDOWS/LINUX FLASH PCILEECH FIRMWARE
// -----------------------------------------------------------------------------

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

static int _action_flash_2(struct pci_dev *pdev)
{
	int ret;
	unsigned char *pbar0;
	// enable the device
	if((ret = pci_enable_device(pdev))) {
		printk(KERN_ERR "PCILEECH FLASH: ERROR: Failed to enable PCIe device.\n");
		return ret;
	}
	// take ownership of pci related regions
	if((ret = pci_request_regions(pdev, "expdev"))) {
		printk(KERN_ERR "PCILEECH FLASH: ERROR: Cannot request regions.\n");
		goto error;
	}
	// checking if PCI-device reachable by checking that BAR0 is defined and memory mapped
	if(!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		printk(KERN_ERR "PCILEECH FLASH: ERROR: BAR0 configuration not found.\n");
		goto error;
	}
	// remap BAR0 avoiding the use of CPU cache
	pbar0 = ioremap_nocache(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
	ret = _action_flash_writeverify(pbar0);
	if(ret) {
		// try force 1-byte addressing and make another flash attempt.
		*(unsigned char*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL + 2) =
		0x60 | (0x1f & *(unsigned char*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL + 2));
		ret = _action_flash_writeverify(pbar0);
	}
	if(ret) {
		// try force 2-byte addressing and make another flash attempt.
		*(unsigned char*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL + 2) =
		  0xa0 | (0x1f & *(unsigned char*)(pbar0 + OFFSET_PCIREG_EEPROM_CTL + 2));
		ret = _action_flash_writeverify(pbar0); 
	}
	iounmap(pbar0);
	if(ret) {
		printk(KERN_ERR "PCILEECH FLASH: ERROR: Firmware write/verify not successful. Error: %08x\n", ret);
	} else {
		printk(KERN_ERR "PCILEECH FLASH: SUCCESSFUL: Please re-insert the device to use as a PCILeech device!\n");
	}
error:
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	return ret ? -ENODEV : 0;
}

static int _action_flash_1(void) {
	int ret;
	bool is_dev_found = false;
	struct pci_dev *pdev = NULL;
	// retrieve compatible devices
	while((pdev = pci_get_device(0x14e4, 0x16bc, pdev))) {
		printk(KERN_INFO "PCILEECH FLASH: Found USB3380 already flashed as PCILeech.\n");
		ret = _action_flash_2(pdev);
		is_dev_found = true;
	}
	while((pdev = pci_get_device(0x10b5, 0x3380, pdev))) {
		printk(KERN_INFO "PCILEECH FLASH: Found USB3380 not flashed as PCILeech.\n");
		ret = _action_flash_2(pdev);
		is_dev_found = true;
	}
	if(!is_dev_found) {
		printk(KERN_ERR "PCILEECH FLASH: ERROR: Device not found.\n");
		return -ENODEV;
	}
	return ret;
}

static int pcileech_flash_init(void) {
	printk(KERN_INFO "PCILEECH FLASH: Module init called.\n");
	return _action_flash_1();
}

static void pcileech_flash_exit(void) {
	printk(KERN_INFO "PCILEECH FLASH: Module exit called.\n");
}

module_init(pcileech_flash_init);
module_exit(pcileech_flash_exit);
