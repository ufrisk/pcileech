// pcileech_flash.c : Linux kernel module to flash the USB3380 into a PCILeech device.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// Compiling:
//  - In order to compile the required flash kernel module please go to the folder with
//    this file and type make. GCC and kernel headers are required.  If successful read
//    the usage section below.
// Usage:
//  - insert PCILeech card in computer via PCIe/mPCIe/ExpressCard/Thunderbolt (not USB)
//  - run 'insmod pcileech_flash.ko'. The insertion will fail,     if the error message
//    says no device then flashing was unsuccessfil. It the error says connection reset
//    by peer then flashing was probably successful. Please run the command dmesg - and
//    consult the logs. If it says SUCCESS then the device should hopefully be flashed.
//    NB! There is no guarantee that this is the case.   If the PP3380 is used then the
//    jumper J3 must be bridged in order to enable the EEPROM.    If the USB3380-EVB is
//    used then no special should be needed.
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

#define OFFSET_PCIE_CONFIG	0x1000
#define OFFSET_REG_EEPROM_CTL	0x260
#define OFFSET_REG_EEPROM_DATA  0x264

void _action_flash_write(unsigned char *pbar0)
{
	const unsigned char firmware_pcileech[] = {
		0x5a, 0x00, 0x2a, 0x00, 0x23, 0x10, 0x49, 0x70, 0x00, 0x00, 0x00, 0x00, 0xe4, 0x14, 0xbc, 0x16,
		0xc8, 0x10, 0x02, 0x06, 0x04, 0x00, 0xd0, 0x10, 0x84, 0x06, 0x04, 0x00, 0xd8, 0x10, 0x86, 0x06,
		0x04, 0x00, 0xe0, 0x10, 0x88, 0x06, 0x04, 0x00, 0x21, 0x10, 0xd1, 0x18, 0x01, 0x90, 0x00, 0x00 };
	unsigned short waddr = 0;
	unsigned int dwdata;
	while(waddr < sizeof(firmware_pcileech)) {
		// write enable latch (and wait for device)
		*(unsigned char*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL + 1) = 0xc0;
		msleep(10);
		*(unsigned char*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL + 1) = 0x00;
		msleep(10);
		// write EEPROM data
		dwdata = *(unsigned int*)(firmware_pcileech + waddr);
		*(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_DATA) = dwdata;
		// write to CTL register to start EEPROM write (and wait for device)
		dwdata = *(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL);
		dwdata = (0x00ff0000 & dwdata) | 0x03004000 | (waddr >> 2);
		*(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL) = dwdata;
		msleep(10);
		// next DWORD
		waddr += 4;
	}

}

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
		ret = -ENODEV;
		goto error;
	}
	// remap BAR0 avoiding the use of CPU cache
	pbar0 = ioremap_nocache(pci_resource_start(pdev, 0), pci_resource_len(pdev, 0));
	_action_flash_write(pbar0);
	iounmap(pbar0);
	printk(KERN_INFO "PCILEECH FLASH: SUCCESS: Target device should now hopefully be flashed!\n");
	ret = -ECONNRESET;
error:
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	return ret;
}

static int _action_flash_1(void)
{
	int ret;
	struct pci_dev *pdev;
	// retrieve compatible device (max 1 device per system)
	if((pdev = pci_get_device(0x14e4, 0x16bc, NULL))) {
		printk(KERN_INFO "PCILEECH FLASH: Found USB3380 already flashed as PCILeech.\n");
	} else if((pdev = pci_get_device(0x10b5, 0x3380, NULL))) {
		printk(KERN_INFO "PCILEECH FLASH: Found USB3380 not flashed as PCILeech.\n");
	} else {
		printk(KERN_ERR "PCILEECH FLASH: ERROR: Device not found.\n");
		return -ENODEV;
	}
	ret = _action_flash_2(pdev);
	pci_dev_put(pdev);
	return ret;
}

static int pcileech_flash_init(void)
{
	printk(KERN_INFO "PCILEECH FLASH: Module init called.\n");
	return _action_flash_1();
}

static void pcileech_flash_exit(void)
{
	printk(KERN_INFO "PCILEECH FLASH: Module exit called.\n");
}

module_init(pcileech_flash_init);
module_exit(pcileech_flash_exit);
