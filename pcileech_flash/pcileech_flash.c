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
//  - Insert PCILeech card in computer via PCIe/mPCIe/ExpressCard/Thunderbolt (not USB)
//  - run 'insmod pcileech_flash.ko'.   If the module is successfully inserted then the
//    flash operation was successful. Run 'rmmod pcileech_flash' to clean up the module
//    from the kernel. In order to enable the PCILeech functionality the device must be
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

#define OFFSET_PCIE_CONFIG	0x1000
#define OFFSET_REG_EEPROM_CTL	0x260
#define OFFSET_REG_EEPROM_DATA  0x264
#define DEVICE_WAIT_TIME	10

static int _action_flash_write(unsigned char *pbar0)
{
	const unsigned char firmware_pcileech[] = {
		0x5a, 0x00, 0x2a, 0x00, 0x23, 0x10, 0x49, 0x70, 0x00, 0x00, 0x00, 0x00, 0xe4, 0x14, 0xbc, 0x16,
		0xc8, 0x10, 0x02, 0x06, 0x04, 0x00, 0xd0, 0x10, 0x84, 0x06, 0x04, 0x00, 0xd8, 0x10, 0x86, 0x06,
		0x04, 0x00, 0xe0, 0x10, 0x88, 0x06, 0x04, 0x00, 0x21, 0x10, 0xd1, 0x18, 0x01, 0x90, 0x00, 0x00 };
	unsigned int dwaddr, dwdata;
	// write firmware loop
	dwaddr = 0;
	while(dwaddr < sizeof(firmware_pcileech)) {
		// write enable latch (and wait for device)
		*(unsigned char*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL + 1) = 0xc0;
		msleep(DEVICE_WAIT_TIME);
		*(unsigned char*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL + 1) = 0x00;
		msleep(DEVICE_WAIT_TIME);
		// write EEPROM data
		dwdata = *(unsigned int*)(firmware_pcileech + dwaddr);
		*(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_DATA) = dwdata;
		// write to CTL register to start EEPROM write (and wait for device)
		dwdata = *(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL);
		dwdata = (0x00ff0000 & dwdata) | 0x03004000 | (dwaddr >> 2);
		*(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL) = dwdata;
		msleep(DEVICE_WAIT_TIME);
		// next DWORD
		dwaddr += 4;
	}
	// verify firmware loop
	dwaddr = 0;
	while(dwaddr < sizeof(firmware_pcileech)) {
		// write to CTL register to start EEPROM read (and wait for device)
		dwdata = *(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL);
		dwdata = (0x00ff0000 & dwdata) | 0x00006000 | (dwaddr >> 2);
		*(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_CTL) = dwdata;
		msleep(DEVICE_WAIT_TIME);
		if( *(unsigned int*)(pbar0 + OFFSET_PCIE_CONFIG + OFFSET_REG_EEPROM_DATA) != *(unsigned int*)(firmware_pcileech + dwaddr)) {
			return -EIO;
		}
		dwaddr += 4;
	}
	return 0;
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
	ret = _action_flash_write(pbar0);
	if(ret) {
		ret = _action_flash_write(pbar0); // make two write attempts
	}
	iounmap(pbar0);
	if(ret) {
		printk(KERN_ERR "PCILEECH FLASH: ERROR: Firmware write/verify not successful.\n");
	} else {
		printk(KERN_ERR "PCILEECH FLASH: SUCCESSFUL: Please re-insert the device to use as a PCILeech device!\n");
	}
error:
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	return ret;
}

static int _action_flash_1(void) {
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

static int pcileech_flash_init(void) {
	printk(KERN_INFO "PCILEECH FLASH: Module init called.\n");
	return _action_flash_1();
}

static void pcileech_flash_exit(void) {
	printk(KERN_INFO "PCILEECH FLASH: Module exit called.\n");
}

module_init(pcileech_flash_init);
module_exit(pcileech_flash_exit);
