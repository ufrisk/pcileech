USB3380 Hardware:
=================
PCILeech uses PCIe hardware devices to read and write from the target system memory. This is achieved by using DMA over PCIe. No drivers are needed on the target system. Check out the [PCILeech](readme.md) project for general information.

PCILeech supports multiple hardware. USB3380 based hardware is only able to read 4GB of memory natively, but is able to read all memory if a kernel module (KMD) is first inserted into the target system kernel. FPGA based hardware is able to read all memory.

<img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_mbp.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_m2.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_shadow.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_dump.gif" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_mount.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/314e527e13e78edd44cc6db2b7c05cfa4a1ce322/_gh_android.jpg" height="150"/>

PCILeech use the PLX Technologies USB3380 chip. The actual chip can be purchased for around $15, but it's more convenient to purchase a development board on which the chip is already mounted. Development boards can be purchased from BPlus Technology, or on eBay / Ali Express. Please note that adapters may be required too depending on your requirements. Please also note that the USB3380 is currently sold out.

http://www.bplus.com.tw/PLX.html

The hardware confirmed working is:
* USB3380-EVB mini-PCIe card.
* PP3380-AB PCIe card.

Please note that the ExpressCard EC3380-AB is not working!

Please note that the USB3380-AB EVK-RC kit is not working!

Flashing Hardware:
==================
In order to turn the USB3380 development board into a PCILeech device it must be flashed. Flashing may be done in Windows 10 (as administrator) or in Linux (as root). The board must be connected to the system via PCIe when performing the initial flash.

To flash in Windows 10 unzip all contents of the ` flash.zip ` archive found in ` pcileech_files `. Run ` PCILeechFlash_Installer.exe `and follow the instructions.

Flashing in 32-bit Windows or in Windows 7 is not supported.

If flashing fails or if Linux is preferred please see [pcileech_flash/linux](pcileech_flash/linux) for instructions.
