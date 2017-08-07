Flashing Hardware in Linux:
===============================
In order to turn the USB3380 development board into a PCILeech device it must be flashed. Flashing in Linux must be done as root. Download the source code for the flash kernel module to build. The files are found in the pcileech_flash/linux folder and are named: pcileech_flash.c and Makefile. The card must be connected to the Linux system doing the flashing via PCIe.

NB! If flashing the PP3380 PCIe card the J3 jumper must be bridged to connect the EEPROM. This is not necessary for the USB3380-EVB mini-PCIe card.

* ` cd /pathtofiles `
* ` make `
* [ insert USB3380 hardware into computer ]
* ` insmod pcileech_flash.ko `

The insmod command must be run as root. If compilation fails you might have to install dependencies before you try again. On debian based systems - such as debian, ubuntu and kali, run ` apt-get update && apt-get install gcc make linux-headers-$(uname -r) ` and try again.

If module insertion is successful flashing is also successful. In order to activate the flashed PCILeech device it must be power-cycled. Re-inserting it in the computer will achieve this. If one wish to flash more devices then unload the pcileech_flash kernel module by issuing the command: ` rmmod pcileech_flash `. If there is an error flashing is unsuccessful. Please try again and check any debug error messages by issing the command: ` dmsg `.

Alternative Flash using uflash:
======================================
If the above method using a kernel module fails or isn't desirable you may also use the [uflash utility](https://github.com/ANSSI-FR/pciemem/tree/master/uflash) by Yves-Alexis Perez / ANSSI-FR. It must be run as root but should build without any special dependencies.
