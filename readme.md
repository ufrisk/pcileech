PCILeech Summary:
=================
PCILeech uses PCIe hardware devices to read and write from the target system memory. This is achieved by using DMA over PCIe. No drivers are needed on the target system. 

PCILeech supports multiple hardware. Currently only the USB3380 hardware is publically available. The USB3380 is only able to read 4GB of memory natively, but is able to read all memory if a kernel module (KMD) is first inserted into the target system kernel.

PCILeech is capable of inserting a wide range of kernel implants into the targeted kernels - allowing for easy access to live ram and the file system via a "mounted drive". It is also possible to remove the logon password requirement, loading unsigned drivers, executing code and spawn system shells. PCIleech runs on Windows/Linux/Android. Supported target systems are currently the x64 versions of: Linux, FreeBSD, macOS and Windows.

<img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_mbp.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_m2.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_shadow.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_dump.gif" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_mount.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/314e527e13e78edd44cc6db2b7c05cfa4a1ce322/_gh_android.jpg" height="150"/>

Capabilities:
=============
* Retrieve memory from the target system at >150MB/s. 
* Write data to the target system memory. 
* 4GB memory can be accessed in native DMA mode.
* ALL memory can be accessed if kernel module (KMD) is loaded.
* Mount live RAM as file [Linux, Windows, macOS].
* Mount file system as drive [Linux, Windows, macOS].
* Execute kernel code on the target system.
* Spawn system shell [Windows].
* Spawn any executable [Windows].
* Load unsigned drivers [Windows].
* Pull files [Linux, FreeBSD, Windows, macOS].
* Push files [Linux, Windows, macOS].
* Patch / Unlock (remove password requirement) [Windows, macOS].
* Easy to create own kernel shellcode and/or custom signatures.
* Even more features not listed here ...

Installing PCILeech:
====================
Please ensure you do have the most recent version of PCILeech by visiting the PCILeech github repository at: https://github.com/ufrisk/pcileech

Clone the PCILeech Github repository. The binaries are found in pcileech_files and should work on 64-bit Windows and Linux. Please copy all files from pcileech_files since some files contains additional modules and signatures.

#### Windows:
The Google Android USB driver also have to be installed. Download the Google Android USB driver from: http://developer.android.com/sdk/win-usb.html#download Unzip the driver. Open Device Manager. Right click on the computer, choose add legacy hardware. Select install the hardware manually. Click Have Disk. Navigate to the Android Driver, select android_winusb.inf and install.

To mount live ram and target file system as drive in Windows the Dokany file system library must be installed. Please download and install the latest version of Dokany at: https://github.com/dokan-dev/dokany/releases/latest

#### Linux:
PCILeech on Linux must be run as root. PCILeech also requires libusb. Libusb is probably installed by default - if not install it by running: `apt-get install libusb-1.0-0`.

#### Android:
Separate instructions for [Android](Android.md).

Hardware:
=================
PCILeech use the PLX Technologies USB3380 chip. The actual chip can be purchased for around $15, but it's more convenient to purchase a development board on which the chip is already mounted. Development boards can be purchased from BPlus Technology, or on eBay / Ali Express. Please note that adapters may be required too depending on your requirements. In addition to the USB3380 PCILeech also supports not yet released FPGA based hardware.

http://www.bplus.com.tw/PLX.html

The hardware confirmed working is:
* USB3380-EVB mini-PCIe card.
* PP3380-AB PCIe card.

Please note that the ExpressCard EC3380-AB is not working!

Please note that the USB3380-AB EVK-RC kit is not working!

Recommended adapters:
* PE3B - ExpressCard to mini-PCIe.
* PE3A - ExpressCard to PCIe.
* ADP - PCIe to mini-PCIe.
* P15S-P15F - M.2 Key A+E to mini-PCIe.
* Sonnet Echo ExpressCard Pro - Thunderbolt to ExpressCard.
* Apple Thunderbolt3 (USB-C) - Thunderbolt2 dongle.

Please note that other adapters may also work.

Flashing Hardware:
==================
In order to turn the USB3380 development board into a PCILeech device it must be flashed. Flashing may be done in Windows 10 (as administrator) or in Linux (as root). The board must be connected to the system via PCIe when performing the initial flash.

To flash in Windows 10 unzip all contents of the ` flash.zip ` archive found in ` pcileech_files `. Run ` PCILeechFlash_Installer.exe `and follow the instructions.

Flashing in 32-bit Windows or in Windows 7 is not supported.

If flashing fails or if Linux is preferred please see [pcileech_flash/linux](pcileech_flash/linux) for instructions.

Examples:
=========
Load macOS kernel module:
* ` pcileech.exe kmdload -kmd macos `

Mount target system live RAM and file system, requires that a KMD is loaded. In this example 0x11abc000 is used.
* ` pcileech.exe mount -kmd 0x11abc000 `

Remove macOS password requirement, requires a KMD is loaded. In this example 0x11abc000 is used.
* ` pcileech.exe macos_unlock -kmd 0x11abc000 -0 1 `

Mount Linux target system live RAM and file system without pre-loading a KMD.
* ` pcileech.exe mount -kmd LINUX_X64_46 `

Retrieve the file /etc/shadow from a Linux system without pre-loading a KMD.
* ` pcileech.exe lx64_filepull -kmd LINUX_X64_46 -s /etc/shadow -out c:\temp\shadow `

Show help for the lx64_filepull kernel implant.
* ` pcileech.exe lx64_filepull -help `

Load a kernel module into Windows Vista by using the default memory scan technique.
* ` pcileech.exe kmdload -kmd winvistax64 `

Load a kernel module into Windows 10 by targeting the page table of the ntfs.sys driver signed on 2016-03-29.
* ` pcileech.exe kmdload -kmd win10x64_ntfs_20160329 -pt `

Load a kernel module into Windows 10. Compatible with VBS/VTL0 only if "Protection of Code Integrity" is not enabled.
* ` pcileech.exe kmdload -kmd WIN10_X64 `

Spawn a system shell on the target system (system needs to be locked and kernel module must be loaded). In this example the kernel module is loaded at address: 0x7fffe000.
* ` pcileech.exe wx64_pscmd -kmd 0x7fffe000 `

Show help for the dump command.
* ` pcileech.exe dump -help `

Dump all memory from the target system given that a kernel module is loaded at address: 0x7fffe000.
* ` pcileech.exe dump -kmd 0x7fffe000 `

Force dump memory below 4GB including accessible memory mapped devices using more stable USB2 approach.
* ` pcileech.exe dump -force -usb2 `

Exploit a vulnerable mac to retrieve the FileVault2 password.
* ` pcileech.exe mac_fvrecover `

Receive PCIe TLPs (Transaction Layer Packets) and print them on screen (correctly configured FPGA dev board required).
* ` pcileech.exe tlp -vv -wait 1000 `

Generating Signatures:
======================
PCILeech comes with built in signatures for Windows, Linux, FreeBSD and macOS. For Windows 8.1 or later it is also possible to use the pcileech_gensig.exe program to generate alternative signatures.

Limitations/Known Issues:
=========================
* Read and write errors on some hardware with the USB3380. Try `pcileech.exe testmemreadwrite -min 0x1000` to test memory reads and writes against the physical address 0x1000 (or any other address) in order to confirm. If issues exists downgrading to USB2 may help.
* Does not work if the OS uses the IOMMU/VT-d. This is the default on macOS (unless disabled in recovery mode). Windows 10 with Virtualization based security features enabled does not work fully - this is however not the default setting in Windows 10 or Linux.
* Some Linux kernels does not work. Sometimes a required symbol is not exported in the kernel and PCILeech fails.
* Linux based on the 4.8 kernel and later might not work with the USB3380 hardware. As an alternative, if target root access exists, compile and insert .ko (pcileech_kmd/linux). If the system is EFI booted an alternative signature exists.
* Windows Vista: some shellcode modules such as wx64_pscmd does not work.
* Windows 7: signatures are not published.
* The Linux/Android versions of PCILeech dumps memory slightly slower than the Windows version. Mount target file system and live RAM are also not availabe in the Linux/Android versions.

Building:
=========
The binaries are found in the pcileech_files folder. If one wish to build an own version it is possible to do so. Compile the pcileech and pcileech_gensig projects from within Visual Studio. Tested with Visual Studio 2015. 

To compile kernel- and shellcode, located in the pcileech_shellcode project, please look into the individual files for instructions. These files are usually compiled command line. To compile for Linux make sure the dependencies are met my running: `apt-get install libusb-1.0-0-dev pkg-config` then move into the pcileech/pcileech directory and build by running: `make`. Copy the pcileech binary to pcileech/pcileech_files afterwards.

Separate instructions for [Android](Android.md).

Links:
======
* Blog: http://blog.frizk.net
* Twitter: https://twitter.com/UlfFrisk
* YouTube: https://www.youtube.com/channel/UC2aAi-gjqvKiC7s7Opzv9rg

Changelog:
==========
v1.0
* Initial release.

v1.1-v1.5
* various updates. please see individual relases for more information.

v2.0
* mount target system live RAM and file system as drive.
* substantial refactorings to support future multiple hardware devices.
* signature: Linux 4.10 kernel support in LINUX_X64_EFI signature.

v2.1
* Linux support.
* Android support.
