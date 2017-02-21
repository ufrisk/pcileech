PCILeech Summary:
=================
The PCILeech use the USB3380 chip in order to read from and write to the memory of a target system. This is achieved by using DMA over PCI Express. No drivers are needed on the target system. The USB3380 is only able to read 4GB of memory natively, but is able to read all memory if a kernel module (KMD) is first inserted into the target system kernel. Reading 8GB of memory from the target system take around one (1) minute. The PCILeech hardware is connected with USB3 to a controlling computer running the PCILeech program.
PCILeech is also capable of inserting a wide range of kernel modules into the targeted kernels - allowing for pulling and pushing files, remove the logon password requirement, loading unsigned drivers, executing code and spawn system shells.
The software is written in visual studio and runs on Windows 7/Windows 10. Supported target systems are currently the x64 versions of: Linux, FreeBSD, macOS and Windows.

Hardware:
=========
PCILeech is dependant on the PLX Technologies USB3380 chip. The actual chip can be purchased for around $15, but it's more convenient to purchase a development board on which the chip is already mounted. Development boards can be purchased from BPlus Technology, or on eBay / Ali Express. Please note that adapters may be required too depending on your requirements.

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
* Sonnet Echo ExpressCard Pro - Thunderbolt to ExpressCard.

Please note that other adapters may also work.

Flashing Hardware:
===============================
In order to turn the USB3380 development board into a PCILeech device it must be flashed. Flashing may be done in Windows 10 (as administrator) or in Linux (as root). The board must be connected to the system via PCIe when performing the initial flash.

To flash in Windows 10 unzip all contents of the ` flash.zip ` archive found in ` pcileech_files `. Run ` PCILeechFlash_Installer.exe `and follow the instructions.

Flashing in 32-bit Windows or in Windows 7 is not supported.

If flashing fails or if Linux is preferred please see [pcileech_flash/linux](pcileech_flash/linux) for instructions.

Installing PCILeech:
====================
Please ensure you do have the most recent version of PCILeech by visiting the PCILeech github repository at: https://github.com/ufrisk/pcileech

Clone the PCILeech Github repository. The binaries are found in pcileech_files and should work on Windows 7 and Windows 10 64-bit versions. Please copy all files from pcileech_files since some files contains additional modules and signatures.

The Google Android USB driver also needs to be installed. Download the Google Android USB driver from: http://developer.android.com/sdk/win-usb.html#download Unzip the driver. Open Device Manager. Right click on the computer, choose add legacy hardware. Select install the hardware manually. Click Have Disk. Navigate to the Android Driver, select android_winusb.inf and install. The PCILeech lies about being a Google Glass so that the Android USB driver may be used to access the PCILeech hardware from Windows.

Generating Signatures:
======================
PCILeech comes with built in signatures for Linux, FreeBSD and macOS. For Windows 8.1 and higher two full pages of driver code is needed to hijack the kernel. In order to avoid copyright issues the end user has to generate these signatures by themselves using the pcileech_gensig.exe program. The user needs to point to a valid ntfs.sys file in order to generate a signature. Alternatively it is possible to use the unstable/experimental win10_x64 generic built-in signature.

Capabilities:
=============
Users should be able to extend PCILeech easily by writing own kernel shellcode modules and/or creating custom signatures used to patch target system memory. Some of the current capabilies are listed below:
* Retrieve memory from the target system at >150MB/s. 
* Write data to the target system memory. 
* 4GB memory can be accessed in native DMA mode.
* ALL memory can be accessed if kernel module (KMD) is loaded.
* Execute kernel code on the target system.
* Spawn system shell [Windows].
* Spawn any executable [Windows].
* Load unsigned drivers [Windows].
* Pull files [Linux, FreeBSD, Windows, macOS].
* Push files [Linux, Windows, macOS].
* Patch / Unlock (remove password requirement) [Windows, macOS].

Limitations/Known Issues:
=========================
* Read and write errors on some hardware. Try "pcileech.exe testmemreadwrite -min 0x1000" in order to test memory reads and writes against the physical address 0x1000 (or any other address) in order to confirm. If issues exists downgrading to USB2 may help.
* Does not work if the OS uses the IOMMU/VT-d. This is the default on macOS (unless disabled in recovery mode). Windows 10 Enterprise with Virtualization based security features enabled does not work fully - this is however not the default setting in Windows 10.
* Some Linux kernels does not work. Sometimes a required symbol is not exported in the kernel and PCILeech fails.
* Linux might also not work if some virtualization based features are enabled.
* Linux based on the 4.8 kernel usually does not work (Ubuntu 16.10). As an alternative, if target root access exists, compile and insert .ko (pcileech_kmd/linux).
* Windows Vista: some shellcode modules such as wx64_pscmd does not work.
* Windows 7: signatures are not published.

Examples:
=========
Load macOS kernel module:
* ` pcileech.exe kmdload -kmd macos `

Remove macOS password requirement, requires that the KMD is loaded at an address. In this example 0x11abc000 is used.
* ` pcileech.exe macos_unlock -kmd 0x11abc000 -0 1 `

Retrieve the file /etc/shadow from a Linux system without pre-loading a KMD.
* ` pcileech.exe lx64_filepull -kmd LINUX_X64 -s /etc/shadow -out c:\temp\shadow `

Show help for the lx64_filepull kernel implant.
* ` pcileech.exe lx64_filepull -help `

Load a kernel module into Windows Vista by using the default memory scan technique.
* ` pcileech.exe kmdload -kmd winvistax64 `

Load a kernel module into Windows 10 by targeting the page table of the ntfs.sys driver signed on 2016-03-29.
* ` pcileech.exe kmdload -kmd win10x64_ntfs_20160329 -pt `

Load a kernel module into Windows 10 (unstable/experimental). Compatible with VBS/VTL0 only if "Protection of Code Integrity" is not enabled.
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

Building:
=========
The binaries are found in the pcileech_files folder. If one wish to build an own version it is possible to do so. Compile the pcileech and pcileech_gensig projects from within Visual Studio. Tested with Visual Studio 2015. To compile kernel- and shellcode, located in the pcileech_shellcode project, please look into the individual files for instructions. These files are usually compiled command line.

Changelog:
==========
v1.0
* Initial release.

v1.1
* core: help for actions and kernel implants.
* core: search for signatures (do not patch).
* core: signature support for wildcard and relative offsets in addition to fixed offsets.
* implant: load unsigned drivers into Windows kernel [wx64_driverload_svc].
* signature: generic Windows 10 (Unstable/Experimental) [win10_x64].
* signature: Windows 10 updated.
* signature: Linux unlock added.
* other: firmware flash support without PLX SDK.
* other: various bug fixes.

v1.2
* core: FreeBSD support.
* implant: pull file from FreeBSD [fbsdx64_filepull]
* signature: Windows 10 updated.
* signature: macOS Sierra added.
* other: various bug fixes and stability improvements.

v1.3
* core: basic linux 4.8 support.
* core: mac_fvrecover - retrieve filevault2 password from locked mac.
* core: stability improvements for USB2 and new options [-out none, -usb2, -iosize, -v]
* implant: pull large files from target [wx64_filepull, mac_filepull, lx64_filepull].
* implant: spawn cmd in user context [wx64_pscmd_user].
* implant: stability improvements for Win8+ [wx64_pscreate, wx64_pscmd, wx64_pscmd_user].
* other: load kmd by compiling and inserting .ko on linux [ pcileech_kmd/linux ].
* other: firmware flash support in Windows.

v1.4
* core: linux 4.8 efi support [-kmd linux_x64_efi] [http://blog.frizk.net/2017/01/attacking-uefi-and-linux.html].
* other: linux stability fixes.

Latest
* signature: macOS Sierra updated.
* signature: Windows 10 updated.
* other: bug fix - memory write in macOS.
* other: firmware flash fixes for PP3380 device.
