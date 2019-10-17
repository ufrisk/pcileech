PCILeech Summary:
=================
PCILeech uses PCIe hardware devices to read and write target system memory. This is achieved by using DMA over PCIe. No drivers are needed on the target system. 

<b>PCILeech also works without hardware together with a wide range of software memory acqusition methods supported by the LeechCore library - including capture of remote live memory using DumpIt or WinPmem. PCILeech also supports local capture of memory and a number of memory dump file formats.</b>

PCILeech supports multiple memory acquisition devices. Both hardware and software based. USB3380 based hardware is only able to read 4GB of memory natively, but is able to read all memory if a kernel module (KMD) is first inserted into the target system kernel. FPGA based hardware, and software based methods, are able to read all memory.

PCILeech is capable of inserting a wide range of kernel implants into the targeted kernels - allowing for easy access to live ram and the file system via a "mounted drive". It is also possible to remove the logon password requirement, loading unsigned drivers, executing code and spawn system shells. PCIleech runs on Windows and Linux. Supported target systems are currently the x64 versions of: UEFI, Linux, FreeBSD, macOS and Windows. This requires write access to memory (USB3380 hardware, FPGA hardware or CVE-2018-1038 "Total Meltdown").

<b>To get going clone the sources in the repository or download the latest [binaries, modules and configuration files](https://github.com/ufrisk/pcileech/releases/latest).</b>

For use cases and more detailed information check out this readme and the [project wiki pages](https://github.com/ufrisk/pcileech/wiki/).

<img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_mbp.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_m2.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_shadow.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/314e527e13e78edd44cc6db2b7c05cfa4a1ce322/_gh_android.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_dump.gif" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/ab5032dac2600acf1480d81ac265b66fecaaa9b2/_gh_ac701_pcileech_main.jpg" height="150"/><img src="https://gist.github.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/ab5032dac2600acf1480d81ac265b66fecaaa9b2/_gh_pciescreamer_pcileech_main.jpg" height="150"/>

Capabilities:
=============
* Retrieve memory from the target system at >150MB/s.
* Retrieve remote memory from remote LeechService.
* Write data to the target system memory. 
* 4GB memory can be accessed in native DMA mode (USB3380 hardware).
* ALL memory can be accessed in native DMA mode (FPGA hardware).
* ALL memory can be accessed if kernel module (KMD) is loaded.
* Raw PCIe TLP access (FPGA hardware).
* Mount live RAM as file [Linux, Windows, macOS Sierra*].
* Mount file system as drive [Linux, Windows, macOS Sierra*].
* Execute kernel code on the target system.
* Spawn system shell and other executables [Windows].
* Pull and Push files [Linux, FreeBSD, Windows, macOS Sierra*].
* Patch / Unlock (remove password requirement) [Windows, macOS Sierra*].
* Easy to create own kernel shellcode and/or custom signatures.
* Connect to a remote LeechAgent over the network to remotely:
   * Dump physical memory over the network.
   * Execute Python memory analysis scripts on the remote host.
* Even more features not listed here ...

\*) macOS High Sierra and above are not supported.

Memory Acquisition Methods:
===========================
PCILeech supports both hardware based and software based memory acqusition methods. All memory acqusition is handled by the [LeechCore](https://github.com/ufrisk/LeechCore) library.

### Hardware based memory aqusition methods:

Please find a summary of the supported hardware based memory acquisition methods listed below. All hardware based memory acquisition methods are supported on both Windows and Linux. The FPGA based methods however sports a slight performance penalty on Linux and will max out at approx: 90MB/s compared to 150MB/s on Windows.

| Device                                      | Type | Interface | Speed | 64-bit memory access | PCIe TLP access |
| ---------------------------------------------------------------------- | ------- | ------ | ------- | --- | --- |
| [AC701/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)    | FPGA    | USB3   | 150MB/s | Yes | Yes |
| [PCIeScreamer](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)   | FPGA    | USB3   | 100MB/s | Yes | Yes |
| [SP605/FT601](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)    | FPGA    | USB3   |  75MB/s | Yes | Yes |
| [SP605/TCP](https://github.com/ufrisk/LeechCore/wiki/Device_SP605TCP)  | FPGA    | TCP/IP | 100kB/s | Yes | Yes |
| [NeTV2/UDP](https://github.com/ufrisk/LeechCore/wiki/Device_RawUDP)    | FPGA    | UDP/IP |   7MB/s | Yes | Yes |
| [USB3380-EVB](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380) | USB3380 | USB3   | 150MB/s | No  | No  |
| [PP3380](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380)      | USB3380 | USB3   | 150MB/s | No  | No  |
| [DMA patched HP iLO](https://github.com/ufrisk/LeechCore/wiki/Device_iLO) | BMC  | TCP/IP |   1MB/s | Yes | No  |

### Software based memory aqusition methods:

Please find a summary of the supported software based memory acquisition methods listed below. Please note that the LeechService only provides a network connection to a remote LeechCore library. It's possible to use both hardware and software based memory acquisition once connected.

| Device                     | Type             | Linux Support |
| -------------------------- | ---------------- | ------------- |
| [RAW physical memory dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)         | File             | Yes |
| [Full Microsoft Crash Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)        | File             | Yes |
| [Full ELF Core Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)               | File             | Yes |
| [Hyper-V Saved State](https://github.com/ufrisk/LeechCore/wiki/Device_HyperV_SavedState) | File             | No  |
| [TotalMeltdown](https://github.com/ufrisk/LeechCore/wiki/Device_Totalmeltdown)           | CVE-2018-1038    | No  |
| [DumpIt /LIVEKD](https://github.com/ufrisk/LeechCore/wiki/Device_DumpIt)                 | Live&nbsp;Memory | No  |
| [WinPMEM](https://github.com/ufrisk/LeechCore/wiki/Device_WinPMEM)                       | Live&nbsp;Memory | No  |
| [LeechService*](https://github.com/ufrisk/LeechCore/wiki/Device_Remote)                  | Remote           | No  |

Installing PCILeech:
====================
Please ensure you do have the most recent version of PCILeech by visiting the PCILeech github repository at: https://github.com/ufrisk/pcileech

<b>Get the latest [binaries, modules and configuration files](https://github.com/ufrisk/pcileech/releases/latest) from the latest release.</b> Alternatively clone the repository and build from source.

#### Windows:

Please see the [PCILeech on Windows](https://github.com/ufrisk/pcileech/wiki/PCILeech-on-Windows) guide for information about running PCILeech on Windows.

The Google Android USB driver have to be installed if USB3380 hardware is used. Download the Google Android USB driver from: http://developer.android.com/sdk/win-usb.html#download Unzip the driver.<br>
FTDI drivers have to be installed if FPGA is used with FT601 USB3 addon card or PCIeScreamer. Download the 64-bit [`FTD3XX.dll`](http://www.ftdichip.com/Drivers/D3XX/FTD3XXLibrary_v1.2.0.6.zip) from FTDI and place it alongside `pcileech.exe`.<br>
To mount live ram and target file system as drive in Windows the Dokany file system library must be installed. Please download and install the latest version of Dokany at: https://github.com/dokan-dev/dokany/releases/latest

#### Linux:
Please see the [PCILeech on Linux](https://github.com/ufrisk/pcileech/wiki/PCILeech-on-Linux) guide for information about running PCILeech on Linux.

Examples:
=========

Please see the [project wiki pages](https://github.com/ufrisk/pcileech/wiki/) for more examples. The wiki is in a buildup phase and information may still be missing.

Mount target system live RAM and file system, requires that a KMD is loaded. In this example 0x11abc000 is used.
* ` pcileech.exe mount -kmd 0x11abc000 `

Show help for a specific kernel implant, in this case lx64_filepull kernel implant.
* ` pcileech.exe lx64_filepull -help `

Show help for the dump command.
* ` pcileech.exe dump -help `

Dump all memory from the target system given that a kernel module is loaded at address: 0x7fffe000.
* ` pcileech.exe dump -kmd 0x7fffe000 `

Force dump memory below 4GB including accessible memory mapped devices using more stable USB2 approach on USB3380.
* ` pcileech.exe dump -force -device usb3380://usb2 `

Receive PCIe TLPs (Transaction Layer Packets) and print them on screen (correctly configured FPGA dev board required).
* ` pcileech.exe tlp -vv -wait 1000 `

Probe/Enumerate the memory of the target system for readable memory pages and maximum memory. (FPGA hardware only).
* ` pcileech.exe probe `

Dump all memory between addresses min and max, don't stop on failed pages. Native access to 64-bit memory is only supported on FPGA hardware.
* ` pcileech.exe dump -min 0x0 -max 0x21e5fffff -force `

Force the usage of a specific device (instead of default auto detecting it). The pmem device is not auto detected.
* ` pcileech.exe pagedisplay -min 0x1000 -device pmem `

Dump remote memory from a remote LeechAgent using connection encrypted and mutually authenticated by kerberos.
* ` pcileech.exe dump -device pmem -remote rpc://computer$@ad.contoso.com `

Execute the Python analysis script `find-rwx.py` on a remote computer using the LeechAgent embedded Python environment.
* ` pcileech.exe agent-execpy -in find-rwx.py -device pmem -remote rpc://computer$@ad.contoso.com `

Dump memory using the the reported "TotalMeltdown" [Windows 7/2008R2 x64 PML4 page table permission vulnerability](https://blog.frizk.net/2018/03/total-meltdown.html).
* ` pcileech.exe dump -out memdump_win7.raw -device totalmeltdown -v -force `

Insert a kernel module into a running Linux system remotely via a [DMA patched HP iLO](https://www.synacktiv.com/posts/exploit/using-your-bmc-as-a-dma-device-plugging-pcileech-to-hpe-ilo-4.html).
* ` pcileech.exe kmdload -vvv -device rawtcp -device-addr 127.0.0.1 -device-port 8888 -kmd LINUX_X64_48 `

Generating Signatures:
======================
PCILeech comes with built in signatures for Windows, Linux, FreeBSD and macOS. There is also an optional, now obsoleted method of generating signatures by using the pcileech_gensig.exe program.

Limitations/Known Issues:
=========================
* Read and write errors on some hardware with the USB3380. Try `pcileech.exe testmemreadwrite -min 0x1000` to test memory reads and writes against the physical address 0x1000 (or any other address) in order to confirm. If issues exists downgrading to USB2 may help.
* Does not work if the OS uses the IOMMU/VT-d. This is the default on macOS (unless disabled in recovery mode). Windows 10 with Virtualization based security features enabled does not work fully - this is however not the default setting in Windows 10 or Linux.
* Some Linux kernels does not work. Sometimes a required symbol is not exported in the kernel and PCILeech fails.
* Linux based on the 4.8 kernel and later might not work with the USB3380 hardware. As an alternative, if target root access exists, compile and insert .ko (pcileech_kmd/linux). If the system is EFI booted an alternative signature exists.
* File system mount support only exists for Windows.
* Remote connectivity support only exists for Windows.

Building:
=========
The binaries are found in the [releases section](https://github.com/ufrisk/pcileech/releases/latest) of this repository. If one wish to build an own version it is possible to do so. Please see the [PCILeech on Windows](https://github.com/ufrisk/pcileech/wiki/PCILeech-on-Windows) or [PCILeech on Linux](https://github.com/ufrisk/pcileech/wiki/PCILeech-on-Linux) for more information about building PCILeech. PCILeech is also dependant on LeechCore and optionally (for some extra functionality) on The Memory Process File System which must both be built separately.

Links:
======
#### Projects:
* PCILeech Wiki: https://github.com/ufrisk/pcileech/wiki
* PCILeech FPGA: https://github.com/ufrisk/pcileech-fpga
* LeechCore: https://github.com/ufrisk/LeechCore
* MemProcFS: https://github.com/ufrisk/MemProcFS
#### Other:
* Blog: http://blog.frizk.net
* Twitter: https://twitter.com/UlfFrisk
* YouTube: https://www.youtube.com/channel/UC2aAi-gjqvKiC7s7Opzv9rg

Changelog:
==========
v1.0
* Initial release.

v1.1-v3.6
* Various updates. please see individual relases for more information.

v4.0
* Major cleanup and internal refactorings.
* FPGA max memory auto-detect and more stable dumping strategy.
* New stable Windows 10 kernel injects with FPGA hardware on non-virtualization based security systems.
* User mode injects (experimental).
* Removal of built-in device support - the [LeechCore](https://github.com/ufrisk/LeechCore) `leechcore.dll`/`leechcore.so` library is now used instead. New devices include:
  * Memory dump files (raw linear dump files and microsoft crash dump files).
  * Hyper-V save files.
  * Live memory via DumpIt / WinPmem.
  * remote devices via -remote setting.
* Removal of API and built-in _Memory Process File System_ - please use the more capable APIs in the [LeechCore](https://github.com/ufrisk/LeechCore) and [Memory Process File System](https://github.com/ufrisk/MemProcFS) instead.
* Multiple other changes and syntax updates.

v4.1
* LeechAgent support - remote memory acquisition and analysis.

[v4.2](https://github.com/ufrisk/pcileech/releases/tag/v4.2)
* Signature updates:
  * Linux kernel module - LINUX_X64_48 (latest versions)
  * Win10 1903 kernel module - WIN10_X64_2 (requires windows version of PCILeech)
  
[v4.3](https://github.com/ufrisk/pcileech/releases/tag/v4.3)
* Bug fixes.
* Support for new device (NeTV2 / RawUDP) via LeechCore library.

Latest:
* Bug fixes and stability improvements.
