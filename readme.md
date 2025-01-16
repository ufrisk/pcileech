PCILeech Summary:
=================
PCILeech uses PCIe hardware devices to read and write target system memory. This is achieved by using DMA over PCIe. No drivers are needed on the target system. 

<b>PCILeech also works without hardware together with a wide range of software memory acqusition methods supported by the LeechCore library - including capture of remote live memory using DumpIt or WinPmem. PCILeech also supports local capture of memory and a number of memory dump file formats.</b>

PCILeech supports multiple memory acquisition devices. Both hardware and software based. USB3380 based hardware is only able to read 4GB of memory natively, but is able to read all memory if a kernel module (KMD) is first inserted into the target system kernel. FPGA based hardware, and software based methods, are able to read all memory.

PCILeech is capable of inserting a wide range of kernel implants into the targeted kernels - allowing for easy access to live ram and the file system via a "mounted drive". It is also possible to remove the logon password requirement, loading unsigned drivers, executing code and spawn system shells. PCIleech runs on Windows and Linux. Supported target systems are currently the x64 versions of: UEFI, Linux, FreeBSD and Windows. This requires write access to memory (USB3380 hardware, FPGA hardware, LiveCloudKd or CVE-2018-1038 "Total Meltdown").

<b>To get going clone the sources in the repository or download the latest [binaries, modules and configuration files](https://github.com/ufrisk/pcileech/releases/latest).</b>

The [PushPin GUI frontend](https://github.com/LuckyPi/PushPin) for PCILeech makes common RedTeam tasks super easy. Note that PushPin is not part of the official PCILeech distribution.

<img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_mbp.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_m2.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_shadow.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/2df37be67047e19ea2c3f73be67a0ba06fea203d/_gh_dump.gif" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/ab5032dac2600acf1480d81ac265b66fecaaa9b2/_gh_ac701_pcileech_main.jpg" height="150"/><img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/d2ff68ce273b3bb2712d2e07555c910b3c3ec65f/_gh_pciescreamer_pcileech_main_150.png" height="150"/><img src="https://raw.githubusercontent.com/LuckyPi/PushPin/master/pushpin_description.PNG" height="150"/>


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

| Device                                                                         | Type | Interface | Speed | 64-bit memory access | PCIe TLP access | Project<br>Sponsor |
| -------------------------------------------------------------------------------| ---- | --------- | ----- | -------------------- | --------------- | ------------------ |
| [Screamer PCIe Squirrel](https://github.com/ufrisk/pcileech-fpga/tree/master/PCIeSquirrel) | [FPGA](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA) | USB-C | 190MB/s  | Yes | Yes | 💖 |
| [ZDMA](https://github.com/ufrisk/pcileech-fpga/blob/master/ZDMA)                  | [FPGA](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)   | Thunderbolt3 | 1000MB/s | Yes | Yes | 💖 |
| [LeetDMA](https://github.com/ufrisk/pcileech-fpga)                                | [FPGA](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)          | USB-C | 190MB/s  | Yes | Yes | 💖 |
| [AC701/FT601](https://github.com/ufrisk/pcileech-fpga/tree/master/ac701_ft601)    | [FPGA](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA)          | USB3  | 190MB/s  | Yes | Yes |    |
| USB3380-EVB                                                                       | [USB3380](https://github.com/ufrisk/LeechCore/wiki/Device_USB3380)    | USB3  | 150MB/s  | No  | No  |    |
| DMA patched HP iLO                                                                | [BMC](https://github.com/ufrisk/LeechCore/wiki/Device_RawTCP)         | TCP   |  1MB/s   | Yes | No  |    |

### Software based memory aqusition methods:

Please find a summary of the supported software based memory acquisition methods listed below. Please note that the LeechService only provides a network connection to a remote LeechCore library. It's possible to use both hardware and software based memory acquisition once connected.

| Device                     | Type             | Volatile | Write | Linux Support | Plugin |
| -------------------------- | ---------------- | -------- | ----- | ------------- | ------ |
| [RAW physical memory dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)         | File             | No  | No  | Yes | No  |
| [Full Microsoft Crash Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)        | File             | No  | No  | Yes | No  |
| [Full ELF Core Dump](https://github.com/ufrisk/LeechCore/wiki/Device_File)               | File             | No  | No  | Yes | No  |
| [VMware](https://github.com/ufrisk/LeechCore/wiki/Device_VMWare)                         | Live&nbsp;Memory | Yes | Yes | No  | No  |
| [VMware memory save file](https://github.com/ufrisk/LeechCore/wiki/Device_File)          | File             | No  | No  | Yes | No  |
| [TotalMeltdown](https://github.com/ufrisk/LeechCore/wiki/Device_Totalmeltdown)           | CVE-2018-1038    | Yes | Yes | No  | No  |
| [DumpIt /LIVEKD](https://github.com/ufrisk/LeechCore/wiki/Device_DumpIt)                 | Live&nbsp;Memory | Yes | No  | No  | No  |
| [WinPMEM](https://github.com/ufrisk/LeechCore/wiki/Device_WinPMEM)                       | Live&nbsp;Memory | Yes | No  | No  | No  |
| [LiveKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveKd)                         | Live&nbsp;Memory | Yes | No  | No  | No  |
| [LiveCloudKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd)               | Live&nbsp;Memory | Yes | Yes | No  | Yes |
| [Hyper-V Saved State](https://github.com/ufrisk/LeechCore/wiki/Device_HyperV_SavedState) | File             | No  | No  | No  | Yes |
| [LeechAgent*](https://github.com/ufrisk/LeechCore/wiki/Device_Remote)                    | Remote           |     |     | No  | No  |

Installing PCILeech:
====================
Please ensure you do have the most recent version of PCILeech by visiting the PCILeech github repository at: https://github.com/ufrisk/pcileech

<b>Get the latest [binaries, modules and configuration files](https://github.com/ufrisk/pcileech/releases/latest) from the latest release.</b> Alternatively clone the repository and build from source.

#### Windows:

Please see the [PCILeech on Windows](https://github.com/ufrisk/pcileech/wiki/PCILeech-on-Windows) guide for information about running PCILeech on Windows.

The Google Android USB driver have to be installed if USB3380 hardware is used. Download the Google Android USB driver from: http://developer.android.com/sdk/win-usb.html#download Unzip the driver.<br>
FTDI drivers have to be installed if FPGA is used with FT601 USB3 addon card or PCIeScreamer. Download the 64-bit [`FTD3XX.dll`](https://ftdichip.com/wp-content/uploads/2023/11/FTD3XXLibrary_v1.3.0.8.zip) from FTDI and place it alongside `pcileech.exe`.<br>
To mount live ram and target file system as drive in Windows the Dokany2 file system library must be installed. Please download and install the latest stable version of Dokany2 at: https://github.com/dokan-dev/dokany/releases/latest

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
* ` pcileech.exe dump -force -device usb3380://usb=2 `

Receive PCIe TLPs (Transaction Layer Packets) and print them on screen (correctly configured FPGA dev board required).
* ` pcileech.exe tlp -vv -wait 1000 `

Probe/Enumerate the memory of the target system for readable memory pages and maximum memory. (FPGA hardware only).
* ` pcileech.exe probe `

Dump all memory between addresses min and max, don't stop on failed pages. Native access to 64-bit memory is only supported on FPGA hardware.
* ` pcileech.exe dump -min 0x0 -max 0x21e5fffff -force `

Dump all memory, try locate the memory map from the target system registry to avoid dumping potentially invalid memory which may freeze the target.
* ` pcileech.exe dump -memmap auto `

Force the usage of a specific device (instead of default auto detecting it). The pmem device is not auto detected.
* ` pcileech.exe pagedisplay -min 0x1000 -device pmem `

Dump remote memory from a remote LeechAgent using connection encrypted and mutually authenticated by kerberos.
* ` pcileech.exe dump -device pmem -remote rpc://computer$@ad.contoso.com `

Execute the Python analysis script `find-rwx.py` on a remote computer using the LeechAgent embedded Python environment.
* ` pcileech.exe agent-execpy -in find-rwx.py -device pmem -remote rpc://computer$@ad.contoso.com `

Dump memory using the the reported "TotalMeltdown" [Windows 7/2008R2 x64 PML4 page table permission vulnerability](https://blog.frizk.net/2018/03/total-meltdown.html).
* ` pcileech.exe dump -out memdump_win7.raw -device totalmeltdown -v -force `

Insert a kernel module into a running Linux system remotely via a [DMA patched HP iLO](https://www.synacktiv.com/posts/exploit/using-your-bmc-as-a-dma-device-plugging-pcileech-to-hpe-ilo-4.html).
* ` pcileech.exe kmdload -vvv -device -device RawTCP://127.0.0.1:8888 -kmd LINUX_X64_48 `

Patch virtual process memory of pid 432 (lsass.exe in this example).
* ` pcileech.exe patch -pid 432 -sig unlock_win10x64.sig `

Limitations/Known Issues:
=========================
* Does not work if the OS uses the IOMMU/VT-d. This is the default on macOS (unless disabled in recovery mode). Windows 10/11 with Virtualization based security features enabled does not work fully.
* Recent Windows and Linux versions block DMA by default.
* Some Linux kernels does not work. Sometimes a required symbol is not exported in the kernel and PCILeech fails.
* File system mount support only exists for Windows (Linux version is planned).
* Remote connectivity support only exists for Windows.



PCILeech and MemProcFS community:
=========
Find all this a bit overwhelming? Or just want to ask a quick question? Join the PCILeech and MemProcFS DMA community server at Discord!

<a href="https://discord.gg/pcileech"><img src="https://discord.com/api/guilds/1155439643395883128/widget.png?style=banner3"/></a>



Building:
=========
The binaries are found in the [releases section](https://github.com/ufrisk/pcileech/releases/latest) of this repository. If one wish to build an own version it is possible to do so. Please see the [PCILeech on Windows](https://github.com/ufrisk/pcileech/wiki/PCILeech-on-Windows) or [PCILeech on Linux](https://github.com/ufrisk/pcileech/wiki/PCILeech-on-Linux) for more information about building PCILeech. PCILeech is also dependant on LeechCore and optionally (for some extra functionality) on The Memory Process File System which must both be built separately.

Contributing:
=============
PCILeech, MemProcFS and LeechCore are open source but not open contribution. PCILeech, MemProcFS and LeechCore offers a highly flexible plugin architecture that will allow for contributions in the form of plugins. If you wish to make a contribution, other than a plugin, to the core projects please contact me before starting to develop.

Links:
======
* Twitter: [![Twitter](https://img.shields.io/twitter/follow/UlfFrisk?label=UlfFrisk&style=social)](https://twitter.com/intent/follow?screen_name=UlfFrisk)
* Discord: [![Discord - PCILeech/MemProcFS](https://img.shields.io/discord/1155439643395883128.svg?label=&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/pcileech)
* PCILeech: https://github.com/ufrisk/pcileech
* PCILeech FPGA: https://github.com/ufrisk/pcileech-fpga
* LeechCore: https://github.com/ufrisk/LeechCore
* MemProcFS: https://github.com/ufrisk/MemProcFS
* Blog: http://blog.frizk.net
* PushPin: GUI for PCILeech: https://github.com/LuckyPi/PushPin

Support PCILeech/MemProcFS development:
=======================================
PCILeech and MemProcFS is free and open source!

I put a lot of time and energy into PCILeech and MemProcFS and related research to make this happen. Some aspects of the projects relate to hardware and I put quite some money into my projects and related research. If you think PCILeech and/or MemProcFS are awesome tools and/or if you had a use for them it's now possible to contribute by becoming a sponsor! 
 
If you like what I've created with PCIleech and MemProcFS with regards to DMA, Memory Analysis and Memory Forensics and would like to give something back to support future development please consider becoming a sponsor at: [`https://github.com/sponsors/ufrisk`](https://github.com/sponsors/ufrisk)

To all my sponsors, Thank You 💖 

All sponsorships are welcome, no matter how large or small.

Changelog:
==========
<details><summary>Previous releases (click to expand):</summary>

v1.0-v3.6
* Initial release and various updates. please see individual relases for more information.

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

[v4.4](https://github.com/ufrisk/pcileech/releases/tag/v4.4)
* Bug fixes and stability improvements.
* Support for MemProcFS v3 library.
* Code signing of binaries.
* "tlploop" command.

[v4.5](https://github.com/ufrisk/pcileech/releases/tag/v4.5)
* Bug fixes.
* Support for v2 of the LeechCore memory acquisition library.
* MemProcFS integration when running on Windows.
* Support for user-defined physical memory map (-memmap option).

[v4.6](https://github.com/ufrisk/pcileech/releases/tag/v4.6)
* Support for [LiveCloudKd](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd).

[v4.7](https://github.com/ufrisk/pcileech/releases/tag/v4.7)
* Bug fixes.
* WIN10_X64_3 new stable kernel signature for Windows 10 - including Win10 2004 release.
* Unlock signature updates - Win10/Linux (NB! most recent kernels on Linux not yet supported).

[v4.8](https://github.com/ufrisk/pcileech/releases/tag/v4.8)
* Bug fixes.
* Better support for recent x64 Linux kernels.

[v4.9](https://github.com/ufrisk/pcileech/releases/tag/v4.9)
* Bug fixes.
* Signature updates.
* Better support for recent x64 Linux kernels (Ubuntu 21.04).
* Unmount of monted driver when CTRL+C pressed.
  </details>

[v4.10](https://github.com/ufrisk/pcileech/releases/tag/v4.10)
* Linux support for Windows 10 built-in signatures (dependency on MemProcFS v4.0).
* Separate releases for Windows and Linux.
* General cleanup.

[v4.11](https://github.com/ufrisk/pcileech/releases/tag/v4.11)
* Support for VMWare Workstation/Player live VM memory.
* Support for remote memory analysis with LeechAgent `agent-forensic` command.
  * Runs MemProcFS forensic mode remotely.
  * Retrieves ElasticSearch compatible JSON data.

[v4.12](https://github.com/ufrisk/pcileech/releases/tag/v4.12)
* 32-bit support (pcileech binary).

[v4.13](https://github.com/ufrisk/pcileech/releases/tag/v4.13)
* Bug fixes.
* Mount improvements:
  - Windows host file system support: Upgrade to [Dokany2](https://github.com/dokan-dev/dokany/releases) (NB! Dokany2 will have to be installed!).
  - Linux host file system support: FUSE support added. <br/>Example: `./pcileech mount /home/user/fusemnt/leechfs -kmd <your_kmd_address>`
  - Now possible to access other local drives than C: on Windows targets.
* Visual Studio 2022 Support.

[v4.14](https://github.com/ufrisk/pcileech/releases/tag/v4.14)
* Process Virtual Memory support (Windows only).
  - Commands: search, patch, write, display, pagedisplay
  - Example:  pcileech patch -pid 732 -sig unlock_win10x64.sig

[v4.15](https://github.com/ufrisk/pcileech/releases/tag/v4.15)
* Support for MemProcFS v5.0

[v4.16](https://github.com/ufrisk/pcileech/releases/tag/v4.16)
* FPGA performance improvements.
* Command `none` added.
* Options `-bar-ro` and `-bar-rw` added.

[v4.17](https://github.com/ufrisk/pcileech/releases/tag/v4.17)
* I/O BAR support.
* Linux improvements:
  - KMD signature update (LINUX_X64_48) to support latest Ubuntu kernels.
  - Update of kernel modules to support latest kernels.
  - New KMD signature - LINUX_X64_MAP - specify target system kernel System.map in -in option.
  - New kernel module: lx64_exec_root.
* Linux PCIe FPGA performance improvements.

[v4.18](https://github.com/ufrisk/pcileech/releases/tag/v4.18)
* Benchmark command added.
* Unlock signatures updated.
* `-psname` option added.

[v4.19](https://github.com/ufrisk/pcileech/releases/tag/v4.19)
* Linux stability improvements and kernel module loading enhancements.
* Linux clang compilation support.
* macOS support.
