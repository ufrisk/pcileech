// help.c : implementation related to displaying help texts.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "help.h"
#include "util.h"
#include "version.h"

VOID ShowListFiles(_In_ LPSTR szSearchPattern, _In_ DWORD cchSpaces, _In_ DWORD cchPre, _In_ DWORD cchPost)
{
    WIN32_FIND_DATAA data;
    HANDLE h;
    CHAR szSearch[MAX_PATH];
    Util_GetFileInDirectory(szSearch, szSearchPattern);
    h = FindFirstFileA(szSearch, &data);
    while(h != INVALID_HANDLE_VALUE) {
        data.cFileName[strlen(data.cFileName) - cchPost] = 0;
        if(!cchPre || !memcmp(data.cFileName, szSearchPattern, cchPre)) {
            printf("%*c%s\n", cchSpaces, ' ', data.cFileName + cchPre);
        }
        if(!FindNextFileA(h, &data)) {
            return;
        }
    }
}

VOID Help_ShowGeneral()
{
    printf(
        " PCILEECH COMMAND LINE REFERENCE                                               \n" \
        " PCILeech can run in two modes - NATIVE (default), Kernel Module Assisted (KMD)\n" \
        " KMD mode may be triggered by supplying the option kmd and optionally cr3 / pt.\n" \
        " If an address is supplied in the kmd option pcileech will use the already ins-\n" \
        " erted KMD. The already inserted KMD will be left intact upon exit.  If the KMD\n" \
        " contains a kernel mode signature the kernel module will be loaded and then un-\n" \
        " loaded on program exit ( except for the kmdload command ).                    \n" \
        " KMD mode may access all memory (available to the kernel of the target system).\n" \
        " NATIVE mode may access 4GB memory if USB3380 hardware is used.                \n" \
        " NATIVE mode may access all memory if FPGA based hardware is used such as the: \n" \
        "   SP605/FT601, AC701/FT601 and PCIeScreamer. This mode also works for software\n" \
        "   based acquisition methods such as Files, DumpIt, WinPmem or any other method\n" \
        "   supported by the LeechCore library. For more information check out:         \n" \
        "   https://github.com/ufrisk/PCILeech and  https://github.com/ufrisk/LeechCore \n" \
        " For detailed help about a specific command type:  pcileech <command> -help    \n" \
        " General syntax: pcileech <command> [-<optionname1> <optionvalue1>] ...        \n" \
        " VALID COMMANDS           MODEs        [ OPTIONS ]    (REQUIREMENTS)           \n" \
        "   info                   NATIVE,KMD                                           \n" \
        "   dump                   NATIVE,KMD   [ min, max, out ]                       \n" \
        "   patch                  NATIVE,KMD   [ min, max, sig, all ]                  \n" \
        "   write                  NATIVE,KMD   [ min, in ]                             \n" \
        "   search                 NATIVE,KMD   [ min, max, sig, in, all ]              \n" \
        "   [implant]                     KMD   [ in, out, s, 0..9 ]                    \n" \
        "   kmdload                NATIVE       [ pt, cr3 ]                             \n" \
        "   kmdexit                       KMD                                           \n" \
        "   mount                  NATIVE,KMD   [ s, cr3 ]     (Windows)                \n" \
        "   display                NATIVE,KMD   [ min, max ]                            \n" \
        "   pagedisplay            NATIVE,KMD   [ min ]                                 \n" \
        "   pt_phys2virt           NATIVE,KMD   [ cr3, 0 ]                              \n" \
        "   pt_virt2phys           NATIVE,KMD   [ cr3, 0 ]                              \n" \
        "   testmemread            NATIVE       [ min ]                                 \n" \
        "   testmemreadwrite       NATIVE       [ min ]                                 \n" \
        " Device specific commands and valid MODEs [ and options ] (and device):        \n" \
        "   tlp                    NATIVE       [ in ]         (FPGA)                   \n" \
        "   tlploop                NATIVE       [ in ]         (FPGA)                   \n" \
        "   probe                  NATIVE       [ min, max ]   (FPGA)                   \n" \
        "   pslist                 NATIVE                      (Windows)                \n" \
        "   psvirt2phys            NATIVE       [ 0, 1 ]       (Windows)                \n" \
        "   agent-execpy           NATIVE       [ in, out ]    (Remote LeechAgent)      \n" \
        " System specific commands and valid MODEs [ and options ]:                     \n" \
        "   mac_fvrecover          NATIVE                      (USB3380)                \n" \
        "   mac_fvrecover2         NATIVE                      (USB3380)                \n" \
        "   mac_disablevtd         NATIVE                      (USB3380)                \n" \
        " External plugin commands:                                                     \n");
    ShowListFiles("leechp_*"PCILEECH_LIBRARY_FILETYPE, 3, 7, (DWORD)strlen(PCILEECH_LIBRARY_FILETYPE));
    printf(
        " Valid options:                                                                \n" \
        "   -device: The memory acquisition device to including config options in the   \n" \
        "          device connection string. If option is not given the USB3380 and FPGA\n" \
        "          will be auto-detected. For a complete list of supported devices and  \n" \
        "          their individual config options check out the documentation for the  \n" \
        "          LeechCore library at: https://github.com/ufrisk/LeechCore            \n" \
        "          Affects all modes and commands.                                      \n" \
        "          Common valid options: USB3380, FPGA, DumpIt, <memory-dump-file-name> \n" \
        "   -remote: Connect to a remote system LeechSvc to acquire remote memory. This \n" \
        "          is a Windows-only feature. Specify remote host and remote user to    \n" \
        "          authenticate (or insecure if no authenciation). Kerberos-secure conn.\n" \
        "          Example: rpc://<remote-user-spn_or_insecure>:<remote_host>           \n" \
        "   -min : memory min address, valid range: 0x0 .. 0xffffffffffffffff           \n" \
        "          default: 0x0                                                         \n" \
        "   -max : memory max address, valid range: 0x0 .. 0xffffffffffffffff           \n" \
        "          default: <max supported by device> (FPGA = no limit, USB3380 = 4GB)  \n" \
        "   -out : name of output file.                                                 \n" \
        "          default: pcileech-<minaddr>-<maxaddr>-<date>-<time>.raw              \n" \
        "          No output file will be created if parameter is set to none or null.  \n" \
        "   -all : search all memory for signature - do not stop at first occurrence.   \n" \
        "          Option has no value. Example: -all                                   \n" \
        "   -v   : verbose option. Additional information is displayed in the output.   \n" \
        "          Affects all modes and commands. Option has no value. Example: -v     \n" \
        "   -vv  : extra verbose option. More detailed additional information is shown  \n" \
        "          in output. Option has no value. Example: -vv                         \n" \
        "   -vvv : super verbose option. Show all data transferred such as PCIe TLPs.   \n" \
        "          Option has no value. Example: -vvv                                   \n" \
        "   -force: force reads and writes even though target memory is marked as not   \n" \
        "          accessible. Dangerous! Affects all modes and commands.               \n" \
        "          Option has no value. Example: -force                                 \n" \
        "   -tlpwait: Wait in seconds while listening for PCIe TLPs.                    \n" \
        "          Wait occurs after any other actions have been completed.             \n" \
        "   -help: show help about the selected command or implant and then exit        \n" \
        "          without running the command. Affects all modes and commands.         \n" \
        "          Option has no value. Example: -help                                  \n" \
        "   -hook: Where to place a hook. In case of IAT hooking (UMD*IAT*) specify as: \n" \
        "          <imported-module>!<function-to-hook> Example: msvcrt.dll!memcpy      \n" \
        "   -in  : file name or hexstring to load as input.                             \n" \
        "          Examples: -in 0102030405060708090a0b0c0d0e0f or -in firmware.bin     \n" \
        "   -s   : string input value.                                                  \n" \
        "          Example: -s \"\\\\??\\C:\\Windows\\System32\\cmd.exe\"               \n" \
        "   -0..9: QWORD input value. Example: -0 0xff , -3 0x7fffffff00001000 or -2 13 \n" \
        "          default: 0                                                           \n" \
        "   -pt  : trigger KMD insertion by automatic page table hijack.                \n" \
        "          Option has no value. Example: -pt. Used in conjunction with          \n" \
        "          -kmd option to trigger KMD insertion by page table hijack.           \n" \
        "   -cr3 : base address of page table (PML4) / CR3 CPU register.                \n" \
        "   -efibase : base address of EFI table when inserting select kernel modules.  \n" \
        "          EFI_SYSTEM_TABLE(IBI SYST) == UEFI ; RUNTSERV == LINUX RUNTSERV EFI. \n" \
        "   -memmap : specify a physical memory map given in a file or specify 'auto'.  \n" \
        "          to use MemProcFS (Windows required on target&host)                   \n" \
        "          example: -memmap c:\\temp\\my_custom_memory_map.txt                  \n" \
        "          example: -memmap auto                                                \n" \
        "   -kmd : address of already loaded kernel module helper (KMD).                \n" \
        "          ALTERNATIVELY                                                        \n" \
        "          kernel module to use, see list below for choices:                    \n" \
        "             WIN10_X64                                                         \n" \
        "             WIN10_X64_2         (Requires: FPGA & Windows)                    \n" \
        "             WIN10_X64_3         (Requires: FPGA & Windows)                    \n" \
        "             LINUX_X64_46        (NB! Kernels 2.6.33 - 4.6)                    \n" \
        "             LINUX_X64_48        (NB! Kernels 4.8+, FPGA only)                 \n" \
        "             LINUX_X64_EFI       (NB! UEFI booted systems only)                \n" \
        "             FREEBSD_X64                                                       \n" \
        "             MACOS                                                             \n" \
        "             UEFI_EXIT_BOOT_SERVICES                                           \n" \
        "             UEFI_SIGNAL_EVENT                                                 \n");
    ShowListFiles("*.kmd", 13, 0, 4);
    printf(
        "   -sig : available patches - including operating system unlock patches:       \n");
    ShowListFiles("*.sig", 13, 0, 4);
    printf(
        " User-Mode implants: EXPERIMENTAL! (Requires: Windows)                         \n" \
        "             UMD_WINX64_IAT_PSEXEC                                             \n" \
        " Kernel-mode implants:                                                         \n");
    ShowListFiles("*.ksh", 13, 0, 4);
    printf("\n");
}

VOID Help_ShowInfo()
{
    printf(
        " PCILEECH INFORMATION                                                          \n" \
        " PCILeech (c) 2016-2020 Ulf Frisk                                              \n" \
        " Version: " \
        VER_FILE_VERSION_STR "\n" \
        "                                                                               \n" \
        " License: GNU GENERAL PUBLIC LICENSE - Version 3, 29 June 2007                 \n" \
        " Contact information: pcileech@frizk.net                                       \n" \
        " System requirements: 64-bit Windows 7, 10 or Linux.                           \n" \
        " Other project references:                                                     \n" \
        "   PCILeech          - https://github.com/ufrisk/pcileech                      \n" \
        "   PCILeech-FPGA     - https://github.com/ufrisk/pcileech-fpga                 \n" \
        "   LeechCore         - https://github.com/ufrisk/LeechCore                     \n" \
        "   MemProcFS         - https://github.com/ufrisk/MemProcFS                     \n" \
        "   Google USB Driver - https://developer.android.com/sdk/win-usb.html          \n" \
        "   FTDI FT601 Driver - http://www.ftdichip.com/Drivers/D3XX.htm                \n" \
        "   PCIe Injector     - https://github.com/enjoy-digital/pcie_injector          \n" \
        "   Dokany            - https://github.com/dokan-dev/dokany/releases/latest     \n" \
        " ----------------                                                              \n" \
        " Use with memory dump files, DumpIt, WinPmem in read-only mode.                \n" \
        " Use with USB3380 hardware programmed as a PCILeech device.                    \n" \
        " Use with FPGA harware programmed as a PCILeech FPGA device.                   \n\n" \
        " ----------------                                                              \n" \
        " Driver information (USB3380/Windows):                                         \n" \
        "   The USB3380 HW requires a dummy driver to function properly. The PCILeech   \n" \
        "   device masks as a Google Glass. Please download and install the Google USB  \n" \
        "   driver before proceeding by using the USB3380 device. USB3 is recommended   \n" \
        "   to performance reasons (USB2 will work but impact performance).             \n" \
        " Driver information (FPGA/FT601/Windows):                                      \n" \
        "   The PCILeech programmed FPGA board with FT601 USB3 requires drivers for USB.\n" \
        "   The drivers are on Windows update and is installed at first use.            \n" \
        "   PCILeech also requires the FTDI application library (DLL). Download DLL from\n" \
        "   FTDI web site and place the 64-bit FTD3XX.dll alongside pcileech.exe.       \n" \
        " Driver information (Dokany/Windows):                                          \n" \
        "   To be able to use the 'mount' functionality for filesystem browsing PCILeech\n" \
        "   requires Dokany to be installed for virtual file system support. Download   \n" \
        "   and install Dokany on your computer before using the mount functionality.   \n" \
        " Driver information (USB3380/Linux):                                           \n" \
        "   PCILeech on Linux requires that libusb is installed. Libusb is most probably\n" \
        "   installed by default, if not install by running:apt-get install libusb-1.0-0\n" \
        " Driver information (FPGA/FT601/Linux):                                        \n" \
        "   The PCILeech programmed FPGA board with FT601 USB3 requires drivers for USB.\n" \
        "   The driver is a small kernel driver found in the drivers/ft60x folder in the\n" \
        "   PCIe Injector Github repository. Once loaded the driver will expose a device\n" \
        "   named /dev/ft60x[0-3] Please note that this device file must be read/write  \n" \
        "   for the current user for PCILeech to find and use it automatically.         \n" \
        " ----------------                                                              \n" \
        " Notes about the PCILeech USB3380 device:                                      \n" \
        " Usage: connect USB3380 device to target computer and USB cable to the computer\n" \
        " executing pcileech. If all memory reads fail try to re-insert the device.     \n" \
        " - It is only possible to access the lower 4GB of RAM (32-bit) with DMA.       \n" \
        " - It may not be possible to access RAM if OS configured IOMMU (VT-d).         \n" \
        "   macOS defaults to VT-d. Windows 10 may, if configured, also use VT-d.       \n" \
        " - No drivers are needed on the target! Memory acquisition is all in hardware! \n" \
        " - Confirmed working with PCIe/mPCIe/ExpressCard/Thunderbolt.                  \n" \
        " - If kernel module is successfully inserted in lower 4GB RAM more RAM will be \n" \
        "   possible to read. Extended funtionality will also be made available.        \n" \
        " ----------------                                                              \n");
    Help_ShowGeneral();
}

VOID _HelpShowExecCommand()
{
    BOOL result;
    PKMDEXEC pKmdExec = NULL;
    result = Util_LoadKmdExecShellcode(ctxMain->cfg.szShellcodeName, &pKmdExec);
    if(!result) {
        printf("HELP: Failed loading shellcode from file: '%s.ksh' ...\n", ctxMain->cfg.szShellcodeName);
        return;
    }
    printf(
        " SHELLCODE IMPLANT HELP: Execute a custom implant in the target kernel.        \n" \
        " MODES   : KMD                                                                 \n" \
        " OPTIONS : -in, -out, -s, -0, -1, -2, -3, -4, -5, -6, -7, -8, -9               \n");
    printf(" Implant loaded from file: %s.ksh\n", ctxMain->cfg.szShellcodeName);
    printf(
        " Implant specific help (output values are left empty/set to zero):             \n" \
        " ============================================================================= \n");
    printf(pKmdExec->szOutFormatPrintf, "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    LocalFree(pKmdExec);
}

VOID Help_ShowDetailed()
{
    switch(ctxMain->cfg.tpAction) {
    case DUMP:
        printf(
            " DUMP MEMORY FROM TARGET SYSTEM TO FILE.                                       \n" \
            " MODES   : NATIVE, KMD                                                         \n" \
            " OPTIONS : -min, -max, -out, -force                                            \n" \
            " The physical memory is dumped to file. If no file is specified in the -out    \n" \
            " option then a default named file is created. When dumping in NATIVE mode the  \n" \
            " max memory will be auto-detected (unless if the USB3380 hardware is used).    \n" \
            " When dumping in KMD mode readable physical memory accessible to the kernel is \n" \
            " dumped automatically. It is possible to override auto-detected sections with  \n" \
            " the -min and -max options. Unreadable memory will be zero-padded.             \n" \
            " Please note that using the -force option may result in a system crash.        \n" \
            " The DUMP command dumps 4kB memory pages. Partial pages are not supported.     \n" \
            " EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
            " 1) dump memory up to 4GB by using NATIVE mode:                                \n" \
            "    pcileech dump                                                              \n" \
            " 2) dump memory as seen by the kernel using kernel module:                     \n" \
            "    pcileech dump -kmd 0x7fffe000                                              \n" \
            " 3) dump memory between 5GB and 6GB:                                           \n" \
            "    pcileech dump -min 0x140000000 -max 0x180000000                            \n" \
            " 4) dump memory to file c:\\temp\\out.raw:                                     \n" \
            "    pcileech dump -kmd 0x7fffe000 -out \"c:\\temp\\out.raw\"                   \n" \
            " 5) dump memory from remote LeechService using DumpIt:                         \n" \
            "    pcileech dump -device dumpit -remote rpc://userspn@ad.domain.com -out 1.dmp\n" \
        );
        break;
    case WRITE:
        printf(
            " WRITE DATA TO TARGET SYSTEM MEMORY.                                           \n" \
            " MODES   : NATIVE, KMD                                                         \n" \
            " OPTIONS : -min, -in, -force                                                   \n" \
            " WRITE will write contents specified in the -in option to the memory address   \n" \
            " specified by the -min option. The memory address may be unaligned. It is also \n" \
            " possible to try to write to non-accessible memory - such as PCIe memory mapped\n" \
            " devices with the -force option. Please note that using the -force option may  \n" \
            " result in a system crash. In KMD mode the write is performed by the target    \n" \
            " operating system. In NATIVE mode the write is performed by the PCILeech device\n" \
            " EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
            " 1) write the bytes 11223344 to the physical address 0x1003                    \n" \
            "    pcileech write -min 0x1003 -in 11223344                                    \n" \
            " 2) write contents in the file replace.bin to the address 0x140000000          \n" \
            "    pcileech write -min 0x140000000 -in replace.bin -kmd 0x7fffe000            \n" \
            " 3) write the bytes 11223344 to the protected address 0xfffe0008               \n" \
            "    pcileech write -min 0xfffe0008 -in 11223344 -force                         \n");
        break;
    case PATCH:
        printf(
            " PATCH THE MEMORY OF THE TARGET SYSTEM.                                        \n" \
            " MODES   : NATIVE, KMD                                                         \n" \
            " OPTIONS : -min, -max, -sig, -all, -force                                      \n" \
            " Patch loads one or several signatures from the .sig file specified in the -sig\n" \
            " option. The -sig option should be specified without file extension. The memory\n" \
            " is scanned until the first signature match is made. The memory is then patched\n" \
            " with new contents according to the loaded signature. After a match has been   \n" \
            " made PCILeech exits. If all available memory should be searched for signatures\n" \
            " please supply the -all option. The options -min and -max may also optionally  \n" \
            " be given to limit the memory space searched. Patching is performed per 4096   \n" \
            " byte page. Signatures spanning multiple pages are unsupported.                \n" \
            " EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
            " 1) try patch the memory with the unlock_win10x64 signature (kmd not loaded)   \n" \
            "    pcileech patch -sig unlock_win10x64                                        \n" \
            " 2) patch the memory with the unlock_win10x64 signature (kmd loaded)           \n" \
            "    pcileech patch -sig unlock_win10x64 -kmd 0x7fffe000                        \n" \
            " 3) patch all occurences with the patch_test signature                         \n" \
            "    pcileech patch -sig patch_test -kmd 0x7fffe000 -all                        \n");
        break;
    case SEARCH:
        printf(
            " SEARCH THE MEMORY OF THE TARGET SYSTEM FOR THE GIVEN SIGNATURE.               \n" \
            " MODES   : NATIVE, KMD                                                         \n" \
            " OPTIONS : -min, -max, -sig, -in, -all, -force                                 \n" \
            " Search the memory for signatures specified in the -sig or -in options. If the \n" \
            " -sig option is specified signatures are loaded from the signature file and are\n" \
            " search for at their fixed page offsets. If the signature is specified with the\n" \
            " -in option the whole memory at all page offsets is searched. The memory ranges\n" \
            " searched can be limited by supplying optional -min and -max options. It is    \n" \
            " also possible to search restricted memory by supplying the -force option. When\n" \
            " a signature is found the search is stopped unless the -all option is given.   \n" \
            " Searching is performed per 4096 byte page. Signatures spanning multiple pages \n" \
            " are unsupported.                                                              \n" \
            " EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
            " 1) search for the first location that matches the unlock_win10x64 signature.  \n" \
            "    pcileech search -sig unlock_win10x64                                       \n" \
            " 2) search for all locations that matches the unlock_win10x64 signature.       \n" \
            "    pcileech search -sig unlock_win10x64 -all                                  \n" \
            " 3) search for all unlock_win10x64 locations by using a kernel module.         \n" \
            "    pcileech search -sig unlock_win10x64 -all -kmd 0x7fffe000                  \n" \
            " 3) search for all locations that contain the pattern 444d4152.                \n" \
            "    pcileech search -in 444d4152 -all -kmd 0x7fffe000                          \n" \
            " 4) search for the first location containing the pattern in the file pat.bin.  \n" \
            "    pcileech search -in pat.bin -all -kmd 0x7fffe000                           \n");
        break;
    case MOUNT:
        printf(
            " MOUNT TARGET LIVE RAM AND FILE SYSTEM AS 'NETWORK DRIVE'.                     \n" \
            " MODES   : KMD                                                                 \n" \
            " REQUIRE : Windows/Dokany                                                      \n" \
            " OPTIONS : -s                                                                  \n" \
            " Mount the target system live ram and file system as the drive letter specified\n" \
            " in the -s option. If the -s option is not specified PCILeech will try to mount\n" \
            " the target file system as the K: drive letter.                                \n" \
            " File system comes with two main functionalities, mount target system files if \n" \
            " hardware device is used, and mount memory process file system (in read-only   \n" \
            " mode when dump file is used, in read-write mode when hardware device is used).\n" \
            " ------------------------------------------------------------------------------\n" \
            " File system mount is currently supported for: macOS, Windows and Linux.  There\n" \
            " are limitations that are important to know, please see below. Use at own risk!\n" \
            "  - Create file: not implemented.                                              \n" \
            "  - Write to files may be buggy and may in rare cases corrupt the target file. \n" \
            "  - Delete file will most often work, but with errors.                         \n" \
            "  - Delete directory, rename/move file and other features may not be supported.\n" \
            "  - Only the C:\\ drive is mounted on Windows target systems.                  \n" \
            " The target system files are found in the files directory.    The memory of the\n" \
            " target system is mapped into the files: liveram-kmd.raw and liveram-native.raw\n" \
            " Writing to the live memory may crash the target system.      Copying files and\n" \
            " dumping memory via the PCILeech virtual file system will work but  performance\n" \
            " will be better when using the built in commandline commands.                  \n" \
            " - Mount it only supported only when running PCILeech on Windows.              \n" \
            " - Mount of live RAM without kernel module is only supported on FPGA hardware. \n" \
            " EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
            " 1) Mount file system and live RAM of target as the default K: drive letter.   \n" \
            "    pcileech mount -kmd 0x7fffe000                                             \n" \
            " 2) Mount file system and live RAM of target as X: drive letter.               \n" \
            "    pcileech mount -kmd 0x7fffe000 -s X                                        \n" \
            " 3) Mount live ram and proc file system only using FPGA hardware.              \n" \
            "    pcileech mount -max 0x21e5fffff                                            \n" \
            " 4) Mount live ram and 'proc' file system by specifying a specific CR3/PML4.   \n" \
            "    prileech mount -cr3 0x1ab000                                               \n" \
        );
        break;
    case DISPLAY:
        printf(
            " DISPLAY MEMORY ON SCREEN.                                                     \n" \
            " MODES   : NATIVE, KMD                                                         \n" \
            " OPTIONS : -min, -max (optional)                                               \n" \
            " The memory contents between min and max is shown on screen.                   \n" \
            " Use the -min option to specify the memory location.                           \n" \
            " EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
            " 1) display memory starting at physical address 0x1000.                        \n" \
            "    pcileech display -min 0x1000                                               \n" \
            " 2) display memory between 0x1000 and 0x2fff.                                  \n" \
            "    pcileech display -min 0x1000 -max 0x2fff                                   \n" \
            " 3) display memory starting at physical address 0x140000000 (5GB).             \n" \
            "    pcileech display -min 0x140000000 -kmd 0x7fffe000                          \n");
        break;
    case PAGEDISPLAY:
        printf(
            " DISPLAY A MEMORY PAGE ON SCREEN.                                              \n" \
            " MODES   : NATIVE, KMD                                                            \n" \
            " OPTIONS : -min                                                                \n" \
            " The memory contents of a single page (4096 bytes) is shown on screen. Use the \n" \
            " -min option to specify the memory location. If the -min option is not aligned \n" \
            " the specified memory address will be truncated. It is also possible to force  \n" \
            " reading of otherwise inaccessible memory with the -force option.              \n" \
            " EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
            " 1) display the page starting at physical address 0x1000.                      \n" \
            "    pcileech pagedisplay -min 0x1000                                           \n" \
            " 2) display the normally restricted page at physical address 0xf0000.          \n" \
            "    pcileech pagedisplay -min 0xf0000 -force                                   \n" \
            " 3) display the page at address 0x140000000 (5GB).                             \n" \
            "    pcileech pagedisplay -min 0x140000000 -kmd 0x7fffe000                      \n");
        break;
    case TESTMEMREAD:
    case TESTMEMREADWRITE:
        printf(
            " TEST READING AND/OR READING+WRITING TO A PHYSICAL MEMORY ADDRESS.             \n" \
            " MODES   : NATIVE                                                                 \n" \
            " Used for debug purposes. Test reading and/or reading+writing to a physical    \n" \
            " memory address. The address page read and optionally written to is specified  \n" \
            " by the -min option. If the address is inside a protected range then the -force\n" \
            " option could be specified to override. A number of reads and writes are exec- \n" \
            " cuted. Unless there is a catastrophic failure the page is restored to its     \n" \
            " original state after testing writes with testmemreadwrite.                    \n" \
            " EXAMPLES:                                                                     \n" \
            " 1) test reading from the memory address at 0x1000                             \n" \
            "    pcileech testmemread -min 0x1000                                           \n" \
            " 1) test reading from the normally protected address 0xf4000000                \n" \
            "    pcileech testmemread -min 0xf4000000 -force                                \n" \
            " 2) test reading and writing to/from the memory address 0x1000                 \n" \
            "    pcileech testmemreadwrite -min 0x1000                                      \n");
        break;
    case KMDLOAD:
        printf(
            " LOAD A KERNEL MODULE INTO THE OPERATING SYSTEM KERNEL FOR LATER USE.          \n" \
            " MODES   : NATIVE                                                                 \n" \
            " OPTIONS : -kmd, -pt, -cr3                                                     \n" \
            " Load a kernel module into the running operating system kernel for later use.  \n" \
            " The kernel module is specified in the -kmd paramter. If the specified kernel  \n" \
            " module is generic and memory searches are supported it will be searched for   \n" \
            " in memory. Specialized windows 10 kernel module are loaded by hi-jacking the  \n" \
            " page table. The page table is searched for automatically with the -pt option. \n" \
            " The page table base may also optionally be specified in the -cr3 option.      \n" \
            " EXAMPLES:                                                                     \n" \
            " 1) load a kernel module into Windows Vista by specifying a generic signature. \n" \
            "    pcileech kmdload -kmd winvistax64                                          \n" \
            " 2) load a kernel module into Linux by specifying a generic signature.         \n" \
            "    pcileech kmdload -kmd LINUX_X64                                            \n" \
            " 3) load a kernel module into Windows 10 by targeting a specific driver.       \n" \
            "    pcileech kmdload -kmd win10x64_ntfs_20160716 -pt                           \n");
        break;
    case KMDEXIT:
        printf(
            " UNLOAD AN ACTIVE KERNEL MODULE FROM THE TARGET SYSTEM.                        \n" \
            " MODES   : KMD                                                                 \n" \
            " OPTIONS :                                                                     \n" \
            " Unload an active kernel module from the target system. The already active     \n" \
            " kernel module is asked to terminate and clean up itself as best as possible.  \n" \
            " After running the kmdexit command it will not be possible to access the       \n" \
            " kernel module any more.                                                       \n" \
            " EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
            " 1) unload the already loaded kernel module.                                   \n" \
            "    pcileech kmdexit -kmd 0x7fffe000                                           \n");
        break;
    case MAC_FVRECOVER:
        printf(
            " RECOVER FILEVAULT 2 PASSWORD FROM A LOCKED macOS SYSTEM.                      \n" \
            " MODES   : NATIVE                                                              \n" \
            " OPTIONS :                                                                     \n" \
            " Plug in the PCILeech device to any macOS system with a Thunderbolt 2 port. You\n" \
            " will be asked to reboot if PCILeech is ready. After the reboot PCILeech will  \n" \
            " try to figure out the filevault 2 full disk encryption password used to unlock\n" \
            " the disk crypto. This issue has been patched in macOS Sierra 10.12.2.         \n" \
            " A small memory dump will also be written to disk. In case PCILeech is uable to\n" \
            " automatically figure out the password this memory dump may be used. In order  \n" \
            " for PCILeech to figure out the password only ascii characters may be used; if \n" \
            " other unicode characters exist in the password PCILeech will not be able to   \n" \
            " automatically recover the password. (CVE-2016-7585).                          \n" \
            " EXAMPLES:                                                                     \n" \
            " 1) recover the filevault 2 disk encryption password.                          \n" \
            "    pcileech mac_fvrecover                                                     \n");
        break;
    case MAC_FVRECOVER2:
        printf(
            " RECOVER FILEVAULT 2 PASSWORD FROM A macOS SYSTEM IMMEDIATELY AFTER UNLOCK.    \n" \
            " MODES   : NATIVE                                                                 \n" \
            " OPTIONS :                                                                     \n" \
            " Plug in the PCILeech device to any macOS system with a Thunderbolt 2 port.    \n" \
            " Wait for the user to enter the filefault 2 password to unlock the computer.   \n" \
            " Immediately after unlock VT-d DMA protections are dropped for a short while   \n" \
            " and the password can be recovered in a similar way to the MAV_FVRECOVER       \n" \
            " command. (CVE-2016-7585).                                                     \n" \
            " EXAMPLES:                                                                     \n" \
            " 1) recover the filevault 2 disk encryption password immediately after unlock. \n" \
            "    pcileech mac_fvrecover2                                                    \n");
        break;
    case MAC_DISABLE_VTD:
        printf(
            " DISABLE Vt-d DMA PROTECTIONS IMMEDIATELY AFTER macOS BOOT.                    \n" \
            " MODES   : NATIVE                                                              \n" \
            " OPTIONS :                                                                     \n" \
            " Plug in the PCILeech device to any macOS system with a Thunderbolt 2 port.    \n" \
            " Wait for the user to enter the filefault 2 password to unlock the computer.   \n" \
            " Immediately after unlock VT-d DMA protections are dropped for a short while   \n" \
            " and it is possible to disable the in-memory DMAR ACPI table - which results   \n" \
            " in completely disabled VT-d protections until the computer is rebooted.       \n" \
            " (CVE-2016-7585).                                                              \n" \
            " EXAMPLES:                                                                     \n" \
            " 1) disable Vt-d DMA protections immediately after macOS boot.                 \n" \
            "    pcileech mac_disablevtd                                                    \n");
        break;
    case PT_PHYS2VIRT:
        printf(
            " SEARCH FOR VIRTUAL ADDRESS MAPPED TO GIVEN PHYSICAL ADDRESS.                  \n" \
            " MODES   : NATIVE, KMD                                                         \n" \
            " OPTIONS : -cr3, -0                                                            \n" \
            " Walk the page table of which base is specified on the 'cr3' option to find the\n" \
            " first occurrence of a virtual address mapped to the physical address specified\n" \
            " in the '0' option. If an entry is found the virtual address and the PTE will  \n" \
            " be displayed. Only the first occurrence will be displayed.                    \n" \
            " EXAMPLEs:                                                                     \n" \
            " 1) search for virtual address mapped to physical 0xfed90000 given a page table\n" \
            "    (PML4) base at: 0x1aa000.                                                  \n" \
            "    pcileech pt_phys2virt -cr3 0x1aa000 -0 0xfed90000                          \n");
        break;
    case PT_VIRT2PHYS:
        printf(
            " RETRIEVE PHYSICAL ADDRESS THAT VIRTUAL ADDRESS RESOLVES TO.                   \n" \
            " MODES   : NATIVE, KMD                                                         \n" \
            " OPTIONS : -cr3, -0                                                            \n" \
            " Retrieve the physical address that the virtual address resolves to.  The Phys-\n" \
            " ical address of the CR3 register is specified in '-cr3' parameter. The virtual\n" \
            " address is specified in the '-0' option.                                      \n" \
            " EXAMPLEs:                                                                     \n" \
            " 1) search for physical address mapped by virtual 0xfffff80000fed000.          \n" \
            "    (PML4) base at: 0x1aa000.                                                  \n" \
            "    pcileech pt_virt2phys -cr3 0x1aa000 -0 0xfffff80000fed000                  \n");
        break;
    case TLP:
        printf(
            " TRANSMIT AND RECEIVE RAW PCIe TLPs                                            \n" \
            " MODES   : NATIVE                                                              \n" \
            " OPTIONS : -in, -vv, -wait                                                     \n" \
            " Transmit and receive PCIe TLPs. Requires supported devices such as the SP605. \n" \
            " The USB3380 is not a supported device. Multiple TLPs may be stacked. If not   \n" \
            " specifying an -in parameter no TLP will be sent. Specify the -vv setting to   \n" \
            " display received and sent TLPs. The default listen time is 0.5s, if a longer  \n" \
            " listen time is required specify it with the -wait parameter.                  \n" \
            " Supported only when running PCILeech on Windows.                              \n" \
            " EXAMPLEs:                                                                     \n" \
            " 1) Listen for incoming TLPs for 10s:                                          \n" \
            "    pcileech -vv -wait 10                                                      \n");
        break;
    case PROBE:
        printf(
            " PROBE MEMORY FOR READABLE PAGES                                               \n" \
            " MODES   : NATIVE                                                              \n" \
            " Probe a memory region specified by defaults or -min, -max for readable pages. \n" \
            " This is done in a device-effifient manner. Probing is performed in NATIVE mode\n" \
            " The USB3380 is not a supported device.                                        \n" \
            " EXAMPLEs:                                                                     \n" \
            " 1) Probe memory up to 10GB                                                    \n" \
            "    pcileech probe -max 0x280000000                                            \n");
        break;
    case PSLIST:
        printf(
            " LIST PROCESSES OF THE TARGET SYSTEM                                           \n" \
            " MODES   : NATIVE                                                              \n" \
            " REQUIRE : Windows                                                             \n" \
            " OPTIONS :                                                                     \n" \
            " List the process names and pids of the targeted system.                       \n" \
            " EXAMPLEs:                                                                     \n" \
            " 1) List devices using 'fpga' or 'usb3380' hardware device.                    \n" \
            "    pcileech pslist                                                            \n" \
            " 2) List devices in dump file win10.raw                                        \n" \
            "    pcileech pslist -device win10.raw                                          \n");
        break;
    case PSVIRT2PHYS:
        printf(
            " TRANSLATE A VIRTUAL MEMORY ADDRESS INTO PHYSICAL MEMORY ADDRESS FOR GIVEN PID \n" \
            " MODES   : NATIVE                                                              \n" \
            " REQUIRE : Windows                                                             \n" \
            " OPTIONS : -0, -1                                                              \n" \
            " Translate a process virtual address into a physical address                   \n" \
            " EXAMPLEs:                                                                     \n" \
            " 1) Translate a virtual address of pid 638 into its physical address           \n" \
            "    pcileech psvirt2phys -0 638 -1 0x7ffc8b41a000                              \n");
        break;
    case EXEC_UMD:
        printf(
            " EXECUTE A USER MODE SHELLCODE (EXPERIMENTAL)                                  \n" \
            " MODES   : NATIVE                                                              \n" \
            " REQUIRE : Windows                                                             \n" \
            " OPTIONS : -0, -1 -hook -s                                                     \n" \
            " Hook a user mode application (currently supported method is hooking the import\n" \
            " address table - IAT). If the hook is successful the shellcode will be executed\n" \
            " (currently supported is creating a new process.                               \n" \
            " pcileech UMD_WINX64_IAT_PSEXEC -0 <pid> -1 <flags> -s <exe> -hook <hook-iat>  \n" \
            " EXAMPLEs:                                                                     \n" \
            " 1) Create a CMD from Utilman.exe by hooking RegCloseKey (632 is the pid):     \n" \
            "    pcileech UMD_WINX64_IAT_PSEXEC -hook ADVAPI32.dll!RegCloseKey              \n" \
            "             -0 632 -1 0x08000000 -s c:\\windows\\system32\\cmd.exe            \n" \
        );
        break;
    case AGENT_EXEC_PY:
        printf(
            " EXECUTE A PYTHON SCRIPT ON A REMOTE HOST RUNNING LeechAgent                   \n" \
            " MODES   : NATIVE                                                              \n" \
            " REQUIRE : Windows/Remote LeechSvc                                             \n" \
            " OPTIONS : -in, -out                                                           \n" \
            " Execute a Python script contained in the -in parameter on a remote host having\n" \
            " the LeechAgent installed.    The script will be executed in an embedded Python\n" \
            "  and the MemProcFS/LeechCore python APIs will be available and initialized.   \n" \
            " Outout will be displayed on screen unless -out parameter is specified.        \n" \
            " EXAMPLE:                                                                      \n" \
            " 1) Execute the script 'myscript.py' on the remote host test1.contoso.com using\n" \
            "    physical memory acquired from WinPmem:                                     \n" \
            "    pcileech.exe agent-execpy -in myscript.py -device pmem                     \n" \
            "                 -remote rpc://test1$@contoso.com:test1.contoso.com            \n" \
        );
        break;
    case EXEC_KMD:
        _HelpShowExecCommand();
        break;
    default:
        printf(
            " Detailed help for this command or implant is not available.                   \n");
        break;
    }
}
