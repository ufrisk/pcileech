// help.c : implementation related to displaying help texts.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "help.h"
#include "util.h"

VOID ShowListFiles(_In_ LPSTR szSearchPattern)
{
	WIN32_FIND_DATAA data;
	HANDLE h;
	CHAR szSearch[MAX_PATH];
	Util_GetFileInDirectory(szSearch, szSearchPattern);
	h = FindFirstFileA(szSearch, &data);
	while(h != INVALID_HANDLE_VALUE) {
		data.cFileName[strlen(data.cFileName) - 4] = 0;
		printf("             %s\n", data.cFileName);
		if(!FindNextFileA(h, &data)) {
			return;
		}
	}
}

VOID Help_ShowGeneral()
{
	printf(
		" PCILEECH COMMAND LINE REFERENCE                                               \n" \
		" PCILeech can run in two modes - DMA (default) and Kernel Module Assisted (KMD)\n" \
		" KMD mode may be triggered by supplying the option kmd and optionally cr3 / pt.\n" \
		" If an address is supplied in the kmd option pcileech will use the already ins-\n" \
		" erted KMD. The already inserted KMD will be left intact upon exit.  If the KMD\n" \
		" contains a kernel mode signature the kernel module will be loaded and then un-\n" \
		" loaded on program exit ( except for the kmdload command ).                    \n" \
		" KMD mode may access all memory. DMA mode may only access memory below 4GB.    \n" \
		" For more detailed help about a specific command type: pcileech <command> -help\n" \
		" General syntax: pcileech.exe <command> [-<optionname1> <optionvalue1>] ...    \n" \
		" Valid commands and valid MODEs [ and options ]:                               \n" \
		"   info                   DMA,KMD                                              \n" \
		"   dump                   DMA,KMD   [ min, max, out ]                          \n" \
		"   patch                  DMA,KMD   [ min, max, sig, all ]                     \n" \
		"   write                  DMA,KMD   [ min, in ]                                \n" \
		"   search                 DMA,KMD   [ min, max, sig, in, all ]                 \n" \
		"   [implant]                  KMD   [ in, out, s, 0..9 ]                       \n" \
		"   kmdload                DMA       [ pt, cr3 ]                                \n" \
		"   kmdexit                    KMD                                              \n" \
		"   8051start              DMA,KMD   [ in ]                                     \n" \
		"   8051stop               DMA,KMD                                              \n" \
		"   flash                  DMA,KMD   [ in ]                                     \n" \
		"   pagedisplay            DMA,KMD   [ min ]                                    \n" \
		"   testmemread            DMA       [ min ]                                    \n" \
		"   testmemreadwrite       DMA       [ min ]                                    \n" \
		" Valid options:                                                                \n" \
		"   -min : memory min address, valid range: 0x0..0xffffffffffffffff             \n" \
		"          default: 0x0                                                         \n" \
		"          For memory accesses over 0xffffffff KMD must be loaded.              \n" \
		"          note that the address must be given in hexadecimal format.           \n" \
		"   -max : memory max address, valid range: 0x0..0xffffffffffffffff             \n" \
		"          default: 0xffffffff (4GB) in standard mode                           \n" \
		"          default: actual memory size in KMD mode                              \n" \
		"          For memory accesses over 0xffffffff KMD must be loaded.              \n" \
		"          note that the address must be given in hexadecimal format.           \n" \
		"   -out : name of output file.                                                 \n" \
		"          default: pcileech-<minaddr>-<maxaddr>-<date>-<time>.raw              \n" \
		"   -all : search all memory for signature - do not stop at first occurrence.   \n" \
		"          Option has no value. Example: -all                                   \n" \
		"   -force: force reads and writes even though target memory is marked as not   \n" \
		"          accessible. Dangerous! Affects all modes and commands.               \n" \
		"          Option has no value. Example: -force                                 \n" \
		"   -help: show help about the selected command or implant and then exit        \n" \
		"          without running the command. Affects all modes and commands.         \n" \
		"          Option has no value. Example: -help                                  \n" \
		"   -in  : file name or hexstring to load as input.                             \n" \
		"          Examples: -in 0102030405060708090a0b0c0d0e0f or -in firmware.bin     \n" \
		"   -s   : string input value.                                                  \n" \
		"          Example: -s \"\\\\??\\C:\\Windows\\System32\\cmd.exe\"               \n" \
		"   -0..9: QWORD input value. Example: -0 0xff , -3 0x7fffffff00001000 or -2 13 \n" \
		"          default: 0                                                           \n" \
		"   -pt  : trigger KMD insertion by automatic page table hijack.                \n" \
		"          Option has no value. Example: -pt                                    \n" \
		"          Only used in conjunction with -kmd option to trigger KMD insertion   \n" \
		"          by page table hijack. Only recommended to use with care on computers \n" \
		"          with 4GB+ RAM when kernel is located in high-memory (Windows 10).    \n" \
		"          Insertion may trigger system crash unless signature exactly matches. \n" \
		"   -cr3 : base address of system page table / CR3 CPU register.                \n" \
		"          Valid range: 0x00..0xfffff000                                        \n" \
		"          Insertion may trigger system crash unless signature exactly matches. \n" \
		"   -kmd : address of already loaded kernel module helper (KMD).                \n" \
		"          ALTERNATIVELY                                                        \n" \
		"          kernel module to use, see list below for choices:                    \n" \
		"             WIN10_X64   (WARNING! Unstable/Experimental)                      \n" \
		"             LINUX_X64                                                         \n" \
		"             FREEBSD_X64                                                       \n" \
		"             MACOS                                                             \n" \
	);
	ShowListFiles("*.kmd");
	printf(
		"   -sig : available patches - including operating system unlock patches:       \n");
	ShowListFiles("*.sig");
	printf(
		" Available implants:                                                           \n");
	ShowListFiles("*.ksh");
	printf("\n");
}

VOID Help_ShowInfo()
{
	printf(
		" PCILEECH INFORMATION                                                          \n" \
		" PCILeech (c) 2016 Ulf Frisk                                                   \n" \
		" Version: 1.2                                                                  \n" \
		" License: GNU GENERAL PUBLIC LICENSE - Version 3, 29 June 2007                 \n" \
		" Contact information: pcileech@frizk.net                                       \n" \
		" System requirements: 64-bit Windows 7, 10 or later.                           \n" \
		" Other project references:                                                     \n" \
		"   PCILeech          - https://github.com/ufrisk/pcileech                      \n" \
		"   Slotscreamer      - https://github.com/NSAPlayset/SLOTSCREAMER              \n" \
		"   Inception         - https://github.com/carmaa/inception                     \n" \
		"   Google USB driver - http://developer.android.com/sdk/win-usb.html#download  \n" \
		" ----------------                                                              \n" \
		" Use with USB3380 hardware programmed as a pcileech device only.               \n" \
		" Use with USB2 or USB3. USB3 is strongly recommended performance wise.         \n\n" \
		" ----------------                                                              \n" \
		" Driver information:                                                           \n" \
		" The pcileech requires a dummy driver to function properly. The pcileech       \n" \
		" device masks as a Google Glass. Please download and install the Google USB    \n" \
		" driver before proceeding.                                                     \n" \
		" ----------------                                                              \n" \
		" Usage: connect USB3380 device to target computer and USB cable to the computer\n" \
		" executing pcileech.exe.  If all memory reads fail try to re-insert the device.\n" \
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

VOID _HelpShowExecCommand(_In_ PCONFIG pCfg)
{
	BOOL result;
	PKMDEXEC pKmdExec = NULL;
	result = Util_LoadKmdExecShellcode(pCfg->szShellcodeName, &pKmdExec);
	if(!result) {
		printf("HELP: Failed loading shellcode from file: '%s.ksh' ...\n", pCfg->szShellcodeName);
		return;
	}
	printf(
		" SHELLCODE IMPLANT HELP: Execute a custom implant in the target kernel.        \n" \
		" MODES   : KMD                                                                 \n" \
		" OPTIONS : -in, -out, -s, -0, -1, -2, -3, -4, -5, -6, -7, -8, -9               \n");
	printf(" Implant loaded from file: %s.ksh\n", pCfg->szShellcodeName);
	printf(
		" Implant specific help (output values are left empty/set to zero):             \n" \
		" ============================================================================= \n");
	printf(pKmdExec->szOutFormatPrintf,	"", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	LocalFree(pKmdExec);
}

VOID Help_ShowDetailed(_In_ PCONFIG pCfg)
{

	switch(pCfg->tpAction) {
	case DUMP:
		printf(
			" DUMP MEMORY FROM TARGET SYSTEM TO FILE.                                       \n" \
			" MODES   : DMA, KMD                                                            \n" \
			" OPTIONS : -min, -max, -out, -force                                            \n" \
			" The physical memory is dumped to file. If no file is specified in the -out    \n" \
			" option then a default named file is created. When dumping in DMA mode PCILeech\n" \
			" tries to dump memory between 0-4GB unless a separate range is specified by the\n" \
			" -min and -max parameters. When dumping in KMD mode readable physical memory   \n" \
			" accessible to the kernel is dumped unless a separate range is specified in the\n" \
			" -min and -max options. Memory related to PCIe and devices is not dumped (these\n" \
			" memory ranges are written as zeroes) unless the -force option is specified.   \n" \
			" Please note that using the -force option may result in a system crash.        \n" \
			" The DUMP command dumps 4kB memory pages. Partial pages are not supported.     \n" \
			" EXAMPLES:      (example kernel module is loaded at address 0x7fffe000)        \n" \
			" 1) dump memory up to 4GB by using native DMA:                                 \n" \
			"    pcileech dump                                                              \n" \
			" 2) dump memory as seen by the kernel:                                         \n" \
			"    pcileech dump -kmd 0x7fffe000                                              \n" \
			" 3) dump memory between 5GB and 6GB:                                           \n" \
			"    pcileech dump -kmd 0x7fffe000 -min 0x140000000 -max 0x180000000            \n" \
			" 4) dump memory to file c:\\temp\\out.raw:                                     \n" \
			"    pcileech dump -kmd 0x7fffe000 -out \"c:\\temp\\out.raw\"                   \n");
		break;
	case WRITE:
		printf(
			" WRITE DATA TO TARGET SYSTEM MEMORY.                                           \n" \
			" MODES   : DMA, KMD                                                            \n" \
			" OPTIONS : -min, -in, -force                                                   \n" \
			" WRITE will write contents specified in the -in option to the memory address   \n" \
			" specified by the -min option. The memory address may be unaligned. It is also \n" \
			" possible to try to write to non-accessible memory - such as PCIe memory mapped\n" \
			" devices with the -force option. Please note that using the -force option may  \n" \
			" result in a system crash. In KMD mode the write is performed by the target    \n" \
			" operating system. In DMA mode the write is performed by the PCILeech device.  \n" \
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
			" MODES   : DMA, KMD                                                            \n" \
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
			" MODES   : DMA, KMD                                                            \n" \
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
	case PAGEDISPLAY:
		printf(
			" DISPLAY A MEMORY PAGE ON SCREEN.                                              \n" \
			" MODES   : DMA, KMD                                                            \n" \
			" OPTIONS : -min, -force                                                        \n" \
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
			" MODES   : DMA                                                                 \n" \
			" Used for debug purposes. Test reading and/or reading+writing to a physical    \n" \
			" memory address with DMA. The address page read and optionally written to is   \n" \
			" specified by the -min option. If the address is inside a protected range then \n" \
			" the -force option could be specified to override. A number of reads and writes\n" \
			" are executed. Unless there is a catastrophic failure the page is restored to  \n" \
			" its original state after testing writes with testmemreadwrite.                \n" \
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
			" MODES   : DMA                                                                 \n" \
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
	case EXEC:
		_HelpShowExecCommand(pCfg);
		break;
	default:
		printf(
			" Detailed help for this command or implant is not available.                   \n");
		break;
	}
}