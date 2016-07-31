// pcileech.c : implementation of core pcileech functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pcileech.h"
#include "cpuflash.h"
#include "device.h"
#include "memdump.h"
#include "mempatch.h"
#include "util.h"
#include "kmd.h"

VOID ShowUpdatePageRead(_In_ PCONFIG pCfg, _In_ QWORD qwCurrentAddress, _Inout_ PPAGE_STATISTICS pPageStat)
{
	QWORD qwPercentTotal = ((pPageStat->cPageSuccess + pPageStat->cPageFail) * 100) / pPageStat->cPageTotal;
	QWORD qwPercentSuccess = (pPageStat->cPageSuccess * 100) / pPageStat->cPageTotal;
	QWORD qwPercentFail = (pPageStat->cPageFail * 100) / pPageStat->cPageTotal;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	QWORD qwTickCountElapsed = GetTickCount64() - pPageStat->qwTickCountStart;
	QWORD qwSpeedMBs = ((pPageStat->cPageSuccess + pPageStat->cPageFail) * 4 / 1024) / (1 + (qwTickCountElapsed / 1000));
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	if(pCfg->fPageStat) {
		GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
		consoleInfo.dwCursorPosition.Y -= 7;
		SetConsoleCursorPosition(hConsole, consoleInfo.dwCursorPosition);
	}
	pCfg->fPageStat = TRUE; 
	printf(
		" Current Action: %s                             \n" \
		" Access Mode:    %s                             \n" \
		" Progress:       %i / %i (%i%%)                 \n" \
		" Speed:          %i MB/s                        \n" \
		" Address:        0x%016llX                      \n" \
		" Pages read:     %i / %i (%i%%)                 \n" \
		" Pages fail:     %i (%i%%)                      \n", 
		pPageStat->szCurrentAction,
		pPageStat->isAccessModeKMD ? "KMD (kernel module assisted DMA)" : "DMA (hardware only)             ",
		(pPageStat->cPageSuccess + pPageStat->cPageFail) / 256,
		pPageStat->cPageTotal / 256,
		qwPercentTotal,
		qwSpeedMBs,
		qwCurrentAddress,
		pPageStat->cPageSuccess,
		pPageStat->cPageTotal,
		qwPercentSuccess,
		pPageStat->cPageFail,
		qwPercentFail);
}

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

VOID ShowHelp()
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
		" General syntax: pcileech.exe <command> [-<optionname1> <optionvalue1>] ...    \n" \
		" Valid commands and valid MODEs [ and options ]:                               \n" \
		"   info                   DMA,KMD                                              \n" \
		"   dump                   DMA,KMD   [ min, max, out ]                          \n" \
		"   patch                  DMA,KMD   [ min, max, sig ]                          \n" \
		"   write                  DMA,KMD   [ min, in ]                                \n" \
		"   [command_module]           KMD   [ in, out, s, 0..9 ]                       \n" \
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
		"             LINUX_X64                                                         \n" \
		"             OSX_X64                                                           \n" \
		);
	ShowListFiles("*.kmd");
	printf(
		"   -sig : available patches - including operating system unlock patches:       \n");
	ShowListFiles("*.sig");
	printf(
		" Available command modules:                                                    \n");
	ShowListFiles("*.ksh");
	printf("\n");
}

VOID ShowInfo()
{
	printf(
		" PCILEECH INFORMATION                                                          \n" \
		" PCILeech (c) 2016 Ulf Frisk                                                   \n" \
		" Version: 1.0 - DEF CON EDITION                                                \n" \
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
		"   OS X defaults to VT-d. Windows 10 may, if configured, also use VT-d.        \n" \
		" - No drivers are needed on the target! Memory acquisition is all in hardware! \n" \
		" - Confirmed working with PCIe/mPCIe/ExpressCard/Thunderbolt.                  \n" \
		" - If kernel module is successfully inserted in lower 4GB RAM more RAM will be \n" \
		"   possible to read. Extended funtionality will also be made available.        \n" \
		" ----------------                                                              \n" );
	ShowHelp();
}

HRESULT ParseCmdLine(_In_ DWORD argc, _In_ char* argv[], _Out_ PCONFIG pCfg)
{
	struct ACTION {
		ACTION_TYPE tp;
		LPSTR sz;
	} ACTION;
	const struct ACTION ACTIONS[] = {
		{.tp = INFO,.sz = "info"},
		{.tp = DUMP,.sz = "dump" },
		{.tp = WRITE,.sz = "write" },
		{.tp = PATCH,.sz = "patch" },
		{.tp = KMDLOAD,.sz = "kmdload" },
		{.tp = KMDEXIT,.sz = "kmdexit" },
		{.tp = FLASH,.sz = "flash" },
		{.tp = START8051,.sz = "8051start" },
		{.tp = STOP8051,.sz = "8051stop" },
		{.tp = PAGEDISPLAY,.sz = "pagedisplay" },
		{.tp = TESTMEMREAD,.sz = "testmemread" },
		{.tp = TESTMEMREADWRITE,.sz = "testmemreadwrite" },
	};
	QWORD qw;
	DWORD j, i = 1;
	if(argc < 2) {
		return E_FAIL;
	}
	// set defaults
	pCfg->tpAction = NA;
	pCfg->qwAddrMax = 0x0ffffffffffffffff;
	// fetch command line actions/options
	loop:
	while(i < argc) {
		for(j = 0; j < sizeof(ACTIONS) / sizeof(ACTION); j++) { // parse command (if found)
			if(0 == strcmp(argv[i], ACTIONS[j].sz)) {
				pCfg->tpAction = ACTIONS[j].tp;
				i++;
				goto loop;
			}
		}
		if(pCfg->tpAction == NA && 0 != memcmp(argv[i], "-", 1)) {
			pCfg->tpAction = EXEC;
			strcpy_s(pCfg->szShellcodeName, MAX_PATH, argv[i]);
			i++;
			continue;
		}
		// parse options (command not found)
		if(0 == strcmp(argv[i], "-pt")) {
			pCfg->fPageTableScan = TRUE;
			i++;
			continue;
		} else if(i + 1 >= argc) {
			return E_FAIL;
		} else if(0 == strcmp(argv[i], "-min")) {
			pCfg->qwAddrMin = Util_GetNumeric(argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-max")) {
			pCfg->qwAddrMax = Util_GetNumeric(argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-cr3")) {
			pCfg->qwCR3 = Util_GetNumeric(argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-out")) {
			strcpy_s(pCfg->szFileOut, MAX_PATH, argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-in")) {
			if(!Util_ParseHexFileBuiltin(argv[i + 1], pCfg->pbIn, CONFIG_MAX_INSIZE, (PDWORD)&pCfg->cbIn)) { return E_FAIL; }
		} else if(0 == strcmp(argv[i], "-s")) {
			strcpy_s(pCfg->szInS, MAX_PATH, argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-sig")) {
			strcpy_s(pCfg->szSignatureName, MAX_PATH, argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-kmd")) {
			pCfg->qwKMD = strtoull(argv[i + 1], NULL, 16);
			if(pCfg->qwKMD == 0) {
				strcpy_s(pCfg->szKMDName, MAX_PATH, argv[i + 1]);
			}
		} else if(2 == strlen(argv[i]) && '0' <= argv[i][1] && '9' >= argv[i][1]) { // -0..9 param
			pCfg->qwDataIn[argv[i][1] - '0'] = Util_GetNumeric(argv[i + 1]);
		} 
		i += 2;
	}
	// try correct erroneous options, if needed
	if(pCfg->tpAction == NA) {
		return E_FAIL;
	}
	if(!pCfg->szKMDName[0] && !pCfg->qwKMD) { // no KMD => 32-bit addressing => 4GiB
		if(pCfg->qwAddrMax == 0 || pCfg->qwAddrMax > 0xffffffff) {
			pCfg->qwAddrMax = 0xffffffff;
		}
	}
	if(pCfg->qwAddrMin > pCfg->qwAddrMax) {
		qw = pCfg->qwAddrMin;
		pCfg->qwAddrMin = pCfg->qwAddrMax;
		pCfg->qwAddrMax = qw;
	}
	pCfg->qwCR3 &= 0xfffff000;
	pCfg->qwKMD &= 0xfffff000;
	return S_OK;
}

int main(_In_ int argc, _In_ char* argv[])
{
	HRESULT hr;
	BOOL result;
	PCONFIG pCfg;
	DEVICE_DATA device;
	PKMDEXEC pKmdExec = NULL;
	printf("\n");
	if(!(pCfg = LocalAlloc(LMEM_ZEROINIT, sizeof(CONFIG)))) {
		printf("PCILEECH: Out of memory.\n");
		return 1;
	}
	hr = ParseCmdLine((DWORD)argc, argv, pCfg);
	if(FAILED(hr)) {
		ShowHelp();
		return 1;
	}
	if(pCfg->tpAction == EXEC && !Util_LoadKmdExecShellcode(pCfg->szShellcodeName, &pKmdExec)) {
		LocalFree(pKmdExec);
		ShowHelp();
		return 1;
	}
	if(pCfg->tpAction == INFO) {
		ShowInfo();
		return 0;
	}
	result = DeviceOpen(&device);
	if(!result) {
		printf("PCILEECH: Failed to connect to USB device.\n");
		return 1;
	}
	if(pCfg->szKMDName[0] || pCfg->qwKMD) {
		result = KMDOpen(pCfg, &device);
		if(!result) {
			printf("PCILEECH: Failed to load kernel module.\n");
			return 1;
		}
	}
	if(pCfg->tpAction == DUMP) {
		ActionMemoryDump(pCfg, &device);
	} else if(pCfg->tpAction == WRITE) {
		ActionMemoryWrite(pCfg, &device);
	} else if(pCfg->tpAction == PAGEDISPLAY) {
		ActionMemoryPageDisplay(pCfg, &device);
	} else if(pCfg->tpAction == PATCH) {
		ActionPatch(pCfg, &device);
	} else if(pCfg->tpAction == FLASH) {
		ActionFlash(pCfg, &device);
	} else if(pCfg->tpAction == START8051) {
		Action8051Start(pCfg, &device);
	} else if(pCfg->tpAction == STOP8051) {
		Action8051Stop(pCfg, &device);
	} else if(pCfg->tpAction == EXEC) {
		ActionExecShellcode(pCfg, &device);
	} else if(pCfg->tpAction == TESTMEMREAD || pCfg->tpAction == TESTMEMREADWRITE) {
		ActionMemoryTestReadWrite(pCfg, &device);
	} else if(pCfg->tpAction == KMDLOAD) {
		if(pCfg->qwKMD) {
			printf("KMD: Successfully loaded at address: 0x%08x\n", (DWORD)pCfg->qwKMD);
		} else {
			printf("KMD: Failed. Please supply valid -kmd and optionally -cr3 parameters.\n");
		}
	} else if(pCfg->tpAction == KMDEXIT) {
		if(device.KMDHandle) {
			KMDClose(&device);
			printf("KMD: Hopefully unloaded.\n");
		}
		else {
			printf("KMD: Failed. Cannot unload KMD - not found!.\n");
		}
	} else {
		printf("Failed. Not yet implemented.\n");
	}
	if(!pCfg->qwKMD) {
		KMDClose(&device);
	}
	DeviceClose(&device);
	LocalFree(pCfg);
	return 0;
}



