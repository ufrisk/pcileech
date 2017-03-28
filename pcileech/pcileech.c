// pcileech.c : implementation of core pcileech functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "pcileech.h"
#include "cpuflash.h"
#include "device.h"
#include "executor.h"
#include "extra.h"
#include "help.h"
#include "memdump.h"
#include "mempatch.h"
#include "util.h"
#include "kmd.h"
#include "vfs.h"

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
		{.tp = SEARCH,.sz = "search" },
		{.tp = KMDLOAD,.sz = "kmdload" },
		{.tp = KMDEXIT,.sz = "kmdexit" },
		{.tp = FLASH,.sz = "flash" },
		{.tp = MOUNT,.sz = "mount" },
		{.tp = START8051,.sz = "8051start" },
		{.tp = STOP8051,.sz = "8051stop" },
		{.tp = PAGEDISPLAY,.sz = "pagedisplay" },
		{.tp = TESTMEMREAD,.sz = "testmemread" },
		{.tp = TESTMEMREADWRITE,.sz = "testmemreadwrite" },
		{.tp = MAC_FVRECOVER,.sz = "mac_fvrecover" },
		{.tp = PT_PHYS2VIRT,.sz = "pt_phys2virt" },
	};
	QWORD qw;
	DWORD j, i = 1;
	if(argc < 2) {
		return E_FAIL;
	}
	// set defaults
	pCfg->tpAction = NA;
	pCfg->qwAddrMax = 0x0ffffffffffffffff;
	pCfg->fOutFile = TRUE;
	pCfg->qwMaxSizeDmaIo = 0x00800000;
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
		} else if(0 == strcmp(argv[i], "-all")) {
			pCfg->fPatchAll = TRUE;
			i++;
			continue;
		} else if(0 == strcmp(argv[i], "-force")) {
			pCfg->fForceRW = TRUE;
			i++;
			continue;
		} else if(0 == strcmp(argv[i], "-help")) {
			pCfg->fShowHelp = TRUE;
			i++;
			continue;
		} else if(0 == _stricmp(argv[i], "-usb2")) {
			pCfg->fForceUsb2 = TRUE;
			i++;
			continue;
		} else if(0 == _stricmp(argv[i], "-v")) {
			pCfg->fVerbose = TRUE;
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
		} else if(0 == strcmp(argv[i], "-iosize")) {
			pCfg->qwMaxSizeDmaIo = Util_GetNumeric(argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-out")) {
			if((0 == _stricmp(argv[i + 1], "none")) || (0 == _stricmp(argv[i + 1], "null"))) {
				pCfg->fOutFile = FALSE;
			} else {
				strcpy_s(pCfg->szFileOut, MAX_PATH, argv[i + 1]);
			}
		} else if(0 == strcmp(argv[i], "-in")) {
			if(!Util_ParseHexFileBuiltin(argv[i + 1], pCfg->pbIn, CONFIG_MAX_INSIZE, (PDWORD)&pCfg->cbIn)) { return E_FAIL; }
		} else if(0 == strcmp(argv[i], "-s")) {
			strcpy_s(pCfg->szInS, MAX_PATH, argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-sig")) {
			strcpy_s(pCfg->szSignatureName, MAX_PATH, argv[i + 1]);
		} else if(0 == strcmp(argv[i], "-kmd")) {
			pCfg->qwKMD = strtoull(argv[i + 1], NULL, 16);
			if(pCfg->qwKMD < 0x1000) {
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
	pCfg->qwCR3 &= ~0xfff;
	pCfg->qwKMD &= ~0xfff;
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
		Help_ShowGeneral();
		return 1;
	}
	if(pCfg->tpAction == EXEC && !Util_LoadKmdExecShellcode(pCfg->szShellcodeName, &pKmdExec)) {
		LocalFree(pKmdExec);
		Help_ShowGeneral();
		return 1;
	}
	if(pCfg->tpAction == INFO) {
		Help_ShowInfo();
		return 0;
	}
	if(pCfg->fShowHelp) {
		Help_ShowDetailed(pCfg);
		return 0;
	}
	result = DeviceOpen(pCfg, &device);
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
		ActionPatchAndSearch(pCfg, &device);
	} else if(pCfg->tpAction == SEARCH) {
		ActionPatchAndSearch(pCfg, &device);
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
	} else if(pCfg->tpAction == MAC_FVRECOVER) {
		Action_MacFilevaultRecover(pCfg, &device);
	} else if(pCfg->tpAction == PT_PHYS2VIRT) {
		Action_PT_Phys2Virt(pCfg, &device);
	} else if(pCfg->tpAction == MOUNT) {
		//ActionMount(pCfg, &device);
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



