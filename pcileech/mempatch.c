// mempatch.c : implementation related to operating systems unlock/patch functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "mempatch.h"
#include "device.h"
#include "util.h"

BOOL Patch_CmpChunk(_In_ PBYTE pbPage, _In_ PSIGNATURE_CHUNK pChunk, _In_opt_ DWORD dwRelBase, _Out_opt_ PDWORD pdwOffset)
{
	DWORD o;
	if(pChunk->tpOffset == SIGNATURE_CHUNK_TP_OFFSET_FIXED) {
		if(pChunk->cbOffset + pChunk->cb > 0x1000) { return FALSE; }
		if(0 == memcmp(pbPage + pChunk->cbOffset, pChunk->pb, pChunk->cb)) {
			if(pdwOffset) { *pdwOffset = pChunk->cbOffset; }
			return TRUE;
		}
	}
	if(pChunk->tpOffset == SIGNATURE_CHUNK_TP_OFFSET_RELATIVE) {
		if(pChunk->cbOffset + dwRelBase + pChunk->cb > 0x1000) { return FALSE; }
		if(0 == memcmp(pbPage + dwRelBase + pChunk->cbOffset, pChunk->pb, pChunk->cb)) {
			if(pdwOffset) { *pdwOffset = dwRelBase + pChunk->cbOffset; }
			return TRUE;
		}
	}
	if(pChunk->tpOffset == SIGNATURE_CHUNK_TP_OFFSET_ANY) {
		for(o = 0; o <= 0x1000 - pChunk->cb; o++) {
			// comparison - extra "unnecessary" dword comparison for speedup reasons.
			if(((pChunk->cb < sizeof(DWORD)) || (*(PDWORD)pChunk->pb == *(PDWORD)(pbPage + o))) &&
				(0 == memcmp(pbPage + o, pChunk->pb, pChunk->cb))) {
				if(pdwOffset) { *pdwOffset = o; }
				return TRUE;
			}
		}
	}
	return FALSE;
}

BOOL Patch_FindAndPatch(_Inout_ PBYTE pbPage, _In_ PSIGNATURE pSignatures, _In_ DWORD cSignatures, _Out_ PDWORD pdwPatchOffset, _Out_ PDWORD pcbPatch)
{
	DWORD i, o, dwRelBase;
	PSIGNATURE ps;
	for(i = 0; i < cSignatures; i++) {
		ps = pSignatures + i;
		if(!ps->chunk[0].cb || !Patch_CmpChunk(pbPage, &ps->chunk[0], 0, &dwRelBase)) {
			continue;
		}
		if(ps->chunk[1].cb && !Patch_CmpChunk(pbPage, &ps->chunk[1], dwRelBase, NULL)) {
			continue;
		}
		o = ps->chunk[2].cbOffset;
		if(ps->chunk[2].tpOffset == SIGNATURE_CHUNK_TP_OFFSET_RELATIVE) { 
			o += dwRelBase;
		}
		if(o + ps->chunk[2].cb < 0x1000) {
			memcpy(pbPage + o, ps->chunk[2].pb, ps->chunk[2].cb);
			*pdwPatchOffset = o;
			*pcbPatch = ps->chunk[2].cb;
			return TRUE;
		}
	}
	return FALSE;
}

#define MAX_NUM_PATCH_LOCATIONS		0x100

VOID ActionPatchAndSearch(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	SIGNATURE oSignatures[CONFIG_MAX_SIGNATURES];
	DWORD dwoPatch, cbPatch, cSignatures = CONFIG_MAX_SIGNATURES;
	QWORD qwAddrBase;
	PBYTE pbBuffer16M = LocalAlloc(0, 0x01000000);
	PAGE_STATISTICS pageStat;
	BOOL result, isModePatch = pCfg->tpAction == PATCH;
	LPSTR szAction = isModePatch ? "Patch" : "Search";
	QWORD i, qwoPages, qwPatchList[MAX_NUM_PATCH_LOCATIONS], cPatchList = 0;
	// initialize / allocate memory
	qwAddrBase = pCfg->qwAddrMin;
	if(!pbBuffer16M) { return; }
	memset(&pageStat, 0, sizeof(PAGE_STATISTICS));
	pageStat.cPageTotal = (pCfg->qwAddrMax - qwAddrBase + 1) / 4096;
	if(!pageStat.cPageTotal) {
		printf("%s: Failed. Zero or negative memory range specified.\n", szAction);
		goto cleanup;
	}
	pageStat.isAccessModeKMD = pDeviceData->KMDHandle ? TRUE : FALSE;
	pageStat.szCurrentAction = isModePatch ? "Patching" : "Searching";
	pageStat.qwTickCountStart = GetTickCount64();
	// load and verify signatures
	if(pCfg->cbIn) {
		Util_CreateSignatureSearchAll(pCfg->pbIn, (DWORD)pCfg->cbIn, oSignatures);
		cSignatures = 1;
	} else {
		result = Util_LoadSignatures(pCfg->szSignatureName, ".sig", oSignatures, &cSignatures, 3);
		if(!result || !cSignatures) {
			printf("%s: Failed. Failed to load signature.\n", szAction);
			goto cleanup;
		}
	}
	if(isModePatch) {
		for(i = 0; i < cSignatures; i++) {
			if(oSignatures[i].chunk[2].cb == 0 || oSignatures[i].chunk[2].cb > 4096 || oSignatures[i].chunk[2].tpOffset == SIGNATURE_CHUNK_TP_OFFSET_ANY) {
				printf("%s: Failed. Invalid patch signature.\n", szAction);
			}
		}
	}
	// loop patch / unlock
	for(; qwAddrBase < pCfg->qwAddrMax; qwAddrBase += 0x01000000) {
		result = Util_Read16M(pCfg, pDeviceData, pbBuffer16M, qwAddrBase, &pageStat);
		ShowUpdatePageRead(pCfg, qwAddrBase, &pageStat);
		if(!result) {
			printf("%s: Failed. Cannot dump any sequential data in 16MB - terminating.\n", szAction);
			goto cleanup;
		}
		for(qwoPages = 0; (qwoPages < 0x01000000) && (qwAddrBase + qwoPages < pCfg->qwAddrMax); qwoPages += 0x1000) {
			result = Patch_FindAndPatch(pbBuffer16M + qwoPages, oSignatures, cSignatures, &dwoPatch, &cbPatch);
			if(!result) {
				continue;
			}
			if(isModePatch) {
				result = DeviceWriteMEM(pDeviceData, qwAddrBase + qwoPages + dwoPatch, pbBuffer16M + qwoPages + dwoPatch, cbPatch, 0);
			}
			if(result) {
				if(cPatchList == MAX_NUM_PATCH_LOCATIONS) {
					printf("%s: Failed. More than %i signatures found. Location: 0x%llx\n", szAction, MAX_NUM_PATCH_LOCATIONS, qwAddrBase + qwoPages + dwoPatch);
					goto cleanup;
				}
				qwPatchList[cPatchList] = qwAddrBase + qwoPages + dwoPatch;
				cPatchList++;
			} else {
				printf("%s: Failed. Write memory failed. Location: 0x%llx\n", szAction, qwAddrBase + qwoPages + dwoPatch);
				goto cleanup;
			}
			if(!pCfg->fPatchAll) {
				goto cleanup;
			}
		}
	}
	if(0 == cPatchList) {
		printf("%s: Failed. No signature found.\n", szAction);
	}
cleanup:
	if(cPatchList) {
		for(i = 0; i < cPatchList; i++) {
			printf("%s: Successful. Location: 0x%llx\n", szAction, qwPatchList[i]);
		}
	}
	LocalFree(pbBuffer16M);
}
