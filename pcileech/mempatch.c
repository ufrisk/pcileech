// mempatch.c : implementation related to operating systems unlock/patch functionality.
//
// (c) Ulf Frisk, 2016-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "mempatch.h"
#include "device.h"
#include "util.h"
#include "vmmx.h"
#include <vmmdll.h>

_Success_(return)
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

_Success_(return)
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

#define MAX_NUM_PATCH_LOCATIONS        0x100

VOID ActionPatchAndSearchPhysical()
{
    PSIGNATURE pSignatures;
    DWORD dwoPatch, cbPatch, cSignatures = CONFIG_MAX_SIGNATURES;
    QWORD qwAddrBase;
    PBYTE pbBuffer16M = NULL;
    PPAGE_STATISTICS pPageStat = NULL;
    BOOL result, isModePatch = ctxMain->cfg.tpAction == PATCH;
    LPSTR szAction = isModePatch ? "Patch" : "Search";
    QWORD i, qwoPages, qwPatchList[MAX_NUM_PATCH_LOCATIONS], cPatchList = 0;
    // initialize / allocate memory
    if(!(pSignatures = LocalAlloc(LMEM_ZEROINIT, cSignatures * sizeof(SIGNATURE)))) { goto cleanup; }
    if(!(pbBuffer16M = LocalAlloc(0, 0x01000000))) { goto cleanup; }
    qwAddrBase = ctxMain->cfg.paAddrMin;
    if(ctxMain->cfg.paAddrMax < qwAddrBase + 0xfff) {
        printf("%s: Failed. Zero or negative memory range specified.\n", szAction);
        goto cleanup;
    }
    // load and verify signatures
    if(ctxMain->cfg.cbIn) {
        Util_CreateSignatureSearchAll(ctxMain->cfg.pbIn, (DWORD)ctxMain->cfg.cbIn, pSignatures);
        cSignatures = 1;
    } else {
        result = Util_LoadSignatures(ctxMain->cfg.szSignatureName, ".sig", pSignatures, &cSignatures, 3);
        if(!result || !cSignatures) {
            printf("%s: Failed. Failed to load signature.\n", szAction);
            goto cleanup;
        }
    }
    if(isModePatch) {
        for(i = 0; i < cSignatures; i++) {
            if(pSignatures[i].chunk[2].cb == 0 || pSignatures[i].chunk[2].cb > 4096 || pSignatures[i].chunk[2].tpOffset == SIGNATURE_CHUNK_TP_OFFSET_ANY) {
                printf("%s: Failed. Invalid patch signature.\n", szAction);
            }
        }
    }
    // loop patch / unlock
    PageStatInitialize(&pPageStat, qwAddrBase, ctxMain->cfg.paAddrMax, isModePatch ? "Patching" : "Searching", ctxMain->phKMD ? TRUE : FALSE, ctxMain->cfg.fVerbose);
    for(; qwAddrBase < ctxMain->cfg.paAddrMax; qwAddrBase += 0x01000000) {
        result = Util_Read16M(pbBuffer16M, qwAddrBase, pPageStat);
        if(!result && !ctxMain->cfg.fForceRW && !ctxMain->phKMD && PCILEECH_DEVICE_EQUALS("usb3380")) {
            // terminate if 16MB cannot be read from the USB3380 device.
            PageStatClose(&pPageStat);
            printf("%s: Failed. Cannot dump any sequential data in 16MB - terminating.\n", szAction);
            goto cleanup;
        }
        for(qwoPages = 0; (qwoPages < 0x01000000) && (qwAddrBase + qwoPages < ctxMain->cfg.paAddrMax); qwoPages += 0x1000) {
            result = Patch_FindAndPatch(pbBuffer16M + qwoPages, pSignatures, cSignatures, &dwoPatch, &cbPatch);
            if(!result) {
                continue;
            }
            if(isModePatch) {
                result = DeviceWriteMEM(qwAddrBase + qwoPages + dwoPatch, cbPatch, pbBuffer16M + qwoPages + dwoPatch, FALSE);
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
        PageStatClose(&pPageStat);
        printf("%s: Failed. No signature found.\n", szAction);
    }
cleanup:
    PageStatClose(&pPageStat);
    if(cPatchList) {
        for(i = 0; i < cPatchList; i++) {
            printf("%s: Successful. Location: 0x%llx\n", szAction, qwPatchList[i]);
        }
    }
    LocalFree(pSignatures);
    LocalFree(pbBuffer16M);
}


typedef struct tdSEARCH_INTERNAL_CONTEXT {
    DWORD dwPID;
    BOOL isModePatch;
    DWORD cSignatures;
    PSIGNATURE pSignatures;
    LPSTR szAction;
    DWORD cPatchList;
    QWORD qwPatchList[MAX_NUM_PATCH_LOCATIONS];
} SEARCH_INTERNAL_CONTEXT, *PSEARCH_INTERNAL_CONTEXT;

/*
* Virtual memory search callback function.
* -- return: continue_search(TRUE), abort_search(FALSE).
*/
BOOL ActionPatchAndSearchVirtual_ResultCB(_In_ PVMMDLL_MEM_SEARCH_CONTEXT ctxs, _In_ QWORD va, _In_ DWORD iSearch)
{
    PSEARCH_INTERNAL_CONTEXT ctxi = (PSEARCH_INTERNAL_CONTEXT)ctxs->pvUserPtrOpt;
    BYTE pbPage[0x1000];
    BOOL result;
    QWORD vaPage;
    DWORD dwoPatch, cbPatch;
    // 1: fetch page
    vaPage = va & ~0xfff;
    if(!VMMDLL_MemRead(ctxMain->hVMM, ctxi->dwPID, vaPage, pbPage, 0x1000)) {
        return TRUE;
    }
    // 2: patch / unlock (using same methodology as in physical layer)
    result = Patch_FindAndPatch(pbPage, ctxi->pSignatures + iSearch, 1, &dwoPatch, &cbPatch);
    if(!result) {
        return TRUE;
    }
    if(ctxi->isModePatch) {
        result = VMMDLL_MemWrite(ctxMain->hVMM, ctxi->dwPID, vaPage + dwoPatch, ctxi->pSignatures[iSearch].chunk[2].pb, ctxi->pSignatures[iSearch].chunk[2].cb);
    }
    if(result) {
        if(ctxi->cPatchList == MAX_NUM_PATCH_LOCATIONS) {
            printf("%s: Failed. More than %i signatures found. Location: 0x%llx\n", ctxi->szAction, MAX_NUM_PATCH_LOCATIONS, vaPage + dwoPatch);
            return FALSE;
        }
        if(ctxi->cPatchList && (ctxi->qwPatchList[ctxi->cPatchList - 1] == vaPage + dwoPatch)) {
            return TRUE;    // skip if already registered (multiple finds in same page)
        }
        ctxi->qwPatchList[ctxi->cPatchList] = vaPage + dwoPatch;
        ctxi->cPatchList++;
        ctxs->cResult++;
    } else {
        printf("%s: Failed. Write memory failed. Location: 0x%llx\n", ctxi->szAction, vaPage + dwoPatch);
        return FALSE;
    }
    return ctxMain->cfg.fPatchAll;
}

VOID ActionPatchAndSearchVirtual()
{
    DWORD i;
    BOOL result;
    PSTATISTICS_SEARCH pStat = NULL;
    SEARCH_INTERNAL_CONTEXT ctxi = { 0 };
    VMMDLL_MEM_SEARCH_CONTEXT ctxs = { 0 };

    // initialize VMM/MemProcFS
    if(!Vmmx_Initialize(TRUE, FALSE)) {
        printf("%s: Failed. Failed to initialize vmm.\n", ctxi.szAction);
        goto cleanup;
    }
    if(!ctxMain->cfg.dwPID) {
        if(!VMMDLL_PidGetFromName(ctxMain->hVMM, ctxMain->cfg.szProcessName, &ctxMain->cfg.dwPID)) {
            printf("%s: Failed. Failed to retrieve PID for process: %s.\n", ctxi.szAction, ctxMain->cfg.szProcessName);
            goto cleanup;
        }
    }

    // initialize ctxi (internal context) & allocate memory
    ctxi.dwPID = ctxMain->cfg.dwPID;
    ctxi.isModePatch = (ctxMain->cfg.tpAction == PATCH);
    ctxi.szAction = ctxi.isModePatch ? "Patch" : "Search";
    ctxi.cSignatures = CONFIG_MAX_SIGNATURES;
    if(!(ctxi.pSignatures = LocalAlloc(LMEM_ZEROINIT, ctxi.cSignatures * sizeof(SIGNATURE)))) { goto cleanup; }

    // load and verify signatures
    if(ctxMain->cfg.cbIn) {
        Util_CreateSignatureSearchAll(ctxMain->cfg.pbIn, (DWORD)ctxMain->cfg.cbIn, ctxi.pSignatures);
        ctxi.cSignatures = 1;
    } else {
        result = Util_LoadSignatures(ctxMain->cfg.szSignatureName, ".sig", ctxi.pSignatures, &ctxi.cSignatures, 3);
        if(!result || !ctxi.cSignatures) {
            printf("%s: Failed. Failed to load signature.\n", ctxi.szAction);
            goto cleanup;
        }
    }
    if(ctxi.isModePatch) {
        for(i = 0; i < ctxi.cSignatures; i++) {
            if(ctxi.pSignatures[i].chunk[2].cb == 0 || ctxi.pSignatures[i].chunk[2].cb > 4096 || ctxi.pSignatures[i].chunk[2].tpOffset == SIGNATURE_CHUNK_TP_OFFSET_ANY) {
                printf("%s: Failed. Invalid patch signature.\n", ctxi.szAction);
            }
        }
    }

    // initialize ctxs (search context)
    ctxs.dwVersion = VMMDLL_MEM_SEARCH_VERSION;
    ctxs.cSearch = ctxi.cSignatures;
    ctxs.vaMin = ctxMain->cfg.vaAddrMin;
    ctxs.vaMax = ctxMain->cfg.vaAddrMax;
    ctxs.pSearch = LocalAlloc(LMEM_ZEROINIT, ctxs.cSearch * sizeof(VMMDLL_MEM_SEARCH_CONTEXT_SEARCHENTRY));
    if(!ctxs.pSearch) { goto cleanup; }
    for(i = 0; i < ctxi.cSignatures; i++) {
        ctxs.pSearch[i].cb = min(ctxi.pSignatures[i].chunk[0].cb, sizeof(ctxs.pSearch[i].pb));
        memcpy(ctxs.pSearch[i].pb, ctxi.pSignatures[i].chunk[0].pb, ctxs.pSearch[i].cb);
    }
    ctxs.pvUserPtrOpt = &ctxi;
    ctxs.pfnResultOptCB = ActionPatchAndSearchVirtual_ResultCB;
    
    // perform search
    StatSearchInitialize(&pStat, &ctxs, ctxi.szAction);
    VMMDLL_MemSearch(ctxMain->hVMM, ctxi.dwPID, &ctxs, NULL, NULL);
    StatSearchClose(&pStat);
cleanup:
    if(ctxi.cPatchList) {
        printf("%s: Successful. Locations:\n", ctxi.szAction);
        for(i = 0; i < ctxi.cPatchList; i++) {
            printf(" 0x%llx\n", ctxi.qwPatchList[i]);
        }
    } else {
        printf("%s: Failed. No signature found.\n", ctxi.szAction);
    }
    LocalFree(ctxi.pSignatures);
    LocalFree(ctxs.pSearch);
}