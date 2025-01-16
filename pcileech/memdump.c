// memdump.c : implementation related to memory dumping functionality.
//
// (c) Ulf Frisk, 2016-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include <leechcore.h>
#include "memdump.h"
#include "device.h"
#include "statistics.h"
#include "util.h"
#include "vmmx.h"
#include <vmmdll.h>
#ifdef WIN32
#include <io.h>
#endif /* WIN32 */

#define MEMDUMP_DATABUFFER_SIZE     0x01000000          // 16MB
#define MEMDUMP_4GB                 0x100000000
#define MEMDUMP_NUM_BUFFER          3


typedef struct tdMEMDUMP_FILEWRITE_DATA {
    QWORD paMin;
    QWORD pa;
    DWORD cb;
    BYTE pb[MEMDUMP_DATABUFFER_SIZE];
} MEMDUMP_FILEWRITE_DATA, *PMEMDUMP_FILEWRITE_DATA;

typedef struct tdMEMDUMP_FILEWRITE {
    FILE *hFile;
    BOOL fFileNone;
    BOOL fValid;
    BOOL fTerminated;
    QWORD iRead;    // index of reader thread
    QWORD iWrite;   // index of writer thread
    MEMDUMP_FILEWRITE_DATA Data[MEMDUMP_NUM_BUFFER];
} MEMDUMP_FILEWRITE, *PMEMDUMP_FILEWRITE;

VOID MemoryDump_SetOutFileName()
{
    SYSTEMTIME st;
    if(ctxMain->cfg.fOutFile && ctxMain->cfg.szFileOut[0] == 0) {
        GetLocalTime(&st);
        _snprintf_s(
            ctxMain->cfg.szFileOut,
            MAX_PATH,
            _TRUNCATE,
            "pcileech-%llx-%llx-%i%02i%02i-%02i%02i%02i.raw",
            ctxMain->cfg.paAddrMin,
            ctxMain->cfg.paAddrMax,
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond);
    }
}

DWORD WINAPI MemoryDump_File_ThreadProc(_In_ PMEMDUMP_FILEWRITE ctx)
{
    PMEMDUMP_FILEWRITE_DATA pd;
    while(ctx->fValid) {
        if(ctx->iRead == ctx->iWrite) {
            Sleep(25);
            continue;
        }
        pd = &ctx->Data[ctx->iRead % MEMDUMP_NUM_BUFFER];
        _fseeki64(ctx->hFile, pd->pa - pd->paMin, SEEK_SET);
        if(pd->cb != fwrite(pd->pb, 1, pd->cb, ctx->hFile)) {
            printf("Memory Dump: Failed. Write to file.\n");
            break;
        }
        InterlockedIncrement64(&ctx->iRead);
    }
    ctx->fTerminated = TRUE;
    return 0;
}

VOID MemoryDump_File_Close(_Post_ptr_invalid_ PMEMDUMP_FILEWRITE pfw)
{
    pfw->fValid = FALSE;
    while(!pfw->fFileNone && !pfw->fTerminated) {
        Sleep(25);
    }
    if(pfw->hFile) { fclose(pfw->hFile); }
    LocalFree(pfw);
}

PMEMDUMP_FILEWRITE MemoryDump_File_Initialize(_In_ BOOL fAllocFile4GB)
{
    FILE *hFileTMP;
    HANDLE hThread;
    PMEMDUMP_FILEWRITE pfw;
    MemoryDump_SetOutFileName();
    if(!(pfw = LocalAlloc(LMEM_ZEROINIT, sizeof(MEMDUMP_FILEWRITE)))) {
        printf("Memory Dump: Failed. Out of memory.\n");
        goto fail;
    }
    if(0 == ctxMain->cfg.szFileOut[0]) {
        pfw->fFileNone = TRUE;
        return pfw;
    }
    if(!fopen_s(&hFileTMP, ctxMain->cfg.szFileOut, "r")) {
        fclose(hFileTMP);
        printf("Memory Dump: Failed. File already exists.\n");
        goto fail;
    }
    if(fopen_s(&pfw->hFile, ctxMain->cfg.szFileOut, "wb")) {
        printf("Memory Dump: Failed. Error writing to file.\n");
        goto fail;
    }
    if(fAllocFile4GB) {
        printf("Memory Dump: Initializing ...");
        if(_chsize_s(_fileno(pfw->hFile), MEMDUMP_4GB)) {
            printf("Memory Dump: Failed. Cannot set initial file size to 4GB for 'safer dump'.\n");
            goto fail;
        }
        printf(" Done.\n");
    }
    pfw->fValid = TRUE;
    if(!(hThread = CreateThread(NULL, 0, MemoryDump_File_ThreadProc, pfw, 0, NULL))) {
        printf("Memory Dump: Failed. Create Thread.\n");
        goto fail;
    }
    CloseHandle(hThread);
    return pfw;
fail:
    if(pfw) {
        if(pfw->hFile) { fclose(pfw->hFile); }
        LocalFree(pfw);
    }
    return NULL;
}

/*
* Dump memory with the kernel module (KMD) / USB3380 strategy - that is:
* - read chunks:
*      from zero (or user-specified value)
*      to to max supported memory (or specified by user)
*      in 16MB chunks.
* If the mode is USB3380 native a failed read for 16MB will stop the dumping.
*/
VOID ActionMemoryDump_KMD_USB3380()
{
    BOOL fPartialSuccess;
    QWORD paCurrent, paMin, paMax;
    PMEMDUMP_FILEWRITE_DATA pd;
    PMEMDUMP_FILEWRITE pfw = NULL;
    PPAGE_STATISTICS pStat = NULL;
    // 1: Initialize result file, buffers and statistics:
    paMin = ctxMain->cfg.paAddrMin & ~0xfff;
    paMax = (ctxMain->cfg.paAddrMax + 1) & ~0xfff;
    if(!(pfw = MemoryDump_File_Initialize(FALSE))) { return; }
    PageStatInitialize(&pStat, paMin, paMax, "Dumping Memory", ctxMain->phKMD ? TRUE : FALSE, ctxMain->cfg.fVerbose);
    // 2: Dump memory in 16MB blocks:
    paCurrent = paMin;
    PageStatUpdate(pStat, paCurrent, 0, 0);
    while(!pfw->fTerminated && (paCurrent < paMax)) {
        if(!pfw->fFileNone && (pfw->iWrite >= pfw->iRead + 3)) {
            Sleep(25);
            continue;
        }
        pd = &pfw->Data[pfw->iWrite % MEMDUMP_NUM_BUFFER];
        pd->cb = (DWORD)min(MEMDUMP_DATABUFFER_SIZE, paMax - paCurrent);
        pd->pa = paCurrent;
        if(!Util_Read16M(pd->pb, paCurrent, pStat)) {
            printf("Memory Dump: Failed. Cannot dump any sequential data in 16MB - terminating.\n");
            goto fail;
        }
        InterlockedIncrement64(&pfw->iWrite);
        paCurrent += pd->cb;
    }
    fPartialSuccess = pStat->cPageSuccess > 0;
    PageStatClose(&pStat);
    if(!pfw->fTerminated) {
        printf("Memory Dump: %s.\n", fPartialSuccess ? "Successful" : "Failed");
    }
fail:
    PageStatClose(&pStat);
    MemoryDump_File_Close(pfw);
}

/*
* Dump memory with native mode strategy:
* If more than 4GB memory exists, dump memory above 4GB first and then start
* dumping between zero and 4GB - this to dump as much memory as possible before
* hitting problematic PCIe memory mapped devices between 3-4GB which commonly
* crashes computer when read ...
*/
VOID ActionMemoryDump_Native()
{
    BOOL fSaferDump;
    QWORD paCurrent, paMin, paMax;
    PMEMDUMP_FILEWRITE_DATA pd;
    PMEMDUMP_FILEWRITE pfw = NULL;
    PPAGE_STATISTICS pStat = NULL;
    // 1: Initialize result file, buffers and statistics:
    paMin = ctxMain->cfg.paAddrMin & ~0xfff;
    paMax = (ctxMain->cfg.paAddrMax + 1) & ~0xfff;
    fSaferDump = PCILEECH_DEVICE_EQUALS("fpga") && (paMin == 0) && (paMax > MEMDUMP_4GB);
    if(!(pfw = MemoryDump_File_Initialize(fSaferDump))) { return; }
    PageStatInitialize(&pStat, paMin, paMax, "Dumping Memory", FALSE, ctxMain->cfg.fVerbose);
    // 2: Dump memory in 16MB blocks:
    paCurrent = fSaferDump ? MEMDUMP_4GB : paMin;
    PageStatUpdate(pStat, paCurrent, 0, 0);
    while(!pfw->fTerminated) {
        if(!pfw->fFileNone && (pfw->iWrite >= pfw->iRead + 3)) {
            Sleep(25);
            continue;
        }
        pd = &pfw->Data[pfw->iWrite % MEMDUMP_NUM_BUFFER];
        pd->cb = (DWORD)min(MEMDUMP_DATABUFFER_SIZE, paMax - paCurrent);
        pd->pa = paCurrent;
        pd->paMin = paMin;
        ZeroMemory(pd->pb, pd->cb);
        DeviceReadDMA(pd->pa, pd->cb, pd->pb, pStat);
        InterlockedIncrement64(&pfw->iWrite);
        if(paMax == pd->pa + pd->cb) {
            if(fSaferDump) {
                paCurrent = 0;
                PageStatUpdate(pStat, paCurrent, 0, 0);
                continue;
            }
            break;
        }
        if(fSaferDump && (MEMDUMP_4GB == pd->pa + pd->cb)) {
            break;
        }
        paCurrent += pd->cb;
    }
    PageStatClose(&pStat);
    if(!pfw->fTerminated) {
        printf("Memory Dump: Successful.\n");
    }
    MemoryDump_File_Close(pfw);
}

VOID ActionMemoryDump()
{
    if(ctxMain->phKMD || PCILEECH_DEVICE_EQUALS("usb3380")) {
        ActionMemoryDump_KMD_USB3380();
    } else {
        ActionMemoryDump_Native();
    }
}

#define MEMORY_PROBE_PAGES_PER_SWEEP    0x1000

VOID ActionMemoryProbe()
{
    QWORD pa, i, cPages;
    PPAGE_STATISTICS pPageStat = NULL;
    PBYTE pbProbeResultMap = NULL;
    DWORD cbProbeResultMap;
    ctxMain->cfg.paAddrMin &= ~0xfff;
    ctxMain->cfg.paAddrMax = (ctxMain->cfg.paAddrMax + 1) & ~0xfff;
    pa = ctxMain->cfg.paAddrMin;
    printf("WARNING: 'probe' may cause the device to stop working until a reboot on AMD or\n");
    printf("         Thunderbolt systems and is discouraged. See link for additional info:\n");
    printf("         https://github.com/ufrisk/LeechCore/wiki/Device_FPGA_AMD_Thunderbolt \n\n");
    PageStatInitialize(&pPageStat, ctxMain->cfg.paAddrMin, ctxMain->cfg.paAddrMax, "Probing Memory", FALSE, TRUE);
    while(pa < ctxMain->cfg.paAddrMax) {
        cPages = (DWORD)min(MEMORY_PROBE_PAGES_PER_SWEEP, (ctxMain->cfg.paAddrMax - pa) / 0x1000);
        if(!LcCommand(ctxMain->hLC, LC_CMD_FPGA_PROBE | cPages, sizeof(QWORD), (PBYTE)&pa, &pbProbeResultMap, &cbProbeResultMap) || (cPages > cbProbeResultMap)) {
            PageStatClose(&pPageStat);
            printf("Memory Probe: Failed. Unsupported device or other failure.\n");
            return;
        }
        for(i = 0; i < cPages; i++) {
            PageStatUpdate(pPageStat, (pa + i * 0x1000 + 0x1000), (pbProbeResultMap[i] ? 1 : 0), (pbProbeResultMap[i] ? 0 : 1));
        }
        pa += MEMORY_PROBE_PAGES_PER_SWEEP * 0x1000;
    }
    PageStatClose(&pPageStat);
    printf("Memory Probe: Completed.\n");
}

VOID ActionMemoryDisplayPhysical()
{
    QWORD qwAddrBase, qwAddrOffset, qwSize, qwSize_4kAlign;
    PBYTE pb;
    // allocate and calculate values
    pb = LocalAlloc(0, 0x10000);
    if(!pb) { return; }
    qwAddrBase = ctxMain->cfg.paAddrMin & 0x0fffffffffffff000;
    qwAddrOffset = ctxMain->cfg.paAddrMin & 0xff0;
    qwSize_4kAlign = SIZE_PAGE_ALIGN_4K(ctxMain->cfg.paAddrMax) - qwAddrBase;
    qwSize = ((ctxMain->cfg.paAddrMax + 0xf) & 0x0fffffffffffffff0) - (qwAddrBase + qwAddrOffset);
    if(qwSize_4kAlign > 0x10000 || (ctxMain->cfg.paAddrMax == ctxMain->dev.paMax)) {
        qwSize = 0x100;
        qwSize_4kAlign = (qwAddrOffset <= 0xf00) ? 0x1000 : 0x2000;
    }
    // read memory and display output
    if(!DeviceReadMEM(qwAddrBase, (DWORD)qwSize_4kAlign, pb, TRUE)) {
        printf("Memory Display: Failed reading memory at address: 0x%016llX.\n", qwAddrBase);
        LocalFree(pb);
        return;
    }
    printf("Memory Display: Contents for address: 0x%016llX\n", qwAddrBase);
    Util_PrintHexAscii(pb, (DWORD)(qwSize + qwAddrOffset), (DWORD)qwAddrOffset);
    LocalFree(pb);
}

VOID ActionMemoryDisplayVirtual()
{
    QWORD qwAddrBase, qwAddrOffset, qwSize, qwSize_4kAlign;
    PBYTE pb;
    // allocate and calculate values
    pb = LocalAlloc(0, 0x10000);
    if(!pb) { return; }
    qwAddrBase = ctxMain->cfg.vaAddrMin & 0x0fffffffffffff000;
    qwAddrOffset = ctxMain->cfg.vaAddrMin & 0xff0;
    qwSize_4kAlign = SIZE_PAGE_ALIGN_4K(ctxMain->cfg.vaAddrMax) - qwAddrBase;
    qwSize = ((ctxMain->cfg.vaAddrMax + 0xf) & 0x0fffffffffffffff0) - (qwAddrBase + qwAddrOffset);
    if(qwSize_4kAlign > 0x10000 || (ctxMain->cfg.vaAddrMax == ctxMain->dev.paMax)) {
        qwSize = 0x100;
        qwSize_4kAlign = (qwAddrOffset <= 0xf00) ? 0x1000 : 0x2000;
    }
    // initialize vmm/memprocfs
    if(!Vmmx_Initialize(FALSE, FALSE)) {
        printf("Memory Display: Failed. Unable to initialize virtual memory.\n");
        LocalFree(pb);
        return;
    }
    if(!ctxMain->cfg.dwPID) {
        if(!VMMDLL_PidGetFromName(ctxMain->hVMM, ctxMain->cfg.szProcessName, &ctxMain->cfg.dwPID)) {
            printf("Memory Display: Failed to retrieve PID for process: %s.\n", ctxMain->cfg.szProcessName);
            LocalFree(pb);
            return;
        }
    }
    // read memory and display output
    if(!VMMDLL_MemRead(ctxMain->hVMM, ctxMain->cfg.dwPID, qwAddrBase, pb, (DWORD)qwSize_4kAlign)) {
        printf("Memory Display: Failed reading memory at address: 0x%016llX.\n", qwAddrBase);
        LocalFree(pb);
        return;
    }
    printf("Memory Display: Contents for address: 0x%016llX\n", qwAddrBase);
    Util_PrintHexAscii(pb, (DWORD)(qwSize + qwAddrOffset), (DWORD)qwAddrOffset);
    LocalFree(pb);
}

VOID ActionMemoryPageDisplay()
{
    if(ctxMain->cfg.fModeVirtual) {
        // virtual memory (Windows only):
        ctxMain->cfg.vaAddrMin = ctxMain->cfg.vaAddrMin & 0x0fffffffffffff000;
        ctxMain->cfg.vaAddrMax = ctxMain->cfg.vaAddrMin + 0x1000;
        ActionMemoryDisplayVirtual();
    } else {
        // physical memory
        ctxMain->cfg.paAddrMin = ctxMain->cfg.paAddrMin & 0x0fffffffffffff000;
        ctxMain->cfg.paAddrMax = ctxMain->cfg.paAddrMin + 0x1000;
        ActionMemoryDisplayPhysical();
    }
}

VOID ActionMemoryTestReadWrite()
{
    BYTE pb1[4096], pb2[4096], pb3[4096];
    DWORD dwAddrPci32 = (DWORD)(ctxMain->cfg.paAddrMin & 0xfffff000);
    DWORD i, dwOffset, dwRuns = 1000;
    BOOL r1, r2;
    if(ctxMain->phKMD) {
        printf("Memory Test Read: Failed. Memory test may not run in KMD mode.\n");
        return;
    }
    LcRead(ctxMain->hLC, dwAddrPci32, 4096, pb1);
    // READ DMA
    printf("Memory Test Read: starting, reading %i times from address: 0x%08x\n", dwRuns, dwAddrPci32);
    LcRead(ctxMain->hLC, dwAddrPci32, 4096, pb1);
    for(i = 0; i < dwRuns; i++) {
        r1 = LcRead(ctxMain->hLC, dwAddrPci32, 4096, pb2);
        if(!r1 || (dwOffset = Util_memcmpEx(pb1, pb2, 4096))) {
            printf("Memory Test Read: Failed. DMA failed / data changed by target computer / memory corruption. Read: %i. Run: %i. Offset: 0x%03x\n", r1, i, (r1 ? --dwOffset : 0));
            return;
        }
    }
    // WRITE DMA
    printf("Memory Test Read: SUCCESS!\n");
    if(ctxMain->cfg.tpAction == TESTMEMREADWRITE) {
        dwRuns = 100;
        printf("Memory Test Write: starting, reading/writing %i times from address: 0x%08x\n", dwRuns, dwAddrPci32);
        for(i = 0; i < dwRuns; i++) {
            Util_GenRandom(pb3, 4096);
            r1 = LcWrite(ctxMain->hLC, dwAddrPci32, 4096, pb3);
            r2 = LcRead(ctxMain->hLC, dwAddrPci32, 4096, pb2);
            if(!r1 || !r2 || (dwOffset = Util_memcmpEx(pb2, pb3, 4096))) {
                LcWrite(ctxMain->hLC, dwAddrPci32, 4096, pb1);
                printf("Memory Test Write: Failed. DMA failed / data changed by target computer / memory corruption. Write: %i. Read: %i. Run: %i. Offset: 0x%03x\n", r1, r2, i, --dwOffset);
                return;
            }
        }
        LcWrite(ctxMain->hLC, dwAddrPci32, 4096, pb1);
        printf("Memory Test Write: Success!\n");
    }
}

VOID ActionMemoryWrite()
{
    BOOL result;
    if(ctxMain->cfg.cbIn == 0) {
        printf("Memory Write: Failed. No data to write.\n");
        return;
    }
    if(ctxMain->cfg.cbIn > 0x01000000) {
        printf("Memory Write: Failed. Data too large: >16MB.\n");
        return;
    }
    if(ctxMain->cfg.fLoop) {
        printf("Memory Write: Starting loop write. Press CTRL+C to abort.\n");
    }
    if(ctxMain->cfg.fModeVirtual) {
        // virtual memory (Windows only):
        if(!Vmmx_Initialize(FALSE, FALSE)) {
            printf("Memory Write: Failed. Unable to initialize virtual memory.\n");
            return;
        }
        if(!ctxMain->cfg.dwPID) {
            if(!VMMDLL_PidGetFromName(ctxMain->hVMM, ctxMain->cfg.szProcessName, &ctxMain->cfg.dwPID)) {
                printf("Memory Write: Failed to retrieve PID for process: %s.\n", ctxMain->cfg.szProcessName);
                return;
            }
        }
        do {
            result = VMMDLL_MemWrite(ctxMain->hVMM, ctxMain->cfg.dwPID, ctxMain->cfg.vaAddrMin, ctxMain->cfg.pbIn, (DWORD)ctxMain->cfg.cbIn);
            if(!result) {
                printf("Memory Write: Failed. Write failed (partial memory may be written).\n");
                return;
            }
        } while(ctxMain->cfg.fLoop);
    } else {
        // physical memory:
        do {
            result = DeviceWriteMEM(ctxMain->cfg.paAddrMin, (DWORD)ctxMain->cfg.cbIn, ctxMain->cfg.pbIn, FALSE);
            if(!result) {
                printf("Memory Write: Failed. Write failed (partial memory may be written).\n");
                return;
            }
        } while(ctxMain->cfg.fLoop);
    }
    printf("Memory Write: Successful.\n");
}
