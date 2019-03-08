// memdump.c : implementation related to memory dumping functionality.
//
// (c) Ulf Frisk, 2016-2019
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "memdump.h"
#include "device.h"
#include "statistics.h"
#include "util.h"
#include "leechcore.h"
#ifdef WIN32
#include <io.h>
#endif /* WIN32 */

#define MEMDUMP_DATABUFFER_SIZE     0x01000000          // 16MB
#define MEMDUMP_4GB                0x100000000

typedef struct tdFILE_WRITE_ASYNC_BUFFER {
    FILE *phFile;
    BOOL isSuccess;
    BOOL isExecuting;
    DWORD cb;
    BYTE pb[MEMDUMP_DATABUFFER_SIZE];
} FILE_WRITE_ASYNC_BUFFER, *PFILE_WRITE_ASYNC_BUFFER;

VOID MemoryDump_FileWriteAsync_Thread(PFILE_WRITE_ASYNC_BUFFER pfb)
{
    pfb->isSuccess = 0 != fwrite(pfb->pb, 1, pfb->cb, pfb->phFile);
    pfb->isExecuting = FALSE;
}

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
            ctxMain->cfg.qwAddrMin,
            ctxMain->cfg.qwAddrMax,
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond);
    }
}

BOOL MemoryDump_AsyncFileAlloc(_Out_ PFILE_WRITE_ASYNC_BUFFER *ppFileBuffer)
{
    *ppFileBuffer = NULL;
    if(ctxMain->cfg.fOutFile != FALSE) {
        MemoryDump_SetOutFileName();
        *ppFileBuffer = LocalAlloc(LMEM_ZEROINIT, sizeof(FILE_WRITE_ASYNC_BUFFER));
        if(!*ppFileBuffer) {
            printf("Memory Dump: Failed. Failed to allocate memory buffers.\n");
            return FALSE;
        }
        if(!fopen_s(&(*ppFileBuffer)->phFile, ctxMain->cfg.szFileOut, "r") || (*ppFileBuffer)->phFile) {
            if((*ppFileBuffer)->phFile) {
                fclose((*ppFileBuffer)->phFile);
            }
            printf("Memory Dump: Failed. File already exists.\n");
            return FALSE;
        }
        if(fopen_s(&(*ppFileBuffer)->phFile, ctxMain->cfg.szFileOut, "wb") || !(*ppFileBuffer)->phFile) {
            printf("Memory Dump: Failed. Error writing to file.\n");
            return FALSE;
        }
        (*ppFileBuffer)->isSuccess = TRUE;
    } else {
        *ppFileBuffer = NULL;
    }
    return TRUE;
}

VOID MemoryDump_AsyncFileClose(_In_ PFILE_WRITE_ASYNC_BUFFER pFileBuffer)
{
    if(pFileBuffer) {
        if(pFileBuffer->phFile) {
            while(pFileBuffer->isExecuting) {
                SwitchToThread();
            }
            fclose(pFileBuffer->phFile);
        }
        LocalFree(pFileBuffer);
    }
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
    BOOL result;
    QWORD qwCurrentAddress;
    PBYTE pbMemoryDump = NULL;
    PPAGE_STATISTICS pPageStat = NULL;
    PFILE_WRITE_ASYNC_BUFFER pFileBuffer = NULL;
    // 1: Initialize
    if(!(pbMemoryDump = LocalAlloc(0, 0x01000000))) {
        printf("Memory Dump: Failed. Failed to allocate memory buffers.\n");
        goto cleanup;
    }
    if(!MemoryDump_AsyncFileAlloc(&pFileBuffer)) { goto cleanup; }
    ctxMain->cfg.qwAddrMin &= ~0xfff;
    ctxMain->cfg.qwAddrMax = (ctxMain->cfg.qwAddrMax + 1) & ~0xfff;
    // 2: start dump in 16MB blocks
    qwCurrentAddress = ctxMain->cfg.qwAddrMin;
    PageStatInitialize(&pPageStat, ctxMain->cfg.qwAddrMin, ctxMain->cfg.qwAddrMax, "Dumping Memory", ctxMain->phKMD ? TRUE : FALSE, ctxMain->cfg.fVerbose);
    while(qwCurrentAddress < ctxMain->cfg.qwAddrMax) {
        result = Util_Read16M(pbMemoryDump, qwCurrentAddress, pPageStat);
        if(!result && !ctxMain->cfg.fForceRW && !ctxMain->phKMD) {
            printf("Memory Dump: Failed. Cannot dump any sequential data in 16MB - terminating.\n");
            goto cleanup;
        }
        if(pFileBuffer) {
            // write file async
            if(!pFileBuffer->isSuccess) {
                printf("Memory Dump: Failed. Failed to write to dump file - terminating.\n");
                goto cleanup;
            }
            while(pFileBuffer->isExecuting) {
                SwitchToThread();
            }
            pFileBuffer->cb = (DWORD)min(0x01000000, ctxMain->cfg.qwAddrMax - qwCurrentAddress);
            memcpy(pFileBuffer->pb, pbMemoryDump, 0x01000000);
            pFileBuffer->isExecuting = TRUE;
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MemoryDump_FileWriteAsync_Thread, pFileBuffer, 0, NULL);
        }
        // add to address
        qwCurrentAddress += 0x01000000;
    }
    printf("Memory Dump: Successful.\n");
cleanup:
    MemoryDump_AsyncFileClose(pFileBuffer);
    PageStatClose(&pPageStat);
    LocalFree(pbMemoryDump);
}

VOID ActionMemoryDump_Native()
{
    BOOL fSaferDump;
    DWORD cbMemoryDump;
    PBYTE pbMemoryDump = NULL;
    PPAGE_STATISTICS pPageStat = NULL;
    LEECHCORE_PAGESTAT_MINIMAL oLeechCoreStat;
    PFILE_WRITE_ASYNC_BUFFER pFileBuffer = NULL;
    QWORD paMin, paMax, paCurrent;
    // 1: Initialize
    if(!(pbMemoryDump = LocalAlloc(0, MEMDUMP_DATABUFFER_SIZE))) { goto fail; }
    if(!MemoryDump_AsyncFileAlloc(&pFileBuffer)) { goto fail; }
    paMin = ctxMain->cfg.qwAddrMin & ~0xfff;
    paMax = (ctxMain->cfg.qwAddrMax + 1) & ~0xfff;
    // 2: adjust starting location to 4GB if FPGA "safer dump" technique should
    // be employed. i.e. dump memory above 4GB first and then after finish dump
    // memory below 4GB. This is done to reduce impact of any freezes by reads
    // to PCIe "device" addresses that are more common in memory below 4GB.
    paCurrent = paMin;
    fSaferDump = (ctxMain->dev.tpDevice == LEECHCORE_DEVICE_FPGA) && (paMin == 0) && (paMax > MEMDUMP_4GB);
    if(fSaferDump) {
        if(pFileBuffer) {
            printf("Memory Dump: Initializing ...");
            if(_chsize_s(_fileno(pFileBuffer->phFile), MEMDUMP_4GB)) {
                printf("Memory Dump: Failed. Cannot set initial file size to 4GB for 'safer dump'.\n");
                goto fail;
            }
            _fseeki64(pFileBuffer->phFile, MEMDUMP_4GB, SEEK_SET);
            printf(" Done.\n");
        }
        paCurrent = MEMDUMP_4GB;
    }
    // 3: start dump
    PageStatInitialize(&pPageStat, paMin, paMax, "Dumping memory", FALSE, ctxMain->cfg.fVerbose);
    PageStatUpdate(pPageStat, paCurrent, 0, 0);
    oLeechCoreStat.h = (HANDLE)pPageStat;
    oLeechCoreStat.pfnPageStatUpdate = (VOID(*)(HANDLE, ULONG64, ULONG64, ULONG64))PageStatUpdate;
    while(TRUE) {
        cbMemoryDump = (DWORD)min(MEMDUMP_DATABUFFER_SIZE, paMax - paCurrent);
        LeechCore_ReadEx(paCurrent, pbMemoryDump, cbMemoryDump, 0, &oLeechCoreStat);
        if(pFileBuffer) {
            // write file async
            if(!pFileBuffer->isSuccess) {
                printf("Memory Dump: Failed. Failed to write to dump file - terminating.\n");
                goto fail;
            }
            while(pFileBuffer->isExecuting) {
                SwitchToThread();
            }
            pFileBuffer->cb = cbMemoryDump;
            memcpy(pFileBuffer->pb, pbMemoryDump, cbMemoryDump);
            pFileBuffer->isExecuting = TRUE;
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MemoryDump_FileWriteAsync_Thread, pFileBuffer, 0, NULL);
        }
        if(paMax == paCurrent + cbMemoryDump) {
            if(fSaferDump) {
                if(pFileBuffer) {
                    while(pFileBuffer->isExecuting) {
                        SwitchToThread();
                    }
                    _fseeki64(pFileBuffer->phFile, 0, SEEK_SET);
                }
                paCurrent = 0;
                PageStatUpdate(pPageStat, paCurrent, 0, 0);
                continue;
            }
            break;
        }
        if(fSaferDump && (MEMDUMP_4GB == paCurrent + cbMemoryDump)) {
            break;
        }
        paCurrent += cbMemoryDump;
    }
    PageStatClose(&pPageStat);
    printf("Memory Dump: Successful.\n");
    // fall-through to cleanup
fail:
    MemoryDump_AsyncFileClose(pFileBuffer);
    PageStatClose(&pPageStat);
    LocalFree(pbMemoryDump);
}

VOID ActionMemoryDump()
{
    if(ctxMain->phKMD || (ctxMain->dev.tpDevice == LEECHCORE_DEVICE_USB3380)) {
        ActionMemoryDump_KMD_USB3380();
    } else {
        ActionMemoryDump_Native();
    }
}

#define MEMORY_PROBE_PAGES_PER_SWEEP    0x1000

VOID ActionMemoryProbe()
{
    QWORD qwA, cPages, i;
    PPAGE_STATISTICS pPageStat = NULL;
    BYTE pbResultMap[MEMORY_PROBE_PAGES_PER_SWEEP];
    ctxMain->cfg.qwAddrMin &= ~0xfff;
    ctxMain->cfg.qwAddrMax = (ctxMain->cfg.qwAddrMax + 1) & ~0xfff;
    qwA = ctxMain->cfg.qwAddrMin;
    PageStatInitialize(&pPageStat, ctxMain->cfg.qwAddrMin, ctxMain->cfg.qwAddrMax, "Probing Memory", FALSE, TRUE);
    while(qwA < ctxMain->cfg.qwAddrMax) {
        cPages = min(MEMORY_PROBE_PAGES_PER_SWEEP, (ctxMain->cfg.qwAddrMax - qwA) / 0x1000);
        memset(pbResultMap, 0, cPages);
        if(!LeechCore_Probe(qwA, (DWORD)cPages, pbResultMap)) {
            PageStatClose(&pPageStat);
            printf("Memory Probe: Failed. Unsupported device or other failure.\n");
            return;
        }
        for(i = 0; i < cPages; i++) {
            PageStatUpdate(pPageStat, (qwA + i * 0x1000), (pbResultMap[i] ? 1 : 0), (pbResultMap[i] ? 0 : 1));
        }
        qwA += MEMORY_PROBE_PAGES_PER_SWEEP * 0x1000;
    }
    PageStatClose(&pPageStat);
    printf("Memory Probe: Completed.\n");
}

VOID ActionMemoryDisplay()
{
    QWORD qwAddrBase, qwAddrOffset, qwSize, qwSize_4kAlign;
    PBYTE pb;
    // allocate and calculate values
    pb = LocalAlloc(0, 0x10000);
    if(!pb) { return; }
    qwAddrBase = ctxMain->cfg.qwAddrMin & 0x0fffffffffffff000;
    qwAddrOffset = ctxMain->cfg.qwAddrMin & 0xff0;
    qwSize_4kAlign = SIZE_PAGE_ALIGN_4K(ctxMain->cfg.qwAddrMax) - qwAddrBase;
    qwSize = ((ctxMain->cfg.qwAddrMax + 0xf) & 0x0fffffffffffffff0) - (qwAddrBase + qwAddrOffset);
    if(qwSize_4kAlign > 0x10000 || (ctxMain->cfg.qwAddrMax == ctxMain->dev.paMax)) {
        qwSize = 0x100;
        qwSize_4kAlign = (qwAddrOffset <= 0xf00) ? 0x1000 : 0x2000;
    }
    // read memory and display output
    if(!DeviceReadMEM(qwAddrBase, pb, (DWORD)qwSize_4kAlign, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
        printf("Memory Display: Failed reading memory at address: 0x%016llX.\n", qwAddrBase);
        LocalFree(pb);
        return;
    }
    printf("Memory Display: Contents for address: 0x%016llX\n", qwAddrBase);
    Util_PrintHexAscii(pb, (DWORD)qwSize, (DWORD)qwAddrOffset);
    LocalFree(pb);
}

VOID ActionMemoryPageDisplay()
{
    ctxMain->cfg.qwAddrMin = ctxMain->cfg.qwAddrMin & 0x0fffffffffffff000;
    ctxMain->cfg.qwAddrMax = ctxMain->cfg.qwAddrMin + 0x1000;
    ActionMemoryDisplay();
}

VOID ActionMemoryTestReadWrite()
{
    BYTE pb1[4096], pb2[4096], pb3[4096];
    DWORD dwAddrPci32 = (DWORD)(ctxMain->cfg.qwAddrMin & 0xfffff000);
    DWORD i, dwOffset, dwRuns = 1000;
    BOOL r1, r2;
    if(ctxMain->phKMD) {
        printf("Memory Test Read: Failed. Memory test may not run in KMD mode.\n");
        return;
    }
    LeechCore_Read(dwAddrPci32, pb1, 4096);
    // READ DMA
    printf("Memory Test Read: starting, reading %i times from address: 0x%08x\n", dwRuns, dwAddrPci32);
    LeechCore_Read(dwAddrPci32, pb1, 4096);
    for(i = 0; i < dwRuns; i++) {
        r1 = 4096 == LeechCore_Read(dwAddrPci32, pb2, 4096);
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
            r1 = LeechCore_Write(dwAddrPci32, pb3, 4096);
            r2 = 4096 == LeechCore_Read(dwAddrPci32, pb2, 4096);
            if(!r1 || !r2 || (dwOffset = Util_memcmpEx(pb2, pb3, 4096))) {
                LeechCore_Write(dwAddrPci32, pb1, 4096);
                printf("Memory Test Write: Failed. DMA failed / data changed by target computer / memory corruption. Write: %i. Read: %i. Run: %i. Offset: 0x%03x\n", r1, r2, i, --dwOffset);
                return;
            }
        }
        LeechCore_Write(dwAddrPci32, pb1, 4096);
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
    do {
        result = DeviceWriteMEM(ctxMain->cfg.qwAddrMin, ctxMain->cfg.pbIn, (DWORD)ctxMain->cfg.cbIn, 0);
        if(!result) {
            printf("Memory Write: Failed. Write failed (partial memory may be written).\n");
            return;
        }
    } while(ctxMain->cfg.fLoop);
    printf("Memory Write: Successful.\n");
}
