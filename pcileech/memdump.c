// memdump.c : implementation related to memory dumping functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "memdump.h"
#include "device.h"
#include "statistics.h"
#include "util.h"

typedef struct tdFILE_WRITE_ASYNC_BUFFER {
	FILE *phFile;
	BOOL isSuccess;
	BOOL isExecuting;
	DWORD cb;
	BYTE pb[0x01000000]; // 16MB Data Buffer
} FILE_WRITE_ASYNC_BUFFER, *PFILE_WRITE_ASYNC_BUFFER;

VOID MemoryDump_FileWriteAsync_Thread(PFILE_WRITE_ASYNC_BUFFER pfb)
{
	pfb->isSuccess = 0 != fwrite(pfb->pb, 1, pfb->cb, pfb->phFile);
	pfb->isExecuting = FALSE;
}

VOID MemoryDump_SetOutFileName(_Inout_ PCONFIG pCfg)
{
	SYSTEMTIME st;
	if(pCfg->fOutFile && pCfg->szFileOut[0] == 0) {
		GetLocalTime(&st);
		_snprintf_s(
			pCfg->szFileOut,
			MAX_PATH,
			_TRUNCATE,
			"pcileech-%llx-%llx-%i%02i%02i-%02i%02i%02i.raw",
			pCfg->qwAddrMin,
			pCfg->qwAddrMax,
			st.wYear,
			st.wMonth,
			st.wDay,
			st.wHour,
			st.wMinute,
			st.wSecond);
	}
}

VOID ActionMemoryDump(_Inout_ PPCILEECH_CONTEXT ctx)
{
	PBYTE pbMemoryDump;
	QWORD qwCurrentAddress;
	BOOL result;
	PAGE_STATISTICS pageStat;
	PFILE_WRITE_ASYNC_BUFFER pFileBuffer;
	// 1: Initialize
	pbMemoryDump = LocalAlloc(0, 0x01000000); // 16MB Data Buffer
	if(!pbMemoryDump) {
		printf("Memory Dump: Failed. Failed to allocate memory buffers.\n");
		return;
	}
	if (ctx->cfg->fOutFile != FALSE)
	{
		MemoryDump_SetOutFileName(ctx->cfg);
		pFileBuffer = LocalAlloc(LMEM_ZEROINIT, sizeof(FILE_WRITE_ASYNC_BUFFER));
		if (!pFileBuffer) {
			printf("Memory Dump: Failed. Failed to allocate memory buffers.\n");
			return;
		}
		if(!fopen_s(&pFileBuffer->phFile, ctx->cfg->szFileOut, "r") || pFileBuffer->phFile) {
			fclose(pFileBuffer->phFile);
			printf("Memory Dump: Failed. File already exists.\n");
			return;
		}
		if(fopen_s(&pFileBuffer->phFile, ctx->cfg->szFileOut, "wb") || !pFileBuffer->phFile) {
			printf("Memory Dump: Failed. Error writing to file.\n");
			return;
		}
		pFileBuffer->isSuccess = TRUE;
	}
	else
	{
		pFileBuffer = NULL;
	}
	ctx->cfg->qwAddrMin &= ~0xfff;
	ctx->cfg->qwAddrMax = (ctx->cfg->qwAddrMax + 1) & ~0xfff;
	// 2: start dump in 16MB blocks
	qwCurrentAddress = ctx->cfg->qwAddrMin;
	PageStatInitialize(&pageStat, ctx->cfg->qwAddrMin, ctx->cfg->qwAddrMax, "Dumping Memory", ctx->phKMD ? TRUE : FALSE, ctx->cfg->fVerbose);
	while(qwCurrentAddress < ctx->cfg->qwAddrMax) {
		result = Util_Read16M(ctx, pbMemoryDump, qwCurrentAddress, &pageStat);
		if(!result && !ctx->cfg->fForceRW && !ctx->phKMD) {
			PageStatClose(&pageStat);
			printf("Memory Dump: Failed. Cannot dump any sequential data in 16MB - terminating.\n");
			goto cleanup;
		}
		if (pFileBuffer != NULL)
		{
			// write file async
			if(!pFileBuffer->isSuccess) {
				PageStatClose(&pageStat);
				printf("Memory Dump: Failed. Failed to write to dump file - terminating.\n");
				goto cleanup;
			}
			while(pFileBuffer->isExecuting) {
				SwitchToThread();
			}
			pFileBuffer->cb = (DWORD)min(0x01000000, ctx->cfg->qwAddrMax - qwCurrentAddress);
			memcpy(pFileBuffer->pb, pbMemoryDump, 0x01000000);
			pFileBuffer->isExecuting = TRUE;
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MemoryDump_FileWriteAsync_Thread, pFileBuffer, 0, NULL);
		}
		// add to address
		qwCurrentAddress += 0x01000000;
	}
	PageStatClose(&pageStat);
	printf("Memory Dump: Successful.\n");
cleanup:
	if(pbMemoryDump) {
		LocalFree(pbMemoryDump);
	}
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

#define MEMORY_PROBE_PAGES_PER_SWEEP	0x1000

VOID ActionMemoryProbe(_Inout_ PPCILEECH_CONTEXT ctx)
{
	PAGE_STATISTICS ps;
	QWORD qwA, cPages, i;
	BYTE pbResultMap[MEMORY_PROBE_PAGES_PER_SWEEP];
	ctx->cfg->qwAddrMin &= ~0xfff;
	ctx->cfg->qwAddrMax = (ctx->cfg->qwAddrMax + 1) & ~0xfff;
	qwA = ctx->cfg->qwAddrMin;
	PageStatInitialize(&ps, ctx->cfg->qwAddrMin, ctx->cfg->qwAddrMax, "Probing Memory", FALSE, TRUE);
	while(qwA < ctx->cfg->qwAddrMax) {
		cPages = min(MEMORY_PROBE_PAGES_PER_SWEEP, (ctx->cfg->qwAddrMax - qwA) / 0x1000);
        memset(pbResultMap, 0, cPages);
		if(!DeviceProbeDMA(ctx, qwA, (DWORD)cPages, pbResultMap)) {
			PageStatClose(&ps);
			printf("Memory Probe: Failed. Unsupported hardware (USB3380) or other failure.\n");
			return;
		}
		for(i = 0; i < cPages; i++) {
			PageStatUpdate(&ps, (qwA + i * 0x1000), (pbResultMap[i] ? 1 : 0), (pbResultMap[i] ? 0 : 1));
		}
		qwA += MEMORY_PROBE_PAGES_PER_SWEEP * 0x1000;
	}
	PageStatClose(&ps);
	printf("Memory Probe: Completed.\n");
}

VOID ActionMemoryDisplay(_Inout_ PPCILEECH_CONTEXT ctx)
{
	QWORD qwAddrBase, qwAddrOffset, qwSize, qwSize_4kAlign;
	PBYTE pb;
	// allocate and calculate values
	pb = LocalAlloc(0, 0x10000);
	if(!pb) { return; }
	qwAddrBase = ctx->cfg->qwAddrMin & 0x0fffffffffffff000;
	qwAddrOffset = ctx->cfg->qwAddrMin & 0xff0;
	qwSize_4kAlign = SIZE_PAGE_ALIGN_4K(ctx->cfg->qwAddrMax) - qwAddrBase;
	qwSize = ((ctx->cfg->qwAddrMax + 0xf) & 0x0fffffffffffffff0) - (qwAddrBase + qwAddrOffset);
	if(qwSize_4kAlign > 0x10000) {
		qwSize = 0x100;
		qwSize_4kAlign = (qwAddrOffset <= 0xf00) ? 0x1000 : 0x2000;
	}
	// read memory and display output
	if(!DeviceReadMEM(ctx, qwAddrBase, pb, (DWORD)qwSize_4kAlign, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
		printf("Memory Display: Failed reading memory at address: 0x%016llX.\n", qwAddrBase);
		LocalFree(pb);
		return;
	}
	printf("Memory Display: Contents for address: 0x%016llX\n", qwAddrBase);
	Util_PrintHexAscii(pb, (DWORD)qwSize, (DWORD)qwAddrOffset);
	LocalFree(pb);
}

VOID ActionMemoryPageDisplay(_Inout_ PPCILEECH_CONTEXT ctx)
{
	ctx->cfg->qwAddrMin = ctx->cfg->qwAddrMin & 0x0fffffffffffff000;
	ctx->cfg->qwAddrMax = ctx->cfg->qwAddrMin + 0x1000;
	ActionMemoryDisplay(ctx);
}

VOID ActionMemoryTestReadWrite(_Inout_ PPCILEECH_CONTEXT ctx)
{
	BYTE pb1[4096], pb2[4096], pb3[4096];
	DWORD dwAddrPci32 = (DWORD)(ctx->cfg->qwAddrMin & 0xfffff000);
	DWORD i, dwOffset, dwRuns = 1000;
	BOOL r1, r2;
	if(ctx->phKMD) {
		printf("Memory Test Read: Failed. Memory test may not run in KMD mode.\n");
		return;
	}
	DeviceReadDMA(ctx, dwAddrPci32, pb1, 4096, 0);
	// READ DMA
	printf("Memory Test Read: starting, reading %i times from address: 0x%08x\n", dwRuns, dwAddrPci32);
	DeviceReadDMA(ctx, dwAddrPci32, pb1, 4096, 0);
	for(i = 0; i < dwRuns; i++) {
		r1 = DeviceReadDMA(ctx, dwAddrPci32, pb2, 4096, 0);
		if(!r1 || (dwOffset = Util_memcmpEx(pb1, pb2, 4096))) {
			printf("Memory Test Read: Failed. DMA failed / data changed by target computer / memory corruption. Read: %i. Run: %i. Offset: 0x%03x\n", r1, i, (r1 ? --dwOffset : 0));
			return;
		}
	}
	// WRITE DMA
	printf("Memory Test Read: SUCCESS!\n");
	if(ctx->cfg->tpAction == TESTMEMREADWRITE) {
		dwRuns = 100;
		printf("Memory Test Write: starting, reading/writing %i times from address: 0x%08x\n", dwRuns, dwAddrPci32);
		for(i = 0; i < dwRuns; i++) {
			Util_GenRandom(pb3, 4096);
			r1 = DeviceWriteDMA(ctx, dwAddrPci32, pb3, 4096, 0);
			r2 = DeviceReadDMA(ctx, dwAddrPci32, pb2, 4096, 0);
			if(!r1 || !r2 || (dwOffset = Util_memcmpEx(pb2, pb3, 4096))) {
				DeviceWriteDMA(ctx, dwAddrPci32, pb1, 4096, 0);
				printf("Memory Test Write: Failed. DMA failed / data changed by target computer / memory corruption. Write: %i. Read: %i. Run: %i. Offset: 0x%03x\n", r1, r2, i, --dwOffset);
				return;
			}
		}
		DeviceWriteDMA(ctx, dwAddrPci32, pb1, 4096, 0);
		printf("Memory Test Write: Success!\n");
	}
}

VOID ActionMemoryWrite(_Inout_ PPCILEECH_CONTEXT ctx)
{
	BOOL result;
	if(ctx->cfg->cbIn == 0) {
		printf("Memory Write: Failed. No data to write.\n");
		return;
	}
	if(ctx->cfg->cbIn > 0x01000000) {
		printf("Memory Write: Failed. Data too large: >16MB.\n");
		return;
	}
    if(ctx->cfg->fLoop) {
        printf("Memory Write: Starting loop write. Press CTRL+C to abort.\n");
    }
    do {
        result = DeviceWriteMEM(ctx, ctx->cfg->qwAddrMin, ctx->cfg->pbIn, (DWORD)ctx->cfg->cbIn, 0);
        if(!result) {
            printf("Memory Write: Failed. Write failed (partial memory may be written).\n");
            return;
        }
    } while(ctx->cfg->fLoop);
	printf("Memory Write: Successful.\n");
}