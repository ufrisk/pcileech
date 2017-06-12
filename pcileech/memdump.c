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

VOID ActionMemoryPageDisplay(_Inout_ PPCILEECH_CONTEXT ctx)
{
	BYTE pb[4096];
	QWORD qwAddr = ctx->cfg->qwAddrMin & 0x0fffffffffffff000;
	printf("Memory Page Read: Page contents for address: 0x%016llX\n", qwAddr);
	if(!DeviceReadMEM(ctx, qwAddr, pb, 4096, PCILEECH_MEM_FLAG_RETRYONFAIL)) {
		printf("Memory Page Read: Failed.\n");
		return;
	}
	Util_PrintHexAscii(pb, 4096);
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
	if(ctx->cfg->cbIn >= 0x01000000) {
		printf("Memory Write: Failed. Data too large: >16MB.\n");
		return;
	}
	result = DeviceWriteMEM(ctx, ctx->cfg->qwAddrMin, ctx->cfg->pbIn, (DWORD)ctx->cfg->cbIn, 0);
	if(!result) {
		printf("Memory Write: Failed. Write failed (partial memory may be written).\n");
		return;
	}
	printf("Memory Write: Successful.\n");
}