// memdump.c : implementation related to memory dumping functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "memdump.h"
#include "device.h"
#include "util.h"

typedef struct tdFILE_WRITE_ASYNC_BUFFER {
	HANDLE hFile;
	BOOL isSuccess;
	BOOL isExecuting;
	DWORD cb;
	BYTE pb[0x01000000]; // 16MB Data Buffer
} FILE_WRITE_ASYNC_BUFFER, *PFILE_WRITE_ASYNC_BUFFER;

VOID MemoryDump_FileWriteAsync_Thread(PFILE_WRITE_ASYNC_BUFFER pfb)
{
	DWORD cbWritten;
	pfb->isSuccess = WriteFile(pfb->hFile, pfb->pb, pfb->cb, &cbWritten, NULL);
	pfb->isExecuting = FALSE;
}

VOID MemoryDump_SetOutFileName(_Inout_ PCONFIG pCfg)
{
	SYSTEMTIME st;
	if(pCfg->szFileOut[0] == 0) {
		GetLocalTime(&st);
		_snprintf_s(
			pCfg->szFileOut,
			MAX_PATH,
			_TRUNCATE,
			"pcileech-%x-%llx-%i%02i%02i-%02i%02i%02i.raw",
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

VOID ActionMemoryDump(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	PBYTE pbMemoryDump;
	QWORD qwCurrentAddress;
	BOOL result;
	PAGE_STATISTICS pageStat;
	PFILE_WRITE_ASYNC_BUFFER pFileBuffer;
	// 1: Initialize
	MemoryDump_SetOutFileName(pCfg);
	pFileBuffer = LocalAlloc(LMEM_ZEROINIT, sizeof(FILE_WRITE_ASYNC_BUFFER));
	pbMemoryDump = LocalAlloc(0, 0x01000000); // 16MB Data Buffer
	if(!pbMemoryDump || !pFileBuffer) {
		printf("Memory Dump: Failed. Failed to allocate memory buffers.\n");
		return;
	}
	pFileBuffer->hFile = CreateFileA(pCfg->szFileOut, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if(!pFileBuffer->hFile || pFileBuffer->hFile == INVALID_HANDLE_VALUE) {
		printf("Memory Dump: Failed. Error writing to file.\n");
		return;
	}
	pFileBuffer->isSuccess = TRUE;
	memset(&pageStat, 0, sizeof(PAGE_STATISTICS));
	pageStat.cPageTotal = (DWORD)((pCfg->qwAddrMax - pCfg->qwAddrMin + 1) / 4096);
	pageStat.isAccessModeKMD = pDeviceData->KMDHandle ? TRUE : FALSE;
	pageStat.szCurrentAction = "Dumping Memory";
	pageStat.qwTickCountStart = GetTickCount64();
	pCfg->qwAddrMin &= ~0xfff;
	pCfg->qwAddrMax = (pCfg->qwAddrMax + 1) & ~0xfff;
	// 2: start dump in 16MB blocks
	qwCurrentAddress = pCfg->qwAddrMin;
	while(qwCurrentAddress < pCfg->qwAddrMax) {
		result = Util_Read16M(pCfg, pDeviceData, pbMemoryDump, qwCurrentAddress, &pageStat);
		ShowUpdatePageRead(pCfg, qwCurrentAddress, &pageStat);
		if(!result) {
			printf("Memory Dump: Failed. Cannot dump any sequential data in 16MB - terminating.\n");
			goto cleanup;
		}
		// write file async
		if(!pFileBuffer->isSuccess) {
			printf("Memory Dump: Failed. Failed to write to dump file - terminating.\n");
			goto cleanup;
		}
		while(pFileBuffer->isExecuting) {
			Sleep(0);
		}
		pFileBuffer->cb = (DWORD)min(0x01000000, pCfg->qwAddrMax - qwCurrentAddress);
		memcpy(pFileBuffer->pb, pbMemoryDump, 0x01000000);
		pFileBuffer->isExecuting = TRUE;
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MemoryDump_FileWriteAsync_Thread, pFileBuffer, 0, NULL);
		// add to address
		qwCurrentAddress += 0x01000000;
	}
	printf("Memory Dump: Successful.\n");
cleanup:
	if(pbMemoryDump) { 
		LocalFree(pbMemoryDump);
	}
	if(pFileBuffer) {
		if(pFileBuffer->hFile) { 
			while(pFileBuffer->isExecuting) {
				Sleep(0);
			}
			CloseHandle(pFileBuffer->hFile);
		}
		LocalFree(pFileBuffer);
	}
}

VOID ActionMemoryPageDisplay(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	BYTE pb[4096];
	CHAR ch[0x8000];
	DWORD cch = 0x8000;
	QWORD qwAddr = pCfg->qwAddrMin & 0x0fffffffffffff000;
	BOOL result;
	printf("Memory Page Read: Page contents for address: 0x%016llX\n", qwAddr);
	result = DeviceReadMEM(pDeviceData, qwAddr, pb, 4096, 0);
	if(!result) {
		result = DeviceReadMEM(pDeviceData, qwAddr, pb, 4096, 0);
	}
	if(!result) {
		printf("Memory Page Read: Failed.\n");
		return;
	}
	CryptBinaryToStringA(pb, 4096, CRYPT_STRING_HEXASCIIADDR, ch, &cch);
	printf("%s\n", ch);
}

VOID ActionMemoryTestReadWrite(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	BYTE pb1[4096], pb2[4096], pb3[4096];
	DWORD dwAddrPci32 = (DWORD)(pCfg->qwAddrMin & 0xfffff000);
	DWORD i, dwOffset, dwRuns = 1000;
	BOOL r1, r2;
	if(pDeviceData->KMDHandle) {
		printf("Memory Test Read: Failed. Memory test may not run in KMD mode.\n");
		return;
	}
	DeviceReadDMA(pDeviceData, dwAddrPci32, pb1, 4096, 0);
	// READ DMA
	printf("Memory Test Read: starting, reading %i times from address: 0x%08x\n", dwRuns, dwAddrPci32);
	DeviceReadDMA(pDeviceData, dwAddrPci32, pb1, 4096, 0);
	for(i = 0; i < dwRuns; i++) {
		r1 = DeviceReadDMA(pDeviceData, dwAddrPci32, pb2, 4096, 0);
		if(!r1 || (dwOffset = Util_memcmpEx(pb1, pb2, 4096))) {
			printf("Memory Test Read: Failed. DMA failed / data changed by target computer / memory corruption. Read: %i. Run: %i. Offset: 0x%03x\n", r1, i, (r1 ? --dwOffset : 0));
			return;
		}
	}
	// WRITE DMA
	printf("Memory Test Read: SUCCESS!\n");
	if(pCfg->tpAction == TESTMEMREADWRITE) {
		dwRuns = 100;
		printf("Memory Test Write: starting, reading/writing %i times from address: 0x%08x\n", dwRuns, dwAddrPci32);
		for(i = 0; i < dwRuns; i++) {
			Util_GenRandom(pb3, 4096);
			r1 = DeviceWriteDMA(pDeviceData, dwAddrPci32, pb3, 4096, 0);
			r2 = DeviceReadDMA(pDeviceData, dwAddrPci32, pb2, 4096, 0);
			if(!r1 || !r2 || (dwOffset = Util_memcmpEx(pb2, pb3, 4096))) {
				DeviceWriteDMA(pDeviceData, dwAddrPci32, pb1, 4096, 0);
				printf("Memory Test Write: Failed. DMA failed / data changed by target computer / memory corruption. Write: %i. Read: %i. Run: %i. Offset: 0x%03x\n", r1, r2, i, --dwOffset);
				return;
			}
		}
		DeviceWriteDMA(pDeviceData, dwAddrPci32, pb1, 4096, 0);
		printf("Memory Test Write: Success!\n");
	}
}

VOID ActionMemoryWrite(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	BOOL result;
	if(pCfg->cbIn == 0) {
		printf("Memory Write: Failed. No data to write.\n");
		return;
	}
	if(pCfg->cbIn >= 0x01000000) {
		printf("Memory Write: Failed. Data too large: >16MB.\n");
		return;
	}
	result = DeviceWriteMEM(pDeviceData, pCfg->qwAddrMin, pCfg->pbIn, (DWORD)pCfg->cbIn, 0);
	if(!result) {
		printf("Memory Write: Failed. Write failed (partial memory may be written).\n");
		return;
	}
	printf("Memory Write: Successful.\n");
}