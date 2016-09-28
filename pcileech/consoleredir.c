// consoleredir.c : implementation related 'console redirect' functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "consoleredir.h"
#include "device.h"
#include "util.h"

// If console redirection is enabled separate buffers are allocated and is as
// follows below:
// page 2: Read/Write - input part (input to targeted console window)
//         0..n       = USERSHELL_BUFFER_IO struct
//         n+1..0xfff = input buffer
// page 3: Read/Write - output part (output from targeted console window)
//         0..n       = USERSHELL_BUFFER_IO struct
//         n+1..0xfff = output buffer
#define USERSHELL_BUFFER_IO_MAGIC 0x012651232dfef9521
#define USERSHELL_BUFFER_IO_SIZE 0x800
typedef struct tUSERSHELLBUFFERIO {
	QWORD qwMagic;
	QWORD cbRead;
	QWORD cbReadAck;
	QWORD qwDebug[10];
	BYTE  pb[];
} USERSHELL_BUFFER_IO, *PUSERSHELL_BUFFER_IO;

typedef struct tdCONSOLEREDIR_THREADDATA {
	PCONFIG pCfg;
	PDEVICE_DATA pDeviceData;
	PUSERSHELL_BUFFER_IO pInfoIS;
	PUSERSHELL_BUFFER_IO pInfoOS;
	BYTE pbDataISConsoleBuffer[4096];
	BYTE pbDataOSConsoleBuffer[4096];
} CONSOLEREDIR_THREADDATA, *PCONSOLEREDIR_THREADDATA;

// input buffer to targeted console (outgoing info)
// read from this console and send to targeted console
DWORD ConsoleRedirect_ThreadConsoleInput(PCONSOLEREDIR_THREADDATA pd)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD cbWrite, cbModulo, cbModuloAck;
	while(TRUE) {
		while(pd->pInfoOS->cbRead == pd->pInfoIS->cbReadAck) {
			Sleep(10);
			continue;
		}
		cbModulo = pd->pInfoOS->cbRead % USERSHELL_BUFFER_IO_SIZE;
		cbModuloAck = pd->pInfoIS->cbReadAck % USERSHELL_BUFFER_IO_SIZE;
		if(cbModuloAck < cbModulo) {
			WriteConsoleA(hConsole, pd->pInfoOS->pb + cbModuloAck, cbModulo - cbModuloAck, &cbWrite, NULL);
		}
		else {
			WriteConsoleA(hConsole, pd->pInfoOS->pb + cbModuloAck, USERSHELL_BUFFER_IO_SIZE - cbModuloAck, &cbWrite, NULL);
		}
		pd->pInfoIS->cbReadAck += cbWrite;
	}
}

DWORD ConsoleRedirect_ThreadConsoleOutput(PCONSOLEREDIR_THREADDATA pd)
{
	HANDLE hConsoleIn = GetStdHandle(STD_INPUT_HANDLE);
	DWORD cbRead;
	while(TRUE) {
		ReadConsoleA(hConsoleIn, pd->pInfoIS->pb + (pd->pInfoIS->cbRead % USERSHELL_BUFFER_IO_SIZE), 1, &cbRead, NULL);
		pd->pInfoIS->cbRead += cbRead;
		while(pd->pInfoIS->cbRead - pd->pInfoOS->cbReadAck >= USERSHELL_BUFFER_IO_SIZE) {
			Sleep(10);
		}
	}
}

VOID ActionConsoleRedirect(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ QWORD ConsoleBufferAddr_InputStream, _In_ QWORD ConsoleBufferAddr_OutputStream)
{
	BOOL result;
	PCONSOLEREDIR_THREADDATA pd = LocalAlloc(LMEM_ZEROINIT, sizeof(CONSOLEREDIR_THREADDATA));
	if(!pd) { return; }
	pd->pCfg = pCfg;
	pd->pDeviceData = pDeviceData;
	pd->pInfoIS = (PUSERSHELL_BUFFER_IO)pd->pbDataISConsoleBuffer;
	pd->pInfoOS = (PUSERSHELL_BUFFER_IO)pd->pbDataOSConsoleBuffer;
	// read initial buffer and check validity
	Sleep(250);
	result = DeviceReadMEM(pDeviceData, ConsoleBufferAddr_OutputStream, pd->pbDataOSConsoleBuffer, 0x1000, 0);
	if(pd->pInfoOS->qwMagic != USERSHELL_BUFFER_IO_MAGIC) {
		printf("\nCONSOLE_REDIRECT: Error: Adress 0x%016llX does not contain a valid console buffer.\n", ConsoleBufferAddr_OutputStream);
		return;
	}
	// create worker threads
	CreateThread(NULL, 0, ConsoleRedirect_ThreadConsoleInput, pd, 0, NULL);
	CreateThread(NULL, 0, ConsoleRedirect_ThreadConsoleOutput, pd, 0, NULL);
	// buffer syncer
	while(TRUE) {
		result = DeviceReadMEM(pDeviceData, ConsoleBufferAddr_OutputStream, pd->pbDataOSConsoleBuffer, 0x1000, 0);
		if(!result || pd->pInfoOS->qwMagic != USERSHELL_BUFFER_IO_MAGIC) {
			printf("\nCONSOLE_REDIRECT: Error: Adress 0x%016llX does not contain a valid console buffer.\n", ConsoleBufferAddr_OutputStream);
			return;
		}
		DeviceWriteMEM(pDeviceData, ConsoleBufferAddr_InputStream, pd->pbDataISConsoleBuffer, 0x1000, 0);
	}
}