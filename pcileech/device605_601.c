// device605_601.c : implementation related to the Xilinx SP605 dev board flashed with bitstream for FTDI UMFT601X-B addon-board.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef WIN32

#include "device605_601.h"
#include "device.h"
#include "tlp.h"
#include "util.h"

//-------------------------------------------------------------------------------
// FPGA/SP605/FT601 defines below.
//-------------------------------------------------------------------------------

#define FPGA_CFG_RX_VALID				0x77000000
#define FPGA_CFG_RX_VALID_MASK			0xff070000
#define FPGA_CMD_RX_VALID				0x77020000
#define FPGA_CMD_RX_VALID_MASK			0xff070000

#define FPGA_TLP_RX_VALID				0x77030000
#define FPGA_TLP_RX_VALID_MASK			0xff030000
#define FPGA_TLP_RX_VALID_LAST			0x77070000
#define FPGA_TLP_RX_VALID_LAST_MASK		0xff070000

#define FPGA_TLP_TX_VALID				0x77030000
#define FPGA_TLP_TX_VALID_LAST			0x77070000
#define FPGA_LOOP_TX_VALID     			0x77010000

#define SP605_601_PROBE_MAXPAGES		0x400
#define SP601_601_MAX_SIZE_RX			0x001e000	// in data bytes (excl. overhead/TLP headers)
#define SP601_601_MAX_SIZE_TX			0x0002000   // in total data (incl. overhead/TLP headers)

#define ENDIAN_SWAP_WORD(x)		(x = (x << 8) | (x >> 8))
#define ENDIAN_SWAP_DWORD(x)	(x = (x << 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x >> 24))

typedef struct tdDEVICE_CONTEXT_SP605_601 {
	WORD wDeviceId;
	WORD wFpgaVersion;
	BOOL isPrintTlp;
	PTLP_CALLBACK_BUF_MRd pMRdBuffer;
	struct {
		PBYTE pb;
		DWORD cb;
		DWORD cbMax;
	} rxbuf;
	struct {
		PBYTE pb;
		DWORD cb;
		DWORD cbMax;
	} txbuf;
	struct {
		HMODULE hModule;
		HANDLE hFTDI;
		ULONG(*pfnFT_Create)(
			PVOID pvArg,
			DWORD dwFlags,
			HANDLE *pftHandle
		);
		ULONG(*pfnFT_Close)(
			HANDLE ftHandle
		);
		ULONG(*pfnFT_WritePipe)(
			HANDLE ftHandle,
			UCHAR ucPipeID,
			PUCHAR pucBuffer,
			ULONG ulBufferLength,
			PULONG pulBytesTransferred,
			LPOVERLAPPED pOverlapped
		);
		ULONG(*pfnFT_ReadPipe)(
			HANDLE ftHandle,
			UCHAR ucPipeID,
			PUCHAR pucBuffer,
			ULONG ulBufferLength,
			PULONG pulBytesTransferred,
			LPOVERLAPPED pOverlapped
		);
		ULONG(*pfnFT_AbortPipe)(
			HANDLE ftHandle,
			UCHAR ucPipeID
		);

	} dev;
	BOOL(*hRxTlpCallbackFn)(_Inout_ PTLP_CALLBACK_BUF_MRd pBufferMrd, _In_ PBYTE pb, _In_ DWORD cb, _In_opt_ HANDLE hEventCompleted);
	QWORD dbg_qwLastTx[8];
	DWORD dbg_cbLastTx;
} DEVICE_CONTEXT_SP605_601, *PDEVICE_CONTEXT_SP605_601;

//-------------------------------------------------------------------------------
// FPGA/SP605/FT601 implementation below.
//-------------------------------------------------------------------------------

VOID Device601_601_InitializeFTDI(_In_ PDEVICE_CONTEXT_SP605_601 ctx)
{
	DWORD status;
	// Load FTDI Library
	ctx->dev.hModule = LoadLibrary(L"FTD3XX.dll");
	if(!ctx->dev.hModule) { return; }
	ctx->dev.pfnFT_AbortPipe = (ULONG(*)(HANDLE, UCHAR))
		GetProcAddress(ctx->dev.hModule, "FT_AbortPipe");
	ctx->dev.pfnFT_Close = (ULONG(*)(HANDLE))
		GetProcAddress(ctx->dev.hModule, "FT_Close");
	ctx->dev.pfnFT_Create = (ULONG(*)(PVOID, DWORD, HANDLE*))
		GetProcAddress(ctx->dev.hModule, "FT_Create");
	ctx->dev.pfnFT_ReadPipe = (ULONG(*)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
		GetProcAddress(ctx->dev.hModule, "FT_ReadPipe");
	ctx->dev.pfnFT_WritePipe = (ULONG(*)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
		GetProcAddress(ctx->dev.hModule, "FT_WritePipe");
	// Open FTDI
	status = ctx->dev.pfnFT_Create(NULL, 0x10 /*FT_OPEN_BY_INDEX*/, &ctx->dev.hFTDI);
	if(status || !ctx->dev.hFTDI) { return; }
	ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x02);
	ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x82);
}

VOID Device605_601_Close(_Inout_ PPCILEECH_CONTEXT ctxPcileech)
{
	PDEVICE_CONTEXT_SP605_601 ctx = (PDEVICE_CONTEXT_SP605_601)ctxPcileech->hDevice;
	if(!ctx) { return; }
	if(ctx->dev.hFTDI) { ctx->dev.pfnFT_Close(ctx->dev.hFTDI); }
	if(ctx->dev.hModule) { FreeLibrary(ctx->dev.hModule); }
	if(ctx->rxbuf.pb) { LocalFree(ctx->rxbuf.pb); }
	if(ctx->txbuf.pb) { LocalFree(ctx->txbuf.pb); }
	LocalFree(ctx);
	ctxPcileech->hDevice = 0;
}

VOID Device605_601_GetDeviceID_FpgaVersion(_In_ PDEVICE_CONTEXT_SP605_601 ctx)
{
	DWORD status;
	DWORD cbTX, cbRX, i, dwStatus, dwData;
	PBYTE pbRX = LocalAlloc(0, 0x01000000);
	BYTE pbTX[24] = {
		// cfg read addr 0
		0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x77,
		// cmd msg: version
		0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x02, 0x77,
		// mirror msg -> at least something to read back -> no ft601 freeze.
		0xff, 0xee, 0xdd, 0xcc,  0x00, 0x00, 0x01, 0x77  
	};
	status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTX, 24, &cbTX, NULL);
	if(status) { goto fail; }
	status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, 0x01000000, &cbRX, NULL);
	if(status || cbRX < 16) { goto fail; }
	for(i = 0; i < cbRX - 7; i += 8) {
		dwData = *(PDWORD)(pbRX + i);
		dwStatus = *(PDWORD)(pbRX + i + 4);
		if(!ctx->wDeviceId && (FPGA_CFG_RX_VALID == (FPGA_CFG_RX_VALID_MASK & dwStatus))) {
			ctx->wDeviceId = dwStatus & 0xffff;
		}
		if(!ctx->wFpgaVersion && (FPGA_CMD_RX_VALID == (FPGA_CMD_RX_VALID_MASK & dwStatus))) {
			ctx->wFpgaVersion = dwData & 0xffff;
			ENDIAN_SWAP_WORD(ctx->wFpgaVersion);
		}
	}
fail:
	LocalFree(pbRX);
}

BOOL Device605_601_TxTlp(_In_ PDEVICE_CONTEXT_SP605_601 ctx, _In_ PBYTE pbTlp, _In_ DWORD cbTlp, BOOL fRdKeepalive, BOOL fFlush)
{
	DWORD status;
	PBYTE pbTx;
	DWORD i, cbTx, cbTxed = 0;
	if(cbTlp & 0x3) { return FALSE; }
	if(cbTlp > 2048) { return FALSE; }
	if(ctx->isPrintTlp) {
		TLP_Print(pbTlp, cbTlp, TRUE);
	}
	// prepare transmit buffer
	pbTx = ctx->txbuf.pb + ctx->txbuf.cb;
	cbTx = 2 * cbTlp;
	for(i = 0; i < cbTlp; i += 4) {
		*(PDWORD)(pbTx + (i << 1)) = *(PDWORD)(pbTlp + i);
		*(PDWORD)(pbTx + ((i << 1) + 4)) = FPGA_TLP_TX_VALID;
	} 
	if(cbTlp) {
		*(PDWORD)(pbTx + ((i << 1) - 4)) = FPGA_TLP_TX_VALID_LAST;
	}
	if(fRdKeepalive) {
		cbTx += 8;
		*(PDWORD)(pbTx + (i << 1)) = 0xffeeddcc;
		*(PDWORD)(pbTx + ((i << 1) + 4)) = FPGA_LOOP_TX_VALID;
	}
	ctx->txbuf.cb += cbTx;
	// transmit
	if((ctx->txbuf.cb > SP601_601_MAX_SIZE_TX) || (fFlush && ctx->txbuf.cb)) {
		status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, ctx->txbuf.pb, ctx->txbuf.cb, &cbTxed, NULL);
		ctx->txbuf.cb = 0;
		return (0 == status);
	}
	return TRUE;
}

#define TLP_RX_MAX_SIZE		1024
VOID Device605_601_RxTlpSynchronous(_In_ PDEVICE_CONTEXT_SP605_601 ctx)
{
	DWORD status;
	DWORD dwTlp, dwStatus;
	DWORD i, cdwTlp = 0;
	BYTE pbTlp[TLP_RX_MAX_SIZE];
	PDWORD pdwTlp = (PDWORD)pbTlp;
	PDWORD pdwRx = (PDWORD)ctx->rxbuf.pb;

	status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, ctx->rxbuf.pb, ctx->rxbuf.cbMax, &ctx->rxbuf.cb, NULL);
	if(status) {
		ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x82);
		return;
	}
	if(ctx->rxbuf.cb % 8) {
		printf("Device Info: SP605 / FT601: Bad read from device. Should not happen!\n");
		return;
	}
	for(i = 0; i < ctx->rxbuf.cb / sizeof(QWORD); i++) { // index in 64-bit (QWORD)
		dwTlp = pdwRx[i << 1];
		dwStatus = pdwRx[1 + (i << 1)];
		if(FPGA_TLP_RX_VALID == (FPGA_TLP_RX_VALID_MASK & dwStatus)) {
			pdwTlp[cdwTlp] = dwTlp;
			cdwTlp++;
			if(cdwTlp >= TLP_RX_MAX_SIZE / sizeof(DWORD)) { return; }
		}
		if(FPGA_TLP_RX_VALID_LAST == (FPGA_TLP_RX_VALID_LAST_MASK & dwStatus)) {
			if(cdwTlp >= 3) {
				if(ctx->isPrintTlp) {
					TLP_Print(pbTlp, cdwTlp << 2, FALSE);
				}
				if(ctx->hRxTlpCallbackFn) {
					ctx->hRxTlpCallbackFn(ctx->pMRdBuffer, pbTlp, cdwTlp << 2, NULL);
				}
			} else {
				printf("Device Info: SP605 / FT601: Bad PCIe TLP received! Should not happen!\n");
			}
			cdwTlp = 0;
		}
	}
}

BOOL Device605_601_ReadDMA(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
	PDEVICE_CONTEXT_SP605_601 ctx = (PDEVICE_CONTEXT_SP605_601)ctxPcileech->hDevice;
	TLP_CALLBACK_BUF_MRd rxbuf;
	DWORD tx[4], o, i;
	BOOL is32;
	PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
	PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
	if(cb > SP601_601_MAX_SIZE_RX) { return FALSE; }
	if(qwAddr % 0x1000) { return FALSE; }
	if((cb >= 0x1000) && (cb % 0x1000)) { return FALSE; }
	if((cb < 0x1000) && (cb % 0x8)) { return FALSE; }
	// prepare
	rxbuf.cb = 0;
	rxbuf.pb = pb;
	rxbuf.cbMax = cb;
	ctx->pMRdBuffer = &rxbuf;
	ctx->hRxTlpCallbackFn = TLP_CallbackMRd;
	// transmit TLPs
	for(o = 0; o < cb; o += 0x1000) {
		memset(tx, 0, 16);
		is32 = qwAddr + o < 0x100000000;
		if(is32) {
			hdrRd32->h.TypeFmt = TLP_MRd32;
			hdrRd32->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
			hdrRd32->RequesterID = ctx->wDeviceId;
			hdrRd32->Tag = (BYTE)(o >> 12);
			hdrRd32->FirstBE = 0xf;
			hdrRd32->LastBE = 0xf;
			hdrRd32->Address = (DWORD)(qwAddr + o);
		}
		else {
			hdrRd64->h.TypeFmt = TLP_MRd64;
			hdrRd64->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
			hdrRd64->RequesterID = ctx->wDeviceId;
			hdrRd64->Tag = (BYTE)(o >> 12);
			hdrRd64->FirstBE = 0xf;
			hdrRd64->LastBE = 0xf;
			hdrRd64->AddressHigh = (DWORD)((qwAddr + o) >> 32);
			hdrRd64->AddressLow = (DWORD)(qwAddr + o);
		}
		for(i = 0; i < 4; i++) {
			ENDIAN_SWAP_DWORD(tx[i]);
		}
		Device605_601_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, TRUE, (o % 0x8000 == 0x7000));
	}
	Device605_601_TxTlp(ctx, NULL, 0, TRUE, TRUE);
	usleep(300);
	Device605_601_RxTlpSynchronous(ctx);
	ctx->pMRdBuffer = NULL;
	return rxbuf.cb >= rxbuf.cbMax;
}

VOID Device605_601_ProbeDMA(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ QWORD qwAddr, _In_ DWORD cPages, _Out_ __bcount(cPages) PBYTE pbResultMap)
{
	DWORD i, j;
	PDEVICE_CONTEXT_SP605_601 ctx = (PDEVICE_CONTEXT_SP605_601)ctxPcileech->hDevice;
	TLP_CALLBACK_BUF_MRd bufMRd;
	DWORD tx[4];
	BOOL is32;
	PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
	PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
	// split probe into processing chunks if too large...
	while(cPages > SP605_601_PROBE_MAXPAGES) {
		Device605_601_ProbeDMA(ctxPcileech, qwAddr, SP605_601_PROBE_MAXPAGES, pbResultMap);
		cPages -= SP605_601_PROBE_MAXPAGES;
		pbResultMap += SP605_601_PROBE_MAXPAGES;
		qwAddr += SP605_601_PROBE_MAXPAGES << 12;
	}
	memset(pbResultMap, 0, cPages);
	// prepare
	bufMRd.cb = 0;
	bufMRd.pb = pbResultMap;
	bufMRd.cbMax = cPages;
	ctx->pMRdBuffer = &bufMRd;
	ctx->hRxTlpCallbackFn = TLP_CallbackMRdProbe;
	// transmit TLPs
	for(i = 0; i < cPages; i++) {
		memset(tx, 0, 16);
		is32 = qwAddr + (i << 12) < 0x100000000;
		if(is32) {
			hdrRd32->h.TypeFmt = TLP_MRd32;
			hdrRd32->h.Length = 1;
			hdrRd32->RequesterID = ctx->wDeviceId;
			hdrRd32->FirstBE = 0xf;
			hdrRd32->LastBE = 0;
			hdrRd32->Address = (DWORD)(qwAddr + (i << 12) + ((i & 0x1f) << 2)); // 5 low address bits coded into the dword read.
			hdrRd32->Tag = (BYTE)((i >> 5) & 0x1f); // 5 high address bits coded into tag.
		} else {
			hdrRd64->h.TypeFmt = TLP_MRd64;
			hdrRd64->h.Length = 1;
			hdrRd64->RequesterID = ctx->wDeviceId;
			hdrRd64->FirstBE = 0xf;
			hdrRd64->LastBE = 0;
			hdrRd64->AddressHigh = (DWORD)((qwAddr + (i << 12)) >> 32);
			hdrRd64->AddressLow = (DWORD)(qwAddr + (i << 12) + ((i & 0x1f) << 2)); // 5 low address bits coded into the dword read.
			hdrRd64->Tag = (BYTE)((i >> 5) & 0x1f); // 5 high address bits coded into tag.
		}
		for(j = 0; j < 4; j++) {
			ENDIAN_SWAP_DWORD(tx[j]);
		}
		Device605_601_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, (i % 24 == 0));
	}
	Device605_601_TxTlp(ctx, NULL, 0, TRUE, TRUE);
	usleep(300);
	Device605_601_RxTlpSynchronous(ctx);
	ctx->hRxTlpCallbackFn = NULL;
	ctx->pMRdBuffer = NULL;
}

// write max 128 byte packets.
BOOL Device605_601_WriteDMA_TXP(_Inout_ PDEVICE_CONTEXT_SP605_601 ctx, _In_ QWORD qwA, _In_ BYTE bFirstBE, _In_ BYTE bLastBE, _In_ PBYTE pb, _In_ DWORD cb)
{
	DWORD txbuf[36], i, cbTlp;
	PBYTE pbTlp = (PBYTE)txbuf;
	PTLP_HDR_MRdWr32 hdrWr32 = (PTLP_HDR_MRdWr32)txbuf;
	PTLP_HDR_MRdWr64 hdrWr64 = (PTLP_HDR_MRdWr64)txbuf;
	memset(pbTlp, 0, 16);
	if(qwA < 0x100000000) {
		hdrWr32->h.TypeFmt = TLP_MWr32;
		hdrWr32->h.Length = (WORD)(cb + 3) >> 2;
		hdrWr32->FirstBE = bFirstBE;
		hdrWr32->LastBE = bLastBE;
		hdrWr32->RequesterID = ctx->wDeviceId;
		hdrWr32->Address = (DWORD)qwA;
		for(i = 0; i < 3; i++) {
			ENDIAN_SWAP_DWORD(txbuf[i]);
		}
		memcpy(pbTlp + 12, pb, cb);
		cbTlp = (12 + cb + 3) & ~0x3;
	} else {
		hdrWr64->h.TypeFmt = TLP_MWr64;
		hdrWr64->h.Length = (WORD)(cb + 3) >> 2;
		hdrWr64->FirstBE = bFirstBE;
		hdrWr64->LastBE = bLastBE;
		hdrWr64->RequesterID = ctx->wDeviceId;
		hdrWr64->AddressHigh = (DWORD)(qwA >> 32);
		hdrWr64->AddressLow = (DWORD)qwA;
		for(i = 0; i < 4; i++) {
			ENDIAN_SWAP_DWORD(txbuf[i]);
		}
		memcpy(pbTlp + 16, pb, cb);
		cbTlp = (16 + cb + 3) & ~0x3;
	}
	return Device605_601_TxTlp(ctx, pbTlp, cbTlp, FALSE, FALSE);
}

BOOL Device605_601_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb)
{
	PDEVICE_CONTEXT_SP605_601 ctx = (PDEVICE_CONTEXT_SP605_601)ctxPcileech->hDevice;
	BOOL result = TRUE;
	BYTE be, pbb[4];
	DWORD cbtx;
	// TX 1st dword if not aligned
	if(cb && (qwA & 0x3)) {
		be = (cb < 3) ? (0xf >> (4 - cb)) : 0xf;
		be <<= qwA & 0x3;
		cbtx = min(cb, 4 - (qwA & 0x3));
		memcpy(pbb + (qwA & 0x3), pb, cbtx);
		result = Device605_601_WriteDMA_TXP(ctx, qwA & ~0x3, be, 0, pbb, 4);
		pb += cbtx;
		cb -= cbtx;
		qwA += cbtx;
	}
	// TX as 128-byte packets (aligned to 128-byte boundaries)
	while(result && cb) {
		cbtx = min(128 - (qwA & 0x7f), cb);
		be = (cbtx & 0x3) ? (0xf >> (4 - (cbtx & 0x3))) : 0xf;
		result = (cbtx <= 4) ?
			Device605_601_WriteDMA_TXP(ctx, qwA, be, 0, pb, 4) :
			Device605_601_WriteDMA_TXP(ctx, qwA, 0xf, be, pb, cbtx);
		pb += cbtx;
		cb -= cbtx;
		qwA += cbtx;
	}
	return Device605_601_TxTlp(ctx, NULL, 0, FALSE, TRUE) && result; // Flush and Return.
}

BOOL Device605_601_ListenTlp(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ DWORD dwTime)
{
	PDEVICE_CONTEXT_SP605_601 ctx = (PDEVICE_CONTEXT_SP605_601)ctxPcileech->hDevice;
	QWORD tmStart = GetTickCount64();
	while(GetTickCount64() - tmStart < dwTime) {
		Device605_601_TxTlp(ctx, NULL, 0, TRUE, TRUE);
		Sleep(10);
		Device605_601_RxTlpSynchronous(ctx);
	}
	return TRUE;
}

BOOL Device605_601_WriteTlp(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ PBYTE pbTlp, _In_ DWORD cbTlp)
{
	PDEVICE_CONTEXT_SP605_601 ctx = (PDEVICE_CONTEXT_SP605_601)ctxPcileech->hDevice;
	return Device605_601_TxTlp(ctx, pbTlp, cbTlp, FALSE, TRUE);
}

BOOL Device605_601_Open(_Inout_ PPCILEECH_CONTEXT ctxPcileech)
{
	PDEVICE_CONTEXT_SP605_601 ctx;
	ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_SP605_601));
	if(!ctx) { return FALSE; }
	ctxPcileech->hDevice = (HANDLE)ctx;
	Device601_601_InitializeFTDI(ctx);
	if(!ctx->dev.hModule && ctxPcileech->cfg->fVerbose) { printf("Device Info: SP605 / FT601: Could not load FTD3XX.dll.\n"); }
	if(!ctx->dev.hModule) { goto fail; }
	if(!ctx->dev.hFTDI && ctxPcileech->cfg->fVerbose) { printf("Device Info: SP605 / FT601: Could not connect to device.\n"); }
	if(!ctx->dev.hFTDI) { goto fail; }
	Device605_601_GetDeviceID_FpgaVersion(ctx);
	if(!ctx->wDeviceId) { goto fail; }
	ctx->rxbuf.cbMax = (DWORD)(2.3 * SP601_601_MAX_SIZE_RX);  // buffer size tuned to lowest possible (+margin) for performance.
	ctx->rxbuf.pb = LocalAlloc(0, ctx->rxbuf.cbMax);
	if(!ctx->rxbuf.pb) { goto fail; }
	ctx->txbuf.cbMax = SP601_601_MAX_SIZE_TX + 0x10000;
	ctx->txbuf.pb = LocalAlloc(0, ctx->txbuf.cbMax);
	if(!ctx->txbuf.pb) { goto fail; }
	ctx->isPrintTlp = ctxPcileech->cfg->fVerboseExtra;
	// set callback functions and fix up config
	ctxPcileech->cfg->dev.tp = PCILEECH_DEVICE_SP605_FT601;
	ctxPcileech->cfg->dev.qwMaxSizeDmaIo = SP601_601_MAX_SIZE_RX;
	ctxPcileech->cfg->dev.qwAddrMaxNative = 0x0000ffffffffffff;
	ctxPcileech->cfg->dev.fPartialPageReadSupported = TRUE;
	ctxPcileech->cfg->dev.pfnClose = Device605_601_Close;
	ctxPcileech->cfg->dev.pfnProbeDMA = Device605_601_ProbeDMA;
	ctxPcileech->cfg->dev.pfnReadDMA = Device605_601_ReadDMA;
	ctxPcileech->cfg->dev.pfnWriteDMA = Device605_601_WriteDMA;
	ctxPcileech->cfg->dev.pfnWriteTlp = Device605_601_WriteTlp;
	ctxPcileech->cfg->dev.pfnListenTlp = Device605_601_ListenTlp;
	// return
	if(ctxPcileech->cfg->fVerbose) { printf("Device Info: SP605 / FT601.\n"); }
	return TRUE;
fail:
	Device605_601_Close(ctxPcileech);
	return FALSE;
}

#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)

#include "device605_601.h"

BOOL Device605_601_Open(_Inout_ PPCILEECH_CONTEXT ctx)
{
	if(ctx->cfg->dev.tp == PCILEECH_DEVICE_SP605_UART) {
		printf("SP605 / FT601: Failed. Device currently only supported in PCILeech for Windows.");
	}
	return FALSE;
}

#endif /* LINUX || ANDROID */
