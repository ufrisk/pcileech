// device605_uart.c : implementation related to the Xilinx SP605 dev board flashed with @d_olex early access bitstream. (UART communication).
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef WIN32

#include "device605_uart.h"
#include "device.h"
#include "tlp.h"

//-------------------------------------------------------------------------------
// SP605 defines below.
//-------------------------------------------------------------------------------

#define COM_PORT_CFG				"COM4"
#define COM_PORT_PCIE				"COM3"
#define SP605_STATUS_TX_CONT		0x000000c0	
#define SP605_STATUS_TX_END			0x010000c0
#define SP605_STATUS_MASK_VALID		0x00000080
#define SP605_STATUS_MASK_END		0x01000000
#define SP605_COM_TIMEOUT			100			// milliseconds
#define SP605_READ_TIMEOUT			500			// milliseconds
#define SP605_PROBE_TIMEOUT			350			// milliseconds
#define SP605_PROBE_MAXPAGES		1024

#define ENDIAN_SWAP_DWORD(x)	(x = (x << 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x >> 24))

typedef struct tdDEVICE_CONTEXT_SP605 {
	HANDLE hCommCfg;
	HANDLE hCommPcie;
	HANDLE hThreadRx;
	WORD wDeviceId;
	BOOL isTerminateThreadRx;
	BOOL isPrintTlp;
	OVERLAPPED oTx;
	OVERLAPPED oRx;
	OVERLAPPED oCfg;
	HANDLE hRxBufferEvent;
	PTLP_CALLBACK_BUF_MRd pMRdBuffer;
	BOOL(*hRxTlpCallbackFn)(_Inout_ PTLP_CALLBACK_BUF_MRd pBufferMrd, _In_ PBYTE pb, _In_ DWORD cb, _In_opt_ HANDLE hEventCompleted);
} DEVICE_CONTEXT_SP605, *PDEVICE_CONTEXT_SP605;

//-------------------------------------------------------------------------------
// SP605 implementation below.
//-------------------------------------------------------------------------------

VOID Device605_UART_Close(_Inout_ PPCILEECH_CONTEXT ctx)
{
	PDEVICE_CONTEXT_SP605 ctx605 = (PDEVICE_CONTEXT_SP605)ctx->hDevice;
	if(!ctx605) { return; }
	if(ctx605->hThreadRx) {
		ctx605->isTerminateThreadRx = TRUE;
		WaitForSingleObject(ctx605->hThreadRx, INFINITE);
	}
	if(ctx605->hRxBufferEvent) {
		WaitForSingleObject(ctx605->hRxBufferEvent, INFINITE);
		while(ctx605->pMRdBuffer) { SwitchToThread(); }
		CloseHandle(ctx605->hRxBufferEvent);
	}
	if(ctx605->hCommCfg) { CloseHandle(ctx605->hCommCfg); }
	if(ctx605->hCommPcie) { CloseHandle(ctx605->hCommPcie); }
	if(ctx605->oTx.hEvent) { CloseHandle(ctx605->oTx.hEvent); };
	if(ctx605->oRx.hEvent) { CloseHandle(ctx605->oRx.hEvent); };
	if(ctx605->oCfg.hEvent) { CloseHandle(ctx605->oCfg.hEvent); };
	LocalFree(ctx605);
	ctx->hDevice = 0;
}

HANDLE Device605_UART_Open_COM(_In_ LPSTR szCOM)
{
	DCB dcb = { 0 };
	HANDLE hComm;
	dcb.DCBlength = sizeof(DCB);
	if(!BuildCommDCBW(L"921600,n,8,1", &dcb)) { return 0; }
	hComm = CreateFileA(szCOM, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);
	if(hComm == INVALID_HANDLE_VALUE) { return 0; }
	if(!SetCommState(hComm, &dcb)) {
		CloseHandle(hComm);
		return 0;
	}
	return hComm;
}

WORD Device605_UART_GetDeviceID(_In_ PDEVICE_CONTEXT_SP605 ctx605)
{
	DWORD dw, txrx[] = { 0x00000000, 0x00000000 };
	if(!WriteFile(ctx605->hCommCfg, txrx, sizeof(txrx), &dw, &ctx605->oCfg)) {
		if(ERROR_IO_PENDING != GetLastError()) { return 0; }
		if(WAIT_TIMEOUT == WaitForSingleObject(ctx605->oCfg.hEvent, SP605_COM_TIMEOUT)) { return 0; }
	}
	if(!ReadFile(ctx605->hCommCfg, txrx, sizeof(txrx), &dw, &ctx605->oCfg)) {
		if(ERROR_IO_PENDING != GetLastError()) { return 0; }
		if(WAIT_TIMEOUT == WaitForSingleObject(ctx605->oCfg.hEvent, SP605_COM_TIMEOUT)) { return 0; }
		if(!GetOverlappedResult(ctx605->hCommCfg, &ctx605->oCfg, &dw, FALSE)) { return 0; }
	}
	return (WORD)_byteswap_ulong(txrx[0]);
}

BOOL Device605_UART_TxTlp(_In_ PDEVICE_CONTEXT_SP605 ctx605, _In_ PBYTE pbTlp, _In_ DWORD cbTlp)
{
	DWORD pdwTx[1024], cTx, i, dwTxed;
	if(!cbTlp) { return TRUE; }
	if((cbTlp & 0x3) || (cbTlp > 2048)) { return FALSE; }
	if(ctx605->isPrintTlp) {
		TLP_Print(pbTlp, cbTlp, TRUE);
	}
	// prepare transmit buffer
	cTx = cbTlp >> 1;
	for(i = 0; i < cTx; i += 2) {
		pdwTx[i] = SP605_STATUS_TX_CONT;
		pdwTx[i + 1] = *(PDWORD)(pbTlp + (i << 1));
	}
	pdwTx[cTx - 2] = SP605_STATUS_TX_END;
	// transmit
	return
		WriteFile(ctx605->hCommPcie, pdwTx, cTx << 2, &dwTxed, &ctx605->oTx) ||
		(GetLastError() == ERROR_IO_PENDING && GetOverlappedResult(ctx605->hCommPcie, &ctx605->oTx, &dwTxed, TRUE));
}

VOID Device605_UART_RxTlp_Thread(_In_ PDEVICE_CONTEXT_SP605 ctx605)
{
	DWORD rx[2], dwTlp[1024], cbRead, dwResult, cdwTlp = 0;
	while(!ctx605->isTerminateThreadRx) {
		if(!ReadFile(ctx605->hCommPcie, rx, 2 * sizeof(DWORD), &cbRead, &ctx605->oRx)) {
			if(GetLastError() != ERROR_IO_PENDING) { goto fail; }
			while(TRUE) {
				dwResult = WaitForSingleObject(ctx605->oRx.hEvent, SP605_COM_TIMEOUT);
				if(ctx605->isTerminateThreadRx) { goto fail; }
				if(dwResult == WAIT_OBJECT_0) { break; }
				if(dwResult == WAIT_TIMEOUT) { continue; }
				ctx605->isTerminateThreadRx = TRUE;
				return;
			}
			if(!GetOverlappedResult(ctx605->hCommPcie, &ctx605->oRx, &cbRead, FALSE)) { goto fail; }
		}
		if(!(rx[0] & SP605_STATUS_MASK_VALID)) { goto fail; }
		dwTlp[cdwTlp] = rx[1];
		cdwTlp++;
		if(rx[0] & SP605_STATUS_MASK_END) {
			if(cdwTlp >= 3) {
				if(ctx605->isPrintTlp) {
					TLP_Print((PBYTE)dwTlp, cdwTlp << 2, FALSE);
				}
				if(ctx605->hRxTlpCallbackFn && ctx605->pMRdBuffer) {
					ctx605->hRxTlpCallbackFn(ctx605->pMRdBuffer, (PBYTE)dwTlp, cdwTlp << 2, ctx605->hRxBufferEvent);
				}
			}
			cdwTlp = 0;
		}
		if(cdwTlp >= 1024) { goto fail; }
	}
fail:
	ctx605->isTerminateThreadRx = TRUE;
}

BOOL Device605_UART_ReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
	PDEVICE_CONTEXT_SP605 ctx605 = (PDEVICE_CONTEXT_SP605)ctx->hDevice;
	TLP_CALLBACK_BUF_MRd rxbuf;
	DWORD tx[4], o, i;
	BOOL is32;
	PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
	PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
	if(cb > 0x00004000) { return FALSE; }
	if(qwAddr % 0x1000) { return FALSE; }
	if((cb >= 0x1000) && (cb % 0x1000)) { return FALSE; }
	if((cb < 0x1000) && (cb % 0x8)) { return FALSE; }
	// prepare
	rxbuf.cb = 0;
	rxbuf.pb = pb;
	rxbuf.cbMax = cb;
	ctx605->pMRdBuffer = &rxbuf;
	ResetEvent(ctx605->hRxBufferEvent);
	ctx605->hRxTlpCallbackFn = TLP_CallbackMRd;
	// transmit TLPs
	for(o = 0; o < cb; o += 0x1000) {
		memset(tx, 0, 16);
		is32 = qwAddr + o < 0x100000000;
		if(is32) {
			hdrRd32->h.TypeFmt = TLP_MRd32;
			hdrRd32->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
			hdrRd32->RequesterID = ctx605->wDeviceId;
			hdrRd32->Tag = (BYTE)(o >> 12);
			hdrRd32->FirstBE = 0xf;
			hdrRd32->LastBE = 0xf;
			hdrRd32->Address = (DWORD)(qwAddr + o);
		} else {
			hdrRd64->h.TypeFmt = TLP_MRd64;
			hdrRd64->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
			hdrRd64->RequesterID = ctx605->wDeviceId;
			hdrRd64->Tag = (BYTE)(o >> 12);
			hdrRd64->FirstBE = 0xf;
			hdrRd64->LastBE = 0xf;
			hdrRd64->AddressHigh = (DWORD)((qwAddr + o) >> 32);
			hdrRd64->AddressLow = (DWORD)(qwAddr + o);
		}
		for(i = 0; i < 4; i++) {
			ENDIAN_SWAP_DWORD(tx[i]);
		}
		Device605_UART_TxTlp(ctx605, (PBYTE)tx, is32 ? 12 : 16);
	}
	// wait for result
	WaitForSingleObject(ctx605->hRxBufferEvent, SP605_READ_TIMEOUT);
	ctx605->hRxTlpCallbackFn = NULL;
	ctx605->pMRdBuffer = NULL;
	SetEvent(ctx605->hRxBufferEvent);
	return rxbuf.cb >= rxbuf.cbMax;
}

VOID Device605_UART_ProbeDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ DWORD cPages, _Out_ __bcount(cPages) PBYTE pbResultMap)
{
	DWORD i, j;
	PDEVICE_CONTEXT_SP605 ctx605 = (PDEVICE_CONTEXT_SP605)ctx->hDevice;
	TLP_CALLBACK_BUF_MRd rxbuf;
	DWORD tx[4];
	BOOL is32;
	PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
	PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
	// split probe into processing chunks if too large...
	while(cPages > SP605_PROBE_MAXPAGES) {
		Device605_UART_ProbeDMA(ctx, qwAddr, SP605_PROBE_MAXPAGES, pbResultMap);
		cPages -= SP605_PROBE_MAXPAGES;
		pbResultMap += SP605_PROBE_MAXPAGES;
		qwAddr += SP605_PROBE_MAXPAGES << 12;
	}
	memset(pbResultMap, 0, cPages);
	// prepare
	rxbuf.cb = 0;
	rxbuf.pb = pbResultMap;
	rxbuf.cbMax = cPages;
	ctx605->pMRdBuffer = &rxbuf;
	ResetEvent(ctx605->hRxBufferEvent);
	ctx605->hRxTlpCallbackFn = TLP_CallbackMRdProbe;
	// transmit TLPs
	for(i = 0; i < cPages; i++) {
		memset(tx, 0, 16);
		is32 = qwAddr + (i << 12) < 0x100000000;
		if(is32) {
			hdrRd32->h.TypeFmt = TLP_MRd32;
			hdrRd32->h.Length = 1;
			hdrRd32->RequesterID = ctx605->wDeviceId;
			hdrRd32->FirstBE = 0xf;
			hdrRd32->LastBE = 0;
			hdrRd32->Address = (DWORD)(qwAddr + (i << 12) + ((i & 0x1f) << 2)); // 5 low address bits coded into the dword read.
			hdrRd32->Tag = (BYTE)((i >> 5) & 0x1f); // 5 high address bits coded into tag.
		} else {
			hdrRd64->h.TypeFmt = TLP_MRd64;
			hdrRd64->h.Length = 1;
			hdrRd64->RequesterID = ctx605->wDeviceId;
			hdrRd64->FirstBE = 0xf;
			hdrRd64->LastBE = 0;
			hdrRd64->AddressHigh = (DWORD)((qwAddr + (i << 12)) >> 32);
			hdrRd64->AddressLow = (DWORD)(qwAddr + (i << 12) + ((i & 0x1f) << 2)); // 5 low address bits coded into the dword read.
			hdrRd64->Tag = (BYTE)((i >> 5) & 0x1f); // 5 high address bits coded into tag.
		}
		for(j = 0; j < 4; j++) {
			ENDIAN_SWAP_DWORD(tx[j]);
		}
		Device605_UART_TxTlp(ctx605, (PBYTE)tx, is32 ? 12 : 16);
	}
	// wait for result
	WaitForSingleObject(ctx605->hRxBufferEvent, SP605_PROBE_TIMEOUT);
	ctx605->hRxTlpCallbackFn = NULL;
	ctx605->pMRdBuffer = NULL;
	SetEvent(ctx605->hRxBufferEvent);
}

BOOL Device605_UART_WriteDMA_TXP(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwA, _In_ BYTE bFirstBE, _In_ BYTE bLastBE, _In_ PBYTE pb, _In_ DWORD cb)
{
	PDEVICE_CONTEXT_SP605 ctx605 = (PDEVICE_CONTEXT_SP605)ctx->hDevice;
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
		hdrWr32->RequesterID = ctx605->wDeviceId;
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
		hdrWr64->RequesterID = ctx605->wDeviceId;
		hdrWr64->AddressHigh = (DWORD)(qwA >> 32);
		hdrWr64->AddressLow = (DWORD)qwA;
		for(i = 0; i < 4; i++) {
			ENDIAN_SWAP_DWORD(txbuf[i]);
		}
		memcpy(pbTlp + 16, pb, cb);
		cbTlp = (16 + cb + 3) & ~0x3;
	}
	return Device605_UART_TxTlp(ctx605, pbTlp, cbTlp);
}

BOOL Device605_UART_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb)
{
	BOOL result = TRUE;
	BYTE be, pbb[4];
	DWORD cbtx;
	if(cb > 0x00004000) { return FALSE; }
	// TX 1st dword if not aligned
	if(cb && (qwA & 0x3)) {
		be = (cb < 3) ? (0xf >> (4 - cb)) : 0xf;
		be <<= qwA & 0x3;
		cbtx = min(cb, 4 - (qwA & 0x3));
		memcpy(pbb + (qwA & 0x3), pb, cbtx);
		result = Device605_UART_WriteDMA_TXP(ctx, qwA & ~0x3, be, 0, pbb, 4);
		pb += cbtx;
		cb -= cbtx;
		qwA += cbtx;
	}
	// TX as 128-byte packets (aligned to 128-byte boundaries)
	while(result && cb) {
		cbtx = min(128 - (qwA & 0x7f), cb);
		be = (cbtx & 0x3) ? (0xf >> (4 - (cbtx & 0x3))) : 0xf;
		result = (cbtx <= 4) ?
			Device605_UART_WriteDMA_TXP(ctx, qwA, be, 0, pb, 4) :
			Device605_UART_WriteDMA_TXP(ctx, qwA, 0xf, be, pb, cbtx);
		pb += cbtx;
		cb -= cbtx;
		qwA += cbtx;
	}
	return result;
}

BOOL Device605_UART_ListenTlp(_Inout_ PPCILEECH_CONTEXT ctx, _In_ DWORD dwTime)
{
	Sleep(dwTime);
	return TRUE;
}

BOOL Device605_UART_WriteTlp(_Inout_ PPCILEECH_CONTEXT ctx, _In_ PBYTE pbTlp, _In_ DWORD cbTlp)
{
	return Device605_UART_TxTlp((PDEVICE_CONTEXT_SP605)ctx->hDevice, pbTlp, cbTlp);
}

BOOL Device605_UART_Open(_Inout_ PPCILEECH_CONTEXT ctx)
{
	DWORD i;
	CHAR szCOM[] = { 'C', 'O', 'M', 'x', 0 };
	PDEVICE_CONTEXT_SP605 ctx605;
	ctx605 = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_SP605));
	if(!ctx605) { return FALSE; }
	ctx->hDevice = (HANDLE)ctx605;
	// open COM ports
	for(i = 1; i <= 9; i++) {
		szCOM[3] = (CHAR)('0' + i);
		if(!ctx605->hCommPcie) {
			ctx605->hCommPcie = Device605_UART_Open_COM(szCOM);
		} else {
			ctx605->hCommCfg = Device605_UART_Open_COM(szCOM);
			if(ctx605->hCommCfg) { break; }
		}
	}
	if(!ctx605->hCommPcie || !ctx605->hCommCfg) { goto fail; }
	SetupComm(ctx605->hCommPcie, 0x8000, 0x8000);
	ctx605->oTx.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!ctx605->oTx.hEvent) { goto fail; }
	ctx605->oRx.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!ctx605->oRx.hEvent) { goto fail; }
	ctx605->oCfg.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(!ctx605->oCfg.hEvent) { goto fail; }
	ctx605->hRxBufferEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
	if(!ctx605->hRxBufferEvent) { goto fail; }
	ctx605->wDeviceId = Device605_UART_GetDeviceID(ctx605);
	if(!ctx605->wDeviceId) { goto fail; }
	ctx605->isPrintTlp = ctx->cfg->fVerboseExtra;
	ctx605->hThreadRx = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Device605_UART_RxTlp_Thread, ctx605, 0, NULL); // start rx thread, must be last in open
	if(!ctx605->hThreadRx) { goto fail; }
	// set callback functions and fix up config
	ctx->cfg->dev.tp = PCILEECH_DEVICE_SP605_UART;
	ctx->cfg->dev.qwMaxSizeDmaIo = 0x4000;
	ctx->cfg->dev.qwAddrMaxNative = 0x0000ffffffffffff;
	ctx->cfg->dev.fPartialPageReadSupported = TRUE;
	ctx->cfg->dev.pfnClose = Device605_UART_Close;
	ctx->cfg->dev.pfnProbeDMA = Device605_UART_ProbeDMA;
	ctx->cfg->dev.pfnReadDMA = Device605_UART_ReadDMA;
	ctx->cfg->dev.pfnWriteDMA = Device605_UART_WriteDMA;
	ctx->cfg->dev.pfnWriteTlp = Device605_UART_WriteTlp;
	ctx->cfg->dev.pfnListenTlp = Device605_UART_ListenTlp;
	// return
	if(ctx->cfg->fVerbose) { printf("Device Info: SP605 / UART.\n"); }
	return TRUE;
fail:
	Device605_UART_Close(ctx);
	return FALSE;
}

#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)

#include "device605_uart.h"

BOOL Device605_UART_Open(_Inout_ PPCILEECH_CONTEXT ctx)
{
	if(ctx->cfg->dev.tp == PCILEECH_DEVICE_SP605_UART) {
		printf("SP605 / UART: Failed. Device currently only supported in PCILeech for Windows.");
	}
	return FALSE;
}

#endif /* LINUX || ANDROID */
