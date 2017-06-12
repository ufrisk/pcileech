// device.c : implementation related to the Xilinx SP605 dev board flashed with @d_olex early access bitstream. (UART communication).
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifdef WIN32

#include "device605.h"
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

#define ENDIAN_SWAP_DWORD(x)	(x = (x << 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x >> 24))

typedef struct tdDEVICE_CONTEXT_SP605_RXBUF {
	DWORD cbMax;
	DWORD cb;
	PBYTE pb;
} DEVICE_CONTEXT_SP605_RXBUF, *PDEVICE_CONTEXT_SP605_RXBUF;

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
	PDEVICE_CONTEXT_SP605_RXBUF pRxBuffer;
} DEVICE_CONTEXT_SP605, *PDEVICE_CONTEXT_SP605;

VOID Device605_RxTlp_Thread(PDEVICE_CONTEXT_SP605 ctx605);

//-------------------------------------------------------------------------------
// SP605 implementation below.
//-------------------------------------------------------------------------------

VOID Device605_Close(_Inout_ PPCILEECH_CONTEXT ctx)
{
	PDEVICE_CONTEXT_SP605 ctx605 = (PDEVICE_CONTEXT_SP605)ctx->hDevice;
	if(!ctx605) { return; }
	if(ctx605->hThreadRx) {
		ctx605->isTerminateThreadRx = TRUE;
		WaitForSingleObject(ctx605->hThreadRx, INFINITE);
	}
	if(ctx605->hRxBufferEvent) {
		WaitForSingleObject(ctx605->hRxBufferEvent, INFINITE);
		while(ctx605->pRxBuffer) { SwitchToThread(); }
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

HANDLE Device605_Open_COM(_In_ LPSTR szCOM)
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

WORD Device605_GetDeviceID(_In_ PDEVICE_CONTEXT_SP605 ctx605)
{
	DWORD dw, txrx[] = { 0x00000000, 0x00000000 };
	if(!WriteFile(ctx605->hCommCfg, txrx, sizeof(txrx), &dw, &ctx605->oCfg)) {
		if(ERROR_IO_PENDING != GetLastError()) { return 0; }
		if(WAIT_TIMEOUT == WaitForSingleObject(ctx605->oCfg.hEvent, SP605_COM_TIMEOUT)) { return 0; }
	}
	if(!ReadFile(ctx605->hCommCfg, txrx, sizeof(txrx), &dw, &ctx605->oCfg)) {
		if(ERROR_IO_PENDING != GetLastError()) { return 0; }
		if(WAIT_TIMEOUT == WaitForSingleObject(ctx605->oCfg.hEvent, SP605_COM_TIMEOUT)) { return 0; }
		if(!GetOverlappedResult(ctx605->hCommPcie, &ctx605->oCfg, &dw, FALSE)) { return 0; }
	}
	return (WORD)_byteswap_ulong(txrx[0]);
}

BOOL Device605_Open(_Inout_ PPCILEECH_CONTEXT ctx)
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
			ctx605->hCommPcie = Device605_Open_COM(szCOM);
		} else {
			ctx605->hCommCfg = Device605_Open_COM(szCOM);
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
	ctx605->wDeviceId = Device605_GetDeviceID(ctx605);
	if(!ctx605->wDeviceId) { goto fail; }
	ctx605->isPrintTlp = ctx->cfg->fVerboseExtra;
	ctx605->hThreadRx = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Device605_RxTlp_Thread, ctx605, 0, NULL); // start rx thread, must be last in open
	if(!ctx605->hThreadRx) { goto fail; }
	if(ctx->cfg->fVerbose) { printf("Device Info: SP605.\n"); }
	return TRUE;
fail:
	Device605_Close(ctx);
	return FALSE;
}

BOOL Device605_TxTlp(_In_ PDEVICE_CONTEXT_SP605 ctx605, _In_ PBYTE pbTlp, _In_ DWORD cbTlp)
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

VOID Device605_RxTlp(_In_ PDEVICE_CONTEXT_SP605 ctx605, _In_ PBYTE pb, _In_ DWORD cb)
{
	PTLP_HDR_CplD hdrC = (PTLP_HDR_CplD)pb;
	PTLP_HDR hdr = (PTLP_HDR)pb;
	PDWORD buf = (PDWORD)pb;
	PDEVICE_CONTEXT_SP605_RXBUF prxbuf;
	DWORD o, c;
	if(cb < 12) { return; }
	if(ctx605->isPrintTlp) {
		TLP_Print(pb, cb, FALSE);
	}
	buf[0] = _byteswap_ulong(buf[0]);
	if(cb < ((DWORD)hdr->Length << 2) - 12) { return; }
	if((hdr->TypeFmt == TLP_CplD) && ctx605->pRxBuffer) {
		buf[1] = _byteswap_ulong(buf[1]);
		buf[2] = _byteswap_ulong(buf[2]);
		// NB! read algorithm below only support reading full 4kB pages _or_
		//     partial page if starting at page boundry and read is less than 4kB.
		prxbuf = ctx605->pRxBuffer;
		o = (hdrC->Tag << 12) + min(0x1000, prxbuf->cbMax) - (hdrC->ByteCount ? hdrC->ByteCount : 0x1000);
		c = (DWORD)hdr->Length << 2;
		memcpy(prxbuf->pb + o, pb + 12, c);
		if(prxbuf->cbMax <= (DWORD)InterlockedAdd(&prxbuf->cb, c)) {
			SetEvent(ctx605->hRxBufferEvent);
		}
	}
}

VOID Device605_RxTlp_Thread(_In_ PDEVICE_CONTEXT_SP605 ctx605)
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
			Device605_RxTlp(ctx605, (PBYTE)dwTlp, cdwTlp << 2);
			cdwTlp = 0;
		}
		if(cdwTlp >= 1024) { goto fail; }
	}
fail:
	ctx605->isTerminateThreadRx = TRUE;
}

BOOL Device605_ReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
	PDEVICE_CONTEXT_SP605 ctx605 = (PDEVICE_CONTEXT_SP605)ctx->hDevice;
	DEVICE_CONTEXT_SP605_RXBUF rxbuf;
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
	ctx605->pRxBuffer = &rxbuf;
	ResetEvent(ctx605->hRxBufferEvent);
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
			hdrRd32->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
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
		Device605_TxTlp(ctx605, (PBYTE)tx, is32 ? 12 : 16);
	}
	// wait for result
	WaitForSingleObject(ctx605->hRxBufferEvent, SP605_READ_TIMEOUT);
	ctx605->pRxBuffer = NULL;
	SetEvent(ctx605->hRxBufferEvent);
	return rxbuf.cb >= rxbuf.cbMax;
}

BOOL Device605_WriteDMA_TXP(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwA, _In_ BYTE bFirstBE, _In_ BYTE bLastBE, _In_ PBYTE pb, _In_ DWORD cb)
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
	return Device605_TxTlp(ctx605, pbTlp, cbTlp);
}

BOOL Device605_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb)
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
		result = Device605_WriteDMA_TXP(ctx, qwA & ~0x3, be, 0, pbb, 4);
		pb += cbtx;
		cb -= cbtx;
		qwA += cbtx;
	}
	// TX as 128-byte packets (aligned to 128-byte boundaries)
	while(result && cb) {
		cbtx = min(128 - (qwA & 0x7f), cb);
		be = (cbtx & 0x3) ? (0xf >> (4 - (cbtx & 0x3))) : 0xf;
		result = (cbtx <= 4) ?
			Device605_WriteDMA_TXP(ctx, qwA, be, 0, pb, 4) :
			Device605_WriteDMA_TXP(ctx, qwA, 0xf, be, pb, cbtx);
		pb += cbtx;
		cb -= cbtx;
		qwA += cbtx;
	}
	return result;
}

VOID Action_Device605_TlpTx(_Inout_ PPCILEECH_CONTEXT ctx)
{
	if(ctx->cfg->tpDevice != PCILEECH_DEVICE_SP605) {
		printf("TLP: Failed. unsupported device.\n");
		return;
	}
	if(Device605_TxTlp((PDEVICE_CONTEXT_SP605)ctx->hDevice, ctx->cfg->pbIn, (DWORD)ctx->cfg->cbIn)) {
		printf("TLP: Success.\n");
		// If no custom exit timeout is set wait 500ms to receive any TLP responses.
		if(ctx->cfg->qwWaitBeforeExit == 0) {
			Sleep(500);
		}
	} else {
		printf("TLP: Failed. TX error.\n");
	}
}

#endif /* WIN32 */
#if defined(LINUX) || defined(ANDROID)

#include "device605.h"

BOOL Device605_Open(_Inout_ PPCILEECH_CONTEXT ctx)
{
	printf("SP605: Failed. Device only supported in PCILeech for Windows.");
	return FALSE;
}

VOID Device605_Close(_Inout_ PPCILEECH_CONTEXT ctx)
{
	return;
}

VOID Action_Device605_TlpTx(_Inout_ PPCILEECH_CONTEXT ctx)
{
	printf("TLP: Failed. Operation only supported in PCILeech for Windows.");
}

BOOL Device605_ReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
	return FALSE;
}

BOOL Device605_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
	return FALSE;
}

#endif /* LINUX || ANDROID */
