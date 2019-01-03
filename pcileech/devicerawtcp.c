// devicerawtcp.c : implementation related to dummy device backed by a TCP service.
//

#ifdef WIN32

#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOCKET int

#define closesocket(_s_) close((_s_))

#define INVALID_SOCKET	-1
#define SOCKET_ERROR	-1

#endif

#ifdef WIN32
#include <PshPack1.h>
#endif

#ifdef WIN32
#include <PopPack.h>
#endif

#include "devicerawtcp.h"
#include "device.h"
#include "util.h"

#define RAWTCP_MAX_SIZE_RX 0x1000000
#define RAWTCP_MAX_SIZE_TX 0x100000

#define DEFAULT_PORT 8888

typedef struct tdDEVICE_CONTEXT_RAWTCP {
	SOCKET Sock;
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
} DEVICE_CONTEXT_RAWTCP, *PDEVICE_CONTEXT_RAWTCP;

typedef struct tdRAWTCP_PROTO_PACKET {
	RawTCPCmd cmd;
	QWORD addr;
	QWORD cb;
} RAWTCP_PROTO_PACKET, *PRAWTCP_PROTO_PACKET;

SOCKET DeviceRawTCP_Connect(_In_ DWORD Addr, _In_ WORD Port)
{
	SOCKET Sock = 0;
	struct sockaddr_in sAddr;
	sAddr.sin_family = AF_INET;
	sAddr.sin_port = htons(Port);
	sAddr.sin_addr.s_addr = Addr;
	if ((Sock = socket(AF_INET, SOCK_STREAM, 0)) != INVALID_SOCKET) {
		if (connect(Sock, (struct sockaddr *)&sAddr, sizeof(sAddr)) != SOCKET_ERROR) { return Sock; }
		fprintf(stderr, "ERROR: connect() fails\n");
		closesocket(Sock);
	}
	else {
		fprintf(stderr, "ERROR: socket() fails\n");
	}
	return 0;
}

BOOL DeviceRawTCP_Status(_In_ PDEVICE_CONTEXT_RAWTCP ctxrawtcp)
{
	RAWTCP_PROTO_PACKET Rx = {0}, Tx = {0};
	DWORD cbRead;
	BYTE ready;
	DWORD len;

	Tx.cmd = STATUS;

	if (send(ctxrawtcp->Sock, (const char *)&Tx, sizeof(Tx), 0) != sizeof(Tx)) {
		fprintf(stderr, "ERROR: send() fails\n");
		return 0;
	}

	cbRead = 0;
	while (cbRead < sizeof(Rx)) {
		len = recv(ctxrawtcp->Sock, (char *)&Rx + cbRead, sizeof(Rx) - cbRead, 0);
		if (len == SOCKET_ERROR || len == 0) {
			fprintf(stderr, "ERROR: recv() fails\n");
			return 0;
		}
		cbRead += len;
	}
	
	len = recv(ctxrawtcp->Sock, (char *)&ready, sizeof(ready), 0);
	if (len == SOCKET_ERROR || len != sizeof(ready)) {
		fprintf(stderr, "ERROR: recv() fails\n");
		return 0;
	}

	if (Rx.cmd != STATUS || Rx.cb != sizeof(ready)) {
		fprintf(stderr, "ERROR: Fail getting device status\n");
	}

	return ready != 0;
}

VOID DeviceRawTCP_Close(_Inout_ PPCILEECH_CONTEXT ctxPcileech)
{
	PDEVICE_CONTEXT_RAWTCP ctx = (PDEVICE_CONTEXT_RAWTCP)ctxPcileech->hDevice;
	if (!ctx) { return; }
	if (ctx->Sock) { closesocket(ctx->Sock); }
	if (ctx->rxbuf.pb) { LocalFree(ctx->rxbuf.pb); }
	if (ctx->txbuf.pb) { LocalFree(ctx->txbuf.pb); }
	LocalFree(ctx);
	ctxPcileech->hDevice = 0;
}

BOOL DeviceRawTCP_ReadDMA(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb)
{
	PDEVICE_CONTEXT_RAWTCP ctxrawtcp = (PDEVICE_CONTEXT_RAWTCP)ctxPcileech->hDevice;
	RAWTCP_PROTO_PACKET Rx = {0}, Tx = {0};
	DWORD cbRead;
	DWORD len;

	if (cb > RAWTCP_MAX_SIZE_RX) { return FALSE; }
	if (qwAddr % 0x1000) { return FALSE; }
	if ((cb >= 0x1000) && (cb % 0x1000)) { return FALSE; }
	if ((cb < 0x1000) && (cb % 0x8)) { return FALSE; }
	
	Tx.cmd = MEM_READ;
	Tx.addr = qwAddr;
	Tx.cb = cb;

	if (send(ctxrawtcp->Sock, (const char *)&Tx, sizeof(Tx), 0) != sizeof(Tx)) {
		fprintf(stderr, "ERROR: send() fails\n");
		return 0;
	}

	cbRead = 0;
	while (cbRead < sizeof(Rx)) {
		len = recv(ctxrawtcp->Sock, (char *)&Rx + cbRead, sizeof(Rx) - cbRead, 0);
		if (len == SOCKET_ERROR || len == 0) {
			fprintf(stderr, "ERROR: recv() fails\n");
			return 0;
		}
		cbRead += len;
	}


	cbRead = 0;
	while (cbRead < Rx.cb) {
		len = recv(ctxrawtcp->Sock, (char *)pb + cbRead, Rx.cb - cbRead, 0);
		if (len == SOCKET_ERROR || len == 0) {
			fprintf(stderr, "ERROR: recv() fails\n");
			return 0;
		}
		cbRead += len;
	}

	if (Rx.cmd != MEM_READ) {
		fprintf(stderr, "ERROR: Memory read fail (0x%x bytes read)\n", cbRead);
	}
	
	return Rx.cb >= cb;
}

BOOL DeviceRawTCP_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb)
{
	PDEVICE_CONTEXT_RAWTCP ctxrawtcp = (PDEVICE_CONTEXT_RAWTCP)ctxPcileech->hDevice;
	RAWTCP_PROTO_PACKET Rx = {0}, Tx = {0};
	DWORD cbRead, cbWritten;
	DWORD len;
	
	Tx.cmd = MEM_WRITE;
	Tx.addr = qwAddr;
	Tx.cb = cb;

	if (send(ctxrawtcp->Sock, (const char *)&Tx, sizeof(Tx), 0) != sizeof(Tx)) {
		fprintf(stderr, "ERROR: send() fails\n");
		return 0;
	}

	cbWritten = 0;
	while (cbWritten < cb) {
		len = send(ctxrawtcp->Sock, (char *)pb + cbWritten, cb - cbWritten, 0);
		if (len == SOCKET_ERROR || len == 0) {
			fprintf(stderr, "ERROR: send() fails\n");
			return 0;
		}
		cbWritten += len;
	}


	cbRead = 0;
	while (cbRead < sizeof(Rx)) {
		len = recv(ctxrawtcp->Sock, (char *)&Rx + cbRead, sizeof(Rx) - cbRead, 0);
		if (len == SOCKET_ERROR || len == 0) {
			fprintf(stderr, "ERROR: recv() fails\n");
			return 0;
		}
		cbRead += len;
	}

	if (Rx.cmd != MEM_WRITE) {
		fprintf(stderr, "ERROR: Memory write fail\n", cbRead);
	}
	
	return cbWritten >= cb;
}

BOOL DeviceRawTCP_Open(_Inout_ PPCILEECH_CONTEXT ctxPcileech)
{
	PDEVICE_CONTEXT_RAWTCP ctx;
#ifdef WIN32

	WSADATA WsaData;
	WSAStartup(MAKEWORD(2, 2), &WsaData);

#endif
	if (ctxPcileech->cfg->TcpAddr == 0) {
		fprintf(stderr, "ERROR: Remote address is not specified\n");
		return FALSE;
	}
	ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_RAWTCP));
	if (!ctx) { return FALSE; }
	ctxPcileech->hDevice = (HANDLE)ctx;	
	// open device connection
	if (ctxPcileech->cfg->TcpPort == 0) { ctxPcileech->cfg->TcpPort = DEFAULT_PORT; }
	ctx->Sock = DeviceRawTCP_Connect(ctxPcileech->cfg->TcpAddr, ctxPcileech->cfg->TcpPort);
	if (!ctx->Sock) { goto fail; }	
	if(!DeviceRawTCP_Status(ctx)) { printf("Error: remote service is not ready\n"); goto fail; }
	ctx->rxbuf.cbMax = RAWTCP_MAX_SIZE_RX;
	ctx->rxbuf.pb = LocalAlloc(0, ctx->rxbuf.cbMax);
	if (!ctx->rxbuf.pb) { goto fail; }
	ctx->txbuf.cbMax = RAWTCP_MAX_SIZE_TX;
	ctx->txbuf.pb = LocalAlloc(0, ctx->txbuf.cbMax);
	if (!ctx->txbuf.pb) { goto fail; }

	// set callback functions and fix up config
	ctxPcileech->cfg->dev.tp = PCILEECH_DEVICE_RAW_TCP;
	ctxPcileech->cfg->dev.qwMaxSizeDmaIo = 0x1000000; // 16MB
	ctxPcileech->cfg->dev.qwAddrMaxNative = 0x0000ffffffffffff;
	ctxPcileech->cfg->dev.fPartialPageReadSupported = TRUE;
	ctxPcileech->cfg->dev.pfnClose = DeviceRawTCP_Close;
	ctxPcileech->cfg->dev.pfnReadDMA = DeviceRawTCP_ReadDMA;
	ctxPcileech->cfg->dev.pfnWriteDMA = DeviceRawTCP_WriteDMA;

	// return
	if (ctxPcileech->cfg->fVerbose) { printf("Device Info: Raw TCP.\n"); }
	return TRUE;
fail:
	DeviceRawTCP_Close(ctxPcileech);
	return FALSE;
}