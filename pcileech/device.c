// device.c : implementation related to hardware devices.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "device.h"
#include "kmd.h"
#include "device3380.h"
#include "device605.h"

BOOL DeviceReadDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	if(flags & PCILEECH_MEM_FLAG_RETRYONFAIL) {
		return DeviceReadDMA(ctx, qwAddr, pb, cb, 0) || DeviceReadDMA(ctx, qwAddr, pb, cb, 0);
	}
	if(PCILEECH_DEVICE_USB3380 == ctx->cfg->tpDevice) {
		return Device3380_ReadDMA(ctx, qwAddr, pb, cb);
	} else if(PCILEECH_DEVICE_SP605 == ctx->cfg->tpDevice) {
		return Device605_ReadDMA(ctx, qwAddr, pb, cb);
	}
	return FALSE;
}

BOOL DeviceWriteDMA(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	PBYTE pbV;
	BOOL result = FALSE;
	if(flags & PCILEECH_MEM_FLAG_RETRYONFAIL) {
		return DeviceWriteDMA(ctx, qwAddr, pb, cb, 0) || DeviceWriteDMA(ctx, qwAddr, pb, cb, 0);
	}
	if(PCILEECH_DEVICE_USB3380 == ctx->cfg->tpDevice) {
		result = Device3380_WriteDMA(ctx, qwAddr, pb, cb);
	} else if(PCILEECH_DEVICE_SP605 == ctx->cfg->tpDevice) {
		result = Device605_WriteDMA(ctx, qwAddr, pb, cb);
	}
	if(!result) { return FALSE; }
	if(flags & PCILEECH_MEM_FLAG_VERIFYWRITE) {
		pbV = LocalAlloc(0, cb + 0x2000);
		if(!pbV) { return FALSE; }
		result =
			DeviceReadDMA(ctx, qwAddr & ~0xfff, pbV, (cb + 0xfff + (qwAddr & 0xfff)) & ~0xfff, flags) &&
			(0 == memcmp(pb, pbV + (qwAddr & 0xfff), cb));
		LocalFree(pbV);
	}
	return result;
}

VOID DeviceClose(_Inout_ PPCILEECH_CONTEXT ctx)
{
	if(ctx->hDevice) {
		if(PCILEECH_DEVICE_USB3380 == ctx->cfg->tpDevice) {
			Device3380_Close(ctx);
		} else if(PCILEECH_DEVICE_SP605 == ctx->cfg->tpDevice) {
			Device605_Close(ctx);
		}
	}
}

BOOL DeviceOpen(_Inout_ PPCILEECH_CONTEXT ctx)
{
	if(PCILEECH_DEVICE_USB3380 == ctx->cfg->tpDevice) {
		return Device3380_Open(ctx);
	} else if(PCILEECH_DEVICE_SP605 == ctx->cfg->tpDevice) {
		return Device605_Open(ctx);
	}
	return FALSE;
}

BOOL DeviceWriteMEM(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _In_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	if(ctx->phKMD) {
		return KMDWriteMemory(ctx, qwAddr, pb, cb);
	} else {
		return DeviceWriteDMA(ctx, qwAddr, pb, cb, flags);
	}
}

BOOL DeviceReadMEM(_Inout_ PPCILEECH_CONTEXT ctx, _In_ QWORD qwAddr, _Out_ PBYTE pb, _In_ DWORD cb, _In_ QWORD flags)
{
	if(ctx->phKMD) {
		return KMDReadMemory(ctx, qwAddr, pb, cb);
	} else {
		return DeviceReadDMA(ctx, qwAddr, pb, cb, flags);
	}
}
