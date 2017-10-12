// tlp.c : implementation of PCIe TLP (transaction layer packets) functionality.
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "tlp.h"
#include "util.h"

VOID TLP_Print(_In_ PBYTE pbTlp, _In_ DWORD cbTlp, _In_ BOOL isTx)
{
	DWORD i;
	BYTE pb[0x1000];
	PDWORD buf = (PDWORD)pb;
	PTLP_HDR hdr = (PTLP_HDR)pb;
	PTLP_HDR_CplD hdrC;
	PTLP_HDR_MRdWr32 hdrM32;
	PTLP_HDR_MRdWr64 hdrM64;
	if(cbTlp < 12 || cbTlp > 0x1000 || cbTlp & 0x3) { return; }
	for(i = 0; i < cbTlp; i += 4) {
		buf[i >> 2] = _byteswap_ulong(*(PDWORD)(pbTlp + i));
	}
	printf("%s_TLP: TypeFmt: %02x Length: %03x(%04x)", (isTx ? "TX" : "RX"), hdr->TypeFmt, hdr->Length, (hdr->Length << 2));
	if(hdr->TypeFmt == TLP_CplD) {
		hdrC = (PTLP_HDR_CplD)pb;
		printf("\nCplD: CplID: %04x ReqID: %04x Status: %01x BC: %03x Tag: %02x LowAddr: %02x", hdrC->RequesterID, hdrC->CompleterID, hdrC->Status, hdrC->ByteCount, hdrC->Tag, hdrC->LowerAddress);
	} else if(hdr->TypeFmt == TLP_MRd32 || hdr->TypeFmt == TLP_MWr32) {
		hdrM32 = (PTLP_HDR_MRdWr32)pb;
		printf("\n%s: ReqID: %04x BE1: %01x BEL: %01x Tag: %02x Addr: %08x", (hdr->TypeFmt == TLP_MRd32) ? "MRd32" : "MWr32", hdrM32->RequesterID, hdrM32->FirstBE, hdrM32->LastBE, hdrM32->Tag, hdrM32->Address);
	} else if(hdr->TypeFmt == TLP_MRd64 || hdr->TypeFmt == TLP_MWr64) {
		hdrM64 = (PTLP_HDR_MRdWr64)pb;
		printf("\n%s: ReqID: %04x BE1: %01x BEL: %01x Tag: %02x Addr: %016llx", (hdr->TypeFmt == TLP_MRd64) ? "MRd64" : "MWr64", hdrM64->RequesterID, hdrM64->FirstBE, hdrM64->LastBE, hdrM64->Tag, ((QWORD)hdrM64->AddressHigh << 32) + hdrM64->AddressLow);
	}
	printf("\n");
	Util_PrintHexAscii(pbTlp, cbTlp);
}

BOOL TLP_CallbackMRd(_Inout_ PTLP_CALLBACK_BUF_MRd pBufferMRd, _In_ PBYTE pb, _In_ DWORD cb, _In_opt_ HANDLE hEventCompleted)
{
	PTLP_HDR_CplD hdrC = (PTLP_HDR_CplD)pb;
	PTLP_HDR hdr = (PTLP_HDR)pb;
	PDWORD buf = (PDWORD)pb;
	DWORD o, c;
	buf[0] = _byteswap_ulong(buf[0]);
	if(cb < ((DWORD)hdr->Length << 2) - 12) { return FALSE; }
	if((hdr->TypeFmt == TLP_CplD) && pBufferMRd) {
		buf[1] = _byteswap_ulong(buf[1]);
		buf[2] = _byteswap_ulong(buf[2]);
		// NB! read algorithm below only support reading full 4kB pages _or_
		//     partial page if starting at page boundry and read is less than 4kB.
		o = ((DWORD)hdrC->Tag << 12) + min(0x1000, pBufferMRd->cbMax) - (hdrC->ByteCount ? hdrC->ByteCount : 0x1000);
		c = (DWORD)hdr->Length << 2;
		if(cb != c + 12) { return FALSE; }
		if(o + c <= pBufferMRd->cbMax) {
			memcpy(pBufferMRd->pb + o, pb + 12, c);
			if(pBufferMRd->cbMax <= (DWORD)InterlockedAdd(&pBufferMRd->cb, c)) {
				if(hEventCompleted) {
					SetEvent(hEventCompleted);
				}
				return TRUE;
			}
		}
	} else {
		QWORD qwDebug[16];
		memset(qwDebug, 0xcc, 16 * 8);
		memcpy(qwDebug, pb, min(cb, 16 * 8));
		DWORD DEBUGX = 0x01;
	}
	return FALSE;
}

BOOL TLP_CallbackMRdProbe(_Inout_ PTLP_CALLBACK_BUF_MRd pBufferMRd, _In_ PBYTE pb, _In_ DWORD cb, _In_opt_ HANDLE hEventCompleted)
{
	PTLP_HDR_CplD hdrC = (PTLP_HDR_CplD)pb;
	PDWORD buf = (PDWORD)pb;
	DWORD i;
	if(cb < 16) { return FALSE; } // min size CplD = 16 bytes.
	buf[0] = _byteswap_ulong(buf[0]);
	buf[1] = _byteswap_ulong(buf[1]);
	buf[2] = _byteswap_ulong(buf[2]);
	if((hdrC->h.TypeFmt == TLP_CplD) && pBufferMRd) {
		// 5 low address bits coded into the dword read, 8 high address bits coded into tag.
		i = ((DWORD)hdrC->Tag << 5) + ((hdrC->LowerAddress >> 2) & 0x1f);
		if(i < pBufferMRd->cbMax) {
			pBufferMRd->pb[i] = 1;
			if(pBufferMRd->cbMax <= (DWORD)InterlockedAdd(&pBufferMRd->cb, 1)) {
				if(hEventCompleted) {
					SetEvent(hEventCompleted);
				}
				return TRUE;
			}
		}
	}
	return FALSE;
}
