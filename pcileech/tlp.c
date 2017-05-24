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
		buf[i] = _byteswap_ulong(*(PDWORD)(pbTlp + i));
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
		printf("\n%s: ReqID: %04x BE1: %01x BEL: %01x Tag: %02x Addr: %016llx", (hdr->TypeFmt == TLP_MRd32) ? "MRr64" : "MWr64", hdrM64->RequesterID, hdrM64->FirstBE, hdrM64->LastBE, hdrM64->Tag, ((QWORD)hdrM64->AddressHigh << 32) + hdrM64->AddressLow);
	}
	printf("\n");
	Util_PrintHexAscii(pbTlp, cbTlp);
}
