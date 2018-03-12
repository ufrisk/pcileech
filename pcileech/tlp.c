// tlp.c : implementation of PCIe TLP (transaction layer packets) functionality.
//
// (c) Ulf Frisk, 2017-2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "tlp.h"
#include "util.h"

VOID TLP_Print(_In_ PBYTE pbTlp, _In_ DWORD cbTlp, _In_ BOOL isTx)
{
    DWORD i;
    LPSTR tp = "";
    BYTE pb[0x1000];
    PDWORD buf = (PDWORD)pb;
    PTLP_HDR hdr = (PTLP_HDR)pb;
    PTLP_HDR_CplD hdrC;
    PTLP_HDR_MRdWr32 hdrM32;
    PTLP_HDR_MRdWr64 hdrM64;
    PTLP_HDR_Cfg hdrCfg;
    if(cbTlp < 12 || cbTlp > 0x1000 || cbTlp & 0x3) { return; }
    for(i = 0; i < cbTlp; i += 4) {
        buf[i >> 2] = _byteswap_ulong(*(PDWORD)(pbTlp + i));
    }
    if((hdr->TypeFmt == TLP_Cpl) || (hdr->TypeFmt == TLP_CplD) || (hdr->TypeFmt == TLP_CplLk) || (hdr->TypeFmt == TLP_CplDLk)) {
        if(hdr->TypeFmt == TLP_Cpl)    { tp = "Cpl:   "; }
        if(hdr->TypeFmt == TLP_CplD)   { tp = "CplD:  "; }
        if(hdr->TypeFmt == TLP_CplLk)  { tp = "CplLk: "; }
        if(hdr->TypeFmt == TLP_CplDLk) { tp = "CplDLk:"; }
        hdrC = (PTLP_HDR_CplD)pb;
        printf(
            "\n%s: %s Len: %03x ReqID: %04x CplID: %04x Status: %01x BC: %03x Tag: %02x LowAddr: %02x",
            (isTx ? "TX" : "RX"),
            tp,
            hdr->Length,
            hdrC->RequesterID,
            hdrC->CompleterID,
            hdrC->Status,
            hdrC->ByteCount,
            hdrC->Tag,
            hdrC->LowerAddress
        );
    } else if((hdr->TypeFmt == TLP_MRd32) || (hdr->TypeFmt == TLP_MWr32)) {
        hdrM32 = (PTLP_HDR_MRdWr32)pb;
        printf(
            "\n%s: %s Len: %03x ReqID: %04x BE_FL: %01x%01x Tag: %02x Addr: %08x", 
            (isTx ? "TX" : "RX"),
            (hdr->TypeFmt == TLP_MRd32) ? "MRd32: " : "MWr32: ", 
            hdr->Length,
            hdrM32->RequesterID, 
            hdrM32->FirstBE, 
            hdrM32->LastBE, 
            hdrM32->Tag, 
            hdrM32->Address);
    } else if((hdr->TypeFmt == TLP_MRd64) || (hdr->TypeFmt == TLP_MWr64)) {
        hdrM64 = (PTLP_HDR_MRdWr64)pb;
        printf(
            "\n%s: %s Len: %03x ReqID: %04x BE_FL: %01x%01x Tag: %02x Addr: %016llx",
            (isTx ? "TX" : "RX"),
            (hdr->TypeFmt == TLP_MRd64) ? "MRd64: " : "MWr64: ",
            hdr->Length,
            hdrM64->RequesterID,
            hdrM64->FirstBE,
            hdrM64->LastBE,
            hdrM64->Tag,
            ((QWORD)hdrM64->AddressHigh << 32) + hdrM64->AddressLow
        );
    } else if((hdr->TypeFmt == TLP_IORd) || (hdr->TypeFmt == TLP_IOWr)) {
        hdrM32 = (PTLP_HDR_MRdWr32)pb; // same format for IO Rd/Wr
        printf(
            "\n%s: %s Len: %03x ReqID: %04x BE_FL: %01x%01x Tag: %02x Addr: %08x",
            (isTx ? "TX" : "RX"),
            (hdr->TypeFmt == TLP_IORd) ? "IORd:  " : "IOWr:  ",
            hdr->Length,
            hdrM32->RequesterID,
            hdrM32->FirstBE,
            hdrM32->LastBE,
            hdrM32->Tag,
            hdrM32->Address
        );
    } else if((hdr->TypeFmt == TLP_CfgRd0) || (hdr->TypeFmt == TLP_CfgRd1) || (hdr->TypeFmt == TLP_CfgWr0) || (hdr->TypeFmt == TLP_CfgWr1)) {
        if(hdr->TypeFmt == TLP_CfgRd0) { tp = "CfgRd0:"; }
        if(hdr->TypeFmt == TLP_CfgRd1) { tp = "CfgRd1:"; }
        if(hdr->TypeFmt == TLP_CfgWr0) { tp = "CfgWr0:"; }
        if(hdr->TypeFmt == TLP_CfgWr1) { tp = "CfgWr1:"; }
        hdrCfg = (PTLP_HDR_Cfg)pb;
        printf(
            "\n%s: %s Len: %03x ReqID: %04x BE_FL: %01x%01x Tag: %02x Dev: %i:%i.%i ExtRegNum: %01x RegNum: %02x",
            (isTx ? "TX" : "RX"),
            tp,
            hdr->Length,
            hdrCfg->RequesterID,
            hdrCfg->FirstBE,
            hdrCfg->LastBE,
            hdrCfg->Tag,
            hdrCfg->BusNum,
            hdrCfg->DeviceNum,
            hdrCfg->FunctionNum,
            hdrCfg->ExtRegNum,
            hdrCfg->RegNum            
        );
    } else { 
        printf(
            "\n%s: TLP???: TypeFmt: %02x dwLen: %03x", 
            (isTx ? "TX" : "RX"), 
            hdr->TypeFmt, 
            hdr->Length
        );
    }
    printf("\n");
    Util_PrintHexAscii(pbTlp, cbTlp, 0);
}

VOID TLP_CallbackMRd(_Inout_ PTLP_CALLBACK_BUF_MRd pBufferMRd, _In_ PBYTE pb, _In_ DWORD cb)
{
    PTLP_HDR_CplD hdrC = (PTLP_HDR_CplD)pb;
    PTLP_HDR hdr = (PTLP_HDR)pb;
    PDWORD buf = (PDWORD)pb;
    DWORD o, c;
    buf[0] = _byteswap_ulong(buf[0]);
    if(cb < ((DWORD)hdr->Length << 2) + 12) { return; }
    if((hdr->TypeFmt == TLP_CplD) && pBufferMRd) {
        buf[1] = _byteswap_ulong(buf[1]);
        buf[2] = _byteswap_ulong(buf[2]);
        // NB! read algorithm below only support reading full 4kB pages _or_
        //     partial page if starting at page boundry and read is less than 4kB.
        o = ((DWORD)hdrC->Tag << 12) + min(0x1000, pBufferMRd->cbMax) - (hdrC->ByteCount ? hdrC->ByteCount : 0x1000);
        c = (DWORD)hdr->Length << 2;
        if(cb != c + 12) { return; }
        if(o + c <= pBufferMRd->cbMax) {
            memcpy(pBufferMRd->pb + o, pb + 12, c);
            pBufferMRd->cb += c;
        }
    }
}

VOID TLP_CallbackMRdProbe(_Inout_ PTLP_CALLBACK_BUF_MRd pBufferMRd, _In_ PBYTE pb, _In_ DWORD cb)
{
    PTLP_HDR_CplD hdrC = (PTLP_HDR_CplD)pb;
    PDWORD buf = (PDWORD)pb;
    DWORD i;
    if(cb < 16) { return; } // min size CplD = 16 bytes.
    buf[0] = _byteswap_ulong(buf[0]);
    buf[1] = _byteswap_ulong(buf[1]);
    buf[2] = _byteswap_ulong(buf[2]);
    if((hdrC->h.TypeFmt == TLP_CplD) && pBufferMRd) {
        // 5 low address bits coded into the dword read, 8 high address bits coded into tag.
        i = ((DWORD)hdrC->Tag << 5) + ((hdrC->LowerAddress >> 2) & 0x1f);
        if(i < pBufferMRd->cbMax) {
            pBufferMRd->pb[i] = 1;
            pBufferMRd->cb++;
        }
    }
}

VOID TLP_CallbackMRd_Scatter(_Inout_ PTLP_CALLBACK_BUF_MRd_SCATTER pBufferMrd_Scatter, _In_ PBYTE pb, _In_ DWORD cb)
{
    PTLP_HDR_CplD hdrC = (PTLP_HDR_CplD)pb;
    PTLP_HDR hdr = (PTLP_HDR)pb;
    PDWORD buf = (PDWORD)pb;
    DWORD o, c, i;
    PDMA_IO_SCATTER_HEADER phResult;
    buf[0] = _byteswap_ulong(buf[0]);
    if(cb < ((DWORD)hdr->Length << 2) + 12) { return; }
    if(hdr->TypeFmt == TLP_CplD) {
        buf[1] = _byteswap_ulong(buf[1]);
        buf[2] = _byteswap_ulong(buf[2]);
        if(pBufferMrd_Scatter->bEccBit != (hdrC->Tag >> 7)) { return; } // ECC bit mismatch
        if(hdrC->Tag & 0x40) {
            // Algoritm: Multiple MRd of size 128 bytes, MRd:CplD ratio 1:1.
            i = (hdrC->Tag & 0x20) ? 1 : 0;
            if(i >= pBufferMrd_Scatter->cph) { return; }
            phResult = *(pBufferMrd_Scatter->pph + i);
            o = 0x80 + ((hdrC->Tag & 0x1f) << 7) - (hdrC->ByteCount ? hdrC->ByteCount : 0x80);
            if(o > 0x1000) { return; }
        } else {
            // Algoritm: Single MRd of page (0x1000) or less, multiple CplD.
            i = hdrC->Tag & 0x3f;
            if(i >= pBufferMrd_Scatter->cph) { return; }
            phResult = *(pBufferMrd_Scatter->pph + i);
            o = phResult->cbMax - (hdrC->ByteCount ? hdrC->ByteCount : 0x1000);
        }
        c = (DWORD)hdr->Length << 2;
        if(o + c > phResult->cbMax) { return; }
        memcpy(phResult->pb + o, pb + 12, c);
        phResult->cb += c;
        pBufferMrd_Scatter->cbReadTotal += c;
    }
}
