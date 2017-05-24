// device605.h : definitions related PCIe TLPs (transaction layper packets).
//
// (c) Ulf Frisk, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __TLP_H__
#define __TLP_H__
#include "pcileech.h"

#define TLP_MRd32		0x00
#define TLP_MRd64		0x20
#define TLP_MRdLk32		0x01
#define TLP_MRdLk64		0x21
#define TLP_MWr32		0x40
#define TLP_MWr64		0x60
#define TLP_IORd		0x02
#define TLP_IOWr		0x42
#define TLP_CfgRd0		0x04
#define TLP_CfgRd1		0x05
#define TLP_CfgWr0		0x44
#define TLP_CfgWr1		0x45
#define TLP_Cpl			0x0A
#define TLP_CplD		0x4A
#define TLP_CplLk		0x0B
#define TLP_CplLkD		0x4B

typedef struct tdTLP_HDR {
	WORD Length : 10;
	WORD _AT : 2;
	WORD _Attr : 2;
	WORD _EP : 1;
	WORD _TD : 1;
	BYTE _R1 : 4;
	BYTE _TC : 3;
	BYTE _R2 : 1;
	BYTE TypeFmt;
} TLP_HDR, *PTLP_HDR;

typedef struct tdTLP_HDR_MRdWr32 {
	TLP_HDR h;
	BYTE FirstBE : 4;
	BYTE LastBE : 4;
	BYTE Tag;
	WORD RequesterID;
	DWORD Address;
} TLP_HDR_MRdWr32, *PTLP_HDR_MRdWr32;

typedef struct tdTLP_HDR_MRdWr64 {
	TLP_HDR h;
	BYTE FirstBE : 4;
	BYTE LastBE : 4;
	BYTE Tag;
	WORD RequesterID;
	DWORD AddressHigh;
	DWORD AddressLow;
} TLP_HDR_MRdWr64, *PTLP_HDR_MRdWr64;

typedef struct tdTLP_HDR_CplD {
	TLP_HDR h;
	WORD ByteCount : 12;
	WORD _BCM : 1;
	WORD Status : 3;
	WORD CompleterID;
	BYTE LowerAddress : 7;
	BYTE _R1 : 1;
	BYTE Tag;
	WORD RequesterID;
} TLP_HDR_CplD, *PTLP_HDR_CplD;

/*
* Print a PCIe TLP packet on the screen in a human readable format.
* -- pbTlp = complete TLP packet (header+data)
* -- cbTlp = length in bytes of TLP packet.
* -- isTx = TRUE = packet is transmited, FALSE = packet is received.
*/
VOID TLP_Print(_In_ PBYTE pbTlp, _In_ DWORD cbTlp, _In_ BOOL isTx);

#endif /* __TLP_H__ */
