// devicerawtcp.h : implementation related to dummy device backed by a TCP service.
//

#ifndef __DEVICERAWTCP_H__
#define __DEVICERAWTCP_H__
#include "pcileech.h"

BOOL DeviceRawTCP_Open(_Inout_ PPCILEECH_CONTEXT ctx);

typedef enum tdRawTCPCmd {
	STATUS,
	MEM_READ,
	MEM_WRITE
} RawTCPCmd;

#endif /* __DEVICERAWTCP_H__ */