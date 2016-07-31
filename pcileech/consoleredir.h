// consoleredir.h : definitions related to 'console redirect' functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __CONSOLEREDIR_H__
#define __CONSOLEREDIR_H__
#include "pcileech.h"

/*
* Connect to an interactive console at the target system over DMA. This works
* by reading and writing memory buffers on the target system.
* -- pCfg
* -- pDeviceData
* -- ConsoleBufferAddr_InputStream = DMA buffer on target system for input.
* -- ConsoleBufferAddr_OutputStream = DMA buffer on target system for output.
*/
VOID ActionConsoleRedirect(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData, _In_ QWORD ConsoleBufferAddr_InputStream, _In_ QWORD ConsoleBufferAddr_OutputStream);

#endif /* __CONSOLEREDIR_H__ */