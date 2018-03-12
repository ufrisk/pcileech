// devicefile.h : definitions related to dummy device backed by a file.
//
// (c) Ulf Frisk, 2018
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __DEVICEFILE_H__
#define __DEVICEFILE_H__
#include "pcileech.h"

/*
* Open a "connection" to the file.
* -- ctx
* -- result
*/
BOOL DeviceFile_Open(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __DEVICEFILE_H__ */
