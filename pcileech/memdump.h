// memdump.h : definitions related to memory dumping functionality.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MEMDUMP_H__
#define __MEMDUMP_H__
#include "pcileech.h"

/*
* Dump physical memory to file. The USB3380 card may only dump the lower 4GB
* in default DMA mode due to hardware limitations. If a kernel module (KMD) is
* inserted in the target computer OS kernel all memory may be dumped.
* -- pCfg = configuration containing dump regions, file name and more info.
* -- pDeviceData
*/
VOID ActionMemoryDump(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

/*
* Write data to the physical memory. The USB3380 may only write to the lower
* 4GB in default DMA mode due to hardware limitations. If a kernel module (KMD)
* is inserted in the target computer OS any kernel accessable memory can be
* written/updated.
* -- pCfg
* -- pDeviceData
*/
VOID ActionMemoryWrite(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

/*
* Tries to read a page 1000 times from the address specified in the min parameter
* in pCfg. If memory is changed the result will be flagged.
* After a read an optional 100 write/read cycles will be completed to test write.
* -- pCfg
* -- pDeviceData
*/
VOID ActionMemoryTestReadWrite(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

/*
* Print out the contents of the 1st readable page. The address specified in the
* min parameter in pCfg.
* -- pCfg
* -- pDeviceData
*/
VOID ActionMemoryPageDisplay(_In_ PCONFIG pCfg, _In_ PDEVICE_DATA pDeviceData);

#endif /* __MEMDUMP_H__ */