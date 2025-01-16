// memdump.h : definitions related to memory dumping functionality.
//
// (c) Ulf Frisk, 2016-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MEMDUMP_H__
#define __MEMDUMP_H__
#include "pcileech.h"

/*
* Dump physical memory to file. The USB3380 card may only dump the lower 4GB
* in default DMA mode due to hardware limitations. If a kernel module (KMD) is
* inserted in the target computer OS kernel all memory may be dumped.
*/
VOID ActionMemoryDump();

/*
* Probe readable physical memory (for reading). The resulting memory map is
* displayed on-screen. Probing is performed in DMA mode. The USB3380 hardware
* does not support this operation.
*/
VOID ActionMemoryProbe();

/*
* Write data to the physical memory. The USB3380 may only write to the lower
* 4GB in default DMA mode due to hardware limitations. If a kernel module (KMD)
* is inserted in the target computer OS any kernel accessable memory can be
* written/updated.
*/
VOID ActionMemoryWrite();

/*
* Tries to read a page 1000 times from the address specified in the min parameter
* in pCfg. If memory is changed the result will be flagged.
* After a read an optional 100 write/read cycles will be completed to test write.
*/
VOID ActionMemoryTestReadWrite();

/*
* Print out the contents of the 1st readable page. The address specified in the
* min parameter in pCfg.
*/
VOID ActionMemoryPageDisplay();

/*
* Print out a maximum of 16kB (0x10000) physical memory limited by the
* paMin and paMax parameters in pCfg. By default 0x100 bytes are displayed.
*/
VOID ActionMemoryDisplayPhysical();

/*
* Print out a maximum of 16kB (0x10000) virtual memory limited by the
* vaMin and vaMax parameters in pCfg. By default 0x100 bytes are displayed.
*/
VOID ActionMemoryDisplayVirtual();

#endif /* __MEMDUMP_H__ */
