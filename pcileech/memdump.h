// memdump.h : definitions related to memory dumping functionality.
//
// (c) Ulf Frisk, 2016, 2017
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __MEMDUMP_H__
#define __MEMDUMP_H__
#include "pcileech.h"

/*
* Dump physical memory to file. The USB3380 card may only dump the lower 4GB
* in default DMA mode due to hardware limitations. If a kernel module (KMD) is
* inserted in the target computer OS kernel all memory may be dumped.
* -- ctx
*/
VOID ActionMemoryDump(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Probe readable physical memory (for reading). The resulting memory map is
* displayed on-screen. Probing is performed in DMA mode. The USB3380 hardware
* does not support this operation.
* -- ctx
*/
VOID ActionMemoryProbe(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Write data to the physical memory. The USB3380 may only write to the lower
* 4GB in default DMA mode due to hardware limitations. If a kernel module (KMD)
* is inserted in the target computer OS any kernel accessable memory can be
* written/updated.
* -- ctx
*/
VOID ActionMemoryWrite(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Tries to read a page 1000 times from the address specified in the min parameter
* in pCfg. If memory is changed the result will be flagged.
* After a read an optional 100 write/read cycles will be completed to test write.
* -- ctx
*/
VOID ActionMemoryTestReadWrite(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Print out the contents of the 1st readable page. The address specified in the
* min parameter in pCfg.
* -- ctx
*/
VOID ActionMemoryPageDisplay(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Print out a maximum of 16kB (0x10000) memory limited by the min and max
* parameters in pCfg. By default 0x100 bytes are displayed.
* -- ctx
*/
VOID ActionMemoryDisplay(_Inout_ PPCILEECH_CONTEXT ctx);


/*
* Try to read all the pages (success or failure)
* Create a CSV file with values to parse them later and
* create a bit map of the RAM
* By default, a page is 4096 bytes (0x1000).
* -- ctx
*/
VOID ActionMemoryGruyere(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __MEMDUMP_H__ */