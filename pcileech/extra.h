// extra.h : definitions related to various extra functionality such as exploits.
//
// (c) Ulf Frisk, 2016-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#ifndef __EXTRA_H__
#define __EXTRA_H__
#include "pcileech.h"
#include "kmd.h"

/*
* Recover the Filevault 2 password on locked macOS systems prior to 10.12.2.
* (IsRebootRequired = TRUE).
* Also recover the Filevault 2 password just after user filevault unlock on
* some macs prior to 10.XX.YY (IsRebootRequired = FALSE).
* -- IsRebootRequired
*/
VOID Action_MacFilevaultRecover(_In_ BOOL IsRebootRequired);

/*
* Try to disable VT-d on a mac in the short time window that exists after EFI
* drops VT-d DMA protections and before macOS enables them again. If successful
* the DMAR ACPI table will be zeroed out - resulting in macOS not enabling VT-d
* DMA protections. This works on macs prior to 10.XX.YY
*/
VOID Action_MacDisableVtd();

/*
* Search for the virtual address that maps to a physical address given a page table base.
*/
VOID Action_PT_Phys2Virt();

/*
* Search for the physical address that is mapped by a virtual address given a page table base.
*/
VOID Action_PT_Virt2Phys();

/*
* Transmit the TLP data specified in the -in parameter.
*/
VOID Action_TlpTx();

/*
* Transmit TLPs in a hardware-assisted loop using on-board fpga logic.
*/
VOID Action_TlpTxLoop();

/*
* Read/Write to FPGA PCIe shadow configuration space.
*/
VOID Action_RegCfgReadWrite();

/*
* Register a callback that will implement read/write support of PCIe BARs.
*/
VOID Extra_BarReadWriteInitialize();

/*
* Run benchmarks (useful for PCIe benchmarking).
*/
VOID Action_Benchmark();

#endif /* __EXTRA_H__ */
