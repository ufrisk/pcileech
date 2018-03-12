// extra.h : definitions related to various extra functionality such as exploits.
//
// (c) Ulf Frisk, 2016-2018
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
* -- ctx
* -- IsRebootRequired
*/
VOID Action_MacFilevaultRecover(_Inout_ PPCILEECH_CONTEXT ctx, _In_ BOOL IsRebootRequired);

/*
* Try to disable VT-d on a mac in the short time window that exists after EFI
* drops VT-d DMA protections and before macOS enables them again. If successful
* the DMAR ACPI table will be zeroed out - resulting in macOS not enabling VT-d
* DMA protections. This works on macs prior to 10.XX.YY
* -- ctx
*/
VOID Action_MacDisableVtd(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Search for the virtual address that maps to a physical address given a page table base.
* -- ctx
*/
VOID Action_PT_Phys2Virt(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Search for the physical address that is mapped by a virtual address given a page table base.
* -- ctx
*/
VOID Action_PT_Virt2Phys(_Inout_ PPCILEECH_CONTEXT ctx);

/*
* Transmit the TLP data specified in the -in parameter.
* -- ctx
*/
VOID Action_TlpTx(_Inout_ PPCILEECH_CONTEXT ctx);

#endif /* __EXTRA_H__ */
