// executor.c : implementation related 'code execution' and 'console redirect' functionality.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
#include "executor.h"
#include "device.h"
#include "util.h"
#include "vmmx.h"

#define EXEC_IO_MAGIC                   0x12651232dfef9521
#define EXEC_IO_CONSOLE_BUFFER_SIZE     0x800
#define EXEC_IO_DMAOFFSET_IS            0x80000
#define EXEC_IO_DMAOFFSET_OS            0x81000
typedef struct tdEXEC_IO {
    QWORD magic;
    struct {
        QWORD cbRead;
        QWORD cbReadAck;
        QWORD Reserved[10];
        BYTE  pb[800];
    } con;
    struct {
        QWORD seq;
        QWORD seqAck;
        QWORD fCompleted;
        QWORD fCompletedAck;
    } bin;
    QWORD Reserved[395];
} EXEC_IO, *PEXEC_IO;

typedef struct tdCONSOLEREDIR_THREADDATA {
    HANDLE hThreadIS;
    HANDLE hThreadOS;
    PEXEC_IO pInfoIS;
    PEXEC_IO pInfoOS;
    BYTE pbDataISConsoleBuffer[4096];
    BYTE pbDataOSConsoleBuffer[4096];
    BOOL fTerminateThread;
} CONSOLEREDIR_THREADDATA, *PCONSOLEREDIR_THREADDATA;

typedef struct tdEXEC_HANDLE {
    PBYTE pbDMA;
    FILE *pFileOutput;
    QWORD qwFileWritten;
    QWORD fError;
    EXEC_IO is;
    EXEC_IO os;
} EXEC_HANDLE, *PEXEC_HANDLE;

// input buffer to targeted console (outgoing info)
// read from this console and send to targeted console
DWORD ConsoleRedirect_ThreadConsoleInput(PCONSOLEREDIR_THREADDATA pd)
{
    DWORD cbWrite, cbModulo, cbModuloAck;
    while(!pd->fTerminateThread) {
        while(pd->pInfoOS->con.cbRead == pd->pInfoIS->con.cbReadAck) {
            Sleep(10);
            continue;
        }
        cbModulo = pd->pInfoOS->con.cbRead % EXEC_IO_CONSOLE_BUFFER_SIZE;
        cbModuloAck = pd->pInfoIS->con.cbReadAck % EXEC_IO_CONSOLE_BUFFER_SIZE;
        if(cbModuloAck < cbModulo) {
            cbWrite = cbModulo - cbModuloAck;
            printf("%.*s", cbWrite, pd->pInfoOS->con.pb + cbModuloAck);
        } else {
            cbWrite = EXEC_IO_CONSOLE_BUFFER_SIZE - cbModuloAck;
            printf("%.*s", cbWrite, pd->pInfoOS->con.pb + cbModuloAck);
        }
        pd->pInfoIS->con.cbReadAck += cbWrite;
    }
    return 0;
}

DWORD ConsoleRedirect_ThreadConsoleOutput(PCONSOLEREDIR_THREADDATA pd)
{
    while(!pd->fTerminateThread) {
        *(pd->pInfoIS->con.pb + (pd->pInfoIS->con.cbRead % EXEC_IO_CONSOLE_BUFFER_SIZE)) = (BYTE)getchar();
        pd->pInfoIS->con.cbRead++;
        while(pd->pInfoIS->con.cbRead - pd->pInfoOS->con.cbReadAck >= EXEC_IO_CONSOLE_BUFFER_SIZE) {
            Sleep(10);
        }
    }
    return 0;
}

BOOL Exec_ConsoleRedirect_Initialize(_In_ QWORD ConsoleBufferAddr_InputStream, _In_ QWORD ConsoleBufferAddr_OutputStream, _In_ DWORD dwPID, _Inout_ PCONSOLEREDIR_THREADDATA pd)
{
    BOOL result;
    pd->pInfoIS = (PEXEC_IO)pd->pbDataISConsoleBuffer;
    pd->pInfoOS = (PEXEC_IO)pd->pbDataOSConsoleBuffer;
    // read initial buffer and check validity
    result = dwPID ?
        Vmmx_MemReadEx(dwPID, ConsoleBufferAddr_OutputStream, pd->pbDataOSConsoleBuffer, 0x1000, NULL, VMMDLL_FLAG_NOCACHE) :
        DeviceReadMEM(ConsoleBufferAddr_OutputStream, 0x1000, pd->pbDataOSConsoleBuffer, FALSE);
    if(!result || (pd->pInfoOS->magic != EXEC_IO_MAGIC)) {
        return FALSE;
    }
    // create worker threads
    pd->hThreadIS = CreateThread(NULL, 0, ConsoleRedirect_ThreadConsoleInput, pd, 0, NULL);
    pd->hThreadOS = CreateThread(NULL, 0, ConsoleRedirect_ThreadConsoleOutput, pd, 0, NULL);
    return TRUE;
}

/*
* Execute a console redirect
* -- ConsoleBufferAddr_InputStream = physical or virtual address.
* -- ConsoleBufferAddr_OutputStream = physical or virtual address.
* -- dwPID = zero if physical address read, non-zero if virtual address read.
*/
VOID Exec_ConsoleRedirect(_In_ QWORD ConsoleBufferAddr_InputStream, _In_ QWORD ConsoleBufferAddr_OutputStream, _In_ DWORD dwPID)
{
    BOOL result;
    PCONSOLEREDIR_THREADDATA pd = LocalAlloc(LMEM_ZEROINIT, sizeof(CONSOLEREDIR_THREADDATA));
    if(!pd) { return; }
    result = Exec_ConsoleRedirect_Initialize(ConsoleBufferAddr_InputStream, ConsoleBufferAddr_OutputStream, dwPID, pd);
    if(!result) {
        printf("\nCONSOLE_REDIRECT: Error: Address 0x%016llX does not\ncontain a valid console buffer.\n", ConsoleBufferAddr_OutputStream);
        goto fail;
    }
    // buffer syncer
    while(TRUE) {
        SwitchToThread();
        result = dwPID ?
            Vmmx_MemReadEx(dwPID, ConsoleBufferAddr_OutputStream, pd->pbDataOSConsoleBuffer, 0x1000, NULL, VMMDLL_FLAG_NOCACHE) :
            DeviceReadMEM(ConsoleBufferAddr_OutputStream, 0x1000, pd->pbDataOSConsoleBuffer, FALSE);
        if(!result || pd->pInfoOS->magic != EXEC_IO_MAGIC) {
            printf("\nCONSOLE_REDIRECT: Error: Address 0x%016llX does not\ncontain a valid console buffer.\n", ConsoleBufferAddr_OutputStream);
            goto fail;
        }
        if(dwPID) {
            Vmmx_MemWrite(dwPID, ConsoleBufferAddr_InputStream, pd->pbDataISConsoleBuffer, 0x1000);
        } else {
            DeviceWriteMEM(ConsoleBufferAddr_InputStream, 0x1000, pd->pbDataISConsoleBuffer, FALSE);
        }
    }
    fail:
    pd->fTerminateThread = TRUE;
}

VOID Exec_Callback(_Inout_ PHANDLE phCallback)
{
    BOOL result;
    PEXEC_HANDLE ph = *phCallback;
    QWORD cbLength;
    // initialize if not initialized previously.
    if(!*phCallback) {
        // core initialize
        ph = *phCallback = LocalAlloc(LMEM_ZEROINIT, sizeof(EXEC_HANDLE));
        if(!ph) { return; }
        ph->pbDMA = LocalAlloc(LMEM_ZEROINIT, ctxMain->pk->dataOutExtraLengthMax);
        if(!ph->pbDMA) { LocalFree(ph); *phCallback = NULL; return; }
        ph->is.magic = EXEC_IO_MAGIC;
        // open output file
        if(!fopen_s(&ph->pFileOutput, ctxMain->cfg.szFileOut, "r") || ph->pFileOutput) {
            if(ph->pFileOutput) {
                fclose(ph->pFileOutput);
            }
            printf("EXEC: Failed. File already exists: %s\n", ctxMain->cfg.szFileOut);
            return;
        }
        if(fopen_s(&ph->pFileOutput, ctxMain->cfg.szFileOut, "wb") || !ph->pFileOutput) {
            ph->is.bin.fCompletedAck = TRUE;
            LcWrite(ctxMain->hLC, ctxMain->pk->DMAAddrPhysical + EXEC_IO_DMAOFFSET_IS, 0x1000, (PBYTE)&ph->is);
            ph->fError = TRUE;
            printf("EXEC: Failed writing large outut to file: %s\n", ctxMain->cfg.szFileOut);
            return;
        }
        printf("EXEC: Start writing large output to file: %s\n", ctxMain->cfg.szFileOut);
    }
    // write to output file and ack to buffer
    if(ph->is.bin.fCompletedAck) { return; }
    LcRead(ctxMain->hLC, ctxMain->pk->DMAAddrPhysical + EXEC_IO_DMAOFFSET_OS, 0x1000, (PBYTE)&ph->os);
    if(ph->os.magic != EXEC_IO_MAGIC) { return; }
    if(ph->is.bin.seqAck >= ph->os.bin.seq) { return; }
    cbLength = 0;
    result =
        DeviceReadDMA(ctxMain->pk->DMAAddrPhysical + ctxMain->pk->dataOutExtraOffset, (DWORD)SIZE_PAGE_ALIGN_4K(ctxMain->pk->dataOutExtraLength), ph->pbDMA, NULL) &&
        (cbLength = fwrite(ph->pbDMA, 1, ctxMain->pk->dataOutExtraLength, ph->pFileOutput)) &&
        (ctxMain->pk->dataOutExtraLength == cbLength);
    ph->qwFileWritten += cbLength;
    ph->fError = !result;
    ph->is.bin.fCompletedAck = ph->is.bin.fCompletedAck || ph->os.bin.fCompleted || !result;
    ph->is.bin.seqAck = ph->os.bin.seq;
    LcWrite(ctxMain->hLC, ctxMain->pk->DMAAddrPhysical + EXEC_IO_DMAOFFSET_IS, 0x1000, (PBYTE)&ph->is);
}

VOID Exec_CallbackClose(_In_opt_ HANDLE hCallback)
{
    PEXEC_HANDLE ph = hCallback;
    if(hCallback == NULL) { return; }
    if(ph->pFileOutput) {
        if(ph->fError) {
            printf("EXEC: Failed writing large outut to file: %s\n", ctxMain->cfg.szFileOut);
        } else {
            printf("EXEC: Successfully wrote %i bytes.\n", (DWORD)ph->qwFileWritten);
        }
    }
    if(ph->pFileOutput) { fclose(ph->pFileOutput); }
    LocalFree(ph->pbDMA);
    LocalFree(ph);
}

_Success_(return)
BOOL Exec_ExecSilent(_In_ LPSTR szShellcodeName, _In_ PBYTE pbIn, _In_ QWORD cbIn, _Out_opt_ PBYTE *ppbOut, _Out_opt_ PQWORD pcbOut)
{
    PKMDDATA pk = ctxMain->pk;
    BOOL result = FALSE;
    DWORD cbBuffer;
    PBYTE pbBuffer = NULL;
    PKMDEXEC pKmdExec = NULL;
    //------------------------------------------------
    // 1: Setup and initial validity checks.
    //------------------------------------------------
    if(!ctxMain->phKMD) { goto fail; }
    result = Util_LoadKmdExecShellcode(szShellcodeName, &pKmdExec);
    if(!result) { goto fail; }
    cbBuffer = SIZE_PAGE_ALIGN_4K(pKmdExec->cbShellcode) + SIZE_PAGE_ALIGN_4K(cbIn);
    if(!result || (ctxMain->pk->DMASizeBuffer < cbBuffer)) { result = FALSE;  goto fail; }
    pbBuffer = LocalAlloc(LMEM_ZEROINIT, cbBuffer);
    if(!pbBuffer) { result = FALSE;  goto fail; }
    //------------------------------------------------
    // 2: Set up shellcode and indata and write to target memory.
    //    X, Y = page aligned.
    //    [0 , Y       [ = shellcode
    //    [Y , X       [ = data in (to target computer)
    //    [X , buf_max [ = data out (from target computer)
    //------------------------------------------------
    memcpy(pbBuffer, pKmdExec->pbShellcode, pKmdExec->cbShellcode);
    memcpy(pbBuffer + SIZE_PAGE_ALIGN_4K(pKmdExec->cbShellcode), pbIn, cbIn);
    result = DeviceWriteDMA_Retry(ctxMain->hLC, pk->DMAAddrPhysical, cbBuffer, pbBuffer);
    if(!result) { goto fail; }
    pk->dataInExtraOffset = SIZE_PAGE_ALIGN_4K(pKmdExec->cbShellcode);
    pk->dataInExtraLength = cbIn;
    pk->dataInExtraLengthMax = SIZE_PAGE_ALIGN_4K(cbIn);
    pk->dataOutExtraOffset = pk->dataInExtraOffset + pk->dataInExtraLengthMax;
    pk->dataOutExtraLength = 0;
    pk->dataOutExtraLengthMax = pk->DMASizeBuffer - pk->dataOutExtraOffset;
    //------------------------------------------------ 
    // 3: Execute!
    //------------------------------------------------
    KMD_SubmitCommand(KMD_CMD_VOID);
    result = KMD_SubmitCommand(KMD_CMD_EXEC);
    if(!result || pk->dataOut[0] || (pk->dataOutExtraLength > pk->dataOutExtraLengthMax)) {
        result = FALSE;
        goto fail;
    }
    //------------------------------------------------
    // 5: Display/Write additional output.
    //------------------------------------------------
    if(ppbOut && pcbOut) {
        *pcbOut = pk->dataOutExtraLength;
        *ppbOut = (PBYTE)LocalAlloc(0, SIZE_PAGE_ALIGN_4K(*pcbOut));
        if(!*ppbOut) { result = FALSE; goto fail; }
        result = SIZE_PAGE_ALIGN_4K(*pcbOut) == DeviceReadDMA(pk->DMAAddrPhysical + pk->dataOutExtraOffset, SIZE_PAGE_ALIGN_4K(*pcbOut), *ppbOut, NULL);
    }
fail:
    LocalFree(pKmdExec);
    LocalFree(pbBuffer);
    return result;
}

VOID ActionExecShellcode()
{
    BOOL result;
    PKMDEXEC pKmdExec = NULL;
    PBYTE pbBuffer = NULL;
    BYTE pbZeroPage2[0x2000] = { 0 };
    PSTR szBufferText = NULL;
    DWORD cbLength;
    FILE *pFile = NULL;
    PKMDDATA pk = ctxMain->pk;
    //------------------------------------------------ 
    // 1: Setup and initial validity checks.
    //------------------------------------------------
    if(!ctxMain->phKMD) {
        printf("EXEC: Failed. Executing code requires an active kernel module (KMD).\n      Please use in conjunction with the -kmd option only.\n");
        goto fail;
    }
    if(pk->DMASizeBuffer < 0x084000 + 0x100000 + min(0x100000, SIZE_PAGE_ALIGN_4K(ctxMain->cfg.cbIn))) {
        printf("EXEC: Failed. DMA buffer is too small / input size exceeded.\n");
        goto fail;
    }
    //------------------------------------------------ 
    // 2: Load KMD shellcode and commit to target memory.
    //------------------------------------------------
    result = Util_LoadKmdExecShellcode(ctxMain->cfg.szShellcodeName, &pKmdExec);
    if(!result) {
        printf("EXEC: Failed loading shellcode from file: '%s.ksh' ...\n", ctxMain->cfg.szShellcodeName);
        goto fail;
    }
    result = DeviceWriteDMA_Verify(ctxMain->hLC, pk->DMAAddrPhysical, (DWORD)pKmdExec->cbShellcode, pKmdExec->pbShellcode);
    if(!result) {
        printf("EXEC: Failed writing shellcode to target memory.\n");
        goto fail;
    }
    //------------------------------------------------ 
    // 3: Set up indata and write to target memory.
    //    Memory layout of DMA buffer:
    //    [0x000000, 0x080000[ = shellcode
    //    [0x080000          ] = (shellcode initiated com buffer for console and data transfer (input  to   implant) [IS])
    //    [0x081000          ] = (shellcode initiated com buffer for console and data transfer (output from implant) [OS])
    //    [0x082000, X       [ = data in (to target computer); X = max(0x100000, cb_in)
    //    [X       , buf_max [ = data out (from target computer)
    //------------------------------------------------
    LcWrite(ctxMain->hLC, pk->DMAAddrPhysical + 0x080000, 0x2000, pbZeroPage2);
    pk->dataInExtraOffset = 0x082000;
    pk->dataInExtraLength = ctxMain->cfg.cbIn;
    pk->dataInExtraLengthMax = max(0x100000, SIZE_PAGE_ALIGN_4K(ctxMain->cfg.cbIn));
    pk->dataOutExtraOffset = pk->dataInExtraOffset + pk->dataInExtraLengthMax;
    pk->dataOutExtraLength = 0;
    pk->dataOutExtraLengthMax = pk->DMASizeBuffer - pk->dataOutExtraOffset;
    memcpy(pk->dataIn, ctxMain->cfg.qwDataIn, sizeof(QWORD) * 10);
    memcpy(pk->dataInStr, ctxMain->cfg.szInS, MAX_PATH);
    memset(pk->dataOut, 0, sizeof(QWORD) * 10);
    memset(pk->dataOutStr, 0, MAX_PATH);
    if(ctxMain->cfg.cbIn) {
        result = LcWrite(ctxMain->hLC, pk->DMAAddrPhysical + pk->dataInExtraOffset, (DWORD)SIZE_PAGE_ALIGN_4K(ctxMain->cfg.cbIn), ctxMain->cfg.pbIn);
        if(!result) {
            printf("EXEC: Failed writing data to target memory.\n");
            goto fail;
        }
    }
    pk->dataInConsoleBuffer = 0;
    pk->dataOutConsoleBuffer = 0;
    //------------------------------------------------ 
    // 4: Execute! and display result.
    //------------------------------------------------
    KMD_SubmitCommand(KMD_CMD_VOID);
    result = KMD_SubmitCommand(KMD_CMD_EXEC);
    if(!result) {
        printf("EXEC: Failed sending execute command to KMD.\n");
        goto fail;
    }
    printf("EXEC: SUCCESS! shellcode should now execute in kernel!\nPlease see below for results.\n\n");
    printf(pKmdExec->szOutFormatPrintf,
        pk->dataOutStr,
        pk->dataOut[0],
        pk->dataOut[1],
        pk->dataOut[2],
        pk->dataOut[3],
        pk->dataOut[4],
        pk->dataOut[5],
        pk->dataOut[6],
        pk->dataOut[7],
        pk->dataOut[8],
        pk->dataOut[9]);
    //------------------------------------------------ 
    // 5: Display/Write additional output.
    //------------------------------------------------
    cbLength = (DWORD)pk->dataOutExtraLength;
    if(cbLength > 0) {
        // read extra output buffer
        if(!(pbBuffer = LocalAlloc(LMEM_ZEROINIT, SIZE_PAGE_ALIGN_4K(cbLength))) ||
            !DeviceReadDMA(pk->DMAAddrPhysical + pk->dataOutExtraOffset, SIZE_PAGE_ALIGN_4K(cbLength), pbBuffer, NULL)) {
            printf("EXEC: Error reading output.\n");
            goto fail;
        }
        // print to screen
        Util_PrintHexAscii(pbBuffer, cbLength, 0);
        // write to out file
        if(ctxMain->cfg.szFileOut[0]) {
            // open output file
            if(!fopen_s(&pFile, ctxMain->cfg.szFileOut, "r") || pFile) {
                printf("EXEC: Error writing output to file. File already exists: %s\n", ctxMain->cfg.szFileOut);
                goto fail;
            }
            if(fopen_s(&pFile, ctxMain->cfg.szFileOut, "wb") || !pFile) {
                printf("EXEC: Error writing output to file.\n");
                goto fail;
            }
            if(cbLength != fwrite(pbBuffer, 1, cbLength, pFile)) {
                printf("EXEC: Error writing output to file.\n");
                goto fail;
            }
            printf("EXEC: Wrote %i bytes to file %s.\n", cbLength, ctxMain->cfg.szFileOut);
        }
    }
    //----------------------------------------------------------
    // 6: Call the post execution console redirection if needed.
    //----------------------------------------------------------
    if(pk->dataInConsoleBuffer || pk->dataOutConsoleBuffer) {
        Exec_ConsoleRedirect(pk->dataInConsoleBuffer, pk->dataOutConsoleBuffer, 0);
    }
    printf("\n");
fail:
    LocalFree(pKmdExec);
    LocalFree(pbBuffer);
    LocalFree(szBufferText);
    if(pFile) { fclose(pFile); }
}

VOID ActionSvcExecPy()
{
    BOOL result;
    DWORD cbResult = 0;
    PBYTE pbResult = NULL;
    FILE *pFile = NULL;
    if(!ctxMain->cfg.pbIn || (ctxMain->cfg.cbIn < 4)) {
        printf("AGENT-PYEXEC: Failed. Input file not valid. Please supply input file in -in option.\n");
        return;
    }
    printf("AGENT-PYEXEC: Sending script to remote LeechAgent for processing.\n");
    printf("AGENT-PYEXEC: Waiting for result ...\n");
    result = LcCommand(ctxMain->hLC, LC_CMD_AGENT_EXEC_PYTHON, (DWORD)ctxMain->cfg.cbIn, ctxMain->cfg.pbIn, &pbResult, &cbResult);
    if(!result) {
        printf("AGENT-PYEXEC: Failed.\n");
        return;
    }
    if(pbResult && (cbResult > 0)) {
        cbResult -= 1;  // remove length of string null terminator.
        // write to out file
        if(ctxMain->cfg.szFileOut[0]) {
            // open output file
            if(!fopen_s(&pFile, ctxMain->cfg.szFileOut, "r") || pFile) {
                printf("AGENT-PYEXEC: Error writing output to file. File already exists: %s\n", ctxMain->cfg.szFileOut);
                goto fail;
            }
            if(fopen_s(&pFile, ctxMain->cfg.szFileOut, "wb") || !pFile) {
                printf("AGENT-PYEXEC: Error writing output to file.\n");
                goto fail;
            }
            if(cbResult != fwrite(pbResult, 1, cbResult, pFile)) {
                printf("AGENT-PYEXEC: Error writing output to file.\n");
                goto fail;
            }
            printf("AGENT-PYEXEC: Wrote %i bytes to file %s.\n", cbResult, ctxMain->cfg.szFileOut);
        }
        // print to screen
        printf("AGENT-PYEXEC: Please see result below: \n================================ \n");
        Util_AsciiFilter(pbResult, cbResult); // filter away potentially harmful chars from untrusted remote input
        printf("%s\n", (LPSTR)pbResult);
    }

fail:
    if(pFile) { fclose(pFile); }
    LcMemFree(pbResult);
}

