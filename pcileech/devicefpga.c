// devicefpga.h : implementation related to the:
//     - Xilinx SP605 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - Xilinx AC701 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - PCIeScreamer board flashed with PCILeech bitstream.
//
// (c) Ulf Frisk, 2017-2018
// Author: Ulf Frisk, pcileech@frizk.net
//

#include "devicefpga.h"
#include "device.h"
#include "tlp.h"
#include "util.h"

//-------------------------------------------------------------------------------
// FPGA defines below.
//-------------------------------------------------------------------------------

#define FPGA_CMD_VERSION_MAJOR  0x01
#define FPGA_CMD_DEVICE_ID      0x03
#define FPGA_CMD_VERSION_MINOR  0x05

#define ENDIAN_SWAP_WORD(x)     (x = (x << 8) | (x >> 8))
#define ENDIAN_SWAP_DWORD(x)    (x = (x << 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x >> 24))

typedef struct tdDEV_CFG_PHY {
    BYTE magic;
    BYTE tp_cfg : 4;
    BYTE tp : 4;
    struct {
        BYTE pl_directed_link_auton : 1;
        BYTE pl_directed_link_change : 2;
        BYTE pl_directed_link_speed : 1;
        BYTE pl_directed_link_width : 2;
        BYTE pl_upstream_prefer_deemph : 1;
        BYTE pl_transmit_hot_rst : 1;
        BYTE pl_downstream_deemph_source : 1;
        BYTE _filler : 7;
    } wr;
    struct {
        BYTE pl_ltssm_state : 6;
        BYTE pl_rx_pm_state : 2;
        BYTE pl_tx_pm_state : 3;
        BYTE pl_initial_link_width : 3;
        BYTE pl_lane_reversal_mode : 2;
        BYTE pl_sel_lnk_width : 2;
        BYTE pl_phy_lnk_up : 1;
        BYTE pl_link_gen2_cap : 1;
        BYTE pl_link_partner_gen2_supported : 1;
        BYTE pl_link_upcfg_cap : 1;
        BYTE pl_sel_lnk_rate : 1;
        BYTE pl_directed_change_done : 1;
        BYTE pl_received_hot_rst : 1;
        BYTE _filler : 7;
    } rd;
} DEV_CFG_PHY, *PDEV_CFG_PHY;

typedef struct tdDEVICE_PERFORMANCE {
    LPSTR SZ_DEVICE_NAME;
    DWORD PROBE_MAXPAGES;    // 0x400
    DWORD RX_FLUSH_LIMIT;
    DWORD MAX_SIZE_RX;        // in data bytes (excl. overhead/TLP headers)
    DWORD MAX_SIZE_TX;        // in total data (incl. overhead/TLP headers)
    DWORD DELAY_PROBE_READ;
    DWORD DELAY_PROBE_WRITE;
    DWORD DELAY_WRITE;
    DWORD DELAY_READ;
    BOOL RETRY_ON_ERROR;
} DEVICE_PERFORMANCE, *PDEVICE_PERFORMANCE;

#define DEVICE_ID_SP605_FT601                   0
#define DEVICE_ID_PCIESCREAMER                  1
#define DEVICE_ID_AC701_FT601                   2

#define PERFORMANCE_PROFILE_SP605_FT601         0
#define PERFORMANCE_PROFILE_PCIESCREAMER        1
#define PERFORMANCE_PROFILE_AC701_FT601         2
#define PERFORMANCE_PROFILE_MAX                 2

const DEVICE_PERFORMANCE PERFORMANCE_PROFILES[PERFORMANCE_PROFILE_MAX + 1] = {
    {
        .SZ_DEVICE_NAME = "SP605 / FT601",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0x8000,
        .MAX_SIZE_RX = 0x1f000,
        .MAX_SIZE_TX = 0x2000,
        .DELAY_PROBE_READ = 500,
        .DELAY_PROBE_WRITE = 0,
        .DELAY_WRITE = 175,
        .DELAY_READ = 400,
        .RETRY_ON_ERROR = FALSE
    }, {
        // The PCIeScreamer or at least the current bitstream implementation running
        // on it have a problem with the PCIe link stability which results on lost or
        // delayed TLPS - workarounds are in place to retry after a delay.
        .SZ_DEVICE_NAME = "PCIeScreamer",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x1c000,
        .MAX_SIZE_TX = 0x1000,
        .DELAY_PROBE_READ = 1000,
        .DELAY_PROBE_WRITE = 150,
        .DELAY_WRITE = 0,
        .DELAY_READ = 500,
        .RETRY_ON_ERROR = TRUE
    }, {
        .SZ_DEVICE_NAME = "AC701 / FT601",
        .PROBE_MAXPAGES = 0x400,
        .RX_FLUSH_LIMIT = 0xfffff000,
        .MAX_SIZE_RX = 0x20000,
        .MAX_SIZE_TX = 0x8000,
        .DELAY_PROBE_READ = 500,
        .DELAY_PROBE_WRITE = 0,
        .DELAY_WRITE = 0,
        .DELAY_READ = 300,
        .RETRY_ON_ERROR = FALSE
    }
};

typedef struct tdDEVICE_CONTEXT_FPGA {
    WORD wDeviceId;
    WORD wFpgaVersionMajor;
    WORD wFpgaVersionMinor;
    WORD wFpgaID;
    BOOL phySupported;
    DEV_CFG_PHY phy;
    DEVICE_PERFORMANCE perf;
    BOOL isPrintTlp;
    struct {
        PBYTE pb;
        DWORD cb;
        DWORD cbMax;
    } rxbuf;
    struct {
        PBYTE pb;
        DWORD cb;
        DWORD cbMax;
    } txbuf;
    struct {
        HMODULE hModule;
        HANDLE hFTDI;
        ULONG(*pfnFT_Create)(
            PVOID pvArg, 
            DWORD dwFlags, 
            HANDLE *pftHandle
        );
        ULONG(*pfnFT_Close)(
            HANDLE ftHandle
        );
        ULONG(*pfnFT_WritePipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID,
            PUCHAR pucBuffer,
            ULONG ulBufferLength,
            PULONG pulBytesTransferred,
            LPOVERLAPPED pOverlapped
        );
        ULONG(*pfnFT_ReadPipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID,
            PUCHAR pucBuffer,
            ULONG ulBufferLength,
            PULONG pulBytesTransferred,
            LPOVERLAPPED pOverlapped
        );
        ULONG(*pfnFT_AbortPipe)(
            HANDLE ftHandle,
            UCHAR ucPipeID
        );
    } dev;
    PVOID pMRdBufferX; // NULL || PTLP_CALLBACK_BUF_MRd || PTLP_CALLBACK_BUF_MRd_2
    VOID(*hRxTlpCallbackFn)(_Inout_ PVOID pBufferMrd, _In_ PBYTE pb, _In_ DWORD cb);
    BYTE RxEccBit;
} DEVICE_CONTEXT_FPGA, *PDEVICE_CONTEXT_FPGA;

// STRUCT FROM FTD3XX.h
typedef struct {
    USHORT       VendorID;
    USHORT       ProductID;
    UCHAR        StringDescriptors[128];
    UCHAR        Reserved;
    UCHAR        PowerAttributes;
    USHORT       PowerConsumption;
    UCHAR        Reserved2;
    UCHAR        FIFOClock;
    UCHAR        FIFOMode;
    UCHAR        ChannelConfig;
    USHORT       OptionalFeatureSupport;
    UCHAR        BatteryChargingGPIOConfig;
    UCHAR        FlashEEPROMDetection;
    ULONG        MSIO_Control;
    ULONG        GPIO_Control;
} FT_60XCONFIGURATION, *PFT_60XCONFIGURATION;

//-------------------------------------------------------------------------------
// FPGA implementation below:
//-------------------------------------------------------------------------------

LPSTR DeviceFPGA_InitializeFTDI(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    LPSTR szErrorReason;
    CHAR c;
    DWORD status;
    ULONG(*pfnFT_GetChipConfiguration)(HANDLE ftHandle, PVOID pvConfiguration);
    ULONG(*pfnFT_SetChipConfiguration)(HANDLE ftHandle, PVOID pvConfiguration);
    FT_60XCONFIGURATION oCfgNew, oCfgOld;
    // Load FTDI Library
    ctx->dev.hModule = LoadLibrary(L"FTD3XX.dll");
    if(!ctx->dev.hModule) { 
        szErrorReason = "Unable to load FTD3XX.dll";
        goto fail; 
    }
    ctx->dev.pfnFT_AbortPipe = (ULONG(*)(HANDLE, UCHAR))
        GetProcAddress(ctx->dev.hModule, "FT_AbortPipe");
    ctx->dev.pfnFT_Create = (ULONG(*)(PVOID, DWORD, HANDLE*))
        GetProcAddress(ctx->dev.hModule, "FT_Create");
    ctx->dev.pfnFT_Close = (ULONG(*)(HANDLE))
        GetProcAddress(ctx->dev.hModule, "FT_Close");
    ctx->dev.pfnFT_ReadPipe = (ULONG(*)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_ReadPipe");
    ctx->dev.pfnFT_WritePipe = (ULONG(*)(HANDLE, UCHAR, PUCHAR, ULONG, PULONG, LPOVERLAPPED))
        GetProcAddress(ctx->dev.hModule, "FT_WritePipe");
    pfnFT_GetChipConfiguration = (ULONG(*)(HANDLE, PVOID))GetProcAddress(ctx->dev.hModule, "FT_GetChipConfiguration");
    pfnFT_SetChipConfiguration = (ULONG(*)(HANDLE, PVOID))GetProcAddress(ctx->dev.hModule, "FT_SetChipConfiguration");
    if(!ctx->dev.pfnFT_Create) {
        szErrorReason = "Unable to retrieve required functions from FTD3XX.dll";
        goto fail; 
    }
    // Open FTDI
    status = ctx->dev.pfnFT_Create(NULL, 0x10 /*FT_OPEN_BY_INDEX*/, &ctx->dev.hFTDI);
    if(status || !ctx->dev.hFTDI) { 
        szErrorReason = "Unable to connect to USB/FT601 device";
        goto fail; 
    }
    ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x02);
    ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x82);
    // Check FTDI chip configuration and update if required
    status = pfnFT_GetChipConfiguration(ctx->dev.hFTDI, &oCfgOld);
    if(status) { 
        szErrorReason = "Unable to retrieve device configuration";
        goto fail; 
    }
    memcpy(&oCfgNew, &oCfgOld, sizeof(FT_60XCONFIGURATION));
    oCfgNew.FIFOMode = 0; // FIFO MODE FT245
    oCfgNew.ChannelConfig = 2; // 1 CHANNEL ONLY
    oCfgNew.OptionalFeatureSupport = 0;
    if(memcmp(&oCfgNew, &oCfgOld, sizeof(FT_60XCONFIGURATION))) {
        printf(
            "IMPORTANT NOTE! FTDI FT601 USB CONFIGURATION DIFFERS FROM RECOMMENDED\n" \
            "PLEASE ENSURE THAT ONLY PCILEECH FPGA FTDI FT601 DEVICE IS CONNECED  \n" \
            "BEFORE UPDATING CONFIGURATION. DO YOU WISH TO CONTINUE Y/N?          \n"
        );
        while(TRUE) {
            c = (CHAR)getchar();
            if(c == 'Y' || c == 'y') { break; }
            if(c == 'N' || c == 'n') { 
                szErrorReason = "User abort required device configuration";
                goto fail; 
            }
            
        }
        status = pfnFT_SetChipConfiguration(ctx->dev.hFTDI, &oCfgNew);
        if(status) { 
            szErrorReason = "Unable to set required device configuration";
            goto fail;
        }
        printf("FTDI USB CONFIGURATION UPDATED - RESETTING AND CONTINUING ...\n");
        ctx->dev.pfnFT_Close(ctx->dev.hFTDI);
        FreeLibrary(ctx->dev.hModule);
        ctx->dev.hModule = NULL;
        ctx->dev.hFTDI = NULL;
        Sleep(3000);
        return DeviceFPGA_InitializeFTDI(ctx);
    }
    return NULL;
fail:
    if(ctx->dev.hFTDI && ctx->dev.pfnFT_Close) { ctx->dev.pfnFT_Close(ctx->dev.hFTDI); }
    if(ctx->dev.hModule) { FreeLibrary(ctx->dev.hModule); }
    ctx->dev.hModule = NULL;
    ctx->dev.hFTDI = NULL;
    return szErrorReason;
}

VOID DeviceFPGA_ReInitializeFTDI(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    // called to try to recover link in case of instable devices.
    ctx->dev.pfnFT_Close(ctx->dev.hFTDI);
    ctx->dev.hFTDI = NULL;
    Sleep(250);
    ctx->dev.pfnFT_Create(NULL, 0x10 /*FT_OPEN_BY_INDEX*/, &ctx->dev.hFTDI);
}

VOID DeviceFPGA_Close(_Inout_ PPCILEECH_CONTEXT ctxPcileech)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxPcileech->hDevice;
    if(!ctx) { return; }
    if(ctx->dev.hFTDI) { ctx->dev.pfnFT_Close(ctx->dev.hFTDI); }
    if(ctx->dev.hModule) { FreeLibrary(ctx->dev.hModule); }
    if(ctx->rxbuf.pb) { LocalFree(ctx->rxbuf.pb); }
    if(ctx->txbuf.pb) { LocalFree(ctx->txbuf.pb); }
    LocalFree(ctx);
    ctxPcileech->hDevice = 0;
}

BOOL DeviceFPGA_GetSetPHY(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ BOOL isUpdate)
{
    DWORD status;
    DWORD i, j, cbRxTx, dwStatus;
    PDWORD pdwData;
    BYTE pbRx[0x1000];
    BYTE pbTx[16] = {
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, // dummy: to be overwritten
        0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x03, 0x77, // cmd msg: version (filler)
    };
    if(isUpdate) {
        ctx->phy.magic = 0x77;
        ctx->phy.tp_cfg = 1;
        ctx->phy.tp = 4;
        *(PQWORD)pbTx = _byteswap_uint64(*(PQWORD)&ctx->phy);
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, sizeof(pbTx), &cbRxTx, NULL);
        if(status) { return FALSE; }
        Sleep(10);
    }
    *(PQWORD)&ctx->phy = 0;
    *(PQWORD)pbTx = 0x7731000000000000; // phy read (3) + cfg (1) + magic (77)
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTx, sizeof(pbTx), &cbRxTx, NULL);
    if(status) { return FALSE; }
    Sleep(10);
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRx, 0x1000, &cbRxTx, NULL);
    if(status) { return FALSE; }
    for(i = 0; i < cbRxTx; i += 32) {
        while(*(PDWORD)(pbRx + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
            i += 4;
            if(i + 32 > cbRxTx) { return FALSE; }
        }
        dwStatus = *(PDWORD)(pbRx + i);
        pdwData = (PDWORD)(pbRx + i + 4);
        if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
        for(j = 0; j < 7; j++) {
            if(((dwStatus & 0x03) == 0x01) && ((*pdwData & 0xffff0000) == 0x77310000)) { // PCIe CFG REPLY
                // sloppy algorithm below, but it works unless high amount of interfering incoming TLPs
                *(PQWORD)(&ctx->phy) = _byteswap_uint64(*(PQWORD)(pdwData - 1));
                return TRUE;
            }
            pdwData++;
            dwStatus >>= 4;
        }
    }
    return FALSE;
}

BYTE DeviceFPGA_PHY_GetLinkWidth(_In_ PDEVICE_CONTEXT_FPGA ctx) {
    const BYTE LINK_WIDTH[4] = { 1, 2, 4, 8 };
    return LINK_WIDTH[ctx->phy.rd.pl_sel_lnk_width];
}

BYTE DeviceFPGA_PHY_GetPCIeGen(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    return 1 + ctx->phy.rd.pl_sel_lnk_rate;
}

VOID DeviceFPGA_SetSpeedPCIeGen1(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    if(ctx->phySupported && ctx->phy.rd.pl_sel_lnk_rate) {
        ctx->phy.wr.pl_directed_link_auton = 1;
        ctx->phy.wr.pl_directed_link_speed = 0;
        ctx->phy.wr.pl_directed_link_change = 2;
        DeviceFPGA_GetSetPHY(ctx, TRUE);
    }
}

VOID DeviceFPGA_GetDeviceID_FpgaVersion(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DWORD status;
    DWORD cbTX, cbRX, i, j;
    PBYTE pbRX;
    DWORD dwStatus, dwData, cdwCfg = 0;
    PDWORD pdwData;
    BYTE pbTX[32] = {
        // cfg status: (pcie bus,dev,fn id)
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x01, 0x77,
        // cmd msg: FPGA bitstream version (major)
        0x00, 0x00, 0x00, 0x00,  0x01, 0x00, 0x03, 0x77,
        // cmd msg: FPGA bitstream version (minor)
        0x00, 0x00, 0x00, 0x00,  0x05, 0x00, 0x03, 0x77,
        // cmd msg: FPGA bitstream device id
        0x00, 0x00, 0x00, 0x00,  0x03, 0x00, 0x03, 0x77
    };
    if(!(pbRX = LocalAlloc(0, 0x01000000))) { return; }
    status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, pbTX, sizeof(pbTX), &cbTX, NULL);
    if(status) { goto fail; }
    Sleep(10);
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, pbRX, 0x01000000, &cbRX, NULL);
    if(status) { goto fail; }
    for(i = 0; i < cbRX; i += 32) {
        while(*(PDWORD)(pbRX + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
            i += 4;
            if(i + 32 > cbRX) { goto fail; }
        }
        dwStatus = *(PDWORD)(pbRX + i);
        pdwData = (PDWORD)(pbRX + i + 4);
        if((dwStatus & 0xf0000000) != 0xe0000000) { continue; }
        for(j = 0; j < 7; j++) {
            dwData = *pdwData;
            if((dwStatus & 0x03) == 0x03) { // CMD REPLY (or filler)
                switch(dwData >> 24) {
                    case FPGA_CMD_VERSION_MAJOR:
                        ctx->wFpgaVersionMajor = (WORD)dwData;
                        break;
                    case FPGA_CMD_VERSION_MINOR:
                        ctx->wFpgaVersionMinor = (WORD)dwData;
                        break;
                    case FPGA_CMD_DEVICE_ID:
                        ctx->wFpgaID = (WORD)dwData;
                        break;
                }
            }
            if((dwStatus & 0x03) == 0x01) { // PCIe CFG REPLY
                if(((++cdwCfg % 2) == 0) && (WORD)dwData) {    // DeviceID: (pcie bus,dev,fn id)
                    ctx->wDeviceId = (WORD)dwData;
                }
            }
            pdwData++;
            dwStatus >>= 4;
        }
    }
    ctx->phySupported = (ctx->wFpgaVersionMajor >= 3) ? DeviceFPGA_GetSetPHY(ctx, FALSE) : FALSE;
fail:
    LocalFree(pbRX);
}

VOID DeviceFPGA_SetPerformanceProfile(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _Inout_ PDEVICE_CONTEXT_FPGA ctx)
{
    switch(ctx->wFpgaID) {
        case DEVICE_ID_PCIESCREAMER:
            memcpy(&ctx->perf, &PERFORMANCE_PROFILES[PERFORMANCE_PROFILE_PCIESCREAMER], sizeof(DEVICE_PERFORMANCE));
            break;
        case DEVICE_ID_AC701_FT601:
            memcpy(&ctx->perf, &PERFORMANCE_PROFILES[PERFORMANCE_PROFILE_AC701_FT601], sizeof(DEVICE_PERFORMANCE));
            break;
        default:
        case DEVICE_ID_SP605_FT601:
            memcpy(&ctx->perf, &PERFORMANCE_PROFILES[PERFORMANCE_PROFILE_SP605_FT601], sizeof(DEVICE_PERFORMANCE));
            break;
    }
    ctx->perf.DELAY_READ = ctxPcileech->cfg->DeviceOpt[0].isValid ? (DWORD)ctxPcileech->cfg->DeviceOpt[0].qwValue : ctx->perf.DELAY_READ;
    ctx->perf.DELAY_WRITE = ctxPcileech->cfg->DeviceOpt[1].isValid ? (DWORD)ctxPcileech->cfg->DeviceOpt[1].qwValue : ctx->perf.DELAY_WRITE;
    ctx->perf.DELAY_PROBE_READ = ctxPcileech->cfg->DeviceOpt[2].isValid ? (DWORD)ctxPcileech->cfg->DeviceOpt[2].qwValue : ctx->perf.DELAY_PROBE_READ;
}

//-------------------------------------------------------------------------------
// TLP handling functionality below:
//-------------------------------------------------------------------------------

BOOL DeviceFPGA_TxTlp(_In_ PDEVICE_CONTEXT_FPGA ctx, _In_ PBYTE pbTlp, _In_ DWORD cbTlp, BOOL fRdKeepalive, BOOL fFlush)
{
    DWORD status;
    PBYTE pbTx;
    DWORD i, cbTx, cbTxed = 0;
    if(cbTlp & 0x3) { return FALSE; }
    if(cbTlp > 2048) { return FALSE; }
    if(ctx->isPrintTlp) {
        TLP_Print(pbTlp, cbTlp, TRUE);
    }
    // prepare transmit buffer
    pbTx = ctx->txbuf.pb + ctx->txbuf.cb;
    cbTx = 2 * cbTlp;
    for(i = 0; i < cbTlp; i += 4) {
        *(PDWORD)(pbTx + (i << 1)) = *(PDWORD)(pbTlp + i);
        *(PDWORD)(pbTx + ((i << 1) + 4)) = 0x77000000;    // TX TLP
    } 
    if(cbTlp) {
        *(PDWORD)(pbTx + ((i << 1) - 4)) = 0x77040000;    // TX TLP VALID LAST
    }
    if(fRdKeepalive) {
        cbTx += 8;
        *(PDWORD)(pbTx + (i << 1)) = 0xffeeddcc;
        *(PDWORD)(pbTx + ((i << 1) + 4)) = 0x77020000;    // LOOPBACK TX
    }
    ctx->txbuf.cb += cbTx;
    // transmit
    if((ctx->txbuf.cb > ctx->perf.MAX_SIZE_TX) || (fFlush && ctx->txbuf.cb)) {
        status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, ctx->txbuf.pb, ctx->txbuf.cb, &cbTxed, NULL);
        if(status == 0x20 && ctx->perf.RETRY_ON_ERROR) {
            DeviceFPGA_ReInitializeFTDI(ctx); // try recovery if possible.
            status = ctx->dev.pfnFT_WritePipe(ctx->dev.hFTDI, 0x02, ctx->txbuf.pb, ctx->txbuf.cb, &cbTxed, NULL);
        }
        ctx->txbuf.cb = 0;
        return (0 == status);
    }
    return TRUE;
}

#define TLP_RX_MAX_SIZE        2048
VOID DeviceFPGA_RxTlpSynchronous(_In_ PDEVICE_CONTEXT_FPGA ctx)
{
    DWORD status;
    DWORD i, j, cdwTlp = 0;
    BYTE pbTlp[TLP_RX_MAX_SIZE];
    PDWORD pdwTlp = (PDWORD)pbTlp;
    PDWORD pdwRx = (PDWORD)ctx->rxbuf.pb;
    DWORD dwStatus, *pdwData;
    status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, ctx->rxbuf.pb, ctx->rxbuf.cbMax, &ctx->rxbuf.cb, NULL);
    if(status == 0x20 && ctx->perf.RETRY_ON_ERROR) {
        DeviceFPGA_ReInitializeFTDI(ctx); // try recovery if possible.
        status = ctx->dev.pfnFT_ReadPipe(ctx->dev.hFTDI, 0x82, ctx->rxbuf.pb, ctx->rxbuf.cbMax, &ctx->rxbuf.cb, NULL);
    }
    if(status) {
        ctx->dev.pfnFT_AbortPipe(ctx->dev.hFTDI, 0x82);
        return;
    }
    for(i = 0; i < ctx->rxbuf.cb; i += 32) { // index in 64-bit (QWORD)
        while(*(PDWORD)(ctx->rxbuf.pb + i) == 0x55556666) { // skip over ftdi workaround dummy fillers
            i += 4;
            if(i + 32 > ctx->rxbuf.cb) { return; }
        }
        dwStatus = *(PDWORD)(ctx->rxbuf.pb + i);
        pdwData = (PDWORD)(ctx->rxbuf.pb + i + 4);
        if((dwStatus & 0xf0000000) != 0xe0000000) { 
            continue; 
        }
        for(j = 0; j < 7; j++) {
            if((dwStatus & 0x03) == 0x00) { // PCIe TLP
                pdwTlp[cdwTlp] = *pdwData;
                cdwTlp++;
                if(cdwTlp >= TLP_RX_MAX_SIZE / sizeof(DWORD)) { return; }
            }
            if((dwStatus & 0x07) == 0x04) { // PCIe TLP and LAST
                if(cdwTlp >= 3) {
                    if(ctx->isPrintTlp) {
                        TLP_Print(pbTlp, cdwTlp << 2, FALSE);
                    }
                    if(ctx->hRxTlpCallbackFn) {
                        ctx->hRxTlpCallbackFn(ctx->pMRdBufferX, pbTlp, cdwTlp << 2);
                    }
                } else {
                    printf("Device Info: FPGA: Bad PCIe TLP received! Should not happen!\n");
                }
                cdwTlp = 0;
            }
            pdwData++;
            dwStatus >>= 4;
        }
    }
}

VOID DeviceFPGA_ReadScatterDMA_Impl(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _Inout_ PPDMA_IO_SCATTER_HEADER ppDMAs, _In_ DWORD cpDMAs)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxPcileech->hDevice;
    TLP_CALLBACK_BUF_MRd_SCATTER rxbuf;
    DWORD tx[4] = { 0 };
    DWORD o, i, j, cb, cbFlush, cbTotalInCycle = 0;
    BOOL isAlgorithmReadTiny;
    BOOL is32;
    PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
    PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
    PDMA_IO_SCATTER_HEADER pDMA;
    BYTE bTag;
    isAlgorithmReadTiny = (1 == ctxPcileech->cfg->DeviceOpt[3].qwValue);
    i = 0;
    ctx->pMRdBufferX = &rxbuf;
    while(i < cpDMAs) {
        // Prepare callback buffer
        ctx->RxEccBit = ctx->RxEccBit ? 0 : 1;
        rxbuf.bEccBit = ctx->RxEccBit;
        rxbuf.cbReadTotal = 0;
        rxbuf.cph = cpDMAs - i;
        rxbuf.pph = ppDMAs + i;
        ctx->hRxTlpCallbackFn = (VOID(*)(PVOID, PBYTE, DWORD))TLP_CallbackMRd_Scatter;
        // Transmit TLPs
        cbFlush = 0;
        cbTotalInCycle = 0;
        bTag = (ctx->RxEccBit ? 0x80 : 0) + (isAlgorithmReadTiny ? 0x40 : 0);
        for(; i < cpDMAs; i++) {
            pDMA = *(ppDMAs + i);
            if((pDMA->cbMax <= pDMA->cb) || (pDMA->cbMax % 8) || (pDMA->cbMax > 0x1000)) { // already completed or unsupported size -> skip over
                bTag += isAlgorithmReadTiny ? 0x20 : 1;
                if(!(bTag & 0x3f)) { break; }
                continue;
            }
            cbTotalInCycle += pDMA->cbMax;
            if(cbTotalInCycle > ctx->perf.MAX_SIZE_RX) { break; } // over max size -> break loop and read result
            o = 0;
            while(o < pDMA->cbMax) {
                cb = isAlgorithmReadTiny ? 0x80 : pDMA->cbMax;
                is32 = pDMA->qwA + o < 0x100000000;
                if(is32) {
                    hdrRd32->h.TypeFmt = TLP_MRd32;
                    hdrRd32->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
                    hdrRd32->RequesterID = ctx->wDeviceId;
                    hdrRd32->Tag = bTag;
                    hdrRd32->FirstBE = 0xf;
                    hdrRd32->LastBE = 0xf;
                    hdrRd32->Address = (DWORD)(pDMA->qwA + o);
                } else {
                    hdrRd64->h.TypeFmt = TLP_MRd64;
                    hdrRd64->h.Length = (WORD)((cb < 0x1000) ? cb >> 2 : 0);
                    hdrRd64->RequesterID = ctx->wDeviceId;
                    hdrRd64->Tag = bTag;
                    hdrRd64->FirstBE = 0xf;
                    hdrRd64->LastBE = 0xf;
                    hdrRd64->AddressHigh = (DWORD)((pDMA->qwA + o) >> 32);
                    hdrRd64->AddressLow = (DWORD)(pDMA->qwA + o);
                }
                for(j = 0; j < 4; j++) {
                    ENDIAN_SWAP_DWORD(tx[j]);
                }
                cbFlush += cb;
                if((cbFlush >= ctx->perf.RX_FLUSH_LIMIT) || (isAlgorithmReadTiny && (cbFlush >= 0x1000))) {
                    DeviceFPGA_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, TRUE);
                    usleep(ctx->perf.DELAY_WRITE);
                    cbFlush = 0;
                } else {
                    DeviceFPGA_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, FALSE);
                }
                o += cb;
                bTag++;
            }
            if(isAlgorithmReadTiny && ((bTag & 0x3f) < 0x20)) { bTag = 0x20; }
            if(!(bTag & 0x3f)) { break; }
        }
        // Receive TLPs
        DeviceFPGA_TxTlp(ctx, NULL, 0, TRUE, TRUE);
        usleep(ctx->perf.DELAY_READ);
        DeviceFPGA_RxTlpSynchronous(ctx);
    }
    ctx->pMRdBufferX = NULL;
}

VOID DeviceFPGA_ReadScatterDMA(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _Inout_ PPDMA_IO_SCATTER_HEADER ppDMAs, _In_ DWORD cpDMAs, _Out_opt_ PDWORD pchDMAsRead)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxPcileech->hDevice;
    DWORD i = 0, c = 0;
    BOOL fRetry = FALSE;
    DeviceFPGA_ReadScatterDMA_Impl(ctxPcileech, ppDMAs, cpDMAs);
    if(pchDMAsRead || ctx->perf.RETRY_ON_ERROR) {
        while(i < cpDMAs) {
            if((ppDMAs[i]->cb < ppDMAs[i]->cbMax) && ctx->perf.RETRY_ON_ERROR && !fRetry) {
                Sleep(100);
                DeviceFPGA_ReadScatterDMA_Impl(ctxPcileech, ppDMAs, cpDMAs);
                fRetry = TRUE;
            }
            c += (ppDMAs[i]->cb >= ppDMAs[i]->cbMax) ? 1 : 0;
            i++;
        }
    }
    if(pchDMAsRead) {
        *pchDMAsRead = c;
    }
}

VOID DeviceFPGA_ProbeDMA_Impl(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_ __bcount(cPages) PBYTE pbResultMap)
{
    DWORD i, j, cTxTlp = 0;
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxPcileech->hDevice;
    TLP_CALLBACK_BUF_MRd bufMRd;
    DWORD tx[4];
    BOOL is32, isFlush;
    PTLP_HDR_MRdWr64 hdrRd64 = (PTLP_HDR_MRdWr64)tx;
    PTLP_HDR_MRdWr32 hdrRd32 = (PTLP_HDR_MRdWr32)tx;
    // split probe into processing chunks if too large...
    while(cPages > ctx->perf.PROBE_MAXPAGES) {
        DeviceFPGA_ProbeDMA_Impl(ctxPcileech, qwAddr, ctx->perf.PROBE_MAXPAGES, pbResultMap);
        cPages -= ctx->perf.PROBE_MAXPAGES;
        pbResultMap += ctx->perf.PROBE_MAXPAGES;
        qwAddr += ctx->perf.PROBE_MAXPAGES << 12;
    }
    // prepare
    bufMRd.cb = 0;
    bufMRd.pb = pbResultMap;
    bufMRd.cbMax = cPages;
    ctx->pMRdBufferX = &bufMRd;
    ctx->hRxTlpCallbackFn = (VOID(*)(PVOID, PBYTE, DWORD))TLP_CallbackMRdProbe;
    // transmit TLPs
    for(i = 0; i < cPages; i++) {
        if(pbResultMap[i]) { continue; } // skip over if page already marked as ok
        memset(tx, 0, 16);
        is32 = qwAddr + (i << 12) < 0x100000000;
        if(is32) {
            hdrRd32->h.TypeFmt = TLP_MRd32;
            hdrRd32->h.Length = 1;
            hdrRd32->RequesterID = ctx->wDeviceId;
            hdrRd32->FirstBE = 0xf;
            hdrRd32->LastBE = 0;
            hdrRd32->Address = (DWORD)(qwAddr + (i << 12) + ((i & 0x1f) << 2)); // 5 low address bits coded into the dword read.
            hdrRd32->Tag = (BYTE)((i >> 5) & 0x1f); // 5 high address bits coded into tag.
        } else {
            hdrRd64->h.TypeFmt = TLP_MRd64;
            hdrRd64->h.Length = 1;
            hdrRd64->RequesterID = ctx->wDeviceId;
            hdrRd64->FirstBE = 0xf;
            hdrRd64->LastBE = 0;
            hdrRd64->AddressHigh = (DWORD)((qwAddr + (i << 12)) >> 32);
            hdrRd64->AddressLow = (DWORD)(qwAddr + (i << 12) + ((i & 0x1f) << 2)); // 5 low address bits coded into the dword read.
            hdrRd64->Tag = (BYTE)((i >> 5) & 0x1f); // 5 high address bits coded into tag.
        }
        for(j = 0; j < 4; j++) {
            ENDIAN_SWAP_DWORD(tx[j]);
        }
        isFlush = (++cTxTlp % 24 == 0);
        if(isFlush) {
            DeviceFPGA_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, TRUE);
            usleep(ctx->perf.DELAY_PROBE_WRITE);
        } else {
            DeviceFPGA_TxTlp(ctx, (PBYTE)tx, is32 ? 12 : 16, FALSE, FALSE);
        }
    }
    DeviceFPGA_TxTlp(ctx, NULL, 0, TRUE, TRUE);
    usleep(ctx->perf.DELAY_PROBE_READ);
    DeviceFPGA_RxTlpSynchronous(ctx);
    ctx->hRxTlpCallbackFn = NULL;
    ctx->pMRdBufferX = NULL;
}

VOID DeviceFPGA_ProbeDMA(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ QWORD qwAddr, _In_ DWORD cPages, _Inout_ __bcount(cPages) PBYTE pbResultMap)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxPcileech->hDevice;
    DWORD i;
    DeviceFPGA_ProbeDMA_Impl(ctxPcileech, qwAddr, cPages, pbResultMap);
    if(ctx->perf.RETRY_ON_ERROR) {
        for(i = 0; i < cPages; i++) {
            if(0 == pbResultMap[i]) {
                Sleep(100);
                DeviceFPGA_ProbeDMA_Impl(ctxPcileech, qwAddr, cPages, pbResultMap);
                return;
            }
        }
    }
}

// write max 128 byte packets.
BOOL DeviceFPGA_WriteDMA_TXP(_Inout_ PDEVICE_CONTEXT_FPGA ctx, _In_ QWORD qwA, _In_ BYTE bFirstBE, _In_ BYTE bLastBE, _In_ PBYTE pb, _In_ DWORD cb)
{
    DWORD txbuf[36], i, cbTlp;
    PBYTE pbTlp = (PBYTE)txbuf;
    PTLP_HDR_MRdWr32 hdrWr32 = (PTLP_HDR_MRdWr32)txbuf;
    PTLP_HDR_MRdWr64 hdrWr64 = (PTLP_HDR_MRdWr64)txbuf;
    memset(pbTlp, 0, 16);
    if(qwA < 0x100000000) {
        hdrWr32->h.TypeFmt = TLP_MWr32;
        hdrWr32->h.Length = (WORD)(cb + 3) >> 2;
        hdrWr32->FirstBE = bFirstBE;
        hdrWr32->LastBE = bLastBE;
        hdrWr32->RequesterID = ctx->wDeviceId;
        hdrWr32->Address = (DWORD)qwA;
        for(i = 0; i < 3; i++) {
            ENDIAN_SWAP_DWORD(txbuf[i]);
        }
        memcpy(pbTlp + 12, pb, cb);
        cbTlp = (12 + cb + 3) & ~0x3;
    } else {
        hdrWr64->h.TypeFmt = TLP_MWr64;
        hdrWr64->h.Length = (WORD)(cb + 3) >> 2;
        hdrWr64->FirstBE = bFirstBE;
        hdrWr64->LastBE = bLastBE;
        hdrWr64->RequesterID = ctx->wDeviceId;
        hdrWr64->AddressHigh = (DWORD)(qwA >> 32);
        hdrWr64->AddressLow = (DWORD)qwA;
        for(i = 0; i < 4; i++) {
            ENDIAN_SWAP_DWORD(txbuf[i]);
        }
        memcpy(pbTlp + 16, pb, cb);
        cbTlp = (16 + cb + 3) & ~0x3;
    }
    return DeviceFPGA_TxTlp(ctx, pbTlp, cbTlp, FALSE, FALSE);
}

BOOL DeviceFPGA_WriteDMA(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ QWORD qwA, _In_ PBYTE pb, _In_ DWORD cb)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxPcileech->hDevice;
    BOOL result = TRUE;
    BYTE be, pbb[4];
    DWORD cbtx;
    // TX 1st dword if not aligned
    if(cb && (qwA & 0x3)) {
        be = (cb < 3) ? (0xf >> (4 - cb)) : 0xf;
        be <<= qwA & 0x3;
        cbtx = min(cb, 4 - (qwA & 0x3));
        memcpy(pbb + (qwA & 0x3), pb, cbtx);
        result = DeviceFPGA_WriteDMA_TXP(ctx, qwA & ~0x3, be, 0, pbb, 4);
        pb += cbtx;
        cb -= cbtx;
        qwA += cbtx;
    }
    // TX as 128-byte packets (aligned to 128-byte boundaries)
    while(result && cb) {
        cbtx = min(128 - (qwA & 0x7f), cb);
        be = (cbtx & 0x3) ? (0xf >> (4 - (cbtx & 0x3))) : 0xf;
        result = (cbtx <= 4) ?
            DeviceFPGA_WriteDMA_TXP(ctx, qwA, be, 0, pb, 4) :
            DeviceFPGA_WriteDMA_TXP(ctx, qwA, 0xf, be, pb, cbtx);
        pb += cbtx;
        cb -= cbtx;
        qwA += cbtx;
    }
    return DeviceFPGA_TxTlp(ctx, NULL, 0, FALSE, TRUE) && result; // Flush and Return.
}

BOOL DeviceFPGA_ListenTlp(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ DWORD dwTime)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxPcileech->hDevice;
    QWORD tmStart = GetTickCount64();
    while(GetTickCount64() - tmStart < dwTime) {
        DeviceFPGA_TxTlp(ctx, NULL, 0, TRUE, TRUE);
        Sleep(10);
        DeviceFPGA_RxTlpSynchronous(ctx);
    }
    return TRUE;
}

BOOL DeviceFPGA_WriteTlp(_Inout_ PPCILEECH_CONTEXT ctxPcileech, _In_ PBYTE pbTlp, _In_ DWORD cbTlp)
{
    PDEVICE_CONTEXT_FPGA ctx = (PDEVICE_CONTEXT_FPGA)ctxPcileech->hDevice;
    return DeviceFPGA_TxTlp(ctx, pbTlp, cbTlp, FALSE, TRUE);
}

BOOL DeviceFPGA_Open(_Inout_ PPCILEECH_CONTEXT ctxPcileech)
{
    LPSTR szDeviceError;
    PDEVICE_CONTEXT_FPGA ctx;
    ctx = LocalAlloc(LMEM_ZEROINIT, sizeof(DEVICE_CONTEXT_FPGA));
    if(!ctx) { return FALSE; }
    ctxPcileech->hDevice = (HANDLE)ctx;
    szDeviceError = DeviceFPGA_InitializeFTDI(ctx);
    if(szDeviceError) { goto fail; }
    DeviceFPGA_GetDeviceID_FpgaVersion(ctx);
    if(ctxPcileech->cfg->fForcePCIeGen1) { 
        DeviceFPGA_SetSpeedPCIeGen1(ctx);
        DeviceFPGA_GetDeviceID_FpgaVersion(ctx);
    }
    if(!ctx->wDeviceId) { 
        szDeviceError = "Unable to retrieve required Device PCIe ID";
        goto fail;
    }
    DeviceFPGA_SetPerformanceProfile(ctxPcileech, ctx);
    ctx->rxbuf.cbMax = (DWORD)(1.30 * ctx->perf.MAX_SIZE_RX + 0x1000);  // buffer size tuned to lowest possible (+margin) for performance.
    ctx->rxbuf.pb = LocalAlloc(0, ctx->rxbuf.cbMax);
    if(!ctx->rxbuf.pb) { goto fail; }
    ctx->txbuf.cbMax = ctx->perf.MAX_SIZE_TX + 0x10000;
    ctx->txbuf.pb = LocalAlloc(0, ctx->txbuf.cbMax);
    if(!ctx->txbuf.pb) { goto fail; }
    ctx->isPrintTlp = ctxPcileech->cfg->fVerboseExtraTlp;
    // set callback functions and fix up config
    ctxPcileech->cfg->dev.tp = PCILEECH_DEVICE_FPGA;
    ctxPcileech->cfg->dev.qwMaxSizeDmaIo = ctx->perf.MAX_SIZE_RX;
    ctxPcileech->cfg->dev.qwAddrMaxNative = 0x0000ffffffffffff;
    ctxPcileech->cfg->dev.fPartialPageReadSupported = TRUE;
    ctxPcileech->cfg->dev.pfnClose = DeviceFPGA_Close;
    ctxPcileech->cfg->dev.pfnProbeDMA = ctx->perf.PROBE_MAXPAGES ? DeviceFPGA_ProbeDMA : NULL;
    ctxPcileech->cfg->dev.pfnReadScatterDMA = DeviceFPGA_ReadScatterDMA;
    ctxPcileech->cfg->dev.pfnWriteDMA = DeviceFPGA_WriteDMA;
    ctxPcileech->cfg->dev.pfnWriteTlp = DeviceFPGA_WriteTlp;
    ctxPcileech->cfg->dev.pfnListenTlp = DeviceFPGA_ListenTlp;
    // return
    if(ctxPcileech->cfg->fVerbose) { 
        printf(
            "FPGA: Device Info: %s PCIe gen%i x%i [%i,%i,%i] [v%i.%i,%04x]\n", 
            ctx->perf.SZ_DEVICE_NAME, 
            DeviceFPGA_PHY_GetPCIeGen(ctx), 
            DeviceFPGA_PHY_GetLinkWidth(ctx), 
            ctx->perf.DELAY_READ, 
            ctx->perf.DELAY_WRITE, 
            ctx->perf.DELAY_PROBE_READ,
            ctx->wFpgaVersionMajor,
            ctx->wFpgaVersionMinor,
            ctx->wDeviceId);
    }
    return TRUE;
fail:
    if(szDeviceError && (ctxPcileech->cfg->fVerbose || (ctxPcileech->cfg->dev.tp == PCILEECH_DEVICE_FPGA))) {
        printf(
            "FPGA: ERROR: %s [%i,v%i.%i,%04x]\n", 
            szDeviceError,
            ctx->wFpgaID,
            ctx->wFpgaVersionMajor,
            ctx->wFpgaVersionMinor,
            ctx->wDeviceId);
    }
    DeviceFPGA_Close(ctxPcileech);
    return FALSE;
}
