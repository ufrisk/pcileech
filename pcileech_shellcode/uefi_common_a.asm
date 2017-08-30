; uefi_common_a.asm : assembly to receive execution from stage3 exec command.
; Compatible with UEFI x64.
;
; (c) Ulf Frisk, 2017
; Author: Ulf Frisk, pcileech@frizk.net
;

; -------------------------------------
; Prototypes
; -------------------------------------
EXTRN c_EntryPoint:NEAR

; -------------------------------------
; Code
; -------------------------------------
.CODE

main PROC
	; STORE address of IBI SYST to use when making future
	; function calls from c-code.
	MOV rax, rcx			; pk
	ADD rax, 058h			; ReservedKMD (addr of IBI SYST)
	MOV rax, [rax]
	MOV [addr_UEFI_IBI_SYST], eax
	; set up stack and call into c-code.
	PUSH rsi
	MOV rsi, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	CALL c_EntryPoint
	MOV rsp, rsi
	POP rsi
	RET
main ENDP

addr_UEFI_IBI_SYST			dd 00000000h

EFI_BOOT_SERVICES_GenericJMP PROC
	MOV eax, [addr_UEFI_IBI_SYST]		; EFI_SYSTEM_TABLE
	ADD rax, 60h						; offset to *BootServices
	MOV rax, [rax]						; EFI_BOOT_SERVICES
	ADD rax, r10						; offset to ????
	MOV rax, [rax]
	JMP rax								; JMP to intended target
EFI_BOOT_SERVICES_GenericJMP ENDP

GetMemoryMap PROC
	MOV r10, 38h
	JMP EFI_BOOT_SERVICES_GenericJMP
GetMemoryMap ENDP

SetMem PROC
	MOV r10, 168h
	JMP EFI_BOOT_SERVICES_GenericJMP
SetMem ENDP

CopyMem PROC
	MOV r10, 160h
	JMP EFI_BOOT_SERVICES_GenericJMP
CopyMem ENDP

SetWatchdogTimer PROC
	MOV r10, 100h
	JMP EFI_BOOT_SERVICES_GenericJMP
SetWatchdogTimer ENDP

AllocatePages PROC
	MOV r10, 28h
	JMP EFI_BOOT_SERVICES_GenericJMP
AllocatePages ENDP

FreePages PROC
	MOV r10, 30h
	JMP EFI_BOOT_SERVICES_GenericJMP
FreePages ENDP

LocateProtocol PROC
	MOV r10, 140h
	JMP EFI_BOOT_SERVICES_GenericJMP
LocateProtocol ENDP

END
