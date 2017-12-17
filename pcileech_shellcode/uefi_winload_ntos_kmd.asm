; uefi_winload_ntos_kmd.asm : assembly to receive execution from hooked function PsCreateSystemThread at end of execution (instead of RET)
;
; (c) Ulf Frisk, 2017
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN c_EntryPoint:NEAR

.CODE

main PROC
	JMP main_setup
main ENDP

data_trigger_count	db 00h, 00h		; offset 0x02
addr_base_ntos		dd 00000000h	; offset 0x04
addr_this			dd 00000000h    ; offset 0x08
addr_sym0			dd 00000000h    ; offset 0x0c
addr_sym1			dd 00000000h    ; offset 0x10
addr_sym2			dd 00000000h    ; offset 0x14

main_setup PROC
	PUSH rax
	; ----------------------------------------------------
	; only continue of running at IRQL PASSIVE_LEVEL
	; ----------------------------------------------------
	MOV rax, cr8
	TEST al, al
	JNZ main_setup_exit
	; ----------------------------------------------------
	; save registers (14regs)
	; ----------------------------------------------------
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
	; fetch ntos base, vfs addr, cr3, align stack, jump to c-code
	; ----------------------------------------------------
	LEA rcx, [main]
	MOV eax, [addr_this]
	SUB rcx, rax
	MOV eax, [addr_base_ntos]
	ADD rcx, rax
	LEA rdx, [main]
	MOV r8, cr3
	MOV r15, rsp
	SUB rsp, 100h
	SHR rsp, 4
	SHL rsp, 4
	CALL c_EntryPoint
	MOV rsp, r15
	; ----------------------------------------------------
	; restore registers
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
	; ----------------------------------------------------
	; return
	; ----------------------------------------------------
	main_setup_exit:
	POP rax
	RET
main_setup ENDP

END
