; wx64_stage3.asm : assembly to receive execution from stage2 shellcode.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN stage3_c_EntryPoint:NEAR

.CODE

main PROC
	; ----------------------------------------------------
	; 1: SAME INITIAL BYTE SEQUENCE AS wx64_stage3_pre.asm
	; ----------------------------------------------------
	label_main_base:
	LEA rax, label_main_base-8h
	MOV rax, [rax]
	CMP rax, 0
	JZ label_main_base
	; ----------------------------------------------------
	; 2: CALL C CODE
	; ----------------------------------------------------
	LEA rcx, label_main_base - 1000h ; address of data page in parameter 1
	PUSH rsi
	MOV rsi, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	CALL stage3_c_EntryPoint
	MOV rsp, rsi
	POP rsi
	RET
main ENDP

END
