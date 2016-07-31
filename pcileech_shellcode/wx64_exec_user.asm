; wx64_exec_user.asm : assembly to receive execution from APC in user mode.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN c_EntryPoint:NEAR

.CODE

main PROC
	label_main_base:
	; ----------------------------------------------------
	; 1: ENSURE ATOMICITY IN THREADED ENVIRONMENTS
	; ----------------------------------------------------
	MOV al, 00h
	MOV dl, 01h
	LEA rcx, data_cmpxchg_flag
	LOCK CMPXCHG [rcx], dl
	JNE skipcall
    ; ----------------------------------------------------
	; 2: Fetch code address
	; ----------------------------------------------------
	LEA rcx, label_main_base
	AND rcx, 0fffffffffffff000h
    ; ----------------------------------------------------
	; 3: Fetch KERNEL32 address
	; ----------------------------------------------------
	MOV  rdx, GS:[30h]    ; TEB
	MOV  rdx, [rdx + 60h] ; PEB
	MOV  rdx, [rdx + 18h] ; LDR
	MOV  rdx, [rdx + 20h] ; LIST_LOADED_MODULES
	MOV  rdx, [rdx]       ; NTDLL
	MOV  rdx, [rdx]       ; KERNEL32
	MOV  rdx, [rdx + 20h] ; ADDR of KERNEL32
    ; ----------------------------------------------------
	; 4: Call c-code and return
	; ----------------------------------------------------
	PUSH rsi
	MOV rsi, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	CALL c_EntryPoint
	MOV rsp, rsi
	POP rsi
	skipcall:
	RET
main ENDP

data_cmpxchg_flag		db 00h

END
