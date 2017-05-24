; lx64_common_a.asm : assembly to receive execution from stage3 exec command.
; Compatible with Linux x64.
;
; (c) Ulf Frisk, 2016, 2017
; Author: Ulf Frisk, pcileech@frizk.net
;

; -------------------------------------
; Prototypes
; -------------------------------------
main PROTO
LookupFunctions PROTO
SysVCall PROTO 
WinCallSetFunction PROTO
m_phys_to_virt PROTO
m_page_to_phys PROTO
EXTRN c_EntryPoint:NEAR

; -------------------------------------
; Code
; -------------------------------------
.CODE

main PROC
	PUSH rsi
	MOV rsi, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	CALL c_EntryPoint
	MOV rsp, rsi
	POP rsi
	RET
main ENDP

; ------------------------------------------------------------------
; Lookup function pointers and place them in the supplied struct
; rcx -> address of kallsyms_lookup_name
; rdx -> ptr to name array
; r8  -> ptr to function destination array
; r9  -> number of items in array
; rax <- 0 = FAIL, 1 = SUCCESS
; ------------------------------------------------------------------
LookupFunctions PROC
	; ----------------------------------------------------
	; 0: SET UP / STORE NV-REGISTERS
	; ----------------------------------------------------
	PUSH r15
	PUSH r14
	PUSH r13
	PUSH r12
	MOV r15, rcx				; address of kallsyms_lookup_name
	MOV r14, rdx				; ptr to funcion name array
	MOV r13, r9					; num functions * 8
	SHL r13, 3
	MOV r12, r8					; ptr to function destination array
	; ----------------------------------------------------
	; 1: LOOKUP FUNCTION POINTERS BY NAME
	; ----------------------------------------------------
	lookup_loop:
	SUB r13, 8
	MOV rcx, r15
	MOV rdx, [r14+r13]
	CALL SysVCall
	TEST rax, rax
	JZ lookup_fail
	MOV [r12+r13], rax
	TEST r13, r13
	JNZ lookup_loop
	; ----------------------------------------------------
	; 3: RESTORE NV REGISTERS AND RETURN
	; ----------------------------------------------------
	POP r12
	POP r13
	POP r14
	POP r15
	MOV RAX, 1
	RET
	lookup_fail:
	XOR rax, rax
	RET
LookupFunctions ENDP

; ------------------------------------------------------------------
; Convert from the Windows X64 calling convention to the SystemV
; X64 calling convention used by Linux.
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
; WinCall callback function pointer.
; ------------------------------------------------------------------
data_wincall_fnptr dq 0

; ------------------------------------------------------------------
; Set the (windows x64 calling convention compatible) callback function
; to forward callbacks sent to WinCall to.
; NB! This requires the memory to be RWX.
; rcx -> address of kallsyms_lookup_name
; ------------------------------------------------------------------
WinCallSetFunction PROC
	MOV [data_wincall_fnptr], rcx
	RET
WinCallSetFunction ENDP

; ------------------------------------------------------------------
; Convert from the SystemV X64 calling convention (used by Linux)
; to the Windows Windows X64 calling convention.
; Function typically called by the Linux kernel as a callback function.
; The address of the Windows X64 function to forward the call to is
; set by 'WinCallSetFunction'.
; A maximum of six (6) parameters are supported.
; rdi -> rcx
; rsi -> rdx
; rdx -> r8
; rcx -> r9
; r8  -> stack
; r9  -> stack
; ------------------------------------------------------------------
WinCall PROC
	PUSH r15
	MOV r15, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h

	PUSH r9
	PUSH r8
	SUB rsp, 020h
	MOV r9, rcx
	MOV r8, rdx
	MOV rdx, rsi
	MOV rcx, rdi

	MOV rax, [data_wincall_fnptr]
	CALL rax
	MOV rsp, r15
	POP r15
	RET
WinCall ENDP

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

; ----------------------------------------------------
; Flush the CPU cache.
; ----------------------------------------------------
CacheFlush PROC
	WBINVD
	RET
CacheFlush ENDP

END