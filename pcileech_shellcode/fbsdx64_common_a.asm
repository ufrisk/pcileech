; fbsdx64_common_a.asm : assembly to receive execution from stage3 exec command.
; Compatible with FreeBSD x64.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

; -------------------------------------
; Prototypes
; -------------------------------------
main PROTO
LookupFunctionFreeBSD PROTO
SysVCall PROTO
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

; ----------------------------------------------------
; TRIVIAL VERSION OF STRCMP
; destroyed registers :: <none>
; rdi -> ptr to str1
; rsi -> ptr to str2
; rax <- 0 == success, !0 == fail
; ----------------------------------------------------
strcmp_simple PROC
	PUSH rcx
	XOR rcx, rcx
	DEC rcx
	loop_strcmp:
	INC rcx
	MOV al, [rdi+rcx]
	CMP al, [rsi+rcx]
	JNE error
	CMP al, 0
	JNE loop_strcmp
	XOR rax, rax
	POP rcx
	RET
	error:
	MOV al, 1
	POP rcx
	RET
strcmp_simple ENDP

; ----------------------------------------------------
; FIND EXPORTED SYMBOL IN BSD KERNEL
; destroyed registers :: rsi
; rcx -> PKMDDATA
; rdx -> rdi -> ptr to symbol/function str
; rax <- resulting address (zero if error)
; ----------------------------------------------------
LookupFunctionFreeBSD PROC
	PUSH rdi
	PUSH rsi
	MOV rdi, rdx
	MOV rcx, [rcx+58h]			; [PKMDDATA->ReservedKMD]
	MOV rdx, rcx				; [PKMDDATA->ReservedKMD]
	SUB rcx, 8
	loop_symsearch:
	SUB rcx, 18h
	MOV rax, [rcx]
	TEST rax, rax
	JZ error
	MOV esi, [rcx]
	ADD rsi, rdx
	CALL strcmp_simple
	TEST rax, rax
	JNZ loop_symsearch
	MOV rax, [rcx+8]
	POP rsi
	POP rdi
	RET
	error:
	XOR rax, rax
	POP rsi
	POP rdi
	RET
LookupFunctionFreeBSD ENDP

; ------------------------------------------------------------------
; Convert from the Windows X64 calling convention to the SystemV
; X64 calling convention used by Linux. A maximum of twelve (12)
; parameters in addition to the function ptr can be supplied.
; QWORD SysVCall(QWORD fn, QWORD p1, QWORD p2, QWORD p3, QWORD p4, QWORD p5);
; QWORD SysVCall(QWORD fn, ...);
; ------------------------------------------------------------------
SysVCall PROC
	MOV rax, rcx
	PUSH rdi
	PUSH rsi
	PUSH r14
	PUSH r15
	MOV rdi, rdx
	MOV rsi, r8
	MOV rdx, r9
	MOV rcx, [rsp+28h+4*8+00h] ; 20h stack shadow space + 8h (RET) + 4*8h PUSH + xxh offset
	MOV r8,  [rsp+28h+4*8+08h]
	MOV r9,  [rsp+28h+4*8+10h]
	MOV r15, rsp
	MOV r14, [rsp+28h+4*8+40h] ; 20h stack shadow space + 8h (RET) + 3*8h PUSH + xxh offset
	PUSH r14
	MOV r14, [rsp+28h+5*8+38h] ; 20h stack shadow space + 8h (RET) + 4*8h PUSH + xxh offset
	PUSH r14
	MOV r14, [rsp+28h+6*8+30h] ; 20h stack shadow space + 8h (RET) + 5*8h PUSH + xxh offset
	PUSH r14
	MOV r14, [rsp+28h+7*8+28h] ; 20h stack shadow space + 8h (RET) + 6*8h PUSH + xxh offset
	PUSH r14
	MOV r14, [rsp+28h+8*8+20h] ; 20h stack shadow space + 8h (RET) + 7*8h PUSH + xxh offset
	PUSH r14
	MOV r14, [rsp+28h+9*8+18h] ; 20h stack shadow space + 8h (RET) + 8*8h PUSH + xxh offset
	PUSH r14
	CALL rax
	MOV rsp, r15
	POP r15
	POP r14
	POP rsi
	POP rdi
	RET
SysVCall ENDP

__curthread PROC
	MOV rax, gs:[0]
	RET
__curthread ENDP

END