; macos_common_a.asm : assembly to receive execution from stage3 exec command.
; Compatible with macOS.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

; -------------------------------------
; Prototypes
; -------------------------------------
main PROTO
LookupFunctionMacOS PROTO
SysVCall PROTO
PageFlush PROTO
GetCR3 PROTO
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
LookupFunctionMacOS PROC
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
LookupFunctionMacOS ENDP

PageFlush PROC
	MOV rax, cr3
	MOV cr3, rax
	RET
PageFlush ENDP

GetCR3 PROC
	MOV rax, cr3
	RET
GetCR3 ENDP

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

END