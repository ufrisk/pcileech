; lx64_stage3_pre.asm : assembly wait loop to wait for continue when executable code exists after.
; Compatible with Linux x64.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

.CODE

main PROC
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
main ENDP

; -----------------------------------------------------------------------------
; This code compiles into 53 bytes. This is copied by
; stage3 area by the setup function.
; Linux cannot use the simpler windows stage3 pre code
; since the thread will get stuck without a sleep.
; -----------------------------------------------------------------------------

END
