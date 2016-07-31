; wx64_pageinfo.asm : shellcode assembly for retrieving various CPU registers.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;
; compile with:
; ml64 wx64_pageinfo.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /entry:main
; shellcode64.exe -o wx64_pageinfo.exe "PAGEINFO: Results:%s\n  CR0=%016llX\n  CR2=%016llX\n  CR3=%016llX\n  CR4=%016llX\n"
;

.CODE

; ----------------------------------------------------
; Fetch control registers and store in dataOut.
; rcx = 1st parameter (PKMDDATA)
; rdx = 2nd parameter (ptr to dataIn)
; r8  = 3rd parameter (ptr to dataOut)
; on exit:
; dataOut[0] = cr0
; dataOut[1] = cr2
; dataOut[2] = cr3
; dataOut[3] = cr4
; ----------------------------------------------------
main PROC
	MOV rax, cr0
	MOV [r8-00h], rax
	MOV rax, cr2
	MOV [r8+08h], rax
	MOV rax, cr3
	MOV [r8+10h], rax
	MOV rax, cr4
	MOV [r8+18h], rax
	RET
main ENDP

END
