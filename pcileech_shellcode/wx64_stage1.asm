; wx64_stage1.asm : assembly to redirect hook to larger code section.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

.CODE

main PROC
	label_main_base:
	CALL label_main_base
main ENDP

; -----------------------------------------------------------------------------
; Info
; compiles into  E8FBFFFFFF
; In order to CALL correct stage2 entry point address the value FBFFFFFF
; (FFFFFFFB when loaded as DWORD) has to be incremented with the offset between
; stage1 and stage2. 
; After completing stage2 - JMP back to CALL-stack - 5 (length of shellcode)
; -----------------------------------------------------------------------------

END
