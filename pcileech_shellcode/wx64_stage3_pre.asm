; wx64_stage3_pre.asm : assembly wait loop to wait for continue when executable code exists after
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

; -------------------------------------
; Prototypes
; -------------------------------------
main PROTO 

; -----------------------------------------------------------------------------
; Code
; -----------------------------------------------------------------------------
.CODE

main PROC
	label_main_base:
	LEA rax, label_main_base-8h
	MOV rax, [rax]
	CMP rax, 0
	JZ label_main_base
main ENDP

; -----------------------------------------------------------------------------
; Compiles into:
; 48 8D 05 F1 FF FF FF 48  8B 00 48 83 F8 00 74 F0
; -----------------------------------------------------------------------------

END
