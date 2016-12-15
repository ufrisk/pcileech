; wx64_common_a.asm : assembly to receive execution from stage3 exec command.
; Compatible with Windowx 64.
;
; (c) Ulf Frisk, 2016
; Author: Ulf Frisk, pcileech@frizk.net
;

; -------------------------------------
; Prototypes
; -------------------------------------
main PROTO
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

GetCR3 PROC
	MOV rax, cr3
	RET
GetCR3 ENDP

; ----------------------------------------------------
; Flush the CPU cache.
; ----------------------------------------------------
CacheFlush PROC
	WBINVD
	RET
CacheFlush ENDP

END
