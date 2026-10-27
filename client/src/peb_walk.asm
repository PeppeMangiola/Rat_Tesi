; peb_walk.asm - legge PEB base tramite GS register
; compatibile con mingw x64
section .text
global GetPEBAddress
GetPEBAddress:
    mov rax, gs:[0x60]
    ret
