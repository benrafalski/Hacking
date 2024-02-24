.intel_syntax noprefix
.globl _start

.section .text

_start:
    push rbp
    mov rbp, rsp
    sub rsp, 0x1000

    mov rdi, 0x2
    mov rsi, 0x1
    mov rdx, 0x0
    mov rax, 41     # SYS_socket
    syscall

    mov rbx, rax    # socket fd 

    mov rdi, rbx
    mov word ptr [rbp-0x20],0x2
    mov dword ptr [rbp-0x1c],0x0
    xor rax, rax
    mov ax, 0x5000
    mov word ptr [rbp-0x1e], ax
    lea rax, [rbp-0x20]
    mov rsi, rax
    mov rdx, 0x10
    mov rax, 49     # SYS_bind
    syscall

    mov rdi, rbx
    mov rsi, 0
    mov rax, 50     # SYS_listen
    syscall

    mov rdi, rbx
    mov rsi, 0
    mov rdx, 0
    mov rax, 43     # SYS_accept
    syscall

    mov r12, rax    # accept fd

while1:
    mov rax, 57     # SYS_fork
    syscall

    test rax, rax
    je child

    mov rdi, r12
    mov rax, 3     # SYS_close
    syscall

    mov rdi, rbx
    mov rsi, 0
    mov rdx, 0
    mov rax, 43     # SYS_accept
    syscall
    jmp while1

    mov r12, rax    # accept fd

    leave
    ret

child:
    mov rdi, rbx
    mov rax, 3     # SYS_close
    syscall

    mov rdi, r12
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0     # SYS_read
    syscall
    
    pop ax 
    cmp rax,0x4547
    jne POST

GET: 
    pop ax
    mov al, 0x0
    mov byte ptr[rsp+16], al
    mov rdi, rsp
    mov rsi, 0
    mov rdx, 0
    mov rax, 2     # SYS_open
    syscall

    mov rbx, rax   # open /tmp/asdf fd

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x1000
    mov rax, 0     # SYS_read
    syscall

    mov r14, rax   # amount read

    mov rdi, rbx
    mov rax, 3     # SYS_close
    syscall

    mov rdi, r12
    lea rsi, [rip+write]
    mov rdx, 19
    mov rax, 1     # SYS_write
    syscall

    mov rdi, r12
    mov rsi, rsp
    mov rdx, r14
    mov rax, 1     # SYS_write
    syscall

    mov rdi, 0
    mov rax, 60     # SYS_exit
    syscall

POST: 

    pop ax
    add rsp, 0x1
    mov al, 0x0
    mov byte ptr[rsp+16], al
    mov rdi, rsp
    mov rsi, 65
    mov rdx, 0777
    mov rax, 2     # SYS_open
    syscall

    mov rbx, rax

    add rsp, 0xa5
    pop ax
    pop ax 
    pop ax 
    lea rax, [rsp-1]
    xor rdx, rdx

str:
    inc rdx
    inc rax
    cmpb [rax], 0x0 
    jne str 

    cmpb [rsp], 0x0a
    jne nonewline
    add rsp, 0x1
    sub rdx, 0x1

nonewline:
    mov rdi, rbx
    mov rsi, rsp
    sub rdx, 0x1
    mov rax, 1     # SYS_write
    syscall

    mov rdi, rbx
    mov rax, 3     # SYS_close
    syscall

    mov rdi, r12
    lea rsi, [rip+write]
    mov rdx, 19
    mov rax, 1     # SYS_write
    syscall

    mov rdi, 0
    mov rax, 60     # SYS_exit
    syscall 

    leave 
    ret

write:
    .string "HTTP/1.0 200 OK\r\n\r\n"