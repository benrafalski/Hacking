#!/usr/bin/python3
from pwn import *
import os
import glob
import sys
import time



context.log_level = 'DEBUG'
# s = process("/challenge/embryoio_level141")
# p = remote('localhost', 1016)
# print(s.readall())
# r.recvuntil(b'for:')
# fif = open('fif', 'w')
# p = process(['/challenge/embryoio_level104'], stdout=fif)
# while(1):
#     print(p.readline().decode())

# print(p.readall())

# while(1):
#     print(p.readline())

# r = process(['./a.out'])
# f1 = open('/tmp/fif', 'r')
# f2 = open('/tmp/fif2', "w")
# p = process(['/challenge/embryoio_level106'], stdin=f1, stdout=f2)
# print(p.readline())

# finr = os.open('/tmp/fif', os.O_RDWR)
# finw = os.open('/tmp/fif', os.O_WRONLY)
# foutr = os.open('/tmp/fif2', os.O_RDWR)
# foutw = os.open('/tmp/fif2', os.O_WRONLY)
p = process(['./x.sh'])
print(p.readline())
print(p.recvuntil(b'for.'))
for i in range(0,500):
        print(p.recvuntil(b"for:"))
        chall = eval(p.recv().decode().strip())
        print(chall)
        # cat_in.wait()
        p.sendline(str(chall).encode("utf-8"))
print(b"recved: "+p.recvline())
p.interactive()

# 134
# c = process(["cat", '-'], stdin=PIPE)
# p = process(["./a.out"], stdin=PIPE, stdout=c.stdin)
# cat_in = process(["cat"], stdout=p.stdin)
# print(c.recvuntil(b'for.'))
# for i in range(0,50):
#         print(c.recvuntil(b"for:"))
#         chall = eval(c.recv().decode().strip())
#         print(chall)
#         # cat_in.wait()
#         cat_in.sendline(str(chall).encode("utf-8"))
#         print(b"recved: "+c.recvline())
# c.interactive()



# for i in range(0,50):


# print(p.recvuntil(b": ['"))

# li = list(str(p.readuntil(b"']\n").strip()).split("\', \'"))


# for i in range(0,500): 
#         if i == 0: 
#                 li[i] = li[i][5:]
#                 # kill.wait()
#                 # print(p.recvline())
#                 # print(li[i][5:])
#         elif i == len(li)-1:
#                 # print(p.recvline())
#                 li[i] = li[i][3:-3]
#                 # print(p.recvline())
#                 # kill.close()
#                 # print(li[i][3:-3])
#         else:  
#                 # print(p.recvline())
#                 li[i] = li[i][3:]
#                 # print(p.recvline())
#                 # kill.close()
#                 # print(li[i][3:])
# for i in range(0,500): 
#         print(li[i])
#         print(i)
#         if i == 0: 
#                 kill = process(['kill', '-s', li[i], str(p.pid+1)])
#                 p.recvline()
#         elif i == len(li)-1:
#                 p.recvline()
#                 kill = process(['kill', '-s', li[i], str(p.pid+1)])
#         else:  
#                 p.recvline()
#                 kill = process(['kill', '-s', li[i], str(p.pid+1)])
#                 p.recvline()   
# print("recved: "+p.recvall().decode())
# p.interactive()
    





# OLDOLDOLDOLDODLOLDODL

# context.log_level = 'DEBUG'
# pip = process(["/bin/cat"], stdout=PIPE)

# pip = process(["/bin/cat"], stdout=PIPE)
# l=["None"]*300
# l[0] = "/challenge/embryoio_level78"
# l[264] = "kzytpmfqva"
# cd = process(['/usr/bin/cd', '~'])
# p = process(["tjnrrw"], executable='/challenge/embryoio_level103', stdin=) 
# os.mkfifo('/tmp/fif')
# os.mkfifo('/tmp/fif2')
# f1 = open('/tmp/fif', 'r')
# f2 = open('/tmp/fif2', "w")
# p = process(['/challenge/embryoio_level106'], stdin=f1, stdout=f2)
# # p.interactive()
# print(p.readline())
# p.wait()



# pip.writeline(b'dqqmrpsf\4')
# print(p.readall())
# p.writeline(b'tlhktiys')
# print(p.readuntil('[TEST] CHALLENGE! Please send the solution for: '))
# p.writeline(b'100')
# print(p.realall())

# pip.interactive()


# while(1): 
#     print(p.readline())
# print(p.writeline(b'nppjhksv'))
# while(1): 
#     print(p.readline())

# while(1): 
#     print(p.readline())
# p.close()



# 106

# way #1
# finr = os.open('/tmp/fif', os.O_RDWR)
# finw = os.open('/tmp/fif', os.O_WRONLY)
# foutr = os.open('/tmp/fif2', os.O_RDWR)
# foutw = os.open('/tmp/fif2', os.O_WRONLY)
# c1 = process(["cat"], stdout=finw)
# c2 = process(['cat'], stdin=foutr)
# p = process(['/challenge/embryoio_level106'], stdin=finr, stdout=foutw)
# print(c2.recvuntil(b"for:"))
# chall = eval(c2.recv().decode().strip())
# print(chall)
# c1.sendline(str(chall).encode("utf-8"))
# print("recved: "+c2.recvuntil(b'flag:\n').decode())
# print("flag: "+c2.recvuntil(b'}').decode())

# way #2
# start cat > /tmp/fif first
# start cat < /tmp/fif2 second
# start python3 x.py last
f1 = open('/tmp/fif', 'r')
f2 = open('/tmp/fif2', 'w')
p = process(['/challenge/embryoio_level106'], stdin=f1, stdout=f2)
p.wait()
print(p.readline())
