#!/usr/bin/python3
from pwn import *

p = process('python3', 'x.py')

print(p.readall())