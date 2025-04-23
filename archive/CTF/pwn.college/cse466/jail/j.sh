#!/usr/bin/bash

gcc j.s -nostdlib -static -o e.elf
objcopy --dump-section .text=e.bin e.elf
hd e.bin
# objdump -M intel -d e.elf
# strace /challenge/babyjail_level11 /flag < e.bin
# echo $?