#!/usr/bin/bash

# vm start; vm connect
gcc k.s -nostdlib -static -o e.elf
objcopy --dump-section .text=e.bin e.elf
hd e.bin
# vm start; vm connect
# /challenge/babykernel_level12.0 < e.bin
# objdump -M intel -d e.elf

# gcc k2.s -nostdlib -static -o e2.elf
# objcopy --dump-section .text=e2.bin e2.elf
# hd e2.bin
# objdump -M intel -d e2.elf