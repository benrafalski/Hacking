# #define _GNU_SOURCE
# #include <unistd.h>
# #include <stdio.h>
# #include <stdlib.h>
# #include <string.h>
# #include <fcntl.h>
# #include <sys/wait.h>
# #include <openssl/sha.h>

# #define FILENAME        "admin/secret"
# #define ADMINBIN        "admin/bin"
# #define MAX_SIZE        256
# #define SIGN_SIZE       20

# int main()
# {
#         int i, fd, admin = 0;
#         unsigned char c, content[MAX_SIZE + 1] = {0}, signature[SIGN_SIZE + 1] = {0};
#         pid_t frk;

#         if ((fd = open(FILENAME, O_RDONLY)) == -1) {
#                 printf("Fail...\n");
#                 exit(1);
#         }
#         printf("Start reading...");

#         while (strlen((char*)content) < MAX_SIZE && read(fd, &c, 1) == 1) {
#                 content[strlen((char*)content)] = c;
#         }
#         printf("Done !\n");

#         setreuid(getuid(), getuid());
#         frk = fork();

#         if (frk == -1) {
#                 printf("Fork fail...\n");
#                 exit(1);
#         }

#         if (frk == 0)
#         {
#                 if (execve(ADMINBIN, NULL, NULL) == -1) {
#                         printf("Exec fail...\n");
#                         exit(1);
#                 }
#         }
#         else
#         {
#                 wait(&admin);

#                 if (admin)
#                 {
#                         SHA1(content, strlen((char*)content), signature);
#                         printf("Signature of %s is ", FILENAME );

#                         for (i = 0; i < SIGN_SIZE; i++) {
#                                 printf("%02x", signature[i]);
#                         }

#                         printf("\n");
#                 }
#                 else
#                 {
#                         printf("Good bye.\n");
#                 }
#         }

#         return 0;
# }