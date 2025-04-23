// #include <assert.h>
// #include <fcntl.h>
// #include <unistd.h>
// #include <string.h>
// #include <stdio.h>
// #include <sys/sendfile.h>
// #include <sys/ioctl.h>
// #include <stdlib.h>
// #include <time.h>
// #include <stdlib.h>
// #include <linux/seccomp.h>
// #include <linux/thread_info.h>

// #include <linux/atomic.h>
// #include <linux/ctype.h>
// #include <linux/export.h>
// #include <linux/kexec.h>
// #include <linux/kmod.h>
// #include <linux/kmsg_dump.h>
// #include <linux/reboot.h>
// #include <linux/suspend.h>
// #include <linux/syscalls.h>
// #include <linux/syscore_ops.h>
// #include <linux/uaccess.h>


// ffffffffc0000510 t init_module  [challenge]

// ffffffff81088d90 T commit_creds
// ffffffff810890d0 T prepare_kernel_cred

// ffffffffc00010ac t device_write [challenge]

// int main(int argc, char **argv){
//     int fd = open("/home/hacker/pwncollege", O_RDWR | O_CREAT);
//     sendfile(fd, open("/flag", 0), 0, 1000);
// }

// void test(void){

//     run_cmd("cmd");
// }




// #include <linux/module.h>
// #include <linux/kernel.h>
// #include <linux/cred.h>
// MODULE_LICENSE("GPL")

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>

int main( void )
{

    // int pid = getpid();
    // char c[3];
    // int i=2;
    // while(pid!=0){
    //     c[i] = (pid%10) + '0';
    //     pid/=10;
    //     i--;
    // }
    
    // char path1[15] = {'/', 'p', 'r', 'o', 'c', '/', c[0], c[1], c[2], '/', 'm', 'a', 'p', 's', '\0'};
    // char path2[14] = {'/', 'p', 'r', 'o', 'c', '/', c[0], c[1], c[2], '/', 'm', 'e', 'm', '\0'};
    // printf("%s", path2);
    // int fd1 = open(path1, 0);
    // int fd2 = open(path2, 0);
    // int outputfile = open("self.dump", 1);
    
    // char curr[10] = { };
    // while(curr != "\n"){
    //     read(fd1, curr, 1);
    //     write(outputfile, curr, 1);
    // }

    // printf("%d", SEEK_SET);
    // sprintf(mem_file_name, "/proc/%d/mem", pid);

    // int mem_fd = open("/proc/self/mem", O_RDONLY);
    // // ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    // // waitpid(pid, NULL, 0);
    // char buf[_SC_PAGE_SIZE] = {};
    // lseek(mem_fd, 0x00401000, SEEK_SET);
    // read(mem_fd, buf, 30);
    // ptrace(PTRACE_DETACH, pid, NULL, NULL);
    int pid = getpid();
    printf("parent=%d", pid);
    int i = fork();
    if(i == 0) {
        pid = getpid();
        printf("child=%d", pid);
    }
    else {
        waitpid(i, NULL, 0); 
    }

}

