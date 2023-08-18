#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include <fcntl.h>
#include<sys/socket.h>
#include<arpa/inet.h>	
   
int main()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servaddr = {0};
    write(0, &sockfd, 1);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(1016);
    connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));



    char buffer[4096] = {0};
    int size;
    for(int i =0;i<761;++i){
        read(sockfd, buffer, 1);
        memset(buffer, 0, sizeof(buffer));
    }
    for(int i=0;i<5;++i){
        while(buffer[0] != '\n'){
            memset(buffer, 0, sizeof(buffer));
            read(sockfd, buffer, 1);
            printf("%s", buffer);

        }
        char ans[100] = {0};
        scanf("%s", ans);
        ans[strlen(ans)] = '\n';
        write(sockfd, ans, strlen(ans));
        for(int i=0;i<64;++i){
            read(sockfd, buffer, 1);
            memset(buffer, 0, sizeof(buffer));
        }


    }
    memset(buffer, 0, sizeof(buffer));
    while(buffer[0]!='}'){
        memset(buffer, 0, sizeof(buffer));
        read(sockfd, buffer, 1);
        printf("%s", buffer);
    } 

    // char buf[4096] = {0};
    // for(int i=0;i<761;++i){
    //     read(sockfd, buf, 1);
    //     memset(buf, 0, sizeof(buf));
    // }
    // while(buf[0] != '\n'){
    //     memset(buf, 0, sizeof(buf));
    //     read(sockfd, buf, 1);
    //     printf("%s", buf);
    // }
    // memset(buf, 0, sizeof(buf));
    // for(int i =0;i<5;++i){
    //     char hello[100] = {0};
    //     scanf("%s", hello);
    //     hello[strlen(hello)] = '\n';
    //     send(sockfd, hello, strlen(hello), 0);
    //     for(int i=0;i<64;++i){
    //         read(sockfd, buf, 1);
    //         memset(buf, 0, sizeof(buf));
    //     }
    //     while(buf[0] != '\n'){
    //         memset(buf, 0, sizeof(buf));
    //         read(sockfd, buf, 1);
    //         printf("%s", buf);
            
    //     }

    // }

    // memset(buf, 0, sizeof(buf));
    // while(buf[0]!='}'){
    //     memset(buf, 0, sizeof(buf));
    //     read(sockfd, buf, 1);
    //     printf("%s", buf);
    // }   
}

int pwncollege(){ }
// int main(int argc, char **argv){
//     // execve("/challenge/embryoio_level75", 0, 0);
//     // return 0;


//     // char *args[] = {"vaaitf", 0};
//     // execve("/challenge/embryoio_level135", 0, 0);
//     // return 0;
//     // printf("%s", argv[1]);
//     int i = fork();
//     char *args[173];
//     for(int i=0;i<173;++i) args[i]="";
//     args[0] = "/challenge/embryoio_level83";
//     args[171] = "uchxmpxbxl";
//     args[172] = 0;
//     char *envp[]={"150=ldsxzzrvec", 0};
//     if(i == 0) {
//         execve("/challenge/embryoio_level83", args, envp);
//     }
//     else {
//         waitpid(i, NULL, 0); 
//     }
//     return 0;




//     if(i == 0) {
        
//         // int fds[2];
//         // pipe(fds);

//         // int fd = open("ghycgb", O_RDONLY);

//         // int j = fork();
//         // if(j!=0){


//         //     // pipe(fds);

//         //     // int k = fork();
//         //     // if(k!=0){
//         //     //     dup2(fds[0], 0);
//         //     //     close(fds[1]);
//         //     //     execl("/usr/bin/cat", "/usr/bin/cat", 0);
//         //     // }else{
                
//         //     // }

//         //     dup2(fds[1], 1);
//         //     close(fds[0]);
//             // execve("/challenge/embryoio_level83", args, envp);
            


//         // }else{
//         //     dup2(fds[0], 0);
//         //     close(fds[1]);
//         //     execl("/usr/bin/cat", "/usr/bin/cat", 0);
//         // }
//         // // setenv("19","wpzcvksbtt",1);
//         // dup2(fd, 0);
//         // chdir("/tmp/mwitgy");
//         execve("/challenge/embryoio_level83", args, envp);
//         // execl("/challenge/embryoio_level82", 0);
        

//     }
//     else {
//         waitpid(i, NULL, 0); 
//     }
//     return 0;
// }


