#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>

int main( void )
{


    int j = open("/", 0);    
    int i = openat(j, "/flag", 0);


    printf("%d, %d", AT_FDCWD, i);
}