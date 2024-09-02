/**
 * gcc direct_io_read_write_file.c -o direct_io_read_write_file -D_GNU_SOURCE
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h> 
#include <string.h>
#define BUF_SIZE 1024
 
// int main(int argc, char * argv[])
// {
//     int fd, fd1;
//     int ret;
//     unsigned char *buf;
//     ret = posix_memalign((void **)&buf, 512, BUF_SIZE);
//     if (ret) {
//         perror("posix_memalign failed");
//         exit(1);
//     }
//     memset(buf, 'c', BUF_SIZE);
 
//     fd = open("/dev/sda", O_RDONLY | O_DIRECT | O_LARGEFILE, 0755);
//     if (fd < 0){
//         perror("open /dev/sda failed");
//         exit(1);
//     }
 
//     fd1 = open("./direct_io.data", O_WRONLY | O_DIRECT | O_CREAT, 0755);
//     if (fd1 < 0){
//         perror("open ./direct_io.data failed");
//         close(fd);
//         exit(1);
//     }
 
//     do {
//         ret = read(fd, buf, BUF_SIZE);
//         if (ret < 0) {
//             perror("read /dev/sda failed");
//         }
//         ret = write(fd1, buf, BUF_SIZE);
//         if (ret < 0) {
//             perror("write ./direct_io.data failed");
//         }
//     } while (1);
 
//     free(buf);
//     close(fd);
//     close(fd1);
//     return 0;
// }

int main()
{
    
    int fildes[2];
    pid_t pid;
    int i, j;
    char buf[256];
    if ( pipe( fildes ) < 0 )
    {
        fprintf( stderr, "pipe error!\n" );
        return -1;
    }
    if ( (pid = fork() ) < 0 )
    {
        fprintf( stderr, "fork error!\n" );
        return -1;
    }
    if ( pid == 0 )
    {
        close( fildes[0] );
        sleep(3);
        int sz = write( fildes[1], "Hello!", sizeof("Hello!") );
        printf("child: %d", sz);
        return 10;
    }
    memset( buf, 0, sizeof(buf) );
    close( fildes[1] );
    j = read( fildes[0], buf, sizeof(buf));
    printf("j: %d\n", j);
    printf("string: %s", buf);
    return 0;
}