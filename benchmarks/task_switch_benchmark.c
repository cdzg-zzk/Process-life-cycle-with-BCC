#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h> 
#include <string.h>
#define BUF_SIZE 1024

// int fibonacci(int n) {
//     if (n <= 0)
//         return 0;
//     else if (n == 1)
//         return 1;
//     else
//         return fibonacci(n - 1) + fibonacci(n - 2);
// }
// int main()
// {
//     int ret = 0;
//     sleep(1);
//     printf("ret = %d\n", ret);
//     return 0;
// }
// int fibonacci(int n) {
//     if (n <= 0)
//         return 0;
//     else if (n == 1)
//         return 1;
//     else
//         return fibonacci(n - 1) + fibonacci(n - 2);
// }

int main(int argc, char * argv[])
{
    int fd = open("/dev/random", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/random failed");
        return -1;
    }
    char buffer[256];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        perror("read failed");
        close(fd);
        return -1;
    }
    printf("Read %zd bytes from /dev/randomxxx \n", bytes_read);
    close(fd);
    // sleep(1);
    // int sum = 0;
    // for(int i = 0; i < 10000; i++) {
    //     sum = i * i;
    // }
    // printf("%d\n", sum);
    // int ret = fibonacci(40);
    return 0;
}