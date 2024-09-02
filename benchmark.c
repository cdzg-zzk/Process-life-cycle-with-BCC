#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

// 定义信号处理函数
void signal_handler(int signum) {
    printf("Received signal: %d\n", signum);
}

int fibonacci(int n) {
    if (n <= 0)
        return 0;
    else if (n == 1)
        return 1;
    else
        return fibonacci(n - 1) + fibonacci(n - 2);
}

int main() {
    // 注册信号处理函数
    signal(SIGINT, signal_handler);

    // 进行I/O操作
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
    printf("Read %zd bytes from /dev/random \n", bytes_read);
    close(fd);
    fd = open("./examaaaaaaaaa.txt", O_WRONLY | O_CREAT);
    if (fd == -1) {
        perror("无法打开或创建文件");
        return 1;
    }
    ssize_t bytes_written = write(fd, "content\n", 500);
    printf("actual write bytes: %zd\n", bytes_written);
    close(fd);


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
        write( fildes[1], "Hello!", strlen( "Hello!" ) );
        return 10;
    }
    memset( buf, 0, sizeof(buf) );
    close( fildes[1] );
    j = read( fildes[0], buf, sizeof(buf) );
    int loop = 50;
    while (loop--) {
        // 进行一些计算密集型操作
        for (int i = 0; i < 10000; i++) {
        // for (int i = 0; i < 100; i++) {
            int sum = 0;
            for (int j = 0; j < 1000; j++) {
                sum += i * j;
            }
        }
        break;
    }
    int ret = fibonacci(43);
    printf("ret: %d\n", ret);
    sleep(1);
    return 0;
}