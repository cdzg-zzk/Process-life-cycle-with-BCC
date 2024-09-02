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
    fibonacci(46);
    sleep(1);
    return 0;
}