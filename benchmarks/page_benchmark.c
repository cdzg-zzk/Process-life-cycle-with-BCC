
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
 
int main(int argc, const char * argv[]) {
    int page_size = getpagesize();
    //申请内存
    int* arr = (int*)(mmap(
                    NULL,                   //分配的首地址
                    3*page_size,          //分配内存大小(必须是页的整数倍, 32位1页=4k)
                    PROT_READ | PROT_WRITE, //映射区域保护权限：读|写
                    MAP_ANON | MAP_SHARED,  //匿名映射(不涉及文件io), 后面两个参数忽略
                    0,                      //要映射到内存中的文件描述符
                    0                       //文件映射的偏移量，通常设置为0，必须是页的整数倍
                ));
    int gap = page_size / sizeof(int);
    arr[0] = 10;
    arr[gap] = 20;
    arr[2*gap] = 30;

    
    //释放指针arr指向的内存区域，并制定释放的内存大小
    munmap(arr, getpagesize());
    sleep(5);
    return 0;
}


// #include <stdio.h>
// #include <sys/mman.h>
// #include <fcntl.h>
// #include <errno.h>
// #include <sys/stat.h>
// #include <unistd.h>
// int main(int argc, char *argv[])
// {
//     int fd = 0;
//     char *ptr = NULL;
//     struct stat buf = {0};
 
//     if (argc < 2)
//     {
//         printf("please enter a file!\n");
//         return -1;
//     }
 
//     if ((fd = open(argv[1], O_RDWR)) < 0)
//     {
//         printf("open file error\n");
//         return -1;
//     }
 
//     if (fstat(fd, &buf) < 0)
//     {
//         printf("get file state error:%d\n", errno);
//         close(fd);
//         return -1;
//     }
 
//     ptr = (char *)mmap(NULL, 3*getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
//     if (ptr == MAP_FAILED)
//     {
//         printf("mmap failed\n");
//         close(fd);
//         return -1;
//     }
//     close(fd);
//     printf("start addr is %p", ptr);
//     ptr[0] = 'a';
//     ptr[5000] = 'c';
//     // ptr[10000] = 'e';
//     // printf("length of the file is : %ld\n", buf.st_size);
//     // printf("the %s content is : %s\n", argv[1], ptr);
 
//     // ptr[] = 'a';
//     // printf("the %s new content is : %s\n", argv[1], ptr);
//     munmap(ptr, buf.st_size);
//     sleep(10);
//     return 0;
// }