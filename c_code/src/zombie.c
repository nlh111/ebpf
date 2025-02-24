#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    pid_t pid = fork();

    if (pid < 0) {
        // fork失败
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        // 子进程
        printf("子进程: PID = %d\n", getpid());
        exit(0); // 子进程退出，变成僵尸进程
    } else {
        // 父进程
        printf("父进程: PID = %d\n", getpid());
        printf("子进程PID = %d\n", pid);
        //waitpid(pid, NULL, 0); // 等待子进程退出
        while (1) {
            sleep(1);
        }
    }

    return 0;
}