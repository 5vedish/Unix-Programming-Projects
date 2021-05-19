#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

//My Includes
#include <headers.h>

int main(){

    char *i;
    i = NULL;

    int fd = open("logs.csv", O_CREAT | O_WRONLY);

    lkfree(&i, LKF_UNKNOWN);

    struct CleanUp *clean = malloc(sizeof(struct CleanUp));
    clean -> fd = fd;
    clean -> flags = 0x3f;

    on_exit(&exit_func, (void *) clean);
    exit(0);
}