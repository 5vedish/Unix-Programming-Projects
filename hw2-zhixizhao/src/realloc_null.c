#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

//My Includes
#include <headers.h>

int main(){

    int exit_status = EXIT_SUCCESS;
    int ans;

    char *i;
    i = NULL;

    int fd = open("logs.csv", O_CREAT | O_WRONLY);

    ans = lkmalloc(32, &i, LKM_REALLOC);

    if (ans == -LKM_REALLOC){
        exit_status = EXIT_FAILURE;
    }

    struct CleanUp *clean = malloc(sizeof(struct CleanUp));
    clean -> fd = fd;
    clean -> flags = 0x3f;

    on_exit(&exit_func, (void *) clean);
    exit(exit_status);
}