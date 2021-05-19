#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

//My Includes
#include <headers.h>

int main(){

    int exit_status;

    char *i;
    i = NULL;

    int fd = open("logs.csv", O_CREAT | O_WRONLY);

    const char *under = "kkkkkkkk";
    const char *over = "ZZZZZZZZ";
    const char mid[8] = {0,0,0,0};
    int a = 0,b = 0,c = 0;

    lkmalloc(8, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    lkmalloc(4, &i, LKM_INIT | LKM_UNDER | LKM_OVER | LKM_REALLOC);

    i -= 8;
    c = memcmp(i, under, 8);
    
    i += 8;
    c = memcmp(i, mid, 4);

    i += 4;
    c = memcmp(i, over, 8);

    if ((a != 0) || (b != 0) || (c != 0)){
        exit_status = EXIT_FAILURE;
    } else {
        exit_status = EXIT_SUCCESS;
    }

    struct CleanUp *clean = malloc(sizeof(struct CleanUp));
    clean -> fd = fd;
    clean -> flags = 0x3f;

    on_exit(&exit_func, (void *) clean);
    exit(exit_status);
}