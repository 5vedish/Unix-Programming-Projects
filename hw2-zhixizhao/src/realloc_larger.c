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

    char *s;
    s = NULL;

    int fd = open("logs.csv", O_CREAT | O_WRONLY);

    lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    lkmalloc(64, &s, LKM_INIT | LKM_UNDER | LKM_OVER);
    lkmalloc(128, &i, LKM_REALLOC);

    struct CleanUp *clean = malloc(sizeof(struct CleanUp));
    clean -> fd = fd;
    clean -> flags = 0x3f;

    on_exit(&exit_func, (void *) clean);
    exit(0);
}