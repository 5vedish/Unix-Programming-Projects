#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <wait.h>
#include <sys/time.h>
#include <sys/resource.h>

struct Arg{
    int in; // for redirection
    int out;
    int err;
    u_short arg_len; // length of the arguments
    char args[0]; // OOB data structure to store arguments
};

extern int debug_flag; // flag for debug printouts

extern int non_interactive_flag; // flag for non-interactive mode

extern int time_flag; // flag for time printouts

extern struct Arg* ret_arg(struct Arg* arg, FILE *script); // takes input from user

extern int parse_arg(char *input); // parses input from user

extern void my_exit(); // custom exit command

extern int echo(int index); // built in echo

extern int assign(); // assignment of env variables

extern int pwd(); // print working directory

extern int cd(char *path); // change directory

extern int execute(); // execute external commands

extern int set_streams(); // establish redirection

extern void argv_clean_up(); // free stored argv

extern int close_fds(struct Arg *); // clean up open fds