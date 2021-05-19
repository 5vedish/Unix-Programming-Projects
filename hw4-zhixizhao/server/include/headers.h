#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <wait.h>
#include <sys/wait.h>
#include <signal.h>

struct Job // server end job storage format
{
    int id;     // unique identifier
    int pid;    // child process
    int status; // state
    int job;    // serves as the return code
    int size;   // size of argv
    char *argv; // command
};
// custom clean up function for pipes and streams
extern void clean_pipes(char *link1, char *link2, FILE *stream1, FILE *stream2, int progress);
// execute job
extern int process_job(int index);
// child handler for when child process of job changes state
extern void sig_child_handler(int signum, siginfo_t *siginfo, void *ucontext);
// send signal to job
extern void kill_job(char *cmd, FILE *f);
// retrieve meta data
extern void extract_data(struct Job *job, FILE *f);
// next available space for job storage
extern int next_available();
