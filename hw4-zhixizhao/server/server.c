#include <headers.h>
#include <macros.h>
#include <protocol.h>

struct Job **jobs; // storage for jobs
int job_index;     // current index of job
int max_jobs;      // user defined max number of jobs default 64

void sig_child_handler(int signum, siginfo_t *siginfo, void *ucontext)
{
    int status; // stores the status of wait

    if (ucontext == NULL) // context check
    {
        fprintf(stderr, "Context is null for signum %d\n", signum);
    }

    int w; // waiting for sigchild
    while (!(w = waitid(P_ALL, -1, siginfo, WEXITED | WSTOPPED | WCONTINUED | WNOHANG)))
    {

        if (siginfo->si_code == CLD_EXITED) // determining reason why signal was sent
        {
            status = CLD_EXITED; // determining statuses
        }
        else if (siginfo->si_code == CLD_STOPPED)
        {
            status = CLD_STOPPED;
        }
        else if (siginfo->si_code == CLD_KILLED)
        {
            status = CLD_KILLED;
        }
        else if (siginfo->si_code == CLD_DUMPED)
        {
            status = CLD_DUMPED;
        }
        else if (siginfo->si_code == CLD_CONTINUED)
        {
            status = CLD_CONTINUED;
        }

        if (siginfo->si_pid == 0) // handling return in child
        {
            break;
        }

        for (int i = 0; i < max_jobs; i++) // setting status
        {

            struct Job *job = jobs[i];

            if (job->pid == siginfo->si_pid) // match pid
            {
                job->status = status;
                job->job = siginfo->si_status;
                break;
            }
        }
    }
}

int main(int argc, char *argv[])
{
    printf("Server Started.\n");
    int exit_status = EXIT_SUCCESS;

    int option;                  // return for getopt
    max_jobs = DEFAULT_MAX_JOBS; // max num of jobs

    while ((option = getopt(argc, argv, "n:")) != -1) // argument parsing for custom max jobs
    {

        switch (option)
        {
        case 'n':
            max_jobs = atoi(optarg); // retrieving int
            break;

        default:
            break;
        }
    }

    jobs = malloc(sizeof(struct Job) * max_jobs); // space for jobs storage
    job_index = 0;                                // initial job index

    if (jobs == NULL) // no memory for jobs storage
    {
        perror("Insufficient memory for jobs");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < max_jobs; i++) // initializing jobs storage
    {
        jobs[i] = NULL;
    }

    char *client_server = "/tmp/client-server"; // names of FIFOS
    char *server_client = "/tmp/server-client";

    FILE *c_file, *s_file; // streams for FIFOS

    char *buf; // dynamic buffer

    while (1)
    {
        int mk;

        mk = mkfifo(client_server, 0666); // creating client to serve pipe

        if (mk < 0)
        {
            perror("Failed to create client-to-server pipe");
            exit_status = EXIT_FAILURE;
            break;
        }

        mk = mkfifo(server_client, 0666); // creating server to client pipe

        if (mk < 0)
        {
            clean_pipes(client_server, server_client, c_file, s_file, 1);
            perror("Failed to create server-to-client pipe");
            exit_status = EXIT_FAILURE;
            break;
        }

        c_file = fopen(client_server, "r"); // opening stream to read from client

        if (c_file == NULL)
        {
            clean_pipes(client_server, server_client, c_file, s_file, 2);
            perror("Failed to create client-to-server stream");
            exit_status = EXIT_FAILURE;
            break;
        }

        s_file = fopen(server_client, "w"); // opening stream to write to client

        if (s_file == NULL)
        {
            clean_pipes(client_server, server_client, c_file, s_file, 3);
            perror("Failed to create server-to-client stream");
            exit_status = EXIT_FAILURE;
            break;
        }

        buf = malloc(sizeof(int)); // space for buffer

        fread(buf, sizeof(int), 1, c_file); // reading request code
        int code = *((int *)buf);

        if (code == JOB_CODE) // determining action to take
        {
            if (next_available() == max_jobs) // exceed max num of jobs
            {
                fprintf(stderr, "Maximum job limit reached.\n");
                clean_pipes(client_server, server_client, c_file, s_file, 4);

                continue;
            }

            struct Job *job = malloc(sizeof(struct Job)); // creating job and setting fields
            job->job = code;

            job_index = next_available(); // finding next available index
            jobs[job_index++] = job;      // storing in array
            job->id = job_index;          // establishing unique id

            fread(buf, sizeof(int), 1, c_file); // determnining size of command
            int buf_siz = *((int *)buf);
            job->size = buf_siz;

            buf = realloc(buf, buf_siz); // resizing to store command

            fread(buf, buf_siz, 1, c_file);

            char *jargv = malloc(buf_siz); // storage for command

            if (jargv == NULL) // no space to store command
            {
                clean_pipes(client_server, server_client, c_file, s_file, 4);
                perror("Insufficient memory for job argv");
                exit_status = EXIT_FAILURE;
                break;
            }

            memcpy(jargv, buf, buf_siz); // saving command in job
            job->argv = jargv;

            process_job(job->id); // executing job

            struct JobResponse *res = malloc(sizeof(struct JobResponse)); // space for response

            res->status_code = OK;
            res->job_id = job_index;

            fwrite(res, sizeof(struct JobResponse), 1, s_file); // respond to client
            fflush(s_file);

            free(res);
        }
        else if (code == STATUS) // client requests status of 1+ jobs
        {
            struct JobStatus *status = malloc(sizeof(struct JobStatus)); // store response
            int total_jobs = 0;

            fread(buf, sizeof(int), 1, c_file); // retrieving index
            int index = *((int *)buf);

            if (index != 0) // requests specific job
            {

                total_jobs = 1;
                fwrite(&total_jobs, sizeof(int), 1, s_file); // client knows to parse one response

                struct Job *current_job = jobs[index - 1];

                status->job_id = current_job->id;
                status->status = current_job->status;

                if ((current_job->status != CLD_EXITED) && (current_job->status != CLD_KILLED) &&
                    (current_job->status != CLD_DUMPED))
                {
                    status->ret = 55555;
                }
                else
                {
                    status->ret = current_job->job;
                }

                fwrite(status, sizeof(struct JobStatus), 1, s_file); // sending status
                fflush(stdout);

                // extract_data(current_job, s_file);

                free(status);
                clean_pipes(client_server, server_client, c_file, s_file, 4);
                continue;
            }

            for (int i = 0; i < max_jobs; i++) // finding total existing jobs
            {
                if (jobs[i] != NULL)
                {
                    total_jobs += 1;
                }
            }

            fwrite(&total_jobs, sizeof(int), 1, s_file); // client knows how many responses

            for (int i = 0; i < max_jobs; i++)
            {
                if (jobs[i] == NULL)
                {
                    continue;
                }

                struct Job *current_job = jobs[i];

                status->job_id = current_job->id;
                status->status = current_job->status;

                if ((current_job->status != CLD_EXITED) && (current_job->status != CLD_KILLED) &&
                    (current_job->status != CLD_DUMPED))
                {
                    status->ret = 55555;
                }
                else
                {
                    status->ret = current_job->job;
                }

                fwrite(status, sizeof(struct JobStatus), 1, s_file); // sending response

                // extract_data(current_job, s_file);
            }

            fflush(s_file);

            free(status);
        }
        else if (code == KILL) // sending a signal to a process
        {

            fread(buf, sizeof(int), 1, c_file); // determining size of args "id signal"
            int buf_siz = *((int *)buf);
            buf = realloc(buf, buf_siz); // resizing to fit args

            fread(buf, buf_siz, 1, c_file);

            char *jargv = malloc(buf_siz); // space for args

            if (jargv == NULL) // no space for args
            {
                clean_pipes(client_server, server_client, c_file, s_file, 4);
                perror("Insufficient memory for job argv");
                exit_status = EXIT_FAILURE;
                break;
            }

            memcpy(jargv, buf, buf_siz); // storing args

            kill_job(jargv, s_file); // sending signal

            free(buf);
        }
        else if (code == CLOSE) // erasing a job
        {

            fread(buf, sizeof(int), 1, c_file); // determining which job to erase
            int id = *((int *)buf);

            struct Job *temp = jobs[id - 1];

            free(temp->argv); // free the job's arguments

            jobs[id - 1] = NULL; // erasing job
        }
        else if (code == SHUTDOWN) // close server
        {
            printf("Server has shutdown.\n");
            break;
        }

        clean_pipes(client_server, server_client, c_file, s_file, 4); // reset pipes and streams
    }

    for (int i = 0; i < max_jobs; i++) // clearing memory allocation upon shutdown
    {
        if (jobs[i] != NULL)
        {
            free(jobs[i]->argv);
        }
    }

    free(jobs);
    clean_pipes(client_server, server_client, c_file, s_file, 4);
    exit(exit_status);
}

void clean_pipes(char *link1, char *link2, FILE *stream1, FILE *stream2, int progress)
{

    for (int i = 0; i < progress; i++) // custom function to close streams and unlink files
    {                                  // depending on where it is called in the server loop

        if (i == 0)
        {
            unlink(link1);
        }

        if (i == 1)
        {
            unlink(link2);
        }

        if (i == 2)
        {
            fclose(stream1);
        }

        if (i == 3)
        {
            fclose(stream2);
        }
    }
}

int process_job(int jindex)
{
    struct Job *current_job = jobs[jindex - 1]; // accessing job

    current_job->status = RUNNING; // set status

    char *filler = current_job->argv; // argument passed to strtok
    char *token = NULL;               // actual token from strtok

    char **cmd = malloc(DEFAULT_CMD_LIMIT * sizeof(char *)); // buffer for commands

    if (cmd == NULL)
    { // failed to allocate space for command
        perror("Failed to allocate memory for command");
    }

    for (int i = 0; i < DEFAULT_CMD_LIMIT; i++)
    { // initializing commands
        cmd[i] = NULL;
    }

    int index = 0;
    while ((token = strtok(filler, " ")) != NULL)
    { // loop token by token delimiting by space

        cmd[index] = token; // storing token
        index += 1;

        if (index == DEFAULT_CMD_LIMIT) // 64 tokens
        {                               // exceeded max num of tokens
            fprintf(stderr, "Error: Exceeded Max Commands\n");
            fflush(stderr);
        }

        filler = NULL; // reset for strtok
    }

    int name_len = snprintf(NULL, 0, "%d", current_job->id); // turning id into filename
    char *name = malloc(name_len + 1);                       // include null terminator
    snprintf(name, name_len + 1, "%d", current_job->id);

    int job_fd = open(name, O_WRONLY | O_CREAT | O_TRUNC);
    int perms = fchmod(job_fd, 0666); // permissions to access file

    char *name_err = strcat(name, ".err"); // turning id into error log filename
    int err_fd = open(name_err, O_WRONLY | O_CREAT | O_TRUNC);
    int err_perms = fchmod(err_fd, 0666); // permissions to access error log

    if (perms < 0) // failed to set permissions for either file
    {
        perror("Failed to change job file permissions");
    }

    if (err_perms < 0)
    {
        perror("Failed to change job error file permissions");
    }

    // int status;
    pid_t pid = fork();

    struct sigaction action; // setting up signal handler

    action.sa_sigaction = &sig_child_handler;  // providing callback
    action.sa_flags = SA_SIGINFO | SA_RESTART; // to access proper information from signal

    sigaction(SIGCHLD, &action, NULL); // mounting handler

    if (pid == 0)
    { // child process

        dup2(job_fd, STDOUT_FILENO); // output and errors to respective files
        dup2(err_fd, STDERR_FILENO);

        int ex_code = execvpe(cmd[0], cmd, NULL); // executing external command w/ our argv

        if (ex_code < 0)
        { // failed to execute command
            perror("Failed to execute command");
        }

        exit(EXIT_SUCCESS);
    }
    else
    { // parent process

        if (pid < 0)
        { // failed to fork
            perror("Failed to spawn child process");
        }

        current_job->pid = pid; // establishing pid for job
    }

    free(cmd);
    free(name);

    return 0;
}

void kill_job(char *cmd, FILE *f) // selectively send signal to job
{

    struct Job *target_job;

    char *filler = cmd; // argument passed to strtok
    char *token = NULL; // actual token from strtok

    int id, signal;

    int index = 0;
    while ((token = strtok(filler, " ")) != NULL)
    { // loop token by token delimiting by space

        if (index == 0) // id
        {
            id = atoi(token);
        }
        else // signal number
        {
            signal = atoi(token);
        }

        filler = NULL; // reset for strtok
        index++;
    }

    target_job = jobs[id - 1];

    kill(target_job->pid, signal); // sending signal

    struct JobSignal *sig = malloc(sizeof(struct JobSignal)); // response for client

    sig->job_id = id; // setting fields for response
    sig->signal = signal;

    fwrite(sig, sizeof(struct JobSignal), 1, f); // sending response
    fflush(f);
}

void extract_data(struct Job *job, FILE *f)
{
    if (job->status != RUNNING) // ignore non running jobs = cannot print meta data
    {
        return;
    }

    int pid_len = snprintf(NULL, 0, "%d", job->pid); // turn pid into string
    char *pid_str = malloc(pid_len + 1);             // include null terminator
    snprintf(pid_str, pid_len + 1, "%d", job->pid);

    int buf_siz = 6 + strlen(pid_str) + 7 + 1;

    char name[buf_siz]; // buffer for metadata filename

    strcat(name, "/proc/"); // constructing filename
    strcat(name, pid_str);
    strcat(name, "/status");

    name[strlen(name)] = '\0';

    FILE *meta_info = fopen(name, "r");

    perror(name);

    if (f)
    {
    }

    fclose(meta_info);
}

int next_available() // determining next available empty space
{

    for (int i = 0; i < max_jobs; i++)
    {
        if (jobs[i] == NULL)
        {
            return i;
        }
    }

    return max_jobs;
}