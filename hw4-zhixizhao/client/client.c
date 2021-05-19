#include <headers.h>
#include <protocol.h>
#include <macros.h>

int main(int argc, char *argv[])
{
    int exit_status = EXIT_SUCCESS;

    int option; // store getopt return value

    char *command; // command storage
    int buf_siz;   // dynamic buffer
    int id;        // target job

    while ((option = getopt(argc, argv, "jr:es:k:c:x")) != -1) // parsing all possible options
    {

        switch (option)
        {
        case 'j':
            global_options = global_options | JOB;
            break;

        case 'r':
            global_options = global_options | RUN;
            command = optarg;
            break;

        case 'e':
            global_options = global_options | JENV;
            break;

        case 's':
            global_options = global_options | STATUS_CHECK;
            id = atoi(optarg);
            break;

        case 'k':
            global_options = global_options | SEND_KILL;
            command = optarg;
            break;

        case 'c':
            global_options = global_options | CLEAR;
            id = atoi(optarg);
            break;

        case 'x':
            global_options = global_options | SHUT;
            break;

        default:
            break;
        }
    }

    struct Request *req; // request struct
    int extra = 0;       // possible added sizes

    if (global_options & RUN) // determining request to send
    {
        buf_siz = strlen(command) + NULL_TERMINATOR;
        req = malloc(sizeof(struct Request) + buf_siz);
        req->code = JOB_CODE;
        req->size = buf_siz;
        memcpy(req->payload, command, req->size - 1); // storing command
        extra = buf_siz;
    }
    else if (global_options & STATUS_CHECK)
    {

        req = malloc(sizeof(struct Request));

        req->code = STATUS;
        req->size = id; // size serves as id to search for
    }
    else if (global_options & SEND_KILL)
    {

        buf_siz = strlen(command) + NULL_TERMINATOR;
        req = malloc(sizeof(struct Request) + buf_siz);
        req->code = KILL;
        req->size = buf_siz;
        memcpy(req->payload, command, req->size - 1); // storing command
        extra = buf_siz;
    }
    else if (global_options & CLEAR)
    {
        req = malloc(sizeof(struct Request));
        req->code = CLOSE;
        req->size = id; // size serves as id to search for
    }
    else if (global_options & SHUT)
    {
        req = malloc(sizeof(struct Request));
        req->code = SHUTDOWN;
    }

    char *client_server = "/tmp/client-server"; // file names for FIFOS
    char *server_client = "/tmp/server-client";

    FILE *c_file, *s_file; // streams for FIFOS

    c_file = fopen(client_server, "w"); // opening pipes
    s_file = fopen(server_client, "r");

    fwrite(req, sizeof(struct Request) + extra, 1, c_file); // sending request
    fflush(c_file);

    // Receiving Response

    char *recv = malloc(sizeof(int)); // dynamic buffer

    if (global_options & JOB) // determining type of response to expect
    {

        fread(recv, sizeof(int), 1, s_file); // read status code and id
        int status_code = *((int *)recv);

        if (status_code == OK)
        {
            fread(recv, sizeof(int), 1, s_file);
            int id = *((int *)recv);

            printf("Successfully submitted job id: %d\n", id);
            fflush(stdout);
        }
    }
    else if (global_options & STATUS_CHECK) // parse statuses
    {

        fread(recv, sizeof(int), 1, s_file); // knowing total jobs to parse in advance
        int total_jobs = *((int *)recv);
        char *msg;

        struct JobStatus *status = malloc(sizeof(struct JobStatus)); // storage for status

        for (int i = 0; i < total_jobs; i++)
        {

            fread(status, sizeof(struct JobStatus), 1, s_file);

            printf("Job Id: %d\n", status->job_id);

            if (status->status == CLD_EXITED) // correspond the statuses
            {
                msg = "Exited";
            }
            else if (status->status == CLD_KILLED)
            {
                msg = "Killed";
            }
            else if (status->status == CLD_STOPPED)
            {
                msg = "Stopped";
            }
            else if (status->status == CLD_CONTINUED)
            {
                msg = "Continued";
            }
            else if (status->status == CLD_DUMPED)
            {
                msg = "Dumped";
            }
            else
            {
                msg = "Running";
            }

            printf("Status: %s\n", msg);

            if (status->ret == 55555)
            {
                printf("Return Value: N/A\n");
            }
            else
            {
                printf("Return value: %d\n", status->ret);
            }
        }
        free(status);
    }
    else if (global_options & SEND_KILL) // send signal to id
    {

        struct JobSignal *sig = malloc(sizeof(struct JobSignal)); // space for signal

        fread(sig, sizeof(struct JobSignal), 1, s_file);

        printf("Signal %d sent to job %d\n", sig->signal, sig->job_id);
        free(sig);
    }
    else if (global_options & CLEAR)
    {
        printf("Job id %d was cleared\n", id);
    }
    else if (global_options & SHUT)
    {
        printf("Server has shut down.\n");
    }

    fclose(c_file); // clean up
    fclose(s_file);

    free(req);

    exit(exit_status);
}