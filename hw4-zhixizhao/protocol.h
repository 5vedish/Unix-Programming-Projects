struct Request // standard format for requests
{
    int code;        // type of request
    int size;        // size of command
    char payload[1]; // command
};

struct JobResponse // standard format for job submissions
{
    int status_code; // success
    int job_id;
};

struct JobStatus // standard format for status reports
{
    int job_id;
    int status; // current status of job
    int ret;    // return code of job
};

struct JobSignal // standard format for signal request responses
{
    int job_id;
    int signal;
};

//Job Codes
#define JOB_CODE 0 // job submission
#define STATUS 1   // check status(es)
#define KILL 2     // send signal to process
#define CLOSE 3    // erasing job
#define SHUTDOWN 4 // shutdown server

// Status Codes
#define OK 200