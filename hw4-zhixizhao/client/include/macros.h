#define NULL_TERMINATOR 1 // remember null terminator

#define JOB 0x1          // determine type of request
#define RUN 0x2          // execute job via string
#define JENV 0x4         // environment variable support
#define STATUS_CHECK 0x8 // pass 0 to view all, else search by id
#define SEND_KILL 0x10   // pass in string "<id> <signal>"
#define CLEAR 0x20       // pass in job id to clear
#define SHUT 0x40        // shutdown server
