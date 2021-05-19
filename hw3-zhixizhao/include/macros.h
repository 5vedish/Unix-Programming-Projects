#define DEFAULT_ARGS_LIMIT 100 // max num of args
#define DEFAULT_CMD_LIMIT 100 // max num of commands
#define DEFAULT_DIRECTORY_LIMIT 4096 // max path name len

#define DEFAULT_DIR_ENT_LIMIT 4096 // max num of dir entries
#define DIR_BUFF_SIZE 4096 // max size of dir entries storage

#define EXIT_FLAG 0x1 // flags for running commands
#define ECHO_FLAG 0x2
#define PWD_FLAG 0x4
#define CD_FLAG 0x8
#define EXEC_FLAG 0x10

#define V_PRINT(...) fprintf(stderr, __VA_ARGS__) // macro for debug printouts