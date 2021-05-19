#include <tish.h>
#include <macros.h>

int debug_flag; // flag for debug printouts
int non_interactive_flag; // flag for non-interactive mode
int time_flag; // flag for time printouts

struct Arg **args; // global arg storage
char **cmd; // current command to be run
int arg_ind; // index of current argument
int prv_ret; // return value of most recent command

int main(int argc, char *argv[]){

    debug_flag = 0; // initializing flags
    non_interactive_flag = 0;
    time_flag = 0;

    arg_ind = 0; // initializing starting index and return value
    prv_ret = 0;

    int option; // store getopt return value

    while ((option = getopt(argc, argv, "dt")) != -1){

        switch (option)
        {
        case 'd': // debug printout
            debug_flag = 1;
            break;

        case 't': // time printout
            time_flag = 1;
            break;
        
        default:
            break;
        }

    }

    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0;

    char *script =  argv[optind]; // script provided for non-interactive mode
    FILE *f; // stream for script

    if (script != NULL){ // if script exists

        struct stat s;

        int script_stat = lstat(script, &s); // attempt to stat

        if (script_stat < 0){ // stat failed
            perror("Failed to lstat script");
            (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, EXIT_FAILURE) : 0; 
            exit(EXIT_FAILURE);
        }

        f = fopen(script, "r"); // open stream to script

        if (f == NULL){ // failed to open script
            perror("Failed to open script");
            (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, EXIT_FAILURE) : 0; 
            exit(EXIT_FAILURE);
        }

        non_interactive_flag = 1; // set flag
    } 

    args = malloc(DEFAULT_ARGS_LIMIT * sizeof(struct Arg*)); // allocating space for
    // arguments

    if (args == NULL){ // out of mem for args
        perror("Args Array Allocation");
    }

    for (int i = 0; i < DEFAULT_ARGS_LIMIT; i++){ // initializing array
        args[i] = NULL;
    }

    while (1) { // loop for tish

        struct Arg *arg = NULL;
        
        arg = ret_arg(arg, f); // retrieve argument

        if (arg == NULL){  // failed to retrieve next argument

            if (non_interactive_flag){ // end of script
                fclose(f);
                break;
            } else {
                continue; // wait for next interactive argument
            }

        }

        args[arg_ind] = arg; // store arg and increment index
        arg_ind++;

        if (arg_ind == DEFAULT_ARGS_LIMIT){ // overwrite starting from beginning
            arg_ind = 0;
        }

        parse_arg(arg -> args); // process arg

    }

    argv_clean_up(); // default clean up and exit
    free(args);

    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, EXIT_FAILURE) : 0; 
    exit(EXIT_FAILURE);
}

struct Arg* ret_arg(struct Arg *arg, FILE *script){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    (non_interactive_flag) ? 0 : dprintf(STDIN_FILENO ,"tish> "); // prompt user

    char *lineptr = NULL; // buffer for command
    size_t size = 0; // sizes for getline
    ssize_t s;

    if (non_interactive_flag){ // read from script

        s = getline(&lineptr, &size, script);

        if (s < 0){
            return NULL;
        }

    } else {
        s = getline(&lineptr, &size, stdin); // read from stdin
    }

    if (s < 0){ // failed to read line
        perror("Function <getline> failed");
        free(lineptr);
        return NULL;
    }

    size_t len = strlen(lineptr) + 1; // include null terminator

    arg = malloc(sizeof(struct Arg) + len); // space for arg

    if (arg == NULL){ // failed to allocate space for arg
        perror("Failed to malloc Arg struct");
        free(lineptr);
        return NULL;
    }

    arg -> arg_len = len; 
    strncpy(arg -> args, lineptr, len); // copy into OOB buffer

    arg -> in = STDIN_FILENO; // default fds
    arg -> out = STDOUT_FILENO;
    arg -> err = STDERR_FILENO;

    free(lineptr);

    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%p)\n", __func__, arg) : 0; 
    return arg;
}

int parse_arg(char *input){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    struct Arg *arg = args[arg_ind - 1]; // current arg

    char *filler = input; // argument passed to strtok
    char *token = NULL; // actual token from strtok

    cmd = malloc(DEFAULT_CMD_LIMIT * sizeof(char *)); // buffer for commands

    if (cmd == NULL){ // failed to allocate space for command
        perror("Failed to allocate memory for command");
        prv_ret = -1;
        (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
        return -1;
    }

    for (int i = 0; i < DEFAULT_CMD_LIMIT; i++){ // initializing commands
        cmd[i] = NULL;
    }

    int index = 0;
    while ((token = strtok(filler, " ")) != NULL){ // loop token by token delimiting by space
        
        cmd[index] = token; // storing token
        index += 1;

        if (index == DEFAULT_CMD_LIMIT){ // exceeded max num of tokens
            fprintf(stderr, "Error: Exceeded Max Commands\n");
            prv_ret = -1;
            (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
            return -1;
        }

        filler = NULL; // reset for strtok
    }

    int len = strlen(cmd[index-1]);
    filler = cmd[index-1];
    filler += len - 1;
    *filler = '\0'; // truncate newline

    int redir = set_streams(); // determine redirection

    if (redir < 0){ // failed to set streams
        free(cmd);
        prv_ret = -1;
        return -1;
    }

    // executions

    int status, s, flags = 0; // for waitpid, strcmp, and options for executing

    if ((s = strncmp(cmd[0], "#", 1)) == 0){ // handling comments : do nothing
        free(cmd);
        close_fds(arg);
        (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, 0) : 0; 
        return 0;
    }

    if ((s = strcmp(cmd[0], "exit")) == 0){ // setting options for execution
        flags = flags | EXIT_FLAG;
    } else if ((s = strcmp(cmd[0], "echo")) == 0){
        flags = flags | ECHO_FLAG;
    } else if ((s = strcmp(cmd[0], "pwd")) == 0){
        flags = flags | PWD_FLAG;
    } else if ((s = strcmp(cmd[0], "cd")) == 0){
        flags = flags | CD_FLAG;
    } else {
        if (strlen(cmd[0]) != 0){ // execute external command
            flags = flags | EXEC_FLAG;
        } 
    }

    // time printout : start time
    #ifdef EXTRA_CREDIT 
    
    struct rusage start;
    getrusage(RUSAGE_CHILDREN, &start);
    struct timeval start_user = start.ru_utime;
    struct timeval start_system = start.ru_stime;
    struct timeval start_real;
    gettimeofday(&start_real, NULL);

    #else
    #endif

    if (assign() == 0){ // no assignment of env variables

        pid_t pid = fork();

        if (pid == 0){ // child process

            if (flags & EXEC_FLAG){ // execute external command
                prv_ret = execute();
            }

            my_exit(); // kill child

        } else { // parent process

            if (pid < 0){ // failed to fork
                free(cmd);
                (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                return -1;
            }

            pid_t reap = waitpid(pid, &status, 0); // reap child

            if (reap < 0){ // failed to reap
                perror("Failed to reap child process");
            } 

            prv_ret = status; // previous return status

            if (flags & EXIT_FLAG){ // execute internal commands
                my_exit();
            } else if (flags & PWD_FLAG){
                prv_ret = pwd();
            } else if (flags & CD_FLAG){
                prv_ret = cd(cmd[1]);
            } else if (flags & ECHO_FLAG){
                prv_ret = echo(index);
            }

            // time printout : end time
            #ifdef EXTRA_CREDIT

            struct rusage end;
            getrusage(RUSAGE_CHILDREN, &end);
            struct timeval end_user = end.ru_utime;
            struct timeval end_system = end.ru_stime;
            struct timeval end_real;
            gettimeofday(&end_real, NULL);

            if (time_flag){
                fprintf(stderr, "TIMES: ");
                fprintf(stderr, "real=%lu.3s ", end_real.tv_sec - start_real.tv_sec);
                fprintf(stderr, "user=.%.3lus ", (end_user.tv_usec - start_user.tv_usec) / 1000);
                fprintf(stderr, "system=.%.3lus\n", \
                (end_system.tv_usec - start_system.tv_usec) / 1000);
                
            }

            #else
            #endif

        }
    }

    free(cmd);

    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, EXIT_FAILURE) : 0; 
    return 0;
}

void my_exit(){ // custom exit function
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    argv_clean_up(); // free allocated argvs

    free(args); // free global storages
    free(cmd);

    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, prv_ret) : 0; 
    exit(prv_ret);
}

int echo(int index){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    struct Arg *arg = args[arg_ind - 1]; // current arg

    if (index == 1){ // echo without arguments
        dprintf(arg -> out, "\n");
        goto exit_echo;
    }

    int dollar; // storage to indicate env var retrieval
    char *to_print; // string to print

    int avoid = -1; // flag to avoid parsing and echoing

    for (int i = 1; i < index; i++){ // loop through command to echo

        #ifdef EXTRA_CREDIT

        pid_t pid = fork(); // globbing echo

        if (pid == 0){ // child process

            if (strncmp(cmd[i], "*", 1) == 0){

                char *cwd = malloc(DEFAULT_DIRECTORY_LIMIT); // space for currrent working dir

                if (cwd == NULL){ // failed to allocate space for cwd
                    perror("Failed to allocate memory for globbing");
                }

                getcwd(cwd, DEFAULT_DIRECTORY_LIMIT); // fill buffer with cwd

                if (cwd == NULL){ // failed to retrieve cwd
                    perror("Failed to retrieve current working directory");
                }

                DIR *d = opendir(cwd); // open stream to directory

                if (d == NULL){ // failed to open directory
                    perror("Failed to open current working directory");
                }

                struct dirent *entry; // space for dir entry

                errno = 0; // resetting errno for readdir : distinguish between error and eof

                for (;;){
                    entry = readdir(d); // retrieve entry

                    if (entry == NULL){ // failed to retrieve next entry
                        if (errno == 0){ // eof
                            break;
                        } else { // error
                            perror("Failed to read directory entry");
                        }
                    }

                    if (strstr(entry -> d_name, cmd[i]+1)){ // checking extension
                        dprintf(arg -> out, "%s ", entry -> d_name);
                    }

                }

                dprintf(arg -> out, "\n");

                closedir(d); // clean up
                free(cwd);
            }

            my_exit();

        } else { // parent process

            int status;

            waitpid(pid, &status, 0); // reap child

            if (strncmp(cmd[i], "*", 1) == 0){ // parent skips command : handled by child
                continue;
            }

        }

        #else
        #endif

        if (avoid == 0){ // skip command
            avoid = -1;
            continue;
        }

        // skip redirection tokens
        if ((dollar = strncmp(cmd[i], ">", 1)) == 0 || \
            (dollar = strncmp(cmd[i], "<", 1)) == 0){
            avoid = 0;
            continue;
        } 

        if ((dollar = strncmp(cmd[i], "$", 1) == 0)){ // print env variables

            if ((dollar = strncmp(cmd[i], "$?", 2)) == 0){ // previous func return
                dprintf(arg -> out, "%d\n", prv_ret);
                continue;
            }
            
            to_print = getenv((cmd[i]) + 1); // ignore $

            if (to_print == NULL){ // env var doesn't exist
                to_print = "";
            }

        } else { // echo token
            to_print = cmd[i];
        }

        if (i != index - 1){ // formatting printing
            dprintf(arg -> out, "%s ", to_print);
        } else {
            dprintf(arg -> out, "%s\n", to_print);
        }

    }

    exit_echo:
    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, 0) : 0; 
    return 0;
}

int assign(){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    int assign = 0; // return value : num of vars assigned

    for (int i = 0; i < DEFAULT_CMD_LIMIT; i++){

        if (cmd[i] == NULL){
            break;
        }

        char *assignment = strchr(cmd[i], 61); // check for '='

        if (assignment != NULL){

            assign += 1;

            char *var = strtok(cmd[i], "="); // var name
            char *value = assignment + 1; // skip the = : var value

            int s = setenv(var, value, 1);

            if (s < 0){ // failed to set env var
                perror("Failed to set environment variable");
                assign = -1;
            }
        }
    }

    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, assign) : 0; 
    return assign;
}

int pwd(){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    struct Arg *arg = args[arg_ind - 1]; // current arg

    int ret_val = 0;

    char *cwd = malloc(DEFAULT_DIRECTORY_LIMIT); // space for current working dir

    cwd = getcwd(cwd, DEFAULT_DIRECTORY_LIMIT); // retrieving cwd

    if (cwd == NULL){ // failed to retrieve cwd
        dprintf(arg -> err, "Failed to retrieve working directory");
        ret_val = -1;
    }

    dprintf(arg -> out, "%s\n", cwd); // print cwd

    free(cwd);
    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, ret_val) : 0; 
    return ret_val;
}

int cd(char *path){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    int ret_val;

    struct Arg *arg = args[arg_ind - 1]; // current arg

    struct stat p; // for lstat

    if (lstat(path, &p) == -1){ // requested path doesn't exist
        dprintf(arg -> err, "Failed to lstat path: path does not exist\n");
        ret_val = -1;
        goto exit_cd;
    } else { // check if requested path is a directory

        if ((p.st_mode & S_IFDIR) == 0){ // path is not directory
            dprintf(arg -> err, "Failed to changed directory: path is not a directory\n");
            ret_val = -1;
            goto exit_cd;
        }

    }

    int c = chdir(path); // change directory to path

    if (c < 0){ // failed to change directory
        dprintf(arg -> err, "Failed to changed directory: No such file or directory");
        ret_val = -1;
    }

    exit_cd:
    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, ret_val) : 0; 
    return ret_val;
}

int execute(){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    struct Arg *arg = args[arg_ind - 1]; // current arg

    dup2(arg -> in, STDIN_FILENO); // redirect fds for external command
    dup2(arg -> out, STDOUT_FILENO);
    dup2(arg -> err, STDERR_FILENO);

    char **w_out_syms = malloc(DEFAULT_CMD_LIMIT * sizeof(char *)); // stripping illegal tokens

    if (w_out_syms == NULL){ // failed to allocate argv for exec
        dprintf(arg -> err, "%s", strerror(errno));
        (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
        return -1;
    }

    for (int i = 0; i < DEFAULT_CMD_LIMIT; i++){ // initializing argc for exec
        w_out_syms[i] = NULL;
    }

    char *s;
    int avoid = -1; // flag to avoid illegal tokens
    int j = 0; // separate index for passable argv

    for (int i = 0; i < DEFAULT_CMD_LIMIT; i++){

        if (cmd[i] == NULL){
            break;
        }

        if (i == avoid){ // avoid illegal tokens
            continue;
        }
        // avoiding > and <
        if ((s = strchr(cmd[i], 60)) != NULL || \
            (s = strchr(cmd[i], 62)) != NULL){
            avoid = i + 1;
        } else {
            // globbings for executing external commands
            #ifdef EXTRA_CREDIT

            if (strncmp(cmd[i], "*", 1) == 0){

                char *cwd = malloc(DEFAULT_DIRECTORY_LIMIT); // buffer for current working dir

                if (cwd == NULL){ // failed to allocate space for cwd
                    perror("Failed to allocate memory for globbing");
                    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                    return -1;
                }

                getcwd(cwd, DEFAULT_DIRECTORY_LIMIT); // retrieve cwd

                if (cwd == NULL){ // failed to retrieve cwd
                    perror("Failed to retrieve current working directory");
                    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                    return -1;
                }

                DIR *d = opendir(cwd); // open stream for dir

                if (d == NULL){ // failed to open stream for dir
                    perror("Failed to open current working directory");
                    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                    return -1;
                }

                struct dirent *entry;

                errno = 0; // resetting errno : distinguishing between error and eof

                for (;;){
                    entry = readdir(d); // next entry

                    if (entry == NULL){
                        if (errno == 0){ // eof
                            break;
                        } else { // error
                            perror("Failed to read directory entry");
                        }
                    }

                    if (strstr(entry -> d_name, cmd[i]+1)){ // checking extensions
                        w_out_syms[j++] = entry -> d_name;
                    }

                }

                closedir(d); // clean up
                free(cwd);

            } else {
                w_out_syms[j++] = cmd[i]; // store into argv
            }

            #else

            w_out_syms[j++] = cmd[i]; // store into argv

            #endif
        }

    }

    int e = execvp(cmd[0], w_out_syms); // executing external command w/ our argv

    if (e < 0){ // failed to execute command
        perror("Failed to execute command");
    }

    free(w_out_syms);

    close_fds(arg); // close new fds

    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, e) : 0; 
    return e;
}

int set_streams(){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    char *s; // storage for string comparisons
    int fd; // storage for fds
    struct Arg *arg = args[arg_ind - 1]; // current arg

    for (int i = 0; i < DEFAULT_CMD_LIMIT; i++){ // iterating to check requested redirection

        if (cmd[i] == NULL){
            break;
        }

        if ((s = strchr(cmd[i], 62)) != NULL){ // redirecting stdout >
            
            fd = openat(AT_FDCWD, cmd[i+1], O_WRONLY | O_CREAT | O_TRUNC); // open (/+ create) file

            if (fd < 0){ // failed to open file for stdout
                perror("Failed to open output file");
                (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                return -1;
            }

            mode_t perms = S_IRUSR | S_IWUSR; // setting default permissions
            int c = fchmod(fd, perms);

            if (c < 0){ // failed to change permissions for stdout file
                perror("Failed to change permissions of new file");
                (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                return -1;
            }

            if ((s = strchr(cmd[i], 50)) != NULL){ // redirecting stderr 2>
                arg -> err = fd;
            } else {
                arg -> out = fd; // redirecting stdout
            }

        }

        if ((s = strchr(cmd[i], 60)) != NULL){ // redirecting stdin <

            struct stat in; // check if input file exists/accessible

            if (lstat(cmd[i + 1], &in) == -1){ // input file doesn't exist/accessible
                dprintf(arg -> err, "Failed to lstat input file\n");
                (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                return -1;
            } else {

                if (in.st_mode & S_IFDIR){ // input file is a directory : illegal
                    dprintf(arg -> err, "Failed to open file: input file is a directory\n");
                    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                    return -1;
                }

            }

            fd = openat(AT_FDCWD, cmd[i+1], O_RDONLY); // open input file

            if (fd < 0){ // failed to open input file
                perror("Failed to open input file");
                (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, -1) : 0; 
                return -1;
            }

            arg -> in = fd; // redirecting stdin

        }

    }

    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, 0) : 0; 
    return 0;
}

void argv_clean_up(){ // clearing argv stored globally
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    for (int i = 0; i < DEFAULT_ARGS_LIMIT; i++){

        if (args[i] == NULL){
            break;
        }

        struct Arg *arg = args[i];

        free(arg);
    }

    (debug_flag) ? V_PRINT("ENDED <%s> (void)\n", __func__) : 0; 
}

int close_fds(struct Arg *arg){
    (debug_flag) ? V_PRINT("RUNNING <%s>\n", __func__) : 0; 

    int c;

    if (arg -> in != STDIN_FILENO){ // closing redirected fds
        c = close(arg -> in);

        if (c < 0){ // failed to close fd
            perror("Failed to close fd");
            goto exit_close_fds;
        }
    }

    if (arg -> out != STDOUT_FILENO){
        c = close(arg -> out);

        if (c < 0){
            perror("Failed to close fd");
            goto exit_close_fds;
        }
    }

    if (arg -> err != STDERR_FILENO){
        c = close(arg -> err);

        if (c < 0){
            perror("Failed to close fd");
        }
    }

    exit_close_fds:

    (debug_flag) ? V_PRINT("ENDED <%s> (ret=%d)\n", __func__, c) : 0; 
    return c;
}




