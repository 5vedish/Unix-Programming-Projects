#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <options.h>
#include <debug_macros.h>

int main(int argc, char *argv[]){

    int option, opt_num;
    int temp;

    regression = 0; // FOR REGRESSION TEST

    while ((option = getopt(argc, argv, "rdevhD:p:")) != -1){

        switch(option) {

            case 'r': // FOR REGRESSION TEST
                regression = -1;
                break;

            case 'd':
                global_options = global_options | D_MASK_SELF; // decrypt
                break;

            case 'e':
                global_options = global_options | E_MASK_LIB; // encrypt
                break;

            case 'v':
                global_options = global_options | V_MASK_SYS; // version
                break;

            case 'h':
                global_options = global_options | H_MASK; // help
                break;

            case 'D': // set debug values

                if (optarg != NULL){ // if nothing was passed as dbgval
                    temp = *optarg - '0';

                    if (temp == 0 && *(optarg + 1) == '\0'){ // validate to make sure dbgval is an
                        dbgval = 0;                          // integer
                    } else {
                        dbgval = atoi(optarg);

                        if (dbgval == 0){
                            USAGE;
                            exit(EXIT_FAILURE);
                        }
                    }
                } else {
                    USAGE;
                    exit(EXIT_FAILURE);
                }

                global_options = global_options | DEBUG_MASK_ARGS;
                break;

            case 'p': // passfile

                if (optarg != NULL){
                    passfile = optarg;
                } else{
                    USAGE;
                    exit(EXIT_FAILURE);
                }

                global_options = global_options | P_MASK_RET_ERR;
                break;

            default:
                USAGE;
                exit(EXIT_FAILURE);
                
        }
    }
    int exitcode = 0;

    slf = ((dbgval & D_MASK_SELF) == D_MASK_SELF) ? 1 : 0; // setting global debug flags
    lib = ((dbgval & E_MASK_LIB) == E_MASK_LIB) ? 1 : 0;
    sys = ((dbgval & V_MASK_SYS) == V_MASK_SYS) ? 1 : 0;
    arg = ((dbgval & DEBUG_MASK_ARGS) == DEBUG_MASK_ARGS) ? 1 : 0;
    ret = ((dbgval & P_MASK_RET_ERR) == P_MASK_RET_ERR) ? 1 : 0;

    char *infile =  argv[optind]; // names of files
    char *outfile = argv[optind+1];

    if (argv[optind+2] != NULL){ // too many or too few command line arguments
        opt_num = -1;
    } else {
        opt_num = optind;
    }

    if (opt_num < 2){
        USAGE;
        exitcode = EXIT_FAILURE;
        goto exit_main;
    }

    if ((global_options & BOTH) == 0 || (global_options & BOTH) == 0x3){ // both encryption and
        USAGE;                                                           // decryption specified
        exitcode = EXIT_FAILURE;
        goto exit_main;
    }

    if (arg && ret && !(slf || sys || lib)){ // no arg/ret debugging possible
        USAGE;
        exitcode = EXIT_FAILURE;
        goto exit_main;
    }

    if ((dbgval & ~POSSIBLE) != 0){ // anything outside of valid dbgvals
        USAGE;
        exitcode = EXIT_FAILURE;
        goto exit_main;
    }
    
    //end of argument validation
    (slf) ? V_PRINT("[Debug]: Entering '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && arg) ? V_PRINT("[Debug]: %s %s\n", __func__, "does not take arguments.") : 0;

    if ((global_options & V_MASK_SYS) == V_MASK_SYS){ // version
        printf(VERSION);
    }

    if ((global_options & H_MASK) == H_MASK){ // help
        USAGE;
    }

    D_PAGE_SIZ("Before entering", -1);
    page_siz = getpagesize(); // retrieving native OS page size
    D_PAGE_SIZ("After leaving", page_siz);

    if (valid_files(infile, outfile) < 0){ // validating files before processing
        exitcode = EXIT_FAILURE;
        goto exit_main;
    }

    if (fenc_func(infile, outfile) < 0){ // execute program
        exitcode = EXIT_FAILURE;
        goto exit_main;
    }

    exit_main:

    (slf) ? V_PRINT("[Debug]: Leaving '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && ret) ? V_PRINT("[Debug]: %s exited with %d.\n", __func__, exitcode) : 0;
    exit(exitcode);
}