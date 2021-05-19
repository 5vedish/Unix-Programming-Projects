// options to store valid commands and debug values, and OS page size
int global_options, dbgval, page_siz; 
// string to store provided passfile (if any) on execution
char *passfile;
// tests if a file is one of three special file types
extern int special_file(char *filename);
// computes the hash of the password, once for encryption and twice for storage
extern unsigned char* cpt_pass();
// performs tests on files to determine if fenc can run under them
extern int valid_files(char *infile, char *outfile);
// the main function for encryption and decryption
extern int fenc_func(char *infile, char *outfile);
// debug flags set during execution
int slf, lib, sys, arg, ret;
// FOR REGRESSION TEST
int regression;