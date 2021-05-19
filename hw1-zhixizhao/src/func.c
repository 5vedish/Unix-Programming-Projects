#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>

#include <options.h> // my headers
#include <debug_macros.h>

struct stat special_stat; // hold stat to validate
unsigned char *hash_append; // the password hashed twice

const char *in_function = "Before entering"; // string snippet for entering functions
const char *out_function = "After leaving"; // string snippet for leaving functions

int out_exist; // global flag to determine if outfile exists

int special_file(char *filename){
    (slf) ? V_PRINT("[Debug]: Entering '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && arg) ? V_PRINT("[Debug]: %s(%s)\n", __func__, filename) : 0;

    int retcode = 0;

    if  (S_ISDIR(special_stat.st_mode) != 0){  // cannot open directories
        fprintf(stderr, 
                "Error: Cannot open file %s because it is a directory.\n", 
                filename);
        retcode = -1;
        goto special_end;
    }

    if  (S_ISCHR(special_stat.st_mode) != 0){ // cannot handle character special devices
        fprintf(stderr, 
                "Error: Cannot open file %s because it is a character special device.\n", 
                filename);
        retcode = -1;
        goto special_end;
    }

    if  (S_ISBLK(special_stat.st_mode) != 0){ // cannot handle block special devices
        fprintf(stderr, 
                "Error: Cannot open file %s because it is a block special device.\n", 
                filename);
        retcode = -1;
        goto special_end;
    }

    special_end: // to directly exit the function

    (slf) ? V_PRINT("[Debug]: Leaving '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && ret) ? V_PRINT("[Debug]: %s returned %d.\n", __func__, retcode) : 0;
    return retcode;
}

int valid_files(char *infile, char* outfile){
    (slf) ? V_PRINT("[Debug]: Entering '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && arg) ? V_PRINT("[Debug]: %s(%s, %s)\n", __func__, infile, outfile) : 0;

    int retcode = 0;

    if (infile == NULL || outfile == NULL){ // if either file isn't specified
        fprintf(stderr, "%s", "Error: Input Files Missing!\n");
        retcode = -1;
        goto finish_valid_files;
    }

    struct stat in_stat, out_stat; // structs to hold file stats
    int in_stat_code, out_stat_code; // ints to hold returns of stat

    D_STAT(infile, &in_stat, in_function, -1);
    in_stat_code = stat(infile, &in_stat); // copying stat of infile to assigned struct
    D_STAT(infile, &in_stat, out_function, in_stat_code);

    D_STAT(outfile, &out_stat, in_function, -1);
    out_stat_code = stat(outfile, &out_stat); // copying stat of outfile to assigned struct
    D_STAT(outfile, &out_stat, out_function, out_stat_code);

    if ((*infile != '-')){ // if we're not reading from stdin

        if (in_stat_code < 0){ // if the stat failed for infile
            perror(infile);
            retcode = -1;
            goto finish_valid_files;
        }

        special_stat = in_stat; // store in global stat for argument passing

        if (special_file(infile) < 0){ // abort if infile is a special file
            retcode = -1;
            goto finish_valid_files;
        }
    }

    if ((*outfile != '-')){ // if we're not writing to stdout

        if (out_stat_code >= 0){ // outfile exists
            goto check_outfile;
        } else{ // outfile does not exist; cannot validate
            goto finish_valid_files;
        }
    } else {
        goto finish_valid_files; // writing to stdout; cannot validate
    }

    check_outfile: // validate outfile if it exists

    special_stat = out_stat; // store in global stat for argument passing

    if (special_file(outfile) < 0){ // abort if outfile is a special file
        retcode = -1;
        goto finish_valid_files;
    }   

    // verify infile and outfile are not the same file
    if ((in_stat.st_dev == out_stat.st_dev) && (in_stat.st_ino == out_stat.st_ino)){
        fprintf(stderr, "%s", "Error: infile and outfile are the same file!\n");
        retcode = -1;
    }

    finish_valid_files: // to directly exit the function

    (slf) ? V_PRINT("[Debug]: Leaving '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && ret) ? V_PRINT("[Debug]: %s returned %d.\n", __func__, retcode) : 0;
    return retcode;
}

unsigned char* cpt_pass(){
    (slf) ? V_PRINT("[Debug]: Entering '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && arg) ? V_PRINT("[Debug]: %s %s\n", __func__, "does not take arguments.") : 0;

    unsigned char *ret_val;

    int input, pass_fd, close_code; // storage ints for read, open, and close
    char *password, *password_buf; // static storage for getpass and buffer for actual password
    unsigned char *hash; // hash buffer

    const EVP_MD *msg; // the hashing function from OpenSSL

    D_NAME("sha256", in_function, NULL, "EVP_get_digestbyname");
    msg = EVP_get_digestbyname("sha256");
    D_NAME("sha256", out_function, msg, "EVP_get_digestbyname");

    EVP_MD_CTX *context; // the context object to hash under from OpenSSL

    D_CONTEXT(in_function, NULL, "EVP_MD_CTX_new");
    context = EVP_MD_CTX_new();
    D_CONTEXT(out_function, context, "EVP_MD_CTX_new");

    if (context == NULL){ // failed to allocate space for context
        SSL_ERROR("EVP_MD_CTX_new");
        ret_val = NULL;
        goto no_pass_cleanup;
    }

    D_MALLOC(page_siz, in_function, NULL);
    password_buf = malloc(page_siz); // buffer to store password
    D_MALLOC(page_siz, out_function, password_buf);

    D_MALLOC(page_siz, in_function, NULL);
    hash = malloc(32); // buffer to store hash
    D_MALLOC(page_siz, out_function, hash);

    if (password_buf == NULL){ // failed to allocate space for password
        perror("password_buf");
        ret_val = NULL;
        goto no_pass_cleanup;
    }

    if (hash == NULL){ // failed to allocate space for hash
        perror("hash");
        ret_val = NULL;
        goto pass_buf_cleanup;
    }

    int openssl_code; // storage for OpenSSL lib returns

    D_DIGEST_INIT(context, msg, in_function, -1);
    openssl_code = EVP_DigestInit(context, msg); // initialize the context to prepare for hashing
    D_DIGEST_INIT(context, msg, out_function, openssl_code);
    
    if (openssl_code != 1){ // if context initialization failed
        SSL_ERROR("EVP_DigestInit");
        ret_val = NULL;
        goto hash_buf_cleanup;
    }

    if ((global_options & P_MASK_RET_ERR) != P_MASK_RET_ERR){ // passfile is not provided

        D_GETPASS("Please enter a password", in_function, NULL);
        password = getpass("Please enter a password: "); // retrieve password from stdin
        D_GETPASS("Please enter a password", out_function, password);

        int len; // storage for length of password

        D_STRLEN(password, in_function, -1);
        len = strlen(password); // hash precisely only length of password
        D_STRLEN(password, out_function, len);

        D_STRNCPY(password_buf, password, len, in_function, NULL);
        password_buf = strncpy(password_buf, password, len); // copy precisely password to buffer
        D_STRNCPY(password_buf, password, len, out_function, password_buf);

        D_DIGEST_UPDATE(context, password_buf, len, in_function, -1);
        openssl_code = EVP_DigestUpdate(context, password_buf, len); // perform hash precisely
        // on password buffer
        D_DIGEST_UPDATE(context, password_buf, len, out_function, openssl_code);

        if (openssl_code != 1){ // failed to perform hash on password buffer
            SSL_ERROR("EVP_DigestUpdate");
            ret_val = NULL;
            goto hash_buf_cleanup;
        }

        D_DIGEST_FINAL(context, hash, "NULL", in_function, -1);
        openssl_code = EVP_DigestFinal(context, hash, NULL); // finalize the hash and store it
        // in hash buffer
        D_DIGEST_FINAL(context, hash, "NULL", out_function, openssl_code);

        if (openssl_code != 1){ // failed to finalize and store hash in hash buffer
            SSL_ERROR("EVP_DigestFinal");
            ret_val = NULL;
            goto hash_buf_cleanup;
        }

        ret_val = hash; // assign to return hash
        goto pass_buf_cleanup; // only memory to clean up is password buffer

    } else { // passfile is provided

        D_OPEN(passfile, O_RDONLY, in_function, -1);
        pass_fd = open(passfile, O_RDONLY); // open up provided password file to read from
        D_OPEN(passfile, O_RDONLY, out_function, pass_fd);

        if (pass_fd < 0){ // failed to open passfile
            perror(passfile);
            ret_val = NULL;
            goto hash_buf_cleanup;
        }

        D_READ(pass_fd, password_buf, page_siz, in_function, -1);
        input = read(pass_fd, password_buf, page_siz); // read from passfile to password buffer
        D_READ(pass_fd, password_buf, page_siz, out_function, input);

        if (input < 0){ // failed to read from passfile
            perror(passfile);
            ret_val = NULL;
            goto pass_fd_cleanup;
        }

        int counter, new_line; // counter so we don't have to increment pointer directly
        // boolean int to indicate if newline is encountered
        counter = 0;
        new_line = -1;
        while(*(password_buf+counter)){ // search for a newline to indicate end of password
            if (*(password_buf+counter) == '\n'){
                new_line = 0;
                break;
            }
            counter++;
        }

        if (new_line == -1){ // if EOF reached hash entire file

            D_DIGEST_UPDATE(context, password_buf, input, in_function, -1);
            openssl_code = EVP_DigestUpdate(context, password_buf, input);
            D_DIGEST_UPDATE(context, password_buf, input, out_function, openssl_code);

        } else { // if newline encountered hash until newline (counter)

            D_DIGEST_UPDATE(context, password_buf, counter, in_function, -1);
            openssl_code = EVP_DigestUpdate(context, password_buf, counter);
            D_DIGEST_UPDATE(context, password_buf, counter, out_function, openssl_code);

        }

        if (openssl_code != 1){ // failed to perform hash on password buffer
            SSL_ERROR("EVP_DigestUpdate");
            ret_val = NULL;
            goto pass_fd_cleanup;
        }
        
        D_DIGEST_FINAL(context, hash, "NULL", in_function, -1);
        openssl_code = EVP_DigestFinal(context, hash, NULL); // finalize hash and store in
        // hash buffer
        D_DIGEST_FINAL(context, hash, "NULL", out_function, openssl_code);

        if (openssl_code != 1){ // failed to finalize and store hash in hash buffer
            SSL_ERROR("EVP_DigestFinal");
            ret_val = NULL;
            goto pass_fd_cleanup;
        }

        D_CLOSE(pass_fd, in_function, -1);
        close_code = close(pass_fd); // close the file descriptor for passfile; finished reading
        D_CLOSE(pass_fd, out_function, close_code);

        if (close_code < 0){ // failed to close file descriptor for passfile
            perror("pass_fd");
            ret_val = NULL;
        }   
        ret_val = hash; // assign to return hash
        goto pass_buf_cleanup;
    }
    pass_fd_cleanup: // if passfile file descriptor hasn't already been closed, clean it up
    D_CLOSE(pass_fd, in_function, -1);
    close_code = close(pass_fd); // close the file descriptor for passfile; finished reading
    D_CLOSE(pass_fd, out_function, close_code);

    if (close_code < 0){ // failed to close file descriptor for passfile
        perror("pass_fd");
        ret_val = NULL;
    }

    hash_buf_cleanup: // clean up hash if an error is encountered

    D_FREE(hash, in_function);
    free(hash);
    D_FREE(hash, out_function);

    pass_buf_cleanup: // only password buffer clean up is required

    D_MALLOC(32, in_function, NULL);
    hash_append = malloc(32); // buffer to store double hash
    D_MALLOC(32, out_function, hash_append);

    if (hash_append == NULL){ // failed to allocate space for double hash
        perror("hash_append");
        ret_val = NULL;
    }

    D_DIGEST_INIT(context, msg, in_function, -1);
    openssl_code = EVP_DigestInit(context, msg); // reset the context to hash the hash; reinitialize
    D_DIGEST_INIT(context, msg, out_function, openssl_code);

    D_DIGEST_UPDATE(context, hash, 32, in_function, -1);
    openssl_code = EVP_DigestUpdate(context, hash, 32); // perform hash on first hash; 32 bytes
    D_DIGEST_UPDATE(context, hash, 32, out_function, openssl_code);

    D_DIGEST_FINAL(context, hash_append, "NULL", in_function, -1);
    openssl_code = EVP_DigestFinal(context, hash_append, NULL); // finalize double hash buffer
    D_DIGEST_FINAL(context, hash_append, "NULL", out_function, openssl_code);

    D_FREE(password_buf, in_function);
    free(password_buf); // clean up password buffer
    D_FREE(password_buf, out_function);
    
    D_FREE_CONTEXT(context, in_function, "EVP_MD_CTX_free");
    EVP_MD_CTX_free(context); // clean up context using in-built OpenSSL free
    D_FREE_CONTEXT(context, out_function, "EVP_MD_CTX_free");

    no_pass_cleanup: // no more memory clean up required

    (slf) ? V_PRINT("[Debug]: Leaving '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && ret) ? V_PRINT("[Debug]: %s returned pointer %p.\n", __func__, ret_val) : 0;
    return ret_val;
}

int fenc_func(char *infile, char *outfile){
    (slf) ? V_PRINT("[Debug]: Entering '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && arg) ? V_PRINT("[Debug]: %s(%s, %s)\n", __func__, infile, outfile) : 0;

    int retcode, statcode; // storage for return and stat call returns
    retcode = 0;

    int in_fd, out_fd, temp_fd; // storage for file descriptors from infile/outfile/tempfile
    int input, output; // storage for returns from read/write
    unsigned char *in_buf, *out_buf, *hash; // buffers for reading/writing and to store the 
    // hash after computing it

    char tmp[11] = ".tmpXXXXXX\0"; // buffer to hold temporary file name

    int chmod_code, chown_code; // storage for calls to permissions handling
    struct stat copy_stat; // struct to store valuable permissions 

    if (*infile != '-'){ // not reading from stdin

        D_OPEN(infile, O_RDONLY, in_function, -1);
        in_fd = open(infile, O_RDONLY); // open up infile to read from
        D_OPEN(infile, O_RDONLY, out_function, in_fd);

        if (in_fd < 0){ // failed to open infile
            perror(infile);
            retcode = -1;
            goto no_fenc_cleanup;
        }

        int offset; // encrypt means storing file size +32 whereas decrypt stores file size -32
        offset = ((global_options & E_MASK_LIB) == E_MASK_LIB) ? 32 : -32;

        D_STAT(infile, &copy_stat, in_function, -1);
        statcode = stat(infile, &copy_stat); // copying stat of infile to assigned struct
        D_STAT(infile, &copy_stat, out_function, statcode);

        if (statcode < 0){ // if the stat failed for infile
            perror(infile);
            retcode = -1;
            goto fenc_infd_cleanup;
        }

        int falloc_code; // simulate allocating a file of desired size

        D_POSIX(in_fd, 0, copy_stat.st_size + offset, in_function, -1);
        falloc_code = posix_fallocate(in_fd, 0, copy_stat.st_size + offset);
        D_POSIX(in_fd, 0, copy_stat.st_size + offset, out_function, falloc_code);

        if (falloc_code < 0){ // file system does not have space to store outfile
            fprintf(stderr, "%s", "Error: There was not enough space to allocate outfile.\n");
            retcode = -1;
            goto fenc_infd_cleanup;
        }

    } else { // read from stdin
        in_fd = STDIN_FILENO;
    }

    if (*outfile != '-'){ // not writing to stdout

        D_OPEN(outfile, O_WRONLY | O_CREAT | O_EXCL, in_function, -1);
        out_fd = open(outfile, O_WRONLY | O_CREAT | O_EXCL);  // open outfile to write to
        // flags; errno set if outfile already exists and creates a file if it doesn't
        D_OPEN(outfile, O_WRONLY | O_CREAT | O_EXCL, out_function, out_fd);

        if ((out_fd < 0) && (errno != EEXIST)){ // failed to open outfile
            perror(outfile);
            retcode = -1;
            goto fenc_infd_cleanup;
        }

        if (errno == EEXIST){ // outfile already exists
            D_OPEN(outfile, O_WRONLY, in_function, -1);           
            out_fd = open(outfile, O_WRONLY); // open a second time; first open scripted to fail
            D_OPEN(outfile, O_WRONLY, out_function, out_fd);

            out_exist = 0;
            
            D_STAT(outfile, &copy_stat, in_function, -1);
            statcode = stat(outfile, &copy_stat); // copying stat of outfile to assigned struct
            D_STAT(outfile, &copy_stat, out_function, statcode);

        } else { // outfile does not exist, inherit infile permissions

            out_exist = -1;

            D_STAT(infile, &copy_stat, in_function, -1);
            statcode = stat(infile, &copy_stat); // copying stat of infile to assigned struct
            D_STAT(infile, &copy_stat, out_function, statcode);

        }

        if ((statcode < 0) && (*infile != '-')){ // stat failed for infile
            perror("Permissions Error");
            retcode = -1;
            goto fenc_outfd_cleanup;
        }

        D_MKSTEMP(tmp, in_function, -1); // designed to make tempfile regardless of conditions
        temp_fd = mkstemp(tmp); // creation of tempfile to write to
        D_MKSTEMP(tmp, out_function, temp_fd);


        if (*infile != '-'){ // inherit permissions from infile

            D_CHMOD(temp_fd, copy_stat.st_mode, in_function, -1);
            chmod_code = fchmod(temp_fd, copy_stat.st_mode); // copying permissions to tempfile
            D_CHMOD(temp_fd, copy_stat.st_mode, out_function, chmod_code);

            D_CHOWN(temp_fd, copy_stat.st_uid, copy_stat.st_gid, in_function, -1);
            chown_code = fchown(temp_fd, copy_stat.st_uid, copy_stat.st_gid); // copying ownership
            D_CHOWN(temp_fd, copy_stat.st_uid, copy_stat.st_gid, out_function, chown_code);

        } else { // set default permissions to read/write for user
            unsigned int def_mode;
            def_mode = 0600;

            D_CHMOD(temp_fd, copy_stat.st_mode, in_function, -1);
            chmod_code = fchmod(temp_fd, def_mode); // copying default permissions to outfile
            D_CHMOD(temp_fd, copy_stat.st_mode, out_function, chmod_code);

            chown_code = 1; // manually setting return code because uninitialized
        }

        if (chmod_code < 0){ // failed to copy permissions to outfile
            perror(tmp);
            retcode = -1;
            goto fenc_tempfd_cleanup;
        }

        if (chown_code < 0){ // failed to copy ownership to outfile
            perror(tmp);
            retcode = -1;
            goto fenc_tempfd_cleanup;
        }

        if (temp_fd < 0){ // failed to create a tempfile
            perror(tmp);
            retcode = -1;
            goto fenc_tempfd_cleanup;
        }
        out_fd = temp_fd; // everything written to tempfile first
    } else {
        out_fd = STDOUT_FILENO; // write to stdout
    }

    D_MALLOC(page_siz, in_function, NULL); 
    in_buf = malloc(page_siz); // buffer to store bytes from read
    D_MALLOC(page_siz, out_function, in_buf);

    D_MALLOC(page_siz, in_function, NULL);
    out_buf = malloc(page_siz); // buffer to store bytes to write from encryption
    D_MALLOC(page_siz, out_function, out_buf);

    if (in_buf == NULL){ // failed to allocate space for input buffer
        perror("in_buf");
        retcode = -1;
        goto fenc_tempfd_cleanup;
    }

    if (out_buf == NULL){ // failed to allocate space for output buffer
        perror("out_buf");
        retcode = -1;
        goto fenc_inbuf_cleanup;
    }

    if ((hash = cpt_pass()) == NULL){ // failed to compute hash
        retcode = -1;
        goto fenc_outbuf_cleanup;
    }

    if ((global_options & E_MASK_LIB) == E_MASK_LIB){ // encrypt; write hash to beginning

        D_WRITE(out_fd, hash_append, 32, in_function, -1);
        output = write(out_fd, hash_append, 32); // append double hash to beginning of output
        D_WRITE(out_fd, hash_append, 32, out_function, output);
        
        if (output < 0){ // failed to write the double hash to output
        perror(outfile);
        retcode = -1;
        goto fenc_hash_cleanup;
        }
    } else { // decrypt; read hash from beginning

        D_READ(in_fd, in_buf, 32, in_function, -1);
        input = read(in_fd, in_buf, 32); // read hash from provided infile
        D_READ(in_fd, in_buf, 32, out_function, input);
    
        if (input < 0){ // failed to read from provided infile
            perror(infile);
            retcode = -1;
            goto fenc_hash_cleanup;
        }

        int compare; // verifying the double hashes match
        D_STRNCMP(in_buf, hash_append, 32, in_function, -1);
        if ((compare = strncmp((const char *)in_buf, (const char*)hash_append, 32)) != 0){
            D_STRNCMP(in_buf, hash_append, 32, out_function, compare);
            fprintf(stderr, "%s", "Error: The Password Hashes Do Not Match!\n");
            retcode = -1;
            goto fenc_hash_cleanup;
        }

        D_MEMSET(in_buf, 0 , 32, in_function, NULL);
        in_buf = memset(in_buf, 0, 32); // resetting the space in memory in case something small
        // is written
        D_MEMSET(in_buf, 0 , 32, out_function, in_buf);
    }

    EVP_CIPHER_CTX *context; // initializing context object for ciphers

    D_CONTEXT(in_function, NULL, "EVP_CIPHER_CTX_new");
    context = EVP_CIPHER_CTX_new(); // allocating space for cipher context
    D_CONTEXT(out_function, context, "EVP_CIPHER_CTX_new");

    if (context == NULL){ // failed to allocate space for cipher context
        retcode = -1;
        goto fenc_hash_cleanup;
    }

    const EVP_CIPHER *cipher; // object to store the type of cipher
    unsigned char *iv; // initialization vector
    int wrt_by_ciph; // storage for number of bytes encrypted

    D_MALLOC(EVP_MAX_IV_LENGTH, in_function, NULL);
    iv = malloc(EVP_MAX_IV_LENGTH); // buffer for initialization vector
    D_MALLOC(EVP_MAX_IV_LENGTH, out_function, iv);

    if (iv == NULL){ // failed to allocate space for initialization vector
        perror("iv");
        retcode = -1;
        goto fenc_contxt_cleanup;
    }

    D_MEMSET(iv, 0 , EVP_MAX_IV_LENGTH, in_function, NULL);
    iv = memset(iv, 0, EVP_MAX_IV_LENGTH); // 0 as the default iv
    D_MEMSET(iv, 0 , EVP_MAX_IV_LENGTH, out_function, iv);

    D_NAME("aes-256-ctr", in_function, NULL, "EVP_get_cipherbyname");
    cipher = EVP_get_cipherbyname("aes-256-ctr"); // retrieving the actual cipher object
    D_NAME("aes-256-ctr", "After entering", cipher, "EVP_get_cipherbyname");

    if (cipher == NULL){ // failed to retrieve cipher object
        fprintf(stderr, "%s", "Could not retrieve Cipher from OpenSSL.\n");
        retcode = -1;
        goto fenc_iv_cleanup;
    }

    int openssl_code; // storage for return codes to OpenSSL lib calls

    // cryptography begins; always write what we can read; no more no less
    // perform operations on max of page size blocks
    D_READ(in_fd, in_buf, page_siz, in_function, -1); // print debug once before reading

    while ((input = read(in_fd, in_buf, page_siz)) != 0){ // while bytes can be read from input
    D_READ(in_fd, in_buf, page_siz, out_function, input);

    // FOR REGRESSION TEST

        if (regression < 0){
            input = -1;
            errno = EIO;
        }

    // FOR REGRESSION TEST

        if (input < 0){ // if reading from input fails
            perror(infile);
            retcode = -1;
            goto fenc_iv_cleanup;
        }

        if ((global_options & E_MASK_LIB) == E_MASK_LIB){ // encryption

            D_EVP_INIT(context, cipher, hash, iv, in_function, -1, "EVP_EncryptInit");
            openssl_code = EVP_EncryptInit(context, cipher, hash, iv); // initialize cipher context
            D_EVP_INIT(context, cipher, hash, iv, out_function, openssl_code, \
            "EVP_EncryptInit");

            if (openssl_code != 1){ // failed to initialize cipher context
                SSL_ERROR("EVP_EncryptInit");
                retcode = -1;
                goto fenc_iv_cleanup;
            }

            D_EVP_UPDATE(context, out_buf, &wrt_by_ciph, in_buf, input, in_function,
            -1, "EVP_EncryptUpdate");
            openssl_code = EVP_EncryptUpdate(context, out_buf, &wrt_by_ciph, in_buf, input);
            // encrypting input # of bytes from in buffer and storing them in out buffer
            D_EVP_UPDATE(context, out_buf, &wrt_by_ciph, in_buf, input, out_function,
            openssl_code, "EVP_EncryptUpdate");

            if (openssl_code != 1){ // failed to encrypt between buffers
                SSL_ERROR("EVP_EncryptUpdate");
                retcode = -1;
                goto fenc_iv_cleanup;
            }

            D_EVP_FINAL(context, out_buf, &wrt_by_ciph, in_function, -1, "EVP_EncryptFinal");
            openssl_code = EVP_EncryptFinal(context, out_buf, &wrt_by_ciph);
            // finalize the encryption and store it in out buffer
            D_EVP_FINAL(context, out_buf, &wrt_by_ciph, out_function,
            openssl_code, "EVP_EncryptFinal");

            if (openssl_code != 1){ // failed to finalize and store encrypted bytes
                SSL_ERROR("EVP_EncryptFinal");
                retcode = -1;
                goto fenc_iv_cleanup;
            }

        } else {

            D_EVP_INIT(context, cipher, hash, iv, in_function, -1, "EVP_DecryptInit");
            openssl_code = EVP_DecryptInit(context, cipher, hash, iv); // initialize cipher context
            D_EVP_INIT(context, cipher, hash, iv, out_function, openssl_code, \
            "EVP_DecryptInit");

            if (openssl_code != 1){ // failed to initialize cipher context
                SSL_ERROR("EVP_DecryptInit");
                retcode = -1;
                goto fenc_iv_cleanup;
            }

            D_EVP_UPDATE(context, out_buf, &wrt_by_ciph, in_buf, input, in_function,
            -1, "EVP_DecryptUpdate");
            openssl_code = EVP_DecryptUpdate(context, out_buf, &wrt_by_ciph, in_buf, input);
            // decrypting input # of bytes from in buffer and storing them in out buffer
            D_EVP_UPDATE(context, out_buf, &wrt_by_ciph, in_buf, input, out_function,
            openssl_code, "EVP_DecryptUpdate");

            if (openssl_code != 1){ // failed to decrypt between buffers
                SSL_ERROR("EVP_DecryptUpdate");
                retcode = -1;
                goto fenc_iv_cleanup;
            }

            D_EVP_FINAL(context, out_buf, &wrt_by_ciph, in_function, -1, "EVP_DecryptFinal");
            openssl_code = EVP_DecryptFinal(context, out_buf, &wrt_by_ciph);
            // finalize the decryption and store it in out buffer
            D_EVP_FINAL(context, out_buf, &wrt_by_ciph, out_function,
            openssl_code, "EVP_DecryptFinal");

            if (openssl_code != 1){ // failed to finalize and store decrypted bytes
                SSL_ERROR("EVP_DecryptFinal");
                retcode = -1;
                goto fenc_iv_cleanup;
            }
        }

        D_WRITE(out_fd, hash, 32, in_function, -1); // debug print once before writing

        while ( input  - (output = write(out_fd, out_buf, input)) != 0){ // accounting for partial
            D_WRITE(out_fd, hash, 32, out_function, output);             // writes

            if (output < 0){ // failed to write input bytes to output
                perror(tmp);
                retcode = -1;
                goto fenc_iv_cleanup;
            }

            input -= output;
            D_WRITE(out_fd, hash, 32, in_function, -1);
        }
        D_WRITE(out_fd, hash, 32, out_function, output); // debug print once after writing
        D_READ(in_fd, in_buf, page_siz, in_function, -1);
    }
    D_READ(in_fd, in_buf, page_siz, out_function, input); // debug print once after reading

    int close_code, unlink_code; // storage for close and unlink return values
    unlink_code = 1; // signify that tmp has not been unlinked
    
    fenc_iv_cleanup: // clean up initialization vector

    D_FREE(iv, in_function);
    free(iv);
    D_FREE(iv, out_function);

    fenc_contxt_cleanup: // clean up cipher context object

    D_FREE_CONTEXT(context, in_function, "EVP_CIPHER_CTX_free");
    EVP_CIPHER_CTX_free(context);
    D_FREE_CONTEXT(context, out_function, "EVP_CIPHER_CTX_free");

    fenc_hash_cleanup: // clean up hash and double hash

    D_FREE(hash_append, in_function);
    free(hash_append);
    D_FREE(hash_append, out_function);

    D_FREE(hash, in_function);
    free(hash);
    D_FREE(hash, out_function);

    if (retcode == -1){ // error occurred along the way; dispose of tempfile

        D_UNLINK(tmp, in_function, -1);
        unlink_code = unlink(tmp);
        D_UNLINK(tmp, out_function, unlink_code);

        if (unlink_code < 0){ // error deleting tempfile
            perror(tmp);
        }
    }

    fenc_outbuf_cleanup: // clean up output buffer

    D_FREE(out_buf, in_function);
    free(out_buf);
    D_FREE(out_buf, out_function);

    fenc_inbuf_cleanup: // clean up input buffer

    D_FREE(in_buf, in_function);
    free(in_buf);
    D_FREE(in_buf, out_function);

    fenc_tempfd_cleanup: // clean up tempfile file descriptor

    if (*outfile != '-'){ // not writing to stdout, close tempfile file descriptor

        D_CLOSE(temp_fd, in_function, -1);
        close_code = close(temp_fd);
        D_CLOSE(temp_fd, out_function, close_code);

        if (close_code < 0){ // failed to close tempfile file descriptor
            perror("temp_fd");
            retcode = -1;
        }

    }

    fenc_outfd_cleanup: // clean up outfile file descriptor

    if (*outfile != '-' && out_fd != temp_fd){ // not writing to stdout and tempfile was never made

        D_CLOSE(out_fd, in_function, -1);
        close_code = close(out_fd);
        D_CLOSE(out_fd, out_function, close_code);

        if (close_code < 0){ // fails and not closed as temp_fd
        perror("out_fd");
        retcode = -1;
        }

    }

    if ((retcode < 0) && (out_fd == temp_fd) && (out_exist != 0)){ // error occurred and tempfile was made
        D_UNLINK(outfile, in_function, -1);
        unlink_code = unlink(outfile); // delete outfile alongside tempfile
        D_UNLINK(outfile, out_function, unlink_code);

        if (unlink_code < 0){ // deletion of outfile failed
            perror(outfile);
            retcode = -1;
        }
    }

    fenc_infd_cleanup: // clean up infile file descriptor

    D_CLOSE(in_fd, in_function, -1);
    close_code = close(in_fd);
    D_CLOSE(in_fd, out_function, close_code);

    if (close_code < 0){ // failed to close infile file descriptor
        perror("in_fd");
        retcode = -1;
    }

    no_fenc_cleanup: // no more memory clean up

    if (retcode == 0){ // program success, proceed to overwrite outfile with tempfile

        int rename_code;
        if (*outfile != '-'){ // not writing to stdout

            D_RENAME(tmp, outfile, in_function, -1);
            rename_code = rename(tmp, outfile); // replace file
            D_RENAME(tmp, outfile, out_function, rename_code);

            if (rename_code < 0){ // failed to replace outfile with tempfile
                perror(tmp);
                retcode = -1;
            }
        }
    } else if (unlink_code == 1) { // if deletion hadn't occurred, perhaps on some later failure

        D_UNLINK(tmp, in_function, -1);
        unlink_code = unlink(tmp); // tidy up any possible tempfile
        D_UNLINK(tmp, out_function, unlink_code);

        if (unlink_code < 0){ // tempfile deletion failed
            perror(tmp);
            retcode = -1;
        }
    }

    (slf) ? V_PRINT("[Debug]: Leaving '%s' in %s line %d.\n", __func__, __FILE__, __LINE__) : 0;
    (slf && ret) ? V_PRINT("[Debug]: %s returned %d.\n", __func__, retcode) : 0;
    return retcode;
}
