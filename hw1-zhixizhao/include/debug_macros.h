#define VERSION "Fenc v5.5\n"

#define D_MASK_SELF 0x1 // global_options and dbgval flags
#define E_MASK_LIB 0x2
#define V_MASK_SYS 0x4
#define H_MASK 0x8
#define DEBUG_MASK_ARGS 0x10
#define P_MASK_RET_ERR 0x20
#define BOTH 0x3
#define POSSIBLE 0x37

#define USAGE \
    fprintf(stderr, "USAGE: %s\n", \
    "bin/fenc -d|-e [vh] [-D DBGVAL] [-p PASSFILE]  infile outfile\n" \
    "    -d    Decrypt: decrypt infile into outfile using supplied password\n" \
    "    -e    Encrypt: encrypt infile into outfile using supplied password\n" \
    "    -v    Version: prints version of the program\n" \
    "    -h    Help: display help menu\n" \
    "    -D    Debug Flags: prints debugging information to stderr based on bitmask integer DBGVAL\n" \
    "    -p    Password: the password to supply as the first line of a file\n"); 

#define SSL_ERROR(function) do { \
    fprintf(stderr, "Error: OpenSSL function %s has failed.", function); \
} while (0);

#define V_PRINT(...) fprintf(stderr, __VA_ARGS__)

// SYSTEM CALLS

#define D_STAT(filename, stat, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'stat'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: stat(%s, %p)\n", filename, stat); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: stat returned %d.\n", retcode); \
    } \

#define D_OPEN(filename, flag, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'open'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: open(%s, %d)\n", filename, flag); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: open returned %d.\n", retcode); \
    } \

#define D_CLOSE(fd, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'close'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: close(%d)\n", fd); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: close returned %d.\n", retcode); \
    } \

#define D_READ(fd, buf, count, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'read'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: read(%d, %p, %d)\n", fd, buf, count); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: read returned %d.\n", retcode); \
    } \

#define D_WRITE(fd, buf, count, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'write'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: write(%d, %p, %d)\n", fd, buf, count); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: write returned %d.\n", retcode); \
    } \

#define D_CHMOD(fd, mode, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'fchmod'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: fchmod(%d, %u)\n", fd, mode); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: fchmod returned %d.\n", retcode); \
    } \

#define D_CHOWN(fd, user, group, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'fchown'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: fchown(%d, %u, %u)\n", fd, user, group); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: fchown returned %d.\n", retcode); \
    } \

#define D_RENAME(old, newone, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'rename'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: rename(%s, %s)\n", old, newone); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: rename returned %d.\n", retcode); \
    } \

#define D_UNLINK(filename, direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'unlink'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: unlink(%s)\n", filename); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: unlink returned %d.\n", retcode); \
    } \

#define D_PAGE_SIZ(direction, retcode) \
    if (sys) { \
        fprintf(stderr, "[Debug]: %s 'getpagesize'.\n", direction); \
    } \
    if (sys && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: getpagesize does not take arguments.\n"); \
    } \
    if (sys && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: getpagesize returned %d.\n", retcode); \
    } \

// LIB CALLS

#define D_MALLOC(size, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'malloc'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: malloc(%d)\n", size); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: malloc returned %p.\n", retcode); \
    } \

#define D_FREE(buf, direction) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'free'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: free(%p)\n", buf); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: free returned nothing.\n"); \
    } \

// OPENSSL FUNCTIONS

#define D_NAME(ciph_name, direction, retcode, fun_name) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s '%s'.\n", direction, fun_name); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: %s(%s)\n", fun_name, ciph_name); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: %s returned %p.\n", fun_name, retcode); \
    } \

#define D_CONTEXT(direction, retcode, fun_name) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s '%s'.\n", direction, fun_name); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: %s does not take arguments.\n", fun_name); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: %s returned %p.\n", fun_name, retcode); \
    } \

#define D_DIGEST_INIT(context, msg, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'EVP_DigestInit'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: EVP_DigestInit(%p, %p).\n", context, msg); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: EVP_DigestInit returned %d.\n", retcode); \
    } \

#define D_DIGEST_UPDATE(context, buf, len, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'EVP_DigestUpdate'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: EVP_DigestUpdate(%p, %p, %d).\n", context, buf, len); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: EVP_DigestUpdate returned %d.\n", retcode); \
    } \

#define D_DIGEST_FINAL(context, buf, nullmsg, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'EVP_DigestFinal'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: EVP_DigestFinal(%p, %p, %s).\n", context, buf, nullmsg); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: EVP_DigestFinal returned %d.\n", retcode); \
    } \

#define D_EVP_INIT(context, cipher, hash, iv, direction, retcode, fun_name) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s '%s'.\n", direction, fun_name); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: %s(%p, %p, %p, %p).\n", fun_name, context, cipher, hash, iv); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: %s returned %d.\n", fun_name, retcode); \
    } \

#define D_EVP_UPDATE(context, out_buf, wr, in_buf, input, direction, retcode, fun_name) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s '%s'.\n", direction, fun_name); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: %s(%p, %p, %p, %p, %d).\n", fun_name, context, \
        out_buf, wr, in_buf, input); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: %s returned %d.\n", fun_name, retcode); \
    } \

#define D_EVP_FINAL(context, out_buf, wr, direction, retcode, fun_name) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s '%s'.\n", direction, fun_name); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: %s(%p, %p, %p).\n", fun_name, context, out_buf, wr); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: %s returned %d.\n", fun_name, retcode); \
    } \

#define D_FREE_CONTEXT(context, direction, fun_name) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s '%s'.\n", fun_name, direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: %s(%p)\n", fun_name, context); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: %s returned nothing.\n", fun_name); \
    } \

#define D_MKSTEMP(tmp, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'mkstemp'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: mkstemp(%s)\n", tmp); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: mkstemp returned %d.\n", retcode); \
    } \

#define D_STRLEN(s, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'strlen'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: strlen(%p)\n", s); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: strlen returned %d.\n", retcode); \
    } \

#define D_STRNCPY(dest, src, len, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'strncpy'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: strncpy(%p, %p, %d)\n", dest, src, len); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: strncpy returned %p.\n", retcode); \
    } \

#define D_STRNCMP(s1, s2, n, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'strncmp'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: strncmp(%p, %p, %d)\n", s1, s2, n); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: strncpy returned %d.\n", retcode); \
    } \

#define D_MEMSET(buf, c, n, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'memset'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: memset(%p, %d, %d)\n", buf, c, n); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: memset returned %p.\n", retcode); \
    } \

#define D_POSIX(fd, offset, len, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'posix_fallocate'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: posix_fallocate(%d, %d, %lu)\n", fd, offset, len); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: posix_fallocate returned %d.\n", retcode); \
    } \

#define D_GETPASS(prompt, direction, retcode) \
    if (lib) { \
        fprintf(stderr, "[Debug]: %s 'getpass'.\n", direction); \
    } \
    if (lib && arg && (*direction == 'B')) { \
        fprintf(stderr, "[Debug]: getpass(%s)\n", prompt); \
    } \
    if (lib && ret && (*direction == 'A')) { \
        fprintf(stderr, "[Debug]: getpass returned %p.\n", retcode); \
    }
