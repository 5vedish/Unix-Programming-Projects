#define ALLOCATED 0 // flags for allocation status
#define FREE 1

#define LKM_REG 0x0 // flags for lkmalloc
#define LKM_INIT 0x1
#define LKM_OVER 0x2
#define LKM_UNDER 0x4
#define LKM_EXIST 0x8
#define LKM_REALLOC 0x10

#define LKF_REG 0x0 // flags for lkfree
#define LKF_APPROX 0x1
#define LKF_WARN 0x2
#define LKF_UNKNOWN 0x4
#define LKF_ERROR 0x8

#define LKR_NONE 0x0 // flags for lkreport
#define LKR_SERIOUS 0x1
#define LKR_MATCH 0x2
#define LKR_BAD_FREE 0x4
#define LKR_ORPHAN_FREE 0x8
#define LKR_DOUBLE_FREE 0x10
#define LKR_APPROX 0x20

struct MemBlock{ // struct for info stored on successful allocation
    int status;
    u_int size;
    void *header_bytes; // underflow buffer
    void *data_addr;
    void *footer_bytes; // overflow buffer
    char *filename;
    char *func;
    int line_no;
    u_int64_t time;
    int ret_val; // return value always 0 on success
    void *ptr; // passed in pointer
};

struct MemRecord{ // struct for records of special events
    int type;     // stores both malloc and free information for conditional printing
    void *m_ptr;  // original address returned from malloc
    void *f_ptr;
    char *m_filename;
    char *f_filename;
    char *m_func;
    char *f_func;
    int m_line;
    int f_line;
    u_int64_t m_time;
    u_int64_t f_time;
    int m_ret_val;
    int f_ret_val; // returns 0 on success and negative flags on error for respective flags
    u_int size;
    u_int flags;
    void *addr; // original address passed to malloc
    int success; // 0 if it went through and -1 otherwise (for middle frees)
};

struct CleanUp{ // struct for preserving required arguments to clean up on exit
    int fd;
    u_int flags;
};

extern int _lkmalloc(u_int size, void **ptr, u_int flags, char *filename, const char *func, 
int line_no);

extern int _lkfree(void **ptr, u_int flags, char *filename, const char *func, int line_no);

extern int lkreport(int fd, u_int flags);

extern int init_heap(); // initialize data structures from glib

extern u_int64_t get_tim(); // function to retrieve current time

extern int blk_srch(void *target); // function to search for a particular block of memory

extern void prt_blks(); // debug function to display blocks of memory

extern void prt_m_rec(int fd, struct MemRecord *record); // print only malloc record

extern void prt_f_rec(int fd, struct MemRecord *record); // print only free record

extern void prt_solo_m(int fd, struct MemBlock *block); // print malloc blocks for mem leaks

extern void exit_func(int exit_status, void *args); // clean up function for on_exit

#define lkmalloc(size, ptr, flags) \
        _lkmalloc(size, (void *) ptr, flags, __FILE__, __func__, __LINE__)

#define lkfree(ptr, flags) \
        _lkfree((void *) ptr, flags, __FILE__, __func__, __LINE__)
