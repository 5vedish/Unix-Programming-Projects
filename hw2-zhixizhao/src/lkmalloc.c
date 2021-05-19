#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <gmodule.h>
#include <time.h>

// My Includes
#include <headers.h>

static GArray *blocks; // list to store blocks of memory
static GArray *records; // list to store records of special events

int blk_srch(void *target){ // search for particular block of memory

    int index = -1;

    for (int i = (blocks -> len) - 1; i >= 0; i--){ // iterates backwards to find most recent
                                                    // version of block
        struct MemBlock temp_blk = g_array_index(blocks, struct MemBlock, i);

        if (target <= temp_blk.data_addr + temp_blk.size && // match address to block (range)
            target >= temp_blk.data_addr){
            index = i;
            break;
        }

    }

    return index;

}

void prt_blks(){ // debug function to display blocks

    for (unsigned int i = 0; i < (blocks -> len); i++){

        struct MemBlock temp_blk = g_array_index(blocks, struct MemBlock, i);

        printf("\n##### Block %d", i);

        printf("\n%d\n%u\n%p\n%p\n%p\n%s\n%s\n%d\n%lu\n", temp_blk.status, temp_blk.size, 
        temp_blk.header_bytes, temp_blk.data_addr, temp_blk.footer_bytes,
        temp_blk.filename, temp_blk.func, temp_blk.line_no, temp_blk.time);

        printf("#####\n");

    }
    
}

u_int64_t get_tim(){ // uses timespec struct to retrieve current time
    struct timespec time;
    timespec_get(&time, TIME_UTC);

    return ((time.tv_sec * 1000000000) + time.tv_nsec)/1000; // convert to microseconds
}

int init_heap(){ // initialize data structures

    blocks = g_array_new(FALSE, FALSE, sizeof(struct MemBlock));
    records = g_array_new(FALSE, FALSE, sizeof(struct MemRecord));

    return 0;
}

int _lkmalloc(u_int size, void **ptr, u_int flags, char *filename, const char *func, int line_no){

    if (blocks == NULL && records == NULL){ // initialize data structures if necessary
        init_heap();
    }

    if ((*ptr != NULL) && (flags & LKM_EXIST)){ // non-null pointer passed with LKM_EXIST
        fprintf(stderr, "Error: Provided pointer is not NULL.\n");
        return -LKM_EXIST;
    }

    if ((*ptr == NULL) && (flags & LKM_REALLOC)){ // null pointer passed with LKM_REALLOC
        fprintf(stderr, "Error: Null pointer passed to realloc.\n");
        return -LKM_REALLOC;
    }

    if ((flags & LKM_EXIST) && (flags & LKM_REALLOC)){ // incompatible flags, ptr cannot be null
                                                       // and non-null simultaneously
        fprintf(stderr, "Invalids Flags LKM_EXIST | LKM_REALLOC\n");
        return -(LKM_EXIST | LKM_REALLOC);
    }

    void *addr; // store pointer from allocation
    struct MemBlock newMemBlock; // store new memory block

    u_int64_t time = get_tim(); // retrieve the current time

    size_t padding = size; // potential padding for underflows and overflows
    padding += (flags & LKM_OVER) ? 8 : 0;
    padding += (flags & LKM_UNDER) ? 8 : 0;

    newMemBlock.status = ALLOCATED; // setting fields of new block
    newMemBlock.size = size; // original requested size
    newMemBlock.header_bytes = NULL;
    newMemBlock.footer_bytes = NULL;
    newMemBlock.filename = filename;
    newMemBlock.func = (char *) func;
    newMemBlock.line_no = line_no;
    newMemBlock.time = time;
    newMemBlock.ret_val = 0; // assume success
    newMemBlock.ptr = *ptr; // original pointer passed

    if ((*ptr != NULL) && (flags & LKM_REALLOC)){ // if realloc requested

        int index = blk_srch(*ptr); // search for block to realloc

        if (index < 0){ // an allocated block was not found
            fprintf(stderr, "Error: Invalid pointer passed to realloc.\n");
            return -LKM_REALLOC;
        } else { // an allocated block was found

            void *to_realloc; // store address to realloc

            struct MemBlock *tmp_blk =  &g_array_index(blocks, struct MemBlock, index);
            // retrieving block
            if ((tmp_blk -> data_addr) != *ptr || (tmp_blk -> status) == FREE){
                // discovered block doesn't match with passed pointer or has already been freed
                fprintf(stderr, "Error: Invalid pointer %p passed to realloc.\n", *ptr);
                return -LKM_REALLOC;
            }

            if (tmp_blk -> header_bytes != NULL){ // free starting from header bytes if they exist
                to_realloc = tmp_blk -> header_bytes;
            } else { // free starting from data
                to_realloc = tmp_blk -> data_addr;
            }

            addr = realloc(to_realloc, padding);
            tmp_blk -> status = FREE; // set former block free and appened realloced block
        }
        
    } else {
        addr = malloc(padding); // retrieve a new address if we do not realloc
    }

    if (addr == NULL){ // malloc or realloc fails
        perror("Allocation Failure\n");
        return -errno;
    }
    
    if (flags & LKM_UNDER){ // setting underflow buffer if requested
        memset(addr, 0x6b, 8);
        newMemBlock.header_bytes = addr;
        addr += 8;
    }

    if (flags & LKM_INIT){ // setting allocated memory to 0 if requested
        memset(addr, 0, size);
    }

    if (flags & LKM_OVER){ // setting overflow buffer if requested
        addr += size;
        memset(addr, 0x5a, 8);
        newMemBlock.footer_bytes = addr;
        addr -= size;
    }

    *ptr = addr; // user's pointer
    newMemBlock.data_addr = addr; // saving allocated address

    g_array_append_vals(blocks, &newMemBlock, 1); // appending block to list

    return 0;
}

int _lkfree(void **ptr, u_int flags, char *filename, const char *func, int line_no){

    if (blocks == NULL && records == NULL){ // initialize data structures if necessary
        init_heap();
    }

    if ((flags & LKF_APPROX) && (flags & LKF_ERROR)){ // incompatible flags ; cannot let middle
                                                      // frees and prevent them simultaneously
        fprintf(stderr, "Invalid Flags LKF_APPROX | LKF_ERROR\n");
        return -(LKF_APPROX | LKF_ERROR);
    }

    int index, abort; // store index of discovered memory block / error code
    void *to_free; // store address to free
    struct MemBlock *temp_blk; // store memory block (pointer so we can set fields)
    struct MemRecord unk_rec; // various records for various events starting with orphan frees
    struct MemRecord dbl_rec; // double frees
    struct MemRecord record; // matches

    u_int64_t time = get_tim(); // retrieve time

    index = blk_srch(*ptr); // search for block to be freed
    abort = -1;

    if (index == -1){ // block was not found = orphan free

        if (flags & LKF_UNKNOWN){ // if warning requested for orphan free
            fprintf(stderr, "Warning: Pointer %p has not been allocated.\n", *ptr);
        }

        unk_rec.type = LKR_ORPHAN_FREE; // setting fields for orphan free record
        unk_rec.f_ptr = *ptr;
        unk_rec.f_filename = filename;
        unk_rec.f_func = (char *) func;
        unk_rec.f_line = line_no;
        unk_rec.f_time = time;
        unk_rec.flags = flags;
        unk_rec.f_ret_val = -LKF_UNKNOWN;

        g_array_append_vals(records, &unk_rec, 1); // appending record of orphan free

        abort = LKF_UNKNOWN; // error code for return

    } else { // block was found = discovered block

        temp_blk = &g_array_index(blocks, struct MemBlock, index); // retrieving discovered block
        int precision = ((temp_blk -> data_addr) != *ptr) ? LKF_APPROX : LKF_REG;
        // determining whether the provided address is exact ; middle free if it is not

        if ((temp_blk -> status) == FREE){ // most recent of discovered block is free ; double free
            fprintf(stderr, "Error: Double free performed on pointer %p.\n", *ptr);

            dbl_rec.type = LKR_DOUBLE_FREE; // setting fields for double free record
            dbl_rec.f_ptr = *ptr;
            dbl_rec.f_filename = filename;
            dbl_rec.f_func = (char *) func;
            dbl_rec.f_line = line_no;
            dbl_rec.f_time = time;
            dbl_rec.flags = flags;
            dbl_rec.f_ret_val = -LKR_DOUBLE_FREE;
            dbl_rec.success = -1; // free failed

            g_array_append_vals(records, &dbl_rec, 1); // append record of double free

            if (precision == LKF_APPROX){ // middle free on top of double free
                fprintf(stderr, "Error: Double free performed on pointer %p is also \
a middle free.\n", *ptr);

                struct MemRecord mid_dbl_free_rec; // setting fields for middle free record
                mid_dbl_free_rec.type = LKR_BAD_FREE;
                mid_dbl_free_rec.f_ptr = *ptr;
                mid_dbl_free_rec.f_filename = filename;
                mid_dbl_free_rec.f_func = (char *) func;
                mid_dbl_free_rec.f_line = line_no;
                mid_dbl_free_rec.f_time = time;
                mid_dbl_free_rec.flags = flags;
                mid_dbl_free_rec.f_ret_val = -LKR_BAD_FREE;
                mid_dbl_free_rec.success = -1; // free failed

                g_array_append_vals(records, &mid_dbl_free_rec, 1); // append record of middle free
            }

            return -LKR_DOUBLE_FREE; // free failed for double (possible also middle) free
        }
   
        record.f_ptr = *ptr; // setting fields for matches or valid frees
        record.f_filename = filename;
        record.f_func = (char *) func;
        record.f_line = line_no;
        record.f_time = time;
        record.m_ptr = temp_blk -> ptr; // pointer passed to malloc
        record.m_filename = temp_blk -> filename;
        record.m_func = temp_blk -> func;
        record.m_line = temp_blk -> line_no;
        record.m_time = temp_blk -> time;
        record.flags = flags;
        record.f_ret_val = 0;
        record.m_ret_val = temp_blk -> ret_val;
        record.addr = temp_blk -> data_addr; // pointer return by malloc
        record.size = temp_blk -> size; // original requested size

        if (precision == LKF_APPROX){ // handling middle free

            abort = LKF_WARN; // error code in case of return
            record.type = LKR_BAD_FREE;

            if (!(flags & LKF_APPROX)){ // if warning for middle free requested
                fprintf(stderr, "Error: Middle free detected for pointer %p.\n", *ptr);
                record.success = -1; // free failed
                g_array_append_vals(records, &record, 1);

                if (flags & LKF_ERROR){ // if exit on middle free requested
                    fprintf(stderr, "Error: Aborted before middle free attempted with pointer %p.\n"
                    , *ptr);
                    exit(EXIT_FAILURE);
                }

                return -LKF_APPROX;
            } 
        
            if (flags & LKF_WARN) { // free is approved, free success
                fprintf(stderr, "Warning: About to perform a middle free for \
pointer %p.\n", *ptr);
            }
 
        } else {
            record.type = LKR_MATCH; // perfect match
        }

        g_array_append_vals(records, &record, 1); // appending match record

        if ((temp_blk -> header_bytes) != NULL){ // free starting from underflow buffer
            to_free = temp_blk -> header_bytes;
        } else {
            to_free = temp_blk -> data_addr; // free returned address
        }

    }

    if (flags & LKF_ERROR){ // exit for encountered error conditions LKF_WARN and LKF_APPROX

        if (abort == LKF_UNKNOWN){ // print appropriate reason for exiting
        fprintf(stderr, "Error: Aborted before freeing unknown pointer %p.\n", *ptr);
        }

        exit(EXIT_FAILURE);
    } else if (abort == LKF_UNKNOWN){
        return -LKF_UNKNOWN; // prevent orphan free
    }
    
    free(to_free);
    temp_blk -> status = FREE; // block is now freed

    return 0;

}

void prt_m_rec(int fd, struct MemRecord *record){ // print malloc record to provided fd
    dprintf(fd, "0,%s,%s,%d,%lu,%p,%d,%u,%p\n", record -> m_filename, record -> m_func,
    record -> m_line, record -> m_time, record -> m_ptr, record -> m_ret_val, record -> size,
    record -> addr);
}

void prt_f_rec(int fd, struct MemRecord *record){ // print free record to provided fd
    dprintf(fd, "1,%s,%s,%d,%lu,%p,%d,%d\n", record -> f_filename, record -> f_func,
    record -> f_line, record -> f_time, record -> f_ptr, record -> f_ret_val, record -> flags);
}

void prt_solo_m(int fd, struct MemBlock *block){ // print mem leak to provided fd
    dprintf(fd, "0,%s,%s,%d,%lu,%p,%d,%u,%p\n", block -> filename, block -> func,
    block -> line_no, block -> time, block -> ptr, block -> ret_val, block -> size,
    block -> data_addr);
}

int lkreport(int fd, u_int flags){

    if (fcntl(fd, F_GETFD) == -1){ // invalid fd provided
        return -errno;
    }
    // print header for columns
    dprintf(fd, "record_type,filename,fxname,line_num,timestamp,ptr_passed,retval,size_or_flags,\
alloc_addr_returned\n");

    for (unsigned int i = 0; i < (records -> len); i++){ // iterating through records
        struct MemRecord record = g_array_index(records, struct MemRecord, i);
        // successful perfect matches
        if ((flags & LKR_MATCH) && (record.type == LKR_MATCH)){
            // dprintf(fd, "Perfect Match\n");
            prt_m_rec(fd, &record);
            prt_f_rec(fd, &record);
        }
        // successful middle matches
        if ((flags & LKR_APPROX) && (record.type == LKR_BAD_FREE) && record.success == 0){
            // dprintf(fd, "Match With Middle Free\n");
            prt_m_rec(fd, &record);
            prt_f_rec(fd, &record);
        }
        // middle free attempts
        if ((flags & LKR_BAD_FREE) && (record.type == LKR_BAD_FREE)){
            // dprintf(fd, "Middle Free\n");
            prt_f_rec(fd, &record);
        }
        // orphan free attempts
        if ((flags & LKR_ORPHAN_FREE) && (record.type == LKR_ORPHAN_FREE)){
            // dprintf(fd, "Free With No Malloc\n");
            prt_f_rec(fd, &record);
        }
        // double free attempts
        if ((flags & LKR_DOUBLE_FREE) && (record.type == LKR_DOUBLE_FREE)){
            // dprintf(fd, "Double Free\n");
            prt_f_rec(fd, &record);
        }

    }

    if (flags & LKR_SERIOUS){ // if mem leak report requested

        // dprintf(fd, "Memory Leaks\n");

        for (unsigned int i = 0; i < (blocks -> len); i++){ // iterating through blocks
            struct MemBlock block = g_array_index(blocks, struct MemBlock, i);

            if (block.status == ALLOCATED){ // printing remaining allocated blocks
                prt_solo_m(fd, &block);
            }
        }

    }

    return records -> len;
}

void exit_func(int exit_status, void *args){

    struct CleanUp *c;
    c = (struct CleanUp *) args;

    lkreport(c -> fd, c -> flags); // final report

    g_array_free(blocks, FREE); // cleaning up data structures
    g_array_free(records, FREE);


    exit_status = exit_status ? 0 : 0; // placeholder, exit status not required
}