#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

//My Includes
#include <headers.h>

int main(){ // Blank driver to store tests

    exit(0);
}

// Tests

// ### Malloc With LKM_UNDER + LKM_INIT + LKM_OVER ###

    // const char *under = "kkkkkkkk";
    // const char *over = "ZZZZZZZZ";
    // const char mid[8] = {0,0,0,0,0,0,0,0};
    // int c;

    // lkmalloc(8, &i, LKM_INIT | LKM_UNDER | LKM_OVER);

    // i -= 8;
    // c = memcmp(i, under, 8);
    // printf("%d\n", c);
    
    // i += 8;
    // c = memcmp(i, mid, 8);
    // printf("%d\n", c);

    // i += 8;
    // c = memcmp(i, over, 8);
    // printf("%d\n", c);

// ### Realloc With LKM_UNDER + LKM_INIT + LKM_OVER ###

    // const char *under = "kkkkkkkk";
    // const char *over = "ZZZZZZZZ";
    // const char mid[8] = {0,0,0,0};
    // int c;

    // lkmalloc(8, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkmalloc(4, &i, LKM_INIT | LKM_UNDER | LKM_OVER | LKM_REALLOC);

    // i -= 8;
    // c = memcmp(i, under, 8);
    // printf("%d\n", c);
    
    // i += 8;
    // c = memcmp(i, mid, 4);
    // printf("%d\n", c);

    // i += 4;
    // c = memcmp(i, over, 8);
    // printf("%d\n", c);
    
// ### Malloc + LKM_EXIST ###

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkmalloc(32, &i, LKM_EXIST);
    // lkreport(2, 0x3f);

// ### Perfect Match: Malloc And Free ###

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkfree(&i, LKF_REG);
    // lkreport(2, 0x3f);

// ### Middle Free Without LKF_APPROX ###

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // i += 32;
    // lkfree(&i, LKF_REG);
    // lkreport(2, 0x3f);

// ### Middle Free: Middle Free + LKF_WARN ###

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // i += 32;
    // lkfree(&i, LKF_APPROX | LKF_WARN);
    // lkreport(2, 0x3f);

// ### Free With No Malloc + LKF_UNKNOWN ###

    // lkfree(&i, LKF_UNKNOWN);
    // lkreport(2, 0x3f);

// ## Free + LKF_ERROR ###

    // lkmalloc(8, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // i += 4;
    // lkfree(&i, LKF_ERROR);

// ### Double Free ###

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkfree(&i, LKF_REG);
    // lkfree(&i, LKF_REG);
    // lkreport(2, 0x3f);

// ### Double Middle Free ###

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // i += 32;
    // lkfree(&i, LKF_APPROX);
    // lkfree(&i, LKF_APPROX);
    // lkreport(2, 0x3f);

// ### Realloc Larger ###

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkmalloc(64, &s, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkmalloc(128, &i, LKM_REALLOC);
    // lkreport(2, 0x3f);

// ### Realloc Smaller ###

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkmalloc(64, &s, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkmalloc(32, &i, LKM_REALLOC);
    // lkreport(2, 0x3f);

// ### Realloc Null ###

    // lkmalloc(32, &i, LKM_REALLOC);
    // lkreport(2, 0x3f);

// ### Simple Memory Leak ### 

    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkreport(2, 0x3f);

// ### Simple Memory Leak Overwriting Local Address ###

    // i = "HELLO";
    // lkmalloc(64, &i, LKM_INIT | LKM_UNDER | LKM_OVER);
    // lkreport(2, 0x3f);