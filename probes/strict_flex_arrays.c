/* SPDX-License-Identifier: BSD-3-Clause */

/* -fstrict-flex-arrays probe (runtime channel). */

#include <stdio.h>
#include <sys/types.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

struct trailing_two {
    int header;
    char tail[2];
};
struct trailing_one {
    int header;
    char tail[1];
};
struct trailing_zero {
    int header;
    char tail[0];
};

#define SLACK 32

/* Each object is its struct with SLACK bytes of declared storage after it. */
static union {
    struct trailing_two s;
    char storage[sizeof(struct trailing_two) + SLACK];
} two_object;
static union {
    struct trailing_one s;
    char storage[sizeof(struct trailing_one) + SLACK];
} one_object;
static union {
    struct trailing_zero s;
    char storage[sizeof(struct trailing_zero) + SLACK];
} zero_object;

/* File-scope so an unoptimized build does not see which object each one names. */
static struct trailing_two *two;
static struct trailing_one *one;
static struct trailing_zero *zero;

int main(void) {
    two = &two_object.s;
    one = &one_object.s;
    zero = &zero_object.s;

    /* Each prints its own size when bounded, or the rest of the object when the
     * declaration is being treated as a flexible member. */
    printf("flex-two=%zd flex-one=%zd flex-zero=%zd\n",
           (ssize_t)__builtin_object_size(two->tail, 1),
           (ssize_t)__builtin_object_size(one->tail, 1),
           (ssize_t)__builtin_object_size(zero->tail, 1));
#ifdef __OPTIMIZE__
    printf("optimize=yes\n");
#else
    printf("optimize=no\n");
#endif
    printf("storage=declared\n");
    return 0;
}
