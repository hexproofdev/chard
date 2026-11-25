/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE enforcement probe (runtime channel), known-size destination. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/*After the libc headers, so `_FORTIFY_IMPL` reflects which implementation actually wrapped this
 *translation unit. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/* One guard on each side of `dst`; see the header comment for why two. */
static char guard_lo[16];
static char dst[16];
static char guard_hi[16];
static char src[64];

static volatile size_t n = 32;

int main(void)
{
    CHARD_PRINT_REPORT;
    CHARD_NOT_DUMPABLE;

    /* Read in this order, because under clang the order of first reference is
     * the order of placement. */
    char *volatile lo = guard_lo;
    char *volatile d = dst;
    char *volatile hi = guard_hi;
    uintptr_t past_dst = (uintptr_t) d + sizeof dst;

    if ((uintptr_t) hi != past_dst && (uintptr_t) lo != past_dst) {
        /* Offsets from `dst` rather than addresses: the distance between two
         * file-scope objects is fixed at link time, so the message, which becomes
         * the withheld cell's `observed`, reads the same under address-space
         * randomisation run after run. */
        fprintf(stderr,
                "chard-probe: layout precondition failed: guard_lo is at dst%+td and "
                "guard_hi at dst%+td, so the %zu bytes past dst are not a guard this "
                "probe declares\n",
                (ptrdiff_t) ((uintptr_t) lo - (uintptr_t) d),
                (ptrdiff_t) ((uintptr_t) hi - (uintptr_t) d),
                (size_t) (n - sizeof dst));
        return CHARD_EXIT_LAYOUT;
    }

    memset(src, 'A', sizeof src);
    memcpy(dst, src, n);

    /* Reached only when nothing caught the overflow. */
    printf("no-check-fired %c\n", dst[0]);
    return 0;
}
