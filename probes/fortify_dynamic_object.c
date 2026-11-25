/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE level-3 probe (runtime channel), heap destination. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* `malloc_usable_size` is glibc's, from <malloc.h>. musl and Apple have equivalents
 * under other names and other geometries, and neither is what the margin above is
 * computed from, so the assertion is made only where the claim is. */
#if defined(__GLIBC__)
#  include <malloc.h>
#  define CHARD_HAVE_USABLE_SIZE 1
#endif

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/*After the libc headers, so `_FORTIFY_IMPL` reflects which implementation actually wrapped this
 *translation unit. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/*`volatile` is the mechanism, see the header comment: it is what keeps the allocation size opaque
 *to `__builtin_object_size`, and without it level 2 fires like level 3 on both compilers. */
static volatile size_t want = 16;
static volatile size_t n = 32;

int main(void)
{
    CHARD_PRINT_REPORT;
    CHARD_NOT_DUMPABLE;

    char *dst = malloc(want);
    char *src = malloc(64);

    if (dst == NULL || src == NULL) {
        /* Distinct status so an allocation failure is never read as "level 2". */
        return CHARD_EXIT_NO_ALLOCATION;
    }

    /* The precondition, asked of the compiler that built this. */
    if (__builtin_object_size(dst, 0) != (size_t) -1
        || __builtin_object_size(dst, 1) != (size_t) -1) {
        fprintf(stderr,
                "chard-probe: opacity lost: __builtin_object_size(dst) is %zu (type 0) "
                "and %zu (type 1) rather than unknown, so a level-2 build would fire "
                "like level 3\n",
                (size_t) __builtin_object_size(dst, 0),
                (size_t) __builtin_object_size(dst, 1));
        return CHARD_EXIT_OPACITY_LOST;
    }

#if defined(CHARD_HAVE_USABLE_SIZE)
    /*The margin's premise: the chunk geometry the header comment describes, and `src` as the
     *neighbour whose size field the copy overwrites. */
    if (malloc_usable_size(dst) != 32 - sizeof(size_t)) {
        fprintf(stderr,
                "chard-probe: heap geometry is not the one the margin assumes: "
                "malloc_usable_size(dst) is %zu, expected %zu\n",
                malloc_usable_size(dst), 32 - sizeof(size_t));
        return CHARD_EXIT_HEAP_GEOMETRY;
    }
    if ((uintptr_t) src != (uintptr_t) dst + 32) {
        fprintf(stderr,
                "chard-probe: heap geometry is not the one the margin assumes: "
                "src is at dst%+td, expected dst+32\n",
                (ptrdiff_t) ((uintptr_t) src - (uintptr_t) dst));
        return CHARD_EXIT_HEAP_GEOMETRY;
    }
#endif

    memset(src, 'A', 64);
    memcpy(dst, src, n);

    printf("no-check-fired %c\n", dst[0]);
    return 0;
}
