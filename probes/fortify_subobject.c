/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE level-2 probe (runtime channel): rung 2 of the fortify ratchet. */

#include <stdio.h>
#include <string.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/*After the libc headers, so `_FORTIFY_IMPL` reflects which implementation actually wrapped this
 *translation unit. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

struct pair {
    char a[8];
    char b[8];
};

static struct pair obj;

/* The shape of glibc's `__fortify_function` before its clang path: the size is asked for
 * inside an always-inline function, of that function's own parameter. */
static inline __attribute__((__always_inline__, __gnu_inline__, __artificial__)) size_t
chard_bos1_in_wrapper(char *p)
{
    return __builtin_object_size(p, 1);
}

/*Which wrapper form the C library compiled into this translation unit, printed beside the sizes so
 *the gating rule reads the library's state rather than infers it. */
#if defined(_BITS_STRING_FORTIFIED_H)
#  define CHARD_GLIBC_WRAPPERS 1
#else
#  define CHARD_GLIBC_WRAPPERS 0
#endif
#if !defined(__fortify_use_clang)
#  define CHARD_CLANG_PATH "?"
#elif __fortify_use_clang
#  define CHARD_CLANG_PATH "1"
#else
#  define CHARD_CLANG_PATH "0"
#endif

/* 13 characters plus a terminator: overruns `a` but stays inside `obj`. */
static const char source[] = "0123456789ABC";

int main(void)
{
    CHARD_PRINT_REPORT;
    CHARD_NOT_DUMPABLE;

    /* Instrument, not observable: the detector reads none of these fields. */
    printf("CHARD-BOS main1=%zu main0=%zu wrap1=%zu glibc_wrappers=%d clang_path=%s\n",
           __builtin_object_size(obj.a, 1),
           __builtin_object_size(obj.a, 0),
           chard_bos1_in_wrapper(obj.a),
           CHARD_GLIBC_WRAPPERS,
           CHARD_CLANG_PATH);
    /*Flushed for the reason `CHARD_PRINT_REPORT` flushes: the next statement is meant to abort, the
     *harness redirects stdout to a file, and a buffer the abort destroys carries nothing. */
    fflush(stdout);

    strcpy(obj.a, source);

    /* Reached only when nothing caught the subobject overflow. */
    printf("no-check-fired %c\n", obj.a[0]);
    return 0;
}
