/* SPDX-License-Identifier: BSD-3-Clause */

/* -ftrapv read from what a signed overflow does when it runs.
 *
 * The program adds 1 to INT_MAX and reports what happened. Without the flag the sum
 * wraps and the program exits 0 having printed `trapv-overflow=wrapped`. Under -ftrapv
 * it dies before printing that line, and the two compilers kill it differently: gcc
 * calls libgcc's `__addvsi3`, which calls `abort()` (SIGABRT, nothing on stderr), and
 * clang emits an overflow test and a trap instruction (SIGILL on x86, SIGTRAP on
 * aarch64, nothing on stderr). Measured at every optimization level on both compilers;
 * the figures are on `decode::runtime::detect_trapv`.
 *
 * ## What else kills the program the same way
 *
 * A trap on this addition is not clang's -ftrapv alone: UBSan's signed-integer-overflow
 * check in trap mode (`-fsanitize-trap`, `-fsanitize-undefined-trap-on-error`) emits the
 * same test and the same trap, on gcc and clang alike, and on clang the two objects are
 * identical. So the program says whether a UBSan check was compiled in, through
 * `__has_feature(undefined_behavior_sanitizer)`, which clang has defined for every
 * version measured and gcc from 14; a trap is credited to -ftrapv only on clang and only
 * beside a 0. gcc's -ftrapv never traps, so a gcc trap is never credited. An abort is
 * credited only on gcc, and only with stderr empty: `abort()` from the stack protector,
 * fortify or a UBSan handler that does not recover all print first.
 *
 * ## Why the operands are volatile and the function is noinline
 *
 * For the reason `ub_signed_overflow.c` gives: a sum the compiler can see is a constant,
 * and a constant overflow is a diagnostic at compile time and nothing at run time. The
 * loads are real and the function cannot see its caller.
 *
 * ## Why stdout is flushed before the addition
 *
 * stdout is a file when chard runs a probe, so it is fully buffered, and a signal death
 * discards the buffer. The lines before the addition are flushed so that a run that died
 * there still says what it was built with and that it reached the overflow.
 */

#include <stdio.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

#ifndef __has_feature
#  define __has_feature(x) 0
#  define CHARD_TRAPV_NO_FEATURE_TEST 1
#endif

static volatile int lhs = 2147483647; /* INT_MAX */
static volatile int rhs = 1;

__attribute__((noinline)) static int chard_trapv_add(int a, int b)
{
    return a + b;
}

int main(void)
{
    CHARD_NOT_DUMPABLE;
#if defined(__clang__)
    printf("frontend=clang\n");
#elif defined(__GNUC__)
    printf("frontend=gcc\n");
#else
    printf("frontend=other\n");
#endif
#if defined(CHARD_TRAPV_NO_FEATURE_TEST)
    printf("ubsan=unknown\n");
#elif __has_feature(undefined_behavior_sanitizer)
    printf("ubsan=yes\n");
#else
    printf("ubsan=no\n");
#endif
    printf("trapv-overflow=attempted\n");
    fflush(stdout);

    int sum = chard_trapv_add(lhs, rhs);

    printf("trapv-overflow=wrapped sum=%d\n", sum);
    return 0;
}
