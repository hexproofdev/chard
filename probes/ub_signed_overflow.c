/* SPDX-License-Identifier: BSD-3-Clause */

/* -fno-strict-overflow / -fwrapv probe (runtime channel).
 *
 * A different observable from every other probe in this corpus. The others read a
 * macro, a bit in the artifact, a manner of death, or a compiler diagnostic. These
 * three anti-UB flags leave none of those: they do not define a macro, they set no
 * ELF bit, they change no diagnostic, and a build that has them is byte-for-byte
 * ordinary. What they change is whether the optimizer is *permitted to delete code*
 * on the strength of an undefined behaviour never happening.
 *
 * So the observable is whether a guard the optimizer would otherwise remove is still
 * there to run. The program tests its own generated code.
 *
 * ## The shape
 *
 * `x + 1 < x` is false for every `x` where signed overflow is defined not to happen,
 * which, absent this flag, is every `x`, because the standard makes the overflow
 * undefined and the compiler may assume undefined things do not occur. The guard is
 * therefore dead code and gets folded away. Under `-fno-strict-overflow` or `-fwrapv`
 * the overflow is defined to wrap, `INT_MAX + 1` is `INT_MIN`, and the comparison is
 * true, so the guard survives *and fires*.
 *
 * This is the overflow check every C programmer has been told not to write, and the
 * reason it does not work is exactly what this probe measures.
 *
 * ## Why the input is volatile and the function is noinline
 *
 * Both are load-bearing, and for the same reason: if the compiler can see that `x` is
 * `INT_MAX` at the call site it can fold the whole call to a constant, and the answer
 * would then be about constant folding rather than about the flag. `volatile` forces
 * a real load of a value the compiler must treat as unknown; `noinline` keeps the
 * comparison in a function that cannot see its caller.
 *
 * ## Measured behaviour, both compilers
 *
 * The guard is deleted at `-O2` on gcc and clang, and restored by either
 * `-fno-strict-overflow` or `-fwrapv`. gcc 8 and later also fold it at `-O0`, which
 * clang does not, and `-fno-strict-overflow` restores it there too. gcc 4.8, 5.4 and
 * 7.5 keep it at `-O0`, `-O1` and `-Og` without the flag, as clang does at `-O0`. So
 * the probe reports gcc's major version beside its front end, and an unoptimized build
 * is decidable on gcc 8 and later only. The measurements are at the detector,
 * `detect_no_strict_overflow`.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/* Opaque to the optimizer: it must emit a real load and cannot know the value. */
static volatile int input = 2147483647; /* INT_MAX */

__attribute__((noinline)) static int overflow_guard(int x) {
    /* Deleted when signed overflow is assumed not to happen. */
    if (x + 1 < x) {
        return 1;
    }
    return 0;
}

int main(void) {
    /* The probe reports its own compilation, for the reason the aliasing probe beside it
     * does: `ev.macros` is populated only for probes carrying a macro-channel check, and
     * this one is runtime-only, so the detector has nothing else to read.
     *
     * All three facts are needed and none alone is enough. At `-O0` gcc 8 and later
     * still fold the guard away without the flag, so an unoptimized build of theirs that
     * *ran* the guard did so because the flag was passed. clang, and the gcc 4.8, 5.4 and
     * 7.5 measured, keep the guard at `-O0` whether or not the flag was passed, and
     * crediting that reported `-fno-strict-overflow: on` for every such compiler measured
     * under a bare profile. The compiler's identity and gcc's version are therefore part of
     * the evidence rather than part of the detector's assumptions. */
#ifdef __OPTIMIZE__
    printf("optimize=yes\n");
#else
    printf("optimize=no\n");
#endif
#if defined(__clang__)
    printf("frontend=clang\n");
#elif defined(__GNUC__)
    printf("frontend=gcc\n");
    printf("gcc-major=%d\n", __GNUC__);
#else
    printf("frontend=other\n");
#endif

    if (overflow_guard(input)) {
        printf("overflow-guard=ran\n");
    } else {
        printf("overflow-guard=deleted\n");
    }
    return 0;
}
