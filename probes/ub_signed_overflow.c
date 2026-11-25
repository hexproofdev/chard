/* SPDX-License-Identifier: BSD-3-Clause */

/* -fno-strict-overflow / -fwrapv probe (runtime channel). */

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
    /*The probe reports its own compilation, for the reason the aliasing probe beside it does:
     *`ev.macros` is populated only for probes carrying a macro-channel check, and this one is
     *runtime-only, so the detector has nothing else to read. */
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
