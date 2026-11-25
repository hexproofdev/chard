/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE level-2 probe (runtime channel): rung 2' of the fortify ratchet. */

#include <stdio.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/*After the libc headers, so `_FORTIFY_IMPL` reflects which implementation actually wrapped this
 *translation unit. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/* Writable by construction: not `const`, so it lands in a writable section. */
static char format_buffer[8] = "%n";
static char *volatile format = format_buffer;

int main(void)
{
    int written = 0;

    CHARD_PRINT_REPORT;
    CHARD_NOT_DUMPABLE;

    printf(format, &written);

    /* Reached only when nothing rejected the writable-segment %n. */
    printf("no-check-fired %d\n", written);
    return 0;
}
