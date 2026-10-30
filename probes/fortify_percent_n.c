/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE level-2 probe (runtime channel): rung 2' of the fortify ratchet.
 *
 * A `%n` conversion in a format string that lives in *writable* memory. From level
 * 2, glibc refuses it outright and aborts with a message of its own:
 *
 *     *** %n in writable segment(s) detected ***
 *
 * That distinct text is why this probe exists alongside the subobject probe. The
 * two rungs test the same level through mechanically unrelated code paths (one
 * through `__builtin_object_size` type 1, one through glibc's format-string
 * validation) and they carry different diagnostics, so neither can be mistaken
 * for the other or for the whole-object rung. Corroboration of this kind is what
 * the macro channel taught us to want.
 *
 * `%n` is also the specific primitive that turns a format-string bug into an
 * arbitrary write, which makes it worth measuring on its own terms rather than
 * only as a level indicator.
 *
 * Verified on gcc 16.1.1 and clang 22.1.8: exit 0 at levels 0 and 1, abort at
 * levels 2 and 3, on both compilers.
 *
 * The format string is reached through a `volatile` pointer for a practical
 * reason: it keeps the call opaque enough that `-Werror=format-security`, which
 * the OpenSSF guide's own recommended flag set includes, does not reject the
 * translation unit. A probe that cannot be compiled under the profile it is meant
 * to measure is useless. `-Wformat-nonliteral` still warns, which is harmless
 * because it is not in that flag set and is not an error.
 */

#include <stdio.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/* After the libc headers, so `_FORTIFY_IMPL` reflects which implementation
 * actually wrapped this translation unit. The runtime detector needs it: glibc
 * aborts with a message, fortify-headers traps silently, and the two cannot be
 * told apart from the termination alone. */
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
