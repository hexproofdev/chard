/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE enforcement probe (runtime channel), known-size destination.
 *
 * Overflows a destination whose size `__builtin_object_size` can determine at
 * compile time, which _FORTIFY_SOURCE catches from level 1 upward. Outcome:
 *
 *   fortify active   -> SIGABRT, stderr "*** buffer overflow detected ***"
 *   fortify inactive -> prints "no-check-fired" and exits 0
 *
 * Two deliberate choices keep the verdict honest:
 *
 *   - `dst` is at file scope rather than a local. A local would also be covered
 *     by the stack canary, and a canary abort looks identical to a fortify abort
 *     at the level of "the process died by SIGABRT", so fortify would be credited
 *     with the protector's work. At file scope only fortify can fire.
 *
 *   - `n` is volatile, so the length is not a compile-time constant. With a
 *     constant the compiler would reject the call outright via
 *     -Wstringop-overflow, turning a runtime probe into a build failure and
 *     measuring the wrong channel.
 *
 * Note that fortify is inert without optimization: glibc's checks live in inline
 * wrappers that only exist once the optimizer runs. A `bare` profile with no -O
 * therefore reports fortify off, which is the truthful answer for that
 * invocation; the positive control supplies -O2 to prove the probe can fire.
 *
 * ## Where the overflow lands, and the probe's check of it
 *
 * When nothing catches it, the copy writes 16 bytes past the end of `dst`. Those
 * bytes have to be inside an object this probe declares: with nothing there the
 * write lands wherever the linker left room, which was page padding past `_end`
 * on both compilers when this was measured and would be `src` under a reordering
 * link, making the copy self-overlapping, which is undefined behaviour of its own
 * before fortify is even asked. So `dst` is flanked by two 16-byte guard arrays,
 * and before the copy the probe checks at run time that one of them begins
 * exactly where `dst` ends. When neither does it exits CHARD_EXIT_LAYOUT, a
 * status the runtime detector reads as a withheld verdict naming the layout,
 * instead of measuring over memory the probe does not own.
 *
 * Two guards rather than one, because the two compilers place file-scope statics
 * in opposite orders. gcc emits them in declaration order at -O0 and in reverse
 * declaration order from -O1 upward; clang emits an internal-linkage variable
 * when it is first referenced, so its order is the order of first use. A single
 * guard declared after `dst` follows it under clang and precedes it under an
 * optimising gcc, and the positive control is `-O2`. With a guard on each side
 * one of them follows under every order either compiler produces, and the check
 * says which. Measured on this file's own host (Apple clang 21.0.0 and Homebrew
 * gcc 16.2.0, arm64, at -O0, -O1, -O2, -O3 and -Os, fortify off and at level 2):
 * `guard_hi` follows `dst` in every clang build and in gcc's -O0 build, `guard_lo`
 * follows in every other gcc build, and in all twenty the three objects are
 * contiguous at 16-byte spacing. The review that asked for the guard measured the
 * layout before it existed, on Linux/glibc x86_64: gcc placed `src` at 0x403040
 * and `dst` at 0x403080 with `_end` at 0x403090, clang placed them at 0x403030 and
 * 0x403070, and `-fdata-sections -Wl,--sort-section=name` put `src` at dst+16 on
 * both.
 *
 * The guard cannot be a member of the same object as `dst`. Level 1 bounds the
 * copy by the whole enclosing object, so a write that stayed inside a struct
 * holding both would be one that level 1 does not catch, and the probe exists to
 * show level 1 catching it. Adjacency between two distinct objects is a decision
 * of the compiler and the linker, which is why it is checked rather than assumed.
 *
 * The addresses are read through volatile pointers so the comparison is made at
 * run time: a compiler is entitled to fold a comparison between the end of one
 * array and the start of another, and a folded check would be a comment.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/* After the libc headers, so `_FORTIFY_IMPL` reflects which implementation
 * actually wrapped this translation unit. The runtime detector needs it: glibc
 * aborts with a message, fortify-headers traps silently, and the two cannot be
 * told apart from the termination alone. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/* One guard on each side of `dst`; see the header comment for why two. Each is
 * the size of the overrun, so the bytes the copy writes past `dst` fill whichever
 * guard follows it and reach nothing beyond. */
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
