/* SPDX-License-Identifier: BSD-3-Clause */

/* -fzero-init-padding-bits=all probe (runtime channel).
 *
 * The guide recommends this for the same reason as `-ftrivial-auto-var-init`: storage
 * a program never wrote can still be read, and what it holds is whatever the frame
 * held before. This flag covers the half that flag does not, the bytes of an object
 * that *was* initialized but whose initializer does not name every byte.
 *
 * ## Why a union, and why only a union
 *
 * Struct padding is not the case that discriminates. gcc already zeroes it, so
 * `= { .a = 1 }` on a padded struct emits identical code with and without the flag,
 * at every optimization level. Measured on gcc 16.1.1 across `-O0` through `-Os`.
 * A test over partially-initialized structs and bitfields alone reads the flag as
 * unobservable, since gcc handles both already.
 *
 * A union with a short active member is the case. `union { unsigned char c; unsigned
 * long wide; } u = { .c = 1 }` stores one byte and leaves seven; the flag emits a
 * store zeroing the whole object first. At `-O0` on gcc that is one extra
 * instruction, `movq $0, -8(%rbp)`, and it is visible from the bytes past the active
 * member.
 *
 * ## The frame discipline is inherited, not improvised
 *
 * Reading storage that "should" hold dirt requires knowing the dirt was there, and
 * `auto_var_init.c` records at length what goes wrong otherwise: a `dirty()` helper
 * fills its own frame, strictly below the observation frame, so the negative arm ends
 * up reading loader and libc-startup residue and discriminating for a reason
 * unrelated to the flag. That is a false control, and it is one unlucky image away
 * from a silent false positive.
 *
 * So the same shape is used here. One function, called twice: pass 1 fills, pass 2
 * re-enters the identical frame and lets the initializer run over the dirt. Nothing
 * may be called between the two. Every read goes through a `volatile` lvalue so the
 * load must be emitted. `ctrl` carries `__attribute__((uninitialized))`, opting out
 * of initialization entirely, so it must always read back the dirt, if it does not,
 * frame reuse did not happen and the run is `probe-invalid` from the measured build
 * alone, without reference to the controls.
 *
 * ## What the bytes mean
 *
 *   pad=5a  the dirt survived        -> the initializer left the inactive bytes: flag off
 *   pad=00  zeroed                   -> the whole object was zeroed first: flag on
 *   ctrl!=5a                         -> frame reuse failed; nothing is established
 *
 * ## Where this cannot answer, measured rather than assumed
 *
 * **clang has no such flag.** clang 22.1.8 rejects `-fzero-init-padding-bits=all`
 * with "unknown argument", so both control arms fail to build and there is nothing to
 * compare. The check is gated `compiler_unsupported: ["clang"]` for that reason.
 *
 * **gcc above -O0 cannot be measured this way.** From `-O1` upward `ctrl` stops
 * reading the dirt: the frame is reused differently and the premise fails. The
 * padding byte reads 0x00 in both arms there, which looks like the flag working and
 * establishes nothing, exactly the reading the witness exists to refuse. So this
 * answers under `bare` and withholds elsewhere, which is narrower than the guide's
 * recommendation, since the guide asks for the flag on production builds.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if defined(__has_attribute)
#if __has_attribute(uninitialized)
#define CHARD_NOINIT __attribute__((uninitialized))
#endif
#endif
#ifndef CHARD_NOINIT
/* No opt-out available: `ctrl` cannot witness frame reuse, so the detector is told
 * the witness is absent rather than being handed one that means nothing. */
#define CHARD_NOINIT
#define CHARD_NO_CTRL 1
#endif

union chard_pad {
    unsigned char active;
    unsigned long wide;
};

static volatile unsigned char g_sink;

/* Pass 1 (dirty=1) fills the frame; pass 2 (dirty=0) observes the same frame after
 * the initializer for `u` has run over it. */
__attribute__((noinline)) static void frame(int dirty, unsigned char *out)
{
    union chard_pad u = { .active = 1 };
    unsigned char ctrl[32] CHARD_NOINIT;

    if (dirty) {
        /* Each loop counter is declared in a block of its own and initialised there, not
         * in the `for`: gcc before 5 defaults to gnu89, which rejects a declaration in the
         * loop, and every arm builds in the profile's own dialect. The block and the
         * initialiser are the scope and the initialiser the C99 loop had, so the frame and
         * the stores -ftrivial-auto-var-init adds are unchanged: objects byte-identical with
         * the C99 spelling on gcc 16.1.1 and clang 22.1.8, -O0 through -Os, measured
         * 2026-10-07 (a counter declared once for all the loops moves the -O0 frame). */
        {
            size_t i = 0;
            for (; i < sizeof u; i++) {
                ((volatile unsigned char *) &u)[i] = 0x5A;
            }
        }
        {
            size_t i = 0;
            for (; i < sizeof ctrl; i++) {
                ctrl[i] = 0x5A;
            }
        }
    } else {
        /* Byte 1 is past the active member: storage the initializer did not name. */
        out[0] = ((volatile unsigned char *) &u)[1];
        out[1] = *(volatile unsigned char *) &ctrl[0];
    }

    /* Make both addresses escape so neither object can be promoted out of memory. */
    g_sink ^= (unsigned char) (uintptr_t) (void *) &u;
    g_sink ^= (unsigned char) (uintptr_t) (void *) ctrl;
}

int main(void)
{
    unsigned char a[2], b[2];

    frame(1, a);
    frame(0, b); /* NOTHING between these two calls, see the header comment. */

#ifdef CHARD_NO_CTRL
    printf("ZIPB pad=%02x ctrl=%02x ctrl_supported=0\n", b[0], b[1]);
#else
    printf("ZIPB pad=%02x ctrl=%02x ctrl_supported=1\n", b[0], b[1]);
#endif
    return 0;
}
