/* SPDX-License-Identifier: BSD-3-Clause */

/* -fzero-init-padding-bits=all probe (runtime channel). */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if defined(__has_attribute)
#if __has_attribute(uninitialized)
#define CHARD_NOINIT __attribute__((uninitialized))
#endif
#endif
#ifndef CHARD_NOINIT
/* No attribute to keep a whole-variable initializer off `ctrl`. */
#define CHARD_NOINIT
#define CHARD_NO_CTRL 1
#endif

/* The inactive member is wide so that no store the optimizer makes for the active member
 * reaches the byte read (the header's "Why a union, and why a wide one"). */
union chard_pad {
    unsigned char active;
    unsigned char wide[128];
};

static volatile unsigned char g_sink;

/* Pass 1 (dirty=1) fills the frame; pass 2 (dirty=0) observes the same frame after
 * the initializer for `u` has run over it. */
__attribute__((noinline)) static void frame(int dirty, unsigned char *out)
{
    union chard_pad u = { .active = 1 };
    unsigned char ctrl[32] CHARD_NOINIT;

    if (dirty) {
        /*Each loop counter is declared in a block of its own and initialised there, not in the
         *`for`: gcc before 5 defaults to gnu89, which rejects a declaration in the loop, and every
         *arm builds in the profile's own dialect. */
        {
            size_t i = 0;
            for (; i < sizeof u; i++) {
                ((volatile unsigned char *) &u)[i] = 0x5A;
            }
        }
        {
            size_t i = 0;
            for (; i < sizeof ctrl; i++) {
                /* Volatile, so the stores are kept although nothing in this pass reads
                 * them: with plain stores here gcc 16.1.1 at -O1 and above reads `ctrl`
                 * without the dirt. */
                ((volatile unsigned char *) ctrl)[i] = 0x5A;
            }
        }
    } else {
        /* The last byte is past the active member: storage the initializer did not name,
         * and the farthest from it. */
        out[0] = ((volatile unsigned char *) &u)[sizeof u - 1];
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
