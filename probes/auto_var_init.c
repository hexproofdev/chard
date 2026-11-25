/* SPDX-License-Identifier: BSD-3-Clause */

/* -ftrivial-auto-var-init probe (runtime channel). */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#if defined(__has_attribute)
#if __has_attribute(uninitialized)
#define CHARD_NOINIT __attribute__((uninitialized))
#endif
#endif
#ifndef CHARD_NOINIT
/* No opt-out available on this compiler: `ctrl` degrades to a fourth observation
 * and the detector is told not to treat it as a witness. */
#define CHARD_NOINIT
#define CHARD_NO_CTRL 1
#endif

static volatile unsigned char g_sink;

/* Pass 1 (dirty=1) fills; pass 2 (dirty=0) observes the same frame. */
__attribute__((noinline)) static void frame(int dirty, unsigned char *out)
{
    unsigned char arr[64];
    unsigned int word;
    unsigned char small[4];
    unsigned char ctrl[64] CHARD_NOINIT;

    if (dirty) {
        /*Each loop counter is declared in a block of its own and initialised there, not in the
         *`for`: gcc before 5 defaults to gnu89, which rejects a declaration in the loop, and every
         *arm builds in the profile's own dialect. */
        {
            size_t i = 0;
            for (; i < sizeof arr; i++) {
                arr[i] = 0x5A;
            }
        }
        word = 0x5A5A5A5Au;
        {
            size_t i = 0;
            for (; i < sizeof small; i++) {
                small[i] = 0x5A;
            }
        }
        {
            size_t i = 0;
            for (; i < sizeof ctrl; i++) {
                ctrl[i] = 0x5A;
            }
        }
    }

    /* volatile lvalues: the load must be emitted, so the optimizer cannot answer
     * from `undef`. */
    out[0] = *(volatile unsigned char *) &arr[0];
    out[1] = (unsigned char) (*(volatile unsigned int *) &word & 0xFFu);
    out[2] = *(volatile unsigned char *) &small[0];
    out[3] = *(volatile unsigned char *) &ctrl[0];

    /* Make the addresses escape so neither object can be promoted out of memory. */
    g_sink ^= (unsigned char) (uintptr_t) (void *) arr;
    g_sink ^= (unsigned char) (uintptr_t) (void *) ctrl;
}

int main(void)
{
    unsigned char a[4], b[4];

    frame(1, a);
    frame(0, b); /* NOTHING between these two calls, see the header comment. */

    printf("TAVI arr=%02x word=%02x small=%02x ctrl=%02x ctrl_supported=%d\n",
           b[0],
           b[1],
           b[2],
           b[3],
#ifdef CHARD_NO_CTRL
           0
#else
           1
#endif
    );
    return 0;
}
