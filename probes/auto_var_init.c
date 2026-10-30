/* SPDX-License-Identifier: BSD-3-Clause */

/* -ftrivial-auto-var-init probe (runtime channel).
 *
 * This flag has a documented incident behind it. CVE-2024-12085 in rsync was an
 * uninitialized-stack-memory disclosure (CWE-457) that researchers chained into
 * CVE-2024-12084's buffer overflow to reach remote code execution past ASLR.
 * `-ftrivial-auto-var-init=zero` eliminates the disclosure primitive, which breaks
 * the chain at its first link, so whether a given build actually carries it is a
 * question with a concrete answer attached.
 *
 * The observable is what a freshly-declared local reads back as. That is only sound
 * if the memory underneath it is known to be *non*-zero first: otherwise "it came
 * back zero" cannot distinguish the flag having zeroed it from the storage having
 * been zero all along, and fresh anonymous pages from the kernel are zero.
 *
 * ## Why a dirtying helper does not work
 *
 * A `dirty()` helper that fills its own frame with 0x5A before the observation runs
 * fails on both compilers, and on one of them it looks like it is working:
 *
 *   - On gcc the dirt lands in `dirty()`'s own frame, strictly *below* the
 *     observation frame; the two never overlap. What the negative arm reads is
 *     dynamic-loader and libc-startup residue, measured varying from run to run with
 *     the size of the environment. So the check discriminates for a reason unrelated
 *     to the flag, which is a false control. Where that residue draws three equal
 *     bytes on some image, the detector reports the flag active for a build that
 *     passed no flag at all. A silent false positive is worse than an honest refusal.
 *
 *   - On clang it does not get that far. A plain read of a never-stored automatic is
 *     `undef` in LLVM IR and folds to a constant, so `-O1` and above emit no load
 *     whatsoever: the printf arguments are materialized with `xorl`. No amount of
 *     dirtying changes a value that is never read from memory.
 *
 * ## What the probe does instead, and why each part is load-bearing
 *
 * **One function, called twice.** `frame()` fills on the first pass and observes on
 * the second, so the two frames are identical *by construction* rather than by
 * hoping a callee's frame lands inside its caller's. Pass 1's writes land exactly on
 * pass 2's reads. Nothing may be called between the two passes, a libc call in
 * between clobbers the frame, measured.
 *
 * **Every read goes through a `volatile` lvalue**, which forces the load to be
 * emitted and denies the optimizer the `undef`-folding described above.
 *
 * **`ctrl` is a validity witness.** It carries `__attribute__((uninitialized))`,
 * which both compilers document as opting a variable out of this flag, and it is
 * dirtied and read back like the others, so it must *always* read 0x5A. If it does
 * not, the frame-reuse premise has failed and the run is probe-invalid, detectable
 * from the measured build alone without reference to the controls. Without it the
 * probe has no way to notice that its own premise has stopped holding.
 *
 * ## What the bytes mean
 *
 *   0x5A  the probe's own dirt survived  -> nothing initialized it: flag off
 *   0x00  zeroed                         -> `=zero`
 *   0xFE  gcc's pattern fill             -> `=pattern`
 *   0xAA  clang's pattern fill           -> `=pattern`
 *
 * Verified 30/30 across {gcc 16.1.1, clang 22.1.8} x {-O0,-O1,-O2,-O3,-Os} x
 * {zero, uninitialized, pattern}. The negative arm reads the probe's own
 * marker rather than merely "something different", which is the property that makes
 * it a real control.
 *
 * There is no macro channel for this flag: `cc -dM -E` output is byte-identical with
 * and without it on both compilers.
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
        /* Each loop counter is declared in a block of its own and initialised there, not
         * in the `for`: gcc before 5 defaults to gnu89, which rejects a declaration in the
         * loop, and every arm builds in the profile's own dialect. The block and the
         * initialiser are the scope and the initialiser the C99 loop had, so the frame and
         * the stores -ftrivial-auto-var-init adds are unchanged: objects byte-identical with
         * the C99 spelling on gcc 16.1.1 and clang 22.1.8, -O0 through -Os, measured
         * 2026-10-07 (a counter declared once for all the loops moves the -O0 frame). */
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
