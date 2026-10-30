/* SPDX-License-Identifier: BSD-3-Clause */

/* --param ssp-buffer-size probe (elf-static channel).
 *
 * `stack_canary.c` beside this one asks whether the stack protector is emitted at
 * all, using a 64-byte array that every mode covers. This asks something the mode
 * name does not answer: **how much** it covers.
 *
 * `-fstack-protector` instruments a function only when it holds a character array of
 * at least `ssp-buffer-size` bytes, which upstream sets to 8. So a function with a
 * 4-byte array is unprotected under plain `-fstack-protector` and protected under
 * either `-fstack-protector-strong`, whose heuristic covers any array regardless of
 * size, or a lowered threshold.
 *
 * Two things make that worth measuring separately from `ssp-level`. A distribution
 * can lower the threshold without changing the mode (Alpine patches it from 8 to 4)
 * and that is invisible in a report saying `ssp-level: strong`, which is true and
 * understates it. And the mode name is a claim about the compiler's configuration
 * while this is a claim about the artifact: a 4-byte array either got a canary or it
 * did not.
 *
 * ## The observable
 *
 * A reference to `__stack_chk_fail`, exactly as the sibling probe reads it, but from
 * a translation unit whose only candidate is small enough to fall below the default
 * threshold. Absence here is not absence of the stack protector; it is the protector
 * declining to cover this function, which is the whole question.
 *
 * ## Why the array is used rather than merely declared
 *
 * An untouched local is removed before the instrumentation decision is made, and the
 * function would then be uninstrumented for a reason unrelated to the threshold. The
 * array is filled through `scanf` and read back so it must live on the stack and must
 * be a genuine candidate.
 *
 * Measured on gcc 16 and clang 22: no canary under `-fstack-protector`, a canary
 * under `-fstack-protector --param ssp-buffer-size=4`, and a canary under
 * `-fstack-protector-strong`.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/* Four bytes: below the default threshold of eight, above nothing. */
__attribute__((noinline)) static void small_array(void) {
    char buf[4];
    if (scanf("%3s", buf) == 1) {
        printf("%s", buf);
    }
}

int main(void) {
    small_array();
    return 0;
}
