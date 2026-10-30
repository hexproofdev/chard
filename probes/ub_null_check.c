/* SPDX-License-Identifier: BSD-3-Clause */

/* -fno-delete-null-pointer-checks probe (runtime channel).
 *
 * The shape has a kernel CVE behind it. CVE-2009-1897 in the tun driver was a
 * dereference followed by a null check: `struct sock *sk = tun->sk;` and then, later,
 * `if (!tun) return;`. The compiler reasoned that dereferencing `tun` proved it
 * non-null, deleted the check as dead, and turned a defensive test into a null
 * dereference at address 0, which on a kernel with a mappable zero page is a
 * privilege escalation rather than a crash.
 *
 * The code was wrong; the point is that the *check the author wrote* is the thing
 * that disappeared, and nothing in the build output said so.
 *
 * ## The shape
 *
 * A dereference whose result is unused, followed by a null check. The load is dead
 * and gets removed either way. What differs is whether the compiler keeps the
 * *inference the load licensed* (that the pointer cannot be null) and uses it to
 * delete the check. With the check deleted, `check_survives(NULL)` reaches the tail
 * and returns 1; with it kept, it returns 0.
 *
 * Note what does not happen: nothing faults. The load is eliminated in both arms, so
 * the probe distinguishes the two outcomes by its answer rather than by dying. That
 * is deliberate, a probe that segfaults in one arm and not the other is measuring
 * the manner of death, and the manner of death here is a property of whether the zero
 * page happens to be mapped.
 *
 * ## Why the pointer is opaque
 *
 * `opaque` is `volatile` so the compiler cannot see that the argument is a null
 * literal, which makes the observable a property of the flag rather than of what the
 * caller happens to show the optimizer.
 *
 * The paragraph that stood here claimed that with the pointer opaque "both compilers
 * delete the check and both restore it under `-fno-delete-null-pointer-checks`", and
 * said it had been measured. It is not true of clang 22.1.8, which prints
 * `null-check=kept` under BOTH arms, so the controls do not discriminate and there is
 * no verdict to be had, and `probe-invalid` is what a clang run reports. Measured,
 * this time:
 *
 *   gcc 16.1.1    -fdelete-null-pointer-checks     null-check=deleted
 *   gcc 16.1.1    -fno-delete-null-pointer-checks  null-check=kept
 *   clang 22.1.8  -fdelete-null-pointer-checks     null-check=kept
 *   clang 22.1.8  -fno-delete-null-pointer-checks  null-check=kept
 *
 * ## This probe needs optimization to run at all
 *
 * Without it the dead load is not eliminated, so the dereference of a null pointer
 * actually executes and the probe dies on SIGSEGV. That is why every control arm here
 * carries its own `-O2`: measured under a profile with no optimization, this check
 * reports `run-failed`, which is the honest answer, the question cannot be put to a
 * build the optimizer never touched.
 */

#include <stdio.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/* Opaque to the optimizer: it must not see that this is a null literal. */
static int *volatile opaque = (int *)0;

__attribute__((noinline)) static int check_survives(int *p) {
    /* Dead load. Removed either way, but it licenses the inference `p != NULL`. */
    int unused = *p;
    (void)unused;
    /* Deleted when that inference is kept. */
    if (!p) {
        return 0;
    }
    return 1;
}

int main(void) {
    int *p = opaque;
    CHARD_NOT_DUMPABLE;
    if (check_survives(p)) {
        printf("null-check=deleted\n");
    } else {
        printf("null-check=kept\n");
    }
    return 0;
}
