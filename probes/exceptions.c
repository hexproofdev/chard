/* SPDX-License-Identifier: BSD-3-Clause */

/* -fexceptions in C, read twice from one object file: the macro the compiler defined and
 * the exception table it emitted.
 *
 * In a C translation unit `-fexceptions` defines `__EXCEPTIONS` and makes the compiler
 * emit unwind information that runs a `cleanup` attribute's handler when an exception
 * propagates through the frame, which is how glibc's pthread cancellation unwinds a
 * cancelled thread. The handler is reached through a landing pad, and the landing pad is
 * described in `.gcc_except_table`. No frame with a cleanup, no table: a function with no
 * cleanup region compiles to the same sections under either flag, so
 * `chard_exceptions_probe` below is what makes the table appear, and the positive control
 * arm is what proves it does.
 *
 * The handler calls `printf` because a cleanup with no visible effect, around the same
 * opaque call, produced no table under -fexceptions at -O2 and one at -O0 (gcc 16.1.1 and
 * clang 22.1.8, Fedora 44 x86_64, measured 2026-10-01; `predicate::elf_static`'s
 * EXCEPT_TABLE says the same), and the measured arm runs at whatever -O the profile sets.
 * The callee is declared and never defined, so the call is opaque and may unwind; that is
 * also why the probe is compiled and not linked.
 *
 * `<stdio.h>` comes first for `printf` and because the self-report header must follow a
 * libc header.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

static void chard_cleaner(int *p)
{
    printf("cleanup %d %c\n", *p, chard_report[0]);
}

extern int chard_may_unwind(int);

int chard_exceptions_probe(int x)
{
    int guard __attribute__((cleanup(chard_cleaner))) = x;
    return chard_may_unwind(x);
}
