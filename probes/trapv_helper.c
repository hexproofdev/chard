/* SPDX-License-Identifier: BSD-3-Clause */

/* -ftrapv under gcc, read from the object the compiler produced: the libgcc helpers it
 * calls for signed arithmetic.
 *
 * gcc implements -ftrapv by replacing each signed `int` addition, subtraction and
 * multiplication it cannot prove safe with a call into libgcc: `__addvsi3`, `__subvsi3`,
 * `__mulvsi3`, which compute the result and call `abort()` on overflow. In an object file
 * those calls are undefined symbols, and without the flag there are none. The three
 * functions below take their operands as parameters, so nothing is known about them and
 * nothing can be folded.
 *
 * Each function is marked `used`, which is what keeps it, and so its call, in the object.
 * External linkage alone does not: under gcc's `-fwhole-program` every function in the
 * file becomes local, the file has no `main` to reach them from, and all three were
 * deleted, leaving a `.symtab` holding only the file's own entry. The flag was on and
 * working, the controls discriminated, and the check read a clean `off` (gcc 16.1.1 on
 * Fedora 44 x86_64 and gcc 15.2.0 under musl, 2026-10-02). `used` is honoured by gcc and
 * clang alike and tells both to emit the function whether or not anything calls it.
 *
 * clang implements the same flag inline, as an overflow test and a trap instruction, and
 * references no helper (measured, see `predicate::elf_static`'s TRAPV_HELPER). That is why
 * the check reading this object is gcc's alone and declares clang in its compiler gate:
 * clang's positive control reads absent, which turns into `unsupported` rather than `off`.
 * The `trapv` probe reads the flag on both compilers from the overflow itself.
 *
 * Compiled and not linked: in a linked program the helpers are defined, copied in from
 * libgcc.a, and a stripped link loses them from the symbol table.
 *
 * `<stdio.h>` comes first because the self-report header must follow a libc header.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

__attribute__((used)) int chard_trapv_add(int a, int b)
{
    return a + b;
}

__attribute__((used)) int chard_trapv_sub(int a, int b)
{
    return a - b;
}

__attribute__((used)) int chard_trapv_mul(int a, int b)
{
    return a * b;
}
