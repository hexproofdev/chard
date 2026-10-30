/* SPDX-License-Identifier: BSD-3-Clause */

/* RETGUARD probe for the `elf-static` channel, read as an object file.
 *
 * OpenBSD's clang (`-fret-protector`) gives each function it protects a cookie of its
 * own: a hidden weak `__retguard_<n>` object in a COMDAT section named
 * `.openbsd.randomdata.retguard.<n>`, loaded at entry and checked before `ret`. The
 * observable is that section's name in the object the compiler produced.
 *
 * Compiled and not linked, deliberately. OpenBSD's startup objects carry cookies of their
 * own, so a linked program holds some under `-fno-ret-protector` as well, and presence in
 * a linked program cannot separate the arms. An object holds only what the compiler made
 * of this file, so the baseline is excluded by construction rather than by a threshold.
 *
 * Three functions: one with a local array, one leaf that touches no stack, and `main`.
 * `noinline` keeps the optimizer from folding the helpers into `main`. The measurement
 * that licenses the reading is on `predicate::elf_static`'s RET_PROTECTOR.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

__attribute__((noinline)) int with_array(int x)
{
    volatile char buf[16];
    buf[0] = (char) x;
    return buf[0] + 1;
}

__attribute__((noinline)) int leaf(int x)
{
    return x * 3;
}

int main(int argc, char **argv)
{
    (void) argv;
    return with_array(argc) + leaf(argc) + (chard_report[0] == 0);
}
