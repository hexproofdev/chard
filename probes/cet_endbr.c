/* SPDX-License-Identifier: BSD-3-Clause */

/* IBT landing-pad probe for the `elf-static` channel, read as an object file.
 *
 * Under -fcf-protection=branch or =full the compiler begins every function an indirect
 * branch may reach with `endbr64` (x86_64) or `endbr32` (i386). The observable is that
 * instruction at the address of each of the three functions below, in the object the
 * compiler produced: `elf::entry` reads their first four bytes through the symbol table.
 *
 * Compiled and not linked, so the object holds what the compiler made of this file and
 * nothing a startup file or the PLT brought in; a linked program carries landing pads of
 * its own from crt1.o on a distribution that builds its C library with CET.
 *
 * Each function is global, `noinline`, and stored in a `volatile` table of function
 * pointers that `main` calls through, so each stays a function of its own at every -O
 * level and is an indirect-branch target the compiler must instrument. A function inlined
 * away has no symbol, and one never address-taken may legitimately carry no landing pad;
 * either would read as a flag that did nothing. The names are the ones
 * `elf::entry::ENTRY_FUNCTIONS` lists, and the measurement that licenses the reading is on
 * `predicate::elf_static`'s CET_ENDBR.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

__attribute__((noinline)) int chard_ibt_target_a(int x)
{
    return x + 1;
}

__attribute__((noinline)) int chard_ibt_target_b(int x)
{
    return x + 2;
}

__attribute__((noinline)) int chard_ibt_target_c(int x)
{
    return x + 3;
}

int (*volatile chard_ibt_table[3])(int) = {
    chard_ibt_target_a,
    chard_ibt_target_b,
    chard_ibt_target_c,
};

int main(void)
{
    int s = 0;
    /* A block-scoped counter, not one declared in the `for`: gnu89 (gcc before 5). */
    {
        int i = 0;
        for (; i < 3; i++)
            s += chard_ibt_table[i](i);
    }
    printf("%d\n", s);
    return chard_report[0] == 0;
}
