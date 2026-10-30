/* SPDX-License-Identifier: BSD-3-Clause */

/* -fno-plt, read from the object the compiler produced: how its one external call is
 * relocated.
 *
 * A call to a function the object does not define is a relocation the linker resolves.
 * Compiled the default way it is a direct call the linker routes through a PLT entry
 * (`R_X86_64_PLT32`, `R_386_PLT32` or `R_386_PC32`, `R_AARCH64_CALL26`); under -fno-plt it
 * is an indirect call through the callee's GOT slot (`R_X86_64_GOTPCRELX`, `R_386_GOT32X`,
 * the `R_AARCH64_ADR_GOT_PAGE` and `R_AARCH64_LD64_GOT_LO12_NC` pair, or under gcc's
 * small-model `-fpic` and `-fpie` `R_AARCH64_LD64_GOTPAGE_LO15`). The GOT types are
 * also how code loads the address of external data, so the check reads the relocations
 * that name `chard_no_plt_callee` alone, and this file only ever calls it: it never takes
 * its address, and no other symbol is read.
 *
 * The call is what the reading needs, and the detection recipe measured the hazard of a
 * file without one: no relocation of either kind, which a one-sided test reads as the flag
 * on. `predicate::elf_static`'s PLT_BYPASSED reads that as `indeterminate`, so the caller
 * must keep its call: it adds one to the result, so the call is not a tail call either way
 * (a tail call would be read too, as `R_AARCH64_JUMP26` or a `jmp` through either form),
 * and it is `__attribute__((used))`, so -fwhole-program, which makes every function in a
 * file without `main` local, does not delete it with its call (the reason `trapv_helper.c`
 * gives).
 *
 * Compiled and not linked: a link resolves the relocation, and what remains in the program
 * is a PLT entry or a GOT slot whose origin the object alone records.
 *
 * `<stdio.h>` comes first because the self-report header must follow a libc header.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

extern int chard_no_plt_callee(int);

__attribute__((used)) int chard_no_plt_caller(int x)
{
    return chard_no_plt_callee(x) + 1;
}
