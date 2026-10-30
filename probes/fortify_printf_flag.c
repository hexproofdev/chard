/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE's level, read from the code of the object the compiler produced.
 *
 * glibc fortifies `printf` only at level 2 and above, by calling `__printf_chk` (gcc) or
 * `__vprintf_chk` from a local wrapper (clang) with a first argument of
 * `__USE_FORTIFY_LEVEL - 1`: 1 at level 2 and 2 at level 3. That argument is an immediate
 * loaded into the first argument register just before the call, and `elf::code` searches
 * for it: `mov $1,%edi` or `mov $2,%edi` (`push $N` and a later `pop %rdi` at -Oz) on
 * x86_64, `mov w0, #1` or `#2` on aarch64. Level 1 leaves `printf` alone, so the second function is the
 * level-1 witness: a `strcpy` into an array of known size calls `__strcpy_chk` from level
 * 1 up.
 *
 * `chard_fortify_printf_probe` is load-bearing: it passes its own arguments through and
 * holds no constant, so under gcc the only immediate it loads into the first argument
 * register is the flag. clang's wrapper is glibc's code, named by its mangling (listed
 * beside this function in `elf::code::SCANS`); the triple holds it to the same claim on
 * each toolchain. The measurement is on `predicate::elf_static`'s `FORTIFY_PRINTF_FLAG`.
 *
 * Compiled and not linked: `escape` is declared and never defined, so the copy is not
 * dead, and in an object no relocated field contributes bytes to the searched code.
 *
 * `<stdio.h>` comes first because the self-report header must follow a libc header.
 */

#include <stdio.h>
#include <string.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

void escape(void *);

int chard_fortify_printf_probe(const char *fmt, const char *s)
{
    return printf(fmt, s);
}

void chard_fortify_onset_probe(const char *s)
{
    char buf[8];
    strcpy(buf, s);
    escape(buf);
}
