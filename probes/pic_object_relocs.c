/* SPDX-License-Identifier: BSD-3-Clause */

/* -fPIC against -fPIE, read from the relocation the compiler wrote for one access.
 *
 * Compiled and not linked: the linker relaxes a GOT access to a direct one wherever it
 * can, so a linked program no longer says how the code was generated, and the object
 * does. Under -fPIC an exported global may be preempted by another module's definition,
 * so the compiler reaches `chard_pic_object_anchor` through the GOT
 * (`R_X86_64_REX_GOTPCRELX`, `R_386_GOT32X`, `R_AARCH64_ADR_GOT_PAGE`); under -fPIE an
 * executable's own data cannot be interposed, and without PIC there is no GOT to go
 * through, so the access is direct (`R_X86_64_PC32`, `R_386_GOTOFF`,
 * `R_AARCH64_ADR_PREL_PG_HI21`). `pic-shared-link` asks the same question of the linker,
 * through a `-shared` link of `pic_shared_link.c`.
 *
 * ## Why the global is exported, defined here, 4096 bytes, and externally visible
 *
 * Each property was measured to be load-bearing (2026-10-02; the toolchains are beside
 * the predicate in `predicate::elf_static`):
 *
 *   - Defined in this translation unit and referenced: an undefined global is reached
 *     through the GOT under -fPIE as well by clang on x86_64 and gcc on aarch64, and a
 *     global nothing references has no relocation at all.
 *   - `visibility("default")`: under `-fPIC -fvisibility=hidden` a hidden global is not
 *     preemptible, its access is direct, and the detection recipe measured that reading
 *     as a false -fPIE. The attribute does not hold against every flag: clang's
 *     `-fvisibility-from-dllstorageclass -fvisibility-nodllstorageclass=hidden` overrides
 *     it on ELF and the global is hidden again. The reader records a symbol's visibility
 *     beside its relocation, and the predicate withholds on a hidden anchor.
 *   - 4096 bytes: gcc at -O1 and above on aarch64 reaches a small global through a
 *     section anchor, a relocation against `.data` that names no symbol. The array is
 *     past the anchor offset limit of 4095, so it is addressed by its own name, as in
 *     `pic_shared_link.c`.
 *   - `externally_visible` on gcc: under `-fwhole-program` gcc makes every symbol but
 *     `main` local, and the access becomes a relocation against `.data` again. clang
 *     ignores `-fwhole-program` and does not know the attribute, so it is gcc's alone.
 *
 * A build in which no code relocation names the global, or names it with a type the
 * predicate has not been measured on, reads `indeterminate`, never `off`: a slim LTO
 * object, whose code is bytecode, is that build.
 *
 * `<stdio.h>` comes first because the self-report header must follow a libc header.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

#if defined(__GNUC__) && !defined(__clang__)
#define CHARD_PIC_EXPORTED __attribute__((visibility("default"), externally_visible))
#else
#define CHARD_PIC_EXPORTED __attribute__((visibility("default")))
#endif

CHARD_PIC_EXPORTED int chard_pic_object_anchor[1024] = {7};

int chard_pic_object_probe(int index);

/* The array is indexed by the argument so that the read cannot be folded to a constant. */
CHARD_PIC_EXPORTED int chard_pic_object_probe(int index)
{
    return chard_pic_object_anchor[index & 1023];
}
