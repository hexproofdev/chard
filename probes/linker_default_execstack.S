/* SPDX-License-Identifier: BSD-3-Clause */

/* Linker default for an unmarked object (elf-static channel).
 *
 * The only assembly probe in this corpus, and it has to be, because what it measures is
 * a decision the linker makes **when an input object says nothing**.
 *
 * A C translation unit is not usable here. gcc emits a `.note.GNU-stack` section into
 * every object it produces, and that note is precisely what the linker consults, so a
 * C probe can only ever measure what gcc asked for. Getting an object without the note
 * means writing the object by hand.
 *
 * ## What this distinguishes
 *
 * The stack is executable if *any* linked input requires it, and an input carrying no
 * `.note.GNU-stack` has historically been treated as requiring it, the conservative
 * reading, on the assumption that a hand-written object might contain a trampoline.
 * One unmarked object therefore makes the whole binary's stack executable, silently.
 *
 * binutils configured with `--enable-default-execstack=no` reverses that default: an
 * unmarked input is assumed not to need an executable stack. Gentoo turns this on
 * through `sys-devel/binutils[hardened]`, and it is the only compiler-visible effect of
 * that USE flag.
 *
 * Measured on Gentoo 23.0, same autobuild, both profiles, from this exact source:
 *
 *   binutils[hardened]   ->  GNU_STACK RW    (unmarked input assumed safe)
 *   binutils (stock)     ->  GNU_STACK RWE   (unmarked input makes the stack executable)
 *
 * ## Why the flag under test is the linker's default rather than a flag
 *
 * `-Wl,-z,noexecstack` and `-Wl,-z,execstack` both override this decision entirely,
 * which makes them exactly the right control arms (they prove the detector can see
 * both states on this toolchain) while the measured build, carrying neither, reveals
 * which way the linker leans when nobody tells it.
 *
 * ## Scope
 *
 * x86_64 only, and gated as such. The property is portable but this `main` is not, and a
 * probe that assembles on one architecture and silently fails elsewhere would report a
 * build failure as a measurement.
 *
 * x86 (i386) is gated in as well: the two instructions assemble unchanged for i386, and
 * both control arms discriminated there; the gate in `src/probe.rs` carries the
 * measurement.
 */

    .text
    .globl main
    .type main, @function
main:
    xorl %eax, %eax
    ret
    .size main, .-main

/* Deliberately no `.note.GNU-stack` section. Its absence is the whole probe: adding one
 * here (as gcc does for every C object) would answer the question before the linker
 * was asked. */
