/* SPDX-License-Identifier: BSD-3-Clause */

/* UBSan trap mode, read from the code of four functions in the object the compiler
 * produced.
 *
 * Under `-fsanitize=undefined` the compiler guards each construct the sanitizer checks,
 * and a failed guard either calls the runtime (`__ubsan_handle_*`, handler mode) or
 * executes a trap instruction (`-fsanitize-trap=undefined`, trap mode). The observable is
 * that trap's encoding inside `chard_ubsan_trap_probe`, `chard_ubsan_trap_groups`,
 * `chard_ubsan_trap_sized` and `chard_ubsan_trap_indirect`, which `elf::code` searches
 * for: `ud2` from gcc and `ud1` from clang on x86_64, `brk` from both on aarch64.
 *
 * The first function loads an element of an array through a pointer, shifts it and adds
 * to it, which the sanitizer checks (`null`, `alignment`, `bounds`, `pointer-overflow`,
 * `shift`, `signed-integer-overflow`), and calls nothing and holds no constant but the
 * array's bound, so nothing else in its bytes comes from the source. The array is not the
 * structure's last member, so neither compiler reads it as a flexible array whose bound is
 * unknown.
 *
 * The second holds a construct for every other group gcc 16.1.1 and clang 22.1.8 accept
 * in trap mode for C and instrument without a call or a local array: an unsigned division
 * (`integer-divide-by-zero`), a pointer to a variably modified type, which checks its
 * bound and allocates nothing (`vla-bound`), `__builtin_unreachable` (`unreachable`),
 * `__builtin_ctz` (`builtin`), a load of a `_Bool` (`bool`), a float division converted
 * to `int` (`float-divide-by-zero`, `float-cast-overflow`), an always-inline callee with
 * a `nonnull` parameter and one that is `returns_nonnull` (`nonnull-attribute`,
 * `returns-nonnull-attribute`), clang's `_Nonnull` on both and on a
 * local (`nullability-arg`, `-return`, `-assign`), implicit narrowing and sign changes and
 * a store to a bit-field (clang's `implicit-conversion` groups), and an unsigned
 * subtraction and shift (clang's `unsigned-integer-overflow` and `unsigned-shift-base`).
 * Neither holds a signed subtraction, multiplication or negation, which clang's `-ftrapv`
 * compiles to a trap with a nonzero check number, and the bit-field is stored through a
 * pointer rather than into a local: at -O0 a local structure under
 * `-ftrivial-auto-var-init` is a `memset` call (clang 22.1.8) and, beside
 * `-fstack-protector-strong`, a canary call (gcc 16.1.1), either of which the predicate
 * reads as a call the source does not make. The second function holds
 * constants the first does not (a bit-field's mask, the float limits clang loads), so the
 * first's argument for its bytes does not carry over; the measurement that no trap or call
 * the reader matches in it is one the compiler did not emit is at its `elf::code::SCANS`
 * entry.
 *
 * The third and fourth hold the two constructs that need an object the compiler can size
 * or a call the source makes, which the first two exclude.
 * `chard_ubsan_trap_sized` indexes a global array of known size through a pointer to its
 * element type, `((int *)cells)[i]`: gcc 16.1.1 checks it under `object-size` (at -O0 and
 * -O2; clang 22.1.8 folds its own `object-size` check away on every access that is not a
 * provable fault, and drops the group at -O0), and clang checks it under `local-bounds`,
 * whose default is to trap and which `-fno-sanitize-trap=local-bounds` turns into a call
 * to `__ubsan_handle_local_out_of_bounds`. Neither compiler's `bounds` checks it, and
 * that is the cast's purpose: `bounds` reads the array type from the expression and a
 * cast to the element pointer hides it, while `local-bounds`
 * and gcc's `object-size` size the object itself and see through the cast. As a plain
 * `cells[i]` the access is checked by `bounds` as well, and under
 * `-fsanitize=bounds,local-bounds -fsanitize-trap=bounds -fno-sanitize-trap=local-bounds`
 * at -O2 clang folds the `local-bounds` handler call away under the dominating `bounds`
 * trap, so a build with a group in handler mode reads `on`; the first function's
 * `row->cell[i]` is where `bounds` has its construct. A global rather than a
 * local array, since a local one is a canary call under `-fstack-protector-strong` and a
 * `memset` under `-ftrivial-auto-var-init` at -O0, and a global is a relocation whose
 * field is zero in an object. `chard_ubsan_trap_indirect` calls through a function
 * pointer, which clang checks under `function` (trap `ud1` with check number 6, handler
 * `__ubsan_handle_function_type_mismatch`); gcc has no such group and refuses the flag.
 * The call is through a register, which the reader does not search those functions for.
 * Each is searched for a narrower list than the second function (`elf::code::SCANS` has
 * why: gcc's `object-size` check can encode a relocated immediate as `e8 00 00 00 00`,
 * and clang's `-fsanitize=kcfi` puts a `ud2` of its own in a function that calls through
 * a pointer). The groups left without a construct, and why each is, are on
 * `predicate::elf_static`'s `UBSAN_TRAP`: `enum` and `return`, which neither compiler
 * instruments in C, and clang's `object-size`.
 *
 * `chard_ubsan_trap_feature` is defined where the compiler says an undefined-behavior
 * sanitizer group is enabled (`__has_feature(undefined_behavior_sanitizer)`, which gcc
 * 16.1.1 and clang 22.1.8 both answer for the groups `-fsanitize=undefined` names, and
 * which clang 22.1.8 does not answer for `local-bounds`), so a build that enables a group
 * no function exercises is not read as one with no sanitizer. A gcc that answers no
 * `__has_feature` (13.3.0) never defines this symbol, and such a build's object is the
 * flagless object byte for byte; there `report::sanitizer_group_limitation` withholds the
 * `off` from the driver's own listing of the compile's sanitizer words (the measurement is
 * on that function).
 *
 * Why a byte search over the four functions is sound is in `elf::code`'s module
 * documentation. Their names are listed in `elf::code::SCANS`, with gcc's `.cold` part of
 * each, and renaming one here without there leaves it unsearched, which the predicate
 * reads as `indeterminate` and the triple as `probe-invalid`.
 *
 * Compiled and not linked: in an object every reference to another symbol is a
 * relocation whose field is zero until the link, so no address contributes bytes, and
 * gcc's handler-mode arm needs no libubsan to build.
 *
 * `<stdio.h>` comes first because the self-report header must follow a libc header.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

#if defined(__has_feature)
#if __has_feature(undefined_behavior_sanitizer)
const char chard_ubsan_trap_feature = 1;
#endif
#endif

#if defined(__clang__)
#define CHARD_UBSAN_TRAP_NONNULL _Nonnull
#else
#define CHARD_UBSAN_TRAP_NONNULL
#endif

/* The implicit conversions below are constructs, not mistakes, so a profile's
 * -Wconversion has nothing to say about them. */
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wfloat-conversion"

struct chard_ubsan_trap_row {
    int cell[4];
    int after;
};

int chard_ubsan_trap_probe(const struct chard_ubsan_trap_row *row, int i, int shift)
{
    return (row->cell[i] << shift) + i;
}

struct chard_ubsan_trap_bits {
    unsigned int low : 3;
};

static inline __attribute__((always_inline, nonnull(1))) int
chard_ubsan_trap_nonnull(const int *CHARD_UBSAN_TRAP_NONNULL p)
{
    return *p;
}

static inline __attribute__((always_inline, returns_nonnull)) const int *CHARD_UBSAN_TRAP_NONNULL
chard_ubsan_trap_returns(const int *p)
{
    return p;
}

unsigned int chard_ubsan_trap_groups(unsigned int u, unsigned int v, int n, const int *p,
                                     const _Bool *flag, struct chard_ubsan_trap_bits *bits,
                                     float f, float g)
{
    const int (*rows)[n] = (const int (*)[n])chard_ubsan_trap_returns(p);
    const int *CHARD_UBSAN_TRAP_NONNULL q = p;
    unsigned char narrow = n;
    unsigned char unarrow = u;
    signed char snarrow = u;
    int whole = f / g;
    if (u == v)
        __builtin_unreachable();
    bits->low = u;
    return (u / v) ^ (u - v) ^ (u << v) ^ narrow ^ unarrow ^ snarrow ^ bits->low ^ whole
           ^ __builtin_ctz(u) ^ *flag ^ chard_ubsan_trap_nonnull(q) ^ (*rows)[0];
}

int chard_ubsan_trap_cells[4];

int chard_ubsan_trap_sized(int i)
{
    return ((int *)chard_ubsan_trap_cells)[i];
}

int chard_ubsan_trap_indirect(int (*fn)(int), int x)
{
    return fn(x);
}
