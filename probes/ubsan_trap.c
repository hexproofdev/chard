/* SPDX-License-Identifier: BSD-3-Clause */

/* UBSan trap mode, read from the code of four functions in the object the compiler produced. */

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
