/* SPDX-License-Identifier: BSD-3-Clause */

/* Stack protector level read per function (elf-static channel), from an object file. */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

void ssp_escape(void *);
int ssp_use(int);

/* Admitted by -fstack-protector-all alone: no array, no address taken. */
__attribute__((noinline, used)) int ssp_any(int x)
{
    int a = x * 3;
    int b = a ^ 5;
    return ssp_use(a) + b;
}

/* Admitted by -strong and -all: a scalar whose address escapes. */
__attribute__((noinline, used)) int ssp_addr_taken(int x)
{
    int v = x;
    ssp_escape(&v);
    return v;
}

/* Admitted at every level: a 64-byte character array, above any threshold a
 * distribution is known to set (upstream 8, Alpine 4). */
__attribute__((noinline, used)) int ssp_char_array(int x)
{
    char s[64];
    s[0] = (char) x;
    ssp_escape(s);
    return s[0];
}

/* Admitted at every level, at any ssp-buffer-size: a variable-length alloca. */
__attribute__((noinline, used)) int ssp_alloca(int n)
{
    char *p = __builtin_alloca((unsigned) n);
    p[0] = 1;
    ssp_escape(p);
    return p[0];
}

/*Admitted by -strong and by plain -fstack-protector at the default threshold (a 64-byte character
 *array), and left on the ordinary stack by SafeStack at -O1 and above: every index is masked into
 *range and the array's address never escapes, so SafeStack has no unsafe frame to move it to and
 *places no canary. */
__attribute__((noinline, used)) int ssp_safe_array(int x)
{
    volatile char s[64];
    unsigned i = (unsigned) x & 63u;
    s[i] = (char) x;
    return s[i ^ 1u] + ssp_use(x);
}
