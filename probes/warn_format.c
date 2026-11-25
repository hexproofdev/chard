/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wformat probe (compiler-diag channel). */

/* Not <stdio.h>: see the header comment. */
__attribute__((format(printf, 1, 2))) void chard_fmt(const char *fmt, ...);

void chard_fmt(const char *fmt, ...)
{
    (void) fmt;
}

#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    /* The observable: the argument type does not match the conversion.
     * chard_fmt never reads its varargs, so nothing here is undefined. */
    chard_fmt("%d", (long long) 1);

    return 0;
}
