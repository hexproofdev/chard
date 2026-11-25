/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wformat=2 probe (compiler-diag channel). */

/* Not <stdio.h>: see the header comment. */
__attribute__((format(printf, 1, 2))) void chard_fmt(const char *fmt, ...);

void chard_fmt(const char *fmt, ...)
{
    (void) fmt;
}

#pragma GCC diagnostic warning "-Wunused-variable"

static const char *chard_pick(void)
{
    static const char *s = "%s";
    return s;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    /* The observable: a non-literal format that does have a format argument, so
     * it is not the -Wformat-security shape. */
    chard_fmt(chard_pick(), "x");

    return 0;
}
