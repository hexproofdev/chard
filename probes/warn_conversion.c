/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wconversion probe (compiler-diag channel). */

#pragma GCC diagnostic warning "-Wunused-variable"

static volatile int chard_wide = 300;

/* The observable: a value-changing narrowing conversion, int -> char. */
static char chard_narrow(void)
{
    char c = chard_wide;
    return c;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_narrow() == 0 ? 1 : 0;
}
