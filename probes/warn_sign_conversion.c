/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wsign-conversion probe (compiler-diag channel). */

#pragma GCC diagnostic warning "-Wunused-variable"

static volatile int chard_negative = -1;

/* The observable: a sign-changing conversion, int -> unsigned int. */
static unsigned int chard_unsign(void)
{
    unsigned int u = chard_negative;
    return u;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_unsign() == 0u ? 1 : 0;
}
