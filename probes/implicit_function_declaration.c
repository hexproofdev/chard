/* SPDX-License-Identifier: BSD-3-Clause */

/* compiler-diag channel probe: is calling an undeclared function an error? */

#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_probe_target() != 0;
}

int chard_probe_target(void)
{
    return 0;
}
