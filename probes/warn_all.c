/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wall probe (compiler-diag channel). */

#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    /* The observable: a label that is defined and never jumped to. */
chard_wall_dead_label:
    return 0;
}
