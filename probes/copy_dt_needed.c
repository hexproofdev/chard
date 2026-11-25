/* SPDX-License-Identifier: BSD-3-Clause */

/* Probe for `-Wl,--no-copy-dt-needed-entries`, a flag in the OpenSSF guide's recommended set. */

extern int chard_dt_afunc(void);
extern int chard_dt_bfunc(void);

/* The pragma pins the canary to a warning, as the other compiler-diag probes' pragmas do
 * (see warn_all.c): it then fires with no -Wall on the line, and under -Werror it stays a
 * warning instead of failing the link this check reads. */
#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /*The canary every compiler-diag probe carries: an unused local that must draw a warning if
     *diagnostics are being reported at all. */
    int chard_canary_unused = 0;

    /* Both calls matter. */
    return chard_dt_afunc() + chard_dt_bfunc();
}
