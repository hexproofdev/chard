/* SPDX-License-Identifier: BSD-3-Clause */

/* The far end of the chain `-Wl,--no-copy-dt-needed-entries` governs.
 *
 * Built as `libchard_dt_b.so` and never named on the probe's own link line. The
 * only route from the probe to this symbol is through `libchard_dt_a.so`'s
 * DT_NEEDED, which is precisely the route the flag decides whether the linker
 * may take. See `copy_dt_needed.c`.
 */

int chard_dt_bfunc(void)
{
    return 7;
}
