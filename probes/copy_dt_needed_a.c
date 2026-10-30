/* SPDX-License-Identifier: BSD-3-Clause */

/* The near end of the chain: built as `libchard_dt_a.so`, linked against
 * `libchard_dt_b.so`, and the only library the probe names.
 *
 * It calls into B so that B is a genuine dependency recorded in A's DT_NEEDED
 * rather than one `--as-needed` would drop, the mistake that would leave both
 * control arms of the check identical and the flag unmeasurable.
 */

extern int chard_dt_bfunc(void);

int chard_dt_afunc(void)
{
    return chard_dt_bfunc() + 1;
}
