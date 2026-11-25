/* SPDX-License-Identifier: BSD-3-Clause */

/*The near end of the chain: built as `libchard_dt_a.so`, linked against `libchard_dt_b.so`, and the
 *only library the probe names. */

extern int chard_dt_bfunc(void);

int chard_dt_afunc(void)
{
    return chard_dt_bfunc() + 1;
}
