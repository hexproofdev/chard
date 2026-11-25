/* SPDX-License-Identifier: BSD-3-Clause */

/*Probe for `-Whardened`: does this toolchain report an option that `-fhardened` wanted to enable
 *and could not? */

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return 0;
}
