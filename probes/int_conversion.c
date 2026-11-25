/* SPDX-License-Identifier: BSD-3-Clause */

/* -Werror=int-conversion probe (compiler-diag channel). */

#pragma GCC diagnostic warning "-Wunused-variable"

/* Not a constant expression, so its value is not a null pointer constant. */
static int chard_int_source(void)
{
    return 0;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    /* The observable: integer -> pointer with no cast. */
    int *chard_target = chard_int_source();

    return chard_target != (int *) 0;
}

