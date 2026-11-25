/* SPDX-License-Identifier: BSD-3-Clause */

/* compiler-diag channel probe: is a declaration with no type specifier an error? */

#pragma GCC diagnostic warning "-Wunused-variable"

/* The observable: a declaration that specifies no type. */
static chard_implicit_int_value = 0;

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_implicit_int_value;
}
