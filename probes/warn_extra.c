/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wextra probe (compiler-diag channel). */

#pragma GCC diagnostic warning "-Wunused-variable"

/* The observable: a comparison between a signed and an unsigned operand. */
int chard_extra_signcmp(int signed_side, unsigned unsigned_side);

int chard_extra_signcmp(int signed_side, unsigned unsigned_side)
{
    return signed_side < unsigned_side;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_extra_signcmp(1, 2u) ? 0 : 0;
}
