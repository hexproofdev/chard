/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wtrampolines probe (compiler-diag channel). */

#pragma GCC diagnostic warning "-Wunused-variable"

/* Defined, not merely declared: chard's build always emits `-o <out> <src>` and
 * never `-c`, so an undefined callee would fail to link in every arm. */
static int chard_apply(int (*fn)(int), int x)
{
    return fn(x);
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    volatile int bias = 1;

    /* The observable: a nested function that captures `bias`, whose address is then taken. */
    int chard_nested(int v)
    {
        return v + bias;
    }

    return chard_apply(chard_nested, -1);
}
