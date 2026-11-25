/* SPDX-License-Identifier: BSD-3-Clause */

/* -Werror=incompatible-pointer-types probe (compiler-diag channel). */

/* A real object, so the pointer that is assigned points somewhere valid. */
static char chard_bytes[sizeof(int)];

/* Defined, not merely declared: see the header comment. */
static int chard_sink(const int *p)
{
    return p != (const int *) 0;
}

#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    char *bytes = chard_bytes;
    int *words = (int *) 0;

    /* The observable: assignment between incompatible pointer types, no cast. */
    words = bytes;

    return chard_sink(words) - 1;
}

