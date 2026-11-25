/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wbidi-chars=any probe (compiler-diag channel). */

#pragma GCC diagnostic warning "-Wunused-variable"

/* The observable, in a comment: ‮desrever si txet siht‬ and here it is not. */

static const char *chard_bidi_literal(void)
{
    /* The observable again, in a string literal. */
    static const char *s = "chard_bidi_‮desrever‬_marker";
    return s;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_bidi_literal()[0] == 0;
}

