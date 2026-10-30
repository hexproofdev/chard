/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wimplicit-fallthrough probe (compiler-diag channel).
 *
 * The observable is a switch whose first case runs a statement and then reaches
 * the next case label with no break, no return, and no attribute marking the
 * fall-through as deliberate.
 *
 * The selector is `volatile` so the switch is not folded away before the warning
 * pass runs.
 *
 * There is deliberately NO comment inside the switch. gcc's default level,
 * -Wimplicit-fallthrough=3, accepts a range of comment spellings ("fall through",
 * "FALLTHRU", and others) as suppressing the diagnostic, so a stray explanatory
 * comment next to the fall-through would silence the very thing being measured.
 * The explanation therefore lives up here.
 *
 * The detector matches the message text and NOT the option name, and that
 * distinction is load-bearing rather than stylistic. Measured on clang 22:
 *
 *     $ clang -O2 -Wimplicit-fallthrough=5 ...
 *     warning: unknown warning option '-Wimplicit-fallthrough=5'; did you mean
 *              '-Wimplicit-fallthrough'? [-Wunknown-warning-option]
 *
 * That message contains the substring "implicit-fallthrough" twice while clang
 * has ignored the flag entirely and emitted no fall-through diagnostic at all. A
 * detector keyed on the option name would score it present. The numeric spellings
 * are not hypothetical (`-Wimplicit-fallthrough=3` and `=5` are what the Linux
 * kernel and several distributions actually pass), so this is a false positive on
 * a realistic profile, not a contrived one. The detector matches gcc's "may fall
 * through" or clang's "unannotated fall-through between switch labels" instead.
 *
 * A confound the report must carry: gcc's -Wextra implies -Wimplicit-fallthrough=3,
 * so a profile passing only -Wextra lights this cell on gcc but not on clang.
 *
 * No libc header is included. Nothing here needs one, and a header's own contents
 * can add or suppress diagnostics under a fortifying profile.
 *
 * The unused variable and the in-source pragma are the canary for the diagnostic
 * channel itself; see warn_all.c.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

static volatile int chard_selector = 1;

int chard_sink;

static void chard_switch(void)
{
    switch (chard_selector) {
    case 0:
        chard_sink = 11;
    case 1:
        chard_sink = 22;
        break;
    default:
        chard_sink = 33;
        break;
    }
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    chard_switch();
    return 0;
}
