/* SPDX-License-Identifier: BSD-3-Clause */

/* -Werror=format-security probe (compiler-diag channel).
 *
 * The observable is the compiler's own *severity* on a call that passes a
 * non-literal format string with no format arguments, the shape an attacker
 * controls in a format-string bug. Present means the build stops; absent means the
 * same text was emitted as a warning and the build succeeded. The cell therefore
 * says "a non-literal format string stops this build", not "this token appeared on
 * the command line", which is the same property the implicit-function-declaration
 * check reports and is deliberately the more useful one: `-Wall -Werror` and, on
 * clang, a bare `-Werror` produce it just as `-Werror=format-security` does.
 *
 * Two deliberate choices, both established by measurement:
 *
 *   - The format function is *defined*, not merely declared. chard's build always
 *     emits `-o <out> <src>` and never `-c`, so a declaration with no body fails to
 *     link in every arm, the control triple then reports build-failed everywhere
 *     and the check measures nothing.
 *
 *   - No libc header is included, and the printf-attributed function is the probe's
 *     own. glibc's fortify headers take the `__fortify_use_clang` branch under
 *     clang and redeclare `printf` as an `overloadable` function carrying no format
 *     attribute, which silently disables all `-Wformat` checking of printf whenever
 *     `_FORTIFY_SOURCE >= 2`. A probe that called the real printf would report this
 *     protection absent on any clang build that fortifies, a false negative caused
 *     entirely by the probe's own choice of callee.
 *
 * The unused variable and the in-source pragma below are a canary for the
 * diagnostic channel itself. `-fdiagnostics-format=sarif-file` sends stderr to a
 * file, `-w` suppresses warnings wholesale, and neither is countermanded by the
 * control flags, so a silent stderr could otherwise be read as "the flag is off"
 * when in truth nothing was listening. If the canary warning is missing too, the
 * detector reports indeterminate rather than absent. `-Wunused-variable` is chosen
 * because it is not escalated by `-Werror`, so the canary can never break a build.
 */

/* Not <stdio.h>: see the header comment. */
__attribute__((format(printf, 1, 2))) void chard_fmt(const char *fmt, ...);

void chard_fmt(const char *fmt, ...)
{
    (void) fmt;
}

#pragma GCC diagnostic warning "-Wunused-variable"

static const char *chard_pick(void)
{
    static const char *s = "%s";
    return s;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    /* The observable: a non-literal format with no format arguments. */
    chard_fmt(chard_pick());
    return 0;
}
