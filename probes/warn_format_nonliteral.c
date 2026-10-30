/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wformat=2 probe (compiler-diag channel).
 *
 * The observable is a non-literal format string that *does* carry format
 * arguments, -Wformat-nonliteral, which is the check GCC's -Wformat=2 adds over
 * plain -Wformat.
 *
 * Passing an argument is deliberate: it keeps this construct out of the
 * -Wformat-security shape (non-literal, *no* arguments) that format_security.c
 * already measures, so the two probes cannot be reading the same diagnostic.
 * Verified, `gcc -Wformat -Wformat-security` and `clang -Wformat-security` raise
 * nothing at all on this call.
 *
 * The guide notes a divergence this check exists to expose: in Clang, -Wformat
 * already includes what GCC calls -Wformat=2, while Clang's -Wformat=2 does *not*
 * include the -Wformat diagnostics. Measuring the effect rather than the token is
 * the only way to report that honestly.
 *
 * The diagnostic is read from the message text, never from the bracketed option
 * name, and the reason is a measured trap. `gcc -Wformat-nonliteral` with no
 * -Wformat emits
 *
 *     cc1: warning: '-Wformat-nonliteral' ignored without '-Wformat'
 *                                                    [-Wformat-nonliteral]
 *
 * which announces the option is *not* in effect while printing its name twice. A
 * bracket match would score that as the flag being on. The message texts are also
 * stable under -Werror, where the brackets are not: gcc rewrites them to
 * [-Werror=format-nonliteral] and clang to [-Werror,-Wformat-nonliteral]. The
 * substrings chosen carry no quote characters either, because gcc quotes with
 * U+2018/U+2019 under a UTF-8 locale and ASCII apostrophes under LC_ALL=C.
 *
 * This probe carries one observable. Its sibling warn_format.c holds the -Wformat
 * type-mismatch case, because sharing a translation unit let `-Wformat -Werror`
 * raise the mismatch as an error first, leaving this cell to report indeterminate
 * where the truth was absent.
 *
 * No libc header, and the format function is the probe's own: glibc's fortify
 * headers redeclare printf under clang without a format attribute and silently
 * disable -Wformat checking whenever _FORTIFY_SOURCE >= 2.
 *
 * The unused variable and the in-source pragma are a canary for the diagnostic
 * channel itself; see warn_all.c.
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

    /* The observable: a non-literal format that does have a format argument, so
     * it is not the -Wformat-security shape. */
    chard_fmt(chard_pick(), "x");

    return 0;
}
