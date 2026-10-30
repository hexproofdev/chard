/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wformat probe (compiler-diag channel).
 *
 * The observable is an argument whose type does not match its conversion, the
 * level-1 -Wformat diagnostic. This reads presence, not severity: the sibling
 * check format-security-is-error reads the severity of a different construct.
 *
 * The diagnostic is read from the message text, never from the bracketed option
 * name. gcc says "expects argument of type" and clang says "format specifies
 * type"; the detector accepts either. Matching the bracket would be wrong in two
 * measured ways: -Werror rewrites it (gcc to [-Werror=format=], clang to
 * [-Werror,-Wformat]) and -fno-diagnostics-show-option removes it. The chosen
 * substrings carry no quote characters, because gcc quotes with U+2018/U+2019
 * under a UTF-8 locale and ASCII apostrophes under LC_ALL=C.
 *
 * A confound this check cannot remove, and which the report must carry: on clang
 * -Wformat is on by *default*, and on gcc it is implied by -Wall. So a `present`
 * here is weak evidence that the profile asked for -Wformat specifically; it is
 * strong evidence only of the property, which is what chard reports. The negative
 * control (-Wno-format) is what keeps the check honest: it demonstrates the
 * detector can still see the flag turned off.
 *
 * No libc header, and the format function is the probe's own: glibc's fortify
 * headers redeclare printf under clang without a format attribute and silently
 * disable -Wformat checking whenever _FORTIFY_SOURCE >= 2. A probe that called
 * the real printf would report this absent on any clang build that fortifies, a
 * false negative caused entirely by the probe's own choice of callee.
 *
 * The function is *defined*, not merely declared: chard builds with
 * `cc <flags> -o <out> <src>` and never -c, so a bodiless declaration would fail
 * to link in every arm and the control triple would measure nothing.
 *
 * The unused variable and the in-source pragma are a canary for the diagnostic
 * channel itself; see warn_all.c for the full rationale. -Wunused-variable is a
 * distinct group from every -Wformat group, so it can never be mistaken for the
 * observable, and the pragma pins it to warning severity so it cannot break a
 * build under -Werror.
 */

/* Not <stdio.h>: see the header comment. */
__attribute__((format(printf, 1, 2))) void chard_fmt(const char *fmt, ...);

void chard_fmt(const char *fmt, ...)
{
    (void) fmt;
}

#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    /* The observable: the argument type does not match the conversion.
     * chard_fmt never reads its varargs, so nothing here is undefined. */
    chard_fmt("%d", (long long) 1);

    return 0;
}
