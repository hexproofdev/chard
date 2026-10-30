/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wconversion probe (compiler-diag channel).
 *
 * The observable is a value-changing narrowing conversion, int -> char.
 *
 * The source value is `volatile` so the compiler cannot prove the conversion
 * safe and skip the warning. A literal 300 would let both compilers reason about
 * the value range; a volatile load forces the diagnostic on the declared types,
 * which is what the flag is actually about.
 *
 * The diagnostic is read from the message text. gcc says "conversion from 'int'
 * to 'char' may change value" and clang says "implicit conversion loses integer
 * precision"; the detector accepts either. The bracketed option name is not
 * matched: -Werror rewrites it and -fno-diagnostics-show-option removes it. The
 * chosen substrings carry no quote characters, because gcc quotes with
 * U+2018/U+2019 under a UTF-8 locale and ASCII apostrophes under LC_ALL=C.
 *
 * A containment relationship the report must carry: on both compilers
 * -Wconversion enables -Wsign-conversion for C, so a profile passing only
 * -Wconversion lights the sibling sign-conversion cell too. The reverse does not
 * hold. The sibling therefore adds signal only for -Wsign-conversion-only
 * profiles, and the two cells must not be read as independent evidence.
 *
 * This probe carries one observable; the sign-changing case lives in
 * warn_sign_conversion.c. Sharing a translation unit let a -Werror profile raise
 * one diagnostic as an error and mask the other, which reported indeterminate
 * where the truth was absent.
 *
 * No libc header is included. Nothing here needs one, and a header's own contents
 * can add or suppress diagnostics under a fortifying profile.
 *
 * The unused variable and the in-source pragma are the canary for the diagnostic
 * channel itself; see warn_all.c. Measured here: `gcc -Werror` and `clang -Werror`
 * both still print the canary as a warning and still exit 0, so it can never break
 * a build, and it is a different warning from the observable, so the flag under
 * test cannot turn the canary into a false hit.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

static volatile int chard_wide = 300;

/* The observable: a value-changing narrowing conversion, int -> char. */
static char chard_narrow(void)
{
    char c = chard_wide;
    return c;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_narrow() == 0 ? 1 : 0;
}
