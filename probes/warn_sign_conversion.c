/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wsign-conversion probe (compiler-diag channel).
 *
 * The observable is a sign-changing conversion, int -> unsigned int.
 *
 * The source value is `volatile` so the compiler cannot prove the conversion
 * safe and skip the warning; a literal -1 would let both compilers reason about
 * the value directly.
 *
 * The diagnostic is read from the message text. gcc says "conversion to
 * 'unsigned int' from 'int' may change the sign of the result" and clang says
 * "implicit conversion changes signedness"; the detector accepts either. The
 * bracketed option name is not matched, because -Werror rewrites it and
 * -fno-diagnostics-show-option removes it. The chosen substrings carry no quote
 * characters, because gcc quotes with U+2018/U+2019 under a UTF-8 locale and
 * ASCII apostrophes under LC_ALL=C.
 *
 * This cell is NOT independent of the -Wconversion cell, and the report must say
 * so: on both compilers -Wconversion enables -Wsign-conversion for C, so a
 * profile passing only -Wconversion lights this cell too. This check adds signal
 * only for profiles that pass -Wsign-conversion without -Wconversion. In C++ the
 * relationship differs again, which is one reason this probe is C.
 *
 * This probe carries one observable; the narrowing case lives in
 * warn_conversion.c. Sharing a translation unit let a -Werror profile raise one
 * diagnostic as an error and mask the other, which reported indeterminate where
 * the truth was absent.
 *
 * No libc header is included. Nothing here needs one, and a header's own contents
 * can add or suppress diagnostics under a fortifying profile.
 *
 * The unused variable and the in-source pragma are the canary for the diagnostic
 * channel itself; see warn_all.c.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

static volatile int chard_negative = -1;

/* The observable: a sign-changing conversion, int -> unsigned int. */
static unsigned int chard_unsign(void)
{
    unsigned int u = chard_negative;
    return u;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_unsign() == 0u ? 1 : 0;
}
