/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wextra probe (compiler-diag channel).
 *
 * The observable is a comparison between a signed and an unsigned operand. Both
 * gcc and clang place -Wsign-compare in -Wextra for C, in neither default set,
 * and in neither -Wall, so the check is answerable while -Wall is absent, which
 * is what makes it a -Wextra check rather than a "some warning group is on"
 * check. Note the containment differs by language: in C++ -Wsign-compare is in
 * -Wall, so this probe is C only.
 *
 * Neither group contains the other: -Wall does not imply -Wextra and -Wextra
 * does not imply -Wall, so each of the two checks had to be measured with the
 * other group absent, and both were.
 *
 * This probe carries exactly one observable, and its sibling warn_all.c explains
 * why at length: sharing a translation unit made `-Wall -Werror` raise the other
 * file's diagnostic as an error first, so this cell reported indeterminate on
 * exactly the profiles that harden hardest.
 *
 * Both operands are parameters, so the comparison reaches the front end's warning
 * pass at every optimization level instead of being folded away.
 *
 * The two compilers word the diagnostic differently ("comparison of integer
 * expressions of different signedness" on gcc, "comparison of integers of
 * different signs" on clang) and share the substring "different sign", which is
 * what the detector matches. Matching the message rather than the bracketed
 * option name is deliberate: -Werror rewrites the bracket to [-Werror=sign-compare]
 * on gcc and [-Werror,-Wsign-compare] on clang, and -fno-diagnostics-show-option
 * removes it entirely. The chosen substring carries no quote characters, because
 * gcc quotes with U+2018/U+2019 under a UTF-8 locale and ASCII apostrophes under
 * LC_ALL=C.
 *
 * No libc header is included. Nothing here needs one, and a header's own contents
 * can add or suppress diagnostics under a fortifying profile.
 *
 * The function is *defined*, not merely declared: chard's build is always
 * `cc <flags> -o <out> <src>` and never `-c`, so a bodiless declaration would fail
 * to link in every arm and the control triple would measure nothing.
 *
 * The unused variable and the in-source pragma are the canary for the diagnostic
 * channel itself, see warn_all.c. The canary is -Wunused-variable, a distinct
 * group from the observable, and the pragma pins it to warning severity so it can
 * never break a build.
 */

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
