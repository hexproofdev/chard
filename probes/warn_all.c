/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wall probe (compiler-diag channel).
 *
 * The observable is an unused label. Both gcc and clang place -Wunused-label in
 * -Wall, in neither default set, and in neither -Wextra, so the check is
 * answerable while -Wextra is absent, which is what makes it a -Wall check and
 * not a "some warning group is on" check.
 *
 * Three observables that suggest themselves first were measured and rejected:
 *
 *   - -Wreturn-type, -Wparentheses and -Wempty-body are all on by *default* in
 *     clang 22, so a clang negative control emits them just as the positive one
 *     does and the check reports probe-invalid on every clang profile.
 *
 *   - -Wunused-parameter is not enabled by a bare -Wextra on gcc, whose manual
 *     qualifies it "only with -Wunused or -Wall". The two toolchains would
 *     disagree about what the probe even measures.
 *
 *   - -Wunused-function is a *deferred* diagnostic: clang emits it while
 *     finishing the translation unit and skips that pass entirely once any error
 *     has been raised. Under `-Wall -Werror` the line never appears, so -Wall
 *     would read absent on exactly the profiles that enable it hardest.
 *     -Wunused-label is raised when its scope closes and survives that, measured
 *     on both compilers.
 *
 * This probe carries exactly one observable. Paired with the -Wextra check in a
 * single translation unit, it fails in a way that only shows up on hardened
 * profiles: under `-Wall -Werror` gcc raises the unused-label diagnostic as an
 * *error* and never reaches the sign-compare, so the -Wextra cell sees no
 * observable, a live canary and a failed build, and reports indeterminate where
 * the truth is plainly absent. One observable per translation unit prevents that,
 * and is the reason the file is this small.
 *
 * The label carries a deliberately distinctive name. The compilers word the
 * sentence differently ("label 'chard_wall_dead_label' defined but not used" on
 * gcc, "unused label 'chard_wall_dead_label'" on clang), but both quote the
 * identifier, so the identifier is what the detector matches. That also survives
 * -fno-diagnostics-show-option, which strips the bracketed option name, and
 * carries no quote characters of its own: gcc quotes with U+2018/U+2019 under a
 * UTF-8 locale and with ASCII apostrophes under LC_ALL=C.
 *
 * No libc header is included. Nothing here needs one, and a header's own contents
 * can add or suppress diagnostics under a fortifying profile.
 *
 * The unused variable and the in-source pragma are the canary for the diagnostic
 * channel itself. `-w` and `-fdiagnostics-format=sarif-file` empty stderr without
 * countermanding any control flag, so a silent build would otherwise be read as
 * "the flag is off" when in truth nothing was listening. The canary is
 * -Wunused-variable, a distinct group from the observable, and the pragma pins it
 * to warning severity so it can never break a build.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    /* The observable: a label that is defined and never jumped to. */
chard_wall_dead_label:
    return 0;
}
