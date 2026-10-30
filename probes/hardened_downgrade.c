/* SPDX-License-Identifier: BSD-3-Clause */

/* Probe for `-Whardened`: does this toolchain report an option that `-fhardened`
 * wanted to enable and could not?
 *
 * The question is not whether `-fhardened` is on. It is whether the compiler
 * would *tell you* when something silently weakens it. `-fhardened` yields to any
 * explicit `-fno-` on the command line, by design, and a spec file can add
 * `-Wno-hardened` to suppress the complaint that would otherwise be emitted. A
 * toolchain packaged that way builds every `-fhardened` project with hardening
 * quietly removed and says nothing.
 *
 * The source therefore carries nothing but the canary. There is no construct to
 * diagnose here: the diagnostic under test is about the *command line*, not about
 * the code, which is why this probe is a near-empty translation unit rather than
 * a demonstration of some hazard.
 *
 * ## The canary, and why both control arms pass -Wall
 *
 * A compiler-diag check cannot distinguish "the diagnostic did not fire" from
 * "nothing was listening", a build carrying `-w`, or writing diagnostics to a
 * SARIF file, has a silent stderr that looks exactly like a clean result. So this
 * probe declares an unused local that must draw a warning whenever diagnostics
 * are being reported at all, and the shared reader withholds a verdict when
 * neither the primary wording nor the canary appears.
 *
 * An unused variable is only diagnosed under `-Wunused-variable`, which arrives
 * with `-Wall`, so both control arms carry `-Wall`. Without it the canary is
 * silent, the negative arm reads `indeterminate`, and the check reports
 * `probe-invalid` on a toolchain that is working correctly, measured, not
 * supposed.
 */

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return 0;
}
