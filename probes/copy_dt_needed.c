/* SPDX-License-Identifier: BSD-3-Clause */

/* Probe for `-Wl,--no-copy-dt-needed-entries`, a flag in the OpenSSF guide's
 * recommended set.
 *
 * ## The question
 *
 * A link line names `libchard_dt_a.so` and nothing else. `libchard_dt_a.so`
 * records `libchard_dt_b.so` in its own DT_NEEDED. This translation unit calls
 * a function from *B*. May the linker resolve it?
 *
 *   --copy-dt-needed-entries      yes: it follows A's DT_NEEDED into B, the
 *                                 link succeeds, and B is appended to the
 *                                 executable's DT_NEEDED after libc, out of
 *                                 command-line order, because it was never on
 *                                 the command line.
 *   --no-copy-dt-needed-entries   no: `undefined reference to symbol
 *                                 chard_dt_bfunc`, and the link fails.
 *
 * The hardened answer is the refusal. A program that links against libraries it
 * does not name is a program whose dependency set nobody has written down: the
 * transitive library can be swapped, dropped by a packaging change, or satisfy a
 * symbol its author never intended to export.
 *
 * ## Why the observable is a build failure
 *
 * Unusual for this corpus, and unavoidable. The flag's whole effect is to make a
 * link that would otherwise succeed stop; there is no artifact to inspect on the
 * hardened side, because refusing to produce one *is* the hardening. So this is a
 * compiler-diag check reading a failed build, and the detector must distinguish
 * "failed because the flag is in force" from "failed for any other reason". It
 * does that by requiring the linker's own refusal line to name this probe's own
 * transitive symbol rather than treating a non-zero exit as the observable, the
 * same rule `diag_severity_of` applies one channel over.
 *
 * ## Two ways to measure nothing, both recorded in the recipe
 *
 * The linker must be able to *find* B to follow the chain into it. Without
 * `-rpath-link` naming the build directory it cannot, both arms fail with the
 * same message, and a flag working exactly as intended reads as a control that
 * could not discriminate. `Driver::gather` supplies `-L` and `-rpath-link` for
 * any probe with `aux_libs` for this reason.
 *
 * And the arm that is supposed to succeed has to actually succeed. If both arms
 * fail the triple does not discriminate and the check reports `probe-invalid`,
 * which is the honest outcome, but it is worth naming, because "both arms fail
 * identically" and "no difference between the arms" are the same observation
 * from the outside and only one of them means the flag did nothing.
 *
 * ## The finding that motivates measuring rather than asking
 *
 * gcc's driver hard-codes `--no-add-needed`; clang's does not; and GNU ld's own
 * default on binutils 2.46 is already `--no-copy-dt-needed-entries`. So reading
 * the command line and reading the behaviour give different answers, and the
 * effective answer can be the hardened one on a toolchain whose flags never
 * mention it.
 */

extern int chard_dt_afunc(void);
extern int chard_dt_bfunc(void);

/* The pragma pins the canary to a warning, as the other compiler-diag probes' pragmas do
 * (see warn_all.c): it then fires with no -Wall on the line, and under -Werror it stays a
 * warning instead of failing the link this check reads. */
#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary every compiler-diag probe carries: an unused local that must draw a
     * warning if diagnostics are being reported at all.
     *
     * This detector does not read it, and that is worth stating rather than leaving as
     * an omission. The canary exists so silence can be told from absence, and silence is
     * not this check's `absent`, a link that *succeeded* is, which no amount of
     * suppressed stderr can fake. It is here because the invariant is a blanket rule over
     * compiler-diag probes and a blanket rule is worth more than a per-probe judgement,
     * and because a later detector on this probe would want it already present. */
    int chard_canary_unused = 0;

    /* Both calls matter. `chard_dt_afunc` comes from the library actually named,
     * so it resolves either way and keeps the link line honest; `chard_dt_bfunc`
     * is the transitive one, and it is the reference the flag refuses. */
    return chard_dt_afunc() + chard_dt_bfunc();
}
