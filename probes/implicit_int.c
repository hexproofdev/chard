/* SPDX-License-Identifier: BSD-3-Clause */

/* compiler-diag channel probe: is a declaration with no type specifier an error?
 *
 * This is the *implicit-int* half of the guide's `-Werror=implicit` (Table 1,
 * "treat obsolete C constructs as errors"). The other half (calling a function
 * before it is declared) is already measured by the
 * implicit-function-declaration probe. The two are separately controllable
 * (`-Wimplicit-int` vs `-Wimplicit-function-declaration`) and flipped to errors in
 * different compiler releases, so they are measured separately: a toolchain can
 * stop on one and wave the other through.
 *
 * The observable is the compiler's own *severity* on `static x = 0;`. Both control
 * arms emit the same sentence and differ only in whether it is an error, exactly as
 * in the format-security probe, so the detector reads severity and not the mere
 * presence of text. The cell therefore says "an untyped declaration stops this
 * build", which is the property that matters and is also produced by the compiler's
 * own default on gcc >= 14 and clang >= 15.
 *
 * Two deliberate choices, both established by measurement:
 *
 *   - The untyped object is *used* by main. chard's build always emits
 *     `-o <out> <src>` and never `-c`, so the arm in which the diagnostic is only a
 *     warning must still link; and using it also keeps it from drawing an unused-
 *     variable warning of its own, which would collide with the canary below.
 *
 *   - No libc header is included. Nothing here needs one, and a header is a second
 *     source of diagnostics that a fortifying profile can change out from under the
 *     probe.
 *
 * The unused variable and the in-source pragma below are a canary for the
 * diagnostic channel itself. `-w` and `-fdiagnostics-format=sarif-file` both empty
 * stderr (measured here on gcc 16.1.1 and clang 22.1.8) and neither is
 * countermanded by the control flags, so a silent stderr could otherwise be read as
 * "the flag is off" when in truth nothing was listening. If neither the implicit-int
 * wording nor the canary appears, the detector reports indeterminate rather than
 * absent. `-Wunused-variable` is chosen because it is not escalated by `-Werror`, so
 * the canary can never break a build, and because both compilers print the
 * controlling option in brackets (`[-Wunused-variable]` for the canary,
 * `[-Wimplicit-int]` for the observable), so the two can never be confused.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

/* The observable: a declaration that specifies no type. */
static chard_implicit_int_value = 0;

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_implicit_int_value;
}
