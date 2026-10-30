/* SPDX-License-Identifier: BSD-3-Clause */

/* compiler-diag channel probe: is calling an undeclared function an error?
 *
 * This was a warning for thirty years. GCC 14 and Clang 16 promoted it to an
 * error by default, which breaks real builds and is precisely the sort of
 * cross-version delta chard exists to catch, and it leaves no trace whatsoever
 * in a binary, so the compiler's own output is the only possible observable.
 *
 * Verdict comes from the build's exit status: non-zero means the toolchain treats
 * it as an error. The positive control forces
 * -Werror=implicit-function-declaration and the negative control disables the
 * diagnostic, which together prove the probe can distinguish the two on this
 * toolchain rather than merely failing to compile for some unrelated reason.
 *
 * The target function is DEFINED, below its own call site. That is the whole
 * subtlety of this probe. Calling a function that exists nowhere makes the *link*
 * fail whether the diagnostic is an error or a warning, so the exit status stops
 * measuring the diagnostic and starts measuring the undefined reference, and the
 * check then reports "this toolchain treats it as an error" for a toolchain whose
 * own stderr says `warning`. Defining it after the call keeps the call
 * undeclared-at-use (which is what is diagnosed) while leaving the link
 * satisfiable, so the exit status tracks the diagnostic and nothing else.
 *
 * Verified on gcc 16.1.1 and clang 22.1.8: bare is an error (exit 1), and
 * -Wno-error=implicit-function-declaration is a warning with exit 0.
 *
 * The unused variable and the in-source pragma are the diagnostic-channel canary
 * that every compiler-diag probe carries. It is less load-bearing here than
 * elsewhere, and deliberately so: this detector's primary signal is the exit
 * status, which `-w` and `-fdiagnostics-format=sarif-file` do not change, so no
 * verdict depends on the canary today. It is present so the channel's invariant
 * holds uniformly across the corpus, a reader comparing probes should not have to
 * work out which ones can tell silence from absence and which cannot.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    return chard_probe_target() != 0;
}

int chard_probe_target(void)
{
    return 0;
}
