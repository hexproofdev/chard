/* SPDX-License-Identifier: BSD-3-Clause */

/* -Werror=incompatible-pointer-types probe (compiler-diag channel).
 *
 * The observable is the compiler's own *severity* on an assignment between two
 * unrelated pointer types with no cast, the loose conversion C89 already required
 * a diagnostic for and that real code still relies on. Error means the build stops;
 * warning means the same sentence was printed and the build succeeded. The cell
 * therefore says "an incompatible pointer assignment stops this build", not "this
 * token appeared on the command line", which is the same property the
 * implicit-function-declaration check reports and is deliberately the more useful
 * one: a blanket `-Werror` earns it just as `-Werror=incompatible-pointer-types`
 * does (measured on both compilers).
 *
 * C only. GCC 8.4 and later warn that `-Werror=incompatible-pointer-types` is not
 * valid for C++ (confirmed here, cc1plus says so verbatim) because the conversion
 * has always been ill-formed in C++. The probe is Lang::C.
 *
 * Two deliberate choices, both established by measurement:
 *
 *   - The assigned pointer is consumed by a *defined* function and points at a real
 *     object. chard's build always emits `-o <out> <src>` and never `-c`, so
 *     anything left undefined fails to link in every arm; the control triple then
 *     reports build-failed everywhere and the check measures nothing.
 *
 *   - No libc header is included. Nothing here needs one, and every header pulled in
 *     is another chance for a profile macro (`_FORTIFY_SOURCE`, `_GNU_SOURCE`) to
 *     change what the front end sees, the failure mode that forced the format
 *     probe to declare its own printf.
 *
 * The unused variable and the in-source pragma below are a canary for the
 * diagnostic channel itself. `-fdiagnostics-format=sarif-file` sends stderr to a
 * file and `-w` suppresses warnings wholesale; neither is countermanded by the
 * control flags, so a silent stderr could otherwise be read as "the flag is off"
 * when in truth nothing was listening. Both were measured here: gcc with
 * `-w -Wno-error=incompatible-pointer-types` exits 0 with *completely empty*
 * stderr, which is indistinguishable from a clean build unless the canary is
 * missed. The pragma is load-bearing, with it deleted and no `-Wall`, neither
 * compiler emits the unused-variable warning at all. `-Wunused-variable` is a
 * different warning group from the observable and both compilers print the
 * controlling group in brackets ([-Wunused-variable] vs
 * [-Wincompatible-pointer-types]), so the two can never be confused in the output.
 *
 * Measured on gcc 16.1.1 and clang 22.1.8, at -O0 and -O2, identically: bare is an
 * error (exit 1), `-Wno-error=incompatible-pointer-types` downgrades it to a
 * warning (exit 0). Both compilers already error by default, so this check reads as
 * a floor on modern toolchains and only reports absent for a build that actively
 * disables it (`-Wno-error=`, `-Wno-incompatible-pointer-types`, and on gcc also
 * `-fpermissive` or `-std=gnu89`).
 */

/* A real object, so the pointer that is assigned points somewhere valid. */
static char chard_bytes[sizeof(int)];

/* Defined, not merely declared: see the header comment. */
static int chard_sink(const int *p)
{
    return p != (const int *) 0;
}

#pragma GCC diagnostic warning "-Wunused-variable"

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    char *bytes = chard_bytes;
    int *words = (int *) 0;

    /* The observable: assignment between incompatible pointer types, no cast. */
    words = bytes;

    return chard_sink(words) - 1;
}

