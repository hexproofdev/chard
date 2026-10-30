/* SPDX-License-Identifier: BSD-3-Clause */

/* -Werror=int-conversion probe (compiler-diag channel).
 *
 * The observable is the compiler's own *severity* on an implicit conversion from
 * an integer to a pointer with no cast, one of the obsolete C constructs the
 * guide's "treat obsolete C constructs as errors" row is about. Error means the
 * build stops; warning means the same sentence was emitted and the build
 * succeeded.
 *
 * The integer comes from a function call rather than a literal on purpose. A `0`
 * literal is a null pointer constant and converts silently; only a value that is
 * not an integer *constant expression* is diagnosed. The callee is defined, not
 * merely declared, because chard's build always emits `-o <out> <src>` and never
 * `-c`, so an undefined callee would fail to link in every arm and the control
 * triple would measure the link rather than the diagnostic.
 *
 * The construct is deliberately an *initialization of a pointer from an int*, not
 * an assignment between two pointer types: the adjacent
 * -Wincompatible-pointer-types diagnostic must not be what fires. Both compilers
 * print the controlling option in brackets, and the captured text on this box is
 * `[-Wint-conversion]` on gcc and clang alike.
 *
 * The unused variable and the in-source pragma below are a canary for the
 * diagnostic channel itself. `-fdiagnostics-format=sarif-file` sends stderr to a
 * file and `-w` suppresses warnings wholesale, so a silent stderr could otherwise
 * be read as "the flag is off" when in truth nothing was listening. The canary is
 * -Wunused-variable, a distinct option name from the observable's
 * -Wint-conversion, and it is force-enabled by the pragma so it fires regardless
 * of -Wall and is never escalated by -Werror.
 *
 * Measured on gcc 16.1.1 and clang 22.1.8: with no flags at all the construct is
 * already an error (exit 1) on both, so this cell mostly reports a compiler floor
 * rather than a profile's own doing. It still discriminates, because the negative
 * control downgrades it: -Wno-error=int-conversion yields a warning and exit 0 on
 * both compilers at -O0 and -O2. Note that -w does *not* silence it (it stays an
 * error and only the canary disappears) while -Wno-int-conversion removes the
 * diagnostic entirely.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

/* Not a constant expression, so its value is not a null pointer constant. */
static int chard_int_source(void)
{
    return 0;
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    /* The observable: integer -> pointer with no cast. The value is 0, so the
     * pointer is null and is never dereferenced. */
    int *chard_target = chard_int_source();

    return chard_target != (int *) 0;
}

