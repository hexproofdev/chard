/* SPDX-License-Identifier: BSD-3-Clause */

/* -Wtrampolines probe (compiler-diag channel).
 *
 * The observable is a diagnostic on taking the address of a GNU C nested function
 * that captures a variable from its enclosing scope. Capturing is what forces a
 * static chain, and on x86-64 gcc materialises that chain as a trampoline written
 * onto the stack, which is why the guide lists this warning: a build that needs
 * trampolines needs an executable stack, defeating -Wl,-z,noexecstack.
 *
 * GCC-ONLY, and this is a property of the language extension rather than of the
 * warning. Nested functions are a GNU C extension that clang does not implement
 * at all; clang rejects the source outright, so the probe cannot build there and
 * there is no diagnostic to read. The guide itself lists -Wtrampolines in its
 * "when using GCC" conditional table, so a gcc-only cell is the honest shape
 * rather than a shortfall. chard gates the check on the compiler family so clang
 * reports `unsupported` rather than `off`; those are different claims, and
 * reporting the second would read as a distribution's choice.
 *
 * A caveat the report must carry, because it bounds when this cell is readable:
 * the trampoline makes the linker emit
 *
 *     ld.bfd: warning: <object>: requires executable stack
 *
 * on *every* arm, positive and negative alike. That is harmless to the control
 * triple, which reads the compiler's stderr, but a profile carrying
 * -Wl,--fatal-warnings turns it into a link failure, and the cell then reports
 * indeterminate for reasons that have nothing to do with -Wtrampolines. Measured:
 * exit 1, "collect2: error: ld returned 1 exit status".
 *
 * A second caveat: gcc's -ftrampoline-impl=heap moves the trampoline off the
 * stack, and the diagnostic then correctly does not fire. So this cell measures
 * "a stack trampoline in this translation unit is diagnosed", which is the useful
 * property but is not identical to "the -Wtrampolines token was passed".
 *
 * The unused variable and the in-source pragma are the canary for the diagnostic
 * channel itself; see warn_all.c.
 */

#pragma GCC diagnostic warning "-Wunused-variable"

/* Defined, not merely declared: chard's build always emits `-o <out> <src>` and
 * never `-c`, so an undefined callee would fail to link in every arm. */
static int chard_apply(int (*fn)(int), int x)
{
    return fn(x);
}

int main(void)
{
    /* The canary: an unused local that must draw a warning if diagnostics are
     * being reported at all. */
    int chard_canary_unused = 0;

    volatile int bias = 1;

    /* The observable: a nested function that captures `bias`, whose address is
     * then taken. GCC must build a trampoline on the stack to carry the static
     * chain. */
    int chard_nested(int v)
    {
        return v + bias;
    }

    return chard_apply(chard_nested, -1);
}
