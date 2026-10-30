/* SPDX-License-Identifier: BSD-3-Clause */

/* libstdc++ / libc++ precondition-check probe (runtime channel).
 *
 * The OpenSSF guide's TL;DR recommends `-D_GLIBCXX_ASSERTIONS` for libstdc++ and
 * `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST` for libc++. Both turn a
 * standard-library precondition violation from undefined behaviour into a
 * diagnosed abort. Fedora, Rocky, AlmaLinux and Amazon Linux all pass the
 * libstdc++ one in their package build flags, so this is a mitigation
 * distributions actually enable rather than a paper recommendation.
 *
 * Outcome:
 *
 *   assertions on  -> SIGABRT, stderr naming the failed precondition and its
 *                     source location
 *   assertions off -> prints "no-check-fired" and exits 0
 *
 * `operator[]` rather than `at()`: `at()` throws whatever the flags say, so it
 * would report the same result in both arms and the control could not
 * discriminate. `operator[]` is the one whose precondition is unchecked by
 * default, which is exactly what the flag changes.
 *
 * The index and the size are `volatile`-loaded so neither is a compile-time
 * constant. With constants the compiler can see the violation statically and may
 * reject or fold the call, turning a runtime probe into a build failure, the
 * same trap `fortify_known_object.c` documents for `-Wstringop-overflow`.
 *
 * Optimization level is a confound, and a measured one. libstdc++ 16 turns this
 * check on whenever `__OPTIMIZE__` is undefined, and `-U_GLIBCXX_ASSERTIONS` does
 * not suppress it there, at -O0 both control arms abort, and from -O1 upward the
 * flag controls the outcome. The check therefore declares a
 * regime arm (`Regime::Arm`), so the negative arm is re-run under the measured
 * profile's own flags and an unoptimized build yields a withheld verdict rather
 * than a hardening claim it did not earn.
 *
 * A caveat this probe cannot remove: with assertions off, the out-of-range read
 * is undefined behaviour. It happens to survive here, and the "no-check-fired"
 * marker records that it did, but a build where it crashes for an unrelated
 * reason must not be read as "assertions on". That is why the detector requires
 * the abort to carry libstdc++'s or libc++'s own message rather than treating a
 * bare SIGABRT as the observable, a segfault, a canary abort or a fortify abort
 * all die the same way at the level of "the process stopped".
 */

#include <cstdio>
#include <vector>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/* After the standard library headers, so `_CXX_STDLIB` reflects the library that
 * actually provided them. `__GLIBCXX__` and `_LIBCPP_VERSION` are set by including any
 * header from their library, so asking before the includes reports it undefined and
 * the macro check beside it reads nothing. The same ordering the fortify probes
 * document for `_FORTIFY_IMPL`. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

int main()
{
    /* Unbuffer stdout before anything can abort, and outside the `__OPTIMIZE__` arms
     * below because the unoptimized build is the one that needs it.
     *
     * libstdc++ before GCC 12 routes `__glibcxx_assert` through the inline
     * `std::__replacement_assert`, which is `__builtin_printf` -- so the library's own
     * diagnostic goes to *stdout*, which the harness redirects to a file and the C
     * library therefore block-buffers, and glibc's `abort()` has not flushed stdio since
     * 2.27. The message is written into a buffer the abort destroys, and the check sees a
     * bare SIGABRT it is right to refuse to attribute. GCC 12 moved the failure out of
     * line into `__glibcxx_assert_fail`, which writes to stderr, which is where the
     * corpus splits.
     *
     * The marker below already takes the other half of this precaution -- it is on
     * stderr precisely so it survives an abort -- and the reasoning was never applied to
     * the diagnostic the check actually reads. Placed first: an unbuffering that runs
     * after the risky access buys nothing, and one compiled only into the optimized arm
     * buys nothing either, which is what the first attempt at this did.
     *
     * Before GCC 6 g++ defaults to C++98, which has neither `nullptr` nor the brace
     * initialisation below, and the probe did not build on Ubuntu 14.04 and 16.04
     * (measured 2026-10-07). The C++98 spellings are compiled only where the dialect
     * lacks the C++11 ones, so a C++11 build compiles the same tokens as before. */
#if __cplusplus >= 201103L
    std::setvbuf(stdout, nullptr, _IONBF, 0);
#else
    std::setvbuf(stdout, NULL, _IONBF, 0);
#endif
    CHARD_NOT_DUMPABLE;

    /* Report the optimization state from inside the compiled artifact rather than
     * from the flags chard passed. The distinction matters because the library's
     * behaviour keys on `__OPTIMIZE__`, not on the command line, and a spec file or
     * wrapper could set one without the other, the same reason the macro channel
     * reads `.chard.report` instead of `cc -dM -E`.
     *
     * stderr, and before the risky access: it is unbuffered, so the marker survives
     * an abort that would discard buffered stdout. */
#ifdef __OPTIMIZE__
    std::fputs("chard-opt=1\n", stderr);
#else
    std::fputs("chard-opt=0\n", stderr);
#endif
    std::fflush(stderr);

    /* Reference the report from code the linker keeps. `used` keeps `chard_report`
     * through the compiler and not through the linker: under `-Wl,--gc-sections` a
     * linker collects an allocated section nothing references unless it carries
     * `SHF_GNU_RETAIN`, which the header's `retain` attribute asks for only where the
     * compiler has it (gcc 11, clang 13). The two C probes with macro checks reference
     * the array from their output; this probe's detector reads its stdout and stderr, so
     * the reference is silent: a store of the array's address through a volatile pointer
     * is a side effect the compiler must emit, and the relocation it leaves is what makes
     * the section reachable from `main`. Without it, g++ 16.1.1 and clang++ 22.1.8 with a
     * header lacking `retain` linked this probe with no `.chard.report` at all (measured
     * 2026-10-20 under `-O2 -Wl,--gc-sections`), and chard read `cxx-hardening-requested`
     * from the preprocessor dump instead; `tests/probe_sources.rs` links it that way and
     * reads the section back. */
    const char *volatile keep_report = chard_report;
    (void) keep_report;

#if __cplusplus >= 201103L
    std::vector<int> v{1, 2, 3};
#else
    /* The same three elements and, from a forward range, the same capacity. */
    static const int elements[] = {1, 2, 3};
    std::vector<int> v(elements, elements + 3);
#endif

    /* Defeat constant folding: the compiler must not be able to prove the index
     * out of range at compile time, or it may diagnose instead of executing. */
    volatile int index = 7;
    volatile int sink = 0;

    sink = v[static_cast<std::vector<int>::size_type>(index)];
    (void) sink;

    std::puts("no-check-fired");
    return 0;
}
