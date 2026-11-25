/* SPDX-License-Identifier: BSD-3-Clause */

/* libstdc++ / libc++ precondition-check probe (runtime channel). */

#include <cstdio>
#include <vector>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/*After the standard library headers, so `_CXX_STDLIB` reflects the library that actually provided
 *them. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

int main()
{
    /*Unbuffer stdout before anything can abort, and outside the `__OPTIMIZE__` arms below because
     *the unoptimized build is the one that needs it. */
#if __cplusplus >= 201103L
    std::setvbuf(stdout, nullptr, _IONBF, 0);
#else
    std::setvbuf(stdout, NULL, _IONBF, 0);
#endif
    CHARD_NOT_DUMPABLE;

    /*Report the optimization state from inside the compiled artifact rather than from the flags
     *chard passed. */
#ifdef __OPTIMIZE__
    std::fputs("chard-opt=1\n", stderr);
#else
    std::fputs("chard-opt=0\n", stderr);
#endif
    std::fflush(stderr);

    /* Reference the report from code the linker keeps. */
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
