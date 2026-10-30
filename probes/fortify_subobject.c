/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE level-2 probe (runtime channel): rung 2 of the fortify ratchet.
 *
 * Overflows a struct member while staying inside the enclosing struct. The two
 * levels ask `__builtin_object_size` different questions about that write:
 *
 *   level 1  type 0, the WHOLE object: the enclosing struct is 16 bytes, the
 *            13-byte copy fits, nothing fires.
 *   level 2  type 1, the SUBOBJECT: `obj.a` is 8 bytes, the copy overruns it,
 *            SIGABRT with "*** buffer overflow detected ***".
 *
 * So this rung separates level 1 from level 2, which no macro can do and which the
 * whole-object and heap probes both miss. Verified on gcc 16.1.1 and clang 22.1.8:
 * exit 0 at levels 0 and 1, abort at levels 2 and 3, on both compilers.
 *
 * Measured 2026-09-29 in ubuntu:24.04 (glibc 2.39): gcc 13.3.0 aborts at levels 2 and
 * 3, and clang 18.1.3 aborts at no level. The copy is the same; what differs is where
 * the bound is asked for. glibc's `strcpy` wrapper asks `__builtin_object_size(__dest,
 * 1)` of its own parameter inside an always-inline function. gcc answers after
 * inlining, with the member's 8. clang answers for the whole object, 16, and folds the
 * checked copy away as fitting; clang 22.1.8 gives the same 16 through such a wrapper.
 * glibc 2.43 on Fedora 44 declares the parameter `pass_object_size` under clang, which
 * takes the size at the call site, and the probe aborts there. `wrap1` below measures
 * the wrapper's answer; `report::subobject_bound_lost_in_wrapper` reads it.
 *
 * The `strcpy` family is deliberate. The same overflow written with `memset` and a
 * volatile length does NOT fire at any level on either compiler: glibc's `memset`
 * wrapper asks for the whole-object size even at level 2, so a subobject probe
 * built on `memset` reads "level 1" for a level-2 build. The subobject distinction
 * lives in the string functions.
 *
 * File scope, not a local, so the stack protector cannot fire first and be
 * miscredited to fortify.
 */

#include <stdio.h>
#include <string.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/* After the libc headers, so `_FORTIFY_IMPL` reflects which implementation
 * actually wrapped this translation unit. The runtime detector needs it: glibc
 * aborts with a message, fortify-headers traps silently, and the two cannot be
 * told apart from the termination alone. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

struct pair {
    char a[8];
    char b[8];
};

static struct pair obj;

/* The shape of glibc's `__fortify_function` before its clang path: the size is asked for
 * inside an always-inline function, of that function's own parameter. */
static inline __attribute__((__always_inline__, __gnu_inline__, __artificial__)) size_t
chard_bos1_in_wrapper(char *p)
{
    return __builtin_object_size(p, 1);
}

/* Which wrapper form the C library compiled into this translation unit, printed beside
 * the sizes so the gating rule reads the library's state rather than infers it.
 * `_BITS_STRING_FORTIFIED_H` is the include guard of glibc's `<bits/string_fortified.h>`,
 * which `<string.h>` reaches only under `__USE_FORTIFY_LEVEL > 0`, so it says glibc's
 * string wrappers are here. `__fortify_use_clang` is glibc's own switch, from 2.40, for the
 * clang path that declares the destination `pass_object_size`; glibc 2.39 does not define
 * it, and the line prints `?`. */
#if defined(_BITS_STRING_FORTIFIED_H)
#  define CHARD_GLIBC_WRAPPERS 1
#else
#  define CHARD_GLIBC_WRAPPERS 0
#endif
#if !defined(__fortify_use_clang)
#  define CHARD_CLANG_PATH "?"
#elif __fortify_use_clang
#  define CHARD_CLANG_PATH "1"
#else
#  define CHARD_CLANG_PATH "0"
#endif

/* 13 characters plus a terminator: overruns `a` but stays inside `obj`. */
static const char source[] = "0123456789ABC";

int main(void)
{
    CHARD_PRINT_REPORT;
    CHARD_NOT_DUMPABLE;

    /* Instrument, not observable: the detector reads none of these fields.
     *
     * `__builtin_object_size(obj.a, 1)` is what the compiler believes the *subobject*
     * holds at the call site: 8 means it narrowed to the member, 16 means it answered for
     * the enclosing struct, `(size_t)-1` means it declined at this optimization level.
     * Mode 0 is printed beside it because the pair is what makes the reading unambiguous.
     * `wrap1` is the same question asked through an always-inline wrapper, the form a C
     * library's fortify wrapper takes, because inlining changes what the compiler can see.
     *
     * `glibc_wrappers` and `clang_path` say which wrapper the library compiled in.
     *
     * One gating rule reads the line, and only on a positive control that showed no abort:
     * `report::subobject_bound_lost_in_wrapper` names the silence a toolchain fact when
     * `main1` is the member's size and `wrap1` the whole object's, glibc's string wrappers
     * are compiled in, and its clang path is not. The argument for that
     * read is in the project ledger's `fortify-level-ge-2-subobject` entry. */
    printf("CHARD-BOS main1=%zu main0=%zu wrap1=%zu glibc_wrappers=%d clang_path=%s\n",
           __builtin_object_size(obj.a, 1),
           __builtin_object_size(obj.a, 0),
           chard_bos1_in_wrapper(obj.a),
           CHARD_GLIBC_WRAPPERS,
           CHARD_CLANG_PATH);
    /* Flushed for the reason `CHARD_PRINT_REPORT` flushes: the next statement is meant to
     * abort, the harness redirects stdout to a file, and a buffer the abort destroys
     * carries nothing. The same omission cost `cxx-stdlib-assertions` nine toolchains. */
    fflush(stdout);

    strcpy(obj.a, source);

    /* Reached only when nothing caught the subobject overflow. */
    printf("no-check-fired %c\n", obj.a[0]);
    return 0;
}
