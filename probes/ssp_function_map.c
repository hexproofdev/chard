/* SPDX-License-Identifier: BSD-3-Clause */

/* Stack protector level read per function (elf-static channel), from an object file.
 *
 * `ssp-level` reads the level the preprocessor was told (`__SSP_STRONG__` and its
 * siblings) and `canary-emitted` reads that some function got a canary. Neither says
 * which functions did, and the level is a rule about which functions: plain
 * `-fstack-protector` admits a function calling alloca or holding a character array of
 * at least `ssp-buffer-size` bytes, `-strong` adds any array and any local whose
 * address is taken, and `-all` admits every function. Four functions read together
 * give the level the compiler applied rather than the one it announced, and a fifth
 * tells that level apart from a selection that is no level at all:
 *
 *     ssp_any  ssp_addr_taken  ssp_char_array  ssp_alloca  ssp_safe_array   level
 *        -           -               -             -             -          none
 *        -           -               C             C             C          basic
 *        -           -               -             C             -          basic, threshold above 64
 *        -           C               C             C             C          strong
 *        C           C               C             C             C          all
 *        -           CU              CU            CU            -          unsafe-frame (SafeStack, -O1 and above)
 *        -           CU              CU            CU            CU         unsafe-frame (SafeStack, -O0)
 *
 * `C` is a relocation, from inside the function's own range, against the canary failure
 * handler or the guard; `U` is one against `__safestack_unsafe_stack_ptr`, the unsafe
 * stack pointer clang's SafeStack reads in every function it gives an unsafe frame. Any
 * other row is not a level and reads as indeterminate. The measurement is on
 * `predicate::elf_static`'s SSP_LEVEL_EMITTED. The fifth column and the two SafeStack
 * rows were measured on 2026-10-08.
 *
 * ## SafeStack, and why the fifth function
 *
 * Under clang's `-fsanitize=safe-stack` the canary set is not the level's. The frontend
 * records the request (the `__SSP_*` macro, the `sspreq`, `sspstrong` or `ssp` attribute on
 * every function); in the backend SafeStack moves each local whose address escapes or whose
 * accesses it cannot prove in range to a separately mapped unsafe stack, and a canary is
 * placed in that frame for any function carrying an ssp attribute. That SafeStack runs
 * before StackProtector and which pass withholds the ordinary canary from the rest is
 * inferred from the objects and from deleting the `safestack` attribute from the IR, not
 * read from the LLVM source (`predicate::elf_static`'s SSP_LEVEL_EMITTED and
 * THREAT_MODEL.md's `safestack-canaries-follow-the-unsafe-frame` say so, and the latter
 * names the reading that retires it). A function with no unsafe frame gets nothing,
 * whatever the level asked:
 * `ssp_any` stays bare under `-fstack-protector-all`, and `ssp_addr_taken` gains a canary
 * under plain `-fstack-protector`. The two selection rules coincide on the four functions
 * above, which are written to escape, so the first four columns read `strong` under every
 * requested level. `ssp_safe_array` separates them: a 64-byte character array every access
 * to which is masked into range and whose address never escapes. `-strong` and plain
 * `-fstack-protector` both admit it (any array; a character array above the threshold), and
 * SafeStack at `-O1` and above proves it safe and leaves it on the ordinary stack with no
 * canary. At `-O0` SafeStack reads the index through a load it cannot see through and moves
 * the array too, so there the fifth column reads `CU` and the first four alone separate
 * nothing; the `U` column does, and the reading is `unsafe-frame` at both levels.
 *
 * Measured 2026-10-08 with clang 22.1.8 and gcc 16.1.1 on Fedora 44 x86_64 (glibc 2.43),
 * `-c` at -O0, -O1, -O2, -Os and -O3, attributed by symbol range from `readelf -rW` and
 * `readelf -sW`: the rows above for `-fno-stack-protector`, `-fstack-protector`,
 * `-fstack-protector-strong`, `-fstack-protector-all` and `-fstack-protector
 * --param=ssp-buffer-size=128` under both compilers without SafeStack (gcc rejects
 * `-fsanitize=safe-stack`), and under clang with it; with it the row is the same at every
 * requested level, `-fno-stack-protector` apart, which gives `U` on the three escaping
 * functions and no canary anywhere. A constant-index form of the fifth function was tried
 * and rejected: clang's -O2 SROA splits a constant-indexed volatile array into scalars and
 * plain `-strong` then leaves it bare, so it would have read `strong` as no level.
 *
 * ## Why an object
 *
 * A relocatable object keeps one relocation per reference, at an offset inside the
 * section the referring function lives in, so each reference is attributed to the
 * function whose symbol range holds it. A link resolves those relocations and keeps none,
 * so a linked program cannot answer per function.
 *
 * ## Why each function is present by construction
 *
 * The failure this probe cannot tolerate is a function that is missing scoring as one
 * without a canary, which reads `strong` as `basic` or `off`. Each function has external
 * linkage, so the object must define it, and `noinline` and `used` keep it a function
 * of its own; the predicate also requires every one to be present in the symbol table
 * and withholds otherwise. Each one passes its local to an external function it cannot
 * see, so the local must live on the stack at every optimization level.
 *
 * `ssp_any` is the only witness for `-all`: it holds no array and takes no address, and
 * must keep doing so, or `-strong` would read as `-all`. `ssp_safe_array` is the only
 * witness that SafeStack's selection is not `-strong`'s, and must keep every access
 * provably in range and its address unescaped, or SafeStack would move it too and the
 * fifth column would read `CU` at every optimization level.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

void ssp_escape(void *);
int ssp_use(int);

/* Admitted by -fstack-protector-all alone: no array, no address taken. */
__attribute__((noinline, used)) int ssp_any(int x)
{
    int a = x * 3;
    int b = a ^ 5;
    return ssp_use(a) + b;
}

/* Admitted by -strong and -all: a scalar whose address escapes. */
__attribute__((noinline, used)) int ssp_addr_taken(int x)
{
    int v = x;
    ssp_escape(&v);
    return v;
}

/* Admitted at every level: a 64-byte character array, above any threshold a
 * distribution is known to set (upstream 8, Alpine 4). */
__attribute__((noinline, used)) int ssp_char_array(int x)
{
    char s[64];
    s[0] = (char) x;
    ssp_escape(s);
    return s[0];
}

/* Admitted at every level, at any ssp-buffer-size: a variable-length alloca. */
__attribute__((noinline, used)) int ssp_alloca(int n)
{
    char *p = __builtin_alloca((unsigned) n);
    p[0] = 1;
    ssp_escape(p);
    return p[0];
}

/* Admitted by -strong and by plain -fstack-protector at the default threshold (a 64-byte
 * character array), and left on the ordinary stack by SafeStack at -O1 and above: every
 * index is masked into range and the array's address never escapes, so SafeStack has no
 * unsafe frame to move it to and places no canary. `volatile` keeps the array in memory
 * at every optimization level without taking its address; the call to `ssp_use` is the
 * relocation the predicate's `unread-calls` clause requires of every probe function. */
__attribute__((noinline, used)) int ssp_safe_array(int x)
{
    volatile char s[64];
    unsigned i = (unsigned) x & 63u;
    s[i] = (char) x;
    return s[i ^ 1u] + ssp_use(x);
}
