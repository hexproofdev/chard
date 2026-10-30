/* SPDX-License-Identifier: BSD-3-Clause */

/* Stack-protector probe for the `elf-static` channel.
 *
 * Detection is the presence of a `__stack_chk_fail` reference, so the probe's job
 * is to contain a function the protector will certainly instrument at the level
 * we care about:
 *
 *   -fstack-protector          functions that call alloca, and functions with a
 *                              char array of at least --param=ssp-buffer-size
 *                              bytes (8 by default)
 *   -fstack-protector-strong   additionally any function with a local array of
 *                              any type or size, or whose local's address escapes
 *   -fstack-protector-all      every function
 *
 * Three functions, each qualifying under a different rule, so that the observable
 * does not rest on one construct at one tunable threshold:
 *
 *   - `big_char_array`: a 64-byte character array, the plain -fstack-protector
 *     rule at the default threshold.
 *   - `variable_size`: a buffer from `__builtin_alloca`, which plain
 *     -fstack-protector instruments at every threshold. This is the one that keeps
 *     the observable when a distribution raises --param=ssp-buffer-size: with only
 *     the array, `-fstack-protector --param=ssp-buffer-size=128` removed the
 *     reference on both compilers at every optimization level, and the check read
 *     `off` for a toolchain whose protector was fully enabled, with the controls
 *     discriminating, since they force `-all` and `-fno-stack-protector`.
 *   - `address_taken_scalar`: a local whose address escapes, the rule
 *     -fstack-protector-strong adds and plain -fstack-protector does not have.
 *
 * Measured on this file's own host, Apple clang 21.0.0 and Homebrew gcc 16.2.0,
 * arm64, at -O0, -O2 and -Os, from the compiler's own assembly: the reference is
 * present under -fstack-protector, under `-fstack-protector --param
 * ssp-buffer-size=128`, under -strong and under -all, and absent under
 * -fno-stack-protector, on both compilers at every level. Per function, under
 * -strong: clang instruments all three at every level; gcc instruments all three
 * at -O0 and only the array and alloca functions at -O2 and -Os. The cause is
 * IPA-SRA: at -O2 and -Os gcc's interprocedural scalar replacement rewrites
 * `sink(const char *)` to take the byte by value, since `sink` is static and
 * every caller is visible, and once the parameter is a value the scalar's address
 * no longer escapes and the -strong rule has nothing to apply to. Measured on the
 * same gcc 16.2.0: with `-fno-ipa-sra` added, `address_taken_scalar` references
 * `__stack_chk_fail` at -O2 and -Os as it does at -O0, and the other two
 * functions are unchanged. `noinline` does not prevent this, since the rewrite
 * changes the callee's signature rather than inlining its body; gcc's `noipa`
 * attribute would, and is left off because clang has no such attribute and the
 * observable does not rest on this construct. The scalar construct is therefore
 * the weakest of the three, and the check's `on` never depends on it. The review
 * that found the threshold hazard measured the single-array probe on Linux with
 * gcc and clang: one reference at the default threshold, none at 128, at -O0,
 * -O2 and -Os.
 *
 * What changes eligibility, so a reader of an `off` knows where to look:
 * `--param=ssp-buffer-size` moves the array rule's threshold and nothing else;
 * gcc's `-fstack-protector-explicit` instruments only functions marked
 * `__attribute__((stack_protect))`, which none of these carry, so it reads `off`
 * here by design (measured: no reference on gcc 16.2.0 at -O0, -O2 and -Os, and
 * clang rejects the flag); `__attribute__((no_stack_protector))` exempts a function;
 * `-flto` defers the decision to link time and the reference still appears in
 * the linked artifact. The reference is present or absent; which rule admitted it
 * is not something this channel reports, and the check publishes no level.
 *
 * `argv` is the data source so no copy can be constant-folded, each function is
 * `noinline` so its frame is its own and the escape into `sink` is real, and
 * `sink` takes the address so nothing is promoted entirely into registers; any of
 * those optimizations would delete the canary and produce a false `off`.
 */

#include <stdio.h>
#include <string.h>

/* `noinline` so that passing an address here is an escape at every optimization
 * level: inlined, the scalar's address would go nowhere and the -strong rule that
 * `address_taken_scalar` exists to exercise would not apply at -O2. gcc's IPA-SRA
 * still removes the escape at -O2 and -Os by passing the byte by value; the header
 * comment records the measurement and why the probe accepts it. */
__attribute__((noinline)) static void sink(const char *p)
{
    volatile char observed = *p;
    (void) observed;
}

/* Plain -fstack-protector, at the default threshold: a char array of at least
 * ssp-buffer-size bytes. */
__attribute__((noinline)) static void big_char_array(const char *arg)
{
    char buf[64];

    memset(buf, 0, sizeof buf);
    if (arg != NULL) {
        strncpy(buf, arg, sizeof buf - 1);
    }
    sink(buf);
}

/* -fstack-protector-strong: a scalar whose address escapes. Not a candidate under
 * plain -fstack-protector at any threshold. */
__attribute__((noinline)) static void address_taken_scalar(const char *arg)
{
    char one = arg != NULL ? arg[0] : 0;

    sink(&one);
}

/* Plain -fstack-protector, independent of the threshold: a function that calls
 * alloca. The size comes from argc so the allocation cannot be folded into a
 * fixed array, which would put it back under the array rule. */
__attribute__((noinline)) static void variable_size(int len, const char *arg)
{
    size_t size = (size_t) len + 16;
    char *buf = __builtin_alloca(size);

    memset(buf, 0, size);
    if (arg != NULL) {
        strncpy(buf, arg, size - 1);
    }
    sink(buf);
}

int main(int argc, char **argv)
{
    const char *arg = argc > 1 ? argv[1] : NULL;

    big_char_array(arg);
    address_taken_scalar(arg);
    variable_size(argc, arg);
    return 0;
}
