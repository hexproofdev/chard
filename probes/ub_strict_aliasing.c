/* SPDX-License-Identifier: BSD-3-Clause */

/* -fno-strict-aliasing probe (runtime channel).
 *
 * The type-based aliasing rule says an object may only be accessed through a
 * compatible type, so a compiler may assume a store through `int *` cannot affect an
 * object read through `float *`, and may therefore keep the float in a register
 * across the store and never reload it. The write happens; the read does not see it.
 *
 * This is the flag the Linux kernel passes, and it is passed because the assumption
 * is wrong for a great deal of real code that punts types through pointers. What this
 * probe measures is whether a given build still lets the optimizer make it.
 *
 * ## The shape
 *
 * One storage location, written through `float *` and then through `int *`, then read
 * back through the float. Under strict aliasing the reload is optimized away and the
 * read yields the stale value; under `-fno-strict-aliasing` the store is observed.
 *
 * ## This one is genuinely inert without optimization
 *
 * Measured on gcc: at `-O0` the store is observed whether or not the flag is passed,
 * because nothing is being kept in a register in the first place. That makes an
 * unoptimized build's reading uninformative in the direction that matters, "the
 * store was seen" would otherwise be read as the flag being in force, when it only
 * means the optimizer was not asked to do anything.
 *
 * So the detector requires `__OPTIMIZE__` before crediting the observation, the same
 * way the fortify detectors do and for the same reason: without it, no mechanism is
 * running and a positive reading is an artefact of the question not having been put.
 * Every control arm carries its own `-O2`.
 *
 * ## gcc at -O1 and -Og: the level, not the flag
 *
 * `__OPTIMIZE__` is not enough on gcc. gcc enables -fstrict-aliasing by default only
 * at -O2, -O3, -Os and -Oz, so at -O1 and -Og the store is observed with no flag
 * passed, exactly as under -fno-strict-aliasing. No predefined macro separates those
 * levels from -O2, so on gcc the probe carries the same shape twice more under gcc's
 * `optimize` attribute, and prints what each copy saw before the reading they qualify:
 *
 *   o2-witness     the shape under optimize("O2"). gcc 12 and later treat the
 *                  attribute's options as appended to the command line, so this copy
 *                  keeps an explicit -fno-strict-aliasing and otherwise applies the
 *                  rule: `observed` shows the flag in force for code optimized at a
 *                  level that would apply it.
 *   level-witness  the shape under optimize("no-tree-pre"), which names no level and
 *                  nothing aliasing-related. gcc 11 and earlier rebuild an attributed
 *                  function's options from the level's defaults and drop explicit
 *                  command-line options, so there this copy applies the rule exactly
 *                  when the build's level does by default: `lost` beside an observed
 *                  store means the level applies the rule and the build turned it off.
 *                  On gcc 12 and later the copy keeps the command line and reads as
 *                  the store does, so it decides nothing there.
 *
 * Neither witness reads a version: each reports what its copy did, and the detector
 * credits an observed store only where one of them shows the flag rather than the
 * level. An observed store beside an `o2-witness` that lost it and a `level-witness`
 * that saw it is the level speaking, and is withheld. On gcc 11 and earlier that
 * includes -O1 and -Og with the flag passed, since nothing in that build separates the
 * flag from the level. A third copy, under optimize("O2", "strict-aliasing"), must lose
 * the store whatever the command line says; where it does not, the attribute was not
 * honoured, the witnesses prove nothing, and the probe says so.
 *
 * Measured 2026-10-01 with this source at -O0, -O1, -Og, -Os, -O2 and -O3, each bare,
 * with -fno-strict-aliasing and with -fstrict-aliasing: o2-witness keeps the flag under
 * gcc 12.2, 12.3, 13.3, 15.2, 16.1.1 and 16.2.1 and drops it under 7.5, 8.5, 9.4, 11.4
 * and 11.5; level-witness follows the build's level under those five and the store
 * under the rest; the forced copy lost the store under every one. clang does not
 * implement the attribute and applies the rule from -O1 (clang 14, 18, 22.1.8 and
 * 23.1.2), so no copy is built there and the witness line reads `not-built`.
 *
 * ## gcc 12 and later at -O1 and -Og with the flag: a witness that names the level
 *
 * On gcc 12 and later the build's own copy and both witnesses observe the store at -O1
 * and -Og with -fno-strict-aliasing exactly as at -O2 with it, so the lines above cannot
 * say whether the flag changed anything in this build. At -O1 and -Og it did not: the
 * level does not apply the rule by default, so the flag there is present and inert. No
 * copy under the attribute can show the build's level on these versions, because the
 * attribute keeps every option the command line set and the flag is one of them; what
 * can show it is an option the command line did not set, whose default follows the
 * level the way the rule's does.
 *
 *   sibling-call   whether a call in tail position, compiled at the build's own
 *                  options, became a jump. gcc enables -foptimize-sibling-calls by
 *                  default at -O2, -O3, -Os, -Oz and -Ofast and not at -O0, -O1 or -Og,
 *                  the levels at which it enables -fstrict-aliasing. The callee reports
 *                  its frame address, once called directly and once through a function
 *                  whose whole body is the tail call, both from one caller: the two are
 *                  equal only when the intermediate frame was not pushed. `made` names
 *                  a level that applies the rule; `not-made` names one that does not,
 *                  or a build that passed a flag suppressing the jump, such as
 *                  -fno-optimize-sibling-calls.
 *
 * The detector credits a gcc 12 and later observed store from the -O2 copy only beside
 * `sibling-call=made`. The witness reads the option, not the level, so it can be moved:
 * a flag that suppresses the jump at -O2 withholds an `on` the build earned, and
 * -foptimize-sibling-calls at -O1 or -Og credits one it did not; the second is the
 * assumption `sibling-calls-follow-the-aliasing-level` in THREAT_MODEL.md. The first
 * stays `indeterminate` under a profile carrying such a flag: the control arms are built
 * without the profile's flags (measure::arm_flags), so the positive arm still prints
 * `made` and the triple still discriminates.
 *
 * Measured 2026-10-01 with this shape built by hand at -O0, -O1, -Og, -Os, -Oz, -O2, -O3
 * and -Ofast, bare and with each of -fno-strict-aliasing, -fstack-protector-all,
 * -fstack-protector-strong, -fstack-clash-protection, -fno-omit-frame-pointer, -fPIE
 * -pie, -fPIC, -ftrivial-auto-var-init=zero, -fexceptions, -D_FORTIFY_SOURCE=3, -pg,
 * -fsanitize=address, -fsanitize=undefined, -fhardened, -flto, -fcf-protection=full on
 * x86 and -mbranch-protection=standard on aarch64, under gcc 16.1.1 (Fedora 44 x86_64),
 * 16.2.1 (Fedora 44 aarch64), 15.2.0 (Alpine), 13.3.0 (Ubuntu 24.04), 12.2.0 (Debian 12
 * i386) and 11.4.0 (Ubuntu 22.04), wherever the build succeeded: the call
 * became a jump at every level from -Os up and at none of -O0, -O1 and -Og, and of those
 * flags and the two sibling-call ones only -fno-optimize-sibling-calls and
 * -foptimize-sibling-calls moved it. Measured the same day under gcc 16.1.1 (Fedora 44
 * x86_64) and 16.2.1 (Fedora 44 aarch64) at -O1, -Og, -O2 and -Os with
 * -fno-strict-aliasing and each of a further set of hardening and instrumentation flags:
 * -finstrument-functions, -fstrub=all and -fstrub=at-calls kept the call from becoming a
 * jump at -O2 and -Os, and no flag in the set made it one at -O1 or -Og. The set, the
 * flags that did not build and the readings are in the entry in the project ledger;
 * a flag outside both sets is unmeasured, not known to leave the witness alone.
 *
 * ## Sanitizers: the instrumentation, not the flag
 *
 * clang with -fsanitize=undefined observed the store at every optimized level with no flag
 * passed. The rule is still in force: the IR carries its type-based aliasing tags. What
 * keeps the reload is the alignment check, part of -fsanitize=undefined: its recoverable
 * handler is a call that may write memory, placed on a path between the store and the
 * reload, so the reload cannot be folded. The null checks fold away (both pointers are
 * addresses of a local), -fsanitize-trap=all and -fno-sanitize-recover=all make the
 * handler not return, and in each of those the store is lost as without a sanitizer.
 * clang's -fsanitize=type keeps the store in instrumented code with or without
 * -fno-strict-aliasing.
 *
 *   uninstrumented-store  the shape under no_sanitize("address", "undefined"), plus
 *                         "type" where the compiler has the type sanitizer, otherwise
 *                         under the build's own options. `lost` beside an observed store
 *                         is the instrumentation keeping it. `not-built` is a compiler
 *                         without the attribute (gcc before 8).
 *
 * The copy only withholds. Under -fsanitize=type it loses the store with the flag too,
 * since clang emits the aliasing tags for that sanitizer whatever the flag says, so the
 * build reads `indeterminate` there either way.
 *
 * Measured 2026-10-01 with this source at -O0, -O1, -Og, -Os, -Oz, -O2 and -O3, each
 * bare, with -fno-strict-aliasing and with -fstrict-aliasing, under no sanitizer,
 * -fsanitize=undefined, address, alignment, thread, memory and type, undefined with
 * address, and undefined with -fsanitize-trap=all, wherever the build linked: clang
 * 22.1.8 (Fedora 44 x86_64, host and container), 18.1.3 (Ubuntu 24.04) and 14.0.0
 * (Ubuntu 22.04) read the copy `lost` beside an observed store under undefined,
 * alignment, undefined with address, and type, and in no other cell of that set; clang
 * 23.1.2 (Alpine) was measured under trap only, where the two agree; gcc 16.2.1
 * (Fedora 44 aarch64), 15.2.0 (Alpine), 13.3.0 (Ubuntu 24.04), 12.2.0 (Debian 12 i386)
 * and 11.4.0 (Ubuntu 22.04) read the copy as the build at every cell, and every gcc
 * witness line as with no sanitizer, except that -fsanitize=thread keeps the build's
 * tail call from becoming a jump. clang 22.1.8 at -O2 under each of a further set of
 * sanitizers (dataflow, safe-stack, cfi with -flto, kcfi, integer, implicit-conversion,
 * nullability, local-bounds, bounds, function, leak, realtime, numerical,
 * shadow-call-stack, pointer-overflow, vla-bound, return, unreachable, object-size,
 * float-divide-by-zero, builtin, array-bounds, signed-integer-overflow, undefined with
 * -fno-sanitize-recover=all and undefined with -fsanitize-minimal-runtime) read the copy
 * as the build except under the last, which keeps the store as undefined does. The
 * readings are in the entry in the project ledger. That no_sanitize
 * removes whatever instrumentation keeps the store is
 * `no-sanitize-removes-store-keeping-instrumentation` in report::ASSUMPTIONS.
 *
 * The overflow probe beside this one behaves differently: gcc 8 and later fold its
 * guard at `-O0` too, so that check is decidable unoptimized on them, and not on clang
 * or on the gcc 4.8, 5.4 and 7.5 measured. The three anti-UB flags do not share one
 * relationship to the optimizer, and assuming they did would have produced a false
 * reading on two of them.
 */

#include <stdint.h>
#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

__attribute__((noinline)) static int store_is_observed(float *f, int *i) {
    *f = 1.0f;
    /* Aliases *f, but the types say it cannot. */
    *i = 0;
    /* Reloaded, or folded to the stale 1.0f? */
    return *f == 0.0f;
}

#if defined(__has_attribute)
#if __has_attribute(no_sanitize)
#define CHARD_HAS_NO_SANITIZE 1
#endif
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(type_sanitizer)
#define CHARD_NO_SANITIZE no_sanitize("address", "undefined", "type")
#else
#define CHARD_NO_SANITIZE no_sanitize("address", "undefined")
#endif

#ifdef CHARD_HAS_NO_SANITIZE
/* The shape without sanitizer instrumentation, built under the build's own options
 * otherwise. Observing the store here and losing it there cannot happen; losing it here
 * and observing it there is the instrumentation's doing. */
__attribute__((noinline, CHARD_NO_SANITIZE)) static int
store_is_observed_uninstrumented(float *f, int *i) {
    *f = 1.0f;
    *i = 0;
    return *f == 0.0f;
}
#endif

#if defined(__GNUC__) && !defined(__clang__)
#define CHARD_ALIASING_SHAPE \
    {                        \
        *f = 1.0f;           \
        *i = 0;              \
        return *f == 0.0f;   \
    }

/* The shape at -O2, keeping what the command line set for the rule on gcc 12 and later. */
__attribute__((noinline, optimize("O2"))) static int store_is_observed_at_o2(float *f, int *i)
    CHARD_ALIASING_SHAPE

/* The shape at the build's level, rebuilt from that level's defaults on gcc 11 and
 * earlier. `no-tree-pre` is there because the attribute needs an option to carry. */
__attribute__((noinline, optimize("no-tree-pre"))) static int
store_is_observed_at_this_level(float *f, int *i) CHARD_ALIASING_SHAPE

/* The shape with the rule forced on: observing the store means the attribute was
 * not honoured. */
__attribute__((noinline, optimize("O2", "strict-aliasing"))) static int
attribute_is_ignored(float *f, int *i) CHARD_ALIASING_SHAPE

/* The level witness: the callee's frame, reached directly and through a tail call. */
__attribute__((noinline, noclone)) static uintptr_t frame_of_callee(void) {
    return (uintptr_t)__builtin_frame_address(0);
}

__attribute__((noinline, noclone)) static uintptr_t through_tail_position(void) {
    return frame_of_callee();
}

__attribute__((noinline, noclone)) static int sibling_call_is_made(void) {
    uintptr_t direct = frame_of_callee();
    uintptr_t through = through_tail_position();
    return direct == through;
}
#endif

int main(void) {
    /* The probe reports its own compilation rather than relying on the harness having
     * asked for a macro dump. `ev.macros` is populated only for probes carrying a
     * macro-channel check, and this one is runtime-only, a detector reading it would
     * find nothing and withhold every arm, which is exactly what happened the first
     * time this check was wired up. The program knows how it was compiled; asking it
     * is both simpler and closer to the artifact. */
#ifdef __OPTIMIZE__
    printf("optimize=yes\n");
#else
    printf("optimize=no\n");
#endif

    /* Printed before the reading they qualify, so the reading never stands alone. */
#if defined(__GNUC__) && !defined(__clang__)
    float check_storage;
    float o2_storage;
    float level_storage;
    printf("attribute-check=%s\n",
           attribute_is_ignored(&check_storage, (int *)&check_storage) ? "ignored" : "honoured");
    printf("o2-witness=%s\n",
           store_is_observed_at_o2(&o2_storage, (int *)&o2_storage) ? "observed" : "lost");
    printf("level-witness=%s\n",
           store_is_observed_at_this_level(&level_storage, (int *)&level_storage) ? "observed"
                                                                                  : "lost");
    printf("sibling-call=%s\n", sibling_call_is_made() ? "made" : "not-made");
#else
    printf("o2-witness=not-built\n");
#endif

#ifdef CHARD_HAS_NO_SANITIZE
    float bare_storage;
    printf("uninstrumented-store=%s\n",
           store_is_observed_uninstrumented(&bare_storage, (int *)&bare_storage) ? "observed"
                                                                                  : "lost");
#else
    printf("uninstrumented-store=not-built\n");
#endif

    float storage;
    if (store_is_observed(&storage, (int *)&storage)) {
        printf("aliasing-store=observed\n");
    } else {
        printf("aliasing-store=lost\n");
    }
    return 0;
}
