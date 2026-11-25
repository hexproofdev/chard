/* SPDX-License-Identifier: BSD-3-Clause */

/* -fno-strict-aliasing probe (runtime channel). */

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
/* The shape without sanitizer instrumentation, built under the build's own options otherwise. */
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

/* The shape at the build's level, rebuilt from that level's defaults on gcc 11 and earlier. */
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
    /*The probe reports its own compilation rather than relying on the harness having asked for a
     *macro dump. */
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
