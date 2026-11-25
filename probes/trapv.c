/* SPDX-License-Identifier: BSD-3-Clause */

/* -ftrapv read from what a signed overflow does when it runs. */

#include <stdio.h>

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

#ifndef __has_feature
#  define __has_feature(x) 0
#  define CHARD_TRAPV_NO_FEATURE_TEST 1
#endif

static volatile int lhs = 2147483647; /* INT_MAX */
static volatile int rhs = 1;

__attribute__((noinline)) static int chard_trapv_add(int a, int b)
{
    return a + b;
}

int main(void)
{
    CHARD_NOT_DUMPABLE;
#if defined(__clang__)
    printf("frontend=clang\n");
#elif defined(__GNUC__)
    printf("frontend=gcc\n");
#else
    printf("frontend=other\n");
#endif
#if defined(CHARD_TRAPV_NO_FEATURE_TEST)
    printf("ubsan=unknown\n");
#elif __has_feature(undefined_behavior_sanitizer)
    printf("ubsan=yes\n");
#else
    printf("ubsan=no\n");
#endif
    printf("trapv-overflow=attempted\n");
    fflush(stdout);

    int sum = chard_trapv_add(lhs, rhs);

    printf("trapv-overflow=wrapped sum=%d\n", sum);
    return 0;
}
