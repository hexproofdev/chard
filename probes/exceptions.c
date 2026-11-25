/* SPDX-License-Identifier: BSD-3-Clause */

/*-fexceptions in C, read twice from one object file: the macro the compiler defined and the
 *exception table it emitted. */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

static void chard_cleaner(int *p)
{
    printf("cleanup %d %c\n", *p, chard_report[0]);
}

extern int chard_may_unwind(int);

int chard_exceptions_probe(int x)
{
    int guard __attribute__((cleanup(chard_cleaner))) = x;
    return chard_may_unwind(x);
}
