/* SPDX-License-Identifier: BSD-3-Clause */

/* -fno-plt, read from the object the compiler produced: how its one external call is relocated. */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

extern int chard_no_plt_callee(int);

__attribute__((used)) int chard_no_plt_caller(int x)
{
    return chard_no_plt_callee(x) + 1;
}
