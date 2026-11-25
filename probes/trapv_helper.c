/* SPDX-License-Identifier: BSD-3-Clause */

/*-ftrapv under gcc, read from the object the compiler produced: the libgcc helpers it calls for
 *signed arithmetic. */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

__attribute__((used)) int chard_trapv_add(int a, int b)
{
    return a + b;
}

__attribute__((used)) int chard_trapv_sub(int a, int b)
{
    return a - b;
}

__attribute__((used)) int chard_trapv_mul(int a, int b)
{
    return a * b;
}
