/* SPDX-License-Identifier: BSD-3-Clause */

/*Carries the macro state into a compiled artifact, so the macro channel can be read from something
 *the *compiler* produced rather than from a preprocessor run. */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

int main(void)
{
    puts(chard_report);
    return 0;
}
