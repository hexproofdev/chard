/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE's level, read from the code of the object the compiler produced. */

#include <stdio.h>
#include <string.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

void escape(void *);

int chard_fortify_printf_probe(const char *fmt, const char *s)
{
    return printf(fmt, s);
}

void chard_fortify_onset_probe(const char *s)
{
    char buf[8];
    strcpy(buf, s);
    escape(buf);
}
