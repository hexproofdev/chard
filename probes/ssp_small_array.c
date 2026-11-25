/* SPDX-License-Identifier: BSD-3-Clause */

/* --param ssp-buffer-size probe (elf-static channel). */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/* Four bytes: below the default threshold of eight, above nothing. */
__attribute__((noinline)) static void small_array(void) {
    char buf[4];
    if (scanf("%3s", buf) == 1) {
        printf("%s", buf);
    }
}

int main(void) {
    small_array();
    return 0;
}
