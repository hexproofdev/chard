/* SPDX-License-Identifier: BSD-3-Clause */

/*Link-level probe for the `elf-static` channel: PIE, RELRO, NX, nodlopen, DT_RELR, CET markings. */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

int main(void)
{
    /* Referencing the report keeps it alive even on a toolchain that honors
     * neither `used` nor `retain`, and printing the marker lets a human confirm
     * the mechanism worked without reaching for readelf. */
    puts(chard_report);
    return 0;
}
