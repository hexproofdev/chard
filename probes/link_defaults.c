/* SPDX-License-Identifier: BSD-3-Clause */

/* Link-level probe for the `elf-static` channel: PIE, RELRO, NX, nodlopen,
 * DT_RELR, CET markings.
 *
 * Deliberately a complete program rather than a bare `int main(){}`: it must pull
 * in the CRT and touch libc so that what we read back is the linker's real
 * default behavior on a normal executable. A degenerate link can produce
 * different program headers than any real build would, which would make every
 * verdict derived from it a fiction.
 *
 * This is also the probe that carries `.chard.report`, so the artifact records
 * the macro state that built it.
 */

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
