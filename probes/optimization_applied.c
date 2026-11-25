/* SPDX-License-Identifier: BSD-3-Clause */

/*Whether the compiler optimised, read from the object it produced rather than from the preprocessor
 *state it reports. */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

#undef chard_opt_anchor
#undef chard_opt_dead
#undef chard_opt_probe
#undef keep
#undef if
#undef int
#undef void
#undef extern
#undef __attribute__
#undef used

extern void chard_opt_anchor(void);
extern void chard_opt_dead(void);

__attribute__((used)) void chard_opt_probe(void)
{
    int keep = 0;

    chard_opt_anchor();
    if (keep) {
        chard_opt_dead();
    }
}
