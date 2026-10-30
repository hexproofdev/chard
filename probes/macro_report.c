/* SPDX-License-Identifier: BSD-3-Clause */

/* Carries the macro state into a compiled artifact, so the macro channel can be
 * read from something the *compiler* produced rather than from a preprocessor run.
 *
 * The distinction is not academic. `cc -dM -E` is a separate job driven by
 * `*cpp_options`, while code generation is driven by `*cc1_options`. A spec file
 * that patches only one of them makes the two disagree, and a harness reading only
 * the preprocessor reports macros the generated code does not have, or misses ones
 * it does. Fedora's own `redhat-hardened-cc1` patches *both* stanzas with the same
 * line, which is a vendor working around exactly this.
 *
 * So this translation unit is compiled and linked like any other probe, and the
 * `.chard.report` section it carries is what the compiler believed while generating
 * code. Reading both that and `-dM -E` turns the split from a hazard into an
 * observable: when they differ, the difference is the finding.
 *
 * `<stdio.h>` comes first because `__USE_FORTIFY_LEVEL` is defined by glibc's
 * <features.h>, not by the compiler, and the header below reports whatever is
 * defined at the point it is included.
 */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

int main(void)
{
    puts(chard_report);
    return 0;
}
