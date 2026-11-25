/* SPDX-License-Identifier: BSD-3-Clause */

/* AArch64 BTI enforcement probe (runtime channel). */

#define _GNU_SOURCE
#define CHARD_WANT_FAULT_REPORT
#define CHARD_WANT_NOT_DUMPABLE
#define CHARD_WANT_TRANSLATION_REPORT
#include <stdio.h>
#include <stdlib.h>

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#endif

#include "chard_selfreport.h"

#if defined(__aarch64__) && defined(__linux__)

#ifndef HWCAP2_BTI
#define HWCAP2_BTI (1UL << 17)
#endif

/*No landing pad: the first instruction is a `mov`, whatever `-mbranch-protection` says, since
 *top-level assembly is not the compiler's to instrument. */
__asm__(".text\n"
        "\t.balign 4\n"
        "\t.type chard_bti_target, %function\n"
        "chard_bti_target:\n"
        "\tmov w0, #42\n"
        "\tret\n"
        "\t.size chard_bti_target, .-chard_bti_target\n");

int chard_bti_target(void);

int main(void)
{
    int (*target)(void) = chard_bti_target;
    int returned;
    unsigned long hwcap2;

    CHARD_NOT_DUMPABLE;
    chard_report_translation();
    chard_report_faults();

    hwcap2 = getauxval(AT_HWCAP2);
    printf("BTI hwcap=%s\n", (hwcap2 & HWCAP2_BTI) ? "yes" : "no");

    /* The pointer passes through an empty asm, so the call below stays an indirect `blr`. */
    __asm__ volatile("" : "+r"(target) : : "memory");
    chard_declare_fault_target((const void *)target);

    printf("BTI branch=attempted\n");
    fflush(stdout);
    returned = target();
    printf("BTI branch=landed returned=%d\n", returned);
    return 0;
}

#else

int main(void)
{
    chard_report_translation();
#if defined(__aarch64__)
    printf("BTI unsupported-os\n");
#else
    printf("BTI unsupported-arch\n");
#endif
    return 0;
}

#endif
