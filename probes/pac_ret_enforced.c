/* SPDX-License-Identifier: BSD-3-Clause */

/* AArch64 return-address authentication probe (runtime channel). */

#define _GNU_SOURCE
#define CHARD_WANT_FAULT_REPORT
#define CHARD_WANT_NOT_DUMPABLE
#define CHARD_WANT_TRANSLATION_REPORT
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#endif

#include "chard_selfreport.h"

#if defined(__aarch64__) && defined(__linux__)

#ifndef HWCAP_CPUID
#define HWCAP_CPUID (1UL << 11)
#endif
#ifndef HWCAP_PACA
#define HWCAP_PACA (1UL << 30)
#endif

/* Reached only through the overwritten return address. */
__attribute__((noinline, used)) static void chard_pac_marker(void)
{
    static const char line[] = "PAC return=hijacked\n";
    if (write(1, line, sizeof line - 1) < 0) {
        /* Nothing to do: the exit status below is the reading either way. */
    }
    _exit(0);
}

__attribute__((noinline)) static void chard_pac_callee(void)
{
    __asm__ volatile("" : : : "memory");
}

/* Not a leaf, so its return address is saved, signed, in its frame record, which it overwrites
 * with the marker's, unsigned. */
__attribute__((noinline)) static void chard_pac_victim(void)
{
    void **frame;
    chard_pac_callee();
    frame = __builtin_frame_address(0);
    frame[1] = (void *)chard_pac_marker;
    __asm__ volatile("" : : : "memory");
}

/*FEAT_FPAC: APA [7:4] or API [11:8] of ID_AA64ISAR1_EL1, or APA3 [15:12] of ID_AA64ISAR2_EL1, at 4
 *or more. */
static const char *chard_fpac(unsigned long hwcap)
{
    unsigned long isar1 = 0;
    unsigned long isar2 = 0;
    if (!(hwcap & HWCAP_CPUID)) {
        return "unread";
    }
    __asm__ volatile("mrs %0, ID_AA64ISAR1_EL1" : "=r"(isar1));
    __asm__ volatile("mrs %0, S3_0_C0_C6_2" : "=r"(isar2));
    if (((isar1 >> 4) & 0xf) >= 4 || ((isar1 >> 8) & 0xf) >= 4 || ((isar2 >> 12) & 0xf) >= 4) {
        return "yes";
    }
    return "no";
}

int main(void)
{
    unsigned long hwcap;

    CHARD_NOT_DUMPABLE;
    chard_report_translation();
    chard_report_faults();

    hwcap = getauxval(AT_HWCAP);
    printf("PAC hwcap=%s fpac=%s\n", (hwcap & HWCAP_PACA) ? "yes" : "no", chard_fpac(hwcap));
    chard_declare_fault_target((const void *)chard_pac_marker);

    printf("PAC return=attempted\n");
    fflush(stdout);
    chard_pac_victim();
    printf("PAC return=returned\n");
    return 0;
}

#else

int main(void)
{
    chard_report_translation();
#if defined(__aarch64__)
    printf("PAC unsupported-os\n");
#else
    printf("PAC unsupported-arch\n");
#endif
    return 0;
}

#endif
