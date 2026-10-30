/* SPDX-License-Identifier: BSD-3-Clause */

/* Provokes one fault per build, through the fault reporter in chard_selfreport.h, for
 * tests/fault_report.rs. The case is chosen at compile time, since chard's runner passes
 * a probe no arguments: -DCHARD_FAULT_CASE='"trap"', or one of udf, ud1, int3, segv,
 * jump-unmapped, trap-elsewhere, kill, raise, bus, overflow, page-end (x86), pac, bti-declared, bti-undeclared,
 * bti-landing. Run by hand, argv[1] names it instead. `overflow` is a signed overflow,
 * built with a sanitizer trap or -ftrapv by the caller. The aarch64 cases are for
 * -mbranch-protection=standard builds. */
#define _GNU_SOURCE
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#define CHARD_WANT_FAULT_REPORT
#include "chard_selfreport.h"
#ifndef PROT_BTI
#define PROT_BTI 0x10
#endif

#if defined(__aarch64__)
__attribute__((noinline)) static void corrupt_own_return(void)
{
    /* The clobber of x30 makes the function save and sign its return address
     * under pac-ret even where the compiler would otherwise treat it as a leaf,
     * which gcc's -mbranch-protection=standard does not sign. */
    __asm__ volatile("" ::: "x30");
    volatile uintptr_t *frame = __builtin_frame_address(0);
    frame[1] ^= (uintptr_t)1 << 50;
}

static int branch_to_page(int landing_pad, int declare)
{
    uint32_t *code = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int i = 0;
    if (code == MAP_FAILED)
        return 2;
    if (landing_pad)
        code[i++] = 0xd503245f; /* bti c */
    code[i++] = 0xd28000e0; /* mov x0, #7 */
    code[i++] = 0xd65f03c0; /* ret */
    __builtin___clear_cache((char *)code, (char *)(code + i));
    if (mprotect(code, 4096, PROT_READ | PROT_EXEC | PROT_BTI) != 0)
        return 3;
    if (declare)
        chard_declare_fault_target(code);
    int (*volatile f)(void) = (int (*)(void))(uintptr_t)code;
    printf("returned %d\n", f());
    return 0;
}
#endif

int main(int argc, char **argv)
{
#ifdef CHARD_FAULT_CASE
    const char *w = CHARD_FAULT_CASE;
    (void)argc;
    (void)argv;
#else
    const char *w = argc > 1 ? argv[1] : "";
#endif
    setvbuf(stdout, NULL, _IONBF, 0);
    chard_report_faults();
    if (!strcmp(w, "trap"))
        __builtin_trap();
    if (!strcmp(w, "segv"))
        *(volatile int *)8 = 1;
    if (!strcmp(w, "jump-unmapped")) {
        void (*volatile wild)(void) = (void (*)(void))(uintptr_t)16;
        wild();
    }
    if (!strcmp(w, "trap-elsewhere")) {
        chard_declare_fault_target((const void *)(uintptr_t)&main);
        __builtin_trap();
    }
    if (!strcmp(w, "kill"))
        kill(getpid(), SIGILL);
    if (!strcmp(w, "raise"))
        raise(SIGILL);
    if (!strcmp(w, "bus")) {
        /* A read from a shared mapping of an empty file is past its end: SIGBUS. */
        int fd = memfd_create("chard-fault-bus", 0);
        volatile const char *past;
        if (fd < 0)
            return 4;
        past = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0);
        if (past == MAP_FAILED)
            return 5;
        printf("%d\n", past[0]);
    }
    if (!strcmp(w, "overflow")) {
        volatile int x = INT_MAX;
        x += argc;
        printf("%d\n", x);
    }
#if defined(__aarch64__)
    if (!strcmp(w, "udf"))
        __asm__ volatile("udf #0");
    if (!strcmp(w, "bti-declared"))
        return branch_to_page(0, 1);
    if (!strcmp(w, "bti-undeclared"))
        return branch_to_page(0, 0);
    if (!strcmp(w, "bti-landing"))
        return branch_to_page(1, 1);
    if (!strcmp(w, "pac"))
        corrupt_own_return();
#endif
#if defined(__x86_64__) || defined(__i386__)
    if (!strcmp(w, "ud1"))
        __asm__ volatile("ud1 %eax, %eax");
    if (!strcmp(w, "int3"))
        __asm__ volatile("int3");
    if (!strcmp(w, "page-end")) {
        /* ud2 in the last two bytes of a page whose successor is unmapped: the
         * reporter must read the two bytes it can and stop at the page end. */
        unsigned char *two = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        void (*volatile at_end)(void);
        if (two == MAP_FAILED || munmap(two + 4096, 4096) != 0)
            return 2;
        two[4094] = 0x0f;
        two[4095] = 0x0b;
        if (mprotect(two, 4096, PROT_READ | PROT_EXEC) != 0)
            return 3;
        at_end = (void (*)(void))(uintptr_t)(two + 4094);
        at_end();
    }
#endif
    printf("survived %s\n", w);
    return 0;
}
