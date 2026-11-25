/* SPDX-License-Identifier: BSD-3-Clause */

/* -fstack-clash-protection probe (runtime channel). */

#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

/* On Darwin the first line says whether Rosetta 2 translated the run; see the header. */
#define CHARD_WANT_TRANSLATION_REPORT
#include "chard_selfreport.h"

#define PROBE_LOW_KIB 256

static volatile unsigned char *g_sp_before;
static volatile unsigned long long g_alloc;

/* Async-signal-safe unsigned decimal append. */
static char *emit_ull(char *p, unsigned long long v)
{
    char tmp[32];
    int i = 0;
    if (v == 0) {
        *p++ = '0';
        return p;
    }
    while (v > 0 && i < (int) sizeof tmp) {
        tmp[i++] = (char) ('0' + (v % 10));
        v /= 10;
    }
    while (i-- > 0) {
        *p++ = tmp[i];
    }
    return p;
}

static void say(const char *s)
{
    (void) !write(1, s, strlen(s));
}

/* A declined reading from inside the handler: named, and never a distance. */
static void decline_in_handler(const char *s)
{
    say(s);
    _exit(CHARD_EXIT_DECLINED);
}

static void on_fault(int sig, siginfo_t *info, void *ctx)
{
    (void) sig;
    (void) ctx;

    char buf[160];
    char *p = buf;
    uintptr_t addr = (uintptr_t) info->si_addr;
    uintptr_t sp = (uintptr_t) g_sp_before;
    unsigned long long n = g_alloc;

    /* A fault before the size was recorded is not the allocation's. */
    if (n == 0) {
        decline_in_handler("SCPRT probe-invalid=fault-before-allocation\n");
    }
    if (addr == 0) {
        decline_in_handler("SCPRT probe-invalid=no-fault-address\n");
    }
    if (addr >= sp) {
        decline_in_handler("SCPRT probe-invalid=fault-above-frame\n");
    }

    /* How far below the caller's frame the first touch landed. */
    unsigned long long dist = (unsigned long long) (sp - addr);
    unsigned long long ratio = (dist * 100ULL) / n;

    memcpy(p, "SCPRT dist=", 11);
    p += 11;
    p = emit_ull(p, dist);
    memcpy(p, " n=", 3);
    p += 3;
    p = emit_ull(p, n);
    memcpy(p, " ratio_pct=", 11);
    p += 11;
    p = emit_ull(p, ratio);
    *p++ = '\n';
    (void) !write(1, buf, (size_t) (p - buf));

    _exit(0);
}

int main(void)
{
    struct rlimit rl;
    chard_report_translation();
    if (getrlimit(RLIMIT_STACK, &rl) != 0) {
        say("SCPRT probe-invalid=no-rlimit\n");
        return CHARD_EXIT_DECLINED;
    }
    /*An unbounded stack gives nothing to size the allocation from, and a tiny one cannot produce a
     *meaningful ratio. */
    if (rl.rlim_cur == RLIM_INFINITY) {
        say("SCPRT probe-invalid=unbounded-stack\n");
        return CHARD_EXIT_DECLINED;
    }
    if (rl.rlim_cur < (rlim_t) (PROBE_LOW_KIB * 1024)) {
        say("SCPRT probe-invalid=stack-too-small\n");
        return CHARD_EXIT_DECLINED;
    }

    static char altbuf[1 << 16];
    stack_t alt;
    alt.ss_sp = altbuf;
    alt.ss_size = sizeof altbuf;
    alt.ss_flags = 0;
    if (sigaltstack(&alt, NULL) != 0) {
        say("SCPRT probe-invalid=no-altstack\n");
        return CHARD_EXIT_DECLINED;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0 || sigaction(SIGBUS, &sa, NULL) != 0) {
        say("SCPRT probe-invalid=no-handler\n");
        return CHARD_EXIT_DECLINED;
    }

    unsigned char here;
    g_sp_before = &here;
    uintptr_t sp = (uintptr_t) &here;

    /*Eight times the stack limit, so the allocation certainly overruns it and the only question is
     *where the first touch lands. */
    unsigned long long lim = (unsigned long long) rl.rlim_cur;
    if (lim > ULLONG_MAX / 8ULL || lim * 8ULL > (unsigned long long) SIZE_MAX) {
        say("SCPRT probe-invalid=allocation-overflow\n");
        return CHARD_EXIT_DECLINED;
    }
    unsigned long long n = lim * 8ULL;
    if (n >= (unsigned long long) sp) {
        say("SCPRT probe-invalid=address-wrap\n");
        return CHARD_EXIT_DECLINED;
    }
    const uintptr_t half = (UINTPTR_MAX >> 1) + 1;
    if (sp >= half && sp - (uintptr_t) n < half) {
        say("SCPRT probe-invalid=sign-boundary\n");
        return CHARD_EXIT_DECLINED;
    }
    g_alloc = n;

    {
        unsigned char vla[(size_t) n];
        /* The launder. */
        __asm__ volatile("" : : "r"(vla) : "memory");
        vla[0] = 1;
        __asm__ volatile("" : : "r"(vla) : "memory");
    }

    say("SCPRT probe-invalid=no-fault\n");
    return CHARD_EXIT_DECLINED;
}
