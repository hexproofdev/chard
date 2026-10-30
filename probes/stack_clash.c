/* SPDX-License-Identifier: BSD-3-Clause */

/* -fstack-clash-protection probe (runtime channel).
 *
 * The mitigation stops a large stack allocation from *jumping over* the guard
 * page. Without it the prologue subtracts the whole frame from the stack pointer
 * in one step, so the first memory touched can be far below the guard and may
 * land in an unrelated mapping, the stack-clash primitive. With it the prologue
 * walks down a page at a time, touching each, so the guard page is hit and the
 * process dies there instead.
 *
 * So the observable is not *whether* the process faults (it faults either way)
 * but **where**. That distinction is what makes both directions affirmative:
 *
 *   probing on  -> first touch is one page below the frame        -> ratio ~12%
 *   probing off -> first touch is the full allocation below it    -> ratio 100%
 *
 * `ratio_pct = 100 * (sp_before - fault_addr) / n`. Reporting a percentage rather
 * than an address keeps the verdict independent of where the stack happens to sit
 * and of the guard size, which is tunable.
 *
 * Three details are load-bearing, and each was established by measurement rather
 * than assumed:
 *
 *   - The VLA must be laundered through `asm volatile`. Without it gcc and clang
 *     both fold the allocation away entirely and the probe reports no fault in
 *     *every* arm, positive control included, the two arms produce byte-identical
 *     binaries. This is the trap that defeats the obvious version of this probe.
 *
 *   - The fault must be caught on a `sigaltstack`. The stack pointer is by then
 *     far outside the mapped stack, so an ordinary handler cannot be entered and
 *     the process dies without reporting anything.
 *
 *   - `RLIMIT_STACK` must be finite and known, because the allocation is sized
 *     from it. An unbounded stack yields a declined probe
 *     (`CHARD_EXIT_DECLINED`) rather than a guess.
 *
 *   - The allocation must fit below the frame, and the reading must be arithmetic
 *     that cannot wrap. A failure of either prints a ratio the decoder reads as
 *     `present` (measured on 2026-10-05; i386: Debian 12 gcc 12.2.0, Fedora 44
 *     gcc 16.2.1 and clang 22.1.8 `-m32`, in compat mode on a
 *     64-bit kernel 7.3.0-rc3; x86_64: gcc 16.1.1 and clang 22.1.8 natively on
 *     the same kernel, 4-level paging):
 *       - On i386, `unsigned long` is 32 bits. In it `100 * dist` wraps for any
 *         allocation above 2^32 / 100 bytes, so a probing-off build at the default
 *         8 MiB limit prints `dist=67108879 n=67108864 ratio_pct=36`, and
 *         `rlim_cur * 8` wraps from a 512 MiB limit up. The size and the ratio
 *         are `unsigned long long`, and a size that does not fit `size_t` is
 *         declined (`allocation-overflow`).
 *       - Where the allocation is at least the frame's address (a 16 TiB limit on
 *         4-level x86_64, or on i386 a size wrapped to just under 4 GiB by a
 *         limit of 4 GiB minus 1 KiB), `sp - n` wraps. The first
 *         touch then lands above the frame, which a handler clamping to `dist=0`
 *         reads as ratio 0, or at a non-canonical address whose fault
 *         carries `si_addr` 0, which made `dist` the frame's own address and the
 *         ratio 24, 15 or 1. Both are declined before allocating
 *         (`address-wrap`), and the handler declines the two fault shapes
 *         themselves (`fault-above-frame`, `no-fault-address`) rather than
 *         turning them into a distance.
 *       - On i386 clang 22.1.8 compares addresses signed in the dynamic-alloca
 *         probe loop, so an allocation whose bottom crosses the middle of the
 *         address space skips the loop and touches the full allocation first,
 *         a codegen boundary rather than the flag. An allocation that would cross
 *         it is declined (`sign-boundary`); a 64-bit user stack never reaches it.
 *
 * `-fstack-check` produces the same observable through a different mechanism and
 * is not countermanded by `-fno-stack-clash-protection`, so the check declares a
 * regime arm (`Regime::Arm`): a profile enabling stack-check would otherwise be
 * credited to this flag.
 *
 * gcc's `-fhardened` overrides the countermand the same way: it turns stack-clash
 * protection on beside an explicit `-fno-stack-clash-protection`, in either order
 * and with no `-Whardened` warning, while the stack protector, `_FORTIFY_SOURCE`,
 * `-fcf-protection`, `-ftrivial-auto-var-init` and the linker's PIE, RELRO and
 * `-z now` each yield to an explicit countermand and draw a `-Whardened` warning
 * (checked on Fedora 44 gcc 16.1.1), so an arm built with both reads
 * about 12%. The check withholds in both shapes: a driver adding `-fhardened` to
 * every build reads `probe-invalid` with `negative-also-shows` (the negative arm
 * reads 12% too), and a profile passing `-fhardened` reads `probe-invalid` with
 * `regime-confounded` (the regime arm reads 12%, the plain negative 100%). The 12%
 * reading was measured on x86_64 by building the probe by hand with Fedora 44 gcc
 * 16.1.1 and Wolfi gcc 14.4.0 and 16.2.0 (2026-10-15), where a
 * Wolfi gcc 14 wrapper adding `-fhardened` also read `negative-also-shows`; both
 * withheld shapes were measured through chard with Fedora 44 gcc 16.1.1.
 *
 * Output is written from a signal handler, so only async-signal-safe calls are
 * used: `write(2)` and a hand-rolled integer formatter, never printf.
 */

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

/* Async-signal-safe unsigned decimal append. Returns the new end pointer. */
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

    /* A fault before the size was recorded is not the allocation's. One at
     * address 0 is how a non-canonical access arrives (#GP, not a page fault),
     * and one at or above the frame is a wrapped allocation's: neither is a
     * distance below the frame, so neither may become one. */
    if (n == 0) {
        decline_in_handler("SCPRT probe-invalid=fault-before-allocation\n");
    }
    if (addr == 0) {
        decline_in_handler("SCPRT probe-invalid=no-fault-address\n");
    }
    if (addr >= sp) {
        decline_in_handler("SCPRT probe-invalid=fault-above-frame\n");
    }

    /* How far below the caller's frame the first touch landed. In 64 bits on
     * every target: a pointer difference times 100 does not fit 32. */
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
    /* An unbounded stack gives nothing to size the allocation from, and a tiny one
     * cannot produce a meaningful ratio. Both are refusals, not guesses. */
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

    /* Eight times the stack limit, so the allocation certainly overruns it and the
     * only question is where the first touch lands. Computed where it cannot wrap,
     * and declined where it does not fit a size or the address space below the
     * frame: a wrapped size or a wrapped `sp - n` puts the first touch somewhere
     * the ratio does not describe. */
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
        /* The launder. Without it both compilers delete the allocation and no arm
         * ever faults, which makes the control triple non-discriminating while
         * looking like a working probe. */
        __asm__ volatile("" : : "r"(vla) : "memory");
        vla[0] = 1;
        __asm__ volatile("" : : "r"(vla) : "memory");
    }

    say("SCPRT probe-invalid=no-fault\n");
    return CHARD_EXIT_DECLINED;
}
