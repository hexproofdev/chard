/* SPDX-License-Identifier: BSD-3-Clause */

/* Is the stack executable at runtime? (runtime channel)
 *
 * `noexecstack` reads the request a binary makes of the kernel, its PT_GNU_STACK. This
 * probe reads the answer: it copies a few bytes of machine code into a buffer on main's
 * stack, calls them, and reports which of two things happened.
 *
 *   NXRT stack-exec=yes ret=77         the bytes ran and returned their marker
 *   NXRT stack-exec=no fault=payload   SIGSEGV whose fault address is the buffer itself
 *
 * Both are affirmative. The second is not "it crashed": the handler compares si_addr
 * with the buffer's address, so a fault anywhere else (a bad build, a stray pointer, a
 * CFI trap) prints `fault=elsewhere` and the detector withholds. A fault at the first
 * byte of the payload, on an instruction fetch, is the kernel's NX mapping and nothing
 * else.
 *
 * The recipe this rests on (`noexecstack-absent-runtime`) measured why a naive version
 * lies: with `return fn();` gcc -O2 popped the frame and tail-jumped into the buffer, and
 * elided the copy of the bytes altogether, so an executable stack read as non-executable.
 * Each of the following closes one way the optimizer can take the observable away:
 *
 *   - The payload's address passes through an empty `asm volatile` with a memory
 *     clobber, so the compiler cannot see what the call targets or prove the copied
 *     bytes are dead.
 *   - The call's result is printed afterwards, so the call cannot be a tail call and
 *     main's frame (and the buffer in it) is live while the payload runs.
 *   - The payload returns rather than making a raw exit syscall, and the marker (77) is
 *     a value main's own exit path never produces, so a fall-through cannot read as a
 *     run of the payload.
 *
 * aarch64 has separate instruction and data caches, so the copy is followed by
 * `__builtin___clear_cache` over the buffer. Without it the fetch may see stale bytes
 * and fault with SIGILL, which this probe reports as `fault=sigill`, never as either
 * answer. x86 keeps instruction fetch coherent with stores and the builtin emits no cache
 * maintenance there (the launders around it keep the copy), so on x86_64 the call is left
 * out where the compiler does not know it:
 * clang 3.4 (Ubuntu 14.04) rejected it as an unknown builtin, and the probe did not build
 * (measured 2026-10-07). gcc has had it since 4.3, before `__has_builtin`.
 *
 * Each payload starts with its architecture's landing pad (`endbr64`, `bti c`), so an
 * indirect-branch enforcement that some day covers this page does not turn an
 * executable stack into a fault the detector would have to explain. Both are no-ops on
 * a CPU or page that does not enforce them.
 *
 * A fault at the buffer says something about main's stack only if the buffer is on it.
 * clang's -fsanitize=safe-stack moves an array whose address escapes onto a separate
 * unsafe stack it maps read-write, and the probe faulted at the payload under that flag
 * with -z execstack as well as -z noexecstack (measured 2026-10-02, Fedora 44 x86_64,
 * clang 22.1.8). So before the call the probe checks that the buffer lies below `argv`,
 * which the kernel places at the top of the initial stack, and within 1 MiB of it, and
 * otherwise prints `probe-invalid=buffer-not-on-the-initial-stack` and does not call.
 *
 * Output from the handler uses only write(2) and _exit(2).
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* On Darwin the first line says whether Rosetta 2 translated the run; see the header. */
#define CHARD_WANT_TRANSLATION_REPORT
#include "chard_selfreport.h"

#if defined(__x86_64__)
#define NXRT_ARCH "x86_64"
static const unsigned char payload[] = {
    0xf3, 0x0f, 0x1e, 0xfa,       /* endbr64           */
    0xb8, 0x4d, 0x00, 0x00, 0x00, /* mov $77, %eax     */
    0xc3,                         /* ret               */
};
#elif defined(__aarch64__) && defined(__AARCH64EL__)
#define NXRT_ARCH "aarch64"
static const uint32_t payload[] = {
    0xd503245f, /* bti c            */
    0x528009a0, /* mov w0, #77      */
    0xd65f03c0, /* ret              */
};
#endif

#if defined(__has_builtin)
#if __has_builtin(__builtin___clear_cache)
#define NXRT_CLEAR_CACHE 1
#endif
#elif defined(__GNUC__)
#define NXRT_CLEAR_CACHE 1
#endif

static volatile uintptr_t g_payload_at;

static void say(const char *s)
{
    (void) !write(1, s, strlen(s));
}

static void on_fault(int sig, siginfo_t *info, void *ctx)
{
    (void) ctx;
    if (sig == SIGILL) {
        say("NXRT stack-exec=unknown fault=sigill\n");
    } else if ((uintptr_t) info->si_addr == g_payload_at) {
        say("NXRT stack-exec=no fault=payload\n");
    } else {
        say("NXRT stack-exec=unknown fault=elsewhere\n");
    }
    _exit(0);
}

/* How far below `argv` main's frame may be and still count as on the initial stack: the
 * kernel's argument, environment and auxiliary-vector block and the C library's start-up
 * frames lie between them, a few KiB in practice, while a separately mapped stack is
 * hundreds of MiB away. */
#define NXRT_STACK_WINDOW ((uintptr_t) 1 << 20)

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    chard_report_translation();
#ifndef NXRT_ARCH
    say("NXRT probe-invalid=no-payload-for-this-architecture\n");
    return CHARD_EXIT_DECLINED;
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fault;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0 || sigaction(SIGBUS, &sa, NULL) != 0
        || sigaction(SIGILL, &sa, NULL) != 0) {
        say("NXRT probe-invalid=no-handler\n");
        return CHARD_EXIT_DECLINED;
    }

    unsigned char buf[64] __attribute__((aligned(16)));
    unsigned char *code = buf;
    /* The launder: after this the compiler knows nothing about where `code` points. */
    __asm__ volatile("" : "+r"(code) : : "memory");
    memcpy(code, payload, sizeof payload);
#if defined(NXRT_CLEAR_CACHE) || !defined(__x86_64__)
    __builtin___clear_cache((char *) code, (char *) code + sizeof payload);
#endif
    __asm__ volatile("" : "+r"(code) : : "memory");
    g_payload_at = (uintptr_t) code;

    uintptr_t top = (uintptr_t) argv;
    if (g_payload_at >= top || top - g_payload_at > NXRT_STACK_WINDOW) {
        say("NXRT probe-invalid=buffer-not-on-the-initial-stack\n");
        return CHARD_EXIT_DECLINED;
    }

    int (*fn)(void) = (int (*)(void)) (uintptr_t) code;
    say("NXRT arch=" NXRT_ARCH " calling\n");
    int ret = fn();

    if (ret == 77) {
        say("NXRT stack-exec=yes ret=77\n");
    } else {
        printf("NXRT stack-exec=unknown ret=%d\n", ret);
        fflush(stdout);
    }
    return 0;
#endif
}
