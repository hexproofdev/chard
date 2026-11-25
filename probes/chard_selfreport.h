/* SPDX-License-Identifier: BSD-3-Clause */

/* Makes a probe binary testify about its own compilation. */

#ifndef CHARD_SELFREPORT_H
#define CHARD_SELFREPORT_H

/* --- the include-order precondition, enforced ------------------------------ */
#if defined(__linux__) && !defined(__ANDROID__) && !defined(_FEATURES_H)
#  error "chard_selfreport.h must be included after a libc header: <features.h> has not been seen, so __USE_FORTIFY_LEVEL and __GLIBC__ would report as undefined"
#elif defined(__APPLE__) && !defined(_CDEFS_H_)
#  error "chard_selfreport.h must be included after a libc header: <sys/cdefs.h> has not been seen, so _USE_FORTIFY_LEVEL would report as undefined"
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)) && !defined(_SYS_CDEFS_H_)
#  error "chard_selfreport.h must be included after a libc header: <sys/cdefs.h> has not been seen"
#endif

/* --- every header this file includes, before the first entry --------------- */
#if defined(CHARD_WANT_NOT_DUMPABLE) && defined(__linux__)
#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#endif
#if defined(CHARD_WANT_FAULT_REPORT) && defined(__linux__) \
    && (defined(__aarch64__) || defined(__x86_64__) || defined(__i386__))
#if !defined(_GNU_SOURCE)
#  error "CHARD_WANT_FAULT_REPORT needs _GNU_SOURCE defined before the first include"
#endif
#include <signal.h>
#include <string.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>
#endif
#if defined(CHARD_WANT_TRANSLATION_REPORT) && defined(__APPLE__)
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#endif

#define CHARD_REPORT_MARKER "CHARD-REPORT-V2"

#define CHARD__STR(x) #x
#define CHARD__XSTR(x) CHARD__STR(x)

/* --- compiler identity ---------------------------------------------------- */

#ifdef __GNUC__
#  define CHARD__R_GNUC "__GNUC__=" CHARD__XSTR(__GNUC__) "\n"
#else
#  define CHARD__R_GNUC "__GNUC__ undefined\n"
#endif

#ifdef __GNUC_MINOR__
#  define CHARD__R_GNUC_MINOR "__GNUC_MINOR__=" CHARD__XSTR(__GNUC_MINOR__) "\n"
#else
#  define CHARD__R_GNUC_MINOR "__GNUC_MINOR__ undefined\n"
#endif

#ifdef __clang_major__
#  define CHARD__R_CLANG "__clang_major__=" CHARD__XSTR(__clang_major__) "\n"
#else
#  define CHARD__R_CLANG "__clang_major__ undefined\n"
#endif

#ifdef __STDC_VERSION__
#  define CHARD__R_STDC "__STDC_VERSION__=" CHARD__XSTR(__STDC_VERSION__) "\n"
#else
#  define CHARD__R_STDC "__STDC_VERSION__ undefined\n"
#endif

/* --- optimization: FORTIFY is inert without it, so it belongs in the report - */

#ifdef __OPTIMIZE__
#  define CHARD__R_OPT "__OPTIMIZE__=" CHARD__XSTR(__OPTIMIZE__) "\n"
#else
#  define CHARD__R_OPT "__OPTIMIZE__ undefined\n"
#endif

#ifdef __NO_INLINE__
#  define CHARD__R_NOINLINE "__NO_INLINE__=" CHARD__XSTR(__NO_INLINE__) "\n"
#else
#  define CHARD__R_NOINLINE "__NO_INLINE__ undefined\n"
#endif

/* --- position independence ------------------------------------------------ */

#ifdef __PIC__
#  define CHARD__R_PIC "__PIC__=" CHARD__XSTR(__PIC__) "\n"
#else
#  define CHARD__R_PIC "__PIC__ undefined\n"
#endif

#ifdef __PIE__
#  define CHARD__R_PIE "__PIE__=" CHARD__XSTR(__PIE__) "\n"
#else
#  define CHARD__R_PIE "__PIE__ undefined\n"
#endif

/* --- stack protector: the four macros encode the level -------------------- */

#ifdef __SSP__
#  define CHARD__R_SSP "__SSP__=" CHARD__XSTR(__SSP__) "\n"
#else
#  define CHARD__R_SSP "__SSP__ undefined\n"
#endif

#ifdef __SSP_STRONG__
#  define CHARD__R_SSP_STRONG "__SSP_STRONG__=" CHARD__XSTR(__SSP_STRONG__) "\n"
#else
#  define CHARD__R_SSP_STRONG "__SSP_STRONG__ undefined\n"
#endif

#ifdef __SSP_ALL__
#  define CHARD__R_SSP_ALL "__SSP_ALL__=" CHARD__XSTR(__SSP_ALL__) "\n"
#else
#  define CHARD__R_SSP_ALL "__SSP_ALL__ undefined\n"
#endif

/* gcc's -fstack-protector-explicit, which instruments only functions marked
 * __attribute__((stack_protect)); clang rejects the flag and defines no such macro. */
#ifdef __SSP_EXPLICIT__
#  define CHARD__R_SSP_EXPLICIT "__SSP_EXPLICIT__=" CHARD__XSTR(__SSP_EXPLICIT__) "\n"
#else
#  define CHARD__R_SSP_EXPLICIT "__SSP_EXPLICIT__ undefined\n"
#endif

/* --- fortify: requested vs. what glibc settled on ------------------------- */

#ifdef _FORTIFY_SOURCE
#  define CHARD__R_FORTIFY "_FORTIFY_SOURCE=" CHARD__XSTR(_FORTIFY_SOURCE) "\n"
#else
#  define CHARD__R_FORTIFY "_FORTIFY_SOURCE undefined\n"
#endif

#ifdef __USE_FORTIFY_LEVEL
#  define CHARD__R_FORTIFY_EFF "__USE_FORTIFY_LEVEL=" CHARD__XSTR(__USE_FORTIFY_LEVEL) "\n"
#else
#  define CHARD__R_FORTIFY_EFF "__USE_FORTIFY_LEVEL undefined\n"
#endif

/*Apple's parallel to the macro above, and note the single leading underscore: this is
 *`_USE_FORTIFY_LEVEL`, defined by `<secure/_common.h>`, not glibc's `__USE_FORTIFY_LEVEL`. */
#ifdef _USE_FORTIFY_LEVEL
#  define CHARD__R_FORTIFY_APPLE "_USE_FORTIFY_LEVEL=" CHARD__XSTR(_USE_FORTIFY_LEVEL) "\n"
#else
#  define CHARD__R_FORTIFY_APPLE "_USE_FORTIFY_LEVEL undefined\n"
#endif

/*FreeBSD's level macro, from `<ssp/ssp.h>`, which `<string.h>` and the other wrapped headers reach
 *only under `_FORTIFY_SOURCE > 0`. */
#ifdef __SSP_FORTIFY_LEVEL
#  define CHARD__R_FORTIFY_FREEBSD "__SSP_FORTIFY_LEVEL=" CHARD__XSTR(__SSP_FORTIFY_LEVEL) "\n"
#else
#  define CHARD__R_FORTIFY_FREEBSD "__SSP_FORTIFY_LEVEL undefined\n"
#endif

/* Which implementation is providing the wrappers, because they fail differently. */
#ifdef _FORTIFY_HEADERS_H
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL=fortify-headers\n"
#elif defined(__USE_FORTIFY_LEVEL) && __USE_FORTIFY_LEVEL > 0
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL=glibc\n"
#elif defined(__APPLE__) && defined(_USE_FORTIFY_LEVEL) && _USE_FORTIFY_LEVEL > 0
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL=apple\n"
#elif defined(__FreeBSD__) && defined(__SSP_FORTIFY_LEVEL) && __SSP_FORTIFY_LEVEL > 0
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL=freebsd\n"
#else
#  define CHARD__R_FORTIFY_IMPL "_FORTIFY_IMPL undefined\n"
#endif

/* The guard itself as well as the summary: a predicate reads it beside `_FORTIFY_IMPL`,
 * and chard holds each entry to the `-dM -E` dump of the same unit, which a summary no
 * preprocessor defines cannot be. */
#ifdef _FORTIFY_HEADERS_H
#  define CHARD__R_FORTIFY_HEADERS "_FORTIFY_HEADERS_H=" CHARD__XSTR(_FORTIFY_HEADERS_H) "\n"
#else
#  define CHARD__R_FORTIFY_HEADERS "_FORTIFY_HEADERS_H undefined\n"
#endif

/* --- control-flow integrity ----------------------------------------------- */

#ifdef __CET__
#  define CHARD__R_CET "__CET__=" CHARD__XSTR(__CET__) "\n"
#else
#  define CHARD__R_CET "__CET__ undefined\n"
#endif

#ifdef __ARM_FEATURE_BTI_DEFAULT
#  define CHARD__R_BTI "__ARM_FEATURE_BTI_DEFAULT=" CHARD__XSTR(__ARM_FEATURE_BTI_DEFAULT) "\n"
#else
#  define CHARD__R_BTI "__ARM_FEATURE_BTI_DEFAULT undefined\n"
#endif

#ifdef __ARM_FEATURE_PAC_DEFAULT
#  define CHARD__R_PAC "__ARM_FEATURE_PAC_DEFAULT=" CHARD__XSTR(__ARM_FEATURE_PAC_DEFAULT) "\n"
#else
#  define CHARD__R_PAC "__ARM_FEATURE_PAC_DEFAULT undefined\n"
#endif

/*Guarded Control Stack: the third bit in the same feature word as BTI and PAC, and aarch64's
 *counterpart to the x86 shadow stack reported above through __CET__. */
#ifdef __ARM_FEATURE_GCS_DEFAULT
#  define CHARD__R_GCS "__ARM_FEATURE_GCS_DEFAULT=" CHARD__XSTR(__ARM_FEATURE_GCS_DEFAULT) "\n"
#else
#  define CHARD__R_GCS "__ARM_FEATURE_GCS_DEFAULT undefined\n"
#endif

/* --- libc / C++ library hardening ----------------------------------------- */

#ifdef __GLIBC__
#  define CHARD__R_GLIBC "__GLIBC__=" CHARD__XSTR(__GLIBC__) "\n"
#else
#  define CHARD__R_GLIBC "__GLIBC__ undefined\n"
#endif

#ifdef __GLIBC_MINOR__
#  define CHARD__R_GLIBC_MINOR "__GLIBC_MINOR__=" CHARD__XSTR(__GLIBC_MINOR__) "\n"
#else
#  define CHARD__R_GLIBC_MINOR "__GLIBC_MINOR__ undefined\n"
#endif

/*FreeBSD's libc announces itself through the platform macro alone, as OpenBSD's and Apple's do, and
 *its value is the release major, which is the libc's too, since the two ship together. */
#ifdef __FreeBSD__
#  define CHARD__R_FREEBSD "__FreeBSD__=" CHARD__XSTR(__FreeBSD__) "\n"
#else
#  define CHARD__R_FREEBSD "__FreeBSD__ undefined\n"
#endif

#ifdef _GLIBCXX_ASSERTIONS
#  define CHARD__R_GLIBCXX "_GLIBCXX_ASSERTIONS=" CHARD__XSTR(_GLIBCXX_ASSERTIONS) "\n"
#else
#  define CHARD__R_GLIBCXX "_GLIBCXX_ASSERTIONS undefined\n"
#endif

/*Which C++ standard library is providing the headers, because the two answer the hardening question
 *with different macros and a build with neither macro defined is ambiguous without it. */
#if defined(_LIBCPP_VERSION)
#  define CHARD__R_CXX_STDLIB "_CXX_STDLIB=libc++\n"
#elif defined(__GLIBCXX__)
#  define CHARD__R_CXX_STDLIB "_CXX_STDLIB=libstdc++\n"
#else
#  define CHARD__R_CXX_STDLIB "_CXX_STDLIB undefined\n"
#endif

/* The two version macros as well, for the reason `_FORTIFY_HEADERS_H` is reported beside
 * `_FORTIFY_IMPL`: the summary's inputs are each held to the dump. */
#ifdef _LIBCPP_VERSION
#  define CHARD__R_LIBCPP_VERSION "_LIBCPP_VERSION=" CHARD__XSTR(_LIBCPP_VERSION) "\n"
#else
#  define CHARD__R_LIBCPP_VERSION "_LIBCPP_VERSION undefined\n"
#endif

#ifdef __GLIBCXX__
#  define CHARD__R_GLIBCXX_VERSION "__GLIBCXX__=" CHARD__XSTR(__GLIBCXX__) "\n"
#else
#  define CHARD__R_GLIBCXX_VERSION "__GLIBCXX__ undefined\n"
#endif

#ifdef _LIBCPP_HARDENING_MODE
#  define CHARD__R_LIBCPP "_LIBCPP_HARDENING_MODE=" CHARD__XSTR(_LIBCPP_HARDENING_MODE) "\n"
#else
#  define CHARD__R_LIBCPP "_LIBCPP_HARDENING_MODE undefined\n"
#endif

/* --- sanitizers and semantics --------------------------------------------- */

#ifdef __SANITIZE_ADDRESS__
#  define CHARD__R_ASAN "__SANITIZE_ADDRESS__=" CHARD__XSTR(__SANITIZE_ADDRESS__) "\n"
#else
#  define CHARD__R_ASAN "__SANITIZE_ADDRESS__ undefined\n"
#endif

#ifdef __SANITIZE_UNDEFINED__
#  define CHARD__R_UBSAN "__SANITIZE_UNDEFINED__=" CHARD__XSTR(__SANITIZE_UNDEFINED__) "\n"
#else
#  define CHARD__R_UBSAN "__SANITIZE_UNDEFINED__ undefined\n"
#endif

#ifdef __EXCEPTIONS
#  define CHARD__R_EXCEPTIONS "__EXCEPTIONS=" CHARD__XSTR(__EXCEPTIONS) "\n"
#else
#  define CHARD__R_EXCEPTIONS "__EXCEPTIONS undefined\n"
#endif

/* -ffast-math weakens rather than hardens; recorded so a report can flag it. */
#ifdef __FAST_MATH__
#  define CHARD__R_FASTMATH "__FAST_MATH__=" CHARD__XSTR(__FAST_MATH__) "\n"
#else
#  define CHARD__R_FASTMATH "__FAST_MATH__ undefined\n"
#endif

#ifdef _FILE_OFFSET_BITS
#  define CHARD__R_FOB "_FILE_OFFSET_BITS=" CHARD__XSTR(_FILE_OFFSET_BITS) "\n"
#else
#  define CHARD__R_FOB "_FILE_OFFSET_BITS undefined\n"
#endif

#define CHARD_REPORT_BODY \
    CHARD__R_GNUC CHARD__R_GNUC_MINOR CHARD__R_CLANG CHARD__R_STDC \
    CHARD__R_OPT CHARD__R_NOINLINE \
    CHARD__R_PIC CHARD__R_PIE \
    CHARD__R_SSP CHARD__R_SSP_STRONG CHARD__R_SSP_ALL CHARD__R_SSP_EXPLICIT \
    CHARD__R_FORTIFY CHARD__R_FORTIFY_EFF CHARD__R_FORTIFY_APPLE CHARD__R_FORTIFY_FREEBSD \
    CHARD__R_FORTIFY_IMPL CHARD__R_FORTIFY_HEADERS \
    CHARD__R_CET CHARD__R_BTI CHARD__R_PAC CHARD__R_GCS \
    CHARD__R_GLIBC CHARD__R_GLIBC_MINOR CHARD__R_FREEBSD CHARD__R_GLIBCXX CHARD__R_LIBCPP \
    CHARD__R_CXX_STDLIB CHARD__R_LIBCPP_VERSION CHARD__R_GLIBCXX_VERSION \
    CHARD__R_ASAN CHARD__R_UBSAN CHARD__R_EXCEPTIONS CHARD__R_FASTMATH \
    CHARD__R_FOB

/* `retain` keeps the section through `--gc-sections`; it needs GCC 11 / Clang 13,
 * so it is applied only where supported rather than failing the build on older
 * toolchains we still want to measure.
 */
#if defined(__has_attribute)
#  if __has_attribute(retain)
#    define CHARD__RETAIN , retain
#  endif
#endif
#ifndef CHARD__RETAIN
#  define CHARD__RETAIN
#endif

/* Mach-O needs "segment,section"; ELF takes the bare name. */
#if defined(__APPLE__)
#  define CHARD__REPORT_SECTION section("__DATA,.chard.report")
#else
#  define CHARD__REPORT_SECTION section(".chard.report")
#endif

#define CHARD_EMIT_REPORT \
    __attribute__((used CHARD__RETAIN, CHARD__REPORT_SECTION)) \
    static const char chard_report[] = \
        CHARD_REPORT_MARKER "\n" CHARD_REPORT_BODY "CHARD-REPORT-END\n"

/* Print the same report on stdout, for readers with no object-format reader. */
#define CHARD_PRINT_REPORT \
    do { \
        fputs(chard_report, stdout); \
        fflush(stdout); \
    } while (0)

/* --- no core, for probes that crash in their own process -------------------- */
#if defined(CHARD_WANT_NOT_DUMPABLE) && defined(__linux__)
#define CHARD_NOT_DUMPABLE \
    do { \
        if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) { \
            fprintf(stdout, "chard-note dumpable-unset errno=%d\n", errno); \
            fflush(stdout); \
        } \
    } while (0)
#elif defined(CHARD_WANT_NOT_DUMPABLE)
#define CHARD_NOT_DUMPABLE \
    do { \
    } while (0)
#endif

/* --- exit statuses for a precondition a probe could not establish ------------ */

/* malloc returned NULL: the host ran out of memory, a condition of the machine
 * alone. */
#define CHARD_EXIT_NO_ALLOCATION 77

/* fortify_known_object.c: neither guard array directly follows `dst`, so the bytes
 * the overflow would write are not inside an object this probe declares. */
#define CHARD_EXIT_LAYOUT 78

/* fortify_dynamic_object.c: `malloc_usable_size(dst)` or the position of `src`
 * is not the glibc chunk geometry the probe's margin is computed from. */
#define CHARD_EXIT_HEAP_GEOMETRY 79

/* fortify_dynamic_object.c: `__builtin_object_size(dst)` is statically known, so a
 * level-2 build would fire exactly like level 3 and the run cannot separate them. */
#define CHARD_EXIT_OPACITY_LOST 80

/*stack_clash.c and stack_exec_runtime.c: the probe declined to put its question and printed `<TAG>
 *probe-invalid=<reason>` on stdout first, naming why. */
#define CHARD_EXIT_DECLINED 81

/* --- the fault reporter, for probes that must say which fault killed them ------ */
#if defined(CHARD_WANT_FAULT_REPORT)
#if defined(__linux__) && (defined(__aarch64__) || defined(__x86_64__) || defined(__i386__))
/* The ESR record's header and magic from the kernel's arm64 sigcontext ABI, spelled
 * here so the header does not include <asm/sigcontext.h> beside <signal.h>. */
#define CHARD_ESR_MAGIC 0x45535201u
struct chard_ctx_head {
    unsigned int magic;
    unsigned int size;
};

static volatile unsigned long chard_fault_target;

__attribute__((unused)) static void chard_declare_fault_target(const void *p)
{
    chard_fault_target = (unsigned long)p;
}

/* snprintf is not async-signal-safe; these are. */
static char *chard_fault_put(char *at, const char *s)
{
    while (*s)
        *at++ = *s++;
    return at;
}

static char *chard_fault_num(char *at, unsigned long v, int hex)
{
    char digits[24];
    int n = 0;
    unsigned base = hex ? 16 : 10;
    if (hex)
        at = chard_fault_put(at, "0x");
    do {
        digits[n++] = "0123456789abcdef"[v % base];
        v /= base;
    } while (v);
    while (n)
        *at++ = digits[--n];
    return at;
}

/* Copy `n` bytes at `from` without touching them directly: process_vm_readv on the
 * probe's own pid fails with EFAULT for an unreadable address instead of raising a
 * second fault, and uses no descriptor the probe could have closed or reused. */
static int chard_fault_peek(unsigned long from, unsigned char *to, int n)
{
    struct iovec local;
    struct iovec remote;
    local.iov_base = to;
    local.iov_len = (size_t)n;
    remote.iov_base = (void *)from;
    remote.iov_len = (size_t)n;
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)n;
}

static void chard_fault_handler(int sig, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    unsigned long pc;
    unsigned long esr = 0;
    unsigned long word = 0;
    unsigned char bytes[sizeof(unsigned long)] = { 0 };
    int have_esr = 0;
    int have_word = 0;
    int nbytes;
    int i;
    const char *arch;
    char line[320];
    char *at = line;
#if defined(__aarch64__)
    unsigned char *p = (unsigned char *)uc->uc_mcontext.__reserved;
    unsigned char *end = p + sizeof uc->uc_mcontext.__reserved;
    arch = "aarch64";
    nbytes = 4;
    pc = (unsigned long)uc->uc_mcontext.pc;
    while (p + sizeof(struct chard_ctx_head) <= end) {
        struct chard_ctx_head *head = (struct chard_ctx_head *)p;
        if (head->magic == 0 || head->size == 0 || head->size > (unsigned int)(end - p))
            break;
        if (head->magic == CHARD_ESR_MAGIC && head->size >= 16 && end - p >= 16) {
            memcpy(&esr, p + 8, sizeof esr);
            have_esr = 1;
        }
        p += head->size;
    }
#elif defined(__x86_64__)
    arch = "x86_64";
    nbytes = (int)sizeof(unsigned long);
    pc = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
#else
    arch = "x86";
    nbytes = (int)sizeof(unsigned long);
    pc = (unsigned long)uc->uc_mcontext.gregs[REG_EIP];
#endif
    /* On x86 the bytes read stop at the end of the pc's page: a trap in a page's last
     * bytes, before an unmapped page, still yields what it has. x86 pages are 4 KiB at
     * the smallest, and an aarch64 instruction never straddles a page. */
    if (4096 - (int)(pc % 4096) < nbytes)
        nbytes = 4096 - (int)(pc % 4096);
    if ((unsigned long)info->si_addr == pc && chard_fault_peek(pc, bytes, nbytes)) {
        for (i = nbytes - 1; i >= 0; i--)
            word = (word << 8) | bytes[i];
        have_word = 1;
    }
    at = chard_fault_put(at, "chard-fault-v1 signal=");
    at = chard_fault_num(at, (unsigned long)sig, 0);
    at = chard_fault_put(at, " code=");
    if (info->si_code < 0) {
        at = chard_fault_put(at, "-");
        at = chard_fault_num(at, (unsigned long)-(long)info->si_code, 0);
    } else {
        at = chard_fault_num(at, (unsigned long)info->si_code, 0);
    }
    at = chard_fault_put(at, info->si_code <= 0 ? " sent=yes" : " sent=no");
    at = chard_fault_put(at, " arch=");
    at = chard_fault_put(at, arch);
    at = chard_fault_put(at, " pc=");
    at = chard_fault_num(at, pc, 1);
    at = chard_fault_put(at, " addr=");
    at = chard_fault_num(at, (unsigned long)info->si_addr, 1);
    at = chard_fault_put(at, " word=");
    if (have_word)
        at = chard_fault_num(at, word, 1);
    else
        at = chard_fault_put(at, "none");
    at = chard_fault_put(at, " esr=");
    if (have_esr)
        at = chard_fault_num(at, esr, 1);
    else
        at = chard_fault_put(at, "none");
    at = chard_fault_put(at, " at-target=");
    if (chard_fault_target == 0)
        at = chard_fault_put(at, "undeclared");
    else
        at = chard_fault_put(at, pc == chard_fault_target ? "yes" : "no");
    *at++ = '\n';
    if (write(2, line, (size_t)(at - line)) < 0) {
        /* Nothing to do: the death below is the measurement either way. */
    }
    /* SA_RESETHAND restored the default action; raising applies it, so the death
     * is the signal the kernel delivered, as it would have been with no handler. */
    raise(sig);
}

__attribute__((unused)) static void chard_report_faults(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = chard_fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}
#else
__attribute__((unused)) static void chard_declare_fault_target(const void *p) { (void)p; }
__attribute__((unused)) static void chard_report_faults(void) {}
#endif
#endif /* CHARD_WANT_FAULT_REPORT */

/* --- the translation read, for probes whose reading rests on the machine --------- */
#if defined(CHARD_WANT_TRANSLATION_REPORT)
#if defined(__APPLE__)
#define CHARD_TRANSLATION_MARKER "CHARD-TRANSLATION"

__attribute__((unused)) static void chard_report_translation(void)
{
    int translated = -1;
    size_t size = sizeof translated;
    char line[64];
    int n;
    errno = 0;
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) != 0) {
        n = snprintf(line, sizeof line, CHARD_TRANSLATION_MARKER " unreadable errno:%d\n",
                     errno);
    } else if (size != sizeof translated) {
        n = snprintf(line, sizeof line, CHARD_TRANSLATION_MARKER " unreadable size:%lu\n",
                     (unsigned long) size);
    } else if (translated == 0 || translated == 1) {
        n = snprintf(line, sizeof line, CHARD_TRANSLATION_MARKER " %d\n", translated);
    } else {
        n = snprintf(line, sizeof line, CHARD_TRANSLATION_MARKER " unreadable value:%d\n",
                     translated);
    }
    if (n > 0 && (size_t) n < sizeof line) {
        (void) !write(1, line, (size_t) n);
    }
}
#else
__attribute__((unused)) static void chard_report_translation(void) {}
#endif
#endif /* CHARD_WANT_TRANSLATION_REPORT */

#endif /* CHARD_SELFREPORT_H */
