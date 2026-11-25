/* SPDX-License-Identifier: BSD-3-Clause */

/* x86 shadow stack enforcement probe (runtime channel). */

#include <stdio.h>

/* On Darwin the first line says whether Rosetta 2 translated the run; see the header. */
#define CHARD_WANT_TRANSLATION_REPORT
#include "chard_selfreport.h"

/* x32 (`__ILP32__`) is excluded: its 32-bit `unsigned long` would take the kernel's 64-bit
 * status word into a 4-byte slot, and its arms are not run natively in any case. */
#if defined(__x86_64__) && !defined(__ILP32__) && defined(__linux__)
#define CHARD_SHSTK_SUPPORTED 1
#endif

#ifdef CHARD_SHSTK_SUPPORTED
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHARD_STR2(x) #x
#define CHARD_STR(x) CHARD_STR2(x)
#define CHARD_SYM(name) CHARD_STR(__USER_LABEL_PREFIX__) #name
#define CHARD_FUNC(name)                                                                  \
    ".globl " CHARD_SYM(name) "\n\t.hidden " CHARD_SYM(name) "\n\t.type " CHARD_SYM(name) \
    ", @function\n\t.p2align 4\n" CHARD_SYM(name) ":\n\t"
#define CHARD_END(name) ".size " CHARD_SYM(name) ", .-" CHARD_SYM(name) "\n"

#if defined(__CET__) && (__CET__ & 1)
#define CHARD_LANDING ".byte 0xf3, 0x0f, 0x1e, 0xfa\n\t" /* endbr64 */
#else
#define CHARD_LANDING
#endif

/* <asm/prctl.h> and <asm/siginfo.h> name these from Linux 6.6; spelled out so the probe
 * builds against older headers and reads the kernel's answer there instead. */
#define CHARD_ARCH_SHSTK_STATUS 0x5005
#define CHARD_SEGV_CPERR 10

/*The line the hijack target writes, chosen in `main` before the clobber: the pinned and the
 *unpinned process carry different prefixes. */
__attribute__((visibility("hidden"), used)) const char *chard_shstk_hijack_text;
__attribute__((visibility("hidden"), used)) unsigned int chard_shstk_hijack_len;

/* The return lands here when nothing checked it. */
__asm__(".text\n\t" CHARD_FUNC(chard_shstk_hijacked) CHARD_LANDING
        "movl $1, %eax\n\t"
        "movl $1, %edi\n\t"
        "movq " CHARD_SYM(chard_shstk_hijack_text) "(%rip), %rsi\n\t"
        "movl " CHARD_SYM(chard_shstk_hijack_len) "(%rip), %edx\n\t"
        "syscall\n\t"
        "movl $231, %eax\n\t"
        "xorl %edi, %edi\n\t"
        "syscall\n\t"
        "hlt\n\t" CHARD_END(chard_shstk_hijacked));

/* Overwrite this function's own return address, then return through it. */
__asm__(".text\n\t" CHARD_FUNC(chard_shstk_clobber) CHARD_LANDING
        "leaq " CHARD_SYM(chard_shstk_hijacked) "(%rip), %rax\n\t"
        "movq %rax, (%rsp)\n\t"
        "ret\n\t" CHARD_END(chard_shstk_clobber));

void chard_shstk_clobber(void);

/* `SHSTK` for the pinned process chard started, `SHSTK-UNPINNED` for the one it starts. */
static const char *prefix = "SHSTK";

static void on_segv(int sig, siginfo_t *info, void *context)
{
    (void) sig;
    (void) context;
    char line[64];
    int n;
    if (info->si_code == CHARD_SEGV_CPERR) {
        n = snprintf(line, sizeof line, "%s clobber=cperr\n", prefix);
    } else {
        n = snprintf(line, sizeof line, "%s clobber=segv:%d\n", prefix, info->si_code);
    }
    if (n > 0) {
        (void) !write(1, line, (size_t) n);
    }
    _exit(0);
}

/*CPUID with ECX (the subleaf) zero, in inline assembly rather than through <cpuid.h>:
 *`__get_cpuid_count` is missing from that header before gcc 6 and clang 4, and the probe did not
 *build on Ubuntu 14.04 and 16.04 (measured 2026-10-07). */
static void chard_cpuid(unsigned int leaf, unsigned int *a, unsigned int *b, unsigned int *c,
                        unsigned int *d)
{
    __asm__ volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "0"(leaf), "2"(0u));
}

static unsigned long long read_ssp(void)
{
    unsigned long long ssp = 0;
    /* rdsspq %rax, as bytes so an assembler that predates CET still builds the probe. */
    __asm__ volatile(".byte 0xf3, 0x48, 0x0f, 0x1e, 0xc8" : "+a"(ssp));
    return ssp;
}

/* Whether `GLIBC_TUNABLES` reached the C library: `glibc.malloc.perturb=170`, which the pin
 * carries, fills a chunk `malloc` returns from outside tcache with 0x55. 8 KiB is above tcache's
 * largest size; every 64th byte is read, through a volatile pointer so no read is folded. */
#define CHARD_PERTURB_FILL 0x55
#define CHARD_WITNESS_SIZE 8192
static const char *tunables_reached(void)
{
    volatile unsigned char *p = malloc(CHARD_WITNESS_SIZE);
    if (p == NULL) {
        return "unallocated";
    }
    const char *said = "honoured";
    size_t i;
    for (i = 0; i < CHARD_WITNESS_SIZE; i += 64) {
        if (p[i] != CHARD_PERTURB_FILL) {
            said = "ignored";
            break;
        }
    }
    free((void *) p);
    return said;
}

#define CHARD_UNPINNED_ARG "--unpinned"
#define CHARD_UNPINNED "SHSTK-UNPINNED"
#define CHARD_MAX_ENV 64

extern char **environ;

/* Run this program again without `GLIBC_TUNABLES`, and wait for it. */
static void run_unpinned(const char *self)
{
    char *env[CHARD_MAX_ENV + 1];
    size_t n = 0;
    /* A block-scoped cursor, not one declared in the `for`: gnu89 (gcc before 5). */
    {
        char **e = environ;
        for (; *e != NULL; e++) {
            if (strncmp(*e, "GLIBC_TUNABLES=", 15) == 0) {
                continue;
            }
            if (n == CHARD_MAX_ENV) {
                printf(CHARD_UNPINNED " env=too-large\n");
                return;
            }
            env[n++] = *e;
        }
    }
    env[n] = NULL;
    char *args[] = {(char *) self, (char *) CHARD_UNPINNED_ARG, NULL};

    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        printf(CHARD_UNPINNED " fork=errno:%d\n", errno);
        return;
    }
    if (pid == 0) {
        execve("/proc/self/exe", args, env);
        char line[48];
        int len = snprintf(line, sizeof line, CHARD_UNPINNED " exec=errno:%d\n", errno);
        if (len > 0) {
            (void) !write(1, line, (size_t) len);
        }
        _exit(0);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            printf(CHARD_UNPINNED " wait=errno:%d\n", errno);
            return;
        }
    }
    if (WIFSIGNALED(status)) {
        printf(CHARD_UNPINNED " child=signal:%d\n", WTERMSIG(status));
    } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        printf(CHARD_UNPINNED " child=exit:%d\n", WEXITSTATUS(status));
    }
}

int main(int argc, char **argv)
{
    static const char pinned_hijack[] = "SHSTK clobber=hijacked\n";
    static const char unpinned_hijack[] = CHARD_UNPINNED " clobber=hijacked\n";
    /* Before anything else allocates, so the chunk is the witness's own. */
    const char *tunables = tunables_reached();
    chard_report_translation();
    if (argc == 2 && strcmp(argv[1], CHARD_UNPINNED_ARG) == 0) {
        prefix = CHARD_UNPINNED;
        chard_shstk_hijack_text = unpinned_hijack;
        chard_shstk_hijack_len = sizeof unpinned_hijack - 1;
    } else {
        chard_shstk_hijack_text = pinned_hijack;
        chard_shstk_hijack_len = sizeof pinned_hijack - 1;
        printf("SHSTK tunables=%s\n", tunables);
        run_unpinned(argc > 0 && argv[0] != NULL ? argv[0] : "shadow-stack");
    }

    unsigned long features = 0;
    char kernel[24];
    errno = 0;
    if (syscall(SYS_arch_prctl, CHARD_ARCH_SHSTK_STATUS, &features) == 0) {
        snprintf(kernel, sizeof kernel, "ok");
    } else {
        snprintf(kernel, sizeof kernel, "errno:%d", errno);
        features = 0;
    }

    const char *cpu = "no-leaf7";
    unsigned int a = 0, b = 0, c = 0, d = 0;
    chard_cpuid(0, &a, &b, &c, &d);
    if (a >= 7) {
        chard_cpuid(7, &a, &b, &c, &d);
        cpu = (c >> 7) & 1 ? "ss" : "no-ss";
    }

    unsigned long long ssp = read_ssp();
    printf("%s kernel=%s cpu=%s features=%#lx ssp=%s\n", prefix, kernel, cpu, features,
           ssp != 0 ? "nonzero" : "zero");
    fflush(stdout);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

    chard_shstk_clobber();
    /* Not reached: the return either faulted or went to the hijack target. */
    printf("%s clobber=returned\n", prefix);
    return 0;
}
#else
int main(void)
{
    chard_report_translation();
    printf("SHSTK unsupported-arch\n");
    return 0;
}
#endif
