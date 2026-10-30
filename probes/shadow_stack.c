/* SPDX-License-Identifier: BSD-3-Clause */

/* x86 shadow stack enforcement probe (runtime channel).
 *
 * `-fcf-protection=return` (and `=full`) marks every object it compiles with
 * GNU_PROPERTY_X86_FEATURE_1_SHSTK, and the linker keeps the bit in the output only where
 * every input carries it. `cet-marked` reads that bit. Whether a program then runs with a
 * shadow stack is decided later, by the C library at startup and the kernel under it: glibc
 * enables it only where the CPU implements it, the kernel offers it, the program and every
 * object loaded with it carry the bit, and the process opted in. This probe asks whether all
 * of that held for a program this toolchain built, on this machine.
 *
 * The opt-in is glibc's tunable. glibc 2.39 and later leave the shadow stack off for a marked
 * program unless `GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK` is set; `glibc.cpu.x86_shstk=on` and
 * `=permissive` alone enable nothing, and a tunable glibc does not recognise is ignored without
 * a diagnostic. chard runs this probe, and only this probe, with that tunable pinned
 * (`Probe::run_environment`), so the reading is about the toolchain's output, the C library
 * and the kernel, and not about whether the operator opted in. Measured 2026-10-02 on Fedora 44
 * x86_64 (kernel 7.3.0-rc3, glibc 2.43, gcc 16.1.1, clang 22.1.8): with no tunable, or with
 * either `x86_shstk` value alone, a `-fcf-protection=full` program read `features=0 ssp=0` and
 * its clobbered return was taken; with `glibc.cpu.hwcaps=SHSTK` it read `features=0x1`, a
 * non-zero shadow stack pointer, and the clobber faulted with `SEGV_CPERR`.
 *
 * Whether the pin reached glibc at all is the probe's own first line. A C library that ignores
 * `GLIBC_TUNABLES` (a Wolfi-derived rootfs's glibc 2.44-r23 is one) leaves the opt-in
 * unapplied, and the pinned process then reads exactly as an unpinned one, so the pin carries
 * a second tunable with an effect the probe can see: `glibc.malloc.perturb=170`, under which
 * glibc fills a chunk `malloc` returns, outside tcache, with the complement of that byte,
 * 0x55. The pinned process allocates 8 KiB before anything else and prints `SHSTK
 * tunables=honoured` where every sampled byte is 0x55, `ignored` where any is not, and
 * `unallocated` where `malloc` failed. Measured 2026-10-21 on Fedora 44 x86_64 (kernel
 * 7.3.0-rc3): honoured under host glibc 2.43 and Wolfi's glibc 2.44-r8, ignored under a
 * Wolfi-derived rootfs's 2.44-r23 (its loader and libc linked in place of the host's); both
 * glibcs that honoured it still enabled the shadow stack under the combined pin. The
 * perturbation reaches this probe alone, and changes no byte the probe reads otherwise. The
 * witness shows that the variable was applied by the allocator the process uses, not that
 * `glibc.cpu.hwcaps=SHSTK` was: `features=0x1` under the pin is what shows that. A build whose
 * `malloc` is not the C library's (a sanitizer's, another allocator a profile links) reads
 * `ignored` whatever glibc did, which is why the control arms, built with the control flag alone,
 * are where chard attributes `ignored` to the C library.
 *
 * The pinned reading is what makes the control triple discriminate, and it is not what a
 * deployment that sets no tunable gets. So the probe also reads the same program without the
 * pin: before its own reading it runs itself again (`/proc/self/exe`, argument `--unpinned`)
 * with every variable it was handed except `GLIBC_TUNABLES`, which under chard is exactly
 * `run::PROBE_ENVIRONMENT`, and waits for it. That run prints the same two lines prefixed
 * `SHSTK-UNPINNED`. The detector grades on it: enforced under the pin and without it is the
 * `default` level, enforced under the pin alone is `opt-in`, which is below the ask. A glibc
 * patched to enable the shadow stack by default reads `default`; upstream's reads `opt-in`.
 *
 * ## What the lines mean
 *
 *   SHSTK tunables=<honoured|ignored|unallocated>
 *   SHSTK-UNPINNED kernel=<ok|errno:N> cpu=<ss|no-ss|no-leaf7> features=<hex> ssp=<..>
 *   SHSTK-UNPINNED clobber=<cperr|segv:N|hijacked>
 *   SHSTK kernel=<ok|errno:N> cpu=<ss|no-ss|no-leaf7> features=<hex> ssp=<zero|nonzero>
 *   SHSTK clobber=<cperr|segv:N|hijacked>
 *
 * The `tunables` line comes first, from the pinned process alone; the unpinned pair next, from
 * the second process. Where that process could not be
 * started or ended some other way, the parent prints one `SHSTK-UNPINNED` line saying so
 * (`fork=errno:N`, `exec=errno:N`, `child=signal:N`, `child=exit:N`) in place of a reading.
 *
 * `kernel` is the kernel's answer to `arch_prctl(ARCH_SHSTK_STATUS)`: `ok` where the kernel
 * was built with user shadow stack support (Linux 6.6 and later, CONFIG_X86_USER_SHADOW_STACK),
 * an errno where it was not. `features` is what that call returned for this thread, bit 0 the
 * shadow stack. `cpu` is CPUID leaf 7's CET_SS bit, ECX bit 7. `ssp` is `rdsspq`, read into a
 * register zeroed first: the instruction is a no-op where no shadow stack is active, so the
 * zero survives, and only an active shadow stack writes a pointer.
 *
 * `clobber` is the enforcement itself. An assembly function overwrites its own return address
 * with the address of a second assembly function and returns. With the shadow stack active the
 * return address no longer matches the shadow stack's copy, the CPU raises a control-protection
 * fault, and the kernel delivers SIGSEGV with si_code SEGV_CPERR (10), which the handler
 * reports as `cperr`. Without one the return lands in the second function, which writes
 * `hijacked` with a raw `write` and leaves with `exit_group`. Both functions are top-level
 * assembly, so no optimization level, frame layout or stack protector changes what is
 * overwritten, and the hijack target touches no stack, so a misaligned stack cannot fault
 * there and pass for enforcement (the recipe's own hazard: a variadic target faulting on
 * `movaps` with si_code 128). Any other si_code is `segv:N`, evidence for neither side.
 *
 * The detector (`decode::runtime::detect_shadow_stack`) reads `present` only for features bit 0
 * set, a non-zero pointer and `cperr` together, and `absent` only for bit 0 clear, a zero
 * pointer and `hijacked` together, on the pinned pair; the unpinned pair, read the same way,
 * gives the level. A kernel without the interface or a CPU without CET_SS is
 * neither: the reading is indeterminate, and `report::machine_lacks_shadow_stack` names the
 * machine as the reason the positive control was silent.
 *
 * Elsewhere the probe prints `SHSTK unsupported-arch` and builds. The Linux x86 user shadow
 * stack, the one this probe reads, is x86_64 only; i386 has none, and the x32 ABI prints the
 * same line. aarch64 GCS and riscv64 Zicfiss are other mechanisms, behind
 * `prctl(PR_SET_SHADOW_STACK_STATUS)`, which this probe does not read.
 */

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

/* The line the hijack target writes, chosen in `main` before the clobber: the pinned and the
 * unpinned process carry different prefixes. Read by the assembly below, so hidden (a
 * PC-relative load needs no GOT) and `used`. */
__attribute__((visibility("hidden"), used)) const char *chard_shstk_hijack_text;
__attribute__((visibility("hidden"), used)) unsigned int chard_shstk_hijack_len;

/* The return lands here when nothing checked it. No stack is touched: the message is written
 * and the process ends through raw system calls. */
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

/* CPUID with ECX (the subleaf) zero, in inline assembly rather than through <cpuid.h>:
 * `__get_cpuid_count` is missing from that header before gcc 6 and clang 4, and the probe
 * did not build on Ubuntu 14.04 and 16.04 (measured 2026-10-07). The leaf-0 bound below is
 * the check that function makes. */
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

/* Run this program again without `GLIBC_TUNABLES`, and wait for it. Its lines reach the same
 * stdout ahead of this process's own, which `fflush` before the `fork` keeps in order. */
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
