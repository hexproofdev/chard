/* SPDX-License-Identifier: BSD-3-Clause */

/* -fzero-call-used-regs probe (runtime channel).
 *
 * The flag makes a function clear call-used registers immediately before it returns,
 * so a value the function computed or was handed does not survive into its caller for
 * a return-oriented gadget chain to reuse. `=used-gpr` clears the general-purpose
 * registers the function used, the `-arg` forms only those that carry arguments, `=all`
 * every call-used register whether used or not, and `=skip` nothing.
 *
 * The observable is what is left in those registers when the function has returned.
 * Nothing in the object says it directly: the clearing is a few `xor`/`mov` instructions
 * before `ret`, which only a disassembler would find, and there is no macro (`cc -dM -E`
 * is identical with and without the flag on gcc 16.1.1 and clang 22.1.8). So the probe
 * reads the registers themselves, at the one place no compiled code stands between the
 * return and the read.
 *
 * ## How
 *
 * A trampoline written in top-level assembly loads a distinct marker into every argument
 * register and one non-argument register (`r11` on x86_64, `x10` on aarch64), calls
 * `chard_zcur_target`, and stores the same registers to `chard_zcur_regs` as its very
 * next instructions. The compiler never sees the code between the return and the store,
 * so it cannot move, spill or reuse anything there; and the trampoline is not compiled
 * code, so the flag does not apply to it.
 *
 * `chard_zcur_target` reads every argument, which makes each argument register a register
 * it used, and it routes one value through the non-argument register by naming it as the
 * register of a local, which makes that register used too. Under the flag every one of
 * them reads zero after the return. Without it the function leaves at least one argument
 * register untouched, holding exactly the marker the trampoline put there: measured on
 * every compiler and level below, because the function folds its arguments into one
 * register and has no reason to write the others.
 *
 * The same trampoline is also pointed at `chard_zcur_null`, an assembly function that
 * only returns. Every register must come back holding its marker. That is the witness:
 * it shows, from the measured build alone, that the trampoline loads and stores the
 * registers it names, so a reading of zero is the callee's doing and a reading of the
 * marker means the callee left it.
 *
 * ## What the line means
 *
 *   ZCUR args=N null=<args>/<temp> target=<args>/<temp>
 *
 * one letter per register: `z` read zero, `k` kept the marker, `o` anything else.
 *
 *   null not all k                -> the witness failed; nothing is established
 *   target args all z, temp z     -> used registers cleared (`gpr`): `=used-gpr`, `=used`,
 *                                    `=all-gpr`, `=all`, gcc's `=leafy*` on this leaf
 *   target args all z, temp not z -> only argument registers cleared (`arg`): the `-arg`
 *                                    forms
 *   some arg k                    -> a register the function read came back unchanged:
 *                                    no clearing
 *
 * The non-argument register separates `=used-gpr` from `=used-gpr-arg`, which leave the
 * argument registers alike. A non-argument register the function does not use would
 * separate `=all` from `=used-gpr`, and none is read, because which scratch registers a
 * function uses beyond the one it is made to use is the compiler's choice, and the choice
 * moves with that one: when the probe made the function use `x9`, clang 22.1.8 on aarch64
 * used `x10` as scratch from -O1 upward without being asked, so `=used-gpr` cleared it.
 * With the function made to use `x10`, the same clang uses `x9` as
 * scratch at -O0 through -O3 and -Os (`-S` with `=used-gpr`, Fedora 44 x86_64 and
 * aarch64), and `=used-gpr` clears `x9`. Neither it nor gcc 16.2.1 touches `x11` there, nor
 * clang 22.1.8 and gcc 16.1.1 `r10` on x86_64, which is the case against reading one: an
 * unused register stays unused only until the next compiler or the next probe change.
 *
 * The aarch64 register is `x10` and not `x9`, because code emitted after the clearing
 * writes `x9` on OpenBSD. Under OpenBSD 7.9's clang 19.1.7 on arm64, RETGUARD (on by
 * default) loads the function's `__retguard_<n>` value into `x15` and XORs it with the
 * return address in `x30`; its check, after the clearing sequence, XORs `x30` back out,
 * reloads the raw `__retguard_<n>` value into `x9` and subtracts it from `x15`. So `x15`
 * returns zero when the return address is intact and `x9` returns holding the raw value,
 * neither zero nor its marker, under `=used-gpr` and `=all` alike, and `x9` reads zero with
 * `-fno-ret-protector`. Read through `x9`, every OpenBSD arm64 build with the flag would
 * have read `arg`. `x10` and `x15` both read zero there; `x15` is RETGUARD's own register,
 * so `x10`. (The register roles are read from `-S` at -O2 with `=used-gpr` and the
 * `x10` probe, 2026-10-01.)
 *
 * Measured 2026-10-01, every register as the table above predicts: Fedora 44 x86_64
 * (gcc 16.1.1, clang 22.1.8) and Fedora 44 aarch64 (gcc 16.2.1, clang 22.1.8) at -O0
 * through -O3 and -Os; at -O0 and -O2, gcc 11.4.0 (Ubuntu 22.04 container), gcc 13.3.0
 * and clang 18.1.3 (Ubuntu 24.04), gcc 15.2.0 and clang 23.1.2 (Alpine, musl), OpenBSD
 * 7.9's clang 19.1.7 on amd64 and arm64, and Apple clang 21.0.0 on arm64. clang 14.0.0
 * (Ubuntu 22.04) rejects every spelling as an unknown argument, which chard reports as
 * `unsupported` under `bare` and `build-failed` where the profile passes the flag.
 *
 * Elsewhere the probe prints `ZCUR unsupported-arch` and builds. gcc implements the flag
 * on i386 as well; the guide recommends it for x86_64 and aarch64, and the check is gated
 * to those two.
 */

#include <stdint.h>
#include <stdio.h>

#define CHARD_STR2(x) #x
#define CHARD_STR(x) CHARD_STR2(x)
#define CHARD_SYM(name) CHARD_STR(__USER_LABEL_PREFIX__) #name

#if defined(__ELF__)
#define CHARD_FUNC(name)                                                                  \
    ".globl " CHARD_SYM(name) "\n\t.hidden " CHARD_SYM(name) "\n\t.type " CHARD_SYM(name) \
    ", %function\n\t.p2align 4\n" CHARD_SYM(name) ":\n\t"
#define CHARD_END(name) ".size " CHARD_SYM(name) ", .-" CHARD_SYM(name) "\n"
#else
#define CHARD_FUNC(name) \
    ".globl " CHARD_SYM(name) "\n\t.private_extern " CHARD_SYM(name) "\n\t.p2align 4\n" CHARD_SYM(name) ":\n\t"
#define CHARD_END(name) "\n"
#endif

#if defined(__x86_64__) || defined(__aarch64__)
#define CHARD_ZCUR_SUPPORTED 1
#endif

#if defined(__x86_64__)
#define CHARD_ARGS 6
#define CHARD_TEMP "r11"
#if defined(__CET__) && (__CET__ & 1)
#define CHARD_LANDING ".byte 0xf3, 0x0f, 0x1e, 0xfa\n\t" /* endbr64 */
#else
#define CHARD_LANDING
#endif
#elif defined(__aarch64__)
#define CHARD_ARGS 8
#define CHARD_TEMP "x10"
#define CHARD_LANDING "hint #34\n\t" /* bti c; a no-op where BTI is absent */
#endif

#ifdef CHARD_ZCUR_SUPPORTED
/* The argument registers in order, then the non-argument register. */
uint64_t chard_zcur_regs[CHARD_ARGS + 1] __attribute__((used, visibility("hidden")));
volatile uint64_t chard_zcur_sink;

static uint64_t marker(int i)
{
    return UINT64_C(0x5a5a5a5a5a5a5a00) | (uint64_t) ((i + 1) << 4);
}
#endif

#if defined(__x86_64__)
__attribute__((noinline, used, visibility("hidden"))) void chard_zcur_target(
    uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f)
{
    register uint64_t t __asm__(CHARD_TEMP) = a ^ b;
    __asm__ volatile("" : "+r"(t));
    chard_zcur_sink = t ^ c ^ d ^ e ^ f;
}

#define LOAD(r, i) "movabsq $0x5a5a5a5a5a5a5a" #i "0, %" r "\n\t"
#define STORE(r, i) "movq %" r ", " CHARD_SYM(chard_zcur_regs) "+" #i "*8(%rip)\n\t"
#define TRAMPOLINE(name, callee)                                                          \
    __asm__(".text\n\t" CHARD_FUNC(name) CHARD_LANDING "subq $8, %rsp\n\t"                \
            LOAD("rdi", 1) LOAD("rsi", 2) LOAD("rdx", 3) LOAD("rcx", 4) LOAD("r8", 5)    \
            LOAD("r9", 6) LOAD("r11", 7)                                                  \
            "call " CHARD_SYM(callee) "\n\t"                                              \
            STORE("rdi", 0) STORE("rsi", 1) STORE("rdx", 2) STORE("rcx", 3) STORE("r8", 4) \
            STORE("r9", 5) STORE("r11", 6)                                                \
            "addq $8, %rsp\n\tret\n\t" CHARD_END(name));

__asm__(".text\n\t" CHARD_FUNC(chard_zcur_null) CHARD_LANDING "ret\n\t" CHARD_END(chard_zcur_null));
#elif defined(__aarch64__)
__attribute__((noinline, used, visibility("hidden"))) void chard_zcur_target(
    uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t g, uint64_t h)
{
    register uint64_t t __asm__(CHARD_TEMP) = a ^ b;
    __asm__ volatile("" : "+r"(t));
    chard_zcur_sink = t ^ c ^ d ^ e ^ f ^ g ^ h;
}

#if defined(__ELF__)
#define CHARD_PAGE(sym) "adrp x19, " CHARD_SYM(sym) "\n\tadd x19, x19, :lo12:" CHARD_SYM(sym) "\n\t"
#else
#define CHARD_PAGE(sym) "adrp x19, " CHARD_SYM(sym) "@PAGE\n\tadd x19, x19, " CHARD_SYM(sym) "@PAGEOFF\n\t"
#endif
#define LOAD(r, i)                                                                       \
    "movz " r ", #0x5a" #i "0\n\tmovk " r ", #0x5a5a, lsl #16\n\tmovk " r                \
    ", #0x5a5a, lsl #32\n\tmovk " r ", #0x5a5a, lsl #48\n\t"
#define STORE(r, i) "str " r ", [x19, #" #i "*8]\n\t"
#define TRAMPOLINE(name, callee)                                                          \
    __asm__(".text\n\t" CHARD_FUNC(name) CHARD_LANDING                                    \
            "stp x29, x30, [sp, #-32]!\n\tmov x29, sp\n\tstr x19, [sp, #16]\n\t"          \
            LOAD("x0", 1) LOAD("x1", 2) LOAD("x2", 3) LOAD("x3", 4) LOAD("x4", 5)        \
            LOAD("x5", 6) LOAD("x6", 7) LOAD("x7", 8) LOAD("x10", 9)                      \
            "bl " CHARD_SYM(callee) "\n\t" CHARD_PAGE(chard_zcur_regs)                    \
            STORE("x0", 0) STORE("x1", 1) STORE("x2", 2) STORE("x3", 3) STORE("x4", 4)   \
            STORE("x5", 5) STORE("x6", 6) STORE("x7", 7) STORE("x10", 8)                  \
            "ldr x19, [sp, #16]\n\tldp x29, x30, [sp], #32\n\tret\n\t" CHARD_END(name));

__asm__(".text\n\t" CHARD_FUNC(chard_zcur_null) CHARD_LANDING "ret\n\t" CHARD_END(chard_zcur_null));
#endif

#ifdef CHARD_ZCUR_SUPPORTED
TRAMPOLINE(chard_zcur_call_target, chard_zcur_target)
TRAMPOLINE(chard_zcur_call_null, chard_zcur_null)

void chard_zcur_call_target(void);
void chard_zcur_call_null(void);

/* One letter per register: the arguments, a slash, the non-argument register. */
static void classify(char *out)
{
    int o = 0;
    /* A block-scoped counter, not one declared in the `for`: gnu89 (gcc before 5). */
    {
        int i = 0;
        for (; i <= CHARD_ARGS; i++) {
            if (i == CHARD_ARGS) {
                out[o++] = '/';
            }
            uint64_t v = chard_zcur_regs[i];
            out[o++] = v == 0 ? 'z' : v == marker(i) ? 'k' : 'o';
        }
    }
    out[o] = '\0';
}

int main(void)
{
    char null_reading[CHARD_ARGS + 3];
    char target_reading[CHARD_ARGS + 3];

    chard_zcur_call_null();
    classify(null_reading);
    chard_zcur_call_target();
    classify(target_reading);
    printf("ZCUR args=%d temp=%s null=%s target=%s\n", CHARD_ARGS, CHARD_TEMP, null_reading,
           target_reading);
    printf("ZCUR-RAW");
    {
        int i = 0;
        for (; i <= CHARD_ARGS; i++) {
            printf(" %016llx", (unsigned long long) chard_zcur_regs[i]);
        }
    }
    printf("\n");
    return 0;
}
#else
int main(void)
{
    printf("ZCUR unsupported-arch\n");
    return 0;
}
#endif
