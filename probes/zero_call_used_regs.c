/* SPDX-License-Identifier: BSD-3-Clause */

/* -fzero-call-used-regs probe (runtime channel). */

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
