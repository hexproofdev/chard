/* SPDX-License-Identifier: BSD-3-Clause */

/* -fstrict-flex-arrays probe, enforcement (runtime channel). */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/wait.h>
#include <unistd.h>

/* After the libc headers, for the reason `chard_selfreport.h` gives. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

struct row_ctrl {
    int header;
    char head[2];
    char after[30];
};
struct row_two {
    int header;
    char tail[2];
};
struct row_one {
    int header;
    char tail[1];
};
struct row_zero {
    int header;
    char tail[0];
};
struct row_flex {
    int header;
    char tail[];
};

/* 64 bytes, aligned for any of the row structs; the longest copy ends 16 bytes in. */
static union {
    long double ld;
    long long ll;
    void *p;
    char bytes[64];
} storage;

/* Eleven characters and a terminator: past every bounded member, inside `storage`. */
static char source[16] = "AAAAAAAAAAA";

/* Returns `p` unchanged through an asm the optimizer cannot look through. */
static void *opaque(void *p)
{
    __asm__ volatile("" : "+r"(p) : : "memory");
    return p;
}

/*Every copy below overflows on purpose, and gcc sees it for the rows the flag bounds: at
 *`-fstrict-flex-arrays=3` it warns on the `[0]` row's copy (`-Wstringop-overflow`, on by default,
 *and `-Warray-bounds` under `-Wall`). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
#define ROW(name, type, member)                                                  \
    static void copy_##name(void)                                                \
    {                                                                            \
        type *p = opaque(storage.bytes);                                         \
        strcpy(p->member, opaque(source));                                       \
        (void)opaque(p);                                                         \
    }
ROW(ctrl, struct row_ctrl, head)
ROW(two, struct row_two, tail)
ROW(one, struct row_one, tail)
ROW(zero, struct row_zero, tail)
ROW(flex, struct row_flex, tail)
#pragma GCC diagnostic pop

/*The ctrl member's size as the compiler answers it, and through the wrapper form a C library's
 *fortify wrapper takes: `fortify_subobject.c`'s instrument, over an object the compiler can see,
 *since every row's own pointer is laundered and reads `(size_t)-1`. */
static struct row_ctrl witness;

static __inline__ __attribute__((__always_inline__, __gnu_inline__, __artificial__)) size_t
chard_bos1_in_wrapper(char *p)
{
    return __builtin_object_size(p, 1);
}

#if defined(_BITS_STRING_FORTIFIED_H)
#define CHARD_GLIBC_WRAPPERS 1
#else
#define CHARD_GLIBC_WRAPPERS 0
#endif
#if !defined(__fortify_use_clang)
#define CHARD_CLANG_PATH "?"
#elif __fortify_use_clang
#define CHARD_CLANG_PATH "1"
#else
#define CHARD_CLANG_PATH "0"
#endif

static void run_row(const char *name, void (*copy)(void))
{
    fprintf(stderr, "CHARD-SFA-ENFORCED begin row=%s\n", name);
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "CHARD-SFA-ENFORCED end row=%s status=fork-failed\n", name);
        return;
    }
    if (child == 0) {
        struct rlimit none = {0, 0};
        (void)setrlimit(RLIMIT_CORE, &none);
        copy();
        _exit(0);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        fprintf(stderr, "CHARD-SFA-ENFORCED end row=%s status=wait-failed\n", name);
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "CHARD-SFA-ENFORCED end row=%s status=signal:%d\n", name,
                WTERMSIG(status));
    } else {
        fprintf(stderr, "CHARD-SFA-ENFORCED end row=%s status=exit:%d\n", name,
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
}

int main(void)
{
    CHARD_PRINT_REPORT;
#ifdef __linux__
    /* Before the rows, so each forked row inherits it, and outside every row's markers, so a
     * note here is not read as a row's output (see the header). */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        fprintf(stderr, "CHARD-SFA-ENFORCED note dumpable-unset errno=%d\n", errno);
        fflush(stderr);
    }
#endif
    run_row("ctrl", copy_ctrl);
    run_row("two", copy_two);
    run_row("one", copy_one);
    run_row("zero", copy_zero);
    run_row("flex", copy_flex);
#ifdef __OPTIMIZE__
    printf("optimize=yes\n");
#else
    printf("optimize=no\n");
#endif
    printf("CHARD-BOS main1=%lu main0=%lu wrap1=%lu glibc_wrappers=%d clang_path=%s\n",
           (unsigned long)__builtin_object_size(witness.head, 1),
           (unsigned long)__builtin_object_size(witness.head, 0),
           (unsigned long)chard_bos1_in_wrapper(witness.head), CHARD_GLIBC_WRAPPERS,
           CHARD_CLANG_PATH);
    /*The C library, where the build shows one with no subobject bound, which is what lets the
     *detector read a silent `ctrl` row as the library's rather than withhold it. musl defines no
     *macro naming itself; its internal `__NEED_*` guards are how `env::detect_libc` identifies it
     *too, and `__NEED_size_t` is left defined by `<string.h>`. */
#if defined(__OpenBSD__)
    printf("libc=openbsd\n");
#elif defined(__FreeBSD__)
    printf("libc=freebsd\n");
#elif defined(__NEED_size_t) && !defined(__GLIBC__)
    printf("libc=musl\n");
#else
    printf("libc=?\n");
#endif
    printf("rows=5\n");
    return 0;
}
