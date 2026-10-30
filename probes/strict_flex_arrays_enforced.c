/* SPDX-License-Identifier: BSD-3-Clause */

/* -fstrict-flex-arrays probe, enforcement (runtime channel).
 *
 * `strict_flex_arrays.c` reads the compiler's size model: what `__builtin_object_size`
 * answers for a trailing array of each spelling. This probe reads whether that answer is
 * enforced: whether a fortified `strcpy` past the end of each trailing array aborts with
 * glibc's `*** buffer overflow detected ***`. The two can differ, because the copy's bound
 * is asked for inside the C library's wrapper and not at the call site, and the measured
 * case where they do is in the project ledger's `fortify-level-ge-2-subobject` entry.
 *
 * ## The observable
 *
 * One overflowing `strcpy` per row, each in its own child process, since a caught copy
 * ends the process that made it. The parent writes a begin and an end marker to stderr
 * around each child and waits for it between the two, so whatever the child's C library
 * wrote lands between its own row's markers. The detector, not this program, decides
 * whether a row was caught: a child ended by SIGABRT with glibc's diagnostic inside its
 * markers, or by a trap where the self-report names an implementation that traps (Apple's
 * wrappers raise SIGTRAP and print nothing).
 *
 * The rows, and which `-fstrict-flex-arrays` levels bound each (the same ladder
 * `strict_flex_arrays.c` reads):
 *
 *   row    member             bounded at
 *   ctrl   `head[2]`, not last    every level: the witness that the build enforces
 *                                 subobject bounds at all
 *   two    `tail[2]`, last        1, 2, 3
 *   one    `tail[1]`, last        2, 3
 *   zero   `tail[0]`, last        3
 *   flex   `tail[]`, last         none: a true flexible member is never bounded, so a
 *                                 caught `flex` row says the probe is broken
 *
 * Enforcement is the conjunction of two things: the compiler bounding the member, and a
 * fortified copy checking a subobject bound, which glibc does at `_FORTIFY_SOURCE=2` and
 * above and not at `=1`, without optimization, or where no fortified wrapper exists. The
 * `ctrl` row separates them. Where `ctrl` is not caught nothing in this build checks a
 * subobject bound, the three trailing rows are silent whatever the flag says, and the
 * detector withholds rather than reading level 0 from them. The one exception is a C
 * library shown to have no subobject bound at all (musl or OpenBSD's libc, named by the
 * `libc=` line this program prints, with no fortify implementation the self-report
 * recognises, or musl with fortify-headers, which sizes every destination as a whole
 * object): there the silence is the library's, read as absent in every arm, and the check
 * is published `unsupported`.
 *
 * ## Why the pointer is laundered and the storage declared
 *
 * Each row's struct pointer and the copy's source pass through an empty `asm` the
 * compiler cannot see into, so neither the object behind the pointer nor the source's
 * length is known at the copy. A trailing array treated as flexible then has no bound at
 * all (`__builtin_object_size` answers `-1`), and only a bounded one is checked: the row
 * reads the flag and nothing else. The asm is opaque to link-time optimization too, and
 * `-O2 -flto` reads the same rows as `-O2` on both compilers (Fedora 44 aarch64, gcc 16.2.1
 * and clang 22.1.8). The storage is a declared array far larger than any row's struct, so a
 * copy nothing catches writes only bytes this probe owns.
 *
 * No caught row leaves a core. On Linux the probe makes itself non-dumpable before the rows
 * (`PR_SET_DUMPABLE`, which each forked row inherits): a core_pattern that pipes to a
 * handler (systemd-coredump) ignores a core limit of 0 and starts the handler for every
 * crash, a second or more each on a busy host, and the four caught rows of a run crossed
 * chard's probe deadline. Where that call fails, a `note` line outside every row's
 * markers says so, and the rows run as before. Each child also sets its core limit to zero,
 * the only step off Linux; the slow handler was measured on Linux only.
 */

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

/* 64 bytes, aligned for any of the row structs; the longest copy ends 16 bytes in. The
 * aligning members are C99 types: `max_align_t` is C11, and with it the probe did not build
 * under `-std=c99` or `-std=gnu99`, so the check was withheld from every profile that pins
 * either. */
static union {
    long double ld;
    long long ll;
    void *p;
    char bytes[64];
} storage;

/* Eleven characters and a terminator: past every bounded member, inside `storage`. */
static char source[16] = "AAAAAAAAAAA";

/* Returns `p` unchanged through an asm the optimizer cannot look through. Its memory
 * clobber also counts as a read of what `p` points at, which is what keeps a copy whose
 * destination is read by nothing else from being removed as dead. */
static void *opaque(void *p)
{
    __asm__ volatile("" : "+r"(p) : : "memory");
    return p;
}

/* Every copy below overflows on purpose, and gcc sees it for the rows the flag bounds: at
 * `-fstrict-flex-arrays=3` it warns on the `[0]` row's copy (`-Wstringop-overflow`, on by
 * default, and `-Warray-bounds` under `-Wall`). Under `-Werror` that failed the build at
 * exactly the level the guide recommends while the lower levels built, as
 * `fortify_known_object.c` describes for its own copy. Diagnostics only: neither pragma
 * changes the code generated. clang has no `-Wstringop-overflow` group and rejects an
 * unknown one under `-Werror`, so that pragma is gcc's alone. */
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
    /* The C library, where the build shows one with no subobject bound, which is what lets
     * the detector read a silent `ctrl` row as the library's rather than withhold it.
     * musl defines no macro naming itself; its internal `__NEED_*` guards are how
     * `env::detect_libc` identifies it too, and `__NEED_size_t` is left defined by
     * `<string.h>`. FreeBSD's is named by its platform macro, as OpenBSD's is; whether its
     * `<ssp/string.h>` wrappers are in this translation unit is `_FORTIFY_IMPL` in the
     * self-report, and its `strcpy` wrapper, the one these rows call, sizes the destination
     * as a whole object at every level. Any other library prints `?`, and its silence is
     * withheld. */
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
