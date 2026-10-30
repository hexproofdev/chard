/* SPDX-License-Identifier: BSD-3-Clause */

/* _FORTIFY_SOURCE level-3 probe (runtime channel), heap destination.
 *
 * This is the probe that tells level 3 apart from level 2, the distinction that
 * matters most in current distro comparisons and that no macro can settle on its
 * own, because a command line asking for 3 may be silently served as 2.
 *
 * The destination is a heap allocation of a runtime-computed size.
 * `__builtin_object_size` cannot see it, so level 2 misses the overflow
 * entirely; level 3 uses `__builtin_dynamic_object_size`, which can, so it
 * aborts. Hence:
 *
 *   level 3  -> SIGABRT, "*** buffer overflow detected ***"
 *   level 2  -> prints "no-check-fired", exits 0
 *   level 0  -> prints "no-check-fired", exits 0
 *
 * The negative control for this probe is therefore `-D_FORTIFY_SOURCE=2` rather
 * than fortify-off: the claim under test is specifically "level 3 is active", so
 * the control must prove that level 2 does *not* produce the observable.
 *
 * ## The heap margin, and the probe's check of it
 *
 * Nothing is freed, and the 32-byte write into a 16-byte request stays
 * non-fatal by a margin that is stated here rather than left to luck. On glibc
 * (x86_64 and aarch64, 16-byte MALLOC_ALIGNMENT) `malloc(16)` is a 32-byte chunk
 * with 24 usable bytes: the 16 requested plus the next chunk's prev_size field,
 * which belongs to this allocation while its neighbour is in use. `src` is that
 * neighbour, an 80-byte chunk whose user pointer is dst+32 and whose size field
 * occupies dst+24..dst+32. So the copy overwrites src's size field and nothing
 * else, and nothing reads it: no allocation follows the copy (stdout's buffer was
 * allocated by CHARD_PRINT_REPORT before `malloc(want)`), nothing is freed, and
 * exit does not walk the heap. The top chunk's header begins at dst+96 and its
 * size field at dst+104; a write long enough to reach it is validated by the next
 * request that extends the heap, which dies in sysmalloc with glibc's own
 * `malloc.c: assertion failed` message, an abort carrying no fortify text that
 * the detector reads as an unattributable death. Measured on Linux/glibc x86_64 with an allocation following
 * the copy: exit 0 for writes of 32, 48, 64 and 96 bytes, SIGABRT in sysmalloc
 * for 128, 192 and 256. On this file's own host (Apple libc, arm64) the picture
 * is different in kind: `malloc_size(dst)` is 16, `src` sits 400 bytes below
 * `dst` in the nano zone, and writes of up to 4096 bytes survived undiagnosed,
 * because Apple keeps no inline chunk headers to reach.
 *
 * The arithmetic is the same on 32-bit x86, where glibc's MALLOC_ALIGNMENT is also
 * 16 but a chunk's header fields are 4 bytes each. `malloc(16)` is again a 32-byte
 * chunk, and its usable size is that chunk less the one header field it does not
 * own, the neighbour's size field: 32 - sizeof(size_t), which is 24 with an 8-byte
 * size_t and 28 with a 4-byte one. `src` is again at dst+32, its size field now at
 * dst+28..dst+32, still the only bytes the copy writes outside `dst`'s own chunk.
 * The expectation is spelled 32 - sizeof(size_t) for that reason. Spelled
 * 3*sizeof(size_t), it is 24 on LP64 but 12 on i386, where the usable size is 28:
 * under Debian 12 i386's gcc 12.2.0 and glibc 2.36 with the bare and
 * bare-optimized profiles, every arm of the check then exits with the status
 * below and the cell is withheld.
 *
 * The expectation holds where MALLOC_ALIGNMENT is 16: the LP64 targets and i386,
 * which sets it explicitly. A 32-bit glibc target with 8-byte alignment, armhf
 * among them, makes `malloc(16)` a 24-byte chunk with 20 usable bytes and puts
 * `src` at dst+24. That is glibc's chunk arithmetic, not a measurement; no such
 * target has run this probe. There the probe exits with the status below and the
 * cell is withheld, which is the intended outcome for a margin computed for
 * another geometry.
 *
 * The geometry is asserted where the margin is claimed. Under glibc the probe
 * exits CHARD_EXIT_HEAP_GEOMETRY when `malloc_usable_size(dst)` is not the
 * 32 - sizeof(size_t) the arithmetic above assumes, or when `src`'s user pointer is
 * not at dst+32, the position the paragraph above gives it and the one that puts
 * the overwritten size field inside a chunk this probe owns. Either failure is a
 * withheld cell naming its cause rather than a guess about what the copy hit. The
 * other C libraries carry no expectation here: the check is gated on them before
 * this probe's answer is read.
 *
 * ## The precondition, and the probe's own check of it
 *
 * Everything above rests on one property: the compiler that built this must not
 * know the destination's size. `want` is `volatile` for exactly that reason. A
 * volatile read cannot be folded, so `malloc(want)` carries no `alloc_size` the
 * front end can evaluate, `__builtin_object_size(dst, n)` answers unknown, and the
 * level-2 wrappers, which use that static query, install no check. Remove the
 * keyword and `malloc(16)` is a constant: level 2 bounds the copy at 16, fires on
 * the 32-byte write, and the run is indistinguishable from level 3. That is a
 * false `on:3` for a level-2 toolchain, the direction this project is least
 * prepared for, and it was measured rather than supposed. On this file's own host
 * (Apple clang 21.0.0 and Homebrew gcc 16.2.0, arm64, `-D_FORTIFY_SOURCE=2`, at
 * `-O2`, `-O3`, `-O2 -flto` and `-O3 -flto`): with the keyword all eight builds
 * print `no-check-fired` and exit 0; with it removed, and before the self-check
 * below existed, all eight die in Apple's `__chk_fail_overflow` trap, status 133,
 * which the runtime detector credits as the fortify observable. The review that
 * found the hazard measured the same on Linux with gcc and clang at `-O2` and
 * `-O2 -flto`: `*** buffer overflow detected ***`, exit 134, in all four builds.
 *
 * So the keyword is checked rather than trusted. Before the copy, the probe asks
 * the same static question the level-2 wrappers ask, and if the answer is a size
 * it exits CHARD_EXIT_OPACITY_LOST, distinct from 0 and from any signal, which the
 * runtime detector reads as a withheld verdict rather than as either level. Both
 * static types are queried: glibc's level 2 asks type 1, Apple's headers and
 * fortify-headers ask type 0. Link-time optimisation is the other way a size can
 * become visible, so the check's control arms carry `-fno-lto` last; the measured
 * build keeps the profile's flags unaltered, and this self-check is what protects
 * it there.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* `malloc_usable_size` is glibc's, from <malloc.h>. musl and Apple have equivalents
 * under other names and other geometries, and neither is what the margin above is
 * computed from, so the assertion is made only where the claim is. */
#if defined(__GLIBC__)
#  include <malloc.h>
#  define CHARD_HAVE_USABLE_SIZE 1
#endif

/* The crash this probe takes leaves no core: `CHARD_NOT_DUMPABLE` in chard_selfreport.h. */
#define CHARD_WANT_NOT_DUMPABLE

/* After the libc headers, so `_FORTIFY_IMPL` reflects which implementation
 * actually wrapped this translation unit. The runtime detector needs it: glibc
 * aborts with a message, fortify-headers traps silently, and the two cannot be
 * told apart from the termination alone. */
#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

/* `volatile` is the mechanism, see the header comment: it is what keeps the
 * allocation size opaque to `__builtin_object_size`, and without it level 2 fires
 * like level 3 on both compilers. The self-check in `main` catches its loss. */
static volatile size_t want = 16;
static volatile size_t n = 32;

int main(void)
{
    CHARD_PRINT_REPORT;
    CHARD_NOT_DUMPABLE;

    char *dst = malloc(want);
    char *src = malloc(64);

    if (dst == NULL || src == NULL) {
        /* Distinct status so an allocation failure is never read as "level 2". */
        return CHARD_EXIT_NO_ALLOCATION;
    }

    /* The precondition, asked of the compiler that built this. A size known to
     * either static query is a size level 2 would enforce, and then this run could
     * not tell level 2 from level 3. */
    if (__builtin_object_size(dst, 0) != (size_t) -1
        || __builtin_object_size(dst, 1) != (size_t) -1) {
        fprintf(stderr,
                "chard-probe: opacity lost: __builtin_object_size(dst) is %zu (type 0) "
                "and %zu (type 1) rather than unknown, so a level-2 build would fire "
                "like level 3\n",
                (size_t) __builtin_object_size(dst, 0),
                (size_t) __builtin_object_size(dst, 1));
        return CHARD_EXIT_OPACITY_LOST;
    }

#if defined(CHARD_HAVE_USABLE_SIZE)
    /* The margin's premise: the chunk geometry the header comment describes, and
     * `src` as the neighbour whose size field the copy overwrites. Both are read
     * at run time; the offset is printed rather than the addresses so the message
     * is the same under address-space randomisation. */
    if (malloc_usable_size(dst) != 32 - sizeof(size_t)) {
        fprintf(stderr,
                "chard-probe: heap geometry is not the one the margin assumes: "
                "malloc_usable_size(dst) is %zu, expected %zu\n",
                malloc_usable_size(dst), 32 - sizeof(size_t));
        return CHARD_EXIT_HEAP_GEOMETRY;
    }
    if ((uintptr_t) src != (uintptr_t) dst + 32) {
        fprintf(stderr,
                "chard-probe: heap geometry is not the one the margin assumes: "
                "src is at dst%+td, expected dst+32\n",
                (ptrdiff_t) ((uintptr_t) src - (uintptr_t) dst));
        return CHARD_EXIT_HEAP_GEOMETRY;
    }
#endif

    memset(src, 'A', 64);
    memcpy(dst, src, n);

    printf("no-check-fired %c\n", dst[0]);
    return 0;
}
