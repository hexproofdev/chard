/* SPDX-License-Identifier: BSD-3-Clause */

/* -fstrict-flex-arrays probe (runtime channel).
 *
 * A trailing array at the end of a struct is how C code has always faked a
 * variable-length member: `char tail[1]` and then allocate more than the struct's
 * size. The compiler traditionally plays along, treating any trailing array as
 * unbounded, which means `__builtin_object_size` cannot bound it, and every
 * mechanism built on that answer stops working there. Fortify is the one that
 * matters: a fortified `memcpy` into a trailing array is unfortified in practice,
 * because the size it would check against is unknown.
 *
 * `-fstrict-flex-arrays=N` narrows which declarations get that treatment, so real
 * arrays are bounded again and only genuine flexible members `[]` are exempt. The
 * guide recommends `=3`.
 *
 * ## The observable
 *
 * `__builtin_object_size(p, 1)` (the subobject-precision query) answers with the
 * trailing array's own size when it is treated as a real array, and with the whole
 * remaining object when it is treated as flexible. The value is folded at compile
 * time, so this is a runtime *print* of a compile-time decision.
 *
 * Three declarations pin the whole ladder, because each level exempts one fewer
 * spelling. Measured identically on gcc 16 and clang 22:
 *
 *   level   char tail[2]   char tail[1]   char tail[0]
 *   0       flexible       flexible       flexible
 *   1       bounded        flexible       flexible
 *   2       bounded        bounded        flexible
 *   3       bounded        bounded        bounded
 *
 * So the reported level is the strictest one consistent with the three readings,
 * which makes this a graded check rather than a boolean, `partial` where a
 * distribution sets `=1` or `=2`, which is a real posture and not a failure.
 *
 * ## Why the storage is a declared union and the pointers are file-scope
 *
 * `__builtin_object_size` is answered from what the compiler knows about the object.
 * A flexible reading needs a size to report, the rest of the object past the trailing
 * array, so the object has to be larger than the struct and the compiler has to know by
 * how much. Each struct therefore sits in a static union with a `char` array `SLACK`
 * bytes longer than it: the trailing array is at the end of the struct and the object
 * extends past it, which is exactly the pattern the flag exists to govern.
 *
 * The query goes through file-scope pointers assigned in `main`, not through the union
 * itself. Queried as `object.s.tail`, the member is bounded whatever the flag says,
 * because the array is not at the end of the union that holds it. Through the pointer,
 * the optimizer finds the object and the flag decides the reading; an unoptimized build
 * does not find it. A compiler that someday applied the declared-member rule through the
 * pointer as well would bound every spelling in the negative arm, and the control
 * triple, not this construct, is what reports that: both arms would read level 3 and the
 * check would be `probe-invalid`.
 *
 * Storage from `malloc(sizeof *p + SLACK)` would make the flexible readings depend on the
 * compiler recognizing the allocator: under `-fno-builtin-malloc`, which OpenBSD 7.9's
 * driver passes, the negative arm has no size to report. The union has no allocator to
 * recognize. The measurements behind both statements, per host and compiler, are in the
 * project ledger's OpenBSD 7.9 section.
 *
 * ## Why the probe says whether it was optimized
 *
 * `__builtin_object_size` answers `-1` when it cannot determine a size at all. Without
 * optimization gcc answers `-1` for every query and clang for the flexible ones, since
 * neither follows the pointer to the object it was assigned. The `optimize=` line tells
 * the detector that this is the cause, from `__OPTIMIZE__` as the compiler set it rather
 * than from a reading of the command line. `storage=declared` tells it the reading came
 * from this construct, so an optimized `-1` is not blamed on an allocator the probe no
 * longer uses; evidence from the heap construct carries no such line.
 */

#include <stdio.h>
#include <sys/types.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

struct trailing_two {
    int header;
    char tail[2];
};
struct trailing_one {
    int header;
    char tail[1];
};
struct trailing_zero {
    int header;
    char tail[0];
};

#define SLACK 32

/* Each object is its struct with SLACK bytes of declared storage after it. */
static union {
    struct trailing_two s;
    char storage[sizeof(struct trailing_two) + SLACK];
} two_object;
static union {
    struct trailing_one s;
    char storage[sizeof(struct trailing_one) + SLACK];
} one_object;
static union {
    struct trailing_zero s;
    char storage[sizeof(struct trailing_zero) + SLACK];
} zero_object;

/* File-scope so an unoptimized build does not see which object each one names. */
static struct trailing_two *two;
static struct trailing_one *one;
static struct trailing_zero *zero;

int main(void) {
    two = &two_object.s;
    one = &one_object.s;
    zero = &zero_object.s;

    /* Each prints its own size when bounded, or the rest of the object when the
     * declaration is being treated as a flexible member. */
    printf("flex-two=%zd flex-one=%zd flex-zero=%zd\n",
           (ssize_t)__builtin_object_size(two->tail, 1),
           (ssize_t)__builtin_object_size(one->tail, 1),
           (ssize_t)__builtin_object_size(zero->tail, 1));
#ifdef __OPTIMIZE__
    printf("optimize=yes\n");
#else
    printf("optimize=no\n");
#endif
    printf("storage=declared\n");
    return 0;
}
