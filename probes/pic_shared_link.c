/* SPDX-License-Identifier: BSD-3-Clause */

/*Whether the profile's code can be linked into a shared object, which is what -fPIC means and -fPIE
 *does not. */

/* The pragma pins the canary to a warning, as the other compiler-diag probes' pragmas do
 * (see warn_all.c): it then fires with no -Wall on the line, and under -Werror it stays a
 * warning instead of failing the link this check reads. */
#pragma GCC diagnostic warning "-Wunused-variable"

__attribute__((visibility("default"))) int chard_pic_anchor[1024] = {7};

int chard_pic_probe(int index);

__attribute__((visibility("default"))) int chard_pic_probe(int index)
{
    /* The diagnostic-channel canary, which every compiler-diag probe carries. */
    int chard_canary_unused = 0;

    return chard_pic_anchor[index & 1023];
}
