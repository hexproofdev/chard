/* SPDX-License-Identifier: BSD-3-Clause */

/* Whether the profile's code can be linked into a shared object, which is what -fPIC
 * means and -fPIE does not.
 *
 * Linked `-shared` from code compiled exactly as the profile asks: chard adds `-shared`
 * and makes no position-independence choice of its own (`LinkMode::SharedObjectAsCompiled`).
 * A `-fPIE` or non-PIC object addresses `chard_pic_anchor` directly, since an executable's
 * own data cannot be interposed; in a shared object the symbol is exported and may be
 * preempted, so the linker refuses the direct reference with "recompile with -fPIC",
 * naming the symbol. A `-fPIC` object reaches it through the GOT and links.
 *
 * ## Why the global is exported, defined here, and 4096 bytes
 *
 * Every property below was measured to be load-bearing (2026-10-02, Fedora 44 x86_64
 * and aarch64, Ubuntu 22.04 and 24.04, Alpine; GNU ld, lld and mold):
 *
 *   - Without a referenced, exported global the probe has nothing for the linker to
 *     refuse, and a `-fPIE` object links as cleanly as a `-fPIC` one: a false `on`.
 *   - `visibility("default")` keeps the symbol preemptible under a profile carrying
 *     `-fvisibility=hidden`, which would otherwise let a `-fPIE` object link.
 *   - Defined in this translation unit rather than extern: for an undefined extern
 *     global, clang's `-fPIE` code already goes through the GOT on x86_64, and gcc's does
 *     on aarch64, so the link succeeds under `-fPIE` and cannot discriminate.
 *   - 4096 bytes, past aarch64's section-anchor offset limit of 4095: gcc at -O1 and
 *     above on aarch64 reaches a small global through a local section anchor, which the
 *     linker accepts in a shared object, so a 4-byte global linked under `-O2 -fPIE` (and
 *     under `-O2 -fno-pic`) with gcc 16.2.1. gcc anchors no declaration as large as the
 *     limit, so this one is addressed by its own name and refused.
 *
 * The array is indexed by the argument so that the read cannot be folded to a constant.
 *
 * What no probe shape can answer: `-Wl,-Bsymbolic` binds every defined symbol locally,
 * after which a `-fPIE` object is legitimately linkable into a shared object; gcc's LTO
 * under lld 22 regenerates the code at link time and exports neither symbol; and on
 * x86_64 GNU ld and mold accept `-mcmodel=large -fPIE` code, and mold `-fno-pic
 * -mcmodel=large` code by text relocation. Each link succeeds without -fPIC. The check's
 * regime-matched arm (the profile followed by `-fPIE`) links under each, and withholds
 * the verdict; the measurements are beside the check in `src/probe.rs`.
 */

/* The pragma pins the canary to a warning, as the other compiler-diag probes' pragmas do
 * (see warn_all.c): it then fires with no -Wall on the line, and under -Werror it stays a
 * warning instead of failing the link this check reads. */
#pragma GCC diagnostic warning "-Wunused-variable"

__attribute__((visibility("default"))) int chard_pic_anchor[1024] = {7};

int chard_pic_probe(int index);

__attribute__((visibility("default"))) int chard_pic_probe(int index)
{
    /* The diagnostic-channel canary, which every compiler-diag probe carries. Neither of
     * this check's readings rests on it: `absent` needs the linker's refusal text, and a
     * link that failed without it is `indeterminate`, and `present` is a link that wrote
     * its output. It is
     * here for the blanket rule, as in `copy_dt_needed.c`. */
    int chard_canary_unused = 0;

    return chard_pic_anchor[index & 1023];
}
