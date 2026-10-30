/* SPDX-License-Identifier: BSD-3-Clause */

/* Probe for `-Wl,--as-needed`, whose observable is a library the linker chose
 * *not* to record.
 *
 * The corpus builds this against `-lm` and never calls a math function. With
 * `--as-needed` the linker sees that no symbol from libm was used and omits its
 * DT_NEEDED entry; without it, the entry is recorded regardless. So the
 * observable is an absence in the artifact's needed list, and the two control
 * arms differ by exactly one entry.
 *
 * ## Two traps, both of which produced a wrong measurement first
 *
 * `--as-needed` is **positional**. It applies only to libraries that appear
 * after it on the link line, so `cc probe.c -lm -Wl,--as-needed` leaves the
 * entry in place and reads identically to the negative arm, a control that
 * looks undiscriminating while the flag works perfectly. `compile::build`
 * already emits flags, then the source, then `link_libs`, which is the order
 * this needs; its comment says so.
 *
 * The library also has to be one the linker can genuinely drop. glibc 2.34
 * merged libdl, libpthread and librt into libc, so `-ldl` and friends produce
 * the same single DT_NEEDED in both arms and cannot show the difference. libm
 * still resolves to its own object here. Where it does not (a libc that merges
 * it, or a stub archive with nothing to record), neither arm carries the entry,
 * the controls agree, and the check reports `probe-invalid` rather than
 * inventing a verdict. That is the honest outcome and it is why the check does
 * not simply assume the entry exists.
 *
 * Nothing here calls into libm on purpose. Adding a `sqrt()` would make the
 * library genuinely needed, both arms would record it, and the check would go
 * quietly undiscriminating.
 */

int main(void)
{
    return 0;
}
