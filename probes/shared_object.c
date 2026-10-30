/* SPDX-License-Identifier: BSD-3-Clause */

/* Shared-object probe for linker flags that only take effect on a `.so`.
 *
 * `-Wl,-z,nodlopen` is the reason this exists. On an executable the linker
 * accepts the flag, emits DT_FLAGS_1, and leaves DF_1_NOOPEN clear, so a probe
 * that measured it on an executable would report "off" on every distro, forever,
 * and be wrong about all of them. The flag is only meaningful for the kind of
 * object that could be dlopen'd in the first place.
 *
 * One exported function with external linkage, so the object is a legitimate
 * library rather than an empty one the linker might treat specially.
 *
 * ## Why there is a global here
 *
 * `chard_shared_anchor` returns the address of static data, and that address is
 * what `textrel-absent` needs in order to be measurable at all. A text relocation
 * only arises where code must name an address the linker cannot fix at link time;
 * a leaf function operating solely on its argument never does. This probe was
 * exactly that leaf function, so its positive control (`-fno-pic
 * -mcmodel=large -Wl,-z,notext`) linked cleanly and produced no TEXTREL, the
 * control could not discriminate, and the check reported `probe-invalid` on a
 * toolchain that was working correctly.
 *
 * The anchor is `static const` so it lands in a read-only section: the relocation
 * has to point *into* the text mapping for the flag under test to matter.
 */

#include <stddef.h>

/* Address-taken static data. See the note above; do not fold this into the
 * function or make it a local, or `textrel-absent` silently stops working. */
static const char chard_textrel_anchor[] = "chard";

const char *chard_shared_anchor(void);

const char *chard_shared_anchor(void)
{
    return chard_textrel_anchor;
}

size_t chard_shared_probe(const char *text);

size_t chard_shared_probe(const char *text)
{
    size_t count = 0;

    if (text == NULL) {
        return 0;
    }
    while (text[count] != '\0') {
        count++;
    }
    return count;
}
