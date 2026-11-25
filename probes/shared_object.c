/* SPDX-License-Identifier: BSD-3-Clause */

/* Shared-object probe for linker flags that only take effect on a `.so`. */

#include <stddef.h>

/* Address-taken static data. */
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
