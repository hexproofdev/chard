/* SPDX-License-Identifier: BSD-3-Clause */

/* -fPIC against -fPIE, read from the relocation the compiler wrote for one access. */

#include <stdio.h>

#include "chard_selfreport.h"

CHARD_EMIT_REPORT;

#if defined(__GNUC__) && !defined(__clang__)
#define CHARD_PIC_EXPORTED __attribute__((visibility("default"), externally_visible))
#else
#define CHARD_PIC_EXPORTED __attribute__((visibility("default")))
#endif

CHARD_PIC_EXPORTED int chard_pic_object_anchor[1024] = {7};

int chard_pic_object_probe(int index);

/* The array is indexed by the argument so that the read cannot be folded to a constant. */
CHARD_PIC_EXPORTED int chard_pic_object_probe(int index)
{
    return chard_pic_object_anchor[index & 1023];
}
