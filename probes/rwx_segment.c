/* SPDX-License-Identifier: BSD-3-Clause */

/*`rwx-segment-absent`'s positive control: a second input of that arm's link alone, named after
 *`link_defaults.c` on the arm's command line. chard hands it to no other build of any probe. */

__asm__(".section .chard.rwx,\"awx\"\n"
        "\t.globl chard_rwx_byte\n"
        "chard_rwx_byte:\n"
        "\t.byte 0\n"
        "\t.previous");
