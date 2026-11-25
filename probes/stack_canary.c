/* SPDX-License-Identifier: BSD-3-Clause */

/* Stack-protector probe for the `elf-static` channel. */

#include <stdio.h>
#include <string.h>

/* `noinline` so that passing an address here is an escape at every optimization
 * level: inlined, the scalar's address would go nowhere and the -strong rule that
 * `address_taken_scalar` exists to exercise would not apply at -O2. gcc's IPA-SRA
 * still removes the escape at -O2 and -Os by passing the byte by value; the header
 * comment records the measurement and why the probe accepts it. */
__attribute__((noinline)) static void sink(const char *p)
{
    volatile char observed = *p;
    (void) observed;
}

/* Plain -fstack-protector, at the default threshold: a char array of at least
 * ssp-buffer-size bytes. */
__attribute__((noinline)) static void big_char_array(const char *arg)
{
    char buf[64];

    memset(buf, 0, sizeof buf);
    if (arg != NULL) {
        strncpy(buf, arg, sizeof buf - 1);
    }
    sink(buf);
}

/* -fstack-protector-strong: a scalar whose address escapes. */
__attribute__((noinline)) static void address_taken_scalar(const char *arg)
{
    char one = arg != NULL ? arg[0] : 0;

    sink(&one);
}

/* Plain -fstack-protector, independent of the threshold: a function that calls alloca. */
__attribute__((noinline)) static void variable_size(int len, const char *arg)
{
    size_t size = (size_t) len + 16;
    char *buf = __builtin_alloca(size);

    memset(buf, 0, size);
    if (arg != NULL) {
        strncpy(buf, arg, size - 1);
    }
    sink(buf);
}

int main(int argc, char **argv)
{
    const char *arg = argc > 1 ? argv[1] : NULL;

    big_char_array(arg);
    address_taken_scalar(arg);
    variable_size(argc, arg);
    return 0;
}
