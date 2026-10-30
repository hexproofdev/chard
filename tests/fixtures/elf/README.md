<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Synthetic ELF fixtures

Every object here is synthetic: written byte by byte by `tests/elf_builder/mod.rs`, never
by a linker. Beside each `<name>.elf` is `<name>.expected.json`, which says so in its
first field, carries the description the builder gives, and records what `src/elf.rs`
read from the bytes when the record was written.

`tests/elf_fixtures.rs` holds three tests over every file: the checked-in bytes equal the
builder's output, the reader's facts equal the record, and a hand-written table of what each
file was built to carry. Each of the other tests there holds one reading, of a catalogued
file or of an object the builder writes in memory. `tests/elf_readelf.rs` compares the
reader against `readelf` over these files and over a sample of the host's own objects.

Regenerate with:

```sh
CHARD_REGENERATE_ELF_FIXTURES=1 cargo test --test elf_fixtures
```

and read the diff before committing it. A record is evidence of what the reader said;
regenerating it to make a test green is the drift the test exists to catch.

## What the records carry

`truncations` is a list of objects `{table, kind, detail}`. The stripped fixture's record
gives why its symbols cannot be read as the `detail` of a `symbols`/`unread` entry, and the
`.comment` it cannot look up as a `comment`/`unread` entry beside it. Every record but the
stripped one carries `symbol_tables`, the list of `SHT_SYMTAB` and `SHT_DYNSYM` sections the
reader walked, which the artifact precondition on the symbol-reading checks reads; the
stripped record has no section headers to walk and carries no such key. Every record carries
`dt_debug` and `dt_soname`, the two raw facts the link classification reads and records; only
the shared object carries `dt_soname: true`. Every relocatable record carries
`function_references`, which the reader writes only for an `ET_REL` with a symbol table; for a
linked object the member is `null` and omitted.

## Objects with a shape of their own

- `elf64-le-x86_64-static-pie-dt-debug`: the shape lld 10.0.0 gave a static PIE, `ET_DYN`
  with no interpreter, `DT_DEBUG` and no `DT_FLAGS_1`, which reads `static_pie: true`. The
  builder's `dt_debug` knob is off by default.
- `elf64-le-x86_64-rel-functions`: four sized functions in `.text` and a `.rela.text` placing
  references inside them, the shape `ssp-level-emitted` reads. `elf64-le-x86_64-rel`'s
  `function_references` reads `["chard_test_probe:"]`, its one function sized 0 and referring
  to nothing.
- `elf32-le-i386-rel-functions`: the same four functions as an ELF32 i386 object with a
  `.rel.text` of `Elf32_Rel` entries (no addend, the symbol index in `r_info` above bit 8)
  against `__stack_chk_fail_local`, the shape gcc gives an i386 object under `-fPIC`. It and
  the real i386 objects in the replay corpus are what read `SHT_REL`.
- `elf64-le-riscv-rel-no-plt-got`: an `EM_RISCV` relocatable object laid out after what gcc
  16.1.1 (Fedora 44's riscv64 cross compiler) writes for the no-plt probe's caller under
  `-fPIE -fno-plt -march=rv64gc_zicfilp_zicfiss -fcf-protection=full`. Its `.text` and
  `.riscv.attributes` bytes are that compiler's, copied into the builder, and the rest is the
  builder's layout. It carries `R_RISCV_GOT_HI20` against the callee, a `0xc0000000` property
  holding 3, which on RISC-V is the landing-pad and shadow-stack word and is recorded as a
  type with no feature bit decoded, and a `.riscv.attributes` section read with no
  truncation.
- `elf64-le-x86_64-exec-cet-forged`: the control executable, its IBT|SHSTK property kept,
  with `.text` holding `main` and the `cet-endbr` probe's three functions, sized in `.symtab`
  at their addresses and each beginning `lea` then `ret` with no `endbr64`. Those are the
  bytes gcc 16.1.1 and clang 22.1.8 compile under `-O2 -fcf-protection=none` on Fedora 44
  x86_64, and the property is what GNU ld 2.46.1 forces under `-z ibt -z shstk`, measured
  2026-10-05 with `chard detect` over both compilers' linked output. `cet-marked` reads the
  object's note `present` at `full` and `cet-endbr-emitted` its code `absent`, and
  `tests/elf_fixtures.rs` decides `cet-marked`'s control triple over it. In a linked object
  the builder writes a sized function's `st_value` as its section's address plus its offset.
