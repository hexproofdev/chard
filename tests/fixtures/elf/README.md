<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Synthetic ELF fixtures

Every object here is written byte by byte by `tests/elf_builder/mod.rs`, never by a linker.
`tests/elf_fixtures.rs` holds the checked-in bytes equal to the builder's and holds the facts
the reader reads from each object to the builder's spec, written in the test.
`tests/elf_readelf.rs` compares the reader against `readelf` over them.
