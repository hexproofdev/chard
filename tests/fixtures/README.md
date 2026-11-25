<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Test fixtures

Every input here is made by hand or by a generator in this tree, never recorded from a
toolchain, so the suite runs the same on any host.

| path | what it is |
|---|---|
| `synthetic-rows.json` | hand-written evidence rows, each with the reading its check's decoder must give; `tests/synthetic_rows.rs` replays every row |
| [`elf/`](elf/) | synthetic ELF objects that `tests/elf_builder/mod.rs` writes byte by byte |

A row's `toolchain` id begins `synthetic:`, so no reader takes it for a measured toolchain.
