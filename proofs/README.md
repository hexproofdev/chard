<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Proofs

Kani harnesses over the ELF reader's bounded reads, the only code in chard that takes input it
did not produce. Each file here is a module of `src/elf.rs` under `#[cfg(kani)]`, so an
ordinary build never compiles it.

- `cursor_reads_total.rs`: `Cursor`'s slice, fixed-width, address and string reads over any
  offset and length return the bytes asked for or an error, and never panic.
- `align_up_is_least_multiple.rs`: `align_up` returns the least multiple of a power-of-two
  alignment and refuses only on overflow.
- `note_walk_stays_in_its_table.rs`: every note and property the walk takes lies whole in its
  table, and the walk moves forward.

Run them with `make kani`; `scripts/kani-gate.sh` fails unless every declared harness is
verified by name. CI's `kani` job runs the same script.
