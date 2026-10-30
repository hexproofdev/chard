<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Proofs

This directory holds the Kani harnesses `make kani` runs. This file says what each harness
proves, which properties are held by a test over their whole domain instead, and where the
line between the two lies. `tests/proof_harnesses.rs` holds this file to the code. Every
harness file in this directory is included under `#[cfg(kani)]`. Every harness is a row below
and every row is a harness. Every test a row names exists where the row says.

## What the harnesses prove

Each harness file is a module of `src/elf.rs` under `#[cfg(kani)]` and `#[path]`. A proof
reaches the reader's private fields that way, and an ordinary build, the tests and clippy
never see it.

| file | harness | what it proves |
|---|---|---|
| `cursor_reads_total.rs` | `slice_is_total` | over a 16-byte buffer and an unbounded `u64` offset and length, `Cursor::slice` returns a slice of exactly the length asked or an error, and never panics |
| `cursor_reads_total.rs` | `fixed_width_reads_are_total` | over the same buffer and offset, `u16_at`, `u32_at` and `u64_at` succeed exactly where `slice` serves their width, and decode the bytes read in the byte order the cursor was given |
| `cursor_reads_total.rs` | `addr_at_follows_its_width` | over the same buffer and offset, `addr_at` is `u64_at` on ELF64 and a widened `u32_at` on ELF32, in the error case too, and the widening adds no high bits |
| `cursor_reads_total.rs` | `refusals_are_classified` | over the same buffer, offset and length, every refusal `slice` returns carries the condition its variant states, a served read is the complement of every refusal, and `cover` says which refusals this target can produce |
| `align_up_is_least_multiple.rs` | `align_up_is_least_multiple` | for an unbounded `u64` value and each alignment from 1 to 64 that is a power of two, `align_up` returns the least multiple of the alignment not below the value, and refuses only on overflow |
| `align_up_is_least_multiple.rs` | `the_deleted_error_paths_were_unreachable` | for an unbounded `u64` value and each alignment from 2 to 64 that is a power of two, `align_up`'s one refusal is the overflow: for every value it serves, the quotient and the product that produced the result cannot fail |
| `align_up_is_least_multiple.rs` | `absolute_and_relative_padding_differ_where_it_matters` | for every name length up to 1024 and each alignment from 2 to 64 that is a power of two, padding a note's absolute offset and padding its name length agree where the fixed 12-byte header is a multiple of the alignment, and differ for every name length where it is not |

The two files' headers say which inputs the checker settles in seconds (a concrete
alignment, a 16-byte buffer) and which it does not (a symbolic divisor, an `anyhow` error on
the path). One harness doc names the mutant it was run against; another records the first
version of the harness, which proved nothing, and why it was replaced.

## What is held by a test over its whole domain

The properties below were considered for a harness and are held by a test that walks every
point of their domain instead. A harness over a domain a loop can walk adds nothing to the
test. The model checker would unroll the same loop, and it would run only under
`make verify`, while the test runs in every gate.

| property | domain | held by |
|---|---|---|
| The defect rollup's recount. `defect_coverage` keys an observation in protection terms, with `on` and `off` exchanged for a weakening check that observes protection; the consistency rule recounts it from the verdict as written. The two keys are the same once `on` and `off` are folded | every polarity, every word a check observes and every verdict, alone, declared twice and in every pair | `src/report.rs` `the_recount_agrees_with_the_rollup_on_every_polarity_word_and_verdict`; the exchange itself, which the fold hides, by `src/report.rs` `weaken_polarity_counts_absence_as_protection` |
| Inert-form coverage. Every graded check, and every check whose two control arms carry `-O2`, names the form in which its flag is present and inert, or the reason it has none, and not both | the corpus, a constant of the crate | `tests/inert_flags.rs` `every_graded_or_optimization_gated_check_names_its_inert_form_or_a_reason` |
| The mechanism table's shape. The table has a row for every question on every architecture it lists, and every check it names is a gated check of the corpus | the table and the corpus, constants of the crate | `src/mechanism.rs` `the_table_is_total_and_well_formed` |
| The gate derivation. `mechanism::decide` reads the table by searches, with no index and no arithmetic, and returns a decision for every check and architecture. Its decision for every gated check on every listed architecture, and on four targets outside the table, is the one named cell by cell | the gated checks by the table's architectures, and four names the table has no row for | `src/mechanism.rs` `the_decision_of_every_gated_check_on_every_architecture_is_the_one_named` |

## The line

Use a harness where the input is symbolic and unbounded (an offset, a length, a value) and
the code is arithmetic the model checker settles in seconds. Use a test over the whole
domain where the domain is a constant of the crate or a product of enumerations. Use neither
for a rule over data the checker cannot bound, such as a map keyed by strings. The
consistency rules hold those: a `measure` whose report contradicts itself exits 3 and
publishes nothing, and a report read back is held to the rules `report::REREAD_RULES`
lists, the recount among them (`DESIGN.md`).

## Running

`make kani` runs `scripts/kani-gate.sh`. The script runs `cargo kani` and fails unless the
harnesses the checker verified are, by name, the functions under `#[kani::proof]` in this
directory. It needs cargo-kani; `make doctor` says whether it is installed.

The verdict rests on the kani-verifier release as well as on the tree. The CI workflow pins
the release, and its `kani` job runs `make kani` where the tree is pushed. No gate in this
repository runs it, for the reason the Makefile gives. Run it when `src/elf.rs` or a file
here changes; `make verify` runs it after `make check`.
