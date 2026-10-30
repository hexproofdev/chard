<!-- SPDX-License-Identifier: BSD-3-Clause -->

# chard fuzz targets

libFuzzer targets for the inputs chard parses. This is a separate, dev-only crate with its own
`[workspace]`: chard's build, tests, `cargo tree` and `cargo deny` never see `libfuzzer-sys`,
chard keeps its four direct dependencies, and the published package excludes `/fuzz`.

The targets need a nightly toolchain and cargo-fuzz, which the hosts that run the merge gate
are not held to, so nothing here runs in `make check`, `make merge-gate`, `make verify` or CI.
`make check-full` runs `make fuzz-replay`: one pass over every corpus, seed and kept crash, with
no mutation, so a reader change that breaks a target's law fails there. The replay counts the
inputs it feeds each target and fails on a target with none. `detect_evidence`, `report_render`
and `parse_macros` read only the ignored corpus, so on a fresh clone `make fuzz-seed` comes
first.

## Targets

| Target | Input | Invariant |
|---|---|---|
| `elf_parse` | arbitrary bytes | `elf::Elf::parse` and `facts` never panic; a cut table is a recorded truncation, not an index out of bounds; an error formats; the facts survive a JSON round trip unchanged; the code reader's `code_scanned` and `code_matches` agree with each other, with `elf::code`'s two lists and with `MATCHES_KEPT` |
| `detect_evidence` | arbitrary JSON | `detect::decode_evidence` never panics, for every corpus check, alone and with each arm; a report handed to `chard detect` is the one input a third party may have written. Every replay's counts close (`Replay::closes`), and the same input decoded twice prints the same output or the same refusal |
| `predicate` | a vector `{"predicate", "facts"}` or a file of them under `vectors` | a predicate that deserializes is validated, and one that validates is evaluated over its facts through the Published and the Live view and rendered, without a panic. Where the facts read as typed `ElfFacts` and a macro map, `tests/predicate_language.rs`'s two promises hold over them: a publication of the same facts evaluates to exactly what the Live view did, trimmed or untrimmed; one with no watch list stops at `symbols_filter` exactly when a symbol was read; removing any key the evaluation read stops it at that key; and the input's own publication, where it concludes, states the Live view's clause, outcome and level |
| `report_render` | one report, or an array of them | `chard table` (both formats, both groupings, mixed or not) and `chard matrix` render or refuse the set without a panic; THREAT_MODEL.md's "whoever hands you the report". Each renders or refuses identically twice, and the plain table of the reports written compactly equals that of the same reports pretty-printed and, for a single report, that of the input's own bytes |
| `parse_macros` | arbitrary bytes, decoded as UTF-8 lossily and trimmed at the end, as chard reads a `-dM -E` dump | `compile::parse_macros` never panics and parses the same text to the same map twice; every key holds no space and no line break and is named by some `#define ` line, every value is trimmed; the map has no more entries than the text has `#define ` lines; and the map written back as `#define NAME VALUE` lines parses to itself. That a key is a non-empty identifier is not held, since the function does not promise it (the target's module documentation says why) |
| `attestation` | arbitrary text, as `--image-attestation` reads a file | `env::Attestation::from_json` never panics and parses the same text to the same value or refusal twice. What it accepts is a JSON object of known keys, its `installed_disk` an object of known keys; every non-null key comes out as it went in, the three digests lowercased, the two defaults and the three nulls as documented; `digest` is lowercase hex of its `digest_kind`'s length, `installed_disk.installed_from_digest` equals it and `installed_at` is a real instant by a day-count check independent of the parser's; the value written back, and the `image_attestation` block a report publishes for it, parse to an equal value; `classify`, asked for a host, a container and a VM, refuses it as a mismatch exactly when the manifest was fetched and the digest did not match, otherwise refuses it for a host and gives a container and a VM the same record; and its `run.inputs_sha256` lines (`report::attestation_inputs`) are the ones spelled from the parsed value, for it and for its re-parse |
| `flag_words` | arbitrary bytes, decoded as UTF-8 lossily and split at every line feed into the words of a profile's flag list | the readers `measure` refuses a profile by (`compile::response_file_arguments`, `toolchain::runtime_removing_flags`, `compile::relative_path_arguments`; not `toolchain::unsupported_target_flags`, which finds `cc1`'s `-triple` and its value across clang's `-Xclang` list, two words that need not be adjacent, so the laws here do not describe it) the three whose words the control arms carry (`toolchain::target_selecting_flags`, `toolchain::runtime_selecting_flags`, `toolchain::header_selecting_flags`, with `selects_target`) and the two that carry the profile's own words into the arms' `-###` compile listing (`compile_inputs::macro_words`, `compile_inputs::optimization_words`, with `macro_name` asked of every word) never panic and read the same list twice the same way; every word they return is a word of the input, in order (a relative path's words, up to four adjacent ones, joined by a space: an option and its separate argument, or the pairs that hand a tool an option and its path); a refused word is refused whatever surrounds it (a response file is the input's words each refused alone; a removal is refused alone or, after a word that hands the next one on (`-Xpreprocessor`, `-Xarch_<arch>`), as that pair alone, a relative path is refused alone, a list split by a neutral word, `-O2` or the absolute `/`, is read as its two halves, and a removal or a relative path refused alone at any position takes nothing from what follows it, so the reading from there is that refusal and then the reading from after it; a path option handed to a tool with no path after it is refused as unpaired, which `compile::relative_path_readings` reports, and the laws allow that refusal, and it alone, to go where the next words hand it its path); a selected word is selected whatever follows it, and a selection selects itself whole; the four readers whose words the arms carry (`target_selecting_flags`, `runtime_selecting_flags`, `header_selecting_flags`, `linker_program_flags`) and the two whose words the arms' stand-in listing carries (`macro_words`, `optimization_words`) read no word of the input twice between them: wherever one of them takes the words at the head of a list, every other reads that list as it reads the words after them, and what the six return together is the input with words left out (a law over the six against each other, which catches a return to independent walks and not a misreading all six share; the module documentation says why); a word the driver takes the next one as the value of (`toolchain::takes_a_value`, the crate's own classifier, as the longest selection is) takes it from the six carried readers, `selects_target`, `runtime_removing_flags` and `driver_divided_pairs`, which read a list from such a word as from after the pair (`-u -B/x` selects nothing and refuses nothing; the one exception is the macro reader's own `-D` or `-U` in any of gcc's spellings, told by `macro_words` carrying the pair whole); `driver_divided_pairs` is held to the pair laws of `relative_path_arguments` with `-O2` as its neutral word; `macro_name` names a word's macro up to its first `=` or `(`, and a word of `macro_words`' or `optimization_words`' own, alone, is carried, and `optimization_words` carries no word but its own: one beginning `-O`, or gcc's `--optimize` whole or abbreviated to a prefix at least `--op` long, alone, or whole with `=N` (what gcc 16.1.1 takes; the module documentation has the measurement). The module documentation states each law and why its separator is neutral |
| `structured_diag` | arbitrary bytes, decoded as UTF-8 lossily, as a side build's stderr | `structured::decode` never panics and reads the same stderr the same way twice; text ahead of the document (clang's unstable-format line) leaves the reading as it was, refusal included, and text after a decoded one leaves its findings; the findings written back as a document of one run decode to themselves; `severity_of` answers in its vocabulary, with the first carrying finding's level, `None` exactly when no message carries a needle (case folded), and answers for a needle from a finding's own message; `compare` publishes readings in `STRUCTURED_READINGS` and outcomes in `OUTCOMES` for every prose reading, its structured reading being `severity_of`'s. On the seeds the reading is held to what the compilers printed: `seed.rs` refuses a SARIF stderr of the fixtures that reads as undecodable or empty |
| `report_digest` | arbitrary JSON | `report::digest::derive` never panics and derives the same digest or refusal twice; the status given is its `consistency` and changes nothing else; it reads its seven fields and no other, so a report's own `digest` decides nothing in it; a derived digest serializes, its verdict counts are the observations' verdicts counted, its rows are the observations' checks in order with their verdict, level, polarity and channel, its reasons are those rows in order with their verdicts, and its profile's sentence is `meaning`'s; `of_read`, what `chard digest` prints, prints only the digest `derive` gives over the same report under its own status. The live derivation's digest of each seed report is the one it carries, which the last law holds whenever the read is not refused |
| `driver_text` | arbitrary bytes, decoded as UTF-8 lossily, as a driver's or linker's output | the readers of a driver's `-###` listing (`compile_inputs::parse`, `link_inputs::parse`, `toolchain::link_line`), its `-v` report (`toolchain::parse_verbose`), a linker's `--version` banner and `.comment` line (`toolchain::linker_kind`, `toolchain::linker_line`), the `-fhardened` dump's diagnostic and the `-dumpmachine` triple (`toolchain::arch_of_triple`) never panic and read the same text the same way twice; `compile_inputs::parse` reads the text as its lines each parsed alone and joined, refusing with the first line's refusal, and reads only `REMOVALS`, `HEADER_OPTIONS` and `-D`/`-U` words into those fields; `link_inputs::parse` reads command lines alone and `link_line` the last link line alone; `parse_verbose` reads two texts joined by a line feed as its halves; the banner and line readers name only their own vocabulary, a version being a word of its line; the diagnostic is the first line naming the option, trimmed; a triple reads as its first component, and what it reads to reads to itself |
| `env_reads` | arbitrary bytes, decoded as UTF-8 lossily and split at U+001E into the files `env` reads | `env::read_uid_map` reads fields and lines, not spacing, reads `Malformed` exactly where a line is not three `u32` numbers (by a parse of the target's own) and `Unwritten` exactly where it has none, and its extents written back read to themselves; `env::observe_execution_mode` over the reads concludes nothing but `container`, and concludes it exactly when a positive marker is there (a runtime marker file, a cgroup word, a non-blank systemd marker, a non-empty first `container=` word, a non-identity or unwritten uid map), so silence, a refusal and a malformed map settle nothing; every character of its sentence prints as itself (nothing `char::escape_debug` escapes is left raw, controls, format and separator characters among them), whatever the files held; a kernel's spelling decides its byte order whatever chard's own build, and `runs_natively` says `true` only for the kernel's own order |

The readers `driver_text` and `env_reads` call that are not otherwise public (`toolchain::link_line` and its `LinkLine`, `parse_verbose`, `linker_kind`, `linker_line`, `fhardened_diagnostic`, and `env::PlatformReads` with `observe_execution_mode`) are public for them, each saying so. Two readers of foreign text have no target: `guide::INVENTORY` is a table compiled into chard, not a reading of anything, and `compile_inputs::differences`, like `report::set_aside` below, resolves paths on the real filesystem. The readers of `os-release`, `cpuinfo` and macOS's `SystemVersion.plist` (`env::distro_from`, `cpu_from`, `distro_from_system_version`) are reached by no target.

The compiler-diag and runtime decoders are `pub(crate)`, so no target calls them directly.
`tests/diag_grammar.rs` drives the diag decoders with generated stderr, and `detect_evidence`
reaches the runtime decoders through `detect::decode_evidence`, which replays a record's or a
report's run through each check's decoder. The 2026-10-06 campaign (the project ledger, Fuzzing
and proofs) ran `decode::runtime::detect_stack_clash` 12100 times in a coverage build over its
`detect_evidence` corpus and left its normalized-distance branch unexecuted where no seed holds
a distance `--normalize` masked, so `seed.rs` writes such records.

`report::set_aside`, which classifies `-o` before a run, is not fuzzed: every step of its
classification (`symlink_metadata`, the link chain `link_end` follows, whether the end's
directory exists) is a call on the real filesystem, so an input would have to be a tree of
files and links built for each execution, and the classification has no part a fuzzer can
call without one. Its unit tests build those trees.

## Running

Needs `cargo-fuzz` and a nightly toolchain (`FUZZ_TOOLCHAIN`, default `nightly`).

```sh
make fuzz-seed              # a fresh report into corpus/detect_evidence/
make fuzz FUZZ_TIME=300     # each target for five minutes
make fuzz-replay            # every corpus, seed and kept crash once, no mutation, counted
```

Each target's first corpus directory is `corpus/<target>/`, which libFuzzer grows and git
ignores. The seeds come from three places:

- Tracked elsewhere: `tests/fixtures/elf/` for `elf_parse`; `schema/` (with
  `chard-predicate-vectors.json`) for `predicate`; `tests/fixtures/`, whose `sample-report.json`
  is a whole report, for `report_digest`.
- Tracked here, from their readers' unit tests and the fixtures: `seeds/<target>/` for
  `flag_words`, `structured_diag`, `driver_text` and `env_reads`. `seeds/flag_words/` holds the
  flag lists of the readers' unit tests in `src/compile.rs`, `src/toolchain.rs` and
  `src/compile_inputs.rs`, one word a line, each a list a reader takes, refuses or passes; a
  flag list names nothing about the host. `make fuzz` passes these directories and the ones
  above after the target's corpus directory, and libFuzzer writes only into the first. A hand
  run that names a seed directory first makes libFuzzer write new inputs into it, among the
  tracked seeds.
- Written by `make fuzz-seed` and never tracked, because each names the host or toolchain it
  came from: the reports in `corpus/detect_evidence/`, which `report_render` and
  `report_digest` read as seeds too; and `parse_macros`'s inputs, each `FUZZ_SEED_CCS`
  compiler's own `-dM -E` dumps in `corpus/parse_macros/` (with no source, with `<stdio.h>`,
  `<stdlib.h>` and `<string.h>` under `-O2 -D_FORTIFY_SOURCE=2`, and as C++ over `<string>`),
  to which `seed.rs` adds every report's filtered `macro-dump` store entries written back as
  `#define` lines, of which reports measured at this revision store none.

`make fuzz-seed` measures with each compiler `FUZZ_SEED_CCS` names (default `cc`; more than
one varies the set on the compiler axis) under `FUZZ_SEED_PROFILES` (default `bare
bare-optimized openssf-tldr`). It copies every ELF artifact those measurements built into
`corpus/elf_parse/` (executables, shared objects and objects on an ELF host; none on macOS).
Then `seed.rs` writes:

- into `corpus/detect_evidence/`: one fixture record per (check, arm, outcome) of
  `tests/fixtures/detectors.json`; for each whose run prints a value
  `report::VOLATILE_READINGS` names (the stack-clash probe's `dist=`), a copy with the value
  masked as `--normalize` masks it, and one masked copy with a ratio of 0; one store entry of
  each kind; and a `chard elf`-shaped object;
- into `corpus/elf_parse/`: every `tests/fixtures/elf/*.elf`, counted against the
  `*.expected.json` files beside them, so a run over the corpus alone starts from the fixtures
  too (the 2026-10-06 campaign's was such a run, and its coverage left the `EM_RISCV` arm of
  the relocation-name table unexecuted, which `elf64-le-riscv-rel-no-plt-got.elf` reaches);
- into `corpus/report_render/`: the reports alone and joined as one array, once as measured
  and once with one report moved to another corpus and revision.

The joined copies are slimmed to what `table` and `matrix` read. libFuzzer cuts an input above
1048576 bytes when `-max_len` is not given, and a set of three whole reports, cut short, parsed
as nothing. Slimmed, they took `report_render` from 74% to 91% of `dataset.rs`, 55% to 85% of
`matrix.rs` and 90% to 97% of `table.rs` over the same corpus (2026-09-29, Darwin arm64
coverage build over a Fedora 44 x86_64 corpus).

Byte mutation over a report seed reached none of the record, store-entry and `chard elf`
shapes: on 2026-09-29, after an hour of fork-mode fuzzing on Fedora 44 x86_64, 1355 of the
1379 `detect_evidence` inputs that parsed were still reports, and those paths of `detect.rs`
stood at no coverage.

`attestation` has no tracked seeds either: an attestation names its publisher's URLs and,
for a container lane, a local path. `seed.rs` writes a fixed set under `example.invalid`
URLs (each digest kind with and without an installed disk, the shape without `origin` and
`manifest_fetched`, no manifest, a mismatch) and every attestation in the reports it reads,
bare and as published; `make fuzz-seed FUZZ_SEED_ATTESTATIONS="<files>"` adds every
attestation found in the JSON files named (a fleet's session files, reports, a fetcher's
`attestation.json`), each once by content, into `corpus/attestation/`.

`make fuzz` and `make fuzz-replay` pass each target one dictionary with `-dict=`:

| Dictionary | Holds | Targets |
|---|---|---|
| `dictionaries/elf.dict` | ELF and note magic, note, program-header and dynamic-tag words, section and symbol names | `elf_parse` |
| `dictionaries/report.dict` | report, store and predicate keys, and the verdict and outcome words | `detect_evidence`, `predicate`, `report_render`, `report_digest` |
| `dictionaries/macros.dict` | `#define`, line endings, `__`, parentheses, a backslash and the macro names chard reads | `parse_macros` |
| `dictionaries/attestation.dict` | the attestation's keys, digest kinds, fetcher words and boundary timestamps | `attestation` |
| `dictionaries/flags.dict` | the line feed that separates words, and the pass-through, path, selection, removal and value-taking spellings and near spellings of them | `flag_words` |
| `dictionaries/sarif.dict` | the SARIF keys and levels, clang's banner and count | `structured_diag` |
| `dictionaries/driver.dict` | the line shapes of a `-###` listing, `-v`, a banner and a `.comment` line, and the words the readers take | `driver_text` |
| `dictionaries/env.dict` | the field separator and read markers, the container and cgroup words, the uid map's numbers and the kernel spellings | `env_reads` |

## The JSON-aware mutator

About half of each JSON corpus of the first run did not parse as JSON: byte mutation over
documents of hundreds of kilobytes breaks the syntax, and those executions stopped in the
parser. `fuzz_targets/json_mutator.rs`, installed in `detect_evidence`, `predicate`,
`report_render`, `attestation` and `report_digest` through libFuzzer's custom-mutator hook, parses the input and makes one
structural edit to a node reached by a random walk down from the root: a value replaced by
another type, a boundary number or a word chard reads (a verdict, an outcome, a store kind, a
predicate key), a key or element removed, an element duplicated, an array cut, a subtree
grafted from elsewhere, a string mutated or repeated long. One mutation in five, and every
input that does not parse, goes to libFuzzer's byte mutator, so the parser's own refusals stay
covered. `CHARD_FUZZ_BYTES_ONLY`, read by the harness alone, turns it off for comparison.
`attestation` adds its own keys and digest kinds (`ATTESTATION_WORDS`) to the words it offers
through `mutate_with`; the other targets offer only the shared list.

Measured on Darwin arm64 on 2026-09-29, ten minutes per arm from the same seeds, as edges
libFuzzer reports (with the mutator, then byte mutation alone): `detect_evidence` 7220 and
7088, `predicate` 3587 and 3306, `report_render` 4843 and 4748, at a sixth to a tenth of the
executions, since an input that parses runs the code behind the parser. Choosing the edited
node uniformly loses on `report_render` (4369 and 4580): in a report almost
every node is a leaf inside some observation's evidence, which the renderers never read.

A crash worth keeping is minimised (`cargo +nightly fuzz tmin`) and committed under
`crashes/<target>/` beside a `.note` saying what it found, on which input, when and where,
and what the code does with that input;
`make fuzz-replay` then reruns it.
