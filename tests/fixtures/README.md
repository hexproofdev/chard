<!-- SPDX-License-Identifier: BSD-3-Clause -->

# Detector fixtures

Recorded evidence from real toolchains, replayed through the detectors by
`tests/detector_replay.rs`.

`sample-report.json` is one whole report, the one `README.md`'s sample table is rendered from.
It is `chard measure --profile bare` in the `docker.io/library/gcc:16` image (digest
`sha256:3f73339bf0d3d64081cac3f6d9fdafc6dd4cef2b9c49e0a09f91e97cb0eb139a`). The image's GCC
16.2.0 is configured with only `--build`, `--disable-multilib` and `--enable-languages`, as the
report's `configure_args` show. Its glibc 2.41 and binutils 2.44 are the image's own, and the
binutils version string names the distribution the image is built on. The image was booted as
an initramfs under a Linux 6.18.55 kernel in an x86_64 virtual machine with no network. Its
`os-release` was removed, so the report's `toolchain.id` and the table's column name no
distribution. The chard that wrote it was built from a copy of this tree outside git, so the
report carries no `run.harness_revision`; a chard built from a checkout or a crate archive
names its revision there. The observations' `notes` and the references' titles, which every
report carries, name distributions in their own prose. The file is the report as chard wrote
it.

`tests/detector_replay.rs` renders it with `chard table` and holds the README's rows to the
rendering. When a change to the table or to how chard reads a report breaks that, render it
again and paste the rows, or measure a new one the same way, on a kernel whose release string
names no host.

`tests/detector_replay.rs` also checks the sample's `consistency.rules_applied` against
`report::RULES`, in `the_readme_sample_lacks_only_the_rules_its_lag_names`. Every rule the
sample applies is one `RULES` lists, in the order `RULES` lists them. The rules it lacks are
exactly the ones the constant `SAMPLE_RULE_LAG` names. A change that adds a rule to `RULES`
must do one of two things in the same change. It measures the sample again as above and
empties `SAMPLE_RULE_LAG`. Or it adds the new rule's name to `SAMPLE_RULE_LAG`, so review
sees which rules the sample lacks.

A second corpus lives beside this one. [`elf/`](elf/) holds synthetic ELF objects written
byte by byte, with a record of what the reader read from each; nothing in it comes from a
toolchain, and [`elf/README.md`](elf/README.md) says how it is regenerated and why a
regeneration is read before it is committed. Everything below is about `detectors.json`.

These exist because chard's detectors are where a wrong answer gets published, and
without them they would be exercised against exactly one toolchain: whichever compiler
is on the developer's machine. That is the configuration least like the ones a sweep
meets. `detectors.json` carries evidence from toolchains that cannot be reproduced
here, mined from archived sweep output. `SUPPORT.md`'s matrix lists the compiler versions it
holds on each platform, and `tests/support_matrix.rs` holds the matrix to `detectors.json`.

## When the replay fails

The `expected` field is a **reviewed baseline**: what the detectors made of this
evidence when the fixture was created, inspected once. It is deliberately *not* the
verdict the archive recorded, which folds in the control triple and the gating and is
a different quantity, and it is deliberately not frozen from the archive, because an
archived verdict can come from a detector known to read its evidence wrongly.

So when the replay test fails, read the diff and decide whether the new answer is
better. If it is, regenerate and say why in the fixture's `note` field. Regenerating to
make the test green discards the only signal this file provides.

```sh
CHARD_FIXTURE_SOURCES=/path/to/sweep-output \
  CHARD_REGENERATE_FIXTURES=1 cargo test --test detector_replay recorded_evidence \
  -- --nocapture
```

`--nocapture` is what makes the run's accounting visible when it succeeds; libtest holds a
passing test's stderr.

`CHARD_FIXTURE_SOURCES` names the directories holding chard reports, `:`-separated for
several. Give it more than one where you can: mining a single sweep covers more checks
than the archives this file was built from and fewer compilers, and the compilers are the
point. The run prints what it read, what it kept, and any toolchain or check the new set
would lose, so that trade is visible before you commit it.

A lost toolchain stops the run before anything is written. Loss is counted on (toolchain,
architecture) pairs, and the refusal names each one as absent from the sources or thinned
away by another toolchain of the same family. `CHARD_FIXTURE_MERGE=1` carries the previous
rows of every pair the sources do not supply, which is how a regeneration from today's
reports keeps compilers only an older sweep reached; `CHARD_FIXTURE_ALLOW_LOSS=1` writes
despite a loss, for a retirement someone decided on and records in the commit. A reviewed
regeneration prints `losing 0 toolchain(s)`.

Hand-authored fixtures (`toolchain` beginning `synthetic:`) are carried across a
regeneration rather than mined, because no sweep can produce them. They stand in for
compilers this project cannot install, and each one's `note` says which.

Build lines read `<workdir>/probe.c` rather than the directory the probe was actually
compiled in. Mining rewrites home-rooted paths out of `argv`: from a guest that path is
the harness's own account, but from a report measured on a development host it is an
operator's home, which is host-specific detail this repository does not publish. Only
`argv` is rewritten; a path quoted inside a diagnostic is evidence a detector matches on,
so `tests/detector_replay.rs::no_fixture_carries_an_operators_home_path` stops on those
instead of editing them.

The aarch64 evidence is not in a sweep directory, and is not in the repository: the
bring-up reports that first measured an aarch64 Linux host are kept locally and not
published, so a regenerator needs a live aarch64 host and names its reports among the
sources. Regenerating from x86_64 sweeps alone drops the four
aarch64-gated checks, and
`tests/detector_replay.rs::the_fixtures_span_both_architectures_the_corpus_gates_on` fails
rather than letting the coverage quietly shrink.

One source is neither a sweep nor a branch: a set of reports measured on the development
host itself, kept outside this repository, with the sweeps. Their notes name the date, the
host, the toolchain, the profile and the probe corpus digest of the report each was mined
from, which is the provenance every row of the file carries.

A `cxx-hardening-requested` row reads a determinate outcome exactly where its recorded macros,
the evidence its report published, carry `_CXX_STDLIB`, and `indeterminate` where they do not,
including rows whose artifact's self-report names the library;
`tests/detector_replay.rs::a_cxx_hardening_row_is_determinate_exactly_where_its_recorded_macros_name_the_library`
holds that over the file.

## What to look at when the file changes

The run prints its own totals, and `jq` answers the rest. Two properties are worth checking
after any regeneration, neither of which the totals show:

```sh
# checks whose fixtures show only one detector answer: a detector hardwired to
# return that answer would pass every one of them. Outcome *and* level, because
# `present/strong` and `present/basic` are different answers.
jq -r 'sort_by(.check) | group_by(.check)[]
       | select([.[] | "\(.expected)/\(.expected_level // "-")"] | unique | length == 1)
       | "\(.[0].check): all \(length) rows \(.[0].expected)"' detectors.json

# which architectures the evidence was recorded on. Note the `//` inside the
# element expression: `[.[].arch // "x"]` applies it to the whole stream instead,
# which silently drops the hand-authored rows rather than labelling them.
jq -r '[.[] | .arch // "(hand-authored)"] | group_by(.)[]
       | "\(.[0]): \(length)"' detectors.json
```

The first is the one that catches a corpus which grew while getting weaker. It is not a
test, because a check can legitimately have one answer for a while, but a regeneration
that adds rows and *increases* that list is worth reading before committing.

`tests/schema_conformance.rs` pins the number of `elf` blocks in the file (`REPLAY_ELF_ROWS`)
and the number of `ET_REL` rows whose link facts carry a value where the reader writes
`null` (`PRE_NULLABLE_ET_REL_ROWS`); a regeneration updates both and names the new counts in its
commit.

## Coverage

**Every check in the corpus has fixtures.** How many that is, from how many toolchains,
is a question for the file itself: `jq` over `detectors.json` answers it, and the run
that regenerates it prints the totals, so no number for it is written here.

The replay drives detectors alone. The gate that withholds a detector's reading where the
artifact was cut on a table the check declares lives in `measure::run_check`, and is
exercised by `tests/elf_truncations.rs` over the synthetic objects and end to end by
`tests/fake_driver.rs` on a host whose `cc` emits ELF.

The claim that *nothing is missing* is the one worth stating in prose, because it is the
one a test can hold up:
`tests/detector_replay.rs::the_checks_without_recorded_evidence_are_the_ones_we_know_about`
carries the uncovered set and fails if it changes in either direction.

A regeneration from one new sweep alone loses every toolchain only an older sweep reached.
Mined from the seventeen-image sweep of 2026-09-07 alone, a regeneration loses eleven
toolchains, every BSD, Gentoo, Chimera and Wolfi row among them; naming the older sweep
directories alongside the new one keeps them.

The aarch64-gated checks (`branch-protection-macro`, `branch-protection-marked`, `gcs-macro`
and `gcs-marked`) have rows because reports from an aarch64 host are among the sources.
Because more than one architecture is in the file and a toolchain id does not name one
(`gcc-15.2.0-glibc2.43-ubuntu26.04` is the same string on each), each fixture carries an
`arch` field, checked against its own ELF header where it has one.

A detector change that would move a verdict fails here, against recorded compiler output,
before any sweep runs it.

Every `elf` block carries `dt_debug` and `dt_soname`, after `dt_relr` where the reader
serializes them. In blocks mined without those fields they were computed from the block's own
`dynamic_tags` (`0x15` and `0xe`) rather than regenerated: of 2682 such blocks, 2544 carried
`DT_DEBUG`, none `DT_SONAME`, and none was an interpreter-less `ET_DYN`
with `DT_DEBUG` and no `DF_1_PIE`, so no recorded `static_pie` or `shared_object` disagrees
with the rule that reads the tag.

Rows include control arms. A row with `arm` (`positive`, `negative` or `regime`) is one
evaluated arm of an observation, mined from the report's fact store with the arm's own build,
run and macro source; `expected` is what today's decoder reads in it and `archived_verdict`
holds the `outcome` the report published for the arm. The regeneration that mined the arms
read 18 reports (the six gcc and clang cells under `bare`, `bare-optimized` and
`openssf-tldr` on Fedora 44 x86_64 and aarch64, and `link-defaults` under three profiles in
`alpine:edge` with gcc 15.2.0 and musl 1.2.6 on each architecture), with
`CHARD_FIXTURE_MERGE` carrying the 41 pairs those reports did not supply: 4307 rows (3415
measured, 892 arm: 426 positive, 426 negative, 40 regime) from 60 toolchains, losing no
toolchain, and every arm row's `expected` equal to its published outcome.

## Rows mined outside a regeneration

Most rows come from a regeneration over the sweep directories. The sets below were mined by
`fixture::extract` from the reports named, each set in a scratch regeneration under
`CHARD_FIXTURE_MERGE`, and only the rows named were spliced into the file, at their sorted
position or after the check's last row, with no other row changed. Where several reports'
rows would fall in one group, each report was the only source of its own regeneration, since
the cap on a group keeps two. A full regeneration keeps a set only when its reports are among
the sources, and the loss check, which counts (toolchain, architecture) pairs, does not report
a set gone where its pair has rows of its own. Each row's `note` says what it holds.

Toolchains named by host alone are these: Fedora 44 x86_64, gcc 16.1.1 and clang 22.1.8;
Fedora 44 aarch64, gcc 16.2.1 and clang 22.1.8; the Ubuntu 22.04 container, gcc 11.4.0 and
clang 14.0.0; the Ubuntu 24.04 container, gcc 13.3.0 and clang 18.1.3; the Alpine
3.25.0_alpha20260805 container, gcc 15.2.0 and clang 23.1.2 over musl 1.2.6; and the Debian 12
i386 container, gcc 12.2.0. The containers are x86_64 unless named otherwise.

### Stack protector

- `canary-emitted` and `ssp-covers-small-arrays`, from one OpenBSD 7.9 amd64 report (clang
  19.1.7, profile explicit `-fno-ret-protector`): `canary-emitted`'s measured build and both its arms, and
  `ssp-covers-small-arrays`'s measured build, which reference `__stack_smash_handler`. They
  are real evidence rather than synthetic, so the `synthetic:` rule does not carry them.
- `canary-emitted` and `ssp-covers-small-arrays` over a static musl link, from four reports of
  chard built on the host for `x86_64-unknown-linux-musl` and run with `--execution
  container` in a local Alpine 3.25.0_alpha20260805 x86_64 image (musl 1.2.6, GNU ld 2.45.1)
  with no network, restricted with `--probe` to `stack-canary`, `ssp-small-array` and
  `ssp-function-map`: profile explicit `-O2 -static -fno-stack-protector` and `-O2 -static
  -fstack-protector-strong`, each under gcc 15.2.0 and clang 23.1.2. The four
  `canary-emitted` measured builds and gcc's two `ssp-covers-small-arrays` measured builds;
  clang's `ssp-covers-small-arrays` rows are not taken, since its verdict withholds there
  whatever the link holds. The `-fno-stack-protector` links hold no `__stack_chk_fail`,
  `__stack_chk_fail_local` or `__stack_chk_guard` and read `absent`; the
  `-fstack-protector-strong` links hold all three defined and read `present`. gcc's `-static`
  link is a static PIE, clang's an `ET_EXEC`. They refute the claim that a static link
  supplies a canary the flags disabled, and
  `tests/detector_replay.rs::a_static_musl_link_supplies_no_canary_the_flags_disabled` pins
  the four `canary-emitted` rows' readings.
- `ret-protector-emitted`, ten rows. Six are OpenBSD 7.9 amd64
  (clang 19.1.7): the `bare` measured row reading present with its positive and negative arms,
  the `bare-optimized` positive and negative arms, and the measured row under explicit
  `-fno-ret-protector` reading absent. Four are Fedora 44 x86_64 measured rows reading absent,
  gcc and clang each under `bare` and `bare-optimized`. Extraction thinned the rest, the
  `openssf-tldr` cells, the Fedora arms and FreeBSD 15.1's cells among them.
- `ssp-level-emitted`, 21 rows from reports of probe corpus sha256 2b1e3329, each restricted to the `ssp-function-map`, `stack-canary`
  and `toolchain-macros` probes, over `bare`, `bare-optimized`, `openssf-tldr` and thirteen
  explicit forms under gcc and clang on both Fedora 44 hosts and in the Ubuntu 22.04, Ubuntu
  24.04, Alpine and Debian 12 i386 containers. The `bare` measured row for each of the eleven
  toolchains, reading absent under Fedora's, Ubuntu's clang and Debian's i386 gcc and present
  at `strong` under Ubuntu's gcc and Alpine's gcc and clang; the `bare` positive and negative
  arms for gcc and clang on Fedora 44 x86_64 and gcc on Fedora 44 aarch64, reading present at
  `all` and absent; the explicit `-fstack-protector --param=ssp-buffer-size=128` measured row
  for gcc 16.1.1 on Fedora 44 x86_64, clang 22.1.8 on Fedora 44 aarch64 and gcc 12.2.0 on
  Debian 12 i386, reading present at `basic` from the alloca function alone; and the inert
  form `-fstack-protector-all -fno-stack-protector` under clang 23.1.2 on Alpine, reading
  absent. Their objects hold the probe's four roll-called functions; the predicate reads the
  fifth where the object defines it (`predicate::elf_static::SSP_DISCRIMINATOR` says why).
- `ssp-level-emitted` under `SafeStack`, nine rows from seven `--profile explicit` reports
  (probe corpus sha256 cc9e0778), each
  restricted to the same three probes, on Fedora 44 x86_64 (clang 22.1.8 and gcc 16.1.1, glibc
  2.43), over the five-function probe (`probes/ssp_function_map.c` has the table): the
  measured row under `-O2 -fstack-protector-all -fsanitize=safe-stack` reading present at
  `unsafe-frame` (archived `on`), with that cell's positive arm reading present at `all` over
  five functions and its negative arm `absent`; the measured rows under
  `-fstack-protector-all -fsanitize=safe-stack` at -O0 (the in-range array moved too) and
  under `-O2 -fstack-protector-strong -fsanitize=safe-stack` and `-O2 -fstack-protector
  -fsanitize=safe-stack`, each present at `unsafe-frame`; the measured row under `-O2
  -fno-stack-protector -fsanitize=safe-stack`, `absent` with the unsafe stack in use; and the
  measured rows under `-O2 -fstack-protector-all` for gcc and clang, each present at `all`
  over the five functions.
- `ssp-level-emitted` under plain `-fstack-protector`, four rows from four `--profile
  explicit` reports (probe corpus sha256 74954f8c, which differs from cc9e0778 only in the
  probe's header comment), each restricted to the same three probes, on
  Fedora 44 x86_64 (clang 22.1.8 and gcc 16.1.1, glibc 2.43). They hold the `basic` clause to
  the fifth function: the measured rows under `-O2 -fstack-protector` for clang and gcc,
  `ssp_char_array`, `ssp_alloca` and the in-range `ssp_safe_array` canaried and the other two
  bare, each present at `basic`; and the measured rows under `-O2 -fstack-protector
  --param=ssp-buffer-size=128` for clang and gcc, only `ssp_alloca` canaried and both arrays
  bare under the raised threshold, each present at `basic`. `tests/predicates.rs` holds, as a
  row of `FUNCTION_ROWS`, the object with `SafeStack`'s marker and a canary set fitting no
  rule, which the shipped probe cannot produce.

### Bounds and overflow

- `strict-flex-arrays`, three rows, its measured build and both its arms from one OpenBSD 7.9
  amd64 report (clang 19.1.7, profile `bare-optimized`): the corpus's only rows
  from the declared-union construct, whose output carries `storage=declared`. The rows mined
  from the heap construct remain the record of what that construct reads.
- `strict-flex-arrays-enforced`, 36 rows from 18 reports: the three profiles under gcc and clang on Fedora 44 x86_64, in
  the Ubuntu 24.04 container and in the Alpine container (fortify-headers 3.0.2). Measured
  builds and both control arms reading present at 3, absent with the `ctrl` row caught,
  indeterminate with it silent, and absent where the self-report names a library with no
  subobject bound. Every row carries an `elf` block.
- `no-strict-aliasing`, five measured builds from five `--profile explicit` reports on
  Fedora 44 x86_64, the corpus's only rows whose run
  stdout carries the probe's witness lines. gcc 16.1.1 at -O1 bare reads `indeterminate`, at
  -O1 and -O2 with `-fno-strict-aliasing` `present`, and at -O2 bare `absent`; clang 22.1.8 at
  -O2 with the flag reads `present` beside `o2-witness=not-built`.
- `no-strict-overflow`, five rows from three reports measured on x86_64. From gcc 7.5.0 on Ubuntu 18.04 (glibc 2.27): the `bare` measured row,
  an unoptimized build that ran the guard and reads `indeterminate`, and both its arms (`-O2`
  with each flag, `present` and `absent`); and the measured row under `--profile explicit
  --flags -fno-strict-overflow`, which reads `indeterminate` too. From gcc 8.3.0 on Debian 10
  (glibc 2.28): the measured row under the same explicit profile, which reads `present`. They
  are the corpus's rows whose run stdout carries `gcc-major=`, with the rows below.
- `no-strict-overflow`, thirteen rows from reports run in the fleet's virtual
  machines, each report the only source of its own
  scratch regeneration. From gcc 4.8.4 on Ubuntu 14.04 x86_64 (glibc 2.19), gcc 5.4.0 on
  Ubuntu 16.04 x86_64 (glibc 2.23) and gcc 7.5.0 on Ubuntu 18.04 i386 (glibc 2.27): the
  measured build under `--profile explicit --flags -O1`, an optimized build that ran the
  guard without the flag and reads `indeterminate` from its compile line's last `-O` word,
  both its arms (`-O2` with each flag, `present` and `absent`), and the measured
  `bare-optimized` build at -O2, whose guard was folded, `absent`. From gcc 7.5.0 on Ubuntu
  18.04 x86_64, whose `bare` arms the corpus holds: the explicit `-O1` measured build alone.
  They are the corpus's gcc 4.8.4 and 5.4.0 rows. The seven measured builds carry an `elf`
  block and the six arms do not.
- `no-strict-overflow`, five rows from reports (chard built static against
  musl, run in the same gcc 7.5.0 Ubuntu 18.04 x86_64 guest), the measured
  build alone from each report since the corpus holds that toolchain's arms: under `--profile
  explicit --flags` `-Og`, `-O` and `-O2 -O1`, each an optimized build that ran the guard
  without the flag and reads `indeterminate` from its compile line's last `-O` word; under
  `-O2 --optimize=1`, the same reading through gcc's long spelling of the level; and under
  `-Os -fno-strict-overflow`, the guard kept at a level gcc 7.5.0 folds it at, `present`. All
  five carry an `elf` block. Wolfi's gcc 16.1.0 wrapper under `bare`, an optimized build that
  ran the guard, recorded without the probe's `gcc-major=` line and with no `-O` word on its
  line, reads `indeterminate`; its `note` says why.
- `trapv-helper-called` and `trapv-trapped`, 16 rows each, from reports of probe corpus
  sha256 224a771c, each restricted to the
  `trapv` and `trapv-helper` probes. Per check: the `bare` measured row reading absent and the
  explicit `-ftrapv` measured row (present, or absent under clang for `trapv-helper-called`)
  for gcc on Fedora 44 x86_64, gcc and clang on Fedora 44 aarch64, gcc on Alpine and gcc on
  Ubuntu 22.04; for clang on Fedora 44 x86_64 the `bare` measured row and the measured row
  under explicit `-ftrapv -fsanitize=signed-integer-overflow
  -fsanitize-undefined-trap-on-error`, which `trapv-trapped` reads indeterminate; and the
  `bare` positive and negative arms for gcc and clang on Fedora 44 x86_64. The two
  `trapv-trapped` positive arms carry no `elf` block. None of the 32 is a run whose wrapped sum
  stands beside a compiled-in UBSan check or any stderr, the cases the decoder reads
  otherwise.
- `ubsan-trap-mode`, rows from three probe corpora; `predicate::elf_static`'s `UBSAN_TRAP` has why
  each reads as it does.
  - From Fedora 44 aarch64 and the three containers, rows of probe corpus sha256
    50b1aa68: the six profile cells and the two
    `-fsanitize=undefined -fsanitize-trap=undefined` lists with no -O on the aarch64 host,
    and `bare` and the same list for gcc and clang in the containers. gcc 11.4.0's row is
    `unsupported` with no positive arm beside it, its driver having rejected the flag.
  - Those objects lack the probe's second function. The nine reading `present` keep that
    reading. The ten flagless and handler-mode rows are baselined `indeterminate`, each
    `note` saying so: an `absent` there says only that the first function's six groups did
    not trap, and this host cannot measure them again.
  - From Fedora 44 x86_64, under `--probe ubsan-trap`, rows of probe corpus sha256
    44b8cb54 or 9c59b4de, as each row's corpus says. For gcc and clang:
    `bare`'s measured row and both arms, and the explicit `-fsanitize=undefined
    -fsanitize-trap=undefined` measured row.
  - Six shapes from the same host and corpora: clang `-O2 -fsanitize=local-bounds`
    `present`; clang `-O0 -fsanitize=object-size -fsanitize-trap=object-size` `absent`; clang
    `-O2 -fsanitize=undefined -fsanitize-trap=undefined -fno-sanitize-trap=function` and gcc
    `-fsanitize=undefined -fsanitize-trap=undefined -fno-sanitize-trap=object-size`
    `indeterminate`; and gcc `-O2 -fsanitize=object-size -fsanitize-trap=object-size` and
    clang `-O2 -fsanitize=function -fsanitize-trap=function`, each `present`.
  - Two clang rows reading `indeterminate` under `trap-beside-handler`: `-O2
    -fsanitize=bounds,local-bounds -fsanitize-trap=bounds -fno-sanitize-trap=local-bounds` and
    `-O2 -fsanitize=undefined,local-bounds -fsanitize-trap=undefined
    -fno-sanitize-trap=local-bounds`.
- `fortify-printf-flag`, 30 rows from reports of probe corpus sha256 b60c87f9 over the six profile cells on both Fedora 44 hosts, the
  explicit flag lists in the 2026-10-02 code-reader note in the project ledger on both hosts,
  and the check's probe under `bare`, `bare-optimized`, `openssf-tldr` and four explicit lists
  in the Ubuntu 22.04, Ubuntu 24.04 and Alpine containers: the `bare` measured row for each of
  those ten toolchains; the explicit measured row reading present (`-O2 -D_FORTIFY_SOURCE=3` on
  Fedora and `-O2 -D_FORTIFY_SOURCE=1` on Ubuntu) where extraction kept one; the `bare` positive
  and negative arms on both Fedora hosts; and the `bare-optimized` measured rows the Ubuntu
  gccs grade `partial` at 2 and `on` at 3 and the Alpine pair reads `unsupported`, with
  Alpine's two positive arms reading absent. Every row carries an `elf` block with the code
  reader's lists.
- `fortify-requested`, four measured builds under `--profile explicit` with `-O2` and a
  `-D_FORTIFY_SOURCE` the integer reading does not parse: `(3)` from one Fedora 44 x86_64
  report (gcc 16.1.1, glibc 2.43, the full corpus), and `(3)`, `3L` and `2UL`
  from three Fedora 42 aarch64 reports (gcc 15.2.1, glibc 2.41, chard built in a virtual
  machine, the `toolchain-macros` probe alone). The arms are not taken, since the
  controls spell the request `3` and `0` as every other row's do. Each row's
  `archived_verdict` is the `off` its build published without the `unreadable` clause, and its
  `expected` the `indeterminate` it reads; a binary with the clause reads the same three
  aarch64 builds `indeterminate` under `requested-unreadable`. The same
  spellings measured on Darwin arm64 under Apple clang 21 read the same way, and are not rows
  here: a Darwin row would make the matrix's macOS tier `measured` on one check's
  macro-channel rows alone.
- The FreeBSD fortify checks, 25 rows from reports of probe corpus sha256
  3c0f0ac0 in the fleet's two FreeBSD guests. 24 of the 25 carry
  an `elf` block (the `%n` rung's 15.1 positive arm does not).
  - FreeBSD 15.1 amd64 (clang 19.1.7) under `openssf-tldr`: `fortify-enforced-known` and
    `fortify-effective`, each the measured build and both arms. They are the corpus's only
    recorded FreeBSD `__chk_fail` kills: a SIGABRT with nothing on either stream and
    `__memcpy_chk` referenced reads `present` through the self-report's
    `_FORTIFY_IMPL=freebsd`, and `__SSP_FORTIFY_LEVEL=2` reads `present` at 2. Then
    `fortify-level-ge-2-subobject`, `fortify-enforced-dynamic` and
    `fortify-level-ge-2-percent-n`, each the measured build and the positive arm, every one
    surviving; and the measured builds of `strict-flex-arrays-enforced`,
    `fortify-printf-flag` and `fortify-requested`.
  - The same guest under explicit `-O0 -D_FORTIFY_SOURCE=2`: the measured builds of
    `fortify-effective` (withheld, `freebsd-unoptimized`), `fortify-enforced-known` (survived
    with `__memcpy_chk` referenced) and `fortify-requested`.
  - FreeBSD 14.5 amd64 (clang 21.1.8) under `openssf-tldr`: `fortify-effective` and
    `fortify-enforced-known`, each the measured build and the positive arm, and the measured
    builds of `strict-flex-arrays-enforced`, `fortify-printf-flag` and `fortify-requested`.
    Every reading but the request is `absent`, where the request reached headers with no
    `<ssp/ssp.h>`.
  - Not taken: 15.1's `fortify-printf-flag` under `-O0 -D_FORTIFY_SOURCE=2`. The tool
    withholds it live (`freebsd-unoptimized`) from the artifact's self-report, while a replay
    feeds a row's recorded macros alone and an elf-static row records none, so the row would
    pin `present`. `probe::tests::the_printf_flag_withholds_freebsds_unoptimized_wrapper_only`
    and the predicate tests' walk hold the clause instead.
  - The FreeBSD 15.1 `pie` row keeps its `clang-19.1.7-unknown-freebsd15.1` id, recorded
    with the libc named `unknown`.

### Exceptions

- `exceptions-macro` and `except-table-emitted`, 16 rows each, from reports of probe corpus
  sha256 40da49c3. Per check: the `bare`
  measured row reading absent and the explicit `-fexceptions` measured row reading present for
  gcc and clang on both Fedora 44 hosts, gcc on Alpine and gcc on Ubuntu 22.04; and the `bare`
  positive and negative arms for gcc and clang on Fedora 44 x86_64. Every row carries an `elf`
  block, the macro rows included, since both checks read one object.
- `except-table-emitted` on 32-bit ARM, 21 rows, the corpus's only rows of the `arm`
  architecture, from reports measured on a Raspbian
  13 ARMv6 board under gcc 14.2.0 and clang 19.1.7, each restricted to the check. The check
  reads a `.rel.ARM.extab` as the landing-pad table where ARM's exception-handling ABI writes
  no `.gcc_except_table`. Per compiler: the `bare` measured row, the `bare` and
  `bare-optimized` positive and negative arms, and the measured rows of five explicit profiles
  of the `exceptions` probe: `-O2 -fexceptions` and `-O2 -fexceptions -ffunction-sections`
  (present, the latter through the per-function `.rel.ARM.extab.text.<name>`), and
  `-fno-exceptions -funwind-tables`, `-O2 -fasynchronous-unwind-tables` and `-fexceptions
  -fno-exceptions` (absent; gcc's first two carry an `.ARM.extab` with no relocation section,
  the shape the predicate must not read as a table). The twenty-first is clang's measured row
  under explicit `-O2 -fexceptions -fsjlj-exceptions`, which reads absent because clang puts
  that table inside `.text`. The predicate's reading of that object is absent, and the model
  selector reaches the control arms, so the check withholds there (the project ledger,
  "Control arms carry less than the measured build"). Every row carries an `elf` block.

### Control flow and the stack

- `branch-protection-marked`, one row, its measured build from one OpenBSD 7.9 arm64 report
  (clang 19.1.7, under qemu TCG, profile explicit `-Wl,-z,nobtcfi`), the
  corpus's only `branch-protection-marked` row from OpenBSD.
- `cet-marked` under the opt-out header, two rows, each a measured build carrying
  `PT_OPENBSD_NOBTCFI`. One is from OpenBSD 7.9 amd64 under KVM (clang 19.1.7,
  profile explicit `-Wl,-z,nobtcfi`), whose marking reads `present` at level `branch`, IBT
  without SHSTK. The other is from Fedora 44 x86_64 in a container (clang 22.1.8, lld 22.1.8),
  the `-fhardened` constituents spelled out with `-fuse-ld=lld
  -Wl,-z,nobtcfi`, whose marking reads `present` at `full` beside a header lld wrote for a
  Linux target. With the `branch-protection-marked` row above, they are the corpus's three rows
  whose `elf` block carries `openbsd_nobtcfi`; `tests/detector_replay.rs` pins that count and
  reduces `cfi-effective` over the three and `fhardened-effective`'s CET slot over these two.
- `cet-marked` under a forged marking, eight rows from two reports on Fedora
  44 x86_64, profile explicit `-O2 -fcf-protection=none -Wl,-z,ibt -Wl,-z,shstk`, one under gcc
  16.1.1 and one under clang 22.1.8, both linking with GNU ld 2.46.1. Each report gives four:
  the measured build and the regime arm, reading present at `full` because the linker forced
  both bits over code with no `endbr64`, the positive arm (`-fcf-protection=full`) reading
  present at `full`, and the negative arm (`-fcf-protection=none`) reading absent. The
  measured rows' `archived_verdict` is `probe-invalid`, the triple withheld as
  `regime-confounded`, and `tests/detector_replay.rs` decides each triple again from its rows.
- `cet-endbr-emitted`, 16 rows from reports of probe corpus sha256 d4134155.
  Profile reports of corpus 03242580 (decoders e9efc18a), whose code differs only in
  `elf::entry`'s `hex` helper and `elf.rs`'s `watched_of` extraction, decoder source and not
  predicate or probe, read the same verdicts, and the rows replay unchanged under corpus
  b0015e0b (decoders 8b09ed37), whose decoder fingerprint includes `src/elf/entry.rs`. Fourteen are from the six gcc
  and clang profile cells on both Fedora 44 hosts and `--probe cet-endbr` runs under `bare`,
  `bare-optimized`, `openssf-tldr` and seventeen explicit forms on Fedora 44 x86_64, in the
  Ubuntu 22.04, Ubuntu 24.04, Alpine and Debian 12 i386 containers, and under `-m32` in a
  Fedora 44 container: the `bare` measured row for gcc and clang on Fedora 44 x86_64, Ubuntu
  22.04, Ubuntu 24.04 and Alpine and for gcc 12.2.0 on i386, reading present under Ubuntu's
  gcc and absent elsewhere; the `bare` positive and negative arms for gcc 16.1.1; the `bare`
  positive arm for gcc 12.2.0 on i386, the corpus's only `endbr32` row; clang 22.1.8's explicit
  `-Os -fcf-protection=full` row; and gcc 11.4.0's explicit `-O2 -fcf-protection=branch
  -mmanual-endbr` row, reading absent. The `-m32` rows are not here: `fixture::extract` labels
  them `x86_64` from the driver's triple while their artifact's header says `i386`, so
  `the_architecture_label_agrees_with_the_elf_header` would refuse them. Two are from single
  reports under gcc 16.1.1 on Fedora 44 x86_64: the explicit `-O2 -fcf-protection=return`
  measured row, the check's inert form, reading absent, and the explicit `-O2 -flto
  -fcf-protection=full` measured row, a slim LTO object whose `elf` block carries no
  `function_entries`, reading indeterminate through the predicate's `function-unread` clause.
  Every row carries an `elf` block.
- `zero-call-used-regs`, 33 rows from reports of probe corpus sha256 62549063. 28 are the `bare` measured row reading absent for gcc and
  clang on both Fedora 44 hosts and in the Ubuntu 22.04, Ubuntu 24.04 and Alpine containers;
  the explicit `-O2 -fzero-call-used-regs=used-gpr` measured row reading present at `gpr` for
  each of those toolchains but clang 14.0.0, whose explicit `-O2 -fzero-call-used-regs=skip`
  row (a failed build) stands in; and the `bare` positive and negative arms for gcc and clang
  on both Fedora hosts. Five are from single reports: `-fzero-call-used-regs=used-gpr-arg`
  reading present at `arg` under gcc 16.1.1 on x86_64 and clang 22.1.8 on aarch64,
  `-fzero-call-used-regs=skip` and `-fzero-call-used-regs=used-gpr
  -fzero-call-used-regs=skip` reading absent under gcc 16.1.1 on x86_64, and `-O2
  -fstack-protector-all` under gcc 16.2.1 on aarch64, the row whose two zeroed argument
  registers read absent. The positive arms carry no `elf` block.
- `noexecstack-enforced`, 32 rows from reports of probe corpus sha256 c5f5df6a: the six profile cells on both Fedora 44 hosts and the `--profile explicit --probe
  stack-exec-runtime` runs on both. Per compiler and host: the `bare` measured row and positive
  arm reading present, the `bare` negative arm reading absent, the `bare-optimized` positive,
  negative and regime arms, one explicit measured row and one explicit regime arm. The
  explicit measured rows are `-Wl,-z,noexecstack -Wl,-z,execstack` reading absent; on x86_64
  clang the explicit regime arm is `-fsanitize=safe-stack`'s, whose probe declined because the
  buffer was not on the initial stack, reading indeterminate.
- `shadow-stack-enforced`, 14 rows. Twelve are from reports of probe corpus sha256 e08ff720, on
  the Fedora 44 x86_64 host, whose CPU enumerates CET shadow stack (kernel 7.3.0-rc3, glibc
  2.43): the `bare`, `bare-optimized` and `openssf-tldr` cells and `--profile explicit --flags
  "-O2 -fcf-protection=full"`, each under gcc and clang. Per compiler: the `bare` measured row
  reading absent, the explicit measured row reading present at `opt-in` (archived `partial`),
  and the positive and negative arms of `bare` and `bare-optimized`. The probe runs the program
  without glibc's opt-in as well, and the check grades on that run (`opt-in` below `default`).
  Two are positive arms from reports of probe corpus sha256 b86a55b1, measured
  by the fleet harness in KVM guests on the same host, the corpus's only recorded runs that name
  a machine without a shadow stack: Ubuntu 22.04 (kernel 5.15.0-187-generic, gcc 11.4.0,
  `bare`), whose run reads `kernel=errno:22 cpu=no-ss`, and Ubuntu 24.04 (kernel
  6.8.0-137-generic, gcc 13.3.0, `openssf-tldr`), whose run reads `kernel=ok cpu=no-ss`. Both
  read `indeterminate`; the reports published `unsupported` under `kernel-lacks-shadow-stack`
  and `indeterminate` under `cpu-lacks-shadow-stack`.

### Linking and position independence

- `separate-code`, 19 rows. 18 are from reports of probe corpus sha256
  ecbaf231: the `bare` measured row for gcc and clang on Ubuntu
  22.04, gcc on Ubuntu 24.04 and gcc on Alpine, each reading present under GNU ld's x86_64
  default; the same row for gcc and clang on Fedora 44 x86_64, reading present, and on Fedora
  44 aarch64, reading absent under GNU ld's aarch64 default; the `bare` positive and negative
  arms for gcc and clang on Fedora 44 x86_64 and gcc on Fedora 44 aarch64; explicit `-O2
  -Wl,-z,separate-code` under gcc 16.2.1 on aarch64, reading present; explicit `-fuse-ld=lld
  -Wl,-z,noseparate-code` under gcc 16.2.1 and clang 22.1.8 in the Fedora 44 x86_64 container,
  reading absent over a code segment that holds code sections alone, the layout segment
  membership would read as separated; and the inert form `-Wl,-z,separate-code
  -Wl,-z,noseparate-code` under gcc on Alpine, reading absent. The nineteenth, from a probe
  with the 4096-byte page floor (probe corpus sha256 c5ed220a), is the `bare` row for gcc
  12.2.0 (GNU ld 2.40) in the Debian 12 i386 container, reading present; `fixture::extract`
  folds `i386` through `i686` in a target triple to `i386`, the ELF reader's name for `EM_386`,
  so the row carries the label its header agrees with. Every row carries an `elf` block with
  `data_in_code_pages`.
- `pic-shared-link`, 32 rows. 29 are from reports of probe corpus sha256
  41c978af: the six gcc and clang profile
  cells on both Fedora 44 hosts, and `--probe pic-shared-link` runs under `bare`,
  `bare-optimized`, `openssf-tldr` and fifteen explicit forms in the Ubuntu 22.04, Ubuntu
  24.04, Alpine, Fedora 44 linker (GNU ld, lld and mold) and Debian 12 i386 containers and on
  the aarch64 host. They are the `bare` measured row, reading absent, for each of the eleven
  x86_64 and aarch64 toolchains; the explicit `-fPIC` measured row reading present for eight of
  them; the `bare` positive and negative arms for gcc and clang on Fedora 44 x86_64; the `-O2
  -fPIC -Wl,-Bsymbolic -fuse-ld=lld` measured rows for gcc 16.2.1 and clang 22.1.8 and the
  clang regime arm, which links under `-fPIE` and is why that cell withholds; the `-O2 -fno-pic
  -mcmodel=large -Wl,-z,notext` regime arm on aarch64, reading indeterminate; and gcc 16.2.1's
  `bare-optimized` regime arm on aarch64, `-O2 -fPIE`, the section-anchor case the probe's
  4096-byte global exists for, reading absent. The check reads a link that succeeded through
  the shared object's `DT_TEXTREL`, so a row of a successful link carries the object's facts.
  Three of those are control arms whose own reports stored no artifact for this check: the `bare` positive arms of gcc 16.1.1 and clang 22.1.8 and
  gcc 16.2.1's `-O2 -fPIC -Wl,-Bsymbolic -fuse-ld=lld` regime arm, on Fedora 44 x86_64. Each
  carries the `elf` block another report of the same toolchain stores under the same
  `artifact_sha256`, where those bytes are the measured build of an explicit profile, and each
  reads `present`, carrying no tag. Three more are from reports measured
  in the `chard-f44-linkers` container (LLD 22.1.8): the measured builds of
  `-O2 -fno-pic -mcmodel=large -fuse-ld=lld` with a `-z notext` from a specs file (gcc 16.2.1)
  and from a configuration file (clang 22.1.8), and gcc 16.2.1's `-O2 -fPIC -fuse-ld=lld`
  under the same specs file, which LLD tags with no text relocation. All three read
  `indeterminate`.
- `pic-object-relocs`, 32 rows from reports each restricted to the `pic-object` and `pic-shared-link` probes, over `bare`,
  `bare-optimized`, `openssf-tldr` and twenty-three explicit forms under gcc and clang on both
  Fedora 44 hosts and in the Ubuntu 22.04, Ubuntu 24.04, Alpine and Debian 12 i386
  containers. 28 are the `bare` measured row, reading absent, and the explicit `-fPIC`
  measured row, reading present, for each of the eleven toolchains, i386 included; and the
  `bare` positive and negative arms for gcc and clang on Fedora 44 x86_64 and gcc 12.2.0 on
  Debian 12 i386. Four are from single reports: gcc 16.1.1's `-O2 -fPIC -Wl,-Bsymbolic`
  (present, where `pic-shared-link` withholds), `-O2 -fPIC -flto` (a slim LTO object,
  indeterminate) and `-O2 -mcmodel=large -fPIE` (`R_X86_64_GOTOFF64`, absent) on Fedora 44
  x86_64, and gcc 16.2.1's `-fpic` (`R_AARCH64_LD64_GOTPAGE_LO15`, present) on Fedora 44
  aarch64. Every row carries the object's `elf` block.
- `plt-bypassed`, 60 rows from reports of probe corpus sha256 ce87a106, each restricted to the `no-plt` probe, whose `code_relocations` are `TYPE
  SYMBOL` over every named symbol. 54 are from 26 reports: `bare`, explicit `-fno-plt`,
  `-fno-plt -fplt` and `-O2 -fno-plt -flto` under gcc and clang on both Fedora 44 hosts;
  `bare` under gcc and explicit `-fno-plt` under clang in the Ubuntu 22.04, Ubuntu 24.04 and
  Alpine containers; `bare` and `-fno-plt` under gcc 12.2.0 in the Debian 12 i386 container;
  explicit `-fno-plt` under gcc 13.3.0 in an Ubuntu 24.04 aarch64 container and `bare` under
  gcc 12.2.0 in a Debian 12 aarch64 container. They are measured rows and both control arms,
  reading present for a GOT call, absent for a PLT call, and indeterminate for the two `-flto`
  forms; the two clang `-flto` measured rows carry no `elf` block, since the object is LLVM
  bitcode, which the reader refuses. Six are both measured rows and their control arms under
  explicit `-fpic -fno-plt` and `-fpic` with gcc 16.2.1 on Fedora 44 aarch64, the reading the
  reader's `R_AARCH64_LD64_GOTPAGE_LO15` entry decides.
- `as-needed`, one row from a reproduction report rather than a sweep: gcc 13.3.0 on Ubuntu
  24.04 x86_64 under `--profile explicit --flags -O2 --ldflags -static`, the probe linked
  `-static` with no `.dynamic` section and an empty `DT_NEEDED` list, which the report
  published `on`. Its `expected` is `indeterminate`, the `no-dynamic` clause's reading, and its
  `note` says so.
- `relro`, two rows, the measured build under `bare` from the OpenBSD 8.0 amd64 and arm64
  reports of a fleet sweep (clang 22.1.6, lld); the arms are not taken. Both read
  `partial`, PT_GNU_RELRO without BIND_NOW, and they are the corpus's only `relro` rows from
  OpenBSD, where lld places `.got.plt` inside PT_GNU_RELRO (the `relro` check's note in
  `src/probe.rs`). They are the corpus's OpenBSD clang 22.1.6 rows, so `SUPPORT.md`'s OpenBSD
  rows hold 19.1.7 to 22.1.6.
