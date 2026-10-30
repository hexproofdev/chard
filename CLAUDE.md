<!-- SPDX-License-Identifier: BSD-3-Clause -->

# CLAUDE.md

chard: empirical measurement of which C hardening flags a toolchain actually applies. It
compiles probe programs, the probes report on themselves, and chard reads the artifacts it
just produced: never a distribution's packaging spec, never a binary it did not build. Read
[`DESIGN.md`](DESIGN.md) before changing anything that touches a detector, and
[`THREAT_MODEL.md`](THREAT_MODEL.md) before changing anything that touches trust boundaries.
`chard probes` is the live count of probes and checks; do not hand-maintain one in prose.

## The discipline

- The failure mode this project cannot tolerate is a **clean-looking zero**: a wrong `off`
  that reads as a real measurement. Every check is validated by a control triple (flag
  forced on, forced off, and as-configured) before its verdict is trusted. A probe that
  cannot discriminate the two states is `probe-invalid`, never `off`. If you cannot make a
  new check pass through that triple, say so explicitly rather than shipping a bare verdict.
  The reverse error, a flag present and inert reading as `on`, has its own rule in
  `tests/inert_flags.rs`: a graded or optimization-gated check names its inert form or the
  reason it has none.
- An invariant is a mechanism, not a comment: a type that makes the violation
  unrepresentable where one exists, a test where it does not. `report::ASSUMPTIONS` and
  `tests/register.rs` are the pattern: an assumption that ships without an entry and a
  retirement condition is a belief, not an assumption.
- Record rationale where the code is. [`DESIGN.md`](DESIGN.md) carries the
  architecture and the arguments between modules; module doc comments carry mechanism and
  its rationale. Don't restate one in the other; add a pointer.
- A measurement quoted in prose names how it was produced: toolchain, profile, host and
  date. The tree says what chard does, never what it did: no file names a commit of this
  repository, a change it once made or a reading it once gave. Where a document is wrong
  about today, correct it in place to what stands, with no dated note; the history is kept
  outside this repository. A measured number is evidence: replace it only with a new
  measurement and its frame, never edit it to match a later tool.
  `tests/detector_replay.rs`'s `the_counts_in_the_docs_are_the_counts_in_the_corpus` holds
  every check or probe count in prose to the corpus, and `tests/public_tree.rs` holds every
  file of the release tree to naming no commit of the history it is built from.

## Hard constraints

- Four direct dependencies (`serde`, `serde_json`, `clap`, `anyhow`); `unsafe_code = "deny"`
  crate-wide. The ELF reader is safe Rust over a byte slice, never a binding to a C library
  and never a shell-out to `readelf`/`objdump`.
- `off` must be earned. Silence (a probe that did not build, a macro not found, a channel
  the toolchain lacks) is never `off`; it is `probe-invalid`, `unsupported`,
  `not-applicable` or `indeterminate`, each distinct in the schema's verdict enumeration.
  Absence of evidence is not evidence.
- Any code that enumerates work counts what it fed against what it expected. `coverage` is
  mandatory in every report for exactly this reason: a check that never ran cannot report
  its own absence, and a loop over nothing that exits 0 is the failure this project has
  produced more than once.
- Output is deterministic and self-consistent. Derived fields (the fortify ratchet, defect
  coverage, the umbrella composites) are checked against the observations they came from;
  a contradiction exits `3` and writes to `<output>.contradicted` rather than publishing.
- No host-specific detail in a tracked file, a commit message, or an author identity: no
  absolute home paths, no machine names. `scripts/leak-gate.sh` enforces this with no
  override flag (machine names through its untracked private list, where a checkout holds
  one); if the gate is wrong, fix the gate, not the exception.
- The compiler runs under a cleared environment holding only `PATH`, the run's `--env` pairs
  and the pins `compile::compiler_environment` sets, its diagnostic language among them, and
  every report publishes that environment as `profile.compiler_environment`; a probe runs with
  no ambient variable at all, receiving exactly `run::PROBE_ENVIRONMENT` and the pins it
  declares in `probe::Probe::run_environment`, and its run record carries that map as
  `environment`. chard reads no configuration from the environment beyond `PATH`. Don't add a
  new implicit environment read without threading it through that same discipline, and don't
  add a compiler pass or pin, or a probe pin, without the sentence in `THREAT_MODEL.md` that
  `tests/register.rs` holds it to.

## Where things live

[`DESIGN.md`](DESIGN.md) holds the architecture: the control triple, the four observation
channels, the composite umbrellas, verdict vocabulary. [`THREAT_MODEL.md`](THREAT_MODEL.md)
says what is and is not defended, against whom. [`CHANGELOG.md`](CHANGELOG.md) records the
changes to the output contract from the first publication on. The project ledger, the record
of deferred work and the evidence that decides each item, is kept outside this repository.
