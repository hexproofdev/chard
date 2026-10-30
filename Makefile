# SPDX-License-Identifier: BSD-3-Clause
#
# The entry point. Every command a contributor, a reviewer or CI runs has a target
# here, so the string in the README, the string in .github/workflows/ci.yml and the
# string a maintainer types are the same string. Drift between those three is the
# defect this file exists to prevent.
#
# `--locked` on everything that resolves a dependency graph: a gate that silently
# updates Cargo.lock is measuring a different dependency set than the one committed.
# `cargo fmt` is the exception because it rejects the flag.

CARGO       ?= cargo
# Derived from the host rather than written down, for the reason the MSRV is: a target
# hardcoded to x86_64 makes `make musl` a cross-build the moment the host is not x86_64,
# and `make doctor` print a `rustup target add` line for the wrong architecture. Override
# it to cross deliberately; the default should follow the machine you are on.
MUSL_TARGET ?= $(shell uname -m)-unknown-linux-musl
# Read from the manifest rather than repeated here: a floor written in two places is a
# floor that will disagree with itself. Only digits and dots are read, so a `rust-version`
# holding anything else (a fork controls `Cargo.toml` on a pull request) reads as empty and
# fails the toolchain lookup, and is never spliced into a recipe as shell source.
MSRV        := $(shell sed -n 's/^rust-version = "\([0-9][0-9.]*\)"$$/\1/p' Cargo.toml)
# The floor's exact release, the name `msrv` and `msrv-compile` ask rustup for: a two-part
# `rust-version` gains `.0`, a three-part one is taken as it is, and anything else reads as
# empty, which the recipes refuse. Not the two-part name: rustup reads `1.88` as a channel of
# its own, apart from `1.88.0`, and a gate run asking for it has rustup fetch that channel
# from the network inside a run meant to be offline (on a CI host, 2026-10-20).
MSRV_TOOLCHAIN := $(shell printf '%s\n' '$(MSRV)' | sed -n -e 's/^\([0-9][0-9]*\.[0-9][0-9]*\)$$/\1.0/p' -e t -e 's/^\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$$/\1/p')
# Whether rustup has the floor's release installed, asked of `rustup toolchain list`, which
# never installs: `rustup run` and `cargo +X` would fetch a missing toolchain wherever rustup's
# auto-install is on. The name is matched whole, before the host triple.
MSRV_INSTALLED = rustup toolchain list 2>/dev/null | sed -n 's/^\($(MSRV_TOOLCHAIN)\)-[^ ]*.*/\1/p' | grep -qxF '$(MSRV_TOOLCHAIN)'
# The clippy the gate runs, pinned to one release so the gate's verdict is a function of the
# commit: a new clippy's new lint turns `make clippy-gate` red only in the commit that moves
# this line, which fixes or allows what it finds in the same diff. CI reads it from here
# (digits and dots only, as for the floor), so it is written once. Bump it deliberately.
CLIPPY_TOOLCHAIN := 1.97.1
# The corpus total, read from the corpus. A copy written down here goes stale the day a check
# is added, which `the_counts_in_the_docs_are_the_counts_in_the_corpus` catches, but only
# after the fact and only for prose it knows to read.
CHECKS      := $(shell sed -n 's/^        const CHECKS: usize = \([0-9]*\);/\1/p' src/probe.rs)
# Where the test binaries append the arms they could not run (`tests/common::LEDGER_DIR`,
# cargo's `CARGO_TARGET_TMPDIR`): under the target directory cargo builds into.
TARGET_DIR  ?= $(or $(CARGO_TARGET_DIR),target)
LEDGER      := $(TARGET_DIR)/tmp/test-ledger

.DEFAULT_GOAL := help

# A bare `make` must not launch a long gate, so help is the default goal and the
# only target that runs by accident.
.PHONY: help
help:
	@echo 'chard — measure which hardening flags a toolchain actually applies'
	@echo
	@echo '  make doctor      check prerequisites and name what is missing'
	@echo '  make build       build the release binary'
	@echo '  make check       the gate: fmt + clippy-gate + test + deny + leak-gate + spdx'
	@echo '  make check-full  the slow gate: check + audit + musl + msrv + package + clang + compiler-arms + cross-check + zizmor + fuzz-replay'
	@echo '                   (fuzz-replay needs nightly and cargo-fuzz, and make fuzz-seed once on a fresh clone)'
	@echo '  make test        tests only, then the arms this host did not exercise'
	@echo '  make fmt         format in place'
	@echo '  make fmt-check   fail if formatting is not clean'
	@echo '  make clippy      lints on your default toolchain: deny-level lints fail, pedantic warnings are shown'
	@echo '  make clippy-gate clippy $(CLIPPY_TOOLCHAIN) with warnings denied: in check and merge-gate'
	@echo '  make deny        bans, licences and sources — reproducible from the commit'
	@echo '  make audit       live advisory database — verdict changes without a commit'
	@echo '  make musl        static binary for images without a matching libc'
	@echo '  make leak-gate   refuse to publish host-specific or ignored material'
	@echo '  make spdx        fail a tracked text file with no SPDX licence identifier'
	@echo '  make msrv        build and test at the advertised rust-version floor, rustup toolchain $(MSRV_TOOLCHAIN)'
	@echo '  make msrv-compile  check every target at the floor, offline, without code generation'
	@echo '                   (both need: rustup toolchain install $(MSRV_TOOLCHAIN) --profile minimal)'
	@echo '  make ratchets     the text-scan rules (tests/ratchets.txt), in seconds, first in merge-gate'
	@echo '  make merge-gate  what a merge runs: ratchets + fmt-check + clippy-gate + test + msrv-compile + spdx, timed, short output, logs in target/merge-gate (the leak gate beside it); with MERGE_GATE_BASE naming an ancestor, a document-only diff runs ratchets, spdx and the tests that read it'
	@echo '  make cross-check compile the crate and its tests for x86_64 and aarch64 macOS and x86_64 FreeBSD (CROSS_TARGETS), linking nothing'
	@echo '  make package     build the crate archive, with its verification build'
	@echo '  make clang       run the corpus against clang, not just cc'
	@echo '  make compiler-arms  run the inert-flag rows and the local-bounds trap modes of ARMS_CC (default clang), with cc pointed at it'
	@echo '  make sweep       measure gcc and clang under three profiles, and hold each report to its expectation (SWEEP_EXECUTION=host|vm|container required)'
	@echo '  make mutants     check the tests bite, over the ELF reader'
	@echo '  make mutants-detectors  the same, over the detectors and the derivations'
	@echo '  make mutants-rest  the same, over the other modules that decide or publish a verdict'
	@echo '  make zizmor      audit the GitHub Actions workflows'
	@echo '  make kani        model-check the bounded reads in the ELF reader'
	@echo '  make verify      check + kani'
	@echo '  make fuzz        run each libFuzzer target for FUZZ_TIME seconds (nightly, dev-only)'
	@echo '  make fuzz-seed   seed the fuzz corpora with reports, ELF artifacts and each input shape'
	@echo '  make fuzz-replay replay every corpus, seed and kept crash without mutation'
	@echo '  make hooks       install .githooks (never automatic)'
	@echo '  make doc         build the API docs'
	@echo '  make clean       remove what the build produced, and nothing else'
	@echo '  make clean-all   the same, across every worktree'
	@echo '  make clean-dry   list what a clean would remove, and remove nothing'

# The single most useful first-run affordance. chard compiles probe programs with
# your compiler, so the toolchain under test is a prerequisite the build itself
# cannot supply, a missing cc is a runtime failure, not a build failure, which is
# exactly the case a doctor target exists to catch.
# The exit status answers one question: can chard measure on this machine. Only the C
# compiler decides it. The rest are tools for `make check` and its slower siblings, and
# each names the target it is needed for so the reader can decide whether they need it. A
# capable machine is not reported unready for want of cargo-deny, which chard never runs.
.PHONY: doctor
doctor:
	@ok=0; \
	if command -v cc >/dev/null 2>&1; then \
	  echo "ok    cc            $$(cc --version | head -1)"; \
	else \
	  echo "MISS  cc            no C compiler on PATH; chard measures one, so it cannot run without it"; ok=1; \
	fi; \
	if command -v c++ >/dev/null 2>&1; then \
	  echo "ok    c++           $$(c++ --version | head -1)"; \
	else \
	  echo "warn  c++           absent; the two C++ checks will report build-failed"; \
	fi; \
	if command -v jq >/dev/null 2>&1; then \
	  echo "ok    jq            $$(jq --version)"; \
	else \
	  echo "warn  jq            absent; scripts/sweep-gate.sh reads reports with it (needed for \`make sweep\`)"; \
	fi; \
	echo "ok    rustc         $$(rustc --version)"; \
	if rustup run $(CLIPPY_TOOLCHAIN) cargo clippy --version >/dev/null 2>&1; then \
	  echo "ok    clippy pin    $$(rustup run $(CLIPPY_TOOLCHAIN) cargo clippy --version)"; \
	else \
	  echo "MISS  clippy pin    rustup toolchain install $(CLIPPY_TOOLCHAIN) --profile minimal --component clippy   (needed for \`make check\` and \`make merge-gate\`)"; \
	fi; \
	if [ -n '$(MSRV_TOOLCHAIN)' ] && $(MSRV_INSTALLED); then \
	  echo "ok    msrv          $(MSRV_TOOLCHAIN)"; \
	else \
	  echo "MISS  msrv          rustup toolchain install $(MSRV_TOOLCHAIN) --profile minimal   (needed for \`make merge-gate\` and \`make msrv\`)"; \
	fi; \
	if rustup target list --installed 2>/dev/null | grep -qx '$(MUSL_TARGET)'; then \
	  echo "ok    musl target   $(MUSL_TARGET)"; \
	else \
	  echo "MISS  musl target   rustup target add $(MUSL_TARGET)   (only needed for \`make musl\`)"; \
	fi; \
	if command -v cargo-deny >/dev/null 2>&1; then \
	  echo "ok    cargo-deny    $$(cargo deny --version)"; \
	else \
	  echo "MISS  cargo-deny    cargo install cargo-deny   (needed for \`make deny\`)"; \
	fi; \
	if command -v cargo-audit >/dev/null 2>&1; then \
	  echo "ok    cargo-audit   $$(cargo audit --version)"; \
	else \
	  echo "MISS  cargo-audit   cargo install cargo-audit  (needed for \`make audit\`)"; \
	fi; \
	if command -v zizmor >/dev/null 2>&1; then \
	  echo "ok    zizmor        $$(zizmor --version)"; \
	else \
	  echo "MISS  zizmor        cargo install zizmor       (needed for \`make zizmor\`)"; \
	fi; \
	if command -v cargo-kani >/dev/null 2>&1; then \
	  echo "ok    kani          $$(kani --version)"; \
	else \
	  echo "MISS  kani          cargo install --locked kani-verifier && cargo kani setup  (needed for \`make kani\`)"; \
	fi; \
	exit $$ok

# The caller's rustflags would make another binary under the same revision: RUSTFLAGS=-C
# overflow-checks=on gave another sha256 with the same `--version` (measured, the 2026-10-18
# audit). `build.rs` marks such a build (`run.harness_rustflags_sha256`, `--version`), and
# these two targets build without any, by `clippy-gate`'s line, so the binary they make is
# the one its revision names. Not cleared: a rustc wrapper and a profile setting
# (`CARGO_PROFILE_*`), which no build script marks (assumption
# `revision-and-rustflags-name-the-build`).
.PHONY: build
build:
	env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS= \
	  $(CARGO) build --locked --release

.PHONY: musl
musl:
	env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS= \
	  $(CARGO) build --locked --release --target $(MUSL_TARGET)

.PHONY: fmt
fmt:
	$(CARGO) fmt

.PHONY: fmt-check
fmt-check:
	$(CARGO) fmt --check

# The lints on whatever toolchain is your default. A deny-level lint (`clippy::all`, rustc's
# `unused`) fails here as anywhere; the warn-level `pedantic` lints are printed and do not, so a
# newer clippy's suggestions show up here before anyone bumps the pin.
.PHONY: clippy
clippy:
	$(CARGO) clippy --locked --all-targets

# The gate's clippy: the pinned release with every warning denied, `pedantic` included, so a
# change that adds a warning fails the merge that carries it. Not `-D warnings` on the default
# toolchain, which turns red on a day nobody touched the repository when a new clippy ships a
# new lint; not a count held against a baseline, which needs a recorded baseline per
# toolchain and passes any change that trades one warning for another. A host without the
# pinned toolchain fails here with the command that installs it: a gate that cannot run its
# clippy does not pass. `cargo +X` takes precedence over RUSTUP_TOOLCHAIN and any override.
#
# The caller's environment cannot cap the lints: RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS or
# CARGO_BUILD_RUSTFLAGS holding `--cap-lints allow` let a warning through `-D warnings`
# (measured 2026-10-18). The recipe unsets CARGO_ENCODED_RUSTFLAGS, which
# outranks RUSTFLAGS, and CARGO_BUILD_RUSTFLAGS, and sets RUSTFLAGS empty; with RUSTFLAGS set, cargo
# ignores CARGO_BUILD_RUSTFLAGS and a config file's `build.rustflags` and `target.*.rustflags`
# as well, so none of the five reaches rustc (each measured against a seeded warning). Not closed: a rustc wrapper (`RUSTC_WRAPPER`, `build.rustc-wrapper`), which
# can rewrite any flag; that is the caller's own machine, not a variable a script sets in passing.
.PHONY: clippy-gate
clippy-gate:
	@echo "== clippy $(CLIPPY_TOOLCHAIN), warnings denied =="
	@rustup run $(CLIPPY_TOOLCHAIN) cargo clippy --version >/dev/null 2>&1 || { \
	  echo "clippy-gate: the pinned toolchain $(CLIPPY_TOOLCHAIN) with clippy is not installed:" >&2; \
	  echo "  rustup toolchain install $(CLIPPY_TOOLCHAIN) --profile minimal --component clippy" >&2; \
	  exit 1; }
	@echo "$$(rustup run $(CLIPPY_TOOLCHAIN) cargo clippy --version)"
	env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS= \
	  $(CARGO) "+$(CLIPPY_TOOLCHAIN)" clippy --locked --all-targets -- -D warnings

# The ledger is cleared first so it holds this run alone, and read after the run whatever
# the run's status. `--no-fail-fast` so a red run still runs every binary: cargo otherwise
# stops at the first failing one, and the ledger would list only the gaps of the binaries
# before it. `inert_flags` always writes a count line per table; the script fails a ledger
# missing either (`scripts/test-ledger.sh`).
#
# The ledger's toolchain gaps outside `inert_flags`, and which gate runs them, if any (as announced
# on Fedora 44 x86_64 under gcc 16.1.1, and on Ubuntu 24.04 x86_64 under gcc 13.3.0, at
# 2026-10-13). `compiler-arms` runs `inert_flags` and probe_sources' local-bounds trap-mode
# test.
#   - fake_driver's lld and mold corroboration arms need `ld.lld` and `mold` on PATH. No
#     gate installs them, and the test has no gate mode that fails on the gap, as
#     CHARD_TEST_EXPECT_CC is for `inert_flags`. With both on PATH, `make test` runs them.
#   - macro_dump_digest's two order arms run under g++ and are announced under gcc. An arm
#     can fail only under a driver whose macro dump moves with the path or with an added
#     name; g++'s did on both hosts and gcc's did not, so gcc's half is a property of that
#     driver's identifier table, which no gate can install.
#   - core_files' core-in-the-workdir arm needs `kernel.core_pattern` to be a relative path,
#     so a core lands in the probe's working directory (a pipe or an absolute path sends it
#     elsewhere), and a hard core limit of unlimited. The pattern belongs to the host (a pipe
#     to systemd-coredump on Fedora 44) and the hard limit to the session that starts the
#     run, and no target here changes either.
#   - probe_sources' ubsan trap groups under clang run in `make test` wherever `clang` is on
#     PATH. Its six local-bounds rows read as written only from clang 20: under an older
#     clang `make test` holds each to that clang's object and announces the row's own
#     reading as not exercised, and `make compiler-arms`, which CI runs under clang 20,
#     runs that test with clang as `cc` and fails a row below the floor (a flag set the
#     driver refuses is still a gap there). fhardened_set's -fhardened comparison runs
#     where `gcc` is gcc rather than clang, is 14 or later, and targets x86_64 or aarch64
#     Linux, the targets whose expected lines the tree records; it is announced where its
#     condition fails, and no gate requires it.
.PHONY: test
test:
	@rm -rf $(LEDGER); rc=0; \
	echo '$(CARGO) test --locked --no-fail-fast'; $(CARGO) test --locked --no-fail-fast || rc=$$?; \
	scripts/test-ledger.sh --require inert_flags --require 'inert_flags (partly inert)' \
	  $(LEDGER) || rc=1; \
	exit $$rc

.PHONY: doc
doc:
	$(CARGO) doc --locked --no-deps

# The gate. Fast enough to run before every commit, and what CI runs on a pull
# request. If a contributor runs one target, it is this one.
#
# `deny` is in the gate but `audit` is not: `cargo deny check bans licenses sources`
# reads a committed policy against a committed lockfile and is reproducible from the
# commit, while an advisory check fetches a live database and can change verdict on a
# day nobody touched the repository. A gate that does that is not a gate.
.PHONY: check
check: fmt-check clippy-gate test deny leak-gate spdx

.PHONY: check-full
check-full: check audit musl msrv package clang compiler-arms cross-check zizmor fuzz-replay

.PHONY: deny
deny:
	$(CARGO) deny --locked check bans licenses sources

.PHONY: audit
audit:
	# No `--locked`: cargo-audit does not accept it and does not need it; it reads
	# Cargo.lock directly and never resolves a graph of its own. `cargo deny` does accept
	# it and gets it. The two are different tools with different flags, which is why this
	# is checked rather than assumed from the pattern.
	$(CARGO) audit

.PHONY: leak-gate
leak-gate:
	@scripts/leak-gate.sh

# The ratchets (tests/ratchets.txt): tests that read the repository's own text and hold a
# rule about it, in seconds, first in `merge-gate` and before any long run, so a broken rule
# fails before the suite's minutes. scripts/ratchets.sh fails unless each target
# ran exactly the tests the list gives it.
.PHONY: ratchets
ratchets:
	@CARGO='$(CARGO)' scripts/ratchets.sh

# Every tracked text file names its licence, or is of a kind the script names that cannot
# (JSON, a fuzz seed or kept crash, the lockfile, the licence text), each kind counted. In
# `merge-gate` as well as `check`, since it takes a second and nothing else holds a new file to it.
.PHONY: spdx
spdx:
	@scripts/spdx-gate.sh

# The floor's release, refused where `rust-version` is not two or three numbers or rustup
# lacks it, and named in the output by its own `rustc --version`, so a gate's log says which
# compiler compiled at the floor.
define msrv_toolchain
	@test -n '$(MSRV_TOOLCHAIN)' || { \
	  echo "msrv: Cargo.toml's rust-version is not x.y or x.y.z: $$(grep '^rust-version' Cargo.toml)" >&2; exit 1; }
	@$(MSRV_INSTALLED) || { \
	  echo "msrv: the floor's toolchain $(MSRV_TOOLCHAIN) is not installed:" >&2; \
	  echo "  rustup toolchain install $(MSRV_TOOLCHAIN) --profile minimal" >&2; \
	  exit 1; }
	@echo "toolchain $(MSRV_TOOLCHAIN): $$(rustc '+$(MSRV_TOOLCHAIN)' --version)"
endef

# The advertised floor, actually built. `rust-version` is a promise to every downstream
# resolver, and a promise nothing executes is the aspirational text this project refuses
# to ship. Requires the toolchain: `rustup toolchain install $(MSRV_TOOLCHAIN)`.
# `--no-fail-fast`, as `test` has it: the floor's first daily run stopped at the first
# failing binary and so read 1 of 38.
.PHONY: msrv
msrv:
	@echo "== MSRV $(MSRV) =="
	$(msrv_toolchain)
	$(CARGO) "+$(MSRV_TOOLCHAIN)" build --locked
	$(CARGO) "+$(MSRV_TOOLCHAIN)" test --locked --no-fail-fast

# The floor's compile alone, the part of `msrv` a merge gate can afford beside the suite: a
# test that does not compile at `rust-version` fails here, where `test` on the default
# toolchain passes it. It checks
# the library, the binary and every test target (`--all-targets`, with `cfg(test)`); the crate
# has no doctests. A check, not `test --no-run`: rustc's parsing, name resolution, types,
# borrows and lints run alike, and what it skips is code generation, which with the suite at
# opt-level 1 made the floor's compile 80 s cold against 22 s for the check (the x86_64
# host at a load of about 50). What only code generation reports at the floor, a
# post-monomorphization error such as a constant that fails to evaluate in one
# instantiation, is left to `msrv`, which a daily run on the CI host makes, as well as
# GitHub's msrv job. Offline, so it needs the toolchain and a cargo registry cache that
# already holds the locked dependencies (any earlier build fills it), and no network.
.PHONY: msrv-compile
msrv-compile:
	@echo "== MSRV $(MSRV_TOOLCHAIN), checked =="
	$(msrv_toolchain)
	$(CARGO) "+$(MSRV_TOOLCHAIN)" check --locked --offline --all-targets

# The floor's exact release, printed for CI's msrv job to install.
.PHONY: msrv-toolchain
msrv-toolchain:
	@test -n '$(MSRV_TOOLCHAIN)' || { \
	  echo "msrv: Cargo.toml's rust-version is not x.y or x.y.z: $$(grep '^rust-version' Cargo.toml)" >&2; exit 1; }
	@echo '$(MSRV_TOOLCHAIN)'

# What a merge runs before it lands where CI does not: the formatter, the pinned clippy (before
# the suite, so a lint fails in seconds), the suite with its ledger, the floor's compile and the
# licence identifiers. The leak gate runs beside it and not in it: it scans the history
# reachable from HEAD, and the known findings it accepts are the lines of
# `scripts/leak-gate.accepted` (none where the file is empty or absent); deny is in `check` and not here, as the full `msrv` is in
# `check-full`, `kani` in `verify`, and `cross-check` in `check-full`, since it needs another
# target's standard library installed (a merge runs it beside this where one is). The pinned
# clippy is here because in `check` alone, which no merge runs, its warnings grew across
# merges with every gate green. scripts/merge-gate.sh runs `ratchets` and then those five
# targets in that order (a document-only diff against MERGE_GATE_BASE runs the ratchets, spdx
# and the tests that read the changed documents alone),
# stops at the first that fails, times each, keeps each one's output in
# target/merge-gate/PHASE.log ($MERGE_GATE_LOG_DIR), and prints the short account: one line
# per phase, one per test binary, any failure and the ledger.
.PHONY: merge-gate
merge-gate:
	@MAKE='$(MAKE)' scripts/merge-gate.sh

# The crate compiled for operating systems other than this one. chard has code that only
# macOS and the BSDs compile (the `cfg(target_os = ...)` arms in `src/env.rs` and beside it),
# and the suite, the merge gate and every CI job but this target's run on Linux, so a change
# that breaks those builds passes them all. A private enum whose variants only the Linux read
# constructs, for one, fails the macOS, FreeBSD and OpenBSD builds under the manifest's
# `unused = deny` with every Linux gate green.
#
# `cargo check` for each target compiles the library, the binary and every test target with
# rustc's lints (the manifest's `unused = deny` among them, not clippy's), and links nothing,
# so it needs no foreign linker or SDK: only the target's
# standard library, which `rustup target add` installs where rustup ships one. A target whose
# library is missing fails, and cargo's error names it. Every target is compiled before the
# status is decided, and the count is printed against the list, so an empty list fails rather
# than passing over nothing.
#
# CROSS_FLAGS reaches a target rustup ships no library for. OpenBSD's is tier 3; a nightly
# with `rust-src` builds its library from source, offline where the registry cache holds the
# library's dependencies:
#   make cross-check CARGO='cargo +nightly' CROSS_FLAGS=-Zbuild-std=std,panic_abort \
#     CROSS_TARGETS='x86_64-unknown-freebsd x86_64-unknown-openbsd'
CROSS_TARGETS ?= x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-freebsd
CROSS_FLAGS   ?=

.PHONY: cross-check
cross-check:
	@n=0; ok=0; failed=; \
	for t in $(CROSS_TARGETS); do \
	  n=$$((n + 1)); echo "== cross-check $$t"; \
	  if $(CARGO) check --locked --all-targets --target "$$t" $(CROSS_FLAGS); then \
	    ok=$$((ok + 1)); else failed="$$failed $$t"; fi; \
	done; \
	[ $$n -gt 0 ] || { echo 'cross-check: CROSS_TARGETS is empty, so nothing was compiled'; exit 2; }; \
	echo "cross-check: $$ok of $$n target(s) compiled"; \
	[ -z "$$failed" ] || { echo "cross-check: failed for$$failed"; exit 1; }

# Build the crate archive the way a consumer receives it, including cargo's verification
# build. Never `--no-verify`: that build is the only evidence the archive compiles at all.
# It does not run the archive's tests, which is how an archive shipping a test it could not
# run passed unnoticed, see the `exclude` comment in Cargo.toml.
#
# Refuses a dirty tree, deliberately, and no `--allow-dirty` here: an archive built from
# uncommitted work corresponds to no revision, which is the same reason a report measured
# from a modified tree is stamped `-dirty` and cannot be cited. `check-full` is the
# pre-release gate, so failing on uncommitted changes is the behaviour it wants.
.PHONY: package
package:
	$(CARGO) package --locked

# Kani proofs over the bounded reads and the alignment rule in the ELF reader, the only code
# here that takes input chard did not produce (`proofs/README.md` says what each proves).
# Deliberately NOT in `check` or the merge gate: a model checker's run is long where the
# gate's other phases are short, and the harnesses read nothing a commit outside `src/elf.rs`
# and `proofs/` changes, so a run per commit buys nothing there. The verdict does move with
# the verifier release, which the CI workflow's `kani` job pins; that job runs this target
# where the tree is pushed. `scripts/kani-gate.sh` runs the checker and fails unless the
# harnesses it verified are, by name, the ones declared under `proofs/`.
#
# Run it when `src/elf.rs` or a file under `proofs/` changes. `make verify` is the two
# together.
# The workflows are the one place where a mistake publishes rather than fails: a job runs
# with a token, on a runner, against a tree a fork can influence. `--offline` keeps the
# verdict a function of the committed files -- zizmor's online audits query GitHub about
# each action, and this must not become a check whose result depends on the day.
#
# `--persona=auditor` is the strictest of the three and reports findings the default
# persona suppresses as low-confidence. For four files reviewed by hand, the false
# positives are cheaper to read than a missed injection is to find later.
#
# Not in `check`: zizmor is not installed by `rustup`, and the workflows change perhaps
# once a month while `check` runs on every commit.
# chard measures whatever driver it is handed, and gcc is only the one this host has by
# default. The assertion is `all_checks_attempted`, not a verdict count: how many checks
# clang yields will drift with clang, but a corpus that stops being fed to it is a
# regression at any version.
.PHONY: clang
clang:
	$(CARGO) run --locked --release -- measure --profile bare --cc clang -o chard-clang.json
	@grep -q '"all_checks_attempted": true' chard-clang.json \
	  || { echo 'clang lane: not every check was attempted -- see chard-clang.json'; exit 1; }
	@grep -q "\"checks_attempted\": $(CHECKS)" chard-clang.json \
	  || { echo 'clang lane: attempted count is not the corpus total'; exit 1; }
	@echo 'clang lane: $(CHECKS) of $(CHECKS) checks attempted'

# The inert-flag rows another compiler owns, run. `tests/inert_flags.rs` drives `cc`, so on
# a gcc host every row inert only under clang is announced and `make check` passes with
# them unexercised. This target puts a `cc` and a `c++` that exec ARMS_CC and its C++
# driver at the head of PATH and sets CHARD_TEST_EXPECT_CC, under which the test fails
# unless the reports name that family and every row naming it ran
# (`tests/common::expected_compiler`).
#
# Wrappers that exec the compiler by name, not symlinks: Fedora's ccache shim picks the
# compiler from argv[0], so a `cc` symlink to the `clang` on PATH runs gcc, and a
# wrapper reaches the shim as `clang`. The expectation is what catches the trap if
# another one appears. The default is clang because `cc` is gcc on the hosts this gate was
# written for (Fedora 44 x86_64, and the Ubuntu runner CI uses). On a host whose `cc` is
# clang, `ARMS_CC=gcc` runs the gcc rows, and fails where gcc's sanitizer runtime is not
# installed, as on that Fedora host: one row names gcc and needs libubsan, and the gate
# requires every row naming its compiler. CHARD_ALLOW_TEST_SKIP is unset for the run, and
# the test refuses to skip under the gate anyway: a skip would pass it with nothing run.
#
# The clang rows need clang 20 or later. On Ubuntu 24.04 x86_64 (2026-10-13), the archive's
# clang 18.1.3 and 19.1.1 fail the gate on two rows: the `-fsanitize=type` row cannot
# build, and the `-fno-sanitize-trap=local-bounds` row reads `indeterminate`. 20.1.2 runs
# every row. Below the floor the gate fails and names the rows: a row the compiler cannot
# run fails the gate rather than passing it as a skip. The gate also runs probe_sources'
# `a_group_left_in_handler_mode_beside_trapped_groups_is_withheld`, whose local-bounds rows
# have the same clang 20 floor and fail below it under the gate. CI installs clang 20 for its job
# (.github/workflows/ci.yml); a host whose `clang` is older puts a newer one first on PATH.
#
# `cc` is also the linker rustc runs, and the wrappers are for what chard measures, not
# for linking chard, so cargo is handed `link-cc` as the host target's linker: a script
# that restores the caller's PATH and runs `cc`. An absolute path to the caller's `cc` is
# not enough, since Fedora's ccache shim finds its compiler by searching PATH and would
# find the wrapper, and neither is building the tests first, since in a worktree cargo
# relinks on every call.
ARMS_CC  ?= clang
ARMS_DIR ?= $(TARGET_DIR)/compiler-arms

.PHONY: compiler-arms
compiler-arms:
	@case '$(ARMS_CC)' in gcc) cxx=g++ ;; clang) cxx=clang++ ;; \
	  *) echo 'compiler-arms: ARMS_CC is gcc or clang, not $(ARMS_CC)'; exit 2 ;; esac; \
	command -v '$(ARMS_CC)' >/dev/null 2>&1 \
	  || { echo 'compiler-arms: no $(ARMS_CC) on PATH, so its rows cannot run here'; exit 1; }; \
	rm -rf '$(ARMS_DIR)' $(LEDGER); mkdir -p '$(ARMS_DIR)'; \
	printf '#!/bin/sh\nexec %s "$$@"\n' '$(ARMS_CC)' > '$(ARMS_DIR)/cc'; \
	printf '#!/bin/sh\nexec %s "$$@"\n' "$$cxx" > '$(ARMS_DIR)/c++'; \
	chmod +x '$(ARMS_DIR)/cc' '$(ARMS_DIR)/c++'; \
	command -v cc >/dev/null 2>&1 || { echo 'compiler-arms: no cc on PATH to link the tests with'; exit 1; }; \
	case $$PATH in *"'"*) echo 'compiler-arms: PATH holds a quote'; exit 2 ;; esac; \
	printf '#!/bin/sh\nPATH='"'"'%s'"'"' exec cc "$$@"\n' "$$PATH" > '$(ARMS_DIR)/link-cc'; \
	chmod +x '$(ARMS_DIR)/link-cc'; \
	triple=$$(rustc -vV | sed -n 's/^host: //p' | tr 'a-z-' 'A-Z_'); \
	echo "compiler-arms: cc is $$(PATH="$(abspath $(ARMS_DIR)):$$PATH" cc --version 2>&1 | head -1)"; \
	echo "compiler-arms: rustc links with $$(cc --version 2>&1 | head -1)"; \
	rc=0; env -u CHARD_ALLOW_TEST_SKIP "CARGO_TARGET_$${triple}_LINKER=$(abspath $(ARMS_DIR))/link-cc" \
	  "PATH=$(abspath $(ARMS_DIR)):$$PATH" CHARD_TEST_EXPECT_CC='$(ARMS_CC)' \
	  $(CARGO) test --locked --test inert_flags || rc=$$?; \
	env -u CHARD_ALLOW_TEST_SKIP "CARGO_TARGET_$${triple}_LINKER=$(abspath $(ARMS_DIR))/link-cc" \
	  "PATH=$(abspath $(ARMS_DIR)):$$PATH" CHARD_TEST_EXPECT_CC='$(ARMS_CC)' \
	  $(CARGO) test --locked --test probe_sources -- --exact \
	  a_group_left_in_handler_mode_beside_trapped_groups_is_withheld \
	  > '$(ARMS_DIR)/probe_sources.out' 2>&1 || rc=$$?; \
	cat '$(ARMS_DIR)/probe_sources.out'; \
	grep -q '^test result: ok\. 1 passed' '$(ARMS_DIR)/probe_sources.out' \
	  || { echo 'compiler-arms: the local-bounds trap-mode test did not run and pass exactly once'; rc=1; }; \
	scripts/test-ledger.sh --no-skip --require inert_flags --require 'inert_flags (partly inert)' \
	  $(LEDGER) || rc=1; \
	exit $$rc

# The corpus measured end to end, with the reports kept and read. `clang` above asks one
# question of one compiler under one profile; this asks the whole of it: every compiler
# in SWEEP_CC under every profile in SWEEP_PROFILES, each with `--fail-on-missing`, so a
# withheld verdict fails the cell. `scripts/sweep-gate.sh` then reads each report and
# prints its denominators before judging it, because the exit status alone says only
# that something was withheld, and the printed list says which cell. The reports stay in
# SWEEP_DIR as the evidence behind the verdict, and a maintainer opens them; the CI lane
# keeps none, and its log names each withheld cell.
#
# Some cells withhold by design on the toolchain CI runs, and each such cell has a file
# under SWEEP_EXPECTED, `<cc>-<profile>.txt`, listing the withheld verdicts it is expected
# to carry with a reason each. The gate holds the cell to that file in both directions:
# a withheld verdict the file omits fails the cell, and so does a listed check that
# started publishing, so the list changes only on purpose. Every run also writes the
# observed set of each cell as an UNREVIEWED candidate under SWEEP_DIR/expected, which is
# the file a reviewer edits and commits when a toolchain is new; the gate refuses a
# candidate until its header is gone. An empty file expects nothing, so on a toolchain
# whose file is empty every withheld verdict fails.
#
# Every cell is measured before any is judged, and the exit status is the OR of the
# gates, so one red cell does not hide the others. The cell count is printed and a sweep
# that measured nothing fails: a loop over an empty variable would otherwise exit 0.
#
# Several probes abort by design, and chard cannot lower RLIMIT_CORE for its children
# (`run::execute` says why), so the recipe's first statement is `ulimit -c 0`, in the one
# shell that runs every cell, and chard and each probe inherit it. The gate is handed the
# limit that shell reads back and each cell's workdir, which it clears first so the search
# covers this run alone; the gate fails a limit other than 0 and a core file under the
# workdir, and prints `core_pattern`, which decides whether that search can see a core at
# all (`scripts/sweep-gate.sh` gives the cases).
#
# Not in `check`: it needs both compilers and takes minutes. The lane in
# .github/workflows/ci.yml runs it per compiler by overriding SWEEP_CC.
#
# The execution mode is declared, never guessed: SWEEP_EXECUTION is required (`host`, `vm`
# or `container`), because `host` by default withholds the checks that declare `needs_vm`
# and `--fail-on-missing` then fails every cell (DESIGN.md, "Containers vs VMs"). The CI
# lane passes `vm`, a hosted runner being one; a maintainer's own machine is `host`.
SWEEP_CC        ?= gcc clang
SWEEP_PROFILES  ?= bare bare-optimized openssf-tldr
SWEEP_DIR       ?= chard-sweep-out
SWEEP_EXPECTED  ?= tests/sweep-expected
SWEEP_EXECUTION ?=

.PHONY: sweep
sweep: build
	@[ -n "$(SWEEP_EXECUTION)" ] || { echo 'sweep: SWEEP_EXECUTION is required (host, vm or container); the basis is declared, never guessed'; exit 2; }; \
	ulimit -c 0; mkdir -p $(SWEEP_DIR); fail=0; cells=0; \
	for cc in $(SWEEP_CC); do for profile in $(SWEEP_PROFILES); do \
	  cells=$$((cells + 1)); \
	  report=$(SWEEP_DIR)/$$cc-$$profile.json; \
	  work=$(SWEEP_DIR)/work-$$cc-$$profile; \
	  rm -f "$$report" "$$report.contradicted"; rm -rf "$$work"; \
	  ./target/release/chard measure --cc $$cc --profile $$profile --fail-on-missing \
	    --execution $(SWEEP_EXECUTION) --workdir "$$work" --output $$report; rc=$$?; \
	  scripts/sweep-gate.sh --expected $(SWEEP_EXPECTED) --candidate $(SWEEP_DIR)/expected \
	    --core-limit "$$(ulimit -c)" --workdir "$$work" \
	    $$report $(CHECKS) $$rc || fail=1; \
	done; done; \
	echo; echo "sweep: $$cells cell(s) measured into $(SWEEP_DIR)"; \
	[ $$cells -gt 0 ] || { echo 'sweep: measured nothing'; exit 1; }; \
	exit $$fail

# How every mutants target runs. Each mutant is tested at opt-level 1, which keeps debug
# assertions and overflow checks (separate profile keys), under a 900 s timeout: the unmutated
# suite took 551 s at the debug profile and 262 s at opt-level 1 on Fedora 44 x86_64
# (2026-10-20), so under a timeout of 180 or 300 s any mutant the suite does not kill early
# reads as a timeout. cargo-mutants 27.1.0 copies the tree without `.git` and
# without executable bits, so the VCS is copied (`tests/merge_gate.rs` runs `git ls-files`)
# and every test target runs but `cells_script`, which runs `scripts/cells.sh` by its mode;
# naming the targets leaves the doc tests out.
MUTANTS_TESTS = --lib --bins $(foreach t,$(filter-out cells_script,$(basename $(notdir $(wildcard tests/*.rs)))),--test $(t))
MUTANTS = CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1 \
	cargo mutants --copy-vcs true -j 8 --timeout 900

# Do the tests discriminate, or only pass? Scoped to the ELF reader because that is where
# a surviving mutant is a wrong hardening verdict on an attacker-supplied binary. Not in
# any gate: 75 minutes at -j 8 on Fedora 44 x86_64 (2026-10-20; about 25 in September 2026),
# and the survivor list is a reading task, not a pass/fail.
.PHONY: mutants
mutants:
	$(MUTANTS) --file src/elf.rs -- $(MUTANTS_TESTS)

# The detectors and the derivations, which is where a surviving mutant is a wrong verdict
# rather than a wrong read of somebody's binary. Separate from `mutants` because it is four
# hours at -j 8 on Fedora 44 x86_64 rather than 75 minutes (2026-10-20; twenty-five rather
# than five in September 2026), and because the two answer different questions:
# that one asks whether the ELF reader's tests bite, this one asks whether the rules that
# turn evidence into a published claim do.
#
# A survivor count nobody else can re-derive is an anecdote, so the target that produces it
# is in this file.
.PHONY: mutants-detectors
mutants-detectors:
	$(MUTANTS) --file src/probe.rs --file 'src/decode/*.rs' --file src/report.rs -- $(MUTANTS_TESTS)

# Every other source file with a mutant: the ELF reader's code and entry readers, the
# measurement loop, the compiler and run records, the link inputs, the environment and the
# toolchain, the predicate language and its macro predicates, the composites, the readers
# of a published report (`detect`, `table`, `matrix`, the dataset), the fixtures, the
# digests and the CLI. `src/guide.rs`, `src/lib.rs` and `src/elf/reloc_names.rs` have
# none. Run one file at a time, the first twenty took about eight hours at -j 8 on Fedora 44
# x86_64 (2026-10-20); this target, one invocation over all of them, has not been timed.
.PHONY: mutants-rest
mutants-rest:
	$(MUTANTS) --file src/elf/code.rs --file src/elf/entry.rs --file src/report/digest.rs \
	  --file src/run.rs --file src/compile.rs --file src/compile_inputs.rs \
	  --file src/measure.rs --file src/env.rs --file src/toolchain.rs --file src/matrix.rs \
	  --file src/composite.rs --file src/dataset.rs --file src/structured.rs \
	  --file src/mechanism.rs --file src/predicate/elf_static.rs --file src/main.rs \
	  --file src/detect.rs --file src/error.rs --file src/table.rs --file src/digest.rs \
	  --file src/link_inputs.rs --file src/predicate/mod.rs --file src/predicate/macro_channel.rs \
	  --file src/fixture.rs -- $(MUTANTS_TESTS)

.PHONY: zizmor
zizmor:
	zizmor --offline --persona=auditor .github/workflows/

.PHONY: kani
kani:
	@CARGO='$(CARGO)' scripts/kani-gate.sh

.PHONY: verify
verify: check kani
	@echo 'chard: full local gate passed'

# libFuzzer targets in `fuzz/`, a crate outside chard's workspace (`fuzz/Cargo.toml` says
# why): dev-only, and on a nightly toolchain because cargo-fuzz needs one. `fuzz-replay` is
# a step of `check-full` and not of `check`, `merge-gate`, `verify` or CI: it needs that
# nightly toolchain and cargo-fuzz, and the hosts that run the merge gate are held to neither.
# Each target's first directory is its growing corpus under `fuzz/corpus/`, which libFuzzer
# writes to and git ignores; the rest are read-only seeds: the ELF fixtures for the reader,
# `schema/` (the predicate vectors among it) for the predicate language, `tests/fixtures/`
# (a whole report among it) for the digest, and the tracked `fuzz/seeds/<target>/` for the
# flag-word, structured-diagnostics, driver-text and environment readers. `fuzz-replay` runs
# everything once with `-runs=0`, which turns the targets into a regression pass over what
# the fuzzer found before, the way droidsaw's sanitizer targets replay theirs. It counts the
# inputs it feeds each target and fails on a target it has none for, rather than pass having
# replayed nothing: `detect_evidence`, `report_render` and `parse_macros` read only the ignored
# corpus, so on a fresh clone `make fuzz-seed` comes first.
FUZZ_TOOLCHAIN ?= nightly
FUZZ_TIME      ?= 60
# AddressSanitizer, named rather than inherited: it is cargo-fuzz's default, and naming it here
# makes the tree say which sanitizer a campaign runs under. chard denies `unsafe`, so what it
# reaches is the `unsafe` in std and the dependencies, and an allocation or stack depth a
# crafted input drives past libFuzzer's limits, reported as a finding rather than a kill.
FUZZ_SANITIZER ?= address
# Every target, held to the `[[bin]]` list of `fuzz/Cargo.toml` by `fuzz-replay`;
# `FUZZ_TARGETS` names the ones a run takes.
FUZZ_ALL       := elf_parse detect_evidence predicate report_render parse_macros attestation \
                  flag_words structured_diag report_digest driver_text env_reads
FUZZ_TARGETS   ?= $(FUZZ_ALL)
# Read-only seed directories per target, relative to `fuzz/`, and the dictionary each reads.
# A target with no arm is refused, not run with the defaults of another.
fuzz_seeds = case $$t in elf_parse) seeds=../tests/fixtures/elf; dict=dictionaries/elf.dict ;; predicate) seeds=../schema; dict=dictionaries/report.dict ;; report_render) seeds=corpus/detect_evidence; dict=dictionaries/report.dict ;; parse_macros) seeds=; dict=dictionaries/macros.dict ;; attestation) seeds=; dict=dictionaries/attestation.dict ;; flag_words) seeds=seeds/flag_words; dict=dictionaries/flags.dict ;; structured_diag) seeds=seeds/structured_diag; dict=dictionaries/sarif.dict ;; report_digest) seeds="corpus/detect_evidence ../tests/fixtures"; dict=dictionaries/report.dict ;; driver_text) seeds=seeds/driver_text; dict=dictionaries/driver.dict ;; env_reads) seeds=seeds/env_reads; dict=dictionaries/env.dict ;; detect_evidence) seeds=; dict=dictionaries/report.dict ;; *) echo "fuzz: $$t has no seeds arm in the Makefile" >&2; exit 1 ;; esac

# A seed directory under the ignored corpus, which a fresh clone has not made: libFuzzer exits
# 1 on a directory that does not exist, so it is made, empty, before the run reads it.
fuzz_seed_dirs = for d in $$seeds; do case $$d in corpus/*) mkdir -p fuzz/$$d ;; esac; done

.PHONY: fuzz
fuzz:
	@set -e; for t in $(FUZZ_TARGETS); do \
	  echo "== fuzz $$t ($(FUZZ_TIME) s)"; \
	  mkdir -p fuzz/corpus/$$t; $(fuzz_seeds); $(fuzz_seed_dirs); \
	  ( cd fuzz && $(CARGO) +$(FUZZ_TOOLCHAIN) fuzz run --sanitizer $(FUZZ_SANITIZER) $$t corpus/$$t $$seeds -- -max_total_time=$(FUZZ_TIME) -dict=$$dict ); \
	done

# Seeds the fuzzer cannot find from nothing, written under the ignored corpus (a report
# names the host it ran on). Reports under three profiles, since `table` and `matrix` join
# several; every ELF artifact those measurements built, which on an ELF host are real
# executables, shared objects and objects beside the synthetic fixtures; and, through
# `fuzz/seed.rs`, a fixture record per (check, arm, outcome) and a normalized copy of each
# whose run prints a volatile reading, the ELF fixtures copied in, one store entry of each kind
# and a `chard elf`-shaped object, the input shapes `chard detect --evidence` sniffs besides a
# report, plus the reports joined as one array for `report_render` and each report's
# filtered `macro-dump` store entries rendered back as `#define` lines for `parse_macros`
# (reports measured at this revision store none, so those dumps write no seed). Each
# compiler's own `-dM -E` dumps, with no source, with the libc headers chard's macro dump
# reads under `-O2 -D_FORTIFY_SOURCE=2`, and as C++, seed `parse_macros` whole.
FUZZ_SEED_PROFILES ?= bare bare-optimized openssf-tldr
# Every compiler named here is measured under every profile, so the joined set varies on
# the compiler axis `matrix` explains verdicts by; an absent one is skipped.
FUZZ_SEED_CCS ?= cc
# Files to take attestations from for `attestation`: a fleet's session files, reports or a
# fetcher's own `attestation.json`, which name publishers' URLs and local paths and so are
# not tracked. `fuzz/seed.rs` writes a fixed set and every report's own regardless.
FUZZ_SEED_ATTESTATIONS ?=
.PHONY: fuzz-seed
fuzz-seed: build
	mkdir -p fuzz/corpus/detect_evidence fuzz/corpus/elf_parse fuzz/corpus/report_render fuzz/corpus/parse_macros fuzz/corpus/attestation fuzz/corpus/structured_diag
	@set -e; for c in $(FUZZ_SEED_CCS); do \
	  command -v $$c >/dev/null 2>&1 || { echo "fuzz-seed: $$c absent, skipped"; continue; }; \
	  m=fuzz/corpus/parse_macros/seed-$$(basename $$c); \
	  $$c -dM -E -x c /dev/null > $$m-empty.txt || rm -f $$m-empty.txt; \
	  printf '#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n' | $$c -O2 -D_FORTIFY_SOURCE=2 -dM -E -x c - > $$m-libc.txt || rm -f $$m-libc.txt; \
	  printf '#include <string>\n' | $$c -dM -E -x c++ - > $$m-cxx.txt 2>/dev/null || rm -f $$m-cxx.txt; \
	  for p in $(FUZZ_SEED_PROFILES); do \
	    rm -rf target/fuzz-seed-work-$$c-$$p; \
	    ./target/release/chard measure --cc $$c --profile $$p --workdir target/fuzz-seed-work-$$c-$$p -o fuzz/corpus/detect_evidence/$$c-$$p.json || test -s fuzz/corpus/detect_evidence/$$c-$$p.json; \
	    find target/fuzz-seed-work-$$c-$$p -type f -size -8M | while read -r f; do \
	      if [ "$$(head -c 4 "$$f" | od -An -tx1 | tr -d ' ')" = 7f454c46 ]; then \
	        cp "$$f" "fuzz/corpus/elf_parse/seed-$$c-$$p-$$(basename "$$f")"; \
	      fi; \
	    done; \
	  done; \
	done
	cd fuzz && $(CARGO) run --release --quiet --bin seed -- corpus ../tests/fixtures/detectors.json ../tests/fixtures/elf $$(ls corpus/detect_evidence/*-*.json 2>/dev/null | grep -E '/[^/]+-(bare|bare-optimized|openssf-tldr)\.json$$')
	@if [ -n "$(FUZZ_SEED_ATTESTATIONS)" ]; then cd fuzz && $(CARGO) run --release --quiet --bin seed -- --attestations corpus $(abspath $(FUZZ_SEED_ATTESTATIONS)); fi

.PHONY: fuzz-replay
fuzz-replay:
	@set -e; \
	[ -n "$(strip $(FUZZ_TARGETS))" ] || { echo "fuzz-replay: FUZZ_TARGETS names no target" >&2; exit 1; }; \
	bins=$$(sed -n 's/^name = "\(.*\)"$$/\1/p' fuzz/Cargo.toml | grep -vx 'chard-fuzz' | grep -vx 'seed' | sort | tr '\n' ' '); \
	want=$$(printf '%s\n' $(FUZZ_ALL) | sort | tr '\n' ' '); \
	[ "$$bins" = "$$want" ] || { echo "fuzz-replay: fuzz/Cargo.toml builds [$$bins], the Makefile names [$$want]" >&2; exit 1; }; \
	for t in $(FUZZ_TARGETS); do \
	  mkdir -p fuzz/corpus/$$t; $(fuzz_seeds); $(fuzz_seed_dirs); \
	  dirs="corpus/$$t $$seeds"; \
	  if [ -d fuzz/crashes/$$t ]; then dirs="$$dirs crashes/$$t"; fi; \
	  n=$$(cd fuzz && find $$dirs -type f -size +0c ! -name '*.note' | wc -l); \
	  echo "== replay $$t: $$n input(s) from $$dirs"; \
	  [ "$$n" -gt 0 ] || { echo "fuzz-replay: $$t has no input to replay; its corpus is filled by make fuzz-seed or a campaign" >&2; exit 1; }; \
	  ( cd fuzz && $(CARGO) +$(FUZZ_TOOLCHAIN) fuzz run --sanitizer $(FUZZ_SANITIZER) $$t $$dirs -- -runs=0 -dict=$$dict ); \
	done

# Provide the target; let the human run it. A repository that rewrites the
# developer's git configuration as a side effect of building is doing something
# they did not ask for.
.PHONY: hooks
hooks:
	git config core.hooksPath .githooks
	@echo 'hooks installed: pre-commit and pre-push -> .githooks'

# Removes only what a build or a measurement produced. The list lives in
# `hack/clean.sh` and not here, so it has one definition.
.PHONY: clean
clean:
	@hack/clean.sh

# The same, across every worktree `git worktree list` knows about.
.PHONY: clean-all
clean-all:
	@hack/clean.sh --worktrees

# What a clean would remove, and the megabytes, without removing anything.
.PHONY: clean-dry
clean-dry:
	@hack/clean.sh --dry-run --worktrees
