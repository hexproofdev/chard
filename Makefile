# SPDX-License-Identifier: BSD-3-Clause
#
# The entry point. Every command a contributor, a reviewer or CI runs has a target here, so
# the string in the README, the string in .github/workflows/ci.yml and the string a maintainer
# types are the same string. The one exception is CI's `kani` job, which runs
# `scripts/kani-gate.sh` itself so that no edit of the Makefile reaches that run.
#
# `--locked` on the cargo calls that build, check, document or test this crate: a gate that
# silently updates Cargo.lock measures a different dependency set than the one committed.
# `cargo fmt` rejects the flag and `cargo audit` does not accept it; the fuzz and mutants
# recipes run without it.

CARGO       ?= cargo
# Derived from the host: a target hardcoded to x86_64 makes `make musl` a cross-build on any
# other host, and `make doctor` print a `rustup target add` line for the wrong architecture.
# Override it to cross deliberately.
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
# from the network inside a run meant to be offline.
MSRV_TOOLCHAIN := $(shell printf '%s\n' '$(MSRV)' | sed -n -e 's/^\([0-9][0-9]*\.[0-9][0-9]*\)$$/\1.0/p' -e t -e 's/^\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$$/\1/p')
# Whether rustup has the floor's release installed, asked of `rustup toolchain list`, which
# never installs: `rustup run` and `cargo +X` would fetch a missing toolchain wherever rustup's
# auto-install is on. The name is matched whole, before the host triple.
MSRV_INSTALLED = rustup toolchain list 2>/dev/null | sed -n 's/^\($(MSRV_TOOLCHAIN)\)-[^ ]*.*/\1/p' | grep -qxF '$(MSRV_TOOLCHAIN)'
# The clippy the gate runs, pinned to one release so the gate's verdict is a function of the
# commit: a new clippy's new lint turns `make clippy-gate` red only in the commit that moves
# this line, which fixes or allows what it finds in the same diff. CI reads it from here
# (digits and dots only, as for the floor), so it is written once. Bump it deliberately.
CLIPPY_TOOLCHAIN := 1.100.0
# The corpus total, read from the corpus: a copy written down here would go stale the day a
# check is added.
CHECKS      := $(shell sed -n 's/^        const CHECKS: usize = \([0-9]*\);/\1/p' src/probe.rs)
# Where the test binaries append the arms they could not run (`tests/common::LEDGER_DIR`,
# cargo's `CARGO_TARGET_TMPDIR`): under the target directory cargo builds into.
TARGET_DIR  ?= $(or $(CARGO_TARGET_DIR),target)
LEDGER      := $(TARGET_DIR)/tmp/test-ledger
# Where the hooks are and which ones `make hooks` installs and `make check` requires. Set
# with `:=`, so a plain exported variable cannot point the check at another directory.
HOOKS_DIR   := .githooks
HOOKS       := pre-commit

.DEFAULT_GOAL := help

# A bare `make` must not launch a long gate, so help is the default goal and the
# only target that runs by accident.
.PHONY: help
help:
	@echo 'chard — measure which hardening flags a toolchain actually applies'
	@echo
	@echo '  make doctor      check prerequisites and name what is missing'
	@echo '  make build       build the release binary'
	@echo '  make check       the gate: lints + fmt-check + clippy-gate + clippy-fuzz + doc + md-lint + sh-lint + yaml-lint + test + deny + spdx'
	@echo '                   (refuses to run before make hooks; needs rumdl, shellcheck, shfmt and yamllint)'
	@echo '  make check-full  the slow gate: check + audit + musl + msrv + package + clang + compiler-arms + cross-check + fuzz-replay'
	@echo '                   (fuzz-replay needs nightly and cargo-fuzz, and make fuzz-seed once on a fresh clone)'
	@echo '  make test        tests only, then the arms this host did not exercise'
	@echo '  make fmt         format in place'
	@echo '  make fmt-check   fail if formatting is not clean, here or in fuzz/'
	@echo '  make lints       the house lint standard'"'"'s gate over the lint tables, and the C sources against .lints/c/exclude: in check'
	@echo '  make clippy      lints on your default toolchain: deny-level lints fail, pedantic warnings are shown'
	@echo '  make clippy-gate clippy $(CLIPPY_TOOLCHAIN) with warnings denied: in check'
	@echo '  make clippy-fuzz the same clippy over fuzz/, three ways: in check'
	@echo '  make md-lint     the house Markdown gate (rumdl): in check'
	@echo '  make sh-lint     the house shell gate (shellcheck and shfmt): in check'
	@echo '  make yaml-lint   the house YAML gate (yamllint): in check'
	@echo '  make clippy-canary  clippy-gate run over copies of the tree: denies each lint outside test code, passes the relief in it'
	@echo '  make deny        bans, licences and sources — reproducible from the commit'
	@echo '  make audit       live advisory database — verdict changes without a commit'
	@echo '  make musl        static binary for images without a matching libc'
	@echo '  make spdx        fail a tracked text file with no SPDX licence identifier'
	@echo '  make msrv        build and test at the advertised rust-version floor, rustup toolchain $(MSRV_TOOLCHAIN)'
	@echo '  make msrv-compile  check every target at the floor, offline, without code generation'
	@echo '                   (both need: rustup toolchain install $(MSRV_TOOLCHAIN) --profile minimal)'
	@echo '  make cross-check compile the crate and its tests for x86_64 and aarch64 macOS and x86_64 FreeBSD (CROSS_TARGETS), linking nothing'
	@echo '  make package     build the crate archive, with its verification build'
	@echo '  make clang       run the corpus against clang, not just cc'
	@echo '  make compiler-arms  run the inert-flag rows and the local-bounds trap modes of ARMS_CC (default clang), with cc pointed at it'
	@echo '  make sweep       measure gcc and clang under three profiles, and hold each report to its expectation in SWEEP_EXPECTED, a directory of <cc>-<profile>.txt (none by default: every withheld verdict then fails its cell; SWEEP_EXECUTION=host|vm|container required)'
	@echo '  make mutants     check the tests bite, over the ELF reader'
	@echo '  make mutants-detectors  the same, over the detectors and the derivations'
	@echo '  make mutants-rest  the same, over the other modules that decide or publish a verdict'
	@echo '  make kani        model-check the bounded reads in the ELF reader'
	@echo '  make verify      check + kani'
	@echo '  make fuzz        run each libFuzzer target for FUZZ_TIME seconds (nightly, dev-only)'
	@echo '  make fuzz-seed   seed the fuzz corpora with reports, ELF artifacts and each input shape'
	@echo '  make fuzz-replay replay every corpus, seed and kept crash without mutation'
	@echo '  make hooks       install $(HOOKS_DIR) (never automatic; make check refuses to run without them)'
	@echo '  make doc         build the library'"'"'s API docs under clippy'"'"'s pinned toolchain, rustdoc warnings denied: in check'
	@echo '  make clean       remove what the build produced, and nothing else'
	@echo '  make clean-all   the same, across every worktree'
	@echo '  make clean-dry   list what a clean would remove, and remove nothing'

# chard compiles probe programs with your compiler, so the toolchain under test is a
# prerequisite the build cannot supply, and a missing cc is a runtime failure, not a build
# failure. The exit status answers one question, whether chard can measure on this machine,
# and only the C compiler decides it. Each other tool names the target it is needed for; a
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
	  echo "MISS  clippy pin    rustup toolchain install $(CLIPPY_TOOLCHAIN) --profile minimal --component clippy   (needed for \`make check\`)"; \
	fi; \
	if [ -n '$(MSRV_TOOLCHAIN)' ] && $(MSRV_INSTALLED); then \
	  echo "ok    msrv          $(MSRV_TOOLCHAIN)"; \
	else \
	  echo "MISS  msrv          rustup toolchain install $(MSRV_TOOLCHAIN) --profile minimal   (needed for \`make msrv\` and \`make msrv-compile\`)"; \
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
	for d in $(ROUTE_DRIVERS); do \
	  if command -v $$d >/dev/null 2>&1; then \
	    printf 'ok    %-13s %s\n' "$$d" "$$($$d --version | head -1)"; \
	  else \
	    printf 'MISS  %-13s %s\n' "$$d" "absent; \`make test\` needs each of ROUTE_DRIVERS ($(ROUTE_DRIVERS)). On a host without one, run \`make test ROUTE_DRIVERS=<the compilers it has>\`"; \
	  fi; \
	done; \
	if command -v cargo-audit >/dev/null 2>&1; then \
	  echo "ok    cargo-audit   $$(cargo audit --version)"; \
	else \
	  echo "MISS  cargo-audit   cargo install cargo-audit  (needed for \`make audit\`)"; \
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
# these two targets build without any, so the binary they make is the one its revision
# names. Not cleared: a rustc wrapper and a profile setting (`CARGO_PROFILE_*`), which no
# build script marks.
.PHONY: build
build:
	env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS= \
	  $(CARGO) build --locked --release

.PHONY: musl
musl:
	env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS RUSTFLAGS= \
	  $(CARGO) build --locked --release --target $(MUSL_TARGET)

# fuzz/ is a workspace of its own, so `cargo fmt` here does not reach it.
.PHONY: fmt
fmt:
	$(CARGO) fmt
	cd fuzz && $(CARGO) fmt

.PHONY: fmt-check
fmt-check:
	$(CARGO) fmt --check
	cd fuzz && $(CARGO) fmt --check

# The lints on whatever toolchain is your default. A deny-level lint (`clippy::all`, rustc's
# `unused`) fails here as anywhere; the warn-level `pedantic` lints are printed and do not, so a
# newer clippy's suggestions show up here before anyone bumps the pin.
.PHONY: clippy
clippy:
	$(CARGO) clippy --locked --all-targets

# The gate's clippy: the pinned release with every warning denied, `pedantic` included, so a
# change that adds a warning fails the merge that carries it. A host without the pinned
# toolchain fails here with the command that installs it: a gate that cannot run its clippy
# does not pass. `cargo +X` takes precedence over RUSTUP_TOOLCHAIN and any override.
#
# The caller's environment cannot cap the lints: RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS or
# CARGO_BUILD_RUSTFLAGS holding `--cap-lints allow` let a warning through `-D warnings`
# (measured 2026-10-18). CARGO_ENCODED_RUSTFLAGS outranks RUSTFLAGS, so the recipe unsets it
# and CARGO_BUILD_RUSTFLAGS as well as setting RUSTFLAGS empty. With RUSTFLAGS set, even empty,
# cargo also ignores a config file's `build.rustflags` and `target.*.rustflags`, so none of the
# five reaches rustc (each measured against a seeded warning). CLIPPY_CONF_DIR, also unset,
# would replace this tree's clippy.toml with the caller's. `make clippy-canary` holds the call
# this makes. Not closed: a rustc wrapper (`RUSTC_WRAPPER`, `build.rustc-wrapper`), which can
# rewrite any flag, and the caller's own cargo configuration (CARGO_HOME's), whose `[env]
# CLIPPY_ARGS` reaches clippy; that is the caller's own machine. Nor, inside the tree, a build
# script handing clippy a variable or a file past this call (scripts/clippy-canary.sh, "Not
# held").
.PHONY: clippy-gate
clippy-gate:
	@echo "== clippy $(CLIPPY_TOOLCHAIN), warnings denied =="
	@rustup run $(CLIPPY_TOOLCHAIN) cargo clippy --version >/dev/null 2>&1 || { \
	  echo "clippy-gate: the pinned toolchain $(CLIPPY_TOOLCHAIN) with clippy is not installed:" >&2; \
	  echo "  rustup toolchain install $(CLIPPY_TOOLCHAIN) --profile minimal --component clippy" >&2; \
	  exit 1; }
	@echo "$$(rustup run $(CLIPPY_TOOLCHAIN) cargo clippy --version)"
	env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u CLIPPY_CONF_DIR RUSTFLAGS= \
	  $(CARGO) "+$(CLIPPY_TOOLCHAIN)" clippy --locked --all-targets -- -D warnings

# The same clippy over fuzz/, a workspace of its own that the rule above never compiles: the
# pinned release, every warning denied, against fuzz/Cargo.lock. Three ways: the dev profile,
# `--release` (what `cfg(debug_assertions)` leaves out), and under `--cfg fuzzing`, as
# cargo-fuzz builds the targets. Each run lints the fuzz crate alone: chard's library is a
# path dependency outside this workspace, which clippy-gate lints. Neither the tracked code
# nor the locked libfuzzer-sys branches on `cfg(fuzzing)`, and the dev run refuses a branch
# the build does not declare (`unexpected_cfgs`), so the third run reads what the first does;
# it is there for code that comes to branch on it. A rule of its own, not three more lines of
# clippy-gate, whose one call `make clippy-canary` holds by equality. The canary plants no
# site here, so nothing holds this rule's calls but their text, and its account line, the
# recipe's last, is printed whatever the lines above it run.
.PHONY: clippy-fuzz
clippy-fuzz:
	@echo "== clippy $(CLIPPY_TOOLCHAIN) over fuzz/, warnings denied =="
	@rustup run $(CLIPPY_TOOLCHAIN) cargo clippy --version >/dev/null 2>&1 || { \
	  echo "clippy-fuzz: the pinned toolchain $(CLIPPY_TOOLCHAIN) with clippy is not installed:" >&2; \
	  echo "  rustup toolchain install $(CLIPPY_TOOLCHAIN) --profile minimal --component clippy" >&2; \
	  exit 1; }
	cd fuzz && env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u CLIPPY_CONF_DIR RUSTFLAGS= \
	  $(CARGO) "+$(CLIPPY_TOOLCHAIN)" clippy --locked --all-targets -- -D warnings
	cd fuzz && env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u CLIPPY_CONF_DIR RUSTFLAGS= \
	  $(CARGO) "+$(CLIPPY_TOOLCHAIN)" clippy --locked --all-targets --release -- -D warnings
	cd fuzz && env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u CLIPPY_CONF_DIR RUSTFLAGS='--cfg fuzzing' \
	  $(CARGO) "+$(CLIPPY_TOOLCHAIN)" clippy --locked --all-targets -- -D warnings
	@echo "clippy-fuzz: three runs passed"

# The house lint standard's own gate (.lints/std/lints-gate.sh, vendored, whose header lists
# what it checks): the vendored copy, every generated lint block and clippy.toml, every
# manifest's inheritance, the allowances and the lint caps. It is the only hold on a level
# weakened inside a generated block, or a clippy.toml setting widened, for a lint `make
# clippy-canary` plants no site of. Then the C and C++ sources, which this tree excludes by
# prefix from the standard's C gate (.lints/c/exclude): a source outside those prefixes
# fails, so a new one meets the question of whether it is linted or excluded.
.PHONY: lints
lints:
	@sh .lints/std/lints-gate.sh
	@scripts/c-sources-gate.sh

# The house Markdown, shell and YAML gates, each under the repository's own configuration.
# Each fails without its tool, naming it: the vendored shell gate exits 3 where shellcheck or
# shfmt is missing, and this rule asks first so the message is this tree's. The YAML gate
# reads the tracked files, as the shell gate does, not the directory: a build's output, a
# package's unpacked copy or another worktree under this one is not this commit's YAML.
.PHONY: md-lint
md-lint:
	@command -v rumdl >/dev/null 2>&1 || { echo "md-lint: rumdl is not installed" >&2; exit 1; }
	rumdl check --fail-on error .

.PHONY: sh-lint
sh-lint:
	@for tool in shellcheck shfmt; do \
	  command -v "$$tool" >/dev/null 2>&1 || { echo "sh-lint: $$tool is not installed" >&2; exit 1; }; \
	done
	sh .lints/sh/shell-gate.sh

.PHONY: yaml-lint
yaml-lint:
	@command -v yamllint >/dev/null 2>&1 || { echo "yaml-lint: yamllint is not installed" >&2; exit 1; }
	@n=$$(git ls-files -- '*.yml' '*.yaml' .yamllint | grep -c .); [ "$$n" -gt 0 ] || { \
	  echo "yaml-lint: git lists no tracked YAML file" >&2; exit 1; }; \
	  git ls-files -z -- '*.yml' '*.yaml' .yamllint | xargs -0 yamllint -s && \
	  echo "yaml-lint: $$n tracked YAML files read"

# The canary over clippy-gate: the rule above, run through make over copies of this tree with a
# module planted in its library, must fail on a site of each denied lint outside test code and
# on an unrelieved one in test code, and pass the relieved lints' sites in test code, making
# the one cargo call the gate makes each time. It holds what the rule does for the sites it
# plants, where a reader of the rule's text holds only a spelling; scripts/clippy-canary.sh
# says what it runs and what it does not hold. It needs the pinned clippy, so it is a target
# of its own and not part of `make test`.
.PHONY: clippy-canary
clippy-canary:
	@MAKE='$(MAKE)' CARGO='$(CARGO)' scripts/clippy-canary.sh

# The ledger is cleared first so it holds this run alone, and read after the run whatever
# the run's status. `--no-fail-fast` so a red run still runs every binary, and the ledger
# lists the gaps of all of them. `inert_flags` always writes a count line per table, and
# `route_corpus` one for the routes it fed against those its lists make; the script fails a
# ledger missing any of the three (`scripts/test-ledger.sh`), so a run that filtered the
# corpus out or crashed before its frame reads as unaccounted rather than as a corpus with
# nothing to report.
#
# The ledger lists each toolchain gap, and the test that announces one states the condition
# its arm needs. `compiler-arms` runs `inert_flags` and probe_sources' local-bounds trap-mode
# test under a compiler it names.
.PHONY: test
# The ledger's flags beyond the tables it requires: empty here, and `--no-skip` for a run
# whose suite fails on any skipped test (`make test TEST_LEDGER_FLAGS=--no-skip`).
TEST_LEDGER_FLAGS ?=
# The compilers the route corpus must run under (`tests/route_corpus.rs`, `required_drivers`):
# a host that lacks one fails `make test`, since the test ledger does not fail on a gap and a
# lost compiler's routes would otherwise pass unrun. A host with one compiler names it
# (`make test ROUTE_DRIVERS=gcc`), and the other's routes are then a gap. Set with `:=`, so a
# plain exported variable cannot narrow it; a command line, `MAKEFLAGS` or `make -e` can, so
# a run that must hold both names both on its own `make test` line, which none of them
# overrides.
ROUTE_DRIVERS := gcc clang
test:
	@rm -rf $(LEDGER); rc=0; \
	echo '$(CARGO) test --locked --no-fail-fast'; \
	CHARD_ROUTE_DRIVERS='$(ROUTE_DRIVERS)' $(CARGO) test --locked --no-fail-fast || rc=$$?; \
	scripts/test-ledger.sh $(TEST_LEDGER_FLAGS) --require inert_flags --require 'inert_flags (partly inert)' \
	  --require route_corpus $(LEDGER) || rc=1; \
	exit $$rc

# The library's API docs under the pinned toolchain with every rustdoc warning denied, so a
# broken intra-doc link in a public item's docs, or a public item's link to a private one,
# fails here; a private item's docs are not built and not read, as the house standard's
# recipe has it. The binary shares the library's name, so cargo documents the library alone
# and no gate reads the binary's doc comments. In `check`: warnings grow where no gate runs
# the rule. The caller's flags cannot cap it: RUSTDOCFLAGS outranks a
# configuration's `build.rustdocflags`, and CARGO_ENCODED_RUSTDOCFLAGS, which outranks it, is
# unset, as are RUSTDOC and CARGO_BUILD_RUSTDOC, which name another program to run as rustdoc
# (`true` passes everything). A cargo configuration outside the tree that sets
# `build.rustdoc` still reaches it.
.PHONY: doc
doc:
	@rustup run $(CLIPPY_TOOLCHAIN) rustdoc --version >/dev/null 2>&1 || { \
	  echo "doc: the pinned toolchain $(CLIPPY_TOOLCHAIN) is not installed:" >&2; \
	  echo "  rustup toolchain install $(CLIPPY_TOOLCHAIN) --profile minimal --component clippy" >&2; \
	  exit 1; }
	env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u CARGO_ENCODED_RUSTDOCFLAGS \
	  -u RUSTDOC -u CARGO_BUILD_RUSTDOC \
	  RUSTDOCFLAGS='-D warnings' $(CARGO) "+$(CLIPPY_TOOLCHAIN)" doc --locked --no-deps

# `make check` runs only where the hooks are installed: the pre-commit hook checks the
# formatting and the lint tables before an object enters the graph, and a checkout that
# passes the gate without them has skipped that. This names `make hooks` and stops; it never
# runs it.
.PHONY: hooks-installed
hooks-installed:
	@test "$$(git config --get core.hooksPath 2>/dev/null)" = '$(HOOKS_DIR)' || { \
	  echo "check: the hooks are not installed in this checkout: run 'make hooks' first" >&2; \
	  exit 1; }
	@for hook in $(HOOKS); do \
	  test -f "$(HOOKS_DIR)/$$hook" && test -x "$(HOOKS_DIR)/$$hook" || { \
	    echo "check: $(HOOKS_DIR)/$$hook is missing or not executable" >&2; exit 1; }; \
	done

# The gate, and what CI runs on a pull request.
#
# `deny` is in this gate but `audit` is not: `cargo deny check bans licenses sources` reads a
# committed policy against a committed lockfile and is reproducible from the commit, while an
# advisory check fetches a live database and can change verdict on a day nobody touched the
# repository.
.PHONY: check
check: hooks-installed lints fmt-check clippy-gate clippy-fuzz doc md-lint sh-lint yaml-lint test deny spdx

.PHONY: check-full
check-full: check audit musl msrv package clang compiler-arms cross-check fuzz-replay

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

# Every tracked text file names its licence, or is of a kind the script names that cannot
# (JSON, a fuzz seed or kept crash, the lockfile, the licence text), each kind counted. In
# `check`, since it takes a second and nothing else holds a new file to it.
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

# The advertised floor, actually built and tested: `rust-version` is a promise to every
# downstream resolver. Requires the toolchain: `rustup toolchain install $(MSRV_TOOLCHAIN)`.
# `--no-fail-fast`, as `test` has it, so one failing binary does not hide the rest.
.PHONY: msrv
msrv:
	@echo "== MSRV $(MSRV) =="
	$(msrv_toolchain)
	$(CARGO) "+$(MSRV_TOOLCHAIN)" build --locked
	$(CARGO) "+$(MSRV_TOOLCHAIN)" test --locked --no-fail-fast

# The floor's compile alone, the part of `msrv` a gate can afford beside the suite: a
# test that does not compile at `rust-version` fails here, where `test` on the default
# toolchain passes it; the crate has no doctests. A check, not `test --no-run`: what it skips
# is code generation, which with the suite at opt-level 1 made the floor's compile 80 s cold
# against 22 s for the check (the x86_64 host at a load of about 50). What only code
# generation reports, such as a constant that fails to evaluate in one instantiation, is left
# to `msrv`, which the CI workflow's msrv job runs. Offline, so it needs a cargo registry cache
# that already holds the locked dependencies (any earlier build fills it).
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

# The crate compiled for operating systems other than this one. chard has code that only
# macOS and the BSDs compile (the `cfg(target_os = ...)` arms in `src/env.rs` and beside it),
# and the suite and every CI job but this target's run on Linux, so a change
# that breaks those builds passes them all. A private enum whose variants only the Linux read
# constructs, for one, fails the macOS, FreeBSD and OpenBSD builds under the manifest's
# `unused = deny` with every Linux gate green.
#
# `cargo check` runs rustc's lints, not clippy's, and links nothing, so it needs only each
# target's standard library (`rustup target add`); a target whose library is missing fails.
# Every target is compiled before the status is decided, and the count is printed against
# the list, so an empty list fails rather than passing over nothing.
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
# It does not run the archive's tests, so a test the archive cannot run passes here (the
# `exclude` comment in Cargo.toml says what the archive holds).
#
# Refuses a dirty tree, with no `--allow-dirty`: an archive built from uncommitted work
# corresponds to no revision, as a report measured from a modified tree is stamped `-dirty`
# and cannot be cited.
.PHONY: package
package:
	$(CARGO) package --locked

# `kani` (its rule is the one above `verify`): Kani proofs over the bounded reads and the
# alignment rule in the ELF reader, the only code here that takes input chard did not produce
# (`proofs/README.md` says what each proves). Not in `check`: a model checker's run is long
# where the gate's other phases are short. The CI workflow's `kani` job runs the script itself,
# not this target.
#
# `clang`, the rule below: the corpus under clang, since chard measures whatever driver it is
# handed. The assertion is `all_checks_attempted` and the corpus total, not a verdict count:
# how many checks clang yields will drift with clang, but a corpus that stops being fed to it
# is a regression at any version.
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
# compiler from argv[0], so a `cc` symlink to the `clang` on PATH runs gcc. The default is
# clang because `cc` is gcc on Fedora 44 x86_64 and on the Ubuntu runner CI uses;
# `ARMS_CC=gcc` runs the gcc rows, one of which needs libubsan. CHARD_ALLOW_TEST_SKIP is
# unset for the run, and the test refuses to skip under the gate anyway: a skip would pass it
# with nothing run.
#
# The clang rows need clang 20 or later. On Ubuntu 24.04 x86_64 (2026-10-13), the archive's
# clang 18.1.3 and 19.1.1 fail the gate on two rows: the `-fsanitize=type` row cannot
# build, and the `-fno-sanitize-trap=local-bounds` row reads `indeterminate`. 20.1.2 runs
# every row. Below the floor the gate fails and names the rows rather than passing them as
# skips, and so does the probe_sources test it runs, whose local-bounds rows have the same
# floor. CI installs clang 20 for its job; a host whose `clang` is older puts a newer one
# first on PATH.
#
# `cc` is also the linker rustc runs, so cargo is handed `link-cc` as the host target's
# linker: a script that restores the caller's PATH and runs `cc`. Not an absolute path to the
# caller's `cc`: Fedora's ccache shim finds its compiler by searching PATH and would find the
# wrapper.
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

# The corpus measured end to end, with the reports kept and read: every compiler in SWEEP_CC
# under every profile in SWEEP_PROFILES, each with `--fail-on-missing`, so a withheld verdict
# fails the cell. `scripts/sweep-gate.sh` then reads each report and prints its denominators
# before judging it, because the exit status says only that something was withheld, and the
# list says which cell. The reports stay in SWEEP_DIR as the evidence behind the verdict.
#
# A cell that withholds by design on a toolchain can be given a file in a directory of
# expectations, SWEEP_EXPECTED, as `<cc>-<profile>.txt`, listing the withheld verdicts it
# expects with a reason each. The gate holds the cell to it in both directions: a withheld
# verdict the file omits fails the cell, and so does a listed check that started publishing.
# SWEEP_EXPECTED is empty by default, and with no directory of expectations every withheld
# verdict fails its cell. Each run writes the observed set of every cell with a readable
# report as an UNREVIEWED candidate under SWEEP_DIR/expected, the file a reviewer edits and
# keeps for a toolchain; the gate refuses a candidate until its header is gone.
#
# The exit status is the OR of the cells, so one red cell does not hide the others. A sweep
# that measured nothing fails: a loop over an empty variable would otherwise exit 0.
#
# Several probes abort by design, and chard cannot lower RLIMIT_CORE for its children
# (`run::execute` says why), so the recipe sets `ulimit -c 0` in the one shell that runs every
# cell. The gate fails a limit other than 0, as that shell reads it back, and a core file
# under the cell's workdir, which the recipe clears first so the search covers this run alone
# (`scripts/sweep-gate.sh` gives the cases).
#
# Not in `check`: it needs both compilers and takes minutes. SWEEP_CC overridden to one
# compiler runs that compiler's cells alone.
#
# SWEEP_EXECUTION is required (`host`, `vm` or `container`), never guessed: `host` withholds
# the checks that declare `needs_vm`, and `--fail-on-missing` then fails every cell
# (DESIGN.md, "Containers vs VMs"). A hosted CI runner is a VM, so it passes `vm`.
SWEEP_CC        ?= gcc clang
SWEEP_PROFILES  ?= bare bare-optimized openssf-tldr
SWEEP_DIR       ?= chard-sweep-out
SWEEP_EXPECTED  ?=
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
	  scripts/sweep-gate.sh $(if $(SWEEP_EXPECTED),--expected $(SWEEP_EXPECTED)) --candidate $(SWEEP_DIR)/expected \
	    --core-limit "$$(ulimit -c)" --workdir "$$work" \
	    $$report $(CHECKS) $$rc || fail=1; \
	done; done; \
	echo; echo "sweep: $$cells cell(s) measured into $(SWEEP_DIR)"; \
	[ $$cells -gt 0 ] || { echo 'sweep: measured nothing'; exit 1; }; \
	exit $$fail

# How every mutants target runs. Each mutant is tested at opt-level 1, which keeps debug
# assertions and overflow checks, under a 900 s timeout: the unmutated suite took 551 s at the
# debug profile and 262 s at opt-level 1 on Fedora 44 x86_64 (2026-10-20), so under a timeout
# of 180 or 300 s any mutant the suite does not kill early reads as a timeout. cargo-mutants
# 27.1.0 copies the tree without `.git` and without executable bits, so the VCS is copied
# (`build.rs` asks git for the revision) and every test target runs but those MUTANTS_SKIP
# names: a target that runs a script by its mode cannot run in such a copy. Naming the
# targets leaves the doc tests out.
MUTANTS_SKIP  :=
MUTANTS_TESTS = --lib --bins $(foreach t,$(filter-out $(MUTANTS_SKIP),$(basename $(notdir $(wildcard tests/*.rs)))),--test $(t))
MUTANTS = CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1 \
	cargo mutants --copy-vcs true -j 8 --timeout 900

# Do the tests discriminate, or only pass? Scoped to the ELF reader, where a surviving mutant
# is a wrong hardening verdict on an attacker-supplied binary. In no gate: 75 minutes at -j 8
# on Fedora 44 x86_64 (2026-10-20), and the survivor list is a reading task, not a pass/fail.
.PHONY: mutants
mutants:
	$(MUTANTS) --file src/elf.rs -- $(MUTANTS_TESTS)

# The detectors and the derivations, where a surviving mutant is a wrong verdict rather than a
# wrong read of somebody's binary. Apart from `mutants` because it is four hours at -j 8 on
# Fedora 44 x86_64 rather than 75 minutes (2026-10-20), and because it asks whether the tests
# of the rules that turn evidence into a published claim bite. The target is in this file so
# that anyone can re-derive its survivor count.
.PHONY: mutants-detectors
mutants-detectors:
	$(MUTANTS) --file src/probe.rs --file 'src/decode/*.rs' --file src/report.rs -- $(MUTANTS_TESTS)

# Every other source file with a mutant; `src/guide.rs`, `src/lib.rs` and
# `src/elf/reloc_names.rs` have none. Run one file at a time, the first twenty took about eight
# hours at -j 8 on Fedora 44 x86_64 (2026-10-20); this target, one invocation over all of them,
# has not been timed.
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

.PHONY: kani
kani:
	@CARGO='$(CARGO)' scripts/kani-gate.sh

.PHONY: verify
verify: check kani
	@echo 'chard: full local gate passed'

# libFuzzer targets in `fuzz/`, a crate outside chard's workspace (`fuzz/Cargo.toml` says
# why): dev-only, on a nightly toolchain because cargo-fuzz needs one. `fuzz-replay` is a
# step of `check-full` and not of `check`, `verify` or CI: it needs that nightly and
# cargo-fuzz, and a host that runs the gate is held to neither. Each target's
# first directory is its corpus under `fuzz/corpus/`, which libFuzzer grows and git ignores;
# the rest are read-only seeds (`fuzz_seeds`). `fuzz-replay` runs every input once with
# `-runs=0`, a regression pass over what the fuzzer found before. It counts the inputs it
# feeds each target and fails a target it has none for, rather than pass having replayed
# nothing: `detect_evidence`, `report_render`, `parse_macros` and `attestation` read only the
# ignored corpus, so on a fresh clone `make fuzz-seed` comes first.
FUZZ_TOOLCHAIN ?= nightly
FUZZ_TIME      ?= 60
# AddressSanitizer, cargo-fuzz's default, named so the tree says which sanitizer a campaign
# runs under. chard denies `unsafe`, so what it reaches is the `unsafe` in std and the
# dependencies, and an allocation or stack depth a crafted input drives past libFuzzer's
# limits, reported as a finding rather than a kill.
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
# names the host it ran on): reports under each of FUZZ_SEED_PROFILES, since `table` and
# `matrix` join several; every ELF artifact those measurements built, real executables,
# shared objects and objects beside the synthetic fixtures; what `fuzz/seed.rs` derives from
# the reports and the fixtures, the input shapes `chard detect --evidence` sniffs among them;
# and each compiler's own `-dM -E` dumps for `parse_macros`.
FUZZ_SEED_PROFILES ?= bare bare-optimized openssf-tldr
# Every compiler named here is measured under every profile, so the joined set varies on
# the compiler axis `matrix` explains verdicts by; an absent one is skipped.
FUZZ_SEED_CCS ?= cc
# JSON files to take attestations from for `attestation`: reports, a measurement harness's
# session files or a fetcher's own `attestation.json`. They name publishers' URLs and local
# paths, so none is tracked. `fuzz/seed.rs` writes a fixed set and every report's own regardless.
FUZZ_SEED_ATTESTATIONS ?=
# The detector rows `fuzz/seed.rs` writes one record of each (check, arm, expected) from, and
# whose SARIF stderrs seed `structured_diag`: the suite's hand-authored rows, by default.
FUZZ_SEED_ROWS ?= tests/fixtures/synthetic-rows.json
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
	cd fuzz && $(CARGO) run --release --quiet --bin seed -- corpus $(abspath $(FUZZ_SEED_ROWS)) ../tests/fixtures/elf $$(ls corpus/detect_evidence/*-*.json 2>/dev/null | grep -E '/[^/]+-(bare|bare-optimized|openssf-tldr)\.json$$')
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

# Provided, never run for the developer: a build that rewrites the developer's git
# configuration as a side effect does what they did not ask for.
.PHONY: hooks
hooks:
	git config core.hooksPath '$(HOOKS_DIR)'
	@echo 'hooks installed: $(HOOKS) -> $(HOOKS_DIR)'

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
