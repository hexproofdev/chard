#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The merge gate's phases, each timed, each one's whole output kept in a log, and on the
# terminal only what a reader acts on.
#
# Usage: scripts/merge-gate.sh   (what `make merge-gate` runs)
#
# The phases are the Makefile's own targets, in its order, and the first that fails stops
# the gate: ratchets, fmt-check, clippy-gate (before the suite, so a lint fails in seconds),
# test, msrv-compile, spdx; a document-only diff runs only ratchets, test (reduced) and spdx
# (below). Each runs as `make PHASE` with its output in $MERGE_GATE_LOG_DIR/PHASE.log
# (default target/merge-gate), and the terminal gets one line per phase with its time. The
# suite's ~1400 `ok` lines stay in test.log; the terminal gets one line per test binary (its
# counts and time, slowest first), any failure, the lines the suite says no arm ran for (`arm
# not exercised`), and the ledger section that scripts/test-ledger.sh printed, whole and
# unchanged: the CI workflow and the merge record read that section from this output. A
# failing phase also gets the end of its log.
#
# A suite run already made on the same tree can stand for the test phase: with
# MERGE_GATE_REUSE_TEST=DIR naming an earlier gate's log directory, the suite is not run
# again when DIR recorded a clean tree equal to this one, a passing run with its ledger and
# no skip allowed, on the same host under the same toolchain and environment (`reusable`
# below); the reuse is printed and written to LOG_DIR/reuse with both trees, and anything
# else runs the suite. A merge whose tree is the rebased branch's it tested then holds the merge lock for
# the other phases only. Every run of the test phase records what it would need to be
# reused: test.rc, environment, and tested-tree when the tree was clean before and after.
#
# The reuse reads DIR's record and then copies its log, so DIR must be quiescent: no other
# gate writing it meanwhile (the merge lock is what keeps a second gate out).
#
# A document-only diff runs a reduced phase set: a document changes no code, so the
# phases that judge code (fmt, clippy, the MSRV check) have nothing to judge, and the tests it
# can break are the ones that read it by name and the ratchets, the text rules over the whole
# tracked tree. tests/merge_gate.rs holds that every test target that lists the tree
# through git is a ratchet run whole, or is excepted there with its reason; one that walks
# directories instead is outside that hold. The ratchets compile their targets, so a diff
# whose documents no test reads still builds the crate. With MERGE_GATE_BASE naming the commit
# the gated tree is compared with (the queue names the merge's first parent; a session names
# the main it rebased onto), a tree clean as `clean_tree` reads it whose every changed path is
# a regular file listed in `doc_readers` runs the ratchets, spdx and `cargo test` over exactly
# the targets that read the changed documents (no test phase where none does), and the run fails
# unless it ran one binary per target and skipped no test. Anything else runs the whole gate,
# the reason printed: no base named (the CI floor from main names none), a base that does not
# resolve or is not an ancestor of HEAD, a tree with changes git does not hold, a test skip
# allowed (CHARD_ALLOW_TEST_SKIP), an empty diff, a path that changes mode or type (a symlink,
# a submodule), or one path that is not a listed document (a fixture, a source file, a new
# document no one listed). There is no flag that forces the reduced set: the base is the one
# input, and it is held to HEAD's history, not to having been gated itself: a session that
# names a base its own earlier commits sit on reduces over the last ones alone, as it would
# by naming any commit; the queue names main, which its own gate holds. The decision is the first line the gate prints and
# is written to LOG_DIR/phase-set; a reduced test run records no tested tree, so no later
# gate reuses it as the whole suite, and runs no test ledger, which only the whole suite
# keeps.
#
# The gate's verdict is the phases' exit statuses, as `make merge-gate` with the targets
# as prerequisites gave it; this script decides nothing from what it prints.
set -uo pipefail

MAKE=${MAKE:-make}
CARGO=${CARGO:-cargo}
log_dir=${MERGE_GATE_LOG_DIR:-target/merge-gate}
mkdir -p "$log_dir" || { echo "merge-gate: cannot make $log_dir" >&2; exit 2; }
phases=(ratchets fmt-check clippy-gate test msrv-compile spdx)
full_phases=("${phases[@]}")

# The tracked documents and the test targets that read each: `lib` (the crate's unit tests),
# `bin` (src/main.rs's) or a file under tests/ without `.rs`. A path with no arm here is not a
# document to this gate, so a change to it runs the whole gate; a document that joins the
# tree joins this list by an edit here, and tests/merge_gate.rs fails until it does (every
# tracked `.md` outside tests/ has an arm) and until each arm names every target whose source
# names the document as a string literal ending in its path (`"README.md"`,
# `"../DESIGN.md"`, `"/SUPPORT.md"`): a document a test reaches by a name it builds
# piecewise is outside that check. An empty arm is a document that test found no target
# naming. Documents under tests/ are suite input, never listed. The map retires with the
# reduced phase set: when no document is read by a test, or the gate goes back to one phase
# set for every diff.
# doc-map:begin
doc_readers() {
    case "$1" in
        README.md) echo "bin detector_replay proof_harnesses support_matrix" ;;
        QUICKSTART.md) echo "detector_replay" ;;
        CHANGELOG.md) echo "detector_replay" ;;
        SECURITY.md) echo "detector_replay" ;;
        THREAT_MODEL.md) echo "detector_replay register" ;;
        SUPPORT.md) echo "support_matrix" ;;
        DESIGN.md) echo "bin detector_replay support_matrix" ;;
        CLAUDE.md) echo "" ;;
        CODE_OF_CONDUCT.md) echo "" ;;
        CONTRIBUTING.md) echo "" ;;
        fuzz/README.md) echo "" ;;
        proofs/README.md) echo "proof_harnesses" ;;
        *) return 1 ;;
    esac
}
# doc-map:end

# Whether this run is a document-only one: sets doc_targets (the test targets to run, sorted,
# space-separated) and doc_paths, and returns 0; else sets full_reason and returns 1. Called
# after the functions below, since it reads the tree as `clean_tree` does.
classify() {
    local base=${MERGE_GATE_BASE:-} meta path readers old new t listed=() targets=()
    local raw="$log_dir/classify.raw"
    doc_paths=""
    if [ -z "$base" ]; then full_reason="no MERGE_GATE_BASE named"; return 1; fi
    if ! git rev-parse --verify --quiet "$base^{commit}" > /dev/null 2>&1; then
        full_reason="MERGE_GATE_BASE $base does not name a commit"; return 1
    fi
    if ! git merge-base --is-ancestor "$base" HEAD 2>/dev/null; then
        full_reason="MERGE_GATE_BASE $base is not an ancestor of HEAD"; return 1
    fi
    # Set at all, even empty, as tests/common's `refuse` reads it.
    if [ -n "${CHARD_ALLOW_TEST_SKIP+x}" ]; then
        full_reason="CHARD_ALLOW_TEST_SKIP is set"; return 1
    fi
    if [ -z "$(clean_tree)" ]; then full_reason="the tree has changes git does not hold"; return 1; fi
    if ! git diff --raw -z --no-renames --no-abbrev "$base" HEAD > "$raw" 2>/dev/null; then
        full_reason="git cannot list the diff from $base"; return 1
    fi
    if ! [ -s "$raw" ]; then full_reason="the diff from $base is empty"; return 1; fi
    # `--raw -z`: ":OLDMODE NEWMODE OLDSHA NEWSHA STATUS" and the path, each NUL-terminated,
    # so no path is split or unquoted.
    while IFS= read -r -d '' meta && IFS= read -r -d '' path; do
        old=${meta:1:6}
        new=${meta:8:6}
        case "$old $new" in
            "100644 100644" | "000000 100644" | "100644 000000") ;;
            *) full_reason="$path changes mode or type ($old to $new)"; return 1 ;;
        esac
        if ! readers=$(doc_readers "$path"); then
            full_reason="$path is not a listed document"; return 1
        fi
        listed+=("$path")
        for t in $readers; do targets+=("$t"); done
    done < "$raw"
    # Every record read: two NUL-terminated fields each, and at least one.
    local fields
    fields=$(tr -cd '\0' < "$raw" | wc -c)
    if [ "${#listed[@]}" -eq 0 ] || [ "$fields" -ne $(( ${#listed[@]} * 2 )) ]; then
        full_reason="the diff from $base read as ${#listed[@]} path(s) in $fields field(s)"; return 1
    fi
    doc_paths="${listed[*]}"
    doc_targets=$(printf '%s\n' ${targets[@]+"${targets[@]}"} | sed '/^$/d' | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/ $//')
}

# The reduced test phase: `cargo test` over the targets named, written to LOG.
reduced_test() {
    local args=() t
    for t in $doc_targets; do
        case "$t" in
            lib) args+=(--lib) ;;
            bin) args+=(--bin chard) ;;
            *) args+=(--test "$t") ;;
        esac
    done
    echo "$CARGO test --locked --no-fail-fast ${args[*]}"
    "$CARGO" test --locked --no-fail-fast "${args[@]}"
}


# The suite's summary from test.log: per binary, cargo's `Running NAME (PATH)` line and the
# `test result:` line that follows it.
test_summary() {
    awk '
        /^ *Running / { name = ($2 == "unittests") ? $2 " " $3 : $2; next }
        /^ *Doc-tests / { name = "doctests " $2; next }
        /^test result:/ {
            match($0, /[0-9]+ passed/); p = substr($0, RSTART, RLENGTH)
            match($0, /[0-9]+ failed/); f = substr($0, RSTART, RLENGTH)
            match($0, /[0-9]+ ignored/); i = substr($0, RSTART, RLENGTH)
            match($0, /finished in [0-9.]+s/); t = substr($0, RSTART + 12, RLENGTH - 13)
            printf "%9.2fs  %-12s %-10s %-11s %s\n", t, p, f, i, name
        }
    ' "$1" | sort -rn | sed 's/^/  /'
    awk '/^test result:/ {
            n++; match($0, /[0-9]+ passed/); p += substr($0, RSTART, RLENGTH) + 0
            match($0, /[0-9]+ failed/); f += substr($0, RSTART, RLENGTH) + 0
            match($0, /finished in [0-9.]+s/); t += substr($0, RSTART + 12, RLENGTH - 13)
        }
        END { printf "  %d binaries, %d passed, %d failed, %.0f s of test time (run one after another)\n", n, p, f, t }' "$1"
}

# The tree a test run was given, and whether it holds the whole of what cargo compiled: a
# tracked change, an untracked file (cargo builds any tests/*.rs it finds) or an ignored one
# where cargo reads sources means the commit's tree does not describe what ran. Empty when it
# does not, and when git cannot say.
clean_tree() {
    local status
    status=$(git status --porcelain --ignored -- src tests build build.rs probes Cargo.toml Cargo.lock .cargo rust-toolchain rust-toolchain.toml 2>/dev/null) || return 0
    [ -z "$status" ] || return 0
    status=$(git status --porcelain --untracked-files=all 2>/dev/null) || return 0
    [ -z "$status" ] || return 0
    git rev-parse 'HEAD^{tree}' 2>/dev/null
}

# What a suite run depended on beyond the tree: the host and kernel, the Rust toolchain with
# its host triple, the C toolchain, the core handler, and the environment cargo, rustc and the
# suite read (a skip allowance among them).
run_environment() {
    echo "host $(uname -n) $(uname -srm)"
    rustc -vV 2>&1
    # The C toolchain and the host's core handler change what a probe reads.
    for t in cc gcc clang ld; do echo "$t: $("$t" --version 2>/dev/null | head -n 1)"; done
    echo "core_pattern: $(cat /proc/sys/kernel/core_pattern 2>/dev/null)"
    # Values kept as they are, except where a name says secret (a registry token is a CARGO_
    # variable): those are compared by digest, so no record kept beside the logs holds them.
    env | LC_ALL=C sort | grep -E '^(RUST|CARGO|CHARD_|CC=|CXX=|CFLAGS=|CXXFLAGS=|LDFLAGS=|PATH=)' \
        | while IFS='=' read -r name value; do
            case "$name" in
                *TOKEN*|*SECRET*|*PASSWORD*|*PASS|*KEY*|*CREDENTIAL*|*AUTH*)
                    echo "$name=sha256:$(printf '%s' "$value" | sha256sum | cut -c1-16)" ;;
                *) echo "$name=$value" ;;
            esac
        done
}

# Whether the suite run recorded in DIR stands for this one: the same clean tree, before and
# after the run, a run that passed with its ledger and allowed no skip, on the same host
# under the same toolchain and environment. Prints why not, and fails, if not. Only the test
# phase is ever reused; every other phase runs. The CI host's workflow never sets
# MERGE_GATE_REUSE_TEST: its floor is its own run.
reusable() {
    local dir=$1 now
    [ -r "$dir/test.log" ] && [ -r "$dir/test.rc" ] || { echo "no recorded run in $dir"; return 1; }
    [ -r "$dir/tested-tree" ] || { echo "$dir recorded no clean tree"; return 1; }
    [ "$(cat "$dir/test.rc")" = 0 ] || { echo "the recorded run failed"; return 1; }
    # A day at most: a run older than that stands for a host that may have moved since.
    [ -n "$(find "$dir/test.rc" -mmin -1440 2>/dev/null)" ] || { echo "the recorded run is more than a day old"; return 1; }
    now=$(clean_tree)
    [ -n "$now" ] || { echo "this tree has changes git does not hold"; return 1; }
    [ "$now" = "$(cat "$dir/tested-tree")" ] || { echo "tree $now is not the tested $(cat "$dir/tested-tree")"; return 1; }
    local differs
    differs=$(diff <(cat "$dir/environment" 2>/dev/null) <(run_environment) | grep -E '^[<>]' | head -n 2 | tr '\n' ' ')
    [ -z "$differs" ] || { echo "the host, toolchain or environment differs from the recorded run's: $differs"; return 1; }
    ! grep -q '^CHARD_ALLOW_TEST_SKIP=' "$dir/environment" || { echo "the recorded run allowed skips"; return 1; }
    grep -q '^test-ledger:' "$dir/test.log" || { echo "the recorded run has no ledger line"; return 1; }
    ! grep -q 'skipped its accounting' "$dir/test.log" || { echo "the recorded run skipped its ledger accounting"; return 1; }
    ! grep -q '^test result: FAILED' "$dir/test.log" || { echo "the recorded run has a failed binary"; return 1; }
}

# The first diagnostics of a failed phase and the end of its log: rustc and clippy print the
# error that names the fix early and a summary last.
diagnose() {
    local first
    # Not indented, so a reader of the ledger section above (the CI workflow's gaps) stops here.
    echo "== diagnostics, from $1"
    if [ "$(wc -l < "$1")" -le 60 ]; then cat "$1"; return; fi
    # The first error, else the first warning: warnings often come first and say less.
    first=$(grep -n -m1 -E '^error(\[|:)' "$1" | cut -d: -f1)
    [ -n "$first" ] || first=$(grep -n -m1 -E '^warning(\[|:)' "$1" | cut -d: -f1)
    if [ -n "$first" ]; then
        echo "  -- from the first diagnostic (line $first of $1):"
        sed -n "${first},$((first + 39))p" "$1"
        echo "  -- the end of the log:"
        tail -n 15 "$1"
    else
        tail -n 60 "$1"
    fi
}

doc_targets=""
doc_mode=""
if classify; then
    doc_mode=1
    phases=(ratchets spdx)
    [ -z "$doc_targets" ] || phases=(ratchets test spdx)
    echo "== phase set: document-only, against MERGE_GATE_BASE ${MERGE_GATE_BASE}: $doc_paths; runs ${phases[*]}${doc_targets:+ (test: $doc_targets)}; skipped: the other phases and the rest of the suite"
    echo "document-only base=${MERGE_GATE_BASE} paths=$doc_paths tests=${doc_targets:-none}" > "$log_dir/phase-set"
else
    echo "== phase set: full ($full_reason)"
    echo "full reason=$full_reason" > "$log_dir/phase-set"
fi

# A run's records start empty: no log, exit status or tested tree of an earlier run stands
# beside this one's, even where this one stops early or is killed.
reuse_dir=${MERGE_GATE_REUSE_TEST:-}
if [ -n "$reuse_dir" ] && [ "$reuse_dir" -ef "$log_dir" ]; then
    echo "merge-gate: MERGE_GATE_REUSE_TEST is the log directory itself; name the earlier run's" >&2
    exit 2
fi
for phase in "${full_phases[@]}"; do rm -f "$log_dir/$phase.log"; done
rm -f "$log_dir/test.rc" "$log_dir/tested-tree" "$log_dir/environment" "$log_dir/reuse"

total_start=$(date +%s)
times=()
for phase in "${phases[@]}"; do
    log="$log_dir/$phase.log"
    start=$(date +%s)
    rc=0
    reused=""
    echo "== $phase: started $(date +%H:%M:%S)"
    if [ "$phase" = test ] && [ -n "$reuse_dir" ] && [ -z "$doc_mode" ]; then
        if why=$(reusable "$reuse_dir"); then
            cp "$reuse_dir/test.log" "$log" || { echo "merge-gate: cannot copy $reuse_dir/test.log" >&2; exit 2; }
            reused=$reuse_dir
            { echo "reused $reuse_dir"; echo "tested-tree $(cat "$reuse_dir/tested-tree")"; echo "this-tree $(clean_tree)"; } > "$log_dir/reuse"
        else
            echo "== test: not reused ($why); the suite runs"
            echo "not reused: $why" > "$log_dir/reuse"
        fi
    fi
    if [ -z "$reused" ]; then
        tree_before=""
        [ "$phase" = test ] && tree_before=$(clean_tree)
        if [ "$phase" = test ] && [ -n "$doc_mode" ]; then
            reduced_test > "$log" 2>&1 || rc=$?
            # One binary per target, and no test skipped: a reduced run that ran less reads
            # as a failure, not as a pass over nothing.
            ran=$(grep -c '^test result:' "$log")
            want=$(wc -w <<< "$doc_targets")
            if [ "$rc" -eq 0 ] && ! [ "$ran" -eq "$want" ] 2>/dev/null; then
                echo "merge-gate: the reduced test run named $want target(s) and ran $ran" >> "$log"
                rc=1
            fi
            if [ "$rc" -eq 0 ] && grep -q 'SKIPPED TEST' "$log"; then
                echo "merge-gate: the reduced test run skipped a test" >> "$log"
                rc=1
            fi
        else
            "$MAKE" --no-print-directory "$phase" > "$log" 2>&1 || rc=$?
        fi
        if [ "$phase" = test ] && [ -n "$doc_mode" ]; then
            # A reduced run is part of the suite: its status is kept, and nothing a later
            # gate's reuse reads is written, so it never stands for the whole suite.
            echo "$rc" > "$log_dir/test.rc"
        elif [ "$phase" = test ]; then
            # What a later gate needs to name this run: its status, its environment,
            # and its tree only where the tree was clean and the same before and after.
            echo "$rc" > "$log_dir/test.rc"
            run_environment > "$log_dir/environment"
            tree_after=$(clean_tree)
            if [ -n "$tree_before" ] && [ "$tree_before" = "$tree_after" ]; then
                echo "$tree_after" > "$log_dir/tested-tree"
            fi
        fi
    fi
    secs=$(( $(date +%s) - start ))
    times+=("$phase ${secs}s")
    if [ -n "$reused" ]; then
        echo "== test: REUSED, not run: tree $(cat "$reused/tested-tree") passed it ($reused; record in $log_dir/reuse)"
    elif [ "$rc" -eq 0 ]; then
        echo "== $phase: ok in ${secs}s"
    else
        echo "== $phase: FAILED (exit $rc) in ${secs}s, whole output in $log"
    fi
    if [ "$phase" = test ]; then
        [ -z "$reused" ] || echo "  (the counts and the ledger below are the reused run's, from $reused)"
        test_summary "$log"
        # A failing test's own section (cargo prints it under `failures:`), whole.
        awk '/^failures:$/ { f = 1 } f { print } /^test result:/ { f = 0 }' "$log"
        grep -E '^error: (test failed|[0-9]+ targets? failed)' "$log"
        grep -F 'arm not exercised' "$log" | sort | uniq -c | sed 's/^ */  /'
        # The ledger section, as test-ledger.sh printed it, to the end of the log.
        awk '/^== what this test run did not exercise/ { f = 1 } f' "$log"
        # A failure that is not a failing test (a compile error, a ledger refusal, a binary
        # killed by a signal) has no `failures:` section: its diagnostics, then.
        if [ "$rc" -ne 0 ] && ! grep -q '^failures:$' "$log"; then
            diagnose "$log"
        elif [ "$rc" -ne 0 ]; then
            # Failing tests, and perhaps also a binary that did not build or died on a signal.
            grep -E '^error(\[|: could not compile)|Caused by' "$log" | sort -u
        fi
    elif [ "$rc" -ne 0 ]; then
        diagnose "$log"
    fi
    if [ "$rc" -ne 0 ]; then
        echo "merge-gate: FAILED at $phase after $(( $(date +%s) - total_start ))s (${times[*]})"
        exit "$rc"
    fi
done
echo "merge-gate: ok in $(( $(date +%s) - total_start ))s (${times[*]})${doc_mode:+; document-only phase set}"
