#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Run the Kani harnesses and hold what the checker verified to what the tree declares. `make
# kani` fails unless the harnesses the run checked are, by name, exactly the functions under
# `#[kani::proof]` in proofs/, every one verified and none failed; the run reports as many
# cover properties as proofs/ writes `kani::cover!` calls, every one satisfied, with a cover
# line for every harness; every source location the run checked lies in src/elf.rs, in a
# harness file, or in the toolchain's or the verifier's own library; and no check in
# src/elf.rs or a harness file is unreachable, but for two assertions of
# `refusals_are_classified` this script lists, dead on a 64-bit host.
#
# The harnesses are `#[path]`-included under `cfg(kani)`, so no ordinary build compiles them.
# This holds what the checker reached: an include inside a module nothing compiles, or a
# harness inside a block comment, runs nothing and would leave a green run over the rest.
# Names, not a count, so a harness lost and another gained cannot cancel out. The verifier
# reports an unsatisfied cover without failing the harness.
#
# The checker runs with CARGO_ENCODED_RUSTFLAGS, CARGO_BUILD_RUSTFLAGS and RUSTFLAGS unset, not
# with RUSTFLAGS empty as `make build` sets it: cargo-kani hands an empty RUSTFLAGS to rustc as
# an empty input file name and fails.
#
# Usage: scripts/kani-gate.sh    (what `make kani` runs; CARGO names the cargo to use)
set -euo pipefail
# One collation for every sort and comparison below, whatever the caller's locale.
export LC_ALL=C
here=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$here"
CARGO=${CARGO:-cargo}

# The harness files' text, each file ended by a newline (`awk 1`), so the last line of one is
# never joined to the first of the next.
harness_text() {
  awk 1 proofs/*.rs
}

# The declared harnesses: the `fn` after each `#[kani::proof]`, whitespace taken out, other
# attributes between them allowed. The binding test refuses every other spelling.
declared=$(harness_text | tr -d ' \t\r' | awk '
  /^#\[kani::proof\]$/ { pending = 1; next }
  pending && /^#\[/ { next }
  pending && /^fn[A-Za-z0-9_]+\(/ { sub(/^fn/, ""); sub(/\(.*/, ""); print; pending = 0; next }
  { pending = 0 }
' | sort -u)
if [ -z "$declared" ]; then
  echo "kani gate: proofs/ declares no #[kani::proof], so there is nothing to verify" >&2
  exit 1
fi
n_declared=$(printf '%s\n' "$declared" | wc -l | tr -d ' ')

mkdir -p target
log=target/kani.log
# `pipefail` carries a failed run through the tee.
if ! env -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u RUSTFLAGS "$CARGO" kani 2>&1 | tee "$log"; then
  echo "kani gate: FAIL: \`$CARGO kani\` exited non-zero, so a harness failed or did not run ($log)" >&2
  exit 1
fi

summary=$(grep -E '^Complete - [0-9]+ successfully verified harness(es)?, [0-9]+ failures?, [0-9]+ total\.?$' "$log" | tail -n 1 || true)
if [ -z "$summary" ]; then
  echo "kani gate: the run printed no 'Complete - N successfully verified harnesses' summary ($log)" >&2
  exit 1
fi
read -r verified failures total <<<"$(printf '%s\n' "$summary" | sed -E 's/^Complete - ([0-9]+) successfully verified harness(es)?, ([0-9]+) failures?, ([0-9]+) total\.?$/\1 \3 \4/')"
# The harnesses the run checked, by the last component of each path.
checked=$(grep -E '^Checking harness [A-Za-z0-9_:]+\.\.\.$' "$log" | sed -E 's/^Checking harness //; s/\.\.\.$//' | awk -F'::' '{ print $NF }' | sort -u || true)
if [ "$failures" -ne 0 ] || [ "$verified" -ne "$n_declared" ] || [ "$total" -ne "$n_declared" ] || [ "$checked" != "$declared" ]; then
  {
    echo "kani gate: FAIL: proofs/ declares $n_declared harness(es); the run checked $total, verified $verified, failed $failures"
    echo "kani gate: declared:"
    # Split on purpose: a harness name is a Rust identifier, so it neither globs nor breaks.
    # shellcheck disable=SC2086
    printf '  %s\n' $declared
    echo "kani gate: checked:"
    # shellcheck disable=SC2086
    printf '  %s\n' ${checked:-"(none)"}
  } >&2
  exit 1
fi

# A cover line satisfying fewer than it counts, or one the pattern does not read, fails; and
# the counts must add up to the `kani::cover!` calls proofs/ writes outside `//` comments, so a
# run that reports fewer covers, or none, fails rather than reading as every cover satisfied.
# `grep -o` finding none exits 1, a count of 0; any other status stops the gate.
n_covers=$({ harness_text | sed 's|//.*$||' | tr -d ' \t\r\n' | grep -o 'kani::cover!(' || [ $? -eq 1 ]; } | wc -l | tr -d ' ')
covers=$(grep -E 'cover propert' "$log" || true)
unsatisfied=$(printf '%s\n' "$covers" | awk 'NF && !/^ \*\* ([0-9]+) of ([0-9]+) cover propert(y|ies) satisfied$/ { print; next }
  NF { split($0, f, " "); if (f[2] != f[4]) print }')
reported=$(printf '%s\n' "$covers" | awk 'NF { split($0, f, " "); n += f[4] } END { print n + 0 }')
cover_lines=$(printf '%s\n' "$covers" | awk 'NF { n++ } END { print n + 0 }')
if [ -n "$unsatisfied" ]; then
  {
    echo "kani gate: FAIL: a cover property the run reports is not satisfied, or its line is not one this gate reads, so a branch a harness says it reaches is not shown reached:"
    printf '  %s\n' "$unsatisfied"
  } >&2
  exit 1
fi
if [ "$reported" -ne "$n_covers" ]; then
  echo "kani gate: FAIL: proofs/ writes $n_covers kani::cover! call(s) outside // comments and the run reports $reported cover propert(ies): a cover the run did not reach is missing from its count, and a cover in a helper two harnesses call is counted once per harness, so the two must be made to agree" >&2
  exit 1
fi
# Every harness ends on a cover, so every
# harness prints one cover line: fewer lines than harnesses is a harness the run reports no
# cover for, which a cover gained elsewhere would hide from the total above.
if [ "$cover_lines" -ne "$n_declared" ]; then
  echo "kani gate: FAIL: the run prints $cover_lines cover line(s) for $n_declared harness(es); every harness ends on a cover, so a harness without its line is one no cover shows reached" >&2
  exit 1
fi

# A checked location outside the files the header names is code the harnesses reach beyond
# the reader, and fails, as does a run that names none in src/elf.rs. rustc names a
# `#[path]` include `src/../proofs/<file>.rs`, and `src/lib.rs:0:0` is one the compiler
# synthesises for a generated check.
locations=$(grep -oE 'Location: [^ ]+' "$log" | sed 's/^Location: //' | sort -u || true)
# A library path is admitted only outside the crate (`../` or absolute), so a file of the crate
# under a directory named like a library is still the crate's.
outside=$(printf '%s\n' "$locations" | awk 'NF {
  if ($0 == "src/lib.rs:0:0") next
  path = $0; sub(/:[0-9]+:[0-9]+$/, "", path)
  if (path == "src/elf.rs") next
  if (path ~ /^src\/\.\.\/proofs\/[A-Za-z0-9_]+\.rs$/) next
  if (path !~ /^(\.\.\/|\/)/) { print $0; next }
  if (path ~ /\/lib\/rustlib\/src\/rust\/library\//) next
  if (path ~ /\/kani\/library\/(kani|kani_core|std)\//) next
  print $0 }')
if [ -n "$outside" ]; then
  {
    echo "kani gate: FAIL: the run checked code outside src/elf.rs, the harness files and the toolchain's and verifier's libraries:"
    printf '%s\n' "$outside" | sed 's/^/  /'
  } >&2
  exit 1
fi
if ! printf '%s\n' "$locations" | grep -q '^src/elf\.rs:'; then
  echo "kani gate: FAIL: the run names no checked location in src/elf.rs, so this gate cannot read where it reached ($log)" >&2
  exit 1
fi

# A check the verifier reports `UNREACHABLE` holds vacuously, and a `kani::assume` that excludes
# every input makes every assertion after it so. One in src/elf.rs or a harness file fails, but
# for the two assertions of `refusals_are_classified` listed here by description, dead on a
# 64-bit host where `usize::try_from(u64)` cannot fail, and admitted in that harness alone.
#
# The reader is tied to two counts the run prints, so a change in the verifier's layout cannot
# leave it reading nothing: it parses at least one check block, every `- Location:` line belongs
# to one, and its `UNREACHABLE` blocks, covers aside, are as many as the summaries'
# `(N unreachable)` add up to.
dead_by_design='"assertion failed: o == off && usize::try_from(off).is_err()"|"assertion failed: l == len && usize::try_from(len).is_err()"'
dead_in='elf::cursor_proofs::refusals_are_classified'
vacuity=$(awk -v allowed="$dead_by_design" -v dead_in="$dead_in" '
  /^Check [0-9]+: / { name = $0; status = ""; description = ""; open = 1; next }
  /^[[:space:]]+- Status: / { status = $0; sub(/^[[:space:]]+- Status: /, "", status); next }
  /^[[:space:]]+- Description: / { description = $0; sub(/^[[:space:]]+- Description: /, "", description); next }
  /^[[:space:]]+- Location: / {
    if (!open) next
    open = 0; blocks++
    location = $0; sub(/^[[:space:]]+- Location: /, "", location)
    path = location; sub(/ .*/, "", path)
    function_name = location; sub(/^.* in function /, "", function_name)
    # A cover (`<harness>.cover.<n>`) is held by the cover check above, and the harness
    # summaries do not count an unreachable one.
    if (status == "UNREACHABLE" && name !~ /\.cover\.[0-9]+$/) {
      unreachable++
      if (path ~ /^src\/elf\.rs:/ || path ~ /^src\/\.\.\/proofs\//) {
        n = split(allowed, keep, "|"); kept = 0
        for (k = 1; k <= n; k++) if (description == keep[k] && function_name == dead_in) kept = k
        if (kept) { admitted++; if (!(kept in listed)) { listed[kept] = 1; distinct++ } }
        else print "vacuous " name " " description " at " location
      }
    }
  }
  /^ \*\* [0-9]+ of [0-9]+ failed \([0-9]+ unreachable\)$/ {
    n = $0; sub(/^.*\(/, "", n); sub(/ unreachable\)$/, "", n); summarised += n
  }
  END { print "counts " blocks + 0 " " unreachable + 0 " " summarised + 0 " " admitted + 0 " " distinct + 0 }' "$log")
read -r blocks unreachable summarised admitted distinct <<<"$(printf '%s\n' "$vacuity" | sed -n 's/^counts //p')"
located=$(grep -cE '^[[:space:]]+- Location: ' "$log" || true)
# Each count must be a number: a comparison that errors inside an `if` reads as false and
# passes.
for count in "$blocks" "$unreachable" "$summarised" "$admitted" "$distinct" "$located"; do
  case "$count" in
    '' | *[!0-9]*)
      echo "kani gate: FAIL: the reader of the run's checks printed no counts ($log)" >&2
      exit 1
      ;;
    *) ;;
  esac
done
if [ "$blocks" -eq 0 ] || [ "$blocks" -ne "$located" ] || [ "$unreachable" -ne "$summarised" ]; then
  echo "kani gate: FAIL: the run prints $located checked location(s) and $summarised unreachable check(s) in its summaries; this gate parsed $blocks check block(s) and $unreachable unreachable one(s), so it cannot read the run's checks ($log)" >&2
  exit 1
fi
vacuous=$(printf '%s\n' "$vacuity" | sed -n 's/^vacuous //p')
if [ -n "$vacuous" ]; then
  {
    echo "kani gate: FAIL: a check in src/elf.rs or a harness file is unreachable, so it holds vacuously:"
    printf '%s\n' "$vacuous" | sed 's/^/  /'
  } >&2
  exit 1
fi
# On a 64-bit host each listed assertion is unreachable exactly once. Any other count is a list
# out of step with the harness, or a host on which those arms are live.
if [ "$admitted" -ne 2 ] || [ "$distinct" -ne 2 ]; then
  echo "kani gate: FAIL: $admitted unreachable check(s) in $dead_in carry $distinct of the two descriptions this script lists, which names two, each unreachable once on a 64-bit host" >&2
  exit 1
fi

echo "kani gate: $verified of $n_declared harnesses verified by name, 0 failures; $reported of $n_covers cover properties satisfied; every checked location in src/elf.rs, the harnesses or the libraries; no check of theirs unreachable but the 2 listed as dead by design"
