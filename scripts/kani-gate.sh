#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Run the Kani harnesses and hold what the checker verified to what the tree declares, by
# name. `make kani` fails unless the harnesses the run checked are exactly the functions
# under `#[kani::proof]` in proofs/, every one verified and none failed. The harnesses are
# `#[path]`-included under `cfg(kani)`, so no ordinary build, test or lint compiles them.
# tests/proof_harnesses.rs holds their text: the includes and the README's rows. This holds
# what the checker reached, which the text cannot show: an include inside a module nothing
# compiles, or a harness inside a block comment, runs nothing and would otherwise leave a
# green run over the rest. Names rather than a count, so a harness lost and another gained
# cannot cancel out.
#
# Usage: scripts/kani-gate.sh    (what `make kani` runs; CARGO names the cargo to use)
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$here"
CARGO=${CARGO:-cargo}

# The declared harnesses: the `fn` after each `#[kani::proof]`, read with spaces, tabs and
# carriage returns taken out, other attributes between them allowed. The binding test refuses
# every other spelling, so these are the harnesses.
declared=$(cat proofs/*.rs | tr -d ' \t\r' | awk '
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
"$CARGO" kani 2>&1 | tee "$log"

summary=$(grep -E '^Complete - [0-9]+ successfully verified harness(es)?, [0-9]+ failures?, [0-9]+ total\.?$' "$log" | tail -n 1 || true)
if [ -z "$summary" ]; then
  echo "kani gate: the run printed no 'Complete - N successfully verified harnesses' summary ($log)" >&2
  exit 1
fi
read -r verified failures total <<< "$(printf '%s\n' "$summary" | sed -E 's/^Complete - ([0-9]+) successfully verified harness(es)?, ([0-9]+) failures?, ([0-9]+) total\.?$/\1 \3 \4/')"
# The harnesses the run checked, by their last path component: `Checking harness
# elf::cursor_proofs::slice_is_total...` names `slice_is_total`.
checked=$(grep -E '^Checking harness [A-Za-z0-9_:]+\.\.\.$' "$log" | sed -E 's/^Checking harness //; s/\.\.\.$//' | awk -F'::' '{ print $NF }' | sort -u || true)
if [ "$failures" -ne 0 ] || [ "$verified" -ne "$n_declared" ] || [ "$total" -ne "$n_declared" ] || [ "$checked" != "$declared" ]; then
  {
    echo "kani gate: FAIL: proofs/ declares $n_declared harness(es); the run checked $total, verified $verified, failed $failures"
    echo "kani gate: declared:"; printf '  %s\n' $declared
    echo "kani gate: checked:"; printf '  %s\n' ${checked:-"(none)"}
  } >&2
  exit 1
fi
echo "kani gate: $verified of $n_declared harnesses verified by name, 0 failures"
