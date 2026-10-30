#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Run the ratchets tests/ratchets.txt names, one cargo invocation per target, and fail
# unless every target ran exactly the tests it was given (a filter that matched nothing is
# a ratchet that did not run, not a pass). Prints one line per target and the frame: the
# targets, the tests named, the tests run.
#
# Usage: scripts/ratchets.sh [LIST]   (default tests/ratchets.txt; what `make ratchets` runs)
set -uo pipefail
list=${1:-tests/ratchets.txt}
CARGO=${CARGO:-cargo}
[ -r "$list" ] || { echo "ratchets: cannot read $list" >&2; exit 2; }

# target -> its named tests, in the list's order of first appearance.
declare -A tests=() star_count=()
order=()
parsed=0
# `|| [ -n "$target" ]`: a last line without its newline is read too, not dropped.
while IFS=$'\t' read -r target test extra || [ -n "$target" ]; do
    case "$target" in ''|'#'*) continue ;; esac
    # `*` carries the target's test count, so a test dropped from it (deleted, ignored, cfg'd
    # away) fails here rather than leaving the rest to pass; a named test carries none.
    if [ -z "$test" ] || { [ "$test" = "*" ] && ! [[ "$extra" =~ ^[0-9]+$ ]]; } || { [ "$test" != "*" ] && [ -n "$extra" ]; }; then
        echo "ratchets: $list: a line is not 'target<TAB>test' or 'target<TAB>*<TAB>count': $target $test $extra" >&2; exit 2
    fi
    [ "$test" != "*" ] || star_count[$target]=$extra
    parsed=$((parsed + 1))
    [ -n "${tests[$target]+x}" ] || order+=("$target")
    tests[$target]="${tests[$target]:-} $test"
done < "$list"
[ "${#order[@]}" -gt 0 ] || { echo "ratchets: $list names no ratchet" >&2; exit 2; }
# The lines read are the lines the list holds, so none was skipped by the reading itself.
expected=$(grep -cvE '^(#|$)' "$list")
[ "$parsed" -eq "$expected" ] || { echo "ratchets: read $parsed lines of $list, which holds $expected" >&2; exit 2; }

named=0 ran=0 rc=0
for target in "${order[@]}"; do
    read -ra names <<< "${tests[$target]}"
    case "$target" in
        lib) sel=(--lib) ;;
        bin) sel=(--bin chard) ;;
        *) sel=(--test "$target") ;;
    esac
    if [ "${names[*]}" = "*" ]; then filter=(); else filter=(--exact "${names[@]}"); fi
    out=$("$CARGO" test --locked -q "${sel[@]}" -- "${filter[@]}" 2>&1); r=$?
    passed=$(sed -n 's/^test result: [a-zA-Z]*\. \([0-9]*\) passed.*/\1/p' <<< "$out" | head -1)
    failed=$(sed -n 's/^test result: .* \([0-9]*\) failed.*/\1/p' <<< "$out" | head -1)
    passed=${passed:-0}; failed=${failed:-0}
    if [ "${names[*]}" = "*" ]; then want=${star_count[$target]}; else want=${#names[@]}; fi
    ok=$(( passed + failed == want )); named=$((named + want))
    ran=$((ran + passed + failed))
    if [ "$r" -ne 0 ] || [ "$failed" -ne 0 ] || [ "$ok" -ne 1 ]; then
        echo "ratchets: $target: FAILED (exit $r, $passed passed, $failed failed, $want named)"
        echo "$out" | sed -n '/^failures:$/,/^test result/p'
        [ "$r" -ne 0 ] && [ "$failed" -eq 0 ] && echo "$out" | tail -n 20
        rc=1
    else
        echo "ratchets: $target: $passed passed"
    fi
done
echo "ratchets: $parsed lines, ${#order[@]} targets, $named tests named, $ran run"
exit "$rc"
