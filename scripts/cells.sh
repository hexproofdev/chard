#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The six cells: the same measurements taken by a base binary and a head binary, compared,
# and the one frame line an item's record quotes for them.
#
#   scripts/cells.sh [--cc "gcc clang"] [--profiles "bare bare-optimized openssf-tldr"] \
#                    BASE_BINARY HEAD_BINARY DIR
#   scripts/cells.sh [--cc ...] [--profiles ...] --compare DIR
#
# The first form measures every compiler and profile with both binaries into DIR (reports
# `base-<cc>-<profile>.json` and `head-<cc>-<profile>.json`, each beside its workdir, log
# and `.exit`), then compares; `--compare` compares what DIR already holds. Every report is
# taken with `--normalize`, so two measurements of one configuration differ only where a
# result, an input or the run's identity does.
#
# A cell is fed when both its reports parse, each carries at least one observation, every
# observation names its check once and every composite its id once, each report's profile
# is the cell's (and its toolchain kind, where the compiler is named gcc... or clang...),
# neither measurement recorded a nonzero exit, and the two name different revisions. Any
# other cell is NOT FED, with the reason, and counted as such: never skipped and never
# clean. An exit is known only where the measuring form wrote `<cell>.exit`; reports
# compared from elsewhere carry none, and the frame says in how many cells both were
# recorded.
#
# A fed cell is compared on: the verdict and level of every check, and the verdict of every
# composite (a difference is a move; a check or composite on one side only is one too,
# against `absent`); the diagnostics, as whole objects; and every other top-level field but
# the run's identity, which names the binary and differs by construction: `id`,
# `harness_revision` and `inputs_sha256`, under `run` and under `digest.run`. Everything
# else in `run` (the corpus and decoder digests, the deadlines) is compared, so an item that
# changes a probe moves the frame even where no verdict moves.
#
# This is a comparison, not a gate: two binaries that degrade alike (every check withheld
# on a host without the compiler) compare clean. `make sweep` and `scripts/sweep-gate.sh`
# judge one binary's report on its own.
#
# Exit status:
#   0  every cell fed, no move, nothing differs but the run's identity
#   1  a move, a cell not fed, or no cell named
#   3  every cell fed and no move, but another field differs (each is named): an item that
#      changes what a report says without moving a verdict
#   2  usage; jq missing; DIR missing (--compare) or not creatable; a binary not executable
#
# One comparer serves every caller, so the frames the records quote come from the same code
# and no caller compares composites on a field they do not carry.

set -u
set -f

usage() {
  cat >&2 <<'USAGE'
usage: scripts/cells.sh [--cc "gcc clang"] [--profiles "bare bare-optimized openssf-tldr"] BASE_BINARY HEAD_BINARY DIR
       scripts/cells.sh [--cc ...] [--profiles ...] --compare DIR
USAGE
  exit 2
}

ccs="gcc clang"
profiles="bare bare-optimized openssf-tldr"
compare_only=0
while [ $# -gt 0 ]; do
  case $1 in
    --cc) [ $# -ge 2 ] || usage; ccs=$2; shift 2 ;;
    --profiles) [ $# -ge 2 ] || usage; profiles=$2; shift 2 ;;
    --compare) compare_only=1; shift ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done

command -v jq >/dev/null 2>&1 || { echo "cells: jq is required to compare reports" >&2; exit 2; }

if [ "$compare_only" = 1 ]; then
  [ $# -eq 1 ] || usage
  dir=$1
  [ -d "$dir" ] || { echo "cells: no directory $dir" >&2; exit 2; }
else
  [ $# -eq 3 ] || usage
  base=$1 head=$2 dir=$3
  for bin in "$base" "$head"; do
    [ -x "$bin" ] || { echo "cells: $bin is not an executable" >&2; exit 2; }
  done
  mkdir -p "$dir" || exit 2
  for which in base head; do
    bin=$base
    [ "$which" = head ] && bin=$head
    for cc in $ccs; do
      for profile in $profiles; do
        cell=$which-$cc-$profile
        rm -rf "${dir:?}/w-$cell" "$dir/$cell.json" "$dir/$cell.exit"
        "$bin" measure --cc "$cc" --profile "$profile" --normalize \
          --workdir "$dir/w-$cell" -o "$dir/$cell.json" > "$dir/$cell.log" 2>&1
        rc=$?
        echo "$rc" > "$dir/$cell.exit"
        echo "measured $which $cc $profile: exit $rc"
      done
    done
  done
fi

# One cell, as one tab-separated line: "fed" and the counts, or "unfed" and the reason.
compare_cell() { # base head profile kind
  jq -nr --slurpfile b "$1" --slurpfile h "$2" --arg profile "$3" --arg kind "$4" '
    def fault:
      if (.observations | type) != "array" or (.observations | length) == 0 then "no observations"
      elif ([.observations[] | .check | type == "string" and . != ""] | all | not) then "an observation names no check"
      elif ([.observations[].check] | length) != ([.observations[].check] | unique | length) then "a check is observed twice"
      elif ([(.composites // [])[] | .id | type == "string" and . != ""] | all | not) then "a composite names no id"
      elif ([(.composites // [])[].id] | length) != ([(.composites // [])[].id] | unique | length) then "a composite is published twice"
      elif .profile.id != $profile then "the report is of profile \(.profile.id), not \($profile)"
      elif $kind != "" and .toolchain.kind != $kind then "the report is of a \(.toolchain.kind) toolchain, not \($kind)"
      else null end;
    def verdicts:
      ([.observations[] | {key: .check, value: [.verdict, (.level // null)]}]
       + [(.composites // [])[] | {key: "composite:\(.id)", value: [.verdict, null]}])
      | from_entries;
    def unnamed:
      del(.run.id, .run.harness_revision, .run.inputs_sha256,
          .digest.run.id, .digest.run.harness_revision, .digest.run.inputs_sha256);
    def side($v): if $v == null then "absent" else ($v | map(. // "-") | join("/")) end;
    $b[0] as $B | $h[0] as $H
    | if ($B | fault) then "unfed\tthe base report: \($B | fault)"
      elif ($H | fault) then "unfed\tthe head report: \($H | fault)"
      elif $B.run.harness_revision == $H.run.harness_revision then
        "unfed\tbase and head name one revision (\($B.run.harness_revision // "none"))"
      else
        ($B | verdicts) as $bv | ($H | verdicts) as $hv
        | ([$bv, $hv] | add | keys) as $keys
        | ($B | unnamed) as $bu | ($H | unnamed) as $hu
        | [$keys[] | select($bv[.] != $hv[.])] as $moved
        | ([$B.diagnostics[]?] == [$H.diagnostics[]?]) as $diag_equal
        | ([$bu, $hu] | map(keys[]) | unique
           | map(select(. as $k | $bu[$k] != $hu[$k]))
           | map(select(. != "observations" and . != "composites" or $moved == []))) as $fields
        | (["fed",
            ([$B.observations[]] | length), ([$H.observations[]] | length),
            ($keys | length), ($moved | length),
            ([$B.diagnostics[]?] | length), ([$H.diagnostics[]?] | length),
            (if $diag_equal then "equal" else "differ" end),
            (if $fields == [] then "none" else ($fields | join(",")) end)] | join("\t")),
          ($moved[] | "move\t\(.)\t\(side($bv[.]))\t\(side($hv[.]))")
      end'
}

expected=0 fed=0 pairs=0 moves=0 diag_equal=0 differ=0 exits=0
for cc in $ccs; do
  for profile in $profiles; do
    expected=$((expected + 1))
    b=$dir/base-$cc-$profile.json h=$dir/head-$cc-$profile.json
    why='' recorded=0
    for which in base head; do
      code=$(cat "$dir/$which-$cc-$profile.exit" 2>/dev/null) || continue
      recorded=$((recorded + 1))
      [ "$code" = 0 ] || { why="the $which measurement exited $code"; break; }
    done
    case ${cc##*/} in gcc*) kind=gcc ;; clang*) kind=clang ;; *) kind= ;; esac
    if [ -z "$why" ] && ! out=$(compare_cell "$b" "$h" "$profile" "$kind" 2>/dev/null); then
      why="a report is missing or does not parse"
    fi
    if [ -z "$why" ]; then
      first=$(printf '%s\n' "$out" | head -n 1)
      case $first in unfed*) why=${first#unfed	} ;; esac
    fi
    if [ -n "$why" ]; then
      echo "cell $cc $profile: NOT FED: $why"
      continue
    fi
    IFS='	' read -r _ bc hc p m bd hd de fields <<< "$first"
    fed=$((fed + 1)) pairs=$((pairs + p)) moves=$((moves + m))
    [ "$recorded" = 2 ] && exits=$((exits + 1))
    [ "$de" = equal ] && diag_equal=$((diag_equal + 1))
    [ "$fields" = none ] || differ=$((differ + 1))
    echo "cell $cc $profile: checks $bc/$hc, moves $m, diagnostics $bd/$hd $de, fields differing: $fields"
    printf '%s\n' "$out" | tail -n +2 | while IFS='	' read -r _ key bs hs; do
      echo "  MOVE $key base=$bs head=$hs"
    done
  done
done

[ "$expected" -gt 0 ] || { echo "cells: no cell named"; exit 1; }
echo "cells: fed $fed of $expected, pairs $pairs, moves $moves, diagnostics equal in $diag_equal of $fed, other fields differ in $differ of $fed, exits recorded in $exits of $fed"
[ "$fed" -eq "$expected" ] && [ "$moves" -eq 0 ] || exit 1
[ "$differ" -eq 0 ] || exit 3
exit 0
