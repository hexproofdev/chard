#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Print what a test run did not exercise, after the run, where a reader looks.
#
# Usage: scripts/test-ledger.sh [--no-skip] [--require TABLE]... LEDGER_DIR
#
# A test announces each arm it could not run on this host on stderr (`tests/common`'s
# `capability_gap`, and `refuse` under CHARD_ALLOW_TEST_SKIP), among a few hundred `ok` lines
# under a green summary, which reads as every arm run. `tests/common::record` also appends
# each announcement to one file per test process under LEDGER_DIR, one line each: a kind, the
# test, the text. This script prints them once the run is over, grouped and counted, beside
# the count lines the driving tests write.
#
# A TABLE is the name a driving test's count line starts with, before its colon:
# `inert_flags` and `inert_flags (partly inert)` are two tables of one test binary, each
# required by name, so one finishing cannot stand in for the other. Exit 2 on a usage error,
# and 1 on any of:
#
#   1. LEDGER_DIR is missing while a --require names a table. A driving test that runs
#      always writes its count line, so the run reached no such test (filtered or crashed),
#      and an empty list would read as nothing unexercised.
#   2. a --require'd table has no count line, and its binary wrote no skip line (or
#      --no-skip was given): its arms are unaccounted for rather than all run.
#   3. with --no-skip, any `skipped` line, required table or not: a gate passes no test
#      that declined to run.
#   4. a ledger file that cannot be read (a dangling link among them): neither its gaps nor
#      its skips can be counted.
#
# A gap itself fails nothing here: the tests decide which gaps are legitimate on this host,
# and a gate that needs a family's rows run (`make compiler-arms`) fails inside the test.
# This script's job is that the reader sees the list.

set -u

required=()
skip_ok=1
while [ $# -gt 0 ]; do
  case $1 in
    --require)
      required+=("$2")
      shift 2
      ;;
    --no-skip)
      skip_ok=0
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "test-ledger: unknown option $1" >&2
      exit 2
      ;;
    *) break ;;
  esac
done
[ $# -eq 1 ] || {
  echo "usage: test-ledger.sh [--no-skip] [--require TABLE]... LEDGER_DIR" >&2
  exit 2
}
dir=$1

echo
echo "== what this test run did not exercise (ledger: $dir)"
if [ ! -d "$dir" ]; then
  if [ ${#required[@]} -gt 0 ]; then
    echo "test-ledger: no ledger was written, and each of: ${required[*]} always writes one; the run did not reach them"
    exit 1
  fi
  echo "test-ledger: no ledger was written: no test announced an unexercised arm"
  exit 0
fi

# Every entry the glob names, a dangling link among them, so `cat` below reads each or fails.
shopt -s nullglob
files=("$dir"/*.tsv)
shopt -u nullglob
if ! lines=$(cat ${files[@]+"${files[@]}"} /dev/null); then
  echo "test-ledger: a ledger file under $dir cannot be read, so what the run did not exercise is unknown"
  exit 1
fi
# Counted by awk, not `wc -l`, whose count BSD's wc pads with spaces.
count_of() { printf '%s\n' "$lines" | awk -F'\t' -v k="$1" '$1 == k { n++ } END { print n + 0 }'; }
gaps=$(count_of gap)
skips=$(count_of skipped)
echo "test-ledger: ${#files[@]} ledger file(s); $gaps arm(s) not exercised on this host, $skips test(s) skipped"

for kind in skipped gap; do
  printf '%s\n' "$lines" | awk -F'\t' -v k="$kind" '$1 == k { print $2 }' | sort | uniq -c \
    | while read -r n test; do
      echo "  $kind  $test: $n"
      printf '%s\n' "$lines" | awk -F'\t' -v k="$kind" -v t="$test" '$1 == k && $2 == t { print "      " $3 }' | sort
    done
done

printf '%s\n' "$lines" | awk -F'\t' '$1 == "count" { print "  " $3 }'

fail=0
if [ $skip_ok -eq 0 ] && [ "$skips" -gt 0 ]; then
  echo "test-ledger: $skips test(s) skipped, and --no-skip was given: a skipped test is not a pass"
  fail=1
fi
for t in ${required[@]+"${required[@]}"}; do
  # The binary a table belongs to is its name up to the first space.
  bin=${t%% *}
  if printf '%s\n' "$lines" | awk -F'\t' -v t="$t: " '$1 == "count" && index($3, t) == 1 { found = 1 } END { exit !found }'; then
    continue
  fi
  if [ $skip_ok -eq 1 ] && printf '%s\n' "$lines" | awk -F'\t' -v b="$bin" '$1 == "skipped" && $2 == b { found = 1 } END { exit !found }'; then
    echo "test-ledger: $t skipped its accounting (CHARD_ALLOW_TEST_SKIP); its arms went unverified"
    continue
  fi
  echo "test-ledger: $t wrote no count line: it did not finish its accounting, so its arms are unaccounted for"
  fail=1
done
exit $fail
