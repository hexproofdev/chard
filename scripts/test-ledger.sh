#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Print what a test run did not exercise, after the run, where a reader looks.
#
# Usage: scripts/test-ledger.sh [--no-skip] [--require TABLE]... LEDGER_DIR
#
# Every arm a test could not run on this host is announced on stderr as it happens
# (`tests/common`'s `capability_gap`, and `refuse` under CHARD_ALLOW_TEST_SKIP), between a
# few hundred `ok` lines, and a green summary follows them: a reader who sees the summary
# reads every arm as run. The same announcements are appended to one file per test
# process under LEDGER_DIR (`tests/common::record`), one line each: a kind, the test, the
# text. This script prints them once the run is over, grouped and counted, beside the
# count lines the driving tests write (the rows they exercised against the rows the
# toolchain can run, and the rows another compiler owns).
#
# A TABLE is the name a driving test's count line starts with, before its colon:
# `inert_flags` and `inert_flags (partly inert)` are two tables of one test binary, and
# each is required by name, so one finishing cannot stand in for the other. Two things
# fail it, both cases where the ledger could not say what it was asked:
#
#   1. LEDGER_DIR is missing while a --require names a table. A driving test that runs
#      always writes its count line, so an absent ledger means the run reached no such
#      test (a filtered or crashed run), and an empty list would read as "nothing
#      unexercised".
#   2. a --require'd table has no count line, and its binary wrote no skip line (or
#      --no-skip was given). It did not finish its accounting, and its arms are
#      unaccounted for rather than all run. --no-skip is for a gate: a skip there is a
#      gate that ran nothing.
#
# A gap itself fails nothing here: the tests decide which gaps are legitimate on this
# host, and a gate that needs a family's rows run (`make compiler-arms`) fails inside the
# test. This script's job is that the reader sees the list.

set -u

required=()
skip_ok=1
while [ $# -gt 0 ]; do
  case $1 in
    --require) required+=("$2"); shift 2 ;;
    --no-skip) skip_ok=0; shift ;;
    --) shift; break ;;
    -*) echo "test-ledger: unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -eq 1 ] || { echo "usage: test-ledger.sh [--no-skip] [--require TABLE]... LEDGER_DIR" >&2; exit 2; }
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

files=("$dir"/*.tsv)
[ -e "${files[0]}" ] || files=()
lines=$(cat ${files[@]+"${files[@]}"} /dev/null)
# Counted by awk, not `wc -l`, whose count BSD's wc pads with spaces.
count_of() { printf '%s\n' "$lines" | awk -F'\t' -v k="$1" '$1 == k { n++ } END { print n + 0 }'; }
gaps=$(count_of gap)
skips=$(count_of skipped)
echo "test-ledger: ${#files[@]} ledger file(s); $gaps arm(s) not exercised on this host, $skips test(s) skipped"

for kind in skipped gap; do
  printf '%s\n' "$lines" | awk -F'\t' -v k="$kind" '$1 == k { print $2 }' | sort | uniq -c |
    while read -r n test; do
      echo "  $kind  $test: $n"
      printf '%s\n' "$lines" | awk -F'\t' -v k="$kind" -v t="$test" '$1 == k && $2 == t { print "      " $3 }' | sort
    done
done

printf '%s\n' "$lines" | awk -F'\t' '$1 == "count" { print "  " $3 }'

fail=0
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
