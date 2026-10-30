#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Assert on one chard report the way a reader would, and print the numbers first.
#
# `make sweep` measures the corpus under several compilers and profiles with
# `--fail-on-missing`, whose exit status says only that something was withheld. This
# script reads the report the measurement wrote and prints its denominators before it
# judges anything: checks attempted against the corpus total, every verdict's count,
# and each withheld verdict by cause and by check. A failure therefore names the cell,
# which an exit status cannot.
#
# Five things fail it, in the order they are established:
#
#   1. a core limit other than 0, or a core file under the cell's workdir. The sweep
#      recipe runs `ulimit -c 0` first and passes the limit it then reads back; the
#      section below says what the search can and cannot see under each `core_pattern`.
#   2. no report, or a quarantined one: exit 2 is a chard error, exit 3 is a report that
#      contradicted itself and was written beside the requested path as
#      `<report>.contradicted`. Either is a chard defect.
#   3. an incomplete run: `checks_attempted` below the corpus total, or
#      `all_checks_attempted` false. The corpus total is read from the report itself and
#      compared against the total the caller expects, because a report that miscounts
#      its own corpus cannot vouch for its coverage.
#   4. a withheld verdict the cell's expectation file does not list, or a listed one the
#      run did not produce. An earned limitation (`unsupported`, `not-applicable`)
#      passes; `probe-invalid`, `indeterminate`, `build-failed` and `run-failed` are
#      withheld verdicts, and each is held to the expectation file described below. The
#      counts of each kind are held to the report's own `coverage.withholding`, so a
#      limitation verdict no gating rule earns fails the cell.
#   5. a measurement exit status that disagrees with the report: `--fail-on-missing`
#      exits 1 exactly when `all_verdicts_published` is false.
#
# The expectation file. Some cells withhold by design on the toolchain CI runs: a
# control that needs a flag the runner's gcc lacks, a probe that cannot discriminate on
# clang. Each cell has a file `<expected dir>/<label>.txt`, where `<label>` is the
# report's basename without `.json` (`gcc-bare`), holding one line per withheld verdict
# the cell is expected to carry:
#
#     <check id>  <verdict>  <reason, free text to the end of the line>
#
# Blank lines and lines starting with `#` are comments, and the verdict is one of the
# four withheld verdicts. The file is checked in both directions, so it changes only on
# purpose: a withheld verdict absent from the file fails the cell, and a listed check
# that published a verdict, or withheld a different one, fails the cell too. A missing
# or empty file expects nothing, so every withheld verdict fails. A file whose header
# says UNREVIEWED is a candidate this script wrote and is refused until reviewed, as is
# a line whose reason still carries the candidate's placeholder.
#
# `--candidate <dir>` writes the observed withheld set as `<dir>/<label>.txt` with an
# UNREVIEWED header and the report's own cause in the reason column, so the first run on
# a new toolchain produces the file a reviewer edits and commits. Writing it never
# changes the verdict of the run that wrote it.
#
# Usage: scripts/sweep-gate.sh [--expected <dir>] [--candidate <dir>]
#                              --core-limit <ulimit -c> --workdir <dir>
#                              <report.json> <expected corpus total> <measure exit status>
#
# `--core-limit` and `--workdir` are required: a gate that was not told the limit or where
# the probes ran cannot say that no core was left, and passing without saying so is the
# silence this script exists to refuse.

set -euo pipefail

# Sorting and `comm` have to agree on collation, and the two lists are built in
# separate processes.
export LC_ALL=C

usage='usage: sweep-gate.sh [--expected <dir>] [--candidate <dir>] --core-limit <ulimit -c> --workdir <dir> <report.json> <corpus total> <measure exit status>'

expected_dir=tests/sweep-expected
candidate_dir=
core_limit=
core_workdir=
while [ $# -gt 0 ]; do
  case "$1" in
    --expected) expected_dir=${2:?$usage}; shift 2 ;;
    --candidate) candidate_dir=${2:?$usage}; shift 2 ;;
    --core-limit) core_limit=${2:?$usage}; shift 2 ;;
    --workdir) core_workdir=${2:?$usage}; shift 2 ;;
    --) shift; break ;;
    -*) echo "sweep-gate: unknown option $1" >&2; echo "$usage" >&2; exit 2 ;;
    *) break ;;
  esac
done
report=${1:?$usage}
expected_total=${2:?$usage}
measure_rc=${3:?$usage}
if [ -z "$core_limit" ] || [ -z "$core_workdir" ]; then
  echo "sweep-gate: --core-limit and --workdir are required" >&2
  echo "$usage" >&2
  exit 2
fi

label=$(basename "$report" .json)
fail=0
bad()  { printf 'FAIL  %s: %s\n' "$label" "$*"; fail=1; }
good() { printf 'ok    %s: %s\n' "$label" "$*"; }
note() { printf '      %s\n' "$*"; }
count() { printf '%s\n' "$1" | grep -c . || true; }

# Every observation whose verdict was withheld, and every one that earned a limitation,
# each piped through the jq expression given as the argument.
withheld() {
  jq -r '.observations[]
         | select(.verdict | IN("indeterminate","probe-invalid","build-failed","run-failed"))
         | '"$1" "$report"
}
earned() {
  jq -r '.observations[]
         | select(.verdict == "unsupported" or .verdict == "not-applicable")
         | '"$1" "$report"
}
# The cause a withheld observation recorded, in the order the report's fields carry it,
# and the detector's own reason where a verdict was withheld at detector level, which
# records no cause in `controls`. Whitespace runs are folded and the text is cut short,
# because the reason is a sentence and this is a column.
cause_of='(.controls.withheld_because // .build_rejection // .gating.rule
           // (.evidence.observed // "" | gsub("[[:space:]]+"; " ") | .[:96] | select(. != ""))
           // "-")'

printf '\n== %s (chard measure exited %s)\n' "$label" "$measure_rc"

# ------------------------------------------------------------------------ 1. cores
# Several probes abort by design, and `run::execute` cannot lower RLIMIT_CORE for them:
# the crate denies `unsafe_code`, and a `prlimit` or `ulimit; exec` wrapper, though it
# execs the probe in its own process, would put a program chard did not build in front of
# every probe (see the comment on `run::execute`). So the sweep recipe lowers the limit
# for chard and every child with `ulimit -c 0` before it measures, and hands this gate the
# limit it reads back. Any other limit fails the cell, and so does a core file anywhere
# under the cell's workdir, which holds every probe's working directory. A core file is
# known by its content, an ELF header in either byte order whose e_type is ET_CORE,
# because its name is whatever `core_pattern` makes it.
#
# `core_pattern` decides what the search can see, and the gate prints it for that
# reason. A relative pattern writes a core into the crashing probe's working directory,
# inside the workdir, so the search sees every core the kernel wrote. An absolute one
# writes it elsewhere. A pipe hands every crash to a program whatever the limit, and the
# program decides what to keep: on Fedora 44 x86_64 (2026-09-28), systemd-coredump under
# a limit of 0 logged "Resource limits disable core dumping" and recorded storage `none`
# for a program that called abort(), and under an unlimited one stored the core. Under an
# absolute pattern or a pipe an empty search is not evidence that nothing was kept, and
# the gate's line says so.
#
# This section runs before the report is read, so a missing report does not hide a core,
# and runs without jq, which only the count of runs that ended on a signal needs.
core_header() { od -An -tx1 -N18 "$1" 2>/dev/null | tr -d ' \n' || true; }
if [ -r /proc/sys/kernel/core_pattern ]; then
  core_pattern=$(cat /proc/sys/kernel/core_pattern)
  core_source=/proc/sys/kernel/core_pattern
elif core_pattern=$(sysctl -n kern.corefile 2>/dev/null) && [ -n "$core_pattern" ]; then
  core_source=kern.corefile
else
  core_pattern='(unreadable)'
  core_source='neither /proc/sys/kernel/core_pattern nor kern.corefile'
fi
case $core_pattern in
  '(unreadable)') core_sight='an unknown place, so an empty search is not evidence that no core was kept' ;;
  '|'*) core_sight='a pipe, so a core the program keeps is outside the search and an empty search is not evidence that none was kept' ;;
  /*) core_sight='an absolute path, so a core written there is outside the search and an empty search is not evidence that none was kept' ;;
  *) core_sight="the probe's working directory, so the search sees every core the kernel writes" ;;
esac
note "core limit $core_limit; core_pattern ($core_source): $core_pattern"
note "cores go to $core_sight"
if [ -s "$report" ] && command -v jq >/dev/null 2>&1; then
  signalled=$(jq '[.. | objects | select(has("signal") and has("exit_status") and (.signal != null))] | length' \
    "$report" 2>/dev/null || echo unknown)
  note "$signalled probe run(s) in the report ended on a signal"
fi
if [ "$core_limit" = 0 ]; then
  good "core limit 0"
else
  bad "the core limit is $core_limit; the sweep recipe runs \`ulimit -c 0\` first, and under any other limit an aborting probe can leave a core"
fi
if [ ! -d "$core_workdir" ]; then
  bad "no workdir at $core_workdir; the search for core files covered nothing"
else
  searched=0
  cores=
  while IFS= read -r -d '' file; do
    searched=$((searched + 1))
    # e_ident is 16 bytes: the magic, the class, then the data byte (01 little-endian,
    # 02 big-endian); e_type follows in that byte order, and ET_CORE is 4.
    case $(core_header "$file") in
      7f454c46??01????????????????????0400|7f454c46??02????????????????????0004)
        cores="$cores$file"$'\n' ;;
    esac
  done < <(find "$core_workdir" -type f -print0)
  core_count=$(count "$cores")
  if [ "$searched" -eq 0 ]; then
    bad "the workdir $core_workdir holds no file; a search over nothing finds nothing"
  elif [ "$core_count" -gt 0 ]; then
    bad "$core_count core file(s) among $searched file(s) under $core_workdir:"
    printf '%s' "$cores" | sed 's/^/        /'
  else
    good "no core file among $searched file(s) under $core_workdir; cores go to $core_sight"
  fi
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "sweep-gate: jq is needed to read the report; install it and re-run" >&2
  exit 2
fi

# ------------------------------------------------------------- 2. is there a report
if [ -e "$report.contradicted" ]; then
  bad "the report contradicted itself and was quarantined as $report.contradicted"
  jq -r '.consistency.contradictions[] | "      [\(.rule)] \(.property): \(.detail)"' \
    "$report.contradicted" 2>/dev/null || note "(the quarantined file could not be read)"
  exit 1
fi
if [ ! -s "$report" ]; then
  bad "no report was written (chard measure exited $measure_rc)"
  exit 1
fi
if jq -e '.error' "$report" >/dev/null 2>&1; then
  bad "the output is an error envelope; chard wrote no report"
  jq -r '.error' "$report" | sed 's/^/      /'
  exit 1
fi

# ------------------------------------------------------------ 3. the denominators
toolchain=$(jq -r '.toolchain.id' "$report")
profile=$(jq -r '.profile.id' "$report")
attempted=$(jq -r '.coverage.checks_attempted' "$report")
corpus_total=$(jq -r '.coverage.corpus_checks_total' "$report")
valid=$(jq -r '.coverage.checks_valid' "$report")
gated=$(jq -r '.coverage.checks_not_applicable_here' "$report")
published=$(jq -r '.coverage.withholding.published' "$report")
earned_count=$(jq -r '.coverage.withholding.earned_limitations.count' "$report")
withheld_count=$(jq -r '.coverage.withholding.instrument_withholdings.count' "$report")

note "toolchain $toolchain, profile $profile"
note "checks: $attempted attempted of $corpus_total in the corpus; $valid valid; $gated out of this architecture's reach"
note "verdicts: $(jq -r '.coverage.verdict_counts | to_entries | map("\(.key)=\(.value)") | join(" ")' "$report")"
note "withholding: $published published, $earned_count earned limitations, $withheld_count withheld by the instrument ($(jq -r '.coverage.withholding.instrument_withholdings.no_named_cause' "$report") with neither a gating rule nor a triple's cause)"
for set in earned_limitations instrument_withholdings; do
  for by in by_rule by_withheld_cause; do
    if jq -e ".coverage.withholding.$set.$by" "$report" >/dev/null 2>&1; then
      note "$set $by: $(jq -r ".coverage.withholding.$set.$by | to_entries | map(\"\\(.key)=\\(.value)\") | join(\" \")" "$report")"
    fi
  done
done

if [ "$corpus_total" != "$expected_total" ]; then
  bad "the report's corpus total is $corpus_total and the caller expected $expected_total"
fi
if [ "$attempted" != "$corpus_total" ]; then
  bad "attempted $attempted of $corpus_total checks; a check that was never handed in cannot report its own absence"
else
  good "every one of $corpus_total checks was attempted"
fi
if [ "$(jq -r '.coverage.all_checks_attempted' "$report")" != "true" ]; then
  bad "all_checks_attempted is false"
fi

# ---------------------------------------------------- 4. what was withheld, by name
# Earned limitations are listed for the reader and do not fail the gate; withheld
# verdicts are listed and are held to the expectation below. The list is the point: a
# red lane that does not say which cell is red sends the reader to open the report and
# count by hand, and the CI lane keeps no report to open.
earned_rows=$(earned '.check' | grep -c . || true)
if [ "$earned_rows" -gt 0 ]; then
  note "$earned_rows earned limitation(s):"
  earned '"        \(.check): \(.verdict) [\(.gating.rule // "-")]"'
fi
withheld_rows=$(withheld '.check' | grep -c . || true)
if [ "$withheld_rows" -gt 0 ]; then
  note "$withheld_rows withheld verdict(s):"
  withheld '"        \(.check): \(.verdict) [\('"$cause_of"')]"'
fi
# The two lists above sort by the verdict word; the report sorts by the verdict and the
# gating rule beside it (`report::Standing`), so an `unsupported` or `not-applicable` no
# rule earns is listed here as earned and is in the report's instrument set. The counts
# must agree, or a withholding has escaped the expectation below.
if ! jq -e '.coverage.withholding.earned_limitations.count | numbers' "$report" >/dev/null 2>&1; then
  bad "coverage.withholding has no earned_limitations count: a report of the shape before earned limitations were counted apart, to be measured again with this build"
elif [ "$earned_rows" != "$earned_count" ] || [ "$withheld_rows" != "$withheld_count" ]; then
  bad "this gate lists $earned_rows earned and $withheld_rows withheld by verdict word, and coverage.withholding counts $earned_count and $withheld_count: a limitation verdict carries no gating rule that earns it"
  # A limitation the report did not count as earned: no rule, or a rule the earned set's
  # reasons do not name (one whose premise publishes the other verdict).
  jq -r '(.coverage.withholding.earned_limitations.by_rule // {}) as $earned
         | .observations[]
         | select((.verdict == "unsupported" or .verdict == "not-applicable")
                  and ((.gating.rule // "") as $r | $earned | has($r) | not))
         | "        \(.check): \(.verdict) under \(.gating.rule // "no gating rule")"' "$report"
fi

# ---------------------------------------- 5. the withheld set against the expectation
# Both lists are `<check> <verdict>` lines, sorted, so `comm` can take the difference in
# each direction. The expected list is empty when the file is missing, empty or an
# unreviewed candidate, which makes every withheld verdict unexpected. `expect_state`
# stays `reviewed` only for a file that exists, is reviewed and has no defective line;
# the cell's last word below requires it.
is_entry='!/^[[:space:]]*(#|$)/'
# The `$2` is awk's second field, so the quotes are single on purpose.
# shellcheck disable=SC2016
is_withheld_verdict='$2 ~ /^(indeterminate|probe-invalid|build-failed|run-failed)$/'
expected_file=$expected_dir/$label.txt
observed=$(withheld '"\(.check) \(.verdict)"' | sort)
expected=
expect_state=reviewed
if [ ! -e "$expected_file" ]; then
  expect_state=missing
  note "no expectation file at $expected_file; every withheld verdict fails until one is committed"
elif grep -q '^# UNREVIEWED' "$expected_file"; then
  expect_state=unreviewed
  bad "$expected_file is an unreviewed candidate; review each line, delete the UNREVIEWED header line, and commit it"
else
  malformed=$(awk "$is_entry"' && NF < 3 {print NR": "$0}' "$expected_file")
  if [ -n "$malformed" ]; then
    expect_state=defective
    bad "$expected_file has $(count "$malformed") line(s) without a check, a verdict and a reason:"
    printf '%s\n' "$malformed" | sed 's/^/        /'
  fi
  wrong_verdict=$(awk "$is_entry"' && NF >= 3 && !('"$is_withheld_verdict"') {print NR": "$0}' "$expected_file")
  if [ -n "$wrong_verdict" ]; then
    expect_state=defective
    bad "$expected_file lists $(count "$wrong_verdict") verdict(s) that are not withheld verdicts (indeterminate, probe-invalid, build-failed, run-failed):"
    printf '%s\n' "$wrong_verdict" | sed 's/^/        /'
  fi
  placeholder=$(awk "$is_entry"' && /\(unreviewed\)[[:space:]]*$/ {print NR": "$0}' "$expected_file")
  if [ -n "$placeholder" ]; then
    expect_state=defective
    bad "$expected_file has $(count "$placeholder") line(s) still carrying the candidate's placeholder reason; a reason has to be written:"
    printf '%s\n' "$placeholder" | sed 's/^/        /'
  fi
  duplicates=$(awk "$is_entry"' && NF >= 3 {print $1}' "$expected_file" | sort | uniq -d)
  if [ -n "$duplicates" ]; then
    expect_state=defective
    bad "$expected_file lists a check twice: $(printf '%s' "$duplicates" | tr '\n' ' ')"
  fi
  expected=$(awk "$is_entry"' && NF >= 3 && '"$is_withheld_verdict"' {print $1" "$2}' "$expected_file" | sort -u)
fi

unexpected=$(comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$observed") | sed '/^$/d')
stale=$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$observed") | sed '/^$/d')
matched=$(comm -12 <(printf '%s\n' "$expected") <(printf '%s\n' "$observed") | sed '/^$/d')

if [ -n "$matched" ]; then
  note "$(count "$matched") withheld as $expected_file expects:"
  while read -r check verdict; do
    reason=$(awk -v c="$check" "$is_entry"' && $1 == c {$1 = ""; $2 = ""; sub(/^[[:space:]]+/, ""); print; exit}' "$expected_file")
    note "  $check: $verdict ($reason)"
  done <<< "$matched"
fi
if [ -n "$unexpected" ]; then
  bad "$(count "$unexpected") withheld verdict(s) the expectation does not list:"
  while read -r check verdict; do
    cause=$(jq -r --arg c "$check" 'first(.observations[] | select(.check == $c) | '"$cause_of"')' "$report")
    note "  $check: $verdict [$cause]"
  done <<< "$unexpected"
fi
if [ -n "$stale" ]; then
  bad "$(count "$stale") expected withheld verdict(s) this run did not produce; change or delete each line on purpose:"
  while read -r check verdict; do
    actual=$(jq -r --arg c "$check" 'first(.observations[] | select(.check == $c) | .verdict) // "no observation at all"' "$report")
    note "  $check: expected $verdict, this run reported $actual"
  done <<< "$stale"
fi

if [ -n "$candidate_dir" ]; then
  mkdir -p "$candidate_dir"
  candidate=$candidate_dir/$label.txt
  {
    echo "# SPDX-License-Identifier: BSD-3-Clause"
    echo "# UNREVIEWED candidate written by scripts/sweep-gate.sh; the gate refuses it as an expectation while this line exists."
    echo "# Observed: toolchain $toolchain, libc $(jq -r '.environment.libc.impl' "$report"), profile $profile, chard $(jq -r '.run.harness_version + " (" + .run.harness_revision + ")"' "$report"), $(jq -r '.run.started_utc' "$report")."
    echo "# One line per withheld verdict: <check> <verdict> <reason>. The reason column below is the"
    echo "# cause the report recorded; replace each with the reviewed reason, delete the UNREVIEWED"
    echo "# line, and commit the file as $expected_file."
    withheld '"\(.check) \(.verdict) cause: "+'"$cause_of"'+" (unreviewed)"'
  } > "$candidate"
  note "observed withheld set written as an UNREVIEWED candidate to $candidate ($withheld_rows line(s))"
fi

if [ "$(jq -r '.coverage.all_verdicts_published' "$report")" = "true" ]; then
  good "every verdict was published or earned; nothing withheld"
elif [ -z "$unexpected" ] && [ -z "$stale" ] && [ "$expect_state" = reviewed ]; then
  good "$withheld_rows withheld verdict(s), each listed with a reason in $expected_file"
else
  bad "$withheld_rows verdict(s) withheld and the cell's expectation ($expect_state) does not account for them; the cells are listed above"
fi

# The exit status and the report must agree: `--fail-on-missing` exits 1 exactly when
# `all_verdicts_published` is false. A disagreement is a chard defect.
case "$measure_rc" in
  0) [ "$(jq -r '.coverage.all_verdicts_published' "$report")" = "true" ] \
       || bad "chard measure exited 0 while the report says a verdict was withheld" ;;
  1) [ "$(jq -r '.coverage.all_verdicts_published' "$report")" = "false" ] \
       || bad "chard measure exited 1 (coverage gate) while the report says nothing was withheld" ;;
  *) bad "chard measure exited $measure_rc" ;;
esac

exit "$fail"
