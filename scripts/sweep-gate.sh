#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Assert on one chard report the way a reader would, and print the numbers first.
#
# `make sweep` measures the corpus with `--fail-on-missing`, whose exit status says only that
# something was withheld. This script prints the report's denominators before it judges
# anything (checks attempted against the corpus total, every verdict's count, each withheld
# verdict by cause and by check), so a failure names the cell.
#
# Five things fail it, in the order they are established:
#
#   1. a core limit other than 0, or a core file under the cell's workdir; the section below
#      says what the search can and cannot see under each `core_pattern`.
#   2. no report, or a quarantined one: exit 2 is a chard error, exit 3 a report that
#      contradicted itself, written as `<report>.contradicted`. Either is a chard defect.
#   3. an incomplete run: `checks_attempted` below the corpus total, `all_checks_attempted`
#      false, or a corpus total other than the caller's, because a report that miscounts its
#      own corpus cannot vouch for its coverage.
#   4. a withheld verdict (`probe-invalid`, `indeterminate`, `build-failed`, `run-failed`)
#      the cell's expectation file does not list, or a listed one the run did not produce; an
#      earned limitation (`unsupported`, `not-applicable`) passes. The counts of each kind
#      must match the report's own `coverage.withholding`, so a limitation no rule earns fails.
#   5. a measurement exit status that disagrees with the report (the last check below).
#
# The expectation file, `<expected dir>/<label>.txt` with `<label>` the report's basename
# without `.json` (`gcc-bare`), holds one line per withheld verdict the cell is expected to
# carry on the toolchain CI runs:
#
#     <check id>  <verdict>  <reason, free text to the end of the line>
#
# Blank lines and `#` lines are comments. The file is checked in both directions, so it
# changes only on purpose, and a missing or empty one expects nothing. Without `--expected`
# there is no directory and no file, so every withheld verdict fails the cell. A file with an
# UNREVIEWED header line, a candidate this script wrote, is refused until reviewed, as is a
# line whose reason still carries the candidate's placeholder.
#
# `--candidate <dir>` writes the observed withheld set as `<dir>/<label>.txt`, UNREVIEWED
# and with the report's own cause as each reason, for a reviewer to edit and commit on a new
# toolchain. Writing it never changes the verdict of the run that wrote it.
#
# Usage: scripts/sweep-gate.sh [--expected <dir>] [--candidate <dir>]
#                              --core-limit <ulimit -c> --workdir <dir>
#                              <report.json> <expected corpus total> <measure exit status>
#
# `--core-limit` and `--workdir` are required: a gate not told the limit or where the probes
# ran cannot say that no core was left, and passing without saying so is the silence this
# script refuses. Exit 0 when the cell holds, 1 when it fails, 2 for an unknown option, a
# missing `--core-limit` or `--workdir`, or no jq. A positional argument or an option's value
# that is missing or empty fails bash's `${n:?}` expansion instead, which prints the usage
# and exits 1.

set -euo pipefail

# Sorting and `comm` have to agree on collation, and the two lists are built in
# separate processes.
export LC_ALL=C

usage='usage: sweep-gate.sh [--expected <dir>] [--candidate <dir>] --core-limit <ulimit -c> --workdir <dir> <report.json> <corpus total> <measure exit status>'

expected_dir=
candidate_dir=
core_limit=
core_workdir=
while [ $# -gt 0 ]; do
  case "$1" in
    --expected)
      expected_dir=${2:?$usage}
      shift 2
      ;;
    --candidate)
      candidate_dir=${2:?$usage}
      shift 2
      ;;
    --core-limit)
      core_limit=${2:?$usage}
      shift 2
      ;;
    --workdir)
      core_workdir=${2:?$usage}
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "sweep-gate: unknown option $1" >&2
      echo "$usage" >&2
      exit 2
      ;;
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
bad() {
  printf 'FAIL  %s: %s\n' "$label" "$*"
  fail=1
}
good() { printf 'ok    %s: %s\n' "$label" "$*"; }
note() { printf '      %s\n' "$*"; }
count() { printf '%s\n' "$1" | grep -c . || true; }

# The withheld and the earned observations, each through the jq expression given.
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
# The cause a withheld observation recorded, or the detector's own reason where the verdict
# was withheld at detector level, which records no cause in `controls`; folded and cut short,
# because the reason is a sentence and this is a column.
cause_of='(.controls.withheld_because // .build_rejection // .gating.rule
           // (.evidence.observed // "" | gsub("[[:space:]]+"; " ") | .[:96] | select(. != ""))
           // "-")'

printf '\n== %s (chard measure exited %s)\n' "$label" "$measure_rc"

# ------------------------------------------------------------------------ 1. cores
# Several probes abort by design, and `run::execute` cannot lower RLIMIT_CORE for them (its
# comment says why), so the sweep recipe runs `ulimit -c 0` before it measures and hands this
# gate the limit it reads back. Any other limit fails the cell, as does a core file under the
# workdir, which holds every probe's working directory. A core is known by its content, since
# its name is whatever `core_pattern` makes it.
#
# `core_pattern` decides what the search can see, so the gate prints it. A relative pattern
# writes a core inside the workdir, where the search sees it; an absolute one writes it
# elsewhere. A pipe hands every crash to a program whatever the limit, and the program
# decides what to keep: on Fedora 44 x86_64 (2026-09-28), systemd-coredump under a limit of 0
# logged "Resource limits disable core dumping" and recorded storage `none` for a program that
# called abort(), and under an unlimited one stored the core. Under an absolute pattern or a
# pipe an empty search is not evidence that nothing was kept, and the gate's line says so.
#
# This section runs before the report is read, so a missing report does not hide a core, and
# without jq, which only the count of runs that ended on a signal needs.
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
      7f454c46??01????????????????????0400 | 7f454c46??02????????????????????0004)
        cores="$cores$file"$'\n'
        ;;
      *) ;;
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
# Earned limitations are listed and do not fail the gate; withheld verdicts are listed and
# held to the expectation below. The CI lane keeps no report, so this list is how its log
# says which cell is red.
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
# The lists above sort by the verdict word, the report by the verdict and its gating rule
# (`report::Standing`), so a limitation no rule earns is earned here and withheld there. The
# counts must agree, or a withholding has escaped the expectation below.
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
# The expected list is empty for a missing, empty or unreviewed file, so every withheld
# verdict is then unexpected. `expect_state` stays `reviewed` only for a reviewed file with no
# defective line, and the cell's last word below requires it.
is_entry='!/^[[:space:]]*(#|$)/'
# The `$2` is awk's second field, so the quotes are single on purpose.
# shellcheck disable=SC2016
is_withheld_verdict='$2 ~ /^(indeterminate|probe-invalid|build-failed|run-failed)$/'
expected_file=
[ -z "$expected_dir" ] || expected_file=$expected_dir/$label.txt
observed=$(withheld '"\(.check) \(.verdict)"' | sort)
expected=
expect_state=reviewed
if [ -z "$expected_file" ]; then
  expect_state=missing
  note "no --expected directory; every withheld verdict fails"
elif [ ! -e "$expected_file" ]; then
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
  done <<<"$matched"
fi
if [ -n "$unexpected" ]; then
  bad "$(count "$unexpected") withheld verdict(s) the expectation does not list:"
  while read -r check verdict; do
    cause=$(jq -r --arg c "$check" 'first(.observations[] | select(.check == $c) | '"$cause_of"')' "$report")
    note "  $check: $verdict [$cause]"
  done <<<"$unexpected"
fi
if [ -n "$stale" ]; then
  bad "$(count "$stale") expected withheld verdict(s) this run did not produce; change or delete each line on purpose:"
  while read -r check verdict; do
    actual=$(jq -r --arg c "$check" 'first(.observations[] | select(.check == $c) | .verdict) // "no observation at all"' "$report")
    note "  $check: expected $verdict, this run reported $actual"
  done <<<"$stale"
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
    echo "# line, and keep the file as ${expected_file:-<expected dir>/$label.txt}."
    withheld '"\(.check) \(.verdict) cause: "+'"$cause_of"'+" (unreviewed)"'
  } >"$candidate"
  note "observed withheld set written as an UNREVIEWED candidate to $candidate ($withheld_rows line(s))"
fi

if [ "$(jq -r '.coverage.all_verdicts_published' "$report")" = "true" ]; then
  good "every verdict was published or earned; nothing withheld"
elif [ -z "$unexpected" ] && [ -z "$stale" ] && [ "$expect_state" = reviewed ]; then
  good "$withheld_rows withheld verdict(s), each listed with a reason in $expected_file"
else
  bad "$withheld_rows verdict(s) withheld and the cell's expectation ($expect_state) does not account for them; the cells are listed above"
fi

# The exit status and the report must agree: `--fail-on-missing` exits 1 or 4 exactly when
# `all_verdicts_published` is false, and 4 exactly when every check was attempted and every
# unsettled check reads `indeterminate` under a machine-limit or target-limit rule, at least
# one a machine limit. The rule ids are `MACHINE_LIMITS` and `TARGET_LIMITS` in src/main.rs,
# held to them by a unit test there. A disagreement either way is a chard defect; a cell
# exiting 4 is still judged by its expectation file.
machine_rules='["cpu-lacks-shadow-stack","machine-lacks-bti","machine-lacks-pac","cpu-shows-no-fpac"]'
target_rules='["no-check-on-target","arch-outside-table"]'
machine_limited=$(jq -r --argjson m "$machine_rules" --argjson t "$target_rules" '
  [.observations[]
   | select((.verdict | IN("on","off","partial")) | not)
   | select(((.verdict | IN("unsupported","not-applicable")) and (.gating | type == "object")) | not)
  ] as $unsettled
  | (.coverage.all_checks_attempted == true)
    and ($unsettled | length > 0)
    and ($unsettled | all(.verdict == "indeterminate" and (.gating.rule as $r | ($m + $t) | index($r) != null)))
    and ($unsettled | any(.gating.rule as $r | $m | index($r) != null))' "$report")
published=$(jq -r '.coverage.all_verdicts_published' "$report")
case "$measure_rc" in
  0) [ "$published" = "true" ] \
    || bad "chard measure exited 0 while the report says a verdict was withheld" ;;
  1)
    [ "$published" = "false" ] \
      || bad "chard measure exited 1 (coverage gate) while the report says nothing was withheld"
    [ "$machine_limited" = "false" ] \
      || bad "chard measure exited 1 while every shortfall the report holds is a machine or target limit, at least one a machine limit, which is exit 4"
    ;;
  4)
    [ "$published" = "false" ] \
      || bad "chard measure exited 4 (coverage gate, machine limits) while the report says nothing was withheld"
    [ "$machine_limited" = "true" ] \
      || bad "chard measure exited 4 (coverage gate, machine limits) while the report holds a shortfall that is no machine or target limit, or no machine limit"
    ;;
  *) bad "chard measure exited $measure_rc" ;;
esac

exit "$fail"
