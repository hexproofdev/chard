#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Refuse to publish material that must not leave this repository.
#
# Two properties separate a boundary that holds from one that merely exists. It is
# enforced mechanically rather than by whoever last looked, and it is scoped to the
# **object graph** rather than to the checkout, a file committed and later removed is
# invisible to `git ls-files`, passes every checkout-scoped check, and ships in full from
# a clean HEAD.
#
# Fail-closed, and deliberately no override flag. A gate with a --force is a gate that
# gets forced at the moment it matters.
#
# ## Why every check prints its denominator
#
# A check that scans nothing exits 0. This project's standing rule is that any driver
# enumerating work must count what it fed and compare it to the expected total, because
# a clean-looking zero is the failure mode it cannot tolerate. A content scan written with
# a malformed `grep -qlF ... /dev/stdin` reports zero host tokens across every pattern over
# a corpus that contains them, and looks exactly like a pass. So each section below prints
# the size of the set it examined, and the script fails if a set it expected to be
# non-empty came back empty.
#
# ## Why the host names are not in this file
#
# The names this gate hunts (a development host's name, a name that says which machine
# the work was done on, such as a sibling project's, and a path that exists on one host
# only) cannot be listed in a tracked file without publishing exactly what the list exists
# to keep out: the list itself becomes the disclosure, in every clone. So they live in an
# untracked file beside this script, `scripts/leak-gate.private`, ignored by a rule in the
# tracked `.gitignore`, and each developer's machine holds its own. A developer makes one
# with a line per name that identifies their machine:
#
#     # kind  pattern
#     word    myhost
#     path    /srv/build-cache
#
# A `word` is letters, digits, `_` and `-`, starting and ending with a letter, digit or `_`
# (with a `-` at an end, whether `\b` matches depends on the neighbouring character, so the
# word would match where its author did not mean). It is
# matched between `\b` boundaries and without regard to case, as host names are: `myhost`
# also matches `MyHost` and the first part of `myhost-2`. A `path` is matched as a literal,
# case-sensitive substring. Whole-line `#` comments and blank lines are allowed; anything
# else on a pattern line fails, so a path cannot hold a space. The file is read by its path
# in the tree this script sits in, never through an environment variable: chard reads no
# configuration from the environment beyond `PATH`, and the gate keeps the same rule.
#
# An untracked file is outside every vector this gate scans (no ref, index entry or reflog
# names it, and its content is in no object), so the gate never reads its own list as a
# leak. Once staged it is a blob the index reaches, and fails on every pattern it holds;
# unstaged again, it is a blob no ref reaches, reported as local-only until `git gc` removes
# it; once committed it is also a ref-reachable ignored path. The gate's output names a
# private pattern only by its kind and its number among that kind's lines in file order
# (`private word 2`), never by value, so a pasted FAIL does not publish the list.
#
# What a list holds, by kind: every host the work is verified on, not only the first, since
# a message or file naming a host the list leaves out passes every scan; and the name of a
# sibling project developed on the same machine, which can reach a doc comment through a
# kernel release string that no path or hostname pattern matches. A project name is host
# detail for the same reason a hostname is: it says which machine this was built on.
#
# Where no list is given or found (a fresh clone, a public CI) the private scan does not run,
# and the gate says so: a note at the top and the final line, never a bare "passed". Where the file is
# present and holds no pattern line, the gate fails, because a list that scans nothing is
# not a pass. A public CI cannot scan for these names without holding them, which would put
# the list in the CI provider's keeping and within reach of every job's log; the scan runs
# where the names already are.

set -euo pipefail
# One collation for every sort, comm and character class below, whatever the caller's locale.
export LC_ALL=C

# Bash 4.4 or later (associative arrays, `mapfile -d`). macOS ships bash 3.2 as /bin/bash,
# which has neither, so the gate names the version it was given rather than failing at its
# first `declare -A`; a newer bash runs it (Homebrew's, first on PATH, which the `env bash`
# above and `make check` take). The gate uses none of three forms other userlands lack:
# `sed -z`, which macOS's sed refuses; `grep -z`, which POSIX grep lacks; and a `wc` count,
# padded with spaces by BSD wc, read as a string. tests/leak_gate.rs runs the gate under
# shims shaped that way.
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
  printf 'FAIL  leak gate: bash %s cannot run it; it needs bash 4.4 or later (on macOS, the Homebrew bash first on PATH)\n' "${BASH_VERSION:-unknown}"
  exit 1
fi

# `--patterns FILE` reads the private list from FILE instead of `scripts/leak-gate.private`
# beside this script: the CI host keeps its copy outside every tree (infra's queue material)
# and the merge-gate job passes it here, as an argument, so the gate still takes no
# configuration from the environment beyond `PATH` (git's own variables aside, of which the
# gate sets GIT_NO_REPLACE_OBJECTS and unsets GIT_NAMESPACE below). Given, the file must exist: a caller that names a list asked for the scan,
# and its absence fails rather than reading as the fresh-clone skip below.
usage() { printf 'usage: scripts/leak-gate.sh [--patterns FILE]\n' >&2; exit 2; }
patterns_arg=''
while [ $# -gt 0 ]; do
  case $1 in
    --patterns)
      { [ $# -ge 2 ] && [ -n "$2" ]; } || usage
      case $2 in /*) patterns_arg=$2 ;; *) patterns_arg=$PWD/$2 ;; esac
      shift 2 ;;
    *) usage ;;
  esac
done

# Outside a clone there is no object graph to scan: a tarball from `git archive` or a crate
# archive holds the files and none of the history this gate reads. The gate says so and exits
# 0, a skip and not a pass, so `make check` runs to its end from one; a tree like that has no
# history to publish, and the clone it came from is where the gate runs. The same inside
# another repository's work tree (a vendored copy, a tree unpacked under one), whose graph
# is that repository's and not this tree's. A tree holding a `.git` that git cannot read
# fails: that is a clone the gate cannot see into, not a tarball. `scripts/spdx-gate.sh`
# opens the same way.
#
# The tree is the one this script sits in, not the caller's working directory, so the gate
# run from elsewhere scans this repository rather than whichever one the caller stands in.
here=$(cd "$(dirname "$0")/.." && pwd -P)
if ! top=$(git -C "$here" rev-parse --show-toplevel 2>/dev/null); then
  if [ -e "$here/.git" ] || [ -L "$here/.git" ]; then
    printf 'FAIL  leak gate: this tree holds a .git that git cannot read, so its object graph is unknown\n'
    exit 1
  fi
  printf '\nleak gate skipped: this tree is not a git work tree (a tarball or a crate archive), so there is no object graph to scan; it runs in a clone\n\n'
  exit 0
fi
if [ "$(cd "$top" && pwd -P)" != "$here" ]; then
  printf "\nleak gate skipped: this tree sits inside another repository's work tree, whose object graph is not this tree's; it runs in a clone\n\n"
  exit 0
fi
cd "$here"

# A shallow clone holds the commits it was cut to and none behind them, so every vector below
# would scan part of the history and report it whole: a finding in an older commit would not
# be found, and its accepted line would read as an object this clone lacks. That is a clean
# zero over a set the gate did not see, so it fails: the gate runs where the history is.
case "$(git rev-parse --is-shallow-repository 2>/dev/null || echo unknown)" in
  false) ;;
  true)
    printf 'FAIL  leak gate: this clone is shallow, so the history behind its cut is not here to scan; fetch it whole (git fetch --unshallow)\n'
    exit 1 ;;
  *)
    printf 'FAIL  leak gate: git did not say whether this clone is shallow, so how much history is here is unknown\n'
    exit 1 ;;
esac
# A partial clone holds the history and not every object in it, so the content scan would read
# a missing blob as one that matched nothing. Refused for the same reason, and the reachable
# objects are checked present below whatever the configuration says.
# git marks one with a promisor remote (remote.<name>.promisor, which git 2.55 sets on clone)
# or extensions.partialClone, and would fetch a missing object from that remote on demand:
# GIT_NO_LAZY_FETCH keeps the gate off the network, so a missing object stays missing.
export GIT_NO_LAZY_FETCH=1
if [ -n "$(git config --get extensions.partialClone || true)" ] ||
  git config --get-regexp '^remote\..*\.promisor$' 2>/dev/null |
  awk '{ v = tolower($2) } v != "false" && v != "no" && v != "off" && v != "0" { f = 1 } END { exit !f }'; then
  printf 'FAIL  leak gate: this is a partial clone, so objects the history names are not here to scan; clone it whole\n'
  exit 1
fi
# The graph as a push carries it. Replace refs change what rev-list, log and cat-file walk but
# not what a push sends, and a graft file does the same to history, so the replaced commits
# would go unscanned while they publish; neither is honoured, and grafts are refused. A
# namespace would narrow --all to one, so none applies.
export GIT_NO_REPLACE_OBJECTS=1
unset GIT_NAMESPACE
if [ -e "$(git rev-parse --git-path info/grafts)" ]; then
  printf 'FAIL  leak gate: this repository has a graft file, so the history git walks is not the history a push sends\n'
  exit 1
fi
# Inside the repository's own git directory, not TMPDIR: what lands here (every message, each
# blob in turn) is the repository's, and stays with it if the gate is killed before its trap.
tmp=$(mktemp -d "$(git rev-parse --absolute-git-dir)/leak-gate.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
# And what bash and sort spill to a temporary file (a here-string past a pipe's size, a sort
# too large for memory) lands there too, not in the caller's TMPDIR.
export TMPDIR="$tmp"

fail=0
note() { printf '  %s\n' "$*"; }
bad()  { printf 'FAIL  %s\n' "$*"; fail=1; }
# A count another tool printed, as a number, in the variable that held its text. BSD wc pads
# its count with spaces, so as a string "  2208" is not "2208"; text that is not digits once
# the blanks are gone fails the gate, where `$(( ))` would read it as 0. The count's read stays
# its own assignment, so errexit sees the command that gave it fail.
count_of() { # variable name, what it counts
  local text=${!1} digits
  digits=${text//[[:space:]]/}
  case $digits in
    '' | *[!0-9]*)
      printf "FAIL  leak gate: the count of %s is '%s', not a number, so what was counted is unknown\n" "$2" "$text"
      exit 1 ;;
  esac
  printf -v "$1" '%d' "$((10#$digits))"
}
good() { printf 'ok    %s\n' "$*"; }

# Host-specific detail: absolute paths, hostnames and operator layout. These publish in
# tracked files, in commit messages and in author identities alike.
#
# Two classes, because they need different matching. A path fragment is a substring and
# matches literally. A host *name* is a word, and matching it as a substring is how a
# gate earns a reputation for crying wolf, since a short host name is the start of many
# English words. Word-boundary anchors fix it in the direction that matters: `\bhost\b` does
# not match "hostname", because there is no boundary between the t and the n.
#
# The two home roots are here because they are every developer's, not one machine's. The
# names and paths that identify one machine are in the private list (see the header).
PATH_PATTERNS=(
  '/home/'
  '/Users/'
)
# A fixed pattern is also the label the message scan writes into a sed script, where `|`
# ends the expression, `&` stands for the match and a backslash escapes. One of them in a
# pattern added here would break that script, or name the wrong pattern in a finding's key,
# so the gate refuses it with a FAIL naming the pattern.
for pat in "${PATH_PATTERNS[@]}"; do
  case $pat in
    *'|'* | *'&'* | *'\'*)
      printf "FAIL  fixed pattern '%s' contains |, & or a backslash; the message scan cannot write it into its sed label\n" "$pat"
      exit 1
      ;;
  esac
done

# Home directories that are *measured data* rather than this machine's identity.
#
# `/home/chard` is the unprivileged account the sweep harness creates inside a guest. It
# reaches committed evidence two ways: a compiler diagnostic quoting the path of the probe
# it just compiled, and the `-ffile-prefix-map=/home/chard=.` the harness passes to keep
# that path out of the artifact. Neither says anything about the machine this repository
# is developed on, which is the whole thing the pattern above exists to catch.
#
# `/home/` with no name after it is the second entry, and it is a different argument. What
# the `/home/` pattern is hunting is a *username*, the operator this repository is
# developed by, and through them the machine. A bare `/home/` names nobody. It reaches
# committed content as prose about paths rather than as a path: the recorded review corpus
# carries the recipe `grep -o '/home/[^"]*\|<scratch>/[^"]*'`, which is advice about
# running exactly this check. Forgiving it is not a hole, because every real disclosure this
# pattern exists to catch has a name in the next path segment and so does not match this
# entry, `/home/chard` is forgiven by name above, and anything else fails.
#
# This is an exclusion, so it is by *value* and not by path, it is listed here rather than
# buried in a condition, and every blob it forgives is counted and printed. An exclusion
# nobody can see is how a real leak hides, the same argument as the self-skip below.
#
# `/Users/` is the same pattern for macOS's home root: with `/home/` alone, every macOS path
# in a commit message, a doc comment or a mined fixture would pass clean while the
# identical Linux path was refused. It has the same two exclusions: a bare `/Users/` names
# nobody, and `/Users/chard` is the harness's own account under the macOS spelling.
# `/Users/someone` is a third kind of entry: an invented person's home, held by one scanned
# blob of the path scrubber's unit test in `src/fixture.rs`. It is forgiven by name and
# printed on every run like the others, and it is deleted when no blob the gate scans holds
# it: an
# exclusion with a reason and no retirement condition is how the next one gets added without
# argument.
PERMITTED_HOMES=(
  '/home/chard'
  '/home/'
  '/Users/chard'
  '/Users/'
  '/Users/someone'
)
printf '\nleak gate — object graph, not the checkout\n\n'

# ------------------------------------------------------------- the private list
private_list=scripts/leak-gate.private
[ -z "$patterns_arg" ] || private_list=$patterns_arg
PRIVATE_WORDS=()
PRIVATE_PATHS=()
private_present=0
if [ -e "$private_list" ] || [ -L "$private_list" ]; then
  private_present=1
  if [ ! -f "$private_list" ] || [ ! -r "$private_list" ]; then
    bad "private patterns: $private_list exists but is not a readable file, so the names it should hold are unknown"
  else
    # A malformed line fails rather than being skipped: a line the reader does not
    # understand is a name the scan would silently not look for. The value is never
    # printed here, only its line number, so the failure itself does not publish it.
    lineno=0
    while IFS= read -r line || [ -n "$line" ]; do
      lineno=$((lineno + 1))
      line=${line%$'\r'}
      read -r kind value rest <<<"$line" || true
      case "${kind:-}" in
        '' | '#'*) continue ;;
      esac
      if [ -n "${rest:-}" ] || [ -z "${value:-}" ]; then
        bad "private patterns: $private_list line $lineno is not 'kind pattern' (one kind, one pattern, nothing after)"
      elif [ "$kind" = word ]; then
        if [[ "$value" =~ ^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$ ]]; then
          PRIVATE_WORDS+=("$value")
        else
          bad "private patterns: $private_list line $lineno: a word is letters, digits, _ and -, starting and ending with a letter, digit or _ (it is matched between word boundaries)"
        fi
      elif [ "$kind" = path ]; then
        PRIVATE_PATHS+=("$value")
      else
        bad "private patterns: $private_list line $lineno: the kind is neither word nor path"
      fi
    done <"$private_list"
    private_count=$((${#PRIVATE_WORDS[@]} + ${#PRIVATE_PATHS[@]}))
    if [ "$private_count" -eq 0 ]; then
      bad "private patterns: $private_list holds no pattern line; a list that scans nothing is not a pass"
    else
      note "private patterns: $private_count from $private_list (${#PRIVATE_WORDS[@]} word, ${#PRIVATE_PATHS[@]} path), each scanned in every vector below that runs, named by kind and number"
    fi
  fi
elif [ -n "$patterns_arg" ]; then
  bad "private patterns: --patterns names $private_list, which does not exist; a list asked for and not found is not a pass"
else
  note "private patterns: not scanned, no list at $private_list (host names and host-only paths are kept out of the tree; see this script's header)"
fi

# ------------------------------------------------------------ accepted findings
# A finding in history that no commit on the tree can remove would fail every run, and every
# caller would learn to read past the gate's verdict by matching its FAIL lines by text. So
# the findings the gate accepts are the lines of the tracked
# `scripts/leak-gate.accepted`, one line each, keyed by the object it is in, never by a
# count (a count differs between a clone of
# one branch and a checkout holding every branch, and would let a second finding hide behind
# a first):
#
#     ignored-path <object id>             an ignored path reachable from a ref
#     content <blob id> <label>            a reachable blob matching the pattern so labelled
#     message <commit id> <label>          a commit whose message matches it
#
# A label is the one this gate prints (`/home/`, `private word 1`), so the list names no
# private pattern. A listed finding prints as `accept` and does not fail the run; a finding
# not listed fails and prints its key; a line whose object this clone holds and that matches
# no finding fails, so the list cannot outlive what it accepts; a line whose object this
# clone does not hold (a ref it lacks) is noted, not checked. Identities are never accepted:
# one publishes with every commit it signs. The list is empty when history holds no such finding.
accepted_list=scripts/leak-gate.accepted
declare -A accepted=()
accepted_hits=0
if [ -f "$accepted_list" ]; then
  lineno=0
  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    case "$line" in '' | '#'*) continue ;; esac
    read -r kind id label <<<"$line" || true
    if ! [[ "${id:-}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; then
      bad "accepted: $accepted_list line $lineno: the second field is not a full object id"
    elif [ "$kind" = ignored-path ] && [ -z "${label:-}" ]; then
      accepted["$kind $id"]=unused
    elif { [ "$kind" = content ] || [ "$kind" = message ]; } && [ -n "${label:-}" ]; then
      accepted["$kind $id $label"]=unused
    else
      bad "accepted: $accepted_list line $lineno is not 'ignored-path ID', 'content ID LABEL' or 'message ID LABEL'"
    fi
  done <"$accepted_list"
  note "accepted findings: ${#accepted[@]} line(s) in $accepted_list"
else
  note "accepted findings: none ($accepted_list is absent)"
fi

# Sorts KEYS (the keys of one vector's findings, one per line, on stdin) into accepted and
# not, marking each accepted line used; sets `unaccepted`, `taken` and `listing` (a `key:`
# line per unaccepted finding). Called with a here-string, never in a pipeline or a command
# substitution: either runs it in a subshell, and the marks would be lost.
sort_findings() {
  local key
  unaccepted=0 taken=0 listing=''
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    if [ -n "${accepted[$key]+x}" ]; then
      accepted["$key"]=used
      taken=$((taken + 1))
    else
      unaccepted=$((unaccepted + 1))
      listing+="    key: $key"$'\n'
    fi
  done
  accepted_hits=$((accepted_hits + taken))
}
not_exercised=

# ---------------------------------------------------------------- vector 1: refs
# What a clone receives and a push transfers. This is the set that publishes.
#
# Read whole or not at all: a listing cut short would leave what it missed out of `reachable`,
# and the content scan below reports a blob no ref reaches as local-only, not as a finding.
if ! git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype)' > "$tmp/objects"; then
  printf 'FAIL  ref-reachable: git cat-file could not list the object store\n'
  exit 1
fi
# An object git cannot read is listed with the type `missing`, and the listing still exits 0:
# taken as present, it would pass the presence check below and, not being a blob, never be
# scanned. Any record that is not one of the four object types fails the gate.
declare -A type_of=()
unreadable=0
while read -r id type; do
  case $type in
    commit | tree | blob | tag) type_of["$id"]=$type ;;
    *) unreadable=$((unreadable + 1)) ;;
  esac
done < "$tmp/objects"
if [ "$unreadable" -ne 0 ]; then
  printf 'FAIL  leak gate: %s object(s) in the store could not be read (git lists them as missing), so what they hold is unknown\n' "$unreadable"
  exit 1
fi
if ! git rev-list --objects --all --indexed-objects > "$tmp/refs"; then
  printf 'FAIL  ref-reachable: git rev-list failed, so what a clone receives is unknown\n'
  exit 1
fi
mapfile -t ref_objects < "$tmp/refs"
declare -A reachable=() path_objects=()
for line in "${ref_objects[@]}"; do
  [ -n "$line" ] || continue
  reachable["${line%% *}"]=1
  path=${line#* }
  # A tree's path is asked about as a directory (`dir/`), so a rule for a directory matches it
  # whether or not the directory is on this disk: the verdict is the graph's, not the checkout's.
  if [ "$path" != "$line" ] && [ -n "$path" ]; then
    [ "${type_of[${line%% *}]:-}" != tree ] || path="$path/"
    path_objects["$path"]+="${line%% *} "
  fi
done
# Every object a ref reaches is in this store, or the scan below would read a missing one as a
# blob that matched nothing (a partial clone the configuration did not name, a damaged store).
missing=0
for id in "${!reachable[@]}"; do [ -n "${type_of[$id]+x}" ] || missing=$((missing + 1)); done
if [ "$missing" -ne 0 ]; then
  printf 'FAIL  ref-reachable: %s object(s) a ref reaches are not in this object store, so they cannot be scanned\n' "$missing"
  exit 1
fi
mapfile -t ref_paths < <(printf '%s\n' "${!path_objects[@]}" | sort)
if [ "${#ref_paths[@]}" -eq 0 ]; then
  bad "ref-reachable path set is empty — the instrument scanned nothing, which is not a pass"
else
  # `git check-ignore` exits 1 when nothing matched, which is the *passing* case here.
  # Under `set -e` with `pipefail` that status kills the script, so the gate would die
  # after printing its header and report nothing at all, indistinguishable from a pass
  # to anything reading only the exit code, and it exits 1, so it fails closed. The count
  # is the verdict; the search's exit status is not.
  #
  # NUL-separated both ways (-z): without it git quotes a path holding a quote, a backslash or
  # a byte outside ASCII, the quoted spelling names no listed object, and that ignored path
  # would key nothing and read as accepted. Each ignored path is held to the objects listed
  # under it, and one that keys none fails rather than vanishing.
  ci=0
  printf '%s\0' "${ref_paths[@]}" | git check-ignore -z --stdin --no-index > "$tmp/ignored" 2>/dev/null || ci=$?
  if [ "$ci" -gt 1 ]; then
    bad "ref-reachable: git check-ignore failed (exit $ci), so which reachable paths are ignored is unknown"
    hits=0
  else
    mapfile -d '' -t ignored_paths < "$tmp/ignored"
    hits=${#ignored_paths[@]}
  fi
  if [ "$hits" -eq 0 ]; then
    [ "$ci" -gt 1 ] || good "ref-reachable: 0 ignored paths, over ${#ref_paths[@]} paths"
  else
    keys='' unkeyed=0
    for path in "${ignored_paths[@]}"; do
      if [ -z "${path_objects[$path]+x}" ]; then unkeyed=$((unkeyed + 1)); continue; fi
      for id in ${path_objects[$path]}; do keys+="ignored-path $id"$'\n'; done
    done
    [ "$unkeyed" -eq 0 ] || bad "ref-reachable: $unkeyed ignored path(s) match no object the listing named, so they could not be keyed"
    keys=$(sort -u <<<"$keys")
    sort_findings <<<"$keys"
    [ "$taken" -gt 0 ] && printf 'accept ref-reachable: %s object(s) under %s ignored path(s), accepted by %s\n' "$taken" "$hits" "$accepted_list"
    if [ "$unaccepted" -gt 0 ]; then
      bad "ref-reachable: $unaccepted object(s) under ignored paths not accepted ($hits ignored path(s) over ${#ref_paths[@]}) — a clone receives these"
      printf '%s' "$listing"
    elif [ "$unkeyed" -eq 0 ]; then
      good "ref-reachable: $hits ignored path(s) over ${#ref_paths[@]}, every object under them accepted"
    fi
    note "covering rule(s):"
    printf '%s\0' "${ref_paths[@]}" | { git check-ignore -z -v --stdin --no-index 2>/dev/null || true; } | tr '\0' '\n' | paste - - - - | cut -f1-3 | sed 's/\t/:/g' | sort -u | sed 's/^/    /'
    note "paths withheld deliberately: a path under an ignored directory is frequently the disclosure"
  fi
fi

# ------------------------------------------------------------- vector 2: reflog
# Transfers under no push and no clone; publishes only if .git itself is copied.
# The listing is read whole or not at all, as the ref vector's is: a failed `rev-list`
# inside the substitution read as an empty reflog, which prints as "expired, or a fresh
# clone".
list_rc=0
git rev-list --objects --reflog > "$tmp/reflog-objects" 2>/dev/null || list_rc=$?
mapfile -t log_paths < <(cut -d' ' -f2- "$tmp/reflog-objects" | sed '/^$/d' | sort -u)
# `git check-ignore` exits 1 when no path is ignored, which passes; above 1 it failed, and a
# count of its output would read as 0.
loghits=0 log_rc=0
if [ "$list_rc" -eq 0 ] && [ "${#log_paths[@]}" -gt 0 ]; then
  printf '%s\n' "${log_paths[@]}" | git check-ignore --stdin --no-index > "$tmp/log-ignored" 2>/dev/null || log_rc=$?
  loghits=$(wc -l < "$tmp/log-ignored")
fi
count_of loghits 'ignored reflog paths'
if [ "$list_rc" -ne 0 ]; then
  bad "local-only (reflog): git rev-list --reflog failed (exit $list_rc), so which paths the reflog holds is unknown"
elif [ "$log_rc" -gt 1 ]; then
  bad "local-only (reflog): git check-ignore failed (exit $log_rc), so which reflog paths are ignored is unknown"
elif [ "${#log_paths[@]}" -eq 0 ]; then
  # Not `bad`: an empty reflog is the expected state after `reflog expire`, and on a
  # fresh clone. But it must not print as a scan that found nothing, which is what it
  # did, `0 ignored paths, over 0 paths` beside the ref vector's `over 101 paths`,
  # indistinguishable from a check that ran. The label is the whole fix.
  note "local-only (reflog): no reflog to scan (expired, or a fresh clone) — vector not exercised"
  not_exercised='reflog'

elif [ "$loghits" -eq 0 ]; then
  good "local-only (reflog): 0 ignored paths, over ${#log_paths[@]} paths"
else
  note "local-only (reflog): $loghits ignored path(s) over ${#log_paths[@]}"
  note "transfers under no push; clear with: git reflog expire --expire=now --all && git gc --prune=now"
fi

# ------------------------------------------------------- content across history
# The tokens live in file *content*, not only in paths, so a path-shaped check does not
# catch a hostname inside a committed document.
#
# `grep -a` is load-bearing, not tidiness. Without it grep applies its binary heuristic:
# on a blob containing NUL bytes it may report a match as "Binary file matches" or, under
# `-q` with different buffering, decline to match at all. An editor swap file is binary and
# can carry a hostname, and a scan without `-a` can miss it on one run and catch it on
# another. A gate whose verdict on binary input is non-deterministic is not a gate.
# The listing the ref vector read and checked above, every record a readable type.
mapfile -t blobs < <(awk '$2=="blob"{print $1}' "$tmp/objects")
# The blobs of this file listed below are excluded from the history scan: each holds the
# private pattern list, so each matches itself in all four vectors, and the private list
# covers the names they hold. This is the single most dangerous line in this script:
# "exclude something from the scan" is exactly how a real leak would be hidden. So the
# exclusion is by *value*, the blob ids themselves, and the number skipped is printed with
# the results. A silent exclusion would be indistinguishable from a clean scan, which is the
# property this whole script exists to deny.
#
# The exclusion is by value and not by path: a path skip would also pass a name put back
# into this file. Every other blob of this file is scanned like any other; an unreachable one
# left in some clone's object store is reported there as local-only until `git gc` removes
# it, which is the gate saying what that store holds.
#
# The exclusion has an end, like `/Users/someone` above: the history squash leaves none of
# these revisions reachable, the count printed below falls to 0, and this list is deleted.
PRE_LIST_REVISIONS=(
  2adb6369b05f3fe6928aed4d8fee2363180e9c44
  80d0bc2a6c9b4ce66f0c425eda5ea13d465da60a
  85a5e6a004f7ede3734773a455b0f2c7f1b6b382
  b0ace5ba5f5ec1d70dbfec93e953e818ecdb8371
  bf26496a1ec96de0fbb469471102f1e2c98c8f27
  dcb9f02807d8a6476476a470c4805e895c555e6e
  f1e032b5d26b8b7a618ee77e6d13fe70098086a4
)
declare -A self_blob=()
for sha in "${PRE_LIST_REVISIONS[@]}"; do
  if git cat-file -e "$sha" 2>/dev/null; then
    self_blob["$sha"]=1
  fi
done

if [ "${#blobs[@]}" -eq 0 ]; then
  bad "blob set is empty — the content scan examined nothing"
else
  note "content scan: ${#self_blob[@]} blob(s) skipped, of ${#PRE_LIST_REVISIONS[@]} pinned: revisions of this script from before the private list, which held the host names; the skip ends with the history squash"

  # The store is read once. Read per pattern, every blob through its own `git cat-file -p`
  # and grep, about 5,000 blobs by eight patterns made some 80,000 processes, three minutes
  # on a loaded host with twice as much system time as user time. A single
  # `git cat-file --batch` writes every blob to scan, once, into a stream of
  # "<id> blob <size>\n<content>\n" records in the order of $tmp/scan, and each pattern is
  # one grep over the stream whose match offsets are mapped back to the blob they fall in.
  # The stream's length is checked against the sizes `--batch-check` gave, so a blob that
  # could not be read (a `missing` record, a short read) fails the gate instead of reading as
  # one that matched nothing. A match is a match within one line, so none spans two records.
  for o in "${blobs[@]}"; do [ -n "${self_blob[$o]:-}" ] || printf '%s\n' "$o"; done > "$tmp/scan"
  scanned=$(wc -l < "$tmp/scan")
  count_of scanned 'blobs to scan'
  if [ "$scanned" -eq 0 ]; then
    printf 'FAIL  content: no blob is left to scan once the pinned skip is taken out\n'
    exit 1
  fi
  if ! git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize)' < "$tmp/scan" > "$tmp/sizes"; then
    printf 'FAIL  content: git cat-file could not size the blobs to scan\n'
    exit 1
  fi
  if ! awk -v want="$scanned" '$2 != "blob" { bad = 1 } END { exit bad || NR != want }' "$tmp/sizes"; then
    printf 'FAIL  content: a blob to scan is not in the store as a blob, or was not sized\n'
    exit 1
  fi
  # Each blob's first content byte and its size; the last line is the stream's whole length.
  awk '{ start = pos + length($1) + 6 + length($3) + 1; print $1, start, $3; pos = start + $3 + 1 }
       END { print "TOTAL", pos + 0 }' "$tmp/sizes" > "$tmp/table"
  if ! git cat-file --batch < "$tmp/scan" > "$tmp/stream"; then
    printf 'FAIL  content: git cat-file failed while reading the blobs to scan\n'
    exit 1
  fi
  expected=$(awk '$1 == "TOTAL" { print $2 }' "$tmp/table")
  read_bytes=$(wc -c < "$tmp/stream")
  count_of read_bytes 'bytes read'
  count_of expected 'bytes the blobs hold'
  if [ "$read_bytes" != "$expected" ]; then
    printf 'FAIL  content: the store gave %s bytes for blobs that hold %s, so a blob was not read whole\n' "$read_bytes" "$expected"
    exit 1
  fi

  # "<blob id> <matched text>" for every match of the pattern (grep MODE) in the stream;
  # non-zero where grep failed, where the table could not be read, or where a match falls
  # past the last blob, none of which is a stream that matched nothing. A match in the gap
  # between two blobs' contents (a record header, the separator) is in no blob, and only it
  # is set aside.
  matches_in_blobs() { # mode, pattern
    local rc=0
    grep -a -b -o "$1" -e "$2" "$tmp/stream" > "$tmp/hits" || rc=$?
    [ "$rc" -le 1 ] || return "$rc"
    awk -v table="$tmp/table" '
      BEGIN {
        while ((r = (getline line < table)) > 0) {
          split(line, f, " ")
          if (f[1] == "TOTAL") continue
          n++; id[n] = f[1]; first[n] = f[2] + 0; past[n] = f[2] + f[3]
        }
        if (r < 0 || n == 0) exit 2
        i = 1
      }
      {
        colon = index($0, ":")
        off = substr($0, 1, colon - 1) + 0
        while (i <= n && past[i] <= off) i++
        if (i > n) exit 3
        if (off >= first[i]) print id[i], substr($0, colon + 1)
      }' "$tmp/hits" || return $?
  }

  # The blobs a home root appears in, and those where some name after it is not a permitted
  # value. A name runs to the next `/`, space or punctuation mark other than `.`, `_` and `-`,
  # so one that opens with a byte outside ASCII is a name and not a bare root.
  home_tokens() { # root; writes $tmp/home-all and $tmp/home-unpermitted, blob ids
    local root="$1" rc=0
    matches_in_blobs -E "${root}([._-]|[^/[:space:][:punct:]])*" > "$tmp/tokens" || rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    # Called under `||`, where errexit does not apply: every step says when it failed.
    cut -d' ' -f1 "$tmp/tokens" | sort -u > "$tmp/home-all" || return 1
    printf '%s\n' "${PERMITTED_HOMES[@]}" > "$tmp/permitted" || return 1
    awk -v permitted="$tmp/permitted" '
      BEGIN { while ((r = (getline p < permitted)) > 0) ok[p] = 1; if (r < 0) exit 2 }
      { t = substr($0, index($0, " ") + 1); if (!(t in ok)) print $1 }' "$tmp/tokens" | sort -u > "$tmp/home-unpermitted" || return 1
  }

  scan_content() { # pattern, grep-mode-flags, label printed for the pattern
    local pat="$1" mode="$2" label="$3" n=0 f=0 l=0 o keys='' rc=0
    declare -A unpermitted=()
    if [ "$label" = "/home/" ] || [ "$label" = "/Users/" ]; then
      home_tokens "$pat" || rc=$?
      if [ "$rc" -eq 0 ]; then
        cp "$tmp/home-all" "$tmp/matched" || rc=1
        while read -r o; do unpermitted["$o"]=1; done < "$tmp/home-unpermitted"
      fi
    else
      matches_in_blobs "$mode" "$pat" > "$tmp/matched.raw" || rc=$?
      [ "$rc" -ne 0 ] || cut -d' ' -f1 "$tmp/matched.raw" | sort -u > "$tmp/matched" || rc=1
    fi
    if [ "$rc" -ne 0 ]; then
      bad "content: grep failed for '$label' (exit $rc), so which blobs match is unknown"
      return
    fi
    while read -r o; do
      [ -n "$o" ] || continue
      if { [ "$label" = "/home/" ] || [ "$label" = "/Users/" ]; } && [ -z "${unpermitted[$o]+x}" ]; then
        f=$((f + 1))
      elif [ -z "${reachable[$o]+x}" ]; then
        l=$((l + 1))
      else
        n=$((n + 1))
        keys+="content $o $label"$'\n'
      fi
    done < "$tmp/matched"
    [ "$f" -gt 0 ] && note "content: $f blob(s) match '$label' only as permitted values (${PERMITTED_HOMES[*]}) — guest data, or a bare /home/ naming nobody"
    [ "$l" -gt 0 ] && note "local-only (unreachable): $l blob(s) match '$label' — no ref reaches them, so no push or clone carries them; clear with: git reflog expire --expire=now --all && git gc --prune=now"
    if [ "$n" -eq 0 ]; then
      good "content: 0 reachable blobs match '$label', over $scanned blobs"
      return
    fi
    sort_findings <<<"$keys"
    [ "$taken" -gt 0 ] && printf "accept content: %s blob(s) match '%s', accepted by %s\n" "$taken" "$label" "$accepted_list"
    if [ "$unaccepted" -gt 0 ]; then
      bad "content: $unaccepted reachable blob(s) match '$label' and are not accepted, over $scanned blobs"
      printf '%s' "$listing"
    fi
  }
  for pat in "${PATH_PATTERNS[@]}"; do scan_content "$pat" -F "$pat"; done
  for ((i = 0; i < ${#PRIVATE_PATHS[@]}; i++)); do scan_content "${PRIVATE_PATHS[$i]}" -F "private path $((i + 1))"; done
  for ((i = 0; i < ${#PRIVATE_WORDS[@]}; i++)); do scan_content "\\b${PRIVATE_WORDS[$i]}\\b" -iE "private word $((i + 1))"; done
  rm -f "$tmp/stream" "$tmp/hits"
fi

# ------------------------------------------------- commit messages and identities
msgs=$(git log --all --format='%H' 2>/dev/null | wc -l)
count_of msgs 'commits'
if [ "$msgs" -eq 0 ]; then
  # Same distinction the reflog vector draws above, and for the same reason. Zero commits
  # has two causes and they are not alike: the instrument failed, which must fail closed,
  # or there is genuinely nothing yet to scan, which is the state of a repository whose
  # *first* commit is being created -- and a gate that cannot pass a first commit cannot
  # gate one. The tell is whether any ref exists at all. Without this, the pre-commit hook
  # refused the only commit of a freshly initialised repository, reporting an empty scan
  # over a tree in which every content check had just passed.
  if [ -n "$(git for-each-ref --format='%(refname)' 2>/dev/null)" ]; then
    bad "commit set is empty although a ref exists — the message scan examined nothing"
  else
    note "messages: no commits yet (a first commit is being created) — vector not exercised"
    note "messages: the pending message is not readable here; re-run the gate after committing"
  fi
else
  # Keyed by commit: each message is one record, its id on the first line, so a match names
  # the commit it is in. The id is hex and no pattern a gate would hold matches forty hex
  # digits between word boundaries. The records are git's NUL-terminated ones laid out as
  # plain lines, with a table of the line each record starts on, since macOS's sed has no `-z`
  # and POSIX grep none either. A match is a match within one line, as in the content scan,
  # and no pattern can span two (a word is letters, digits, `_` and `-`; a path holds no
  # space), so a record matches exactly where one of its lines does.
  scan_messages() { # pattern, grep-mode-flags, label printed for the pattern
    local pat="$1" mode="$2" label="$3" keys listing
    local rc=0
    # `-a` as in the content scan. No input found reaches this grep that its binary heuristic
    # would act on. Measured with git 2.55 and GNU grep 3.12:
    # - `git hash-object` refuses to write a commit whose body holds a NUL (`nulInCommit`);
    # - a NUL in the log's output (a repository's `i18n.logOutputEncoding=UTF-16`) splits
    #   the records, and the record count, checked before the scans run, fails the gate;
    # - a message committed with bytes outside UTF-8 reached the line file as UTF-8;
    # - under `LC_ALL=C` no byte is an encoding error.
    # So tests/leak_gate.rs holds the content scan's `-a`, and nothing holds this one.
    grep -a -n "$mode" -e "$pat" "$tmp/message-lines" > "$tmp/matched" || rc=$?
    if [ "$rc" -gt 1 ]; then
      bad "messages: grep failed for '$label' (exit $rc), so which commits match is unknown"
      return
    fi
    # Each matched line number to the commit whose record holds it. Both lists ascend, so one
    # walk maps them; a table that could not be read, or a line before the first record, is a
    # failure and not a commit that matched nothing.
    rc=0
    keys=$(awk -v table="$tmp/message-starts" '
      BEGIN {
        while ((r = (getline line < table)) > 0) { split(line, f, " "); n++; start[n] = f[1]; id[n] = f[2] }
        if (r < 0 || n == 0) exit 2
        k = 1
      }
      {
        at = substr($0, 1, index($0, ":") - 1) + 0
        while (k < n && start[k + 1] <= at) k++
        if (at < start[k]) exit 2
        print id[k]
      }' "$tmp/matched") || rc=$?
    if [ "$rc" -ne 0 ]; then
      bad "messages: the matches for '$label' could not be mapped to their commits, so which commits match is unknown"
      return
    fi
    keys=$(sed "/^$/d; s|^|message |; s|\$| $label|" <<<"$keys" | sort -u)
    if [ -z "$keys" ]; then
      good "messages: 0 commits match '$label', over $msgs commits"
      return
    fi
    sort_findings <<<"$keys"
    [ "$taken" -gt 0 ] && printf "accept messages: %s commit(s) match '%s', accepted by %s\n" "$taken" "$label" "$accepted_list"
    if [ "$unaccepted" -gt 0 ]; then
      bad "messages: $unaccepted commit(s) match '$label' and are not accepted, over $msgs commits — messages publish with the commits"
      printf '%s' "$listing"
    fi
  }
  if ! git log --all -z --format='%H%n%s%n%b' > "$tmp/messages"; then
    printf 'FAIL  messages: git log failed, so the messages a push carries are unknown\n'
    exit 1
  fi
  # One record at a time: the record is split into the lines it is written as (mapfile, in one
  # pass; a newline count by pattern substitution takes time quadratic in the message), and
  # its first is the id. Each record ends in a NUL; one that does not (the last, were git to
  # drop its terminator) is still read. The records are checked against the commits listed
  # above and the table's lines against the line file's, so a stream read short or a table
  # out of step fails rather than leaving commits unscanned or misnamed.
  records=0 line=1
  while IFS= read -r -d '' rec || [ -n "$rec" ]; do
    mapfile -t rec_lines <<<"$rec"
    printf '%s\n' "$rec" >&3
    printf '%s %s\n' "$line" "${rec_lines[0]}" >&4
    line=$((line + ${#rec_lines[@]}))
    records=$((records + 1))
  done < "$tmp/messages" 3> "$tmp/message-lines" 4> "$tmp/message-starts"
  if [ "$records" -ne "$msgs" ]; then
    printf 'FAIL  messages: %s message record(s) read for %s commits listed, so which messages were scanned is unknown\n' "$records" "$msgs"
    exit 1
  fi
  written=$(wc -l < "$tmp/message-lines")
  count_of written 'message lines'
  if [ "$written" -ne $((line - 1)) ]; then
    printf 'FAIL  messages: the line file holds %s lines where its table accounts for %s, so a match could be named for the wrong commit\n' "$written" $((line - 1))
    exit 1
  fi
  for pat in "${PATH_PATTERNS[@]}"; do scan_messages "$pat" -F "$pat"; done
  for ((i = 0; i < ${#PRIVATE_PATHS[@]}; i++)); do scan_messages "${PRIVATE_PATHS[$i]}" -F "private path $((i + 1))"; done
  for ((i = 0; i < ${#PRIVATE_WORDS[@]}; i++)); do scan_messages "\\b${PRIVATE_WORDS[$i]}\\b" -iE "private word $((i + 1))"; done
  # Identities, checked rather than displayed: host detail is refused "in tracked files, in
  # commit messages and in author identities alike". A block that counted the distinct
  # addresses, printed them and called `good` would pass a commit authored at an address
  # under a development host's name with that name in the word list.
  #
  # `%an` and `%cn` as well as the addresses: a machine name reaches a commit through
  # whichever of the four git happens to derive from the host.
  scan_identities() { # pattern, grep-mode-flags, label printed for the pattern
    local pat="$1" mode="$2" label="$3" n rc=0
    n=$(grep -a "$mode" -c -e "$pat" "$tmp/identities") || rc=$?
    if [ "$rc" -gt 1 ]; then
      bad "identities: grep failed for '$label' (exit $rc), so which identities match is unknown"
      return
    fi
    if [ "${n:-0}" -eq 0 ]; then
      good "identities: 0 match '$label', over $ids distinct"
    else
      bad "identities: $n match '$label' — an identity publishes with every commit it signs"
    fi
  }
  if ! git log --all --format='%ae%n%ce%n%an%n%cn' > "$tmp/identities.raw"; then
    printf 'FAIL  identities: git log failed, so the identities a push carries are unknown\n'
    exit 1
  fi
  sort -u "$tmp/identities.raw" > "$tmp/identities"
  ids=$(wc -l < "$tmp/identities")
  count_of ids 'identities'
  if [ "$ids" -eq 0 ]; then
    bad "identity set is empty — the identity scan examined nothing"
  else
    for pat in "${PATH_PATTERNS[@]}"; do scan_identities "$pat" -F "$pat"; done
    for ((i = 0; i < ${#PRIVATE_PATHS[@]}; i++)); do scan_identities "${PRIVATE_PATHS[$i]}" -F "private path $((i + 1))"; done
    for ((i = 0; i < ${#PRIVATE_WORDS[@]}; i++)); do scan_identities "\\b${PRIVATE_WORDS[$i]}\\b" -iE "private word $((i + 1))"; done
    git log --all --format='%ae%n%ce' | sort -u | sed 's/^/    /'
  fi
fi

# --------------------------------------------- rules that exist on one machine only
# A rule in .git/info/exclude or core.excludesFile keeps a path out of one checkout's
# `git status` and out of nothing else: not committed, not cloned, absent in CI. So a
# fresh clone has no rule, this gate has no rule, and the first `git add -A` by anyone
# else commits the path. It is invisible in the direction a reviewer looks, because the
# reviewer's own tooling agrees with the maintainer's.
excludes_file=$(git config --get core.excludesFile || true)
if [ -n "$excludes_file" ]; then
  bad "core.excludesFile is set ($excludes_file) — boundary rules there are not cloned and not in CI"
else
  good "core.excludesFile: unset"
fi

# `grep -c` prints its count *and* exits 1 on no match, which is the passing case; above 1
# it could not read the file, and the count it printed would be a clean-looking 0. A
# repository made without git's templates has no exclude file, which is no rule. A file
# counts as absent only where the nearest existing path above it is a directory that can be
# searched. Behind one that cannot be searched, `[ -e ]` is false even for a file that is
# there.
#
# The path is git's, not `.git/info/exclude`: in a linked worktree `.git` is a file, so that
# path does not exist, the read failed, and the gate printed 0 rules there whatever the
# repository's exclude file held. `--git-path` names the one file every worktree
# of the repository reads.
info_exclude=$(git rev-parse --git-path info/exclude)
info_rules=0 exclude_rc=0
above=${info_exclude%/*}
while [ ! -e "$above" ] && [ ! -L "$above" ] && [ "$above" != "${above%/*}" ]; do above=${above%/*}; done
if [ -e "$info_exclude" ] || [ -L "$info_exclude" ]; then
  info_rules=$(grep -cvE '^[[:space:]]*(#|$)' "$info_exclude" 2>/dev/null) || exclude_rc=$?
fi
if ! { [ -e "$info_exclude" ] || [ -L "$info_exclude" ]; } && ! { [ -d "$above" ] && [ -x "$above" ]; }; then
  bad "info/exclude: whether $info_exclude exists cannot be told ($above is not a directory that can be searched), so its rules are unknown"
elif [ "$exclude_rc" -gt 1 ]; then
  bad "info/exclude: $info_exclude could not be read (grep exit $exclude_rc), so its rules are unknown"
elif [ "$info_rules" -gt 0 ]; then
  bad "info/exclude has $info_rules rule(s) — move any boundary rule into the tracked .gitignore with its reason"
else
  good "info/exclude: 0 rules"
fi

# ----------------------------------------------------------- the list itself
# Sorted, so two runs over one graph print one text.
while IFS= read -r key; do
  [ -n "$key" ] || continue
  [ "${accepted[$key]}" = used ] && continue
  read -r _ id label <<<"$key"
  # A line for a private pattern this run did not load (no list here, or a shorter one)
  # cannot match: it is noted, as a line for an object this clone lacks is, not failed as
  # stale. Without this a checkout with no list (a worktree, a fresh clone, a public CI)
  # would fail on the accepted message line.
  if [[ "${label:-}" =~ ^private\ (word|path)\ ([0-9]+)$ ]]; then
    loaded=${#PRIVATE_WORDS[@]}
    [ "${BASH_REMATCH[1]}" = word ] || loaded=${#PRIVATE_PATHS[@]}
    if [ "${BASH_REMATCH[2]}" -gt "$loaded" ]; then
      note "accepted: '$key' names a private pattern this run did not load, so it is not checked here"
      continue
    fi
  fi
  if git cat-file -e "$id" 2>/dev/null; then
    bad "accepted: '$key' matches no finding, so the list is stale; remove the line"
  else
    note "accepted: '$key' names an object this clone does not hold (a ref it lacks), so it is not checked here"
  fi
done < <(printf '%s\n' "${!accepted[@]}" | sort)

# The last line says what was not scanned as well as the verdict, because it is the line a
# reader of a CI log or a hook's output sees, and a bare "passed" over a run that skipped the
# private names would read as a scan that looked for them.
#
# Without a list the exit status is still 0, and that is a named limit, not an oversight:
# the hooks, `make check` and a public CI read only the status, so in a fresh clone, in a
# CI not handed a list, in a worktree that has no copy, and after `git clean -x`, the host-name scan does not run and
# nothing but this line says so. Failing there instead would fail every clone but the
# developer's own, CI among them, and a CI that held the list to pass would hand it to the
# CI provider. So the scan is enforced where the names are: a merge reads the gate's output
# for the `private patterns: N from` line, and a checkout that publishes keeps its list. The
# limit lasts as long as the list is private by design; a gate given a way to scan for the
# names without holding them would retire it.
unscanned=''
if [ "$private_present" -eq 0 ]; then
  unscanned="; private patterns: not scanned, no list at $private_list"
fi
[ "$accepted_hits" -eq 0 ] || unscanned="$unscanned; $accepted_hits finding(s) accepted by $accepted_list"
[ -z "$not_exercised" ] || unscanned="$unscanned; not exercised: $not_exercised"
printf '\n'
if [ "$fail" -ne 0 ]; then
  printf 'leak gate FAILED — this tree is not publishable as it stands%s\n\n' "$unscanned"
  exit 1
fi
printf 'leak gate passed%s\n\n' "$unscanned"
