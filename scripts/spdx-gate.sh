#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# Every tracked text file carries an SPDX licence identifier in its first five lines, or is
# of a kind named below that cannot carry one, each kind with its reason and its count.
#
# The identifier is a line of its own: a comment leader or none, the identifier, one of the
# licences in LICENCES, and a comment closer or none. A mention of the phrase in prose, an
# empty value, or a licence this repository does not use is not a header. LICENCES is
# BSD-3-Clause, the crate's licence (`Cargo.toml`, `LICENSE`), and CC-BY-SA-4.0, which
# CODE_OF_CONDUCT.md alone carries, adapted from a text under it; a file under another licence
# is a decision for a person, made here.
#
# Tracked means the index, the set a commit holds, and text is git's own reading of each
# file there (`git ls-files --eol`): the gate reads what a clone receives, not what lies in
# this checkout. Each kind and the total are printed with their counts, and a tracked set
# that came back empty fails, for the reason the leak gate gives (a check that scans nothing
# exits 0).

set -euo pipefail

# Outside a clone there is no tracked set to read: a tarball from `git archive` or a crate
# archive holds the files and not the index. The gate says so and exits 0, a skip and not a
# pass, so `make check` runs to its end from one; the same inside another repository's work
# tree, whose index is not this tree's. A tree holding a `.git` that git cannot read fails.
# The leak gate opens the same way (`scripts/leak-gate.sh`).
here=$(cd "$(dirname "$0")/.." && pwd -P)
if ! top=$(git -C "$here" rev-parse --show-toplevel 2>/dev/null); then
  if [ -e "$here/.git" ] || [ -L "$here/.git" ]; then
    printf 'FAIL  spdx gate: this tree holds a .git that git cannot read, so its tracked set is unknown\n'
    exit 1
  fi
  printf 'spdx gate skipped: this tree is not a git work tree (a tarball or a crate archive), so there is no tracked set to read; it runs in a clone\n'
  exit 0
fi
if [ "$(cd "$top" && pwd -P)" != "$here" ]; then
  printf "spdx gate skipped: this tree sits inside another repository's work tree, whose tracked set is not this tree's; it runs in a clone\n"
  exit 0
fi
cd "$here"

# The kinds that cannot carry a header, by path. A path that matches no kind and holds no
# identifier fails. A new kind goes here with its reason, never as one more file name.
exempt_kind() { # path -> kind, or nothing
  case "$1" in
    # JSON has no comment syntax; a key would change the document a test, a schema or a
    # reader holds byte for byte.
    *.json) echo json ;;
    # A fuzz seed is the input its target reads, byte for byte; a header would be a
    # different input.
    fuzz/seeds/*) echo fuzz-seed ;;
    # A kept crash is the same: the input `fuzz-replay` reruns, minimised. Its `.note`
    # beside it is prose and carries an identifier like any other file.
    fuzz/crashes/*.note) ;;
    fuzz/crashes/*) echo fuzz-crash ;;
    # cargo writes the lockfile whole on every resolve, and keeps no comment of ours.
    Cargo.lock) echo lockfile ;;
    # The licence text itself, which the identifiers elsewhere point to.
    LICENSE) echo licence-text ;;
  esac
}

LICENCES='BSD-3-Clause|CC-BY-SA-4.0'
header_line="^[[:space:]]*(#|//|/\\*|<!--)?[[:space:]]*SPDX-License-Identifier: (${LICENCES})[[:space:]]*(\\*/|-->)?[[:space:]]*\$"

# The listing is taken whole before it is read, so a git that fails stops the gate under
# `set -e` rather than handing the loop a short list it would scan as if complete; and its
# entries are counted against a second, independent listing of the index.
listing=$(mktemp)
trap 'rm -f "$listing"' EXIT
git ls-files --eol -z > "$listing"
expected=$(git ls-files -z | tr -cd '\0' | wc -c)

declare -A kinds=()
tracked=0 binary=0 empty=0 exempt=0 carry=0 lacking=()
while IFS= read -r -d '' entry; do
  path=${entry#*$'\t'}
  index_eol=${entry%% *}
  tracked=$((tracked + 1))
  # `i/-text` is git's binary; `i/none` is text with no line ending, which still needs one.
  if [ "$index_eol" = i/-text ]; then binary=$((binary + 1)); continue; fi
  if [ "$(git cat-file -s ":$path")" -eq 0 ]; then empty=$((empty + 1)); continue; fi
  # Read through a process substitution and not a pipe, for the reason the leak gate's
  # `scan_content` gives: under `pipefail`, `head` closing the pipe early makes git's
  # SIGPIPE the pipeline's status, and a file carrying the identifier read as one lacking it.
  first=$(head -n 5 < <(git cat-file blob ":$path"))
  if grep -Eq "$header_line" <<<"$first"; then
    carry=$((carry + 1))
    continue
  fi
  kind=$(exempt_kind "$path")
  if [ -n "$kind" ]; then
    kinds[$kind]=$(( ${kinds[$kind]:-0} + 1 ))
    exempt=$((exempt + 1))
  else
    lacking+=("$path")
  fi
done < "$listing"

printf '\nspdx gate: licence identifiers over the tracked set\n\n'
if [ "$tracked" -eq 0 ]; then
  printf 'FAIL  the tracked set is empty: the gate read nothing, which is not a pass\n'
  exit 1
fi
if [ "$tracked" -ne "$expected" ]; then
  printf 'FAIL  the gate read %d entries where the index lists %d, so the listing it scanned was not the tracked set\n' "$tracked" "$expected"
  exit 1
fi
text=$((tracked - binary - empty))
printf '  %d tracked: %d binary by git'"'"'s reading, %d empty, %d text\n' "$tracked" "$binary" "$empty" "$text"
printf '  %d text files carry an identifier (%s) in their first five lines\n' "$carry" "${LICENCES//|/ or }"
for kind in $(printf '%s\n' "${!kinds[@]}" | sort); do
  printf '  %d %s file(s) cannot carry one\n' "${kinds[$kind]}" "$kind"
done
if [ "${#lacking[@]}" -gt 0 ]; then
  for path in "${lacking[@]}"; do printf 'FAIL  %s has no SPDX-License-Identifier line naming %s in its first five lines\n' "$path" "${LICENCES//|/ or }"; done
  printf '\nspdx gate FAILED: %d of %d text files lack an identifier\n\n' "${#lacking[@]}" "$text"
  exit 1
fi
printf '\nspdx gate passed\n\n'
