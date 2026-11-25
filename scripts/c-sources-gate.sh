#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# c-sources-gate.sh: every tracked C or C++ source is under a prefix .lints/c/exclude names.
#
# The house standard has a C and C++ lint gate, and this tree runs none: its C is probe and
# fixture code whose findings are often what a check reads. The exclusion is by path prefix,
# so a source added anywhere else would be linted by nothing. This fails on such a source and
# names it: lint it, or add its prefix to the list with a reason. It fails on a prefix that
# excludes nothing too, so the list does not outlive what it was written for.
#
# Reads the names git tracks ending .c, .h, .cc, .cpp, .cxx, .hpp, .hh, .hxx or .ino, at any
# depth, and .lints/c/exclude, as the house C gate reads them: the list is that gate's file. A
# prefix is the first word of a line that is neither blank nor a comment, and a line with no
# reason after its prefix fails, as it fails that gate. It reads names, not contents: C in a
# file of another name is not seen.
#
# Usage: scripts/c-sources-gate.sh, from the tree's root (`make lints` runs it). Exit 0 where
# every source is under a prefix and every prefix holds one, 1 where not or where a line has no
# reason, 2 where the list or the tracked tree cannot be read.
set -eu

list=.lints/c/exclude
[ -f "$list" ] || {
  echo "c-sources: no $list" >&2
  exit 2
}
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "c-sources: not inside a git work tree, so the tracked sources cannot be listed" >&2
  exit 2
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM

awk '!/^[[:space:]]*(#|$)/ { print $1 }' "$list" >"$T/prefixes"
awk '!/^[[:space:]]*(#|$)/ && NF < 2' "$list" >"$T/unreasoned"
if [ -s "$T/unreasoned" ]; then
  echo "c-sources: lines of $list with no reason after the path:" >&2
  sed 's/^/  /' "$T/unreasoned" >&2
  exit 1
fi
# NUL-separated, so git quotes no name: a quoted one would end in a quote and match no suffix.
# Not held, each a name made so on purpose: a name holding a newline reads as two names, and
# passes where the second lies under a listed prefix; and under the caller's locale, grep may
# read a name that is not valid UTF-8 as binary and drop it.
git ls-files -z >"$T/tracked0" || {
  echo "c-sources: git cannot list the tracked files" >&2
  exit 2
}
tr '\0' '\n' <"$T/tracked0" >"$T/tracked"
grep -E '\.(c|h|cc|cpp|cxx|hpp|hh|hxx|ino)$' "$T/tracked" >"$T/sources" || :

# A source under no prefix, then a prefix over no source. Each awk tells its two files apart by
# name, not by `NR == FNR`, which reads the second file as the first where the first is empty.
awk 'FILENAME == ARGV[1] { prefix[$0]; next }
  { for (p in prefix) if (index($0, p) == 1) next; print }' "$T/prefixes" "$T/sources" >"$T/outside"
awk 'FILENAME == ARGV[1] { source[$0]; next }
  { for (s in source) if (index(s, $0) == 1) next; print }' "$T/sources" "$T/prefixes" >"$T/unused"

rc=0
if [ -s "$T/outside" ]; then
  echo "c-sources: C or C++ sources under no prefix of $list (lint them, or add the prefix with its reason):" >&2
  sed 's/^/  /' "$T/outside" >&2
  rc=1
fi
if [ -s "$T/unused" ]; then
  echo "c-sources: prefixes of $list that no tracked C or C++ source is under:" >&2
  sed 's/^/  /' "$T/unused" >&2
  rc=1
fi
[ "$rc" -eq 0 ] || exit "$rc"
echo "c-sources: $(wc -l <"$T/sources" | tr -d ' ') tracked C and C++ sources, each under one of the $(wc -l <"$T/prefixes" | tr -d ' ') prefixes of $list"
