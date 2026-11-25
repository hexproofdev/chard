#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# shell-gate.sh: the house shell gate, run from a repository's root.
#
# Finds every tracked shell script (a .sh or .bash name, or a first line that is a sh, bash, dash
# or ksh shebang; Jinja templates, *.j2, are not shell until rendered and are skipped), then:
#   files:      an executable file starts with `#!`; a .sh/.bash file without one declares its
#               dialect on a `# shellcheck shell=...` line (a sourced library)
#   lint:       every script through shellcheck, every severity, under the repository's
#               .shellcheckrc (the house file)
#   format:     every script unchanged under shfmt -i 2 -ci -bn
# Prints the frame (tool versions, scripts fed) and each finding; exit 0 clean, 1 findings,
# 3 cannot run. Needs: git, shellcheck, shfmt.
set -eu

command -v git >/dev/null 2>&1 || {
  echo "shell-gate: git is not installed" >&2
  exit 3
}
command -v shellcheck >/dev/null 2>&1 || {
  echo "shell-gate: shellcheck is not installed" >&2
  exit 3
}
command -v shfmt >/dev/null 2>&1 || {
  echo "shell-gate: shfmt is not installed" >&2
  exit 3
}
[ -f .shellcheckrc ] || {
  echo "shell-gate: no .shellcheckrc at the repository root" >&2
  exit 3
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM

# Tracked files with their mode; paths with a newline are not supported.
git ls-files -s | awk '{ m = $1; sub(/^[^\t]*\t/, ""); print m "\t" $0 }' >"$T/tracked"
: >"$T/scripts"
: >"$T/findings"
while IFS="$(printf '\t')" read -r mode f; do
  [ -f "$f" ] || continue
  case $f in *.j2) continue ;; *) ;; esac
  first=$(head -n 1 "$f" 2>/dev/null | tr -d '\000') || first=
  byname=0
  case $f in *.sh | *.bash) byname=1 ;; *) ;; esac
  bang=0
  case $first in '#!'*) bang=1 ;; *) ;; esac
  shell=0
  if [ $byname -eq 1 ]; then
    shell=1
  elif printf '%s\n' "$first" | grep -Eq '^#!.*(/|env )(ba|da|k)?sh( |$)'; then
    shell=1
  fi
  if [ "$mode" = 100755 ] && [ $bang -eq 0 ]; then
    echo "files: $f is executable but has no #! line" >>"$T/findings"
  fi
  [ $shell -eq 1 ] || continue
  if [ $bang -eq 0 ] && ! grep -Eq '^# shellcheck shell=(sh|bash|dash|ksh)' "$f"; then
    echo "files: $f has no #! line and no '# shellcheck shell=' line" >>"$T/findings"
  fi
  printf '%s\n' "$f" >>"$T/scripts"
done <"$T/tracked"

fed=$(wc -l <"$T/scripts" | tr -d ' ')
echo "shell-gate: $(shellcheck --version | sed -n 's/^version: /shellcheck /p'), shfmt $(shfmt --version); scripts fed: $fed"

if [ "$fed" -gt 0 ]; then
  tr '\n' '\0' <"$T/scripts" | xargs -0 shellcheck -S style -f gcc >"$T/sc" 2>&1 || true
  sed 's/^/shellcheck: /' "$T/sc" >>"$T/findings"
  tr '\n' '\0' <"$T/scripts" | xargs -0 shfmt -i 2 -ci -bn -l >"$T/fmt" 2>&1 || true
  sed 's/^/shfmt: needs formatting (shfmt -i 2 -ci -bn -w): /' "$T/fmt" >>"$T/findings"
fi

n=$(wc -l <"$T/findings" | tr -d ' ')
if [ "$n" -eq 0 ]; then
  echo "shell-gate: GREEN"
  exit 0
fi
cat "$T/findings"
echo "shell-gate: RED ($n findings)"
exit 1
