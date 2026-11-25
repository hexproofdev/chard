#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# lints-gate.sh: the repository side of the house lint standard. Run from the repository root
# (a git checkout) as `sh .lints/std/lints-gate.sh`; `make lints` calls it, and `make check`
# calls `make lints`. It does not run clippy: the Makefile's clippy target does that.
#
# Reads .lints/standard, one directive a line ('#' starts a comment):
#   version V                 the VERSION that the copy in .lints/std must carry
#   sha256 H                  sha256 of .lints/std/SHA256SUMS at the standard's commit pinned
#   workspace DIR TIER...     DIR/Cargo.toml carries a [workspace.lints] block for these tiers,
#                             DIR/clippy.toml is generated, and every member inherits
#   package DIR TIER...       a single package: a [lints] block in DIR/Cargo.toml
#   crate FILE TIER...        a crate root that adds tiers as #![deny] lines (assemble.sh attr)
#   exempt PREFIX REASON...   tracked paths outside the standard (fixtures, vendored code)
# A workspace's own extras live in .lints/local/<DIR, / as _, . as root>/local.{lints,clippy,...}.
# .lints/unsafe-allowlist names, one a line, the files allowed to carry expect(unsafe_code).
#
# Checks, each printed with what it read:
#   copy       .lints/std matches its SHA256SUMS, which matches the pinned sha256 and version
#   drift      every generated block or file equals assemble.sh's output
#   inherit    every tracked Cargo.toml is a workspace member that sets [lints] workspace = true,
#              a declared workspace root or package, or exempt: nothing goes unlinted unseen
#   allowances no outer #[allow(...)] (clippy::allow_attributes covers only what it compiles);
#              an inner #![allow(..., reason = "...")] only first inside a #[cfg(test)] module or
#              at the head of a tests/ or benches/ file; #![cfg_attr(test, allow(..., reason))]
#              anywhere, since the non-test build still lints the same code
#   flags      no --cap-lints, -A or --allow in a .cargo/config(.toml) in or above a declared
#              directory (targets, linker flags and build-std are fine), and none of them nor a
#              clippy -A in a non-comment line of a tracked Makefile, .mk or .sh
#   unsafe     the files carrying expect(unsafe_code) equal the allowlist, and if any do, some
#              workspace, package or crate line selects the unsafe tier
# Exit 0 clean, 1 a finding, 3 the gate could not run.
set -eu

STD=.lints/std
CONF=.lints/standard
cannot() {
  printf 'lints-gate: cannot run: %s\n' "$*" >&2
  exit 3
}
[ -e .git ] || cannot "not at a git checkout's root"
[ -f "$CONF" ] || cannot "no $CONF"
[ -f "$STD/assemble.sh" ] || cannot "no $STD/assemble.sh (copy the standard's rust/lints/ into $STD)"
for t in git awk sha256sum cargo jq cmp diff comm; do command -v $t >/dev/null 2>&1 || cannot "$t is not installed"; done

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM
: >"$T/bad"
# finding: print one indented line and mark the run red (works inside a pipeline's subshell).
finding() {
  printf '  %s\n' "$*"
  echo x >>"$T/bad"
}
directives() { sed -e 's/#.*$//' -e '/^[[:space:]]*$/d' "$CONF"; }
localdir() {
  s=$(printf '%s' "$1" | sed -e 's|^\./||' -e 's|/$||' -e 's|/|_|g')
  if [ -z "$s" ] || [ "$s" = . ]; then s=root; fi
  printf '.lints/local/%s' "$s"
}
directives | awk '$1 == "exempt" { print $2 }' >"$T/exempt"
exempt() {
  while read -r p; do case $1 in "$p"*) return 0 ;; *) ;; esac done <"$T/exempt"
  return 1
}

# --- copy -------------------------------------------------------------------------------------
echo "copy:"
want_ver=$(directives | awk '$1 == "version" { print $2 }')
want_sha=$(directives | awk '$1 == "sha256" { print $2 }')
[ -n "$want_ver" ] && [ -n "$want_sha" ] || cannot "$CONF needs a version line and a sha256 line"
have_ver=$(grep -v "^#" "$STD/VERSION" | head -n 1)
[ "$have_ver" = "$want_ver" ] || finding "$STD/VERSION is $have_ver; $CONF pins $want_ver"
have_sha=$(sha256sum "$STD/SHA256SUMS" | awk '{ print $1 }')
[ "$have_sha" = "$want_sha" ] || finding "$STD/SHA256SUMS hashes to $have_sha; $CONF pins $want_sha"
if ! (cd "$STD" && grep -v "^#" SHA256SUMS | sha256sum --quiet --strict -c -) >"$T/sums" 2>&1; then
  finding "files in $STD differ from its SHA256SUMS:"
  sed 's/^/    /' "$T/sums"
fi
echo "  $(grep -c -v "^#" "$STD/SHA256SUMS") files against SHA256SUMS; version $have_ver"

# --- drift ------------------------------------------------------------------------------------
echo "drift:"
block() { awk '/^(#|\/\/) BEGIN house lint standard/ { p = 1 } p { print } /^(#|\/\/) END house lint standard/ { p = 0 }' "$1"; }
compare() { # LABEL WANT HAVE
  echo x >>"$T/ndrift"
  if ! cmp -s "$2" "$3"; then
    finding "$1 differs from the standard's text (regenerate with assemble.sh; edit .lints/, not the output):"
    diff "$2" "$3" | sed -n '1,12p' | sed 's/^/    /'
  fi
}
: >"$T/ndrift"
directives | while read -r kind dir rest; do
  case $kind in
    workspace | package)
      ld=$(localdir "$dir")
      lopt=''
      [ -d "$ld" ] && lopt="--local $ld"
      popt=''
      [ "$kind" = package ] && popt=--package
      # shellcheck disable=SC2086 # options and tiers split on purpose
      if ! sh "$STD/assemble.sh" cargo $popt $lopt $rest >"$T/want"; then
        finding "assemble.sh refused $dir's tiers"
        continue
      fi
      block "$dir/Cargo.toml" >"$T/have"
      compare "$dir/Cargo.toml's lint block" "$T/want" "$T/have"
      # shellcheck disable=SC2086
      if ! sh "$STD/assemble.sh" clippy $lopt $rest >"$T/want"; then
        finding "assemble.sh refused $dir's clippy tiers"
        continue
      fi
      if [ -f "$dir/clippy.toml" ]; then compare "$dir/clippy.toml" "$T/want" "$dir/clippy.toml"; else finding "$dir/clippy.toml is missing"; fi
      if [ -f "$dir/.clippy.toml" ]; then finding "$dir/.clippy.toml exists: clippy reads it instead of the generated clippy.toml"; fi
      ;;
    crate)
      # shellcheck disable=SC2086
      if ! sh "$STD/assemble.sh" attr $rest >"$T/want"; then
        finding "assemble.sh refused $dir's crate tiers"
        continue
      fi
      block "$dir" >"$T/have"
      compare "$dir's crate-root block" "$T/want" "$T/have"
      ;;
    version | sha256 | exempt) ;;
    *) finding "$CONF: unknown directive: $kind" ;;
  esac
done
echo "  $(wc -l <"$T/ndrift" | tr -d ' ') generated texts compared"

# --- inherit ----------------------------------------------------------------------------------
echo "inherit:"
top=$(git rev-parse --show-toplevel)
: >"$T/covered"
directives | while read -r kind dir _; do
  rel=$(printf '%s/Cargo.toml' "$dir" | sed 's|^\./||')
  case $kind in
    workspace)
      printf '%s\n' "$rel" >>"$T/covered"
      if ! cargo metadata --locked --no-deps --format-version 1 --manifest-path "$dir/Cargo.toml" >"$T/meta" 2>"$T/metaerr"; then
        finding "cargo metadata failed for $dir:"
        sed -n '1,5p' "$T/metaerr" | sed 's/^/    /'
        continue
      fi
      jq -r '.workspace_members as $m | .packages[] | select(.id as $i | $m | index($i)) | .manifest_path' "$T/meta" >"$T/members"
      [ -s "$T/members" ] || finding "$dir has no workspace members"
      while read -r m; do
        mrel=${m#"$top"/}
        printf '%s\n' "$mrel" >>"$T/covered"
        if ! awk '/^\[lints\]/ { l = 1; next } /^\[/ { l = 0 } l && /^workspace[ \t]*=[ \t]*true/ { f = 1 } END { exit !f }' "$m"; then
          finding "$mrel does not set [lints] workspace = true"
        fi
      done <"$T/members"
      ;;
    package) printf '%s\n' "$rel" >>"$T/covered" ;;
    *) ;; # the other directives are not workspaces
  esac
done
n=0
for m in $(git ls-files 'Cargo.toml' '*/Cargo.toml'); do
  n=$((n + 1))
  grep -qxF -- "$m" "$T/covered" && continue
  exempt "$m" && continue
  finding "$m is tracked, but no workspace, package or exempt line covers it"
done
echo "  $n tracked manifests; $(sort -u "$T/covered" | wc -l | tr -d ' ') covered; $(wc -l <"$T/exempt" | tr -d ' ') exempt prefixes"

# --- allowances -------------------------------------------------------------------------------
echo "allowances:"
n=0
for f in $(git ls-files '*.rs'); do
  exempt "$f" && continue
  n=$((n + 1))
  testfile=0
  case /$f in */tests/* | */benches/*) testfile=1 ;; *) ;; esac
  awk -v f="$f" -v testfile="$testfile" '
	# One attribute at a time, joined across lines. State: whether the last code line opened a
	# #[cfg(test)] module (so only attributes may follow), and whether any code line has been seen.
	function judge(a, ln) {
		if (a !~ /allow[ \t]*\(/) return
		if (a !~ /^#![ \t]*\[/) { printf "  %s:%d: outer allow; write #[expect(lint, reason = \"...\")]\n", f, ln; bad = 1; return }
		if (a !~ /reason[ \t]*=[ \t]*"[^"]+"/) { printf "  %s:%d: inner allow without a reason\n", f, ln; bad = 1; return }
		if (a ~ /cfg_attr[ \t]*\([ \t]*test[ \t]*,/) return
		if (in_test_head) return
		if (testfile && !seen_code) return
		printf "  %s:%d: inner allow outside a #[cfg(test)] module head or a tests/ file head\n", f, ln; bad = 1
	}
	{
		line = $0; sub(/^[ \t]+/, "", line)
		if (acc != "") { acc = acc " " line; if (line ~ /\][ \t]*$/) { judge(acc, start); acc = "" }; next }
		if (line == "" || line ~ /^\/\//) next
		if (line ~ /^#!?[ \t]*\[/) {
			if (line ~ /\][ \t]*$/) judge(line, NR); else { acc = line; start = NR }
			if (line ~ /^#[ \t]*\[[ \t]*cfg[ \t]*\([ \t]*test[ \t]*\)[ \t]*\]/) pending_test = 1
			next
		}
		if (pending_test && line ~ /^(pub(\([a-z]+\))?[ \t]+)?mod[ \t]+[A-Za-z_0-9]+[ \t]*\{[ \t]*$/) { in_test_head = 1; pending_test = 0; seen_code = 1; next }
		pending_test = 0; in_test_head = 0; seen_code = 1
	}
	END { exit bad }
	' "$f" || echo x >>"$T/bad"
done
echo "  $n Rust files read"

# --- flags ------------------------------------------------------------------------------------
echo "flags:"
directives | while read -r kind dir _; do
  case $kind in workspace | package)
    d=$dir
    while :; do
      # A cargo config may carry targets, linker flags and build-std; it may not lower a lint.
      for c in "$d/.cargo/config.toml" "$d/.cargo/config"; do
        [ -e "$c" ] || continue
        grep -n -E -- '--cap-lints|"-A|"--allow|"-W[[:space:]]*"|RUSTFLAGS' "$c" 2>/dev/null \
          | grep -v -E '^[0-9]+:[[:space:]]*#' >"$T/chits" || true
        while read -r h; do finding "$c:$h  (a local cargo config lowers a lint level)"; done <"$T/chits"
      done
      [ "$d" = . ] && break
      d=$(dirname "$d")
    done
    ;;
  *) ;; # crate, exempt, version and sha256 lines carry no cargo config
  esac
done
for f in $(git ls-files 'Makefile' '*/Makefile' '*.mk' '*.sh'); do
  case $f in "$STD"/*) continue ;; *) ;; esac
  exempt "$f" && continue
  # Comment lines are skipped: a Makefile that explains why it clears RUSTFLAGS is not a hit.
  grep -n -E -- '--cap-lints|clippy[^#]*-- [^#]*(-A|--allow)[ =]|RUSTFLAGS[^#]*-A' "$f" 2>/dev/null \
    | grep -v -E '^[0-9]+:[[:space:]]*#' >"$T/hits" || true
  while read -r h; do finding "$f:$h  (lowers a lint level outside the standard)"; done <"$T/hits"
done
echo "  done"

# --- unsafe -----------------------------------------------------------------------------------
echo "unsafe:"
git grep -l -E 'expect[[:space:]]*\([^)]*unsafe_code' -- '*.rs' 2>/dev/null | while read -r f; do
  exempt "$f" || printf '%s\n' "$f"
done | sort -u >"$T/unsafe-have"
al=.lints/unsafe-allowlist
if [ -f "$al" ]; then sed -e 's/#.*$//' -e 's/[[:space:]]*$//' -e '/^$/d' "$al" | sort -u >"$T/unsafe-want"; else : >"$T/unsafe-want"; fi
comm -23 "$T/unsafe-have" "$T/unsafe-want" | while read -r f; do finding "$f carries expect(unsafe_code) but is not on $al"; done
comm -13 "$T/unsafe-have" "$T/unsafe-want" | while read -r f; do finding "$f is on $al but carries no expect(unsafe_code)"; done
if [ -s "$T/unsafe-want" ] && ! directives | awk '$1 == "workspace" || $1 == "package" || $1 == "crate"' | grep -qw unsafe; then
  finding "$al is not empty, but no workspace, package or crate line selects the unsafe tier"
fi
echo "  $(wc -l <"$T/unsafe-have" | tr -d ' ') files carry expect(unsafe_code); $(wc -l <"$T/unsafe-want" | tr -d ' ') allowlisted"

if [ -s "$T/bad" ]; then
  echo "lints-gate: RED"
  exit 1
fi
echo "lints-gate: GREEN"
