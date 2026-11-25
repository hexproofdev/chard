#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
#
# The canary over the gate's clippy: `make clippy-gate`, run as the gate runs it, over
# copies of this tree with a planted module in its library, and held to what it does rather
# than to how its recipe is spelled. One check here is still a read of text, the one over what
# the copy's build script printed; "Not held" below says what it misses.
#
# Usage: scripts/clippy-canary.sh   (what `make clippy-canary` runs, from the tree's root)
#
# src/lib.rs relieves the library's test code of three lints at the crate root
# (`cfg_attr(test, expect(...))`), and the relief is sound only while the gate also lints the
# library's non-test build, where the three stay denied. Each copy is the tree's files as they
# stand (tracked, and untracked ones git does not ignore; no .git), so it carries whatever the
# real rule reads. src/lib.rs gains `pub mod canary_sites;`, and src/canary_sites.rs is one of
# four bodies:
#
#   - non-test: one public function with a site of each of the three relieved lints and of the
#     four clippy denies in .lints/local. The rule must exit non-zero, and clippy must name all
#     seven; a clippy lint local.lints denies that has no site here stops the canary. It runs
#     twice: as the gate runs it, and in a second copy under a caller who caps the lints
#     (`--cap-lints=allow` in RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS, CARGO_BUILD_RUSTFLAGS,
#     CLIPPY_ARGS and a cargo configuration above the copy, and a CLIPPY_CONF_DIR whose
#     clippy.toml allows u32 arithmetic). The rule must keep each of them from clippy.
#   - test: the three relieved sites alone, in a `#[cfg(test)]` module. The rule must exit 0:
#     the relief reaches test code.
#   - test, unrelieved: the same, and a truncating cast, which the relief does not lift. The
#     rule must exit non-zero and name `cast_possible_truncation`: the gate lints test code.
#   - pedantic: one site of `unreadable_literal`, at warn, and nothing else. The rule must exit
#     non-zero and name it: only `-D warnings` makes a warning fail, so a clippy handed
#     arguments past the recorded call that drop it is seen.
#
# make is given a cargo that records each call, and every run must show one call, `+PIN
# clippy --locked --all-targets -- -D warnings` with PIN the Makefile's CLIPPY_TOOLCHAIN, made
# with RUSTFLAGS set empty and CARGO_ENCODED_RUSTFLAGS and CLIPPY_CONF_DIR unset. So a rule
# that runs another toolchain, drops or adds an argument, sets a RUSTFLAGS, leaves a caller's
# CLIPPY_CONF_DIR, or calls cargo other than through `$(CARGO)`, fails the canary. That is an
# equality over the call make makes, not over the recipe's text: a deliberate change of the
# call edits `call` below. Every run also fails on a plain `cargo:rustc-env=` line, read with
# grep under the caller's locale, that the copy's build script printed for a variable outside
# chard's `CHARD_` ones: `cargo:rustc-env=CLIPPY_ARGS=...` reaches clippy past the recorded
# call. "Not held" below names what passes that read.
#
# Whatever keeps the non-test build from being linted at its levels, for the lints the bodies
# plant sites of, makes the non-test runs pass, and the canary fails: `.IGNORE`, a `SHELL` or
# `CARGO` assignment, a second rule for the target, a cargo configuration of the tree that sets
# CLIPPY_ARGS or rustflags, `--tests`, a status discarded with `|| true`, among others. A lint
# no body plants a site of is not watched this way. A relief line dropped fails the test run;
# one widened past test code fails the non-test runs. The other half of the reliefs' reasons,
# that the test profile keeps overflow checks, is not held here.
#
# Not held, outside the tree:
#   - a rustc wrapper (`RUSTC_WRAPPER`, `build.rustc-wrapper`), as the Makefile's comment says;
#   - a cargo configuration found above the tree but not above TMPDIR, or the reverse;
#   - the caller's own cargo configuration above both (CARGO_HOME's), whose `[env]
#     CLIPPY_ARGS` with `force = true` can carry an `-A` for a lint no body plants a site of.
#     Like a wrapper, it is the caller's own machine.
# Nor the pin's value, which a bump changes in one visible line, nor a level weakened in the
# generated lint block or a clippy.toml setting widened, for a lint or type no body plants a
# site of: `.lints/std/lints-gate.sh`'s drift check compares both generated texts.
#
# Not held either, inside the tree, each a tracked edit:
#   - a build script handing clippy a variable or a file past the read above, which matches
#     only a plain line. Of that, the canary sees only what moves a lint a body plants a site
#     of, and a lost `-D warnings`;
#   - a lowering in the tree's own code outside the canary's module. That is clippy-gate's to
#     find where the gate's host compiles it.
#
# Exit 0 when every run held, 1 when one did not, 2 when the canary could not start: the tree's
# Makefile pin, local.lints or src/lib.rs not read, a clippy deny with no site or a spelling the
# census does not read, TMPDIR inside the tree or holding whitespace, or a copy not made.
# `make clippy-canary` exits 2 for either failure. The copies are under TMPDIR and removed on
# exit; a failing run's log is printed.
set -uo pipefail

MAKE=${MAKE:-make}
CARGO=${CARGO:-cargo}
root=$(pwd -P)

refuse() {
  echo "clippy-canary: $*" >&2
  exit 2
}

[ -f "$root/src/lib.rs" ] || refuse "no src/lib.rs in $root"
# The toolchain the rule must run clippy under: the Makefile's pin, the line ci.yml reads too.
pin=$(sed -n 's/^CLIPPY_TOOLCHAIN := *\([^ ]*\) *$/\1/p' "$root/Makefile" | head -n 1)
[ -n "$pin" ] || refuse "$root/Makefile sets no CLIPPY_TOOLCHAIN"
real_cargo=$(command -v "$CARGO") || refuse "no $CARGO on PATH"

non_test='//! The canary'"'"'s planted sites.

/// A site of each lint the gate denies outside test code.
#[must_use]
pub fn canary(text: &str, a: u32, b: u32, signed: i32, byte: u8) -> (u32, &str, u8, u32, u32) {
    println!("canary");
    (a + b, &text[1..], a as u8, signed as u32, byte as u32)
}
'
warned_only='//! The canary'"'"'s planted sites.

/// A site of a pedantic lint, a warning that only -D warnings makes an error.
pub const CANARY_LITERAL: u32 = 12345678;
'
test_only='//! The canary'"'"'s planted sites.

#[cfg(test)]
mod tests {
    // A helper, not the test itself: clippy does not read a test function body for
    // arithmetic_side_effects, and the relief would then be unfulfilled.
    fn sites(text: &str, a: u32) -> (u32, &str, u64) {
        (a + a, &text[1..], text.len() as u64)
    }

    #[test]
    fn canary() {
        assert_eq!(sites("ab", 1), (2, "b", 2), "the planted sites");
    }
}
'
unrelieved='//! The canary'"'"'s planted sites.

#[cfg(test)]
mod tests {
    fn sites(text: &str, a: u32) -> (u32, &str, u64, u8) {
        (a + a, &text[1..], text.len() as u64, a as u8)
    }

    #[test]
    fn canary() {
        assert_eq!(sites("ab", 1), (2, "b", 2, 1), "the planted sites");
    }
}
'
# The non-test runs must name the three relieved lints and the four .lints/local denies. The
# warned run's lint is alone in its body, since beside the deny sites, which fail the run
# either way, a lost -D warnings would show nothing.
denied="arithmetic_side_effects as_conversions string_slice cast_possible_truncation cast_sign_loss cast_lossless print_stdout"
warned="unreadable_literal"
# Each clippy lint .lints/local/root/local.lints denies has a site above: a new local deny stops
# the canary here until the non-test body carries one.
local_lints=$root/.lints/local/root/local.lints
[ -f "$local_lints" ] || refuse "no $local_lints"
local_denies=0
while IFS= read -r lint; do
  local_denies=$((local_denies + 1))
  case " $denied " in
    *" $lint "*) ;;
    *) refuse "$local_lints denies clippy::$lint, which the non-test body has no site of" ;;
  esac
done < <(sed -n 's/^clippy\.\([a-z_]*\) = "deny".*$/\1/p' "$local_lints")
# Every clippy line that names deny is one the census read: another spelling (an inline table,
# no spaces around `=`) is refused, not passed over; and none at all is refused too.
spelled=$(grep -c '^[[:space:]]*clippy\..*deny' "$local_lints") || spelled=0
[ "$local_denies" -gt 0 ] && [ "$spelled" -eq "$local_denies" ] \
  || refuse "$local_lints has $spelled clippy lines naming deny, and the census read $local_denies as \`clippy.NAME = \"deny\"\`"

work=$(mktemp -d "${TMPDIR:-/tmp}/clippy-canary.XXXXXX") || refuse "cannot make a directory under ${TMPDIR:-/tmp}"
trap 'rm -rf "$work"' EXIT
# make splits $(CARGO) on whitespace, so the recording cargo's path must hold none.
case $work in
  *[[:space:]]*) refuse "the scratch directory $work holds whitespace; set TMPDIR to a path without it" ;;
  *) ;;
esac
# Inside the tree, the copies would list and copy the scratch directory itself.
case $(cd "$work" && pwd -P) in
  "$root"/*) refuse "the scratch directory $work is inside the tree; set TMPDIR outside it" ;;
  *) ;;
esac

# A copy of the tree in DIR, a symbolic link copied as one, dangling or not, with src/lib.rs
# declaring the planted module. The caller's GIT_DIR, GIT_INDEX_FILE or GIT_WORK_TREE would
# list another tree.
copy() {
  local dir=$1
  mkdir -p "$dir" || return 1
  env -u GIT_DIR -u GIT_INDEX_FILE -u GIT_WORK_TREE \
    git -C "$root" ls-files -z --cached --others --exclude-standard \
    | (cd "$root" && while IFS= read -r -d '' f; do
      if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\0' "$f"; fi
    done) \
    | (cd "$root" && tar --null -T - -cf -) | tar -xf - -C "$dir" || return 1
  printf '\n/// The canary'"'"'s planted sites (scripts/clippy-canary.sh).\npub mod canary_sites;\n' >>"$dir/src/lib.rs"
}

# The cargo make is given: it records each call's variables and arguments, then runs the real
# cargo, so a run shows what clippy was asked for after make expanded the rule.
cat >"$work/cargo" <<'EOF' || refuse "cannot write the recording cargo in $work"
#!/bin/sh
printf '%s\t%s\t%s\t%s\n' "${RUSTFLAGS-<unset>}" "${CARGO_ENCODED_RUSTFLAGS-<unset>}" \
  "${CLIPPY_CONF_DIR-<unset>}" "$*" >>"$CLIPPY_CANARY_CALLS"
exec "$CLIPPY_CANARY_CARGO" "$@"
EOF
chmod +x "$work/cargo" || refuse "cannot make $work/cargo executable"

# The one cargo call the rule must make, and the variables it must make it under: RUSTFLAGS set
# empty, which cargo reads before CARGO_BUILD_RUSTFLAGS and a configuration's rustflags;
# CARGO_ENCODED_RUSTFLAGS, which cargo reads first, unset; CLIPPY_CONF_DIR, which replaces the
# tree's clippy.toml, unset.
call="+$pin clippy --locked --all-targets -- -D warnings"

# The tree's clippy-gate rule over the copy in DIR with BODY planted, its output in LOG and
# cargo's calls in LOG.calls, under the variables given after them; its exit status.
# CLIPPY_DISABLE_DOCS_LINKS is cleared, since it drops the anchors the runs read lint names by,
# and MAKEFLAGS, which would carry a caller's `make clippy-canary CARGO=...` past the recording
# cargo. The variables go in the environment, since on make's command line they would override
# a makefile's own assignment of CARGO.
gate() {
  local dir=$1 body=$2 log=$3
  shift 3
  printf '%s' "$body" >"$dir/src/canary_sites.rs" || return 2
  : >"$log.calls" || return 2
  (cd "$dir" && env -u CLIPPY_DISABLE_DOCS_LINKS -u MAKEFLAGS -u MFLAGS "$@" CLIPPY_CANARY_CALLS="$log.calls" \
    CLIPPY_CANARY_CARGO="$real_cargo" CARGO="$work/cargo" CARGO_TARGET_DIR="$dir.target" \
    "$MAKE" --no-print-directory clippy-gate) >"$log" 2>&1
}

# Whether the build script of the copy in DIR printed no plain `cargo:rustc-env=` line for a
# variable outside chard's `CHARD_` ones, read in both of cargo's layouts (the second from 1.100)
# for the host or a target triple. False where no output was found, so a third layout fails. A
# read of text, which the header's "Not held" bounds.
build_outputs() {
  local f
  for f in "$1.target"/*/build/chard-*/output "$1.target"/*/*/build/chard-*/output \
    "$1.target"/*/build/chard/*/run/stdout "$1.target"/*/*/build/chard/*/run/stdout; do
    if [ -f "$f" ]; then printf '%s\n' "$f"; fi
  done
}
build_env_ok() {
  local outs=() f
  while IFS= read -r f; do outs+=("$f"); done < <(build_outputs "$1")
  [ "${#outs[@]}" -gt 0 ] || return 1
  # cargo trims each line it reads, so a leading space or tab keeps the line an instruction. The
  # class below takes those; it does not take every character cargo's trim takes.
  ! grep -h -E '^[[:space:]]*cargo::?rustc-env=' "${outs[@]}" \
    | grep -v -E '^[[:space:]]*cargo::?rustc-env=CHARD_' | grep -q .
}

# Whether the run that logged LOG called cargo once, and that once as `call` says.
ran_as_gate() {
  awk -F '\t' -v call="$call" '
    { n++ }
    $1 == "" && $2 == "<unset>" && $3 == "<unset>" && $4 == call { ok++ }
    END { exit !(n == 1 && ok == 1) }' "$1.calls"
}

failed=0
report() {
  local what=$1 log=$2
  shift 2
  echo "clippy-canary: $what: FAILED: $*; its log:"
  sed 's/^/  | /' "$log"
  failed=1
}
not_as_gate() {
  report "$1" "$2" "clippy-gate did not call \$(CARGO) once, as \`$call\` with RUSTFLAGS empty and CARGO_ENCODED_RUSTFLAGS and CLIPPY_CONF_DIR unset; its calls (RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS, CLIPPY_CONF_DIR, arguments): $(tr '\t\n' '|;' <"$2.calls")"
}

not_chard_env() {
  local outs=() f
  while IFS= read -r f; do outs+=("$f"); done < <(build_outputs "$3")
  report "$1" "$2" "the copy's build scripts wrote no output under $3.target, or set a rustc variable outside CHARD_: ${#outs[@]} output(s), $( ((${#outs[@]})) && grep -h -E '^[[:space:]]*cargo::?rustc-env=' "${outs[@]}" | tr '\n' ';')"
}

# A run over sites of denied lints: the rule must fail, as the gate runs it, and name each of
# LINTS.
denied_run() {
  local what=$1 dir=$2 body=$3 log=$4 lints=$5 rc=0 lint missing=()
  shift 5
  gate "$dir" "$body" "$log" "$@" || rc=$?
  for lint in $lints; do
    # clippy's help line for a lint ends in its page's anchor, `index.html#NAME`.
    grep -qF "#$lint" "$log" || missing+=("$lint")
  done
  if ! ran_as_gate "$log"; then
    not_as_gate "$what" "$log"
  elif ! build_env_ok "$dir"; then
    not_chard_env "$what" "$log" "$dir"
  elif [ "$rc" -eq 0 ] || [ "${#missing[@]}" -gt 0 ]; then
    report "$what" "$log" "clippy-gate exited $rc over a site of each of $lints${missing[*]:+, naming none of ${missing[*]}}"
  else
    echo "clippy-canary: $what: clippy-gate exited $rc under +$pin and named all of: $lints"
  fi
}

copy "$work/tree" || refuse "cannot copy the tree to $work/tree"
copy "$work/capped/tree" || refuse "cannot copy the tree to $work/capped/tree"
if ! mkdir -p "$work/capped/.cargo" "$work/capped/conf" \
  || ! printf '[build]\nrustflags = ["--cap-lints=allow"]\n' >"$work/capped/.cargo/config.toml" \
  || ! printf 'arithmetic-side-effects-allowed = ["u32"]\n' >"$work/capped/conf/clippy.toml"; then
  refuse "cannot write the capped copy's cargo and clippy configuration"
fi

denied_run "non-test sites" "$work/tree" "$non_test" "$work/non-test.log" "$denied"
denied_run "non-test sites, lints capped by the caller" "$work/capped/tree" "$non_test" \
  "$work/capped.log" "$denied" RUSTFLAGS=--cap-lints=allow CARGO_ENCODED_RUSTFLAGS=--cap-lints=allow \
  CARGO_BUILD_RUSTFLAGS=--cap-lints=allow CLIPPY_ARGS=--cap-lints=allow CLIPPY_CONF_DIR="$work/capped/conf"
denied_run "test sites, one unrelieved" "$work/tree" "$unrelieved" "$work/unrelieved.log" cast_possible_truncation
denied_run "a pedantic site alone" "$work/tree" "$warned_only" "$work/warned.log" "$warned"
rc=0
gate "$work/tree" "$test_only" "$work/test.log" || rc=$?
if ! ran_as_gate "$work/test.log"; then
  not_as_gate "test sites" "$work/test.log"
elif ! build_env_ok "$work/tree"; then
  not_chard_env "test sites" "$work/test.log" "$work/tree"
elif [ "$rc" -ne 0 ]; then
  report "test sites" "$work/test.log" "clippy-gate exited $rc over the tree with the three relieved lints' sites in test code"
else
  echo "clippy-canary: test sites: clippy-gate exited 0 over the tree with the three relieved lints' sites in test code"
fi
# A caller can require this line, since the target's exit 0 alone does not show that this
# script ran. It says no run above failed; it counts no runs.
[ "$failed" -ne 0 ] || echo "clippy-canary: every run held"
exit "$failed"
