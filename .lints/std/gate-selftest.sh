#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# gate-selftest.sh: show lints-gate.sh failing, once per check, before anyone trusts it.
#
# Builds a scratch git repository that follows the standard (two workspace members, a crate
# root with an extra tier, a test module with a permitted relief, one allowlisted unsafe file),
# checks that the gate is GREEN on it, then plants one defect at a time, expects RED with a
# message naming the defect, and restores the tree. Three allowed forms must stay GREEN.
# Prints the frame and a count; exit 1 on any miss. Needs git, cargo, jq, sha256sum.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT INT TERM
cd "$W"
git init -q . && git config user.email selftest@invalid && git config user.name selftest

# The standard, vendored as a repository would: the files SHA256SUMS lists, and the pin.
mkdir -p .lints/std
(cd "$HERE" && awk '!/^#/ { print $2 }' SHA256SUMS) | while read -r f; do
  mkdir -p ".lints/std/$(dirname "$f")"
  cp "$HERE/$f" ".lints/std/$f"
done
cp "$HERE/SHA256SUMS" .lints/std/
cat >.lints/standard <<EOF
version $(grep -v "^#" "$HERE/VERSION" | head -n 1)
sha256 $(sha256sum "$HERE/SHA256SUMS" | awk '{ print $1 }')
workspace . lib std
crate crates/a/src/lib.rs unsafe
crate crates/b/src/lib.rs no_std arith
exempt tests/fixtures/ fixtures are inputs, not crates
EOF
mkdir -p .lints/local/root
printf 'rust.unexpected_cfgs = { level = "warn", check-cfg = ["cfg(kani)"] }\n' >.lints/local/root/local.lints
printf 'doc-valid-idents = ["SelfTest", ".."]\n' >.lints/local/root/local.clippy
printf 'crates/a/src/raw.rs\n' >.lints/unsafe-allowlist

printf '[workspace]\nresolver = "3"\nmembers = ["crates/a", "crates/b"]\n\n' >Cargo.toml
sh .lints/std/assemble.sh cargo --local .lints/local/root lib std >>Cargo.toml
sh .lints/std/assemble.sh clippy --local .lints/local/root lib std >clippy.toml
for c in a b; do
  mkdir -p crates/$c/src
  printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2024"\n\n[lints]\nworkspace = true\n' $c >crates/$c/Cargo.toml
done
{
  sh .lints/std/assemble.sh attr unsafe
  cat
} >crates/a/src/lib.rs <<'EOF'
//! a
#![cfg_attr(test, allow(clippy::arithmetic_side_effects, reason = "tests add small numbers"))]
mod raw;

#[cfg(test)]
mod tests {
    #![allow(clippy::as_conversions, reason = "test literals")]
    #[test]
    fn t() { assert_eq!(1 + 1, 2u8 as i32); }
}
EOF
printf '#[expect(unsafe_code, reason = "selftest")]\npub(crate) fn f() {}\n' >crates/a/src/raw.rs
{
  sh .lints/std/assemble.sh attr no_std arith
  printf '//! b\n#![no_std]\n'
} >crates/b/src/lib.rs
mkdir -p tests/fixtures/x && printf '[package]\nname = "x"\n' >tests/fixtures/x/Cargo.toml
printf 'check:\n\tcargo clippy --locked -- -D warnings\n' >Makefile
cargo generate-lockfile -q 2>/dev/null
git add -A && git commit -q -m base

gate() { sh .lints/std/lints-gate.sh >"$W.out" 2>&1; }
pass=0
fail=0
n=0
restore() { git reset -q --hard && git clean -q -fdx; }
# red NAME PATTERN: the gate must exit 1 and print PATTERN.
red() {
  n=$((n + 1))
  if gate; then
    echo "FAIL $1: the gate stayed GREEN"
    fail=$((fail + 1))
  elif grep -q -- "$2" "$W.out"; then
    echo "ok   $1: red, '$2'"
    pass=$((pass + 1))
  else
    echo "FAIL $1: red, but without '$2':"
    sed 's/^/    /' "$W.out"
    fail=$((fail + 1))
  fi
  restore
}
green() {
  n=$((n + 1))
  if gate; then
    echo "ok   $1: green"
    pass=$((pass + 1))
  else
    echo "FAIL $1: red:"
    sed 's/^/    /' "$W.out"
    fail=$((fail + 1))
  fi
  restore
}

echo "gate-selftest: standard $(grep -v "^#" "$HERE/VERSION" | head -n 1); $(git ls-files | wc -l | tr -d ' ') files in the scratch repository"
green "baseline"

echo '# edited' >>.lints/std/tiers/lib.lints
red "copy: a vendored tier edited" "differ from its SHA256SUMS"
sed -i 's/^sha256 .*/sha256 0000/' .lints/standard
red "copy: the pin moved" "pins 0000"
sed -i 's/^rust.missing_docs = "deny"/rust.missing_docs = "warn"/' Cargo.toml
red "drift: the Cargo.toml block edited" "lint block differs"
echo 'too-many-lines-threshold = 1000' >>clippy.toml
red "drift: clippy.toml edited" "clippy.toml differs"
sed -i 's/clippy::arithmetic_side_effects,//' crates/b/src/lib.rs
red "drift: a crate-root block edited" "crate-root block differs"
sed -i '/^\[lints\]/,$d' crates/b/Cargo.toml
red "inherit: a member drops [lints]" "does not set \[lints\] workspace = true"
mkdir -p tools/t/src && printf '[package]\nname = "t"\nversion = "0.1.0"\nedition = "2024"\n\n[workspace]\n' >tools/t/Cargo.toml && echo '' >tools/t/src/main.rs && git add tools
red "inherit: an excluded crate nobody declares" "no workspace, package or exempt line covers it"
printf '#[allow(dead_code, reason = "x")]\nfn g() {}\n' >>crates/a/src/raw.rs
red "allowances: an outer allow" "outer allow"
printf '#[allow(\n    dead_code,\n    reason = "x"\n)]\nfn g() {}\n' >>crates/a/src/raw.rs
red "allowances: a multi-line outer allow" "outer allow"
sed -i '1a #![allow(clippy::unwrap_used, reason = "x")]' crates/a/src/lib.rs
red "allowances: an inner allow at the crate root" "outside a #\[cfg(test)\] module head"
sed -i 's/#!\[allow(clippy::as_conversions, reason = "test literals")\]/#![allow(clippy::as_conversions)]/' crates/a/src/lib.rs
red "allowances: a test-module allow without a reason" "without a reason"
mkdir -p .cargo && printf '[build]\nrustflags = ["-A", "warnings"]\n' >.cargo/config.toml
red "flags: a cargo config that lowers lints" "local cargo config lowers a lint level"
printf 'lint:\n\tcargo clippy -- -A clippy::unwrap_used\n' >>Makefile
red "flags: clippy -A in the Makefile" "lowers a lint level"
mkdir -p .cargo && printf '[build]\ntarget = "x86_64-unknown-linux-gnu"\n[target.x86_64-unknown-linux-gnu]\nrustflags = ["-C", "link-arg=-nostartfiles"]\n' >.cargo/config.toml
green "allowed: a cargo config with only target and linker flags"
printf '# a comment: CARGO_BUILD_RUSTFLAGS holding --cap-lints allow would hide a warning\n' >>Makefile
green "allowed: a Makefile comment that mentions --cap-lints"
printf '#[expect(unsafe_code, reason = "x")]\npub fn h() {}\n' >>crates/b/src/lib.rs
red "unsafe: an unlisted unsafe file" "is not on .lints/unsafe-allowlist"
printf 'crates/b/src/lib.rs\n' >>.lints/unsafe-allowlist
red "unsafe: a stale allowlist entry" "carries no expect(unsafe_code)"
echo 'surface lib' >>.lints/standard
red "standard: an unknown directive" "unknown directive"

printf '\n#[cfg(test)]\nmod more {\n    #![allow(clippy::panic, reason = "a test may panic")]\n}\n' >>crates/a/src/lib.rs
green "allowed: a second test module with a reasoned inner allow"
mkdir -p crates/a/tests && printf '#![allow(clippy::arithmetic_side_effects, reason = "integration test")]\n#[test]\nfn t() {}\n' >crates/a/tests/it.rs && git add crates/a/tests
green "allowed: an inner allow heading a tests/ file"

echo "gate-selftest: $pass of $n cases as expected"
if [ $fail -eq 0 ]; then
  echo "gate-selftest: GREEN"
  exit 0
fi
echo "gate-selftest: RED"
exit 1
