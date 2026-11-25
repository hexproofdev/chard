#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# selftest.sh: show the standard can fail, on the pinned toolchain.
#
# Builds a scratch workspace under a fresh temporary directory with EVERY tier selected, then:
#   1. a clean crate must lint and document with no diagnostic at all. This is what proves every
#      lint name, group and clippy.toml knob in the tiers exists on this toolchain: an unknown
#      lint or knob is itself a diagnostic.
#   2. each plant crate holds one defect and must produce the lint it names.
# Prints the frame (toolchain, tiers, crates fed) and a count; exits 1 on any miss.
# Needs: rustup with the toolchain, jq. Writes nothing outside its temporary directory.
#   CLIPPY_TOOLCHAIN=1.100.0 sh selftest.sh       (the default toolchain is 1.100.0: cargo::unused_dependencies
#   needs cargo 1.100 or later; on an older cargo its plant stays green and the run is RED)
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
TC=${CLIPPY_TOOLCHAIN:-1.100.0}
TIERS="lib std service async no_std no_alloc nofloat arith crypto unsafe kani"
command -v jq >/dev/null 2>&1 || {
  echo "selftest: jq is not installed" >&2
  exit 3
}
rustup run "$TC" cargo clippy --version >/dev/null 2>&1 || {
  echo "selftest: toolchain $TC with clippy is not installed" >&2
  exit 3
}

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT INT TERM
cd "$W"

# plant NAME LINT: a crate whose lib.rs is read from stdin.
members=''
plant() {
  mkdir -p "$1/src"
  printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2024"\nrust-version = "1.88"\n\n[lints]\nworkspace = true\n' "$1" >"$1/Cargo.toml"
  cat >"$1/src/lib.rs"
  members="$members \"$1\","
  [ "$2" = - ] || printf '%s %s\n' "$1" "$2" >>expect.txt
}
: >expect.txt

plant clean - <<'EOF'
//! A crate that satisfies every tier at once.
#![no_std]

/// Adds without overflow.
#[must_use]
pub const fn add(a: u8, b: u8) -> Option<u8> {
    a.checked_add(b)
}
/// Kani harnesses would live here; the kani tier declares the cfg.
#[cfg(kani)]
mod proofs {}
EOF
plant p_unwrap clippy::unwrap_used <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(x: Option<u8>) -> u8 { x.unwrap() }
EOF
plant p_expect clippy::expect_used <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(x: Option<u8>) -> u8 { x.expect("plant") }
EOF
plant p_panic clippy::panic <<'EOF'
//! Plant.
/// Plant.
pub fn f() { panic!("plant") }
EOF
plant p_todo clippy::todo <<'EOF'
//! Plant.
/// Plant.
pub fn f() { todo!() }
EOF
plant p_unreachable clippy::unreachable <<'EOF'
//! Plant.
/// Plant.
pub fn f() { unreachable!() }
EOF
plant p_index clippy::indexing_slicing <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(s: &[u8]) -> u8 { s[0] }
EOF
plant p_strslice clippy::string_slice <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(s: &str) -> &str { s.get(..).map_or("", |t| &t[1..]) }
EOF
plant p_arith clippy::arithmetic_side_effects <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(a: u32, b: u32) -> u32 { a + b }
EOF
plant p_as clippy::as_conversions <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(a: u8) -> u16 { a as u16 }
EOF
plant p_allow clippy::allow_attributes <<'EOF'
//! Plant.
#[allow(dead_code, reason = "plant")]
fn g() {}
EOF
plant p_noreason clippy::allow_attributes_without_reason <<'EOF'
//! Plant.
/// Plant.
#[expect(clippy::unwrap_used)]
#[must_use]
pub fn f(x: Option<u8>) -> u8 { x.unwrap() }
EOF
plant p_stale unfulfilled_lint_expectations <<'EOF'
//! Plant.
/// Plant.
#[expect(clippy::unwrap_used, reason = "plant: nothing here unwraps")]
pub fn f() {}
EOF
plant p_forget clippy::mem_forget <<'EOF'
//! Plant.
/// Plant.
pub fn f(v: String) { core::mem::forget(v); }
EOF
plant p_dbg clippy::dbg_macro <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(a: u8) -> u8 { dbg!(a) }
EOF
plant p_assertmsg clippy::missing_assert_message <<'EOF'
//! Plant.
/// Plant.
pub fn f(a: bool) { debug_assert!(a); }
EOF
plant p_resultpanic clippy::panic_in_result_fn <<'EOF'
//! Plant.
/// Plant.
///
/// # Errors
/// Never.
pub fn f(a: bool) -> Result<(), ()> { assert!(a, "plant"); Ok(()) }
EOF
plant p_mapErr clippy::map_err_ignore <<'EOF'
//! Plant.
/// Plant.
///
/// # Errors
/// When `s` is not a number.
pub fn f(s: &str) -> Result<u8, ()> { s.parse::<u8>().map_err(|_| ()) }
EOF
plant p_resultok clippy::unused_result_ok <<'EOF'
//! Plant.
/// Plant.
pub fn f(s: &str) { s.parse::<u8>().ok(); }
EOF
plant p_rest clippy::rest_pat_in_fully_bound_structs <<'EOF'
//! Plant.
/// Plant.
#[derive(Debug)]
pub struct P { a: u8 }
/// Plant.
#[must_use]
pub const fn f(p: &P) -> u8 { let P { a, .. } = p; *a }
EOF
plant p_std clippy::std_instead_of_core <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(a: u8, b: u8) -> std::cmp::Ordering { a.cmp(&b) }
EOF
plant p_endian clippy::host_endian_bytes <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub const fn f(a: u32) -> [u8; 4] { a.to_ne_bytes() }
EOF
plant p_loop clippy::infinite_loop <<'EOF'
//! Plant.
/// Plant.
pub fn f() { loop { core::hint::spin_loop(); } }
EOF
plant p_stack clippy::large_stack_frames <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(i: usize) -> u8 { let a = core::hint::black_box([7u8; 8192]); a.get(i).copied().unwrap_or(0) }
EOF
plant p_lifetime elided_lifetimes_in_paths <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(s: &str) -> core::str::Chars { s.chars() }
EOF
plant p_float clippy::float_arithmetic <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(a: f32) -> f32 { a * 2.0 }
EOF
plant p_div clippy::integer_division <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(a: u32) -> u32 { a.wrapping_div(3) / 2 }
EOF
plant p_debug clippy::use_debug <<'EOF'
//! Plant.
/// Plant.
///
/// # Errors
/// When the writer fails.
pub fn f(w: &mut impl core::fmt::Write, a: &[u8]) -> core::fmt::Result { write!(w, "{a:?}") }
EOF
plant p_print clippy::print_stdout <<'EOF'
//! Plant.
/// Plant.
pub fn f() { println!("plant"); }
EOF
plant p_exit clippy::exit <<'EOF'
//! Plant.
/// Plant.
pub fn f() { std::process::exit(1) }
EOF
plant p_docs missing_docs <<'EOF'
//! Plant.
pub fn f() {}
EOF
plant p_dbgimpl missing_debug_implementations <<'EOF'
//! Plant.
/// Plant.
pub struct S;
EOF
plant p_unsafedoc clippy::undocumented_unsafe_blocks <<'EOF'
//! Plant.
/// Plant.
#[expect(unsafe_code, reason = "plant")]
#[must_use]
pub fn f(a: &[u8]) -> u8 { if a.is_empty() { 0 } else { unsafe { *a.as_ptr() } } }
EOF
plant p_unsafecode unsafe_code <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(a: &[u8]) -> u8 {
    // SAFETY: plant; the gate must refuse unsafe without an expect.
    if a.is_empty() { 0 } else { unsafe { *a.as_ptr() } }
}
EOF
plant p_transmute clippy::disallowed_methods <<'EOF'
//! Plant.
/// Plant.
#[expect(unsafe_code, reason = "plant")]
#[must_use]
pub fn f(a: u32) -> f32 {
    // SAFETY: u32 and f32 have the same size and every bit pattern is a valid f32.
    unsafe { core::mem::transmute::<u32, f32>(a) }
}
EOF
plant p_vec clippy::disallowed_types <<'EOF'
//! Plant.
extern crate alloc;
/// Plant.
#[must_use]
pub fn f() -> alloc::vec::Vec<u8> { alloc::vec::Vec::new() }
EOF
plant p_vecmacro clippy::disallowed_macros <<'EOF'
//! Plant.
extern crate alloc;
/// Plant.
#[must_use]
pub fn f() -> usize { alloc::vec![1u8].len() }
EOF
plant p_await clippy::await_holding_lock <<'EOF'
//! Plant.
async fn other() {}
/// Plant.
pub async fn f(m: &std::sync::Mutex<u8>) {
    if let Ok(g) = m.lock() { other().await; drop(g); }
}
EOF
plant p_rcptr clippy::clone_on_ref_ptr <<'EOF'
//! Plant.
/// Plant.
#[must_use]
pub fn f(a: &std::sync::Arc<u8>) -> std::sync::Arc<u8> { a.clone() }
EOF
plant p_fromfail clippy::fallible_impl_from <<'EOF'
//! Plant.
/// Plant.
#[derive(Debug)]
pub struct N(pub u8);
impl From<&str> for N {
    fn from(s: &str) -> Self { if s.is_empty() { panic!("plant") } Self(0) }
}
EOF

plant p_letuntyped clippy::let_underscore_untyped <<'EOF'
//! Plant.
const fn g() -> u8 { 1 }
/// Plant.
pub fn f() { let _ = g(); }
EOF
plant p_ignore clippy::ignore_without_reason <<'EOF'
//! Plant.
#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn t() {}
}
EOF
plant p_errorname clippy::error_impl_error <<'EOF'
//! Plant.
/// Plant.
#[derive(Debug)]
pub struct Error;
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str("plant") }
}
impl core::error::Error for Error {}
EOF
plant p_sleep clippy::disallowed_methods <<'EOF'
//! Plant.
/// Plant.
pub fn f() { std::thread::sleep(core::time::Duration::from_millis(1)); }
EOF
plant p_cfg unexpected_cfgs <<'EOF'
//! Plant.
/// Plant.
#[cfg(kanii)]
pub const fn f() {}
EOF
plant p_unuseddep cargo::unused_dependencies <<'EOF'
//! Plant: a dependency nothing uses.
EOF
printf '\n[dependencies]\nclean = { path = "../clean" }\n' >>p_unuseddep/Cargo.toml

printf '[workspace]\nresolver = "3"\nmembers = [%s]\n\n' "$members" >Cargo.toml
# shellcheck disable=SC2086 # the tier list splits on purpose
sh "$HERE/assemble.sh" cargo $TIERS >>Cargo.toml
# shellcheck disable=SC2086
sh "$HERE/assemble.sh" clippy $TIERS >clippy.toml
fed=$(wc -l <expect.txt | tr -d ' ')

echo "selftest: toolchain $(rustup run "$TC" cargo clippy --version)"
echo "selftest: standard $(grep -v "^#" "$HERE/VERSION" | head -n 1), tiers all $TIERS; crates fed: clean + $fed plants"

env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u RUSTDOCFLAGS \
  rustup run "$TC" cargo clippy --quiet --keep-going --workspace --all-targets --message-format=json -- -D warnings \
  >clippy.json 2>clippy.err || true
# Cargo's own lints (cargo::*) are not in the JSON stream: cargo prints them on stderr, as text.
awk '/^(error|warning)/ { c = "" } match($0, " --> [^/ ]+/Cargo[.]toml") { c = substr($0, RSTART + 5, RLENGTH - 16) } c != "" && match($0, /`cargo::[a-z_]+`/) { print c, substr($0, RSTART + 1, RLENGTH - 2) }' clippy.err | sort -u >cargo-lints.txt

fail=0
# 1. the clean crate: no diagnostic at all, from clippy or from rustdoc.
clean=$(jq -r 'select(.reason == "compiler-message" and (.target.name == "clean")) | .message.rendered' clippy.json)
if [ -n "$clean" ]; then
  echo "FAIL clean: clippy reported:"
  printf '%s\n' "$clean"
  fail=1
else echo "ok   clean: no clippy diagnostic"; fi
# A malformed clippy.toml or an unknown knob fails every crate before linting; catch it apart.
if grep -q 'error reading Clippy' clippy.json 2>/dev/null; then
  echo "FAIL clippy.toml was rejected"
  fail=1
fi
if awk '$1 == "clean"' cargo-lints.txt | grep -q .; then
  echo "FAIL clean: cargo reported: $(awk '$1 == "clean" { print $2 }' cargo-lints.txt | tr '\n' ' ')"
  fail=1
fi
docout=$(env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS RUSTDOCFLAGS='-D warnings' \
  rustup run "$TC" cargo doc --quiet --no-deps -p clean 2>&1) || {
  echo "FAIL clean: rustdoc:"
  printf '%s\n' "$docout"
  fail=1
}
[ -n "$docout" ] && [ $fail -eq 0 ] && {
  echo "FAIL clean: rustdoc printed:"
  printf '%s\n' "$docout"
  fail=1
}
[ -z "$docout" ] && echo "ok   clean: no rustdoc diagnostic"

# 2. each plant: its lint must appear among the crate's diagnostics.
hit=0
while read -r crate lint; do
  got=$({
    jq -r --arg c "$crate" 'select(.reason == "compiler-message" and .target.name == $c) | .message.code.code // empty' clippy.json
    awk -v c="$crate" '$1 == c { print $2 }' cargo-lints.txt
  } | sort -u)
  if printf '%s\n' "$got" | grep -qx -- "$lint"; then
    hit=$((hit + 1))
    echo "ok   $crate: $lint"
  else
    fail=1
    echo "FAIL $crate: expected $lint, got: $(printf '%s' "$got" | tr '\n' ' ')"
  fi
done <expect.txt

echo "selftest: $hit of $fed plants red on their lint"
[ $fail -eq 0 ] && echo "selftest: GREEN" || echo "selftest: RED"
exit $fail
