// SPDX-License-Identifier: BSD-3-Clause
//! The detectors over the hand-authored rows of `tests/fixtures/synthetic-rows.json`.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::string_slice,
    reason = "test code lays out fixture bytes, counts results and slices text at offsets it \
              found in the same string, from constants and the sizes of data in memory; the \
              test profile keeps overflow checks, and an overflow, or a slice off a character \
              boundary or past the end, panics and fails the test. Its casts widen a length or \
              a u32, take the offset between two addresses in one string, or name a function \
              pointer type or a closure's trait object. clippy has no test knob for these three \
              lints, and src/lib.rs's crate-root relief does not reach tests/"
)]

use std::collections::BTreeSet;
use std::path::Path;

use chard::fixture::Fixture;

/// The prefix every hand-authored row's toolchain id carries, so no reader takes one for a
/// toolchain a run measured.
const HAND_AUTHORED: &str = "synthetic:";

fn rows() -> Vec<Fixture> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic-rows.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()))
}

#[test]
fn every_hand_authored_row_gives_the_reading_it_expects() {
    let rows = rows();
    assert!(rows.len() >= 23, "the rows file holds {} rows", rows.len());
    let mut seen = BTreeSet::new();
    let mut failures = Vec::new();
    for row in &rows {
        assert!(
            row.toolchain.starts_with(HAND_AUTHORED),
            "{} {}: a row of this file is hand-authored",
            row.check,
            row.toolchain
        );
        assert!(
            seen.insert((row.check.clone(), row.toolchain.clone(), row.arm.clone())),
            "{} {} is in the file twice",
            row.check,
            row.toolchain
        );
        let replay = row
            .replay()
            .unwrap_or_else(|| panic!("{} names no check of the corpus", row.check));
        if !replay.agrees() {
            failures.push(format!(
                "{} {}: expected {} {:?}, got {} {:?}",
                replay.fixture_check,
                replay.toolchain,
                replay.expected,
                replay.expected_level,
                replay.got,
                replay.got_level
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
