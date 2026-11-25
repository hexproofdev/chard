// SPDX-License-Identifier: BSD-3-Clause

//! Every macro a code decoder reads is one the report records.

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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Every `.rs` file under `dir` at any depth, so a nested module under `src/decode/` is
/// scanned too.
fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a readable entry").path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The code decoder source: every module file under `src/decode/` at any depth,
/// concatenated. The sibling `*_tests.rs` files are left out, since a name a unit test
/// plants is not one a decoder reads.
fn detector_source() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    walk(&root.join("decode"), &mut paths);
    paths.retain(|p| !p.to_string_lossy().ends_with("_tests.rs"));
    paths.sort();
    assert!(
        paths.len() >= 4,
        "only {} module files under src/decode/: {paths:?}",
        paths.len()
    );
    let mut src = String::new();
    for path in paths {
        src.push_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display())),
        );
    }
    src
}

/// Macro names the code decoders under `src/decode/` consult, by the three verbs they use.
fn consulted() -> BTreeSet<String> {
    let src = detector_source();
    let mut names = BTreeSet::new();

    // `ev.macros.get("X")`, `.contains_key("X")`, `.get_key_value("X")`
    for (i, _) in src.match_indices("macros") {
        let tail = &src[i..];
        for verb in [".get(", ".contains_key(", ".get_key_value("] {
            let Some(rest) = tail.strip_prefix("macros") else {
                continue;
            };
            let rest = rest.trim_start();
            let Some(rest) = rest.strip_prefix(verb.trim_start_matches('.')).or_else(|| {
                rest.strip_prefix('.')
                    .and_then(|r| r.trim_start().strip_prefix(verb.trim_start_matches('.')))
            }) else {
                continue;
            };
            if let Some(name) = quoted(rest.trim_start()) {
                names.insert(name);
            }
        }
    }

    names
}

/// The contents of a `"..."` literal at the start of `s`, if there is one.
fn quoted(s: &str) -> Option<String> {
    let rest = s.strip_prefix('"')?;
    let end = rest.find('"')?;
    let name = rest.get(..end)?;
    // Macro names only: a detector also passes prose to other calls nearby.
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(name.to_owned())
}

#[test]
fn every_macro_a_code_decoder_reads_is_one_the_report_records() {
    let consulted = consulted();

    // The frame, so a pass means "checked N names" rather than "the regex found nothing".
    eprintln!(
        "{} macro name(s) consulted by the code decoders in src/decode/",
        consulted.len()
    );
    // Anchors: names that must be found, so a scan that silently stops matching one of
    // the verbs fails here rather than passing on the others.
    for anchor in [
        "_CXX_STDLIB",     // get
        "_LIBCPP_VERSION", // contains_key
        "__GLIBCXX__",     // contains_key
    ] {
        assert!(
            consulted.contains(anchor),
            "{anchor} is read by a code decoder and the scan did not find it: {consulted:?}"
        );
    }

    // Exercise the real filter rather than re-parsing its list: hand it every name a
    // detector reads and see which come back.
    let offered: BTreeMap<String, String> = consulted
        .iter()
        .map(|n| (n.clone(), "1".to_owned()))
        .collect();
    let recorded = chard::measure::relevant_macros(&offered);
    let dropped: Vec<&String> = consulted
        .iter()
        .filter(|n| !recorded.contains_key(*n))
        .collect();

    assert!(
        dropped.is_empty(),
        "{} macro(s) a detector reads are dropped: {dropped:?}; add them to MACRO_EVIDENCE_KEEP",
        dropped.len()
    );
}

#[test]
fn the_published_macro_filter_is_the_one_applied() {
    let published = chard::report::evidence_filters().macros;
    let applied: BTreeSet<&str> = chard::measure::MACRO_EVIDENCE_KEEP
        .iter()
        .copied()
        .collect();
    let named: BTreeSet<&str> = published.names.iter().map(String::as_str).collect();
    assert_eq!(named, applied);
    assert_eq!(published.size, applied.len());

    // Every name a detector consults is in the published list too, which is the claim a
    // reader of `evidence_filters.macros` is entitled to: nothing a verdict rests on is
    // outside what the evidence shows.
    let consulted = consulted();
    let outside: Vec<&String> = consulted
        .iter()
        .filter(|n| !named.contains(n.as_str()))
        .collect();
    assert!(
        outside.is_empty(),
        "consulted by a detector and outside the published filter: {outside:?}"
    );
}
