// SPDX-License-Identifier: BSD-3-Clause

//! Every macro a code decoder reads is one the report records.
//!
//! A report publishes a verdict and, beside it, the evidence that verdict came from.
//! `relevant_macros` decides what that evidence contains, because the raw preprocessor
//! dump is thousands of lines and embedding it per observation would bury the few lines
//! that matter. Trimming is right; trimming away something a detector actually consulted
//! is not, and the two are indistinguishable by reading the list.
//!
//! What that costs is not hypothetical. `_CXX_STDLIB` (chard's own summary of which C++
//! standard library answered) was absent from the list while both of its fallbacks were
//! present. On Linux, where the artifact can be read, `measure` replaces the preprocessor
//! dump with the self-report wholesale, and the self-report carries the summary and
//! neither fallback. So `detect_cxx_hardening_requested` identified the library on every
//! Linux run, answered `on` or `off`, and published evidence from which that answer could
//! not be reproduced. Nothing failed: the replay harness read those observations back as
//! `indeterminate`, which is a legitimate detector outcome, and the check sat as the only
//! one in the corpus showing a single outcome across two thousand fixtures.
//!
//! # Scope: code decoders
//!
//! The macro and elf-static checks decode through `chard-predicate/1` predicates, which
//! record every read they make, so their names are data rather than literals to scan for.
//! `tests/predicates.rs` holds every name a predicate reads, and every name a `c-int`
//! follows over the fixtures and a generated space, to the published filter
//! (`every_name_a_predicate_reads_is_kept`, `filtered_macros_suffice`). This file holds
//! the code decoders under `src/decode/`, the runtime and compiler-diag detectors and the
//! `cxx_stdlib` ladder they share.
//!
//! # Why a source scan
//!
//! A code decoder is a function over an opaque map, so nothing at runtime can ask one
//! which keys it will look at. The names are literals in `src/decode/`, and reading them
//! out of the source is the only enumeration available, the same trade
//! `discarded_failures.rs` makes, and honest about being a tripwire rather than a proof.
//! A decoder that built a macro name at runtime would evade this, and the assertions below
//! fail loudly if the shapes being scanned for stop appearing at all.
//!
//! A decoder that looks up names taken from macro values (`_LIBCPP_HARDENING_MODE_FAST`,
//! say) is one no source scan can list. The filter keeps libc++'s mode constants, and the
//! predicates that read libc++'s mode record their own reads (Scope, above).

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
///
/// The runtime and compiler-diag detectors, and the `cxx_stdlib` ladder they share with
/// the predicates' `cxx-stdlib` term, live there, so the number of files read is asserted
/// rather than assumed.
fn detector_source() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    walk(&root.join("decode"), &mut paths);
    paths.retain(|p| !p.to_string_lossy().ends_with("_tests.rs"));
    paths.sort();
    assert!(
        paths.len() >= 4,
        "only {} module files under src/decode/, so the runtime and compiler-diag detectors \
         are not being scanned: {paths:?}",
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
    // the verbs fails here rather than passing on the others. The `cxx_stdlib` ladder is
    // the one macro read the code decoders make, through `detect_cxx_assertions`.
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
        "{} macro(s) are read by a detector and dropped from the evidence a report \
         publishes, so those observations carry a verdict their own evidence cannot \
         reproduce: {dropped:?}\nAdd them to `measure::MACRO_EVIDENCE_KEEP`.",
        dropped.len()
    );
}

/// The list a report publishes as its filter is the list the filter uses.
///
/// The filter was applied and recorded nowhere, so `evidence.macros` read as the macro
/// state when it was a fixed subset of it. The report now carries the list; this holds
/// the published copy to the one `relevant_macros` reads, in both directions, so the
/// two cannot drift into a report that names one list and applies another.
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
