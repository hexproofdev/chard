// SPDX-License-Identifier: BSD-3-Clause
//! `chard table` and `chard matrix` over arbitrary JSON: a report someone else hands you is
//! an input chard renders (THREAT_MODEL.md, "Whoever hands you the report"), so a malformed
//! one is refused or rendered, never a panic. The input is one report, or an array of them
//! read as one dataset, which is what reaches the joins: the dataset identity and its
//! conflicts, the contradiction check, `matrix::build` and its serialization, and
//! `table::render_files` in both formats and both groupings. A single report is also
//! rendered beside itself. `table` takes paths only, so each report is written to a file
//! in the system temporary directory first and removed after.
//!
//! Two invariants hold for every input. Rendering is deterministic: the same files render
//! to the same table, or the same refusal, twice, and `matrix::build` serializes the same
//! twice, since a table is evidence a reader diffs across runs. And a table reads the
//! report, not its bytes: the plain table of the reports as written compactly equals that
//! of the same reports pretty-printed, and for a single report, that of the input's own
//! bytes, since the JSON value is what a report states.

#![no_main]

use std::path::PathBuf;

use libfuzzer_sys::{fuzz_mutator, fuzz_target};

#[path = "json_mutator.rs"]
mod json_mutator;

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    json_mutator::mutate(data, size, max_size, seed)
});
use serde_json::Value;

/// What `chard table` would print: the table, or the refusal with its chain.
fn table(
    paths: &[PathBuf],
    format: chard::table::Format,
    by_defect: bool,
    allow_mixed: bool,
) -> String {
    match chard::table::render_files(
        paths,
        format,
        by_defect,
        allow_mixed,
        chard::table::DEFAULT_WIDTH,
    ) {
        Ok(text) => format!("ok\n{text}"),
        Err(e) => format!("err\n{e:#}"),
    }
}

/// Write each report's bytes to its path; `false` when a write failed.
fn write_all(paths: &[PathBuf], bytes: &[Vec<u8>]) -> bool {
    paths
        .iter()
        .zip(bytes)
        .all(|(path, b)| std::fs::write(path, b).is_ok())
}

/// The plain tables, both groupings, with mixed datasets allowed.
fn plain(paths: &[PathBuf]) -> [String; 2] {
    [false, true].map(|by_defect| table(paths, chard::table::Format::Text, by_defect, true))
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let single = !value.is_array();
    let reports: Vec<Value> = match value {
        Value::Array(many) => many.into_iter().take(8).collect(),
        one => vec![one.clone(), one],
    };
    let named: Vec<(String, Value)> = reports
        .iter()
        .enumerate()
        .map(|(i, r)| (format!("r{i}.json"), r.clone()))
        .collect();
    if named.is_empty() {
        return;
    }
    for set in [&named[..1], &named[..]] {
        let identity = chard::dataset::Identity::of(set);
        let _ = identity.conflicts();
        let _ = chard::dataset::self_contradicted(set);
        let first = chard::matrix::build(set).map(|m| serde_json::to_string(&m));
        let second = chard::matrix::build(set).map(|m| serde_json::to_string(&m));
        match (first, second) {
            (Ok(a), Ok(b)) => assert_eq!(
                a.ok(),
                b.ok(),
                "matrix::build over the same reports serializes differently twice"
            ),
            (Err(a), Err(b)) => assert_eq!(
                format!("{a:#}"),
                format!("{b:#}"),
                "matrix::build over the same reports refuses differently twice"
            ),
            _ => panic!("matrix::build over the same reports builds once and refuses once"),
        }
    }
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let paths: Vec<PathBuf> = (0..reports.len())
        .map(|i| dir.join(format!("chard-fuzz-report-{pid}-{i}.json")))
        .collect();
    let compact: Vec<Vec<u8>> = reports
        .iter()
        .map(|r| serde_json::to_vec(r).expect("a Value serializes"))
        .collect();
    if write_all(&paths, &compact) {
        for format in [chard::table::Format::Text, chard::table::Format::Markdown] {
            for by_defect in [false, true] {
                for allow_mixed in [false, true] {
                    assert_eq!(
                        table(&paths, format, by_defect, allow_mixed),
                        table(&paths, format, by_defect, allow_mixed),
                        "the same reports render differently twice ({format:?}, by_defect \
                         {by_defect}, allow_mixed {allow_mixed})"
                    );
                }
            }
        }
        let expected = plain(&paths);
        let pretty: Vec<Vec<u8>> = reports
            .iter()
            .map(|r| serde_json::to_vec_pretty(r).expect("a Value serializes"))
            .collect();
        if write_all(&paths, &pretty) {
            assert_eq!(
                plain(&paths),
                expected,
                "the pretty-printed reports render otherwise than the compact ones"
            );
        }
        if single && write_all(&paths, &[data.to_vec(), data.to_vec()]) {
            assert_eq!(
                plain(&paths),
                expected,
                "the input's own bytes render otherwise than the report re-serialized"
            );
        }
    }
    for path in &paths {
        let _ = std::fs::remove_file(path);
    }
});
