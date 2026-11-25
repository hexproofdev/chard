// SPDX-License-Identifier: BSD-3-Clause
//! `chard table` and `chard matrix` over arbitrary JSON: a report someone else hands you is
//! an input chard renders (`THREAT_MODEL.md`, "Against whom, and under what assumptions"),
//! so a malformed one is refused or rendered, never a panic. The input is one report, or an
//! array of them read as one dataset, which is what reaches the joins; a single report is
//! also rendered beside itself. `table` takes paths only, so each report goes through a
//! temporary file.

#![no_main]

use std::path::PathBuf;

use libfuzzer_sys::{fuzz_mutator, fuzz_target};

#[path = "json_mutator.rs"]
mod json_mutator;

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    json_mutator::mutate(data, size, max_size, seed, &[])
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
    #![expect(
        clippy::expect_used,
        clippy::panic,
        reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
    )]
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
    let Some(one) = named.get(..1) else {
        return;
    };
    for set in [one, &named[..]] {
        let identity = chard::dataset::Identity::of(set);
        let _: Vec<String> = identity.conflicts();
        let _: Vec<chard::dataset::Finding> = chard::dataset::self_contradicted(set);
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
    // A report file left behind is never read: every input writes each of its paths before
    // it renders from them.
    for path in &paths {
        chard::error::best_effort(std::fs::remove_file(path));
    }
});
