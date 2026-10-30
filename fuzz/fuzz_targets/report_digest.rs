// SPDX-License-Identifier: BSD-3-Clause
//! The digest over arbitrary JSON: `report::digest::derive`, the one derivation of the block
//! every report leads with, and `report::digest::of_read`, which is what `chard digest`
//! prints of a report it read. A report someone else hands you is an input chard reads
//! (THREAT_MODEL.md, "Whoever hands you the report"), and the digest is the part of it a
//! reader with a budget reads instead of the rest, so a digest printed that is not the one
//! the report's own fields give is a verdict the observations under it do not state.
//!
//! The input is one JSON value, mutated structurally by `json_mutator.rs`. Held for every
//! input:
//!
//! - `derive` returns without a panic, and returns the same digest or the same refusal twice,
//!   under each `consistency.status` word and under one no report writes;
//! - the status is passed through and nothing else reads it: the digest's `consistency` is
//!   the word given, and the digests under two words differ in that field alone;
//! - the digest reads seven fields and no other: over an object, the object cut to
//!   `chard_schema`, `run`, `toolchain`, `profile`, `environment`, `coverage` and
//!   `observations` reads to the same digest or the same refusal, so the `digest` the report
//!   carries, and anything else in it, decides nothing in the derivation;
//! - a derived digest serializes and closes: its verdict counts are the observations' verdicts
//!   counted, its rows are the observations' checks in order, each with its observation's verdict,
//!   level, polarity, channel and gating rule, its copied coverage fields are the report's own, its
//!   reasons are rows of those checks in the rows' order with the rows' verdicts, and its profile's
//!   sentence is `meaning`'s for the profile's `flags_source`;
//! - `of_read` returns without a panic, and where it returns a digest, that digest is the
//!   one `derive` gives over the same report under its own `consistency.status`, as JSON:
//!   `chard digest` prints only a digest its report's own fields give. On a report as
//!   `measure` wrote it the two are the same, and on one edited apart from its observations
//!   the read refuses;
//! - `meaning` gives a sentence for every `flags_source` chard writes, under each of its two
//!   clauses, and refuses any other word, the input's `profile.flags_source` among them.
//!
//! The seeds are reports: `make fuzz-seed`'s, under `corpus/detect_evidence/`, and the
//! tracked `tests/fixtures/sample-report.json`, which `make fuzz` and `make fuzz-replay`
//! name by its directory.

#![no_main]

use chard::report::digest::{Digest, derive, meaning, of_read};
use chard::report::{ConsistencyStatus, flags_source};
use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use serde_json::{Map, Value};

#[path = "json_mutator.rs"]
mod json_mutator;

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    json_mutator::mutate(data, size, max_size, seed)
});

/// The fields `derive` is documented to read.
const READ: [&str; 7] = [
    "chard_schema",
    "run",
    "toolchain",
    "profile",
    "environment",
    "coverage",
    "observations",
];
/// A status word no report writes.
const FOREIGN_STATUS: &str = "unchecked";

fn derived(report: &Value, status: &str) -> Result<Digest, String> {
    let first = derive(report, status);
    assert_eq!(derive(report, status), first, "a second derivation differs");
    first
}

/// A derived digest's own arithmetic, against the report it came from.
fn check_closes(digest: &Digest, report: &Value) {
    let as_json = serde_json::to_value(digest).expect("a derived digest serializes");
    let rows = &digest.checks;
    let counted: usize = digest.coverage.verdict_counts.values().sum();
    assert_eq!(
        counted,
        rows.len(),
        "the verdict counts do not sum to the rows"
    );
    let checks: Vec<&str> = report["observations"]
        .as_array()
        .expect("a digest derived from observations")
        .iter()
        .map(|o| {
            o["check"]
                .as_str()
                .expect("a derived row's check is a string")
        })
        .collect();
    let row_checks: Vec<&str> = rows.iter().map(|r| r.check.as_str()).collect();
    assert_eq!(
        row_checks, checks,
        "the rows are not the observations' checks in order"
    );
    // Each row says what its observation says, and the counts are the observations' own.
    let observations = report["observations"].as_array().expect("read above");
    let mut recounted: std::collections::BTreeMap<String, usize> = Default::default();
    for (row, obs) in rows.iter().zip(observations) {
        let verdict = serde_json::to_value(row.verdict).expect("a verdict serializes");
        assert_eq!(verdict, obs["verdict"], "{}: the row's verdict", row.check);
        assert_eq!(
            row.level.as_deref(),
            obs.get("level").and_then(Value::as_str),
            "{}: the row's level",
            row.check
        );
        assert_eq!(
            Some(row.polarity.as_str()),
            obs["polarity"].as_str(),
            "{}: the row's polarity",
            row.check
        );
        assert_eq!(
            Some(row.channel.as_str()),
            obs["channel"].as_str(),
            "{}: the row's channel",
            row.check
        );
        let word = verdict.as_str().expect("a verdict is a word").to_owned();
        *recounted.entry(word).or_default() += 1;
    }
    assert_eq!(
        digest.coverage.verdict_counts, recounted,
        "the verdict counts are not the observations' verdicts counted"
    );
    let mut at = 0usize;
    for reason in &digest.reasons {
        let found = rows[at..]
            .iter()
            .position(|r| r.check == reason.check)
            .unwrap_or_else(|| panic!("the reason for {} is not a later row", reason.check));
        let row = &rows[at + found];
        assert_eq!(
            row.verdict, reason.verdict,
            "{}: the reason's verdict",
            reason.check
        );
        at += found + 1;
    }
    let source = report["profile"]["flags_source"]
        .as_str()
        .expect("a derived profile names its source");
    let config = report["toolchain"]["config_files"]
        .as_array()
        .is_some_and(|files| !files.is_empty());
    let env = report["profile"]["id"]
        .as_str()
        .is_some_and(|id| id.contains("+env:"));
    assert_eq!(
        meaning(source, config, env).as_ref(),
        Ok(&digest.profile.meaning),
        "the profile's sentence is not meaning's"
    );
    for (row, obs) in rows.iter().zip(observations) {
        assert_eq!(
            row.gating.as_deref(),
            obs.get("gating")
                .and_then(|g| g.get("rule"))
                .and_then(Value::as_str),
            "{}: the row's gating rule",
            row.check
        );
    }
    // The coverage fields the digest copies are the report's own.
    let coverage = &report["coverage"];
    let copied = &digest.coverage;
    assert_eq!(
        Some(copied.checks_expected as u64),
        coverage["checks_expected"].as_u64()
    );
    assert_eq!(
        Some(copied.checks_attempted as u64),
        coverage["checks_attempted"].as_u64()
    );
    assert_eq!(
        Some(copied.all_checks_attempted),
        coverage["all_checks_attempted"].as_bool()
    );
    assert_eq!(
        Some(copied.all_verdicts_published),
        coverage["all_verdicts_published"].as_bool()
    );
    for (field, list) in [
        ("checks_missing", &copied.checks_missing),
        ("checks_unexpected", &copied.checks_unexpected),
    ] {
        let written: Vec<&str> = coverage
            .get(field)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert_eq!(
            list.iter().map(String::as_str).collect::<Vec<_>>(),
            written,
            "{field}"
        );
    }
    assert_eq!(as_json["consistency"], digest.consistency.as_str());
}

fn check_meaning(report: &Value) {
    for source in flags_source::ALL {
        for config in [false, true] {
            for env in [false, true] {
                let sentence = meaning(source, config, env)
                    .unwrap_or_else(|e| panic!("{source} has no sentence: {e}"));
                assert!(!sentence.is_empty(), "{source}: an empty sentence");
            }
        }
    }
    if let Some(word) = report
        .get("profile")
        .and_then(|p| p.get("flags_source"))
        .and_then(Value::as_str)
    {
        assert_eq!(
            meaning(word, false, false).is_ok(),
            flags_source::ALL.contains(&word),
            "meaning over {word:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(report) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let statuses: Vec<&str> = ConsistencyStatus::ALL
        .iter()
        .map(|s| s.as_str())
        .chain([FOREIGN_STATUS])
        .collect();
    let readings: Vec<Result<Digest, String>> =
        statuses.iter().map(|s| derived(&report, s)).collect();
    for (status, reading) in statuses.iter().zip(&readings) {
        assert_eq!(
            reading.is_ok(),
            readings[0].is_ok(),
            "derive under {status} and under {} part ways",
            statuses[0]
        );
        if let Ok(digest) = reading {
            assert_eq!(
                digest.consistency, *status,
                "the status is not passed through"
            );
            let mut same = digest.clone();
            same.consistency = statuses[0].to_owned();
            assert_eq!(
                Ok(&same),
                readings[0].as_ref(),
                "the digest under {status} differs beyond its status"
            );
            check_closes(digest, &report);
        }
    }

    if let Value::Object(map) = &report {
        let cut: Map<String, Value> = map
            .iter()
            .filter(|(k, _)| READ.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assert_eq!(
            derive(&Value::Object(cut), statuses[0]),
            readings[0],
            "a field derive does not read changed the digest"
        );
    }

    let read = ("r0.json".to_owned(), report.clone());
    if let Ok(printed) = of_read(&read) {
        let status = report["consistency"]["status"]
            .as_str()
            .expect("a digest printed carries its status");
        let own = derive(&report, status)
            .map(|d| serde_json::to_value(d).expect("a derived digest serializes"));
        assert_eq!(
            own.as_ref(),
            Ok(printed),
            "chard digest printed a digest other than the one the report's fields give"
        );
    }

    check_meaning(&report);
});
