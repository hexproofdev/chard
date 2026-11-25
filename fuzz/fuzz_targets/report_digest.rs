// SPDX-License-Identifier: BSD-3-Clause
//! The digest over arbitrary JSON: `report::digest::derive`, the one derivation of the block
//! every report leads with, and `report::digest::of_read`, what `chard digest` prints of a
//! report it read. A report someone else hands you is an input chard reads (`THREAT_MODEL.md`,
//! "Against whom, and under what assumptions"), and a reader with a budget reads the digest
//! instead of the rest, so a digest its report's own fields do not give states a verdict the
//! observations under it do not.

#![no_main]

use chard::report::digest::{Digest, derive, meaning, of_read};
use chard::report::{ConsistencyStatus, flags_source};
use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use serde_json::{Map, Value};

#[path = "json_mutator.rs"]
mod json_mutator;

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    json_mutator::mutate(data, size, max_size, seed, &[])
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

#[expect(
    clippy::panic_in_result_fn,
    reason = "the assert is the law that a second derivation agrees, and a fuzz target reports a broken law by panicking"
)]
fn derived(report: &Value, status: &str) -> Result<Digest, String> {
    let first = derive(report, status);
    assert_eq!(derive(report, status), first, "a second derivation differs");
    first
}

/// A derived digest's own arithmetic, against the report it came from.
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
)]
#[expect(
    clippy::too_many_lines,
    reason = "the laws the module documentation lists for a derived digest that closes, held in one pass over its report"
)]
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
    let mut recounted = std::collections::BTreeMap::<String, usize>::new();
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
        let (found, row) = rows
            .iter()
            .enumerate()
            .skip(at)
            .find(|(_, r)| r.check == reason.check)
            .unwrap_or_else(|| panic!("the reason for {} is not a later row", reason.check));
        assert_eq!(
            row.verdict, reason.verdict,
            "{}: the reason's verdict",
            reason.check
        );
        at = found + 1;
    }
    let source = report
        .pointer("/profile/flags_source")
        .and_then(Value::as_str)
        .expect("a derived profile names its source");
    let config = report
        .pointer("/toolchain/config_files")
        .and_then(Value::as_array)
        .is_some_and(|files| !files.is_empty());
    let env = report
        .pointer("/profile/id")
        .and_then(Value::as_str)
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
        coverage["checks_expected"].as_u64(),
        "checks_expected"
    );
    assert_eq!(
        Some(copied.checks_attempted as u64),
        coverage["checks_attempted"].as_u64(),
        "checks_attempted"
    );
    assert_eq!(
        Some(copied.all_checks_attempted),
        coverage["all_checks_attempted"].as_bool(),
        "all_checks_attempted"
    );
    assert_eq!(
        Some(copied.all_verdicts_published),
        coverage["all_verdicts_published"].as_bool(),
        "all_verdicts_published"
    );
    for (field, list) in [
        ("checks_missing", &copied.checks_missing),
        ("checks_unexpected", &copied.checks_unexpected),
    ] {
        let written: Vec<&str> = coverage
            .get(field)
            .and_then(Value::as_array)
            .map_or_default(|a| a.iter().filter_map(Value::as_str).collect());
        assert_eq!(
            list.iter().map(String::as_str).collect::<Vec<_>>(),
            written,
            "{field}"
        );
    }
    assert_eq!(
        as_json.get("consistency"),
        Some(&Value::from(digest.consistency.as_str())),
        "the digest's consistency, as JSON"
    );
}

#[expect(
    clippy::panic,
    reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
)]
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
    #![expect(
        clippy::expect_used,
        reason = "a fuzz target reports a broken law by panicking; libFuzzer keeps the input as the crash"
    )]
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
    #[expect(
        clippy::indexing_slicing,
        reason = "statuses holds every ConsistencyStatus and FOREIGN_STATUS, and readings one per status, so the first of each is there"
    )]
    let (first_status, first) = (statuses[0], &readings[0]);
    for (status, reading) in statuses.iter().zip(&readings) {
        assert_eq!(
            reading.is_ok(),
            first.is_ok(),
            "derive under {status} and under {first_status} part ways"
        );
        if let Ok(digest) = reading {
            assert_eq!(
                digest.consistency, *status,
                "the status is not passed through"
            );
            let mut same = digest.clone();
            first_status.clone_into(&mut same.consistency);
            assert_eq!(
                Ok(&same),
                first.as_ref(),
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
            derive(&Value::Object(cut), first_status),
            *first,
            "a field derive does not read changed the digest"
        );
    }

    let read = ("r0.json".to_owned(), report.clone());
    if let Ok(printed) = of_read(&read) {
        let status = report
            .pointer("/consistency/status")
            .and_then(Value::as_str)
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
