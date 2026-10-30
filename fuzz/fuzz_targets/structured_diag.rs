// SPDX-License-Identifier: BSD-3-Clause
//! The structured compiler-diagnostics decoder over arbitrary text: `structured::decode`
//! reads the SARIF document a side build under `--structured-diagnostics` prints on stderr,
//! and `structured::severity_of` and `structured::compare` turn its findings into the
//! readings and outcomes a report publishes. The stderr is the compiler's (THREAT_MODEL.md,
//! "The operator chose the toolchain"), so a failure here is a defect in chard's reader and
//! not an attack; but a decoder that reads a document other than the one the compiler wrote
//! publishes a comparison of the prose decoder against something no compiler said.
//!
//! The input is the stderr: the bytes decoded as UTF-8 lossily, as `compile` reads a
//! build's stderr. Held for every input:
//!
//! - `decode` returns without a panic, and returns the same reading twice;
//! - the text around the document is not read. A line of text ahead of the input (clang's
//!   unstable-format warning) leaves the reading exactly as it was, a refusal's sentence
//!   included; and where the input decodes, text after it (clang's `N error generated.`)
//!   leaves the findings as they were, since the document is the first value and it closed;
//! - the findings are what the document says: written back as a document of one run whose
//!   results carry each finding's level and message, in order, they decode to themselves;
//! - `severity_of` answers in the vocabulary the comparison publishes (`error`, `warning`,
//!   `note`, `none`; any other level reads as `warning`), with the level of the first finding
//!   whose message carries a needle, case folded by `to_lowercase`; answers `None` exactly
//!   when none does; and answers for a needle taken from a finding's own message;
//! - `compare`, for every prose reading the prose decoder gives and none, publishes a
//!   structured reading in `STRUCTURED_READINGS` and an outcome in `OUTCOMES`: `undecodable`
//!   with the reason where the stream did not decode, otherwise `agree` exactly when the two
//!   readings are the same word, the structured one being `severity_of`'s or `absent`.
//!
//! The comparison against the authoritative prose decoder, which is `pub(crate)` and not
//! reached from here, is the seeds' part: `seed.rs` writes every stderr of
//! `tests/fixtures/detectors.json` that carries a `runs` key and holds each to decode to at
//! least one finding with a level SARIF names, since each is a document a real gcc or clang
//! printed and the decoder's reading of a real one is what `--structured-diagnostics`
//! publishes. The tracked seeds under `seeds/structured_diag/` are two of them and the shapes
//! `structured.rs`'s unit tests use.

#![no_main]

use chard::structured::{
    self, Capture, Finding, OUTCOMES, PROSE_READINGS, STRUCTURED_READINGS, compare, decode,
    severity_of,
};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

/// clang 22.1.8's line ahead of every SARIF-mode stderr.
const BANNER: &str = "clang: warning: diagnostic formatting in SARIF mode is currently unstable \
                      [-Wsarif-format-unstable]\n";
/// The text clang prints after the document.
const TRAILER: &str = "\n1 error generated.\n";
/// The levels `severity_of` answers in.
const SEVERITIES: [&str; 4] = ["error", "warning", "note", "none"];

/// `findings` as a document of one run, each result's level written out.
fn document(findings: &[Finding]) -> String {
    let results: Vec<_> = findings
        .iter()
        .map(|f| json!({"level": f.level, "message": {"text": f.message}}))
        .collect();
    json!({"version": "2.1.0", "runs": [{"results": results}]}).to_string()
}

/// A needle taken from a finding's message: its first word of up to 16 characters, or the
/// message itself where it has none.
fn needle_of(message: &str) -> String {
    message
        .split_whitespace()
        .next()
        .unwrap_or(message)
        .chars()
        .take(16)
        .collect()
}

fn check_severity(findings: &[Finding], needles: &[&str]) {
    let read = severity_of(findings, needles);
    assert_eq!(
        severity_of(findings, needles),
        read,
        "a second reading differs"
    );
    if let Some(level) = read {
        assert!(
            SEVERITIES.contains(&level),
            "severity_of answered {level:?}"
        );
        // The first finding carrying a needle answers, its level in the four words, every
        // level SARIF does not name read as `warning`.
        let first = findings
            .iter()
            .find(|f| {
                let message = f.message.to_lowercase();
                needles
                    .iter()
                    .any(|n| message.contains(n.to_lowercase().as_str()))
            })
            .expect("a needle is carried");
        let expected = match first.level.as_str() {
            l @ ("error" | "note" | "none") => l,
            _ => "warning",
        };
        assert_eq!(level, expected, "the level of {:?}", first.message);
    }
    let lowered: Vec<String> = needles.iter().map(|n| n.to_lowercase()).collect();
    let carried = findings.iter().any(|f| {
        let message = f.message.to_lowercase();
        lowered.iter().any(|n| message.contains(n.as_str()))
    });
    assert_eq!(
        read.is_some(),
        carried,
        "severity_of answered {read:?} where a needle of {needles:?} is carried: {carried}"
    );
    if needles.iter().all(|n| n.is_ascii()) {
        let upper: Vec<String> = needles.iter().map(|n| n.to_ascii_uppercase()).collect();
        let upper: Vec<&str> = upper.iter().map(String::as_str).collect();
        assert_eq!(
            severity_of(findings, &upper),
            read,
            "the needles {needles:?} read otherwise in upper case"
        );
    }
}

fn check_compare(capture: &Capture, needles: &[&str]) {
    for prose in PROSE_READINGS.iter().copied().map(Some).chain([None]) {
        let arm = compare(prose, capture, needles);
        assert_eq!(
            arm.prose,
            prose.unwrap_or("absent"),
            "the prose reading changed"
        );
        assert!(
            STRUCTURED_READINGS.contains(&arm.structured),
            "compare published the structured reading {:?}",
            arm.structured
        );
        assert!(
            OUTCOMES.contains(&arm.outcome),
            "compare published the outcome {:?}",
            arm.outcome
        );
        match &capture.findings {
            Err(reason) => {
                assert_eq!(
                    (arm.structured, arm.outcome),
                    ("undecodable", "undecodable")
                );
                assert_eq!(arm.reason.as_deref(), Some(reason.as_str()), "the reason");
            }
            Ok(findings) => {
                assert!(arm.reason.is_none(), "a decoded arm carries a reason");
                assert_eq!(
                    arm.structured,
                    severity_of(findings, needles).unwrap_or("absent"),
                    "compare's structured reading is not severity_of's"
                );
                let agree = arm.prose == arm.structured;
                assert_eq!(arm.outcome, if agree { "agree" } else { "disagree" });
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let stderr = String::from_utf8_lossy(data);
    let read = decode(&stderr);
    assert_eq!(decode(&stderr), read, "a second reading differs");
    assert_eq!(
        decode(&format!("{BANNER}{stderr}")),
        read,
        "a line of text ahead of the stderr changed its reading"
    );
    if let Ok(findings) = &read {
        assert_eq!(
            decode(&format!("{stderr}{TRAILER}")).as_ref(),
            Ok(findings),
            "text after the document changed its findings"
        );
        assert_eq!(
            decode(&document(findings)).as_ref(),
            Ok(findings),
            "the findings written back as a document read otherwise"
        );
    }

    let findings = read.clone().unwrap_or_default();
    let own: Vec<String> = findings.iter().map(|f| needle_of(&f.message)).collect();
    let mut needles: Vec<&str> = own.iter().map(String::as_str).take(4).collect();
    // ASCII alone: Unicode lowercasing is not substring-preserving (a final sigma).
    for f in findings.iter().filter(|f| f.message.is_ascii()) {
        if let Some(word) = own.iter().find(|n| f.message.contains(n.as_str())) {
            assert!(
                severity_of(std::slice::from_ref(f), &[word]).is_some(),
                "a needle from the message {:?} found nothing",
                f.message
            );
        }
    }
    // A needle the input chose: its last line, which a mutation reaches.
    let chosen = stderr.lines().last().unwrap_or("").to_owned();
    needles.push(&chosen);
    check_severity(&findings, &needles);
    check_severity(&findings, &[]);

    let capture = Capture {
        flag: structured::format_flag(chard::toolchain::Kind::Clang).expect("clang has one"),
        findings: read,
    };
    check_compare(&capture, &needles);
});
