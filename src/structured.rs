// SPDX-License-Identifier: BSD-3-Clause

//! A second decoder for the `compiler-diag` channel, reading SARIF beside the prose.
//!
//! Every compiler-diag verdict is decided by [`crate::probe`]'s prose decoder: a needle list
//! per check, matched against lines of `LC_ALL=C` stderr, with the severity read off the
//! line that carries the needle. That decoder stays authoritative. This module asks the same
//! question of the compiler's own structured output, so that the two can be compared and a
//! disagreement diagnosed rather than assumed away. It runs only under
//! `chard measure --structured-diagnostics`, and nothing it finds moves a verdict.
//!
//! # What the compilers offer
//!
//! Measured on Fedora 44 on 2026-09-28, gcc 16.1.1 (x86_64) and 16.2.1 (aarch64), clang
//! 22.1.8 (both):
//!
//! - gcc accepts `-fdiagnostics-format=` `text`, `sarif-stderr` and `sarif-file` only. `json`,
//!   `json-stderr` and `json-file` are rejected ("unrecognized argument"), so gcc's JSON
//!   format is gone and SARIF is the one structured form. `-fdiagnostics-add-output=sarif`
//!   also exists and keeps the text on stderr.
//! - clang accepts `-fdiagnostics-format=sarif` only, prints `diagnostic formatting in SARIF
//!   mode is currently unstable [-Wsarif-format-unstable]` as text ahead of the document, and
//!   prints its trailing `N error(s) generated.` as text after it. It has no
//!   `-fdiagnostics-add-output`.
//! - On both, a diagnostic from the driver rather than the compiler proper (an unknown
//!   option) stays text. SARIF covers what the compiler proper says, which is where every
//!   needle the prose decoder matches comes from.
//!
//! So the structured reading is taken from a separate build: the arm's own argv with the
//! SARIF-to-stderr flag appended, to its own output path. Adding the flag to the measured
//! build instead would change the stream the authoritative decoder reads, and on clang there
//! is no option that writes both.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::compile::BuildRecord;
use crate::toolchain::Kind;

/// The flag that sends this toolchain's diagnostics to stderr as SARIF, or `None` where no
/// structured form was measured.
#[must_use]
pub fn format_flag(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Gcc => Some("-fdiagnostics-format=sarif-stderr"),
        Kind::Clang => Some("-fdiagnostics-format=sarif"),
        Kind::Other => None,
    }
}

/// One SARIF result: its level and its message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: String,
    pub message: String,
}

/// What the side build produced, decoded, or why it could not be.
#[derive(Debug, Clone)]
pub struct Capture {
    pub flag: &'static str,
    pub findings: Result<Vec<Finding>, String>,
}

impl Capture {
    /// Decode a side build's record. A build that could not be run at all is `Err` with the
    /// reason, the same as a stream with no document in it.
    ///
    /// An undecodable stream's reason carries how the build ended
    /// ([`BuildRecord::ended`]: `exited N`, or `was killed by a signal`) and one stderr line,
    /// because the ordinary cause is the driver refusing a flag before the compiler proper
    /// ran, and a driver's refusal is text on both compilers. The line is the first carrying
    /// `error:`, else the first: clang 22.1.8 opens every SARIF-mode stderr with its
    /// unstable-format warning, and where an assertions build of it aborted in cc1 (Gentoo's
    /// binary package, 2026-09-30) the first line named that banner while the cause,
    /// `clang: error: unable to execute command: Aborted (core dumped)`, came later.
    #[must_use]
    pub fn of(flag: &'static str, record: Result<&BuildRecord, String>) -> Self {
        Self {
            flag,
            findings: record.and_then(|r| {
                decode(&r.stderr).map_err(|reason| {
                    let (label, line) =
                        r.stderr.lines().find(|l| l.contains("error:")).map_or_else(
                            || ("first line", r.stderr.lines().next().unwrap_or("<empty>")),
                            |l| ("first error", l),
                        );
                    format!("{reason} ({}; {label}: {line})", r.ended())
                })
            }),
        }
    }
}

/// Read the first SARIF document out of a stderr that may carry text around it.
///
/// The document is the first line that opens with `{`; everything after the value closes is
/// ignored, which is where clang's `N error(s) generated.` and any linker text land.
///
/// # Errors
///
/// When no document starts on any line, when the text there is not JSON, or when it has no
/// `runs` array. Each is `undecodable`, never an empty list of findings: an empty list would
/// read as the compiler having said nothing.
pub fn decode(stderr: &str) -> Result<Vec<Finding>, String> {
    let start = if stderr.starts_with('{') {
        Some(0)
    } else {
        stderr.find("\n{").map(|i| i.saturating_add(1))
    }
    .ok_or_else(|| "no SARIF document on stderr".to_owned())?;
    let text = stderr
        .get(start..)
        .ok_or_else(|| "no SARIF document on stderr".to_owned())?;
    let doc: Value = serde_json::Deserializer::from_str(text)
        .into_iter::<Value>()
        .next()
        .ok_or_else(|| "no SARIF document on stderr".to_owned())?
        .map_err(|e| format!("SARIF document does not parse: {e}"))?;
    let runs = doc
        .get("runs")
        .and_then(Value::as_array)
        .ok_or_else(|| "SARIF document has no runs array".to_owned())?;
    // A run without `results`, or a result without message text, is undecodable rather
    // than silent. Both compilers write `"results": []` for a build with nothing to say
    // (gcc 16.1.1, clang 22.1.8 and Apple clang 21, 2026-09-28), so an absent array is a
    // document this decoder does not understand, not an empty one.
    let mut findings = Vec::new();
    for run in runs {
        let results = run
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| "a SARIF run has no results array".to_owned())?;
        for result in results {
            let message = result
                .pointer("/message/text")
                .and_then(Value::as_str)
                .ok_or_else(|| "a SARIF result has no message text".to_owned())?;
            findings.push(Finding {
                // SARIF 2.1.0 section 3.27.10: an absent level means `warning`.
                level: result
                    .get("level")
                    .and_then(Value::as_str)
                    .unwrap_or("warning")
                    .to_owned(),
                message: message.to_owned(),
            });
        }
    }
    Ok(findings)
}

/// The level of the first finding whose message carries a needle, in the vocabulary the prose
/// decoder answers in, or `None` when no finding does.
///
/// `note` is kept as `note` rather than folded into `warning`. The prose decoder reads a
/// matched line with neither `error:` nor `warning:` as a warning, and a disagreement there is
/// one the comparison should show rather than absorb.
#[must_use]
pub fn severity_of(findings: &[Finding], needles: &[&str]) -> Option<&'static str> {
    let needles: Vec<String> = needles.iter().map(|n| n.to_lowercase()).collect();
    findings
        .iter()
        .find(|f| {
            let message = f.message.to_lowercase();
            needles.iter().any(|n| message.contains(n.as_str()))
        })
        .map(|f| match f.level.as_str() {
            "error" => "error",
            "note" => "note",
            "none" => "none",
            _ => "warning",
        })
}

/// The prose decoder's readings, the structured decoder's, and a comparison's outcomes: the
/// closed vocabularies [`ArmComparison`] publishes, pinned against the schema by
/// `tests/schema_conformance.rs`.
pub const PROSE_READINGS: [&str; 4] = ["error", "warning", "absent", "unreadable"];
pub const STRUCTURED_READINGS: [&str; 6] =
    ["error", "warning", "note", "none", "absent", "undecodable"];
pub const OUTCOMES: [&str; 3] = ["agree", "disagree", "undecodable"];

/// One arm read by both decoders.
#[derive(Debug, Clone, Serialize)]
pub struct ArmComparison {
    /// The prose decoder's reading: `error`, `warning`, `absent`, or `unreadable` (the matched
    /// line names no severity, or the arm's own stderr is a structured document).
    pub prose: &'static str,
    /// The structured decoder's reading: `error`, `warning`, `note`, `none`, `absent`, or
    /// `undecodable`.
    pub structured: &'static str,
    /// `agree`, `disagree`, or `undecodable`.
    pub outcome: &'static str,
    /// Why the structured reading could not be taken, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The arms a comparison is fed, in the order it is fed them: every check's measured build
/// and its two controls, the negative being the clean build where the check has none.
pub const ARMS: [&str; 3] = ["measured", "positive", "negative"];

/// Both decoders over every arm of one check that was built.
#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    /// The flag the structured side build carried.
    pub format: &'static str,
    /// How many arms the comparison was fed: [`ARMS`]'s length. `arms` and `arms_missing`
    /// together account for every one of them.
    pub arms_expected: usize,
    /// Keyed by arm: `measured`, `positive`, `negative`.
    pub arms: BTreeMap<&'static str, ArmComparison>,
    /// Arms fed with no build of their own or no side build, so nothing was compared. Each
    /// is also a warning in the report's diagnostics.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arms_missing: Vec<&'static str>,
}

/// Compare one arm. `prose` is what the authoritative decoder read off the arm's own build.
#[must_use]
pub fn compare(prose: Option<&'static str>, capture: &Capture, needles: &[&str]) -> ArmComparison {
    let prose = prose.unwrap_or("absent");
    match &capture.findings {
        Err(reason) => ArmComparison {
            prose,
            structured: "undecodable",
            outcome: "undecodable",
            reason: Some(reason.clone()),
        },
        Ok(findings) => {
            let structured = severity_of(findings, needles).unwrap_or("absent");
            ArmComparison {
                prose,
                structured,
                outcome: if prose == structured {
                    "agree"
                } else {
                    "disagree"
                },
                reason: None,
            }
        }
    }
}

/// The run-level account of the gate: what was compared, and how it came out.
///
/// Counted against what was eligible, for the reason `coverage` is: a gate that compared
/// nothing and reported no disagreement would read as agreement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// The flag used, or absent where this toolchain has no structured form chard knows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<&'static str>,
    /// Observations of checks the structured decoder has needles for.
    pub checks_eligible: usize,
    /// Of those, the ones that carry a comparison.
    pub checks_compared: usize,
    /// Eligible checks with no comparison, which is every check withheld before its arms
    /// were built.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_compared: Vec<String>,
    /// The arms the compared checks were fed, summed over their comparisons.
    pub arms_expected: usize,
    /// Of those, the arms that carried no build or no side build and were not compared.
    /// `arms_compared + arms_missing == arms_expected`.
    pub arms_missing: usize,
    pub arms_compared: usize,
    pub agreed: usize,
    pub disagreed: usize,
    pub undecodable: usize,
}

impl Summary {
    /// Count the gate's work over a run's observations.
    #[must_use]
    pub fn over(format: Option<&'static str>, observations: &[crate::report::Observation]) -> Self {
        let mut summary = Self {
            format,
            ..Self::default()
        };
        for obs in observations {
            if crate::probe::diag_needles(&obs.check).is_none() {
                continue;
            }
            summary.checks_eligible = summary.checks_eligible.saturating_add(1);
            let Some(comparison) = obs.structured_diagnostics.as_ref() else {
                summary.not_compared.push(obs.check.clone());
                continue;
            };
            summary.checks_compared = summary.checks_compared.saturating_add(1);
            summary.arms_expected = summary
                .arms_expected
                .saturating_add(comparison.arms_expected);
            summary.arms_missing = summary
                .arms_missing
                .saturating_add(comparison.arms_missing.len());
            for arm in comparison.arms.values() {
                summary.arms_compared = summary.arms_compared.saturating_add(1);
                let slot = match arm.outcome {
                    "agree" => &mut summary.agreed,
                    "disagree" => &mut summary.disagreed,
                    _ => &mut summary.undecodable,
                };
                *slot = slot.saturating_add(1);
            }
        }
        summary
    }

    /// The ways this summary does not add up, one sentence each; empty when it does.
    ///
    /// A summary recomputed from the same observations passes these by construction. They
    /// hold the published document, which the consistency rule reads, to its own sums.
    #[must_use]
    pub fn imbalances(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.checks_compared.saturating_add(self.not_compared.len()) != self.checks_eligible {
            out.push(format!(
                "checks_compared ({}) + not_compared ({}) != checks_eligible ({})",
                self.checks_compared,
                self.not_compared.len(),
                self.checks_eligible
            ));
        }
        if self.arms_compared.saturating_add(self.arms_missing) != self.arms_expected {
            out.push(format!(
                "arms_compared ({}) + arms_missing ({}) != arms_expected ({})",
                self.arms_compared, self.arms_missing, self.arms_expected
            ));
        }
        let outcomes = self
            .agreed
            .saturating_add(self.disagreed)
            .saturating_add(self.undecodable);
        if outcomes != self.arms_compared {
            out.push(format!(
                "agreed + disagreed + undecodable ({outcomes}) != arms_compared ({})",
                self.arms_compared
            ));
        }
        out
    }

    /// One sentence per disagreeing, undecodable or missing arm, for the report's
    /// diagnostics.
    #[must_use]
    pub fn findings(observations: &[crate::report::Observation]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for obs in observations {
            let Some(comparison) = obs.structured_diagnostics.as_ref() else {
                continue;
            };
            for arm in &comparison.arms_missing {
                out.push((obs.check.clone(), arm_missing(arm, comparison.format)));
            }
            for (arm, c) in &comparison.arms {
                let sentence = match c.outcome {
                    "disagree" => format!(
                        "the structured and prose decoders disagree on the {arm} arm: prose \
                         read `{}`, {} read `{}`. The verdict is the prose decoder's",
                        c.prose, comparison.format, c.structured
                    ),
                    "undecodable" => format!(
                        "the {arm} arm's {} side build could not be decoded: {}",
                        comparison.format,
                        c.reason.as_deref().unwrap_or("no reason recorded")
                    ),
                    _ => continue,
                };
                out.push((obs.check.clone(), sentence));
            }
        }
        out
    }
}

/// The diagnostic for an arm fed with nothing to compare.
fn arm_missing(arm: &str, format: &str) -> String {
    format!(
        "the {arm} arm was not compared: it carried no build of its own or no {format} side \
         build"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(exit_status: i32, stderr: &str) -> BuildRecord {
        BuildRecord {
            argv: Vec::new(),
            dropped_flags: Vec::new(),
            exit_status,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        }
    }

    /// An undecodable side build names its error line, not a banner ahead of it.
    ///
    /// The stderr is the shape Gentoo's assertions build of clang 22.1.8 wrote on
    /// 2026-09-30: the unstable-format warning, the assertion, then the driver's error.
    #[test]
    fn an_undecodable_reason_quotes_the_error_over_a_banner() {
        let aborted = record(
            1,
            "clang: warning: diagnostic formatting in SARIF mode is currently unstable \
             [-Wsarif-format-unstable]\nclang-22: SARIFDiagnosticPrinter.cpp:50: Assertion \
             failed.\nclang: error: unable to execute command: Aborted (core dumped)\n",
        );
        let Err(reason) = Capture::of("-fdiagnostics-format=sarif", Ok(&aborted)).findings else {
            panic!("no document was written");
        };
        assert!(
            reason.ends_with(
                "first error: clang: error: unable to execute command: Aborted (core dumped))"
            ),
            "{reason}"
        );

        let refused = record(1, "cc1: unrecognized option\nsecond line\n");
        let Err(reason) = Capture::of("-fdiagnostics-format=sarif", Ok(&refused)).findings else {
            panic!("no document was written");
        };
        assert!(
            reason.ends_with("first line: cc1: unrecognized option)"),
            "{reason}"
        );
    }

    /// An undecodable reason says how the build ended in `BuildRecord::ended`'s words: the
    /// `-1` sentinel names a signal, never "exit -1", and a real `exit(-1)`, which reads 255
    /// on Unix, keeps its number.
    #[test]
    fn an_undecodable_reason_says_how_the_build_ended() {
        for (exit_status, ended) in [
            (-1, "was killed by a signal"),
            (255, "exited 255"),
            (1, "exited 1"),
        ] {
            let Err(reason) = Capture::of(
                "-fdiagnostics-format=sarif",
                Ok(&record(exit_status, "cc1: gone\n")),
            )
            .findings
            else {
                panic!("no document was written");
            };
            assert!(
                reason.ends_with(&format!(" ({ended}; first line: cc1: gone)")),
                "{reason}"
            );
        }
    }

    /// The missing-arm diagnostic is one sentence, spaced as written.
    #[test]
    fn the_missing_arm_sentence_is_spaced_as_written() {
        assert_eq!(
            arm_missing("negative", "-fdiagnostics-format=sarif"),
            "the negative arm was not compared: it carried no build of its own or no \
             -fdiagnostics-format=sarif side build"
        );
    }

    /// gcc 16.1.1's shape: the document alone on stderr, one result per diagnostic.
    const GCC: &str = r#"{"$schema": "x", "version": "2.1.0",
 "runs": [{"tool": {"driver": {"name": "GNU C23"}},
           "results": [{"ruleId": "-Werror=format-security", "level": "error",
                        "message": {"text": "format not a string literal and no format arguments"}}]}]}
"#;

    /// clang 22.1.8's shape: a text warning before the document and a count after it.
    const CLANG: &str = "clang: warning: diagnostic formatting in SARIF mode is currently \
                         unstable [-Wsarif-format-unstable]\n\n{\"runs\":[{\"results\":[\
                         {\"level\":\"warning\",\"message\":{\"text\":\"format string is not \
                         a string literal (potentially insecure)\"}},{\"level\":\"note\",\
                         \"message\":{\"text\":\"treat the string as an argument to avoid \
                         this\"}}]}]}\n\n1 warning generated.\n";

    #[test]
    fn both_compilers_documents_decode_around_their_text() {
        let gcc = decode(GCC).expect("gcc's document decodes");
        assert_eq!(gcc.len(), 1);
        assert_eq!(severity_of(&gcc, &["not a string literal"]), Some("error"));

        let clang = decode(CLANG).expect("clang's document decodes past its text");
        assert_eq!(clang.len(), 2);
        assert_eq!(
            severity_of(&clang, &["not a string literal"]),
            Some("warning")
        );
        assert_eq!(severity_of(&clang, &["no such wording"]), None);
    }

    /// A stream with no document is undecodable, never an empty list: an empty list reads as
    /// a compiler that said nothing, which is the silence this project refuses to publish.
    #[test]
    fn a_stream_without_a_document_is_undecodable_not_silent() {
        assert!(decode("gcc: error: unrecognized command-line option '-fno-such'\n").is_err());
        assert!(decode("").is_err());
        assert!(decode("{\"version\": \"2.1.0\"}").is_err(), "no runs array");
        assert!(decode("{not json").is_err());
        assert!(
            decode("{\"runs\": [{}]}").is_err(),
            "a run with no results array"
        );
        assert!(
            decode("{\"runs\": [{\"results\": [{\"level\": \"error\"}]}]}").is_err(),
            "a result with no message"
        );
        assert_eq!(decode("{\"runs\": [{\"results\": []}]}"), Ok(Vec::new()));
        // A brace inside a text line is not a document.
        assert!(decode("t.c:1:1: warning: expected '{' here\n").is_err());
    }

    #[test]
    fn a_comparison_names_each_outcome() {
        let capture = Capture {
            flag: "-fdiagnostics-format=sarif",
            findings: decode(CLANG),
        };
        let needles = ["not a string literal"];
        assert_eq!(
            compare(Some("warning"), &capture, &needles).outcome,
            "agree"
        );
        let d = compare(Some("error"), &capture, &needles);
        assert_eq!((d.outcome, d.structured), ("disagree", "warning"));
        assert_eq!(
            compare(None, &capture, &["absent wording"]).outcome,
            "agree"
        );

        let broken = Capture {
            flag: "-fdiagnostics-format=sarif",
            findings: Err("no SARIF document on stderr".to_owned()),
        };
        let u = compare(Some("warning"), &broken, &needles);
        assert_eq!(u.outcome, "undecodable");
        assert!(u.reason.is_some());
    }

    /// The prose decoder reads a matched line with no severity word as a warning; the
    /// structured one keeps `note`, so that difference surfaces as a disagreement.
    #[test]
    fn a_note_is_not_folded_into_a_warning() {
        let findings = vec![Finding {
            level: "note".to_owned(),
            message: "treat the string as an argument".to_owned(),
        }];
        assert_eq!(severity_of(&findings, &["treat the string"]), Some("note"));
        let none = vec![Finding {
            level: "none".to_owned(),
            message: "treat the string as an argument".to_owned(),
        }];
        assert_eq!(severity_of(&none, &["treat the string"]), Some("none"));
    }

    #[test]
    fn only_the_two_measured_families_have_a_format() {
        assert!(format_flag(Kind::Gcc).is_some());
        assert!(format_flag(Kind::Clang).is_some());
        assert_eq!(format_flag(Kind::Other), None);
    }
}
