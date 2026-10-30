// SPDX-License-Identifier: BSD-3-Clause

//! The digest: a report's verdicts and what they stand on, ahead of the evidence.
//!
//! A report is about a megabyte pretty-printed, and most of it is the replay evidence
//! (`observations[].controls`, `facts`, `decoders`); the fields that say what was found and
//! whether to trust the file, `coverage` and `consistency`, came last. A reader going front
//! to back, an agent with a context budget among them, paid for the evidence before it
//! reached the verdicts. The digest is the report's first key and what `chard digest`
//! prints: the consistency status, coverage with its earned limitations apart from its
//! instrument withholdings, one row per check, every reason a check is not a measurement in
//! one list, and the identity a reader joins on (toolchain, profile with its flags hash and
//! what the profile measures, execution mode with its basis, revision and corpus hashes).
//! No notes, references, facts, decoders, invocation or score.
//!
//! It states nothing about the measurement the file does not already say: every field is
//! derived from the report's own JSON by [`derive`], the one derivation, and the one sentence
//! chard writes there, the profile's [`meaning`], is keyed on `profile.flags_source`.
//! [`super::publish`] runs the derivation over the report it is about to write, and the
//! consistency rule [`super::RULE_DIGEST`] runs it again over a report read back (`table`,
//! `matrix`, `digest`) and compares, so a digest edited apart from the observations under it
//! is refused rather than read. At publication the rule asks only whether the derivation goes
//! through, since the block is then made by it.
//! Deriving from the JSON rather than from [`super::Report`] is what lets one function
//! serve both sides: `Report` is not `Deserialize`, and a second derivation over the typed
//! report would be a checker that can drift from the one the reader runs.
//!
//! The coverage it carries is recounted from the observations, not copied from `coverage`,
//! so the two agree only where the observations do; `coverage`'s own rules hold that block
//! to the same observations. `checks_expected` and the two id lists are copied, since the
//! selection they count is not in the observations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{ObservationView, Standing, Verdict, Withholding, flags_source};

/// The block, in the order a reader needs it: whether to trust the file, what it found,
/// why each unmeasured check is unmeasured, then what was measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Digest {
    /// The report's `chard_schema`, so the block printed alone still names its shape.
    pub chard_schema: String,
    /// `consistency.status`.
    pub consistency: String,
    pub coverage: CoverageDigest,
    /// One row per observation, in the report's order.
    pub checks: Vec<Row>,
    /// One entry per observation that is not a measurement, in the report's order. Absent
    /// when every check measured.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<Reason>,
    /// `toolchain.id`.
    pub toolchain: String,
    pub profile: ProfileDigest,
    pub execution: ExecutionDigest,
    pub run: RunDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageDigest {
    /// `coverage.checks_expected`.
    pub checks_expected: usize,
    /// `coverage.checks_attempted`.
    pub checks_attempted: usize,
    /// `coverage.checks_missing`, absent when empty as there.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks_missing: Vec<String>,
    /// `coverage.checks_unexpected`, absent when empty as there.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks_unexpected: Vec<String>,
    /// `coverage.all_checks_attempted`.
    pub all_checks_attempted: bool,
    /// `coverage.all_verdicts_published`.
    pub all_verdicts_published: bool,
    /// The observations' verdicts, counted.
    pub verdict_counts: BTreeMap<String, usize>,
    /// The observations as [`Withholding::of`] counts them: measured, earned limitations,
    /// instrument withholdings.
    pub withholding: Withholding,
}

/// One observation: its verdict and what the verdict is read through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub check: String,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// `harden` or `weaken`: for a `weaken` check `off` is the protected state.
    pub polarity: String,
    pub channel: String,
    /// `gating.rule`, where a gating rule decided the verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gating: Option<String>,
}

/// Why one observation is not a measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reason {
    pub check: String,
    pub verdict: Verdict,
    /// `earned-limitation` or `instrument-withholding`, as [`Standing`] decides.
    pub standing: &'static str,
    /// `gating.rule`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// `controls.withheld_because`, where the triple withheld.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// The report's sentence for it, on one line: a `build-failed`'s `build_rejection`, else
    /// `gating.reason`, else `controls.failure_reason` beside a triple that withheld, else
    /// `evidence.observed`. Absent where the observation carries none of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileDigest {
    /// `profile.id`.
    pub id: String,
    /// `profile.flags_sha256`, recomputed from the three lists.
    pub flags_sha256: String,
    /// What a column under this profile measures, by `profile.flags_source`, a driver
    /// configuration file and `--env` pairs.
    pub meaning: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionDigest {
    /// `environment.execution.mode`.
    pub mode: String,
    /// `environment.execution.mode_evidence.basis`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunDigest {
    pub id: String,
    pub harness_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_revision: Option<String>,
    /// `run.harness_revision_source`, absent where the report carries none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_revision_source: Option<String>,
    /// `run.harness_rustflags_sha256`, absent where the report carries none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_rustflags_sha256: Option<String>,
    pub probe_corpus_sha256: String,
    pub decoders_sha256: String,
}

/// The `user` sentence [`meaning`] opens with.
const USER_MEANING: &str = "the flags given to `measure` (`profile.cflags`, `cxxflags`, \
     `ldflags`), each list passed to the measured builds it applies to beside the flags the \
     probe itself needs, save where a check reads the toolchain's own default from a build \
     without them (a build's `argv` names every flag it was given, and its `dropped_flags` any \
     listed flag it left out): what this toolchain applied to chard's own probes built with \
     these lists, not a measurement of any package build that injects them";

/// A `user` sentence another revision writes in place of [`USER_MEANING`]. It says what "a
/// package build that injects exactly these lists gets". A report carrying it is from another
/// revision. [`reread`] refuses it, since its digest is not the one this build derives, but
/// as an older report rather than as a contradiction. A fleet sweep carries it in its six
/// OpenBSD `explicit` reports, the only ones of its 311 under `user`.
///
/// The constant, [`with_todays_meaning`] and their tests can go once a re-sweep replaces the
/// reports that carry the sentence.
const USER_MEANING_RETIRED: &str = "the flags given to `measure` (`profile.cflags`, `cxxflags`, \
     `ldflags`), passed to each measured build (a build's `dropped_flags` names any it left \
     out): what a package build that injects exactly these lists gets, and not what a build \
     that also injects anything else gets";

/// What a column under a profile of `flags_source` measures, against what a distribution's
/// package build injects. `config_file` is whether the driver announced a configuration file
/// (`toolchain.config_files`), and `env_pairs` whether the run handed every toolchain run
/// `--env` pairs, which the published `profile.id` names with its `+env:` suffix
/// ([`super::Profile::published_id`]); each adds its clause, since either can change what a
/// column of no flags measures.
///
/// # Errors
///
/// A `flags_source` outside [`flags_source::ALL`], named.
pub fn meaning(source: &str, config_file: bool, env_pairs: bool) -> Result<String, String> {
    let base = match source {
        flags_source::NONE => {
            "the compiler's compiled-in defaults, the profile passing no flag: what `cc file.c` \
             gets, not what a distribution's package build injects through its own flags"
        }
        flags_source::DRIVER_CONFIG => {
            "the compiler's compiled-in defaults plus what the configuration file the driver \
             loads supplies, the profile passing no flag: not what a distribution's package \
             build injects through its own flags"
        }
        flags_source::ENABLING_CONDITION => {
            "the compiler's compiled-in defaults with -O2 alone, the condition fortify needs to \
             instantiate: not what a distribution's package build injects through its own flags"
        }
        flags_source::OPENSSF_GUIDE => {
            "the OpenSSF guide's TL;DR block with its architecture and executables rows, as \
             `profile.cflags` lists them, passed to each measured build (a build's \
             `dropped_flags` names any it left out): whether this toolchain honours that subset \
             of the guide, not what a distribution's package build injects"
        }
        flags_source::USER => USER_MEANING,
        other => {
            return Err(format!(
                "`profile.flags_source` `{other}` is not a source chard writes"
            ));
        }
    };
    let mut sentence = base.to_owned();
    // `driver-config-file` names the file in its own sentence already.
    if config_file && source != flags_source::DRIVER_CONFIG {
        sentence.push_str(
            "; the driver also loaded a configuration file (`toolchain.config_files`), which \
             supplies what it supplies to every build",
        );
    }
    if env_pairs {
        sentence.push_str(
            "; every toolchain run also had the `--env` pairs `profile.compiler_environment.set` \
             lists, which can change any of this",
        );
    }
    Ok(sentence)
}

// --- the derivation's input, read from the report's JSON ----------------------------------

/// The fields [`derive`] reads, and only those: a subset by design, as
/// [`super::ObservationOnRead`], so a field this does not read is not refused here.
#[derive(Deserialize)]
struct Source {
    chard_schema: String,
    run: RunSource,
    toolchain: ToolchainSource,
    profile: ProfileSource,
    environment: EnvironmentSource,
    coverage: CoverageSource,
    observations: Vec<ObservationSource>,
}

#[derive(Deserialize)]
struct RunSource {
    id: String,
    harness_version: String,
    #[serde(default)]
    harness_revision: Option<String>,
    #[serde(default)]
    harness_revision_source: Option<String>,
    #[serde(default)]
    harness_rustflags_sha256: Option<String>,
    probe_corpus_sha256: String,
    decoders_sha256: String,
}

#[derive(Deserialize)]
struct ToolchainSource {
    id: String,
    #[serde(default)]
    config_files: Vec<String>,
}

#[derive(Deserialize)]
struct ProfileSource {
    id: String,
    flags_source: String,
    cflags: Vec<String>,
    #[serde(default)]
    cxxflags: Vec<String>,
    #[serde(default)]
    ldflags: Vec<String>,
}

#[derive(Deserialize)]
struct EnvironmentSource {
    execution: ExecutionSource,
}

#[derive(Deserialize)]
struct ExecutionSource {
    mode: String,
    #[serde(default)]
    mode_evidence: Option<BasisSource>,
}

#[derive(Deserialize)]
struct BasisSource {
    basis: String,
}

#[derive(Deserialize)]
struct CoverageSource {
    checks_expected: usize,
    checks_attempted: usize,
    #[serde(default)]
    checks_missing: Vec<String>,
    #[serde(default)]
    checks_unexpected: Vec<String>,
    all_checks_attempted: bool,
    all_verdicts_published: bool,
}

#[derive(Deserialize)]
struct ObservationSource {
    check: String,
    verdict: Verdict,
    #[serde(default)]
    level: Option<String>,
    polarity: String,
    channel: String,
    #[serde(default)]
    gating: Option<GatingSource>,
    #[serde(default)]
    controls: Option<ControlsSource>,
    #[serde(default)]
    build_rejection: Option<String>,
    evidence: EvidenceSource,
}

#[derive(Deserialize)]
struct GatingSource {
    rule: String,
    /// Absent from an older report, as on the reread side; `null` does
    /// not read.
    #[serde(default, deserialize_with = "super::gating_rule::written_premise")]
    premise: Option<super::gating_rule::Premise>,
    reason: String,
}

/// The cause and its sentence are taken only beside `discriminating: false`, as
/// [`super::Controls::withheld`] gives the cause at publish.
#[derive(Deserialize)]
struct ControlsSource {
    discriminating: bool,
    #[serde(default)]
    withheld_because: Option<String>,
    #[serde(default)]
    failure_reason: Option<String>,
}

#[derive(Deserialize)]
struct EvidenceSource {
    #[serde(default)]
    observed: Option<String>,
}

impl ObservationView for ObservationSource {
    fn check(&self) -> &str {
        &self.check
    }
    fn verdict(&self) -> Verdict {
        self.verdict
    }
    fn level(&self) -> Option<&str> {
        self.level.as_deref()
    }
    /// Not read: nothing [`Withholding::of`] and [`Standing::of`] take depends on a check's
    /// defects. A rule over this view that did would have to read `defects` here first.
    fn defects(&self) -> &[String] {
        &[]
    }
    /// Not read either, for the same reason: the digest derives no defect status and runs
    /// no bearing-table rule.
    fn written_observes(&self) -> Option<crate::probe::Observes> {
        None
    }
    fn gating_rule(&self) -> Option<&str> {
        self.gating.as_ref().map(|g| g.rule.as_str())
    }
    fn gating_written_premise(&self) -> Option<super::gating_rule::Premise> {
        self.gating.as_ref().and_then(|g| g.premise)
    }
    fn withheld_because(&self) -> Option<&str> {
        let controls = self.controls.as_ref()?;
        if controls.discriminating {
            return None;
        }
        controls.withheld_because.as_deref()
    }
}

impl ObservationSource {
    /// The sentence [`Reason::reason`] carries.
    ///
    /// A `build-failed` beside a `build_rejection` takes it first, as `table` does: the
    /// profile's flag the toolchain refused is what a reader acts on, not the probe. A blank
    /// candidate is passed over rather than ending the search, where `table`, which reads one
    /// field per verdict, prints no reason, and `--fail-on-missing`'s line
    /// (`report::shortfalls`) reads no `build_rejection`: the digest can name a reason those
    /// two do not, never a different verdict.
    fn reason(&self) -> Option<String> {
        let rejection = self
            .build_rejection
            .as_deref()
            .filter(|_| self.verdict == Verdict::BuildFailed);
        let failure = self
            .controls
            .as_ref()
            .filter(|c| !c.discriminating)
            .and_then(|c| c.failure_reason.as_deref());
        [
            rejection,
            self.gating.as_ref().map(|g| g.reason.as_str()),
            failure,
            self.evidence.observed.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(|reason| reason.split_whitespace().collect::<Vec<_>>().join(" "))
        .find(|reason| !reason.is_empty())
    }
}

/// The digest of `report`, a chard report as JSON, whose `consistency.status` is `status`.
///
/// The status is passed rather than read because at publication the block is made before
/// the report is serialized, from the status the consistency pass has just decided.
///
/// # Errors
///
/// Why a field the digest is made from is missing or not readable as chard writes it, or a
/// `profile.flags_source` outside the vocabulary.
pub fn derive(report: &serde_json::Value, status: &str) -> Result<Digest, String> {
    let source = Source::deserialize(report)
        .map_err(|e| format!("the fields the digest is made from do not read ({e})"))?;
    let Source {
        chard_schema,
        run,
        toolchain,
        profile,
        environment,
        coverage,
        observations,
    } = source;
    let mut verdict_counts: BTreeMap<String, usize> = BTreeMap::new();
    for obs in &observations {
        let slot = verdict_counts
            .entry(obs.verdict.as_str().to_owned())
            .or_insert(0);
        *slot = slot.saturating_add(1);
    }
    let withholding = Withholding::of(&observations);
    let reasons = observations
        .iter()
        .filter_map(|obs| {
            let standing = match Standing::of(obs.verdict, obs.gating_premise()) {
                Standing::Measured => return None,
                Standing::EarnedLimitation => "earned-limitation",
                Standing::InstrumentWithholding => "instrument-withholding",
            };
            Some(Reason {
                check: obs.check.clone(),
                verdict: obs.verdict,
                standing,
                rule: obs.gating.as_ref().map(|g| g.rule.clone()),
                cause: obs.withheld_because().map(str::to_owned),
                reason: obs.reason(),
            })
        })
        .collect();
    let checks = observations
        .into_iter()
        .map(|obs| Row {
            check: obs.check,
            verdict: obs.verdict,
            level: obs.level,
            polarity: obs.polarity,
            channel: obs.channel,
            gating: obs.gating.map(|g| g.rule),
        })
        .collect();
    let profile_meaning = meaning(
        &profile.flags_source,
        !toolchain.config_files.is_empty(),
        profile.id.contains("+env:"),
    )?;
    Ok(Digest {
        chard_schema,
        consistency: status.to_owned(),
        coverage: CoverageDigest {
            checks_expected: coverage.checks_expected,
            checks_attempted: coverage.checks_attempted,
            checks_missing: coverage.checks_missing,
            checks_unexpected: coverage.checks_unexpected,
            all_checks_attempted: coverage.all_checks_attempted,
            all_verdicts_published: coverage.all_verdicts_published,
            verdict_counts,
            withholding,
        },
        checks,
        reasons,
        toolchain: toolchain.id,
        profile: ProfileDigest {
            id: profile.id,
            flags_sha256: super::flags_sha256(&profile.cflags, &profile.cxxflags, &profile.ldflags),
            meaning: profile_meaning,
        },
        execution: ExecutionDigest {
            mode: environment.execution.mode,
            basis: environment.execution.mode_evidence.map(|e| e.basis),
        },
        run: RunDigest {
            id: run.id,
            harness_version: run.harness_version,
            harness_revision: run.harness_revision,
            harness_revision_source: run.harness_revision_source,
            harness_rustflags_sha256: run.harness_rustflags_sha256,
            probe_corpus_sha256: run.probe_corpus_sha256,
            decoders_sha256: run.decoders_sha256,
        },
    })
}

/// The JSON of the fields of `report` [`derive`] reads, as [`super::publish`] would write
/// them.
fn source_of(report: &super::Report) -> Result<serde_json::Value, String> {
    let value = |field: &str, v: Result<serde_json::Value, serde_json::Error>| {
        v.map_err(|e| format!("`{field}` does not serialize ({e})"))
    };
    Ok(serde_json::json!({
        "chard_schema": report.chard_schema,
        "run": value("run", serde_json::to_value(&report.run))?,
        "toolchain": value("toolchain", serde_json::to_value(&report.toolchain))?,
        "profile": value("profile", serde_json::to_value(&report.profile))?,
        "environment": value("environment", serde_json::to_value(&report.environment))?,
        "coverage": value("coverage", serde_json::to_value(&report.coverage))?,
        "observations": value("observations", serde_json::to_value(&report.observations))?,
    }))
}

/// The digest of `report` as [`super::publish`] writes it, under the status its filled
/// consistency block gives.
///
/// # Errors
///
/// Those of [`derive`], and a field that does not serialize.
pub fn of_report(report: &super::Report) -> Result<Digest, String> {
    derive(&source_of(report)?, report.consistency.status().as_str())
}

/// [`super::RULE_DIGEST`] at publication: whether the derivation goes through over the
/// report about to be written. The status is not decided yet, and the block is not compared
/// with anything, since [`super::publish`] then makes it by this derivation.
pub(super) fn derivable(report: &super::Report) -> Option<super::Contradiction> {
    let why = source_of(report)
        .and_then(|source| derive(&source, super::ConsistencyStatus::Consistent.as_str()))
        .err()?;
    Some(underivable(&why))
}

/// The contradiction a digest that cannot be made is, at publication: the one
/// [`derivable`] and `report::fill_digest` both record.
pub(super) fn underivable(why: &str) -> super::Contradiction {
    super::Contradiction {
        rule: super::RULE_DIGEST.to_owned(),
        property: "digest".to_owned(),
        claims: vec![format!("digest = underivable: {why}")],
        detail: "the digest is made from the report's own fields, and one of them does not \
                 read as chard writes it"
            .to_owned(),
    }
}

/// [`super::RULE_DIGEST`] on read: `profile.flags_sha256` against its three lists where the
/// report publishes one, and the digest `report` carries against the one its own fields
/// give, into `out`.
///
/// A report without a digest never reaches this rule from a reader: `table`, `matrix` and
/// `chard digest` refuse it when they read it (`crate::dataset::refuse_unread`), before any
/// rule runs, as they refuse a `chard_schema` other than the binary's. Over a value handed
/// here without that read, the rule has no digest to hold and adds nothing for it. A digest
/// that is present is held whole, a member added or removed included.
pub(super) fn reread(report: &serde_json::Value, out: &mut super::Reread) {
    let rule = super::RULE_DIGEST;
    let contradiction = |property: String, written: String, derived: String| super::Contradiction {
        rule: rule.to_owned(),
        property: property.clone(),
        claims: vec![
            format!("{property} = {written}"),
            format!("derived from the report = {derived}"),
        ],
        detail: "the digest and the profile's flags hash are derived from the report's own \
                     fields, and this one is not the one they give"
            .to_owned(),
    };
    if let Some(published) = report.get("profile").and_then(|p| p.get("flags_sha256")) {
        match report
            .get("profile")
            .map(ProfileSource::deserialize)
            .transpose()
        {
            Ok(Some(profile)) => {
                let derived =
                    super::flags_sha256(&profile.cflags, &profile.cxxflags, &profile.ldflags);
                if published.as_str() != Some(derived.as_str()) {
                    out.contradictions.push(contradiction(
                        "profile.flags_sha256".to_owned(),
                        published.to_string(),
                        derived,
                    ));
                }
            }
            Ok(None) => {}
            Err(e) => out.unreadable.push(format!(
                "`profile` is not readable as chard writes it ({e}), so `{rule}` cannot be \
                 re-run over it"
            )),
        }
    }
    let Some(written) = report.get("digest") else {
        return;
    };
    let Some(status) = report
        .get("consistency")
        .and_then(|c| c.get("status"))
        .and_then(serde_json::Value::as_str)
    else {
        out.unreadable.push(format!(
            "carries no `consistency.status` for its digest to be held to, so `{rule}` cannot \
             be re-run over it"
        ));
        return;
    };
    let derived = match derive(report, status).and_then(|derived| {
        serde_json::to_value(&derived)
            .map_err(|e| format!("the digest derived from it does not serialize ({e})"))
    }) {
        Ok(derived) => derived,
        Err(why) => {
            out.unreadable
                .push(format!("{why}, so `{rule}` cannot be re-run over it"));
            return;
        }
    };
    let written = match with_todays_meaning(written, &derived) {
        Some(patched) => {
            out.older.push(
                "its `digest.profile.meaning` is a `user` sentence this revision does not \
                 write. It is not a contradiction: read the report with the chard its \
                 `run.harness_revision` names, or run `chard measure` again with this build and \
                 render the new report"
                    .to_owned(),
            );
            // The rest of the digest is still held: only the sentence is the other revision's.
            std::borrow::Cow::Owned(patched)
        }
        None => std::borrow::Cow::Borrowed(written),
    };
    let mut differences = Vec::new();
    differ("digest", &written, &derived, &mut differences);
    out.contradictions.extend(
        differences
            .into_iter()
            .map(|(path, written, derived)| contradiction(path, written, derived)),
    );
}

/// `written` with today's `profile.meaning` in place of the sentence another revision
/// derives from the same fields: [`USER_MEANING_RETIRED`] followed by the clauses
/// today's sentence carries after [`USER_MEANING`]. `None` for any other sentence, an
/// edited one included.
fn with_todays_meaning(
    written: &serde_json::Value,
    derived: &serde_json::Value,
) -> Option<serde_json::Value> {
    let today = derived.pointer("/profile/meaning")?;
    let clauses = today.as_str()?.strip_prefix(USER_MEANING)?;
    let stored = written.pointer("/profile/meaning")?.as_str()?;
    if stored.strip_prefix(USER_MEANING_RETIRED)? != clauses {
        return None;
    }
    let mut patched = written.clone();
    *patched.pointer_mut("/profile/meaning")? = today.clone();
    Some(patched)
}

/// Each place `written` and `derived` disagree, as (path, written, derived), with a
/// member absent on one side named `absent`. An array element is named by its `check`
/// where it carries one, so an edited row names its check rather than its index.
fn differ(
    path: &str,
    written: &serde_json::Value,
    derived: &serde_json::Value,
    out: &mut Vec<(String, String, String)>,
) {
    use serde_json::Value;
    match (written, derived) {
        (Value::Object(w), Value::Object(d)) => {
            let keys: std::collections::BTreeSet<&String> = w.keys().chain(d.keys()).collect();
            for key in keys {
                let at = format!("{path}.{key}");
                match (w.get(key), d.get(key)) {
                    (Some(w), Some(d)) => differ(&at, w, d, out),
                    (w, d) => out.push((at, shown(w), shown(d))),
                }
            }
        }
        (Value::Array(w), Value::Array(d)) if w.len() == d.len() => {
            for (i, (w, d)) in w.iter().zip(d).enumerate() {
                let name = d
                    .get("check")
                    .and_then(Value::as_str)
                    .map_or_else(|| i.to_string(), str::to_owned);
                differ(&format!("{path}[{name}]"), w, d, out);
            }
        }
        // A list of another length is named by its length: its whole text would be most of
        // the digest on each side.
        (Value::Array(w), Value::Array(d)) => out.push((
            path.to_owned(),
            format!("{} entries", w.len()),
            format!("{} entries", d.len()),
        )),
        (w, d) if w == d => {}
        (w, d) => out.push((path.to_owned(), shown(Some(w)), shown(Some(d)))),
    }
}

fn shown(value: Option<&serde_json::Value>) -> String {
    value.map_or_else(|| "absent".to_owned(), serde_json::Value::to_string)
}

/// The digest of the one report `chard digest` read, refused as `table` refuses a report:
/// one that is not a report, one that contradicts itself, one whose digest is not the one
/// its own fields give ([`super::reread_contradictions`] runs this module's rule), and one
/// with no digest. The read refuses the last, with a `chard_schema` other than the binary's,
/// before this runs (`crate::dataset::refuse_unread`); it is refused here too, since this
/// prints the digest and has nothing else to print.
///
/// # Errors
///
/// A [`crate::error::UserError`] naming the refusal.
pub fn of_read(read: &(String, serde_json::Value)) -> anyhow::Result<&serde_json::Value> {
    let (name, report) = read;
    if report.get("observations").is_none() {
        return Err(crate::dataset::not_a_report(name, "it carries no observations").into());
    }
    crate::dataset::refuse_self_contradicted(std::slice::from_ref(read))?;
    report
        .get("digest")
        .ok_or_else(|| crate::dataset::missing_digest(name).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `gating.premise` as the digest reads it: absent is no class, a spelling is its
    /// class, and `null` or a word outside the vocabulary does not read.
    #[test]
    fn the_digest_reads_a_premise_strictly() {
        let read = |gating: serde_json::Value| GatingSource::deserialize(gating).map(|g| g.premise);
        let base = serde_json::json!({"rule": "arch-gated", "reason": "r"});
        assert_eq!(read(base.clone()).expect("absent reads"), None);
        let mut with = base.clone();
        with["premise"] = serde_json::json!("toolchain-fact");
        assert_eq!(
            read(with).expect("a spelling reads"),
            Some(super::super::gating_rule::Premise::ToolchainFact)
        );
        for word in [serde_json::Value::Null, serde_json::json!("fact")] {
            let mut bad = base.clone();
            bad["premise"] = word.clone();
            assert!(read(bad).is_err(), "{word}");
        }
    }

    /// Every source chard writes has its own sentence, placing the column against what a
    /// build injects, with a clause for a driver configuration file (one of its own for
    /// `driver-config-file`) and one for `--env` pairs; a source outside the vocabulary is
    /// refused rather than given one.
    #[test]
    fn every_flags_source_has_a_meaning_and_no_other_does() {
        let mut sentences = std::collections::BTreeSet::new();
        for source in flags_source::ALL {
            for config_file in [false, true] {
                for env_pairs in [false, true] {
                    let sentence = meaning(source, config_file, env_pairs)
                        .unwrap_or_else(|e| panic!("{source}: {e}"));
                    assert!(sentence.contains("inject"), "{source}: {sentence}");
                    assert_eq!(sentence.contains("`--env`"), env_pairs, "{sentence}");
                    assert_eq!(
                        sentence.contains("configuration file"),
                        config_file || *source == flags_source::DRIVER_CONFIG,
                        "{sentence}"
                    );
                    sentences.insert(sentence);
                }
            }
        }
        // Two per source, and two more for each source but `driver-config-file`, whose own
        // sentence names the file either way.
        assert_eq!(sentences.len(), 4 * flags_source::ALL.len() - 2);
        assert!(meaning("hardened", false, false).is_err());
    }

    /// No sentence says what a package or distribution build gets: chard ran none, so every
    /// clause naming one is a denial, opening on "not". The `user` sentence said what "a
    /// package build that injects exactly these lists gets", a claim about a build
    /// chard never ran; it says what chard built, and is pinned whole, since a word list
    /// cannot catch every rewording.
    #[test]
    fn no_meaning_claims_a_package_build_chard_did_not_run() {
        let (mut fed, mut denials) = (0, 0);
        for source in flags_source::ALL {
            for config_file in [false, true] {
                for env_pairs in [false, true] {
                    let sentence = meaning(source, config_file, env_pairs).expect("a source");
                    fed += 1;
                    assert!(!sentence.contains("  "), "{sentence}");
                    for clause in sentence.to_lowercase().split([':', ';', ',']) {
                        if ["packag", "distribution"]
                            .iter()
                            .any(|w| clause.contains(w))
                        {
                            assert!(clause.trim_start().starts_with("not "), "{sentence}");
                            denials += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(fed, 4 * flags_source::ALL.len());
        // Every source's sentence denies once, under each of its four clause sets.
        assert_eq!(denials, fed);
        let user = meaning(flags_source::USER, false, false).expect("user");
        assert_eq!(
            user,
            "the flags given to `measure` (`profile.cflags`, `cxxflags`, `ldflags`), each list \
             passed to the measured builds it applies to beside the flags the probe itself \
             needs, save where a check reads the toolchain's own default from a build without \
             them (a build's `argv` names every flag it was given, and its `dropped_flags` any \
             listed flag it left out): what this toolchain applied to chard's own probes built \
             with these lists, not a measurement of any package build that injects them"
        );
        // The exception the sentence names is a real one: a check of the corpus reads the
        // toolchain's default from the clean build, which carries none of the lists.
        assert!(
            crate::probe::CORPUS
                .iter()
                .flat_map(|p| p.checks.iter())
                .any(|c| c.measures_toolchain_default)
        );
    }

    /// A `user` report as `measure` writes one, its digest derived, with or without a driver
    /// configuration file and `--env` pairs.
    fn user_report(config_file: bool, env_pairs: bool) -> serde_json::Value {
        use serde_json::json;
        let id = if env_pairs {
            "explicit:0123456789ab+env:0123456789ab"
        } else {
            "explicit:0123456789ab"
        };
        let files = if config_file {
            json!(["/etc/clang/x.cfg"])
        } else {
            json!([])
        };
        let mut r = json!({
            "chard_schema": "1",
            "run": {"id": "i", "harness_version": "0", "probe_corpus_sha256": "c",
                    "decoders_sha256": "d"},
            "toolchain": {"id": "t", "config_files": files},
            "profile": {"id": id, "flags_source": "user", "cflags": ["-fPIE"]},
            "environment": {"execution": {"mode": "host"}},
            "coverage": {"checks_expected": 0, "checks_attempted": 0,
                         "all_checks_attempted": true, "all_verdicts_published": true},
            "consistency": {"status": "consistent"},
            "observations": [],
        });
        r["digest"] =
            serde_json::to_value(derive(&r, "consistent").expect("derives")).expect("serializes");
        r
    }

    /// The digest rule over `r`, as the read runs it.
    fn read_digest(r: &serde_json::Value) -> super::super::Reread {
        let mut out = super::super::Reread::default();
        reread(r, &mut out);
        out
    }

    /// Whether the read named the report as older, by the finding's type, and nothing else
    /// kept the rule from running.
    fn named_older(out: &super::super::Reread) -> bool {
        !out.older.is_empty() && out.unreadable.is_empty()
    }

    /// A `user` report another revision wrote carries that revision's sentence: the read names
    /// it as that, not as a contradiction, with both ways on, and still holds the rest of its
    /// digest. Those words with clauses its fields do not give stay contradictions.
    #[test]
    fn a_retired_user_sentence_is_named_as_older_on_read() {
        use serde_json::json;
        // As a fleet sweep's OpenBSD `explicit` reports store it, copied from one.
        assert_eq!(
            USER_MEANING_RETIRED,
            "the flags given to `measure` (`profile.cflags`, `cxxflags`, `ldflags`), passed to \
             each measured build (a build's `dropped_flags` names any it left out): what a \
             package build that injects exactly these lists gets, and not what a build that \
             also injects anything else gets"
        );
        let sets = [(false, false), (false, true), (true, false), (true, true)];
        let clauses = |(c, e): (bool, bool)| {
            meaning(flags_source::USER, c, e)
                .expect("user")
                .strip_prefix(USER_MEANING)
                .expect("the user sentence opens with USER_MEANING")
                .to_owned()
        };
        let mut crossed = 0;
        for fields in sets {
            let today = user_report(fields.0, fields.1);
            let out = read_digest(&today);
            assert!(out.is_empty(), "{out:?}");
            // Every clause set stored against every report's fields: older only where they
            // are the clauses those fields give.
            for stored in sets {
                let mut r = today.clone();
                r["digest"]["profile"]["meaning"] =
                    json!(format!("{USER_MEANING_RETIRED}{}", clauses(stored)));
                let out = read_digest(&r);
                crossed += 1;
                if stored == fields {
                    assert!(named_older(&out), "{fields:?}: {out:?}");
                    // Still a finding: the refusal keys on it.
                    assert!(!out.is_empty());
                    // Both ways on: the chard that wrote it, or a new measurement.
                    let note = out.older.join("\n");
                    for remedy in ["`run.harness_revision`", "`chard measure` again"] {
                        assert!(note.contains(remedy), "{remedy}: {note}");
                    }
                    assert!(out.contradictions.is_empty(), "{:?}", out.contradictions);
                    r["digest"]["toolchain"] = json!("edited");
                    let out = read_digest(&r);
                    assert!(named_older(&out));
                    assert_eq!(out.contradictions.len(), 1, "{:?}", out.contradictions);
                    assert_eq!(out.contradictions[0].property, "digest.toolchain");
                } else {
                    assert!(!named_older(&out), "{fields:?} stored as {stored:?}");
                    assert_eq!(out.contradictions.len(), 1, "{fields:?} as {stored:?}");
                    assert_eq!(out.contradictions[0].property, "digest.profile.meaning");
                }
            }
        }
        assert_eq!(crossed, 16);
    }

    /// Only that sentence whole is older: one with anything before or after it, one cut short,
    /// another sentence, or those words under another source stay contradictions.
    #[test]
    fn a_near_retired_user_sentence_stays_a_contradiction() {
        use serde_json::json;
        let today = user_report(false, false);
        for stored in [
            format!("{USER_MEANING_RETIRED}."),
            USER_MEANING_RETIRED[..USER_MEANING_RETIRED.len() - 1].to_owned(),
            format!("x{USER_MEANING_RETIRED}"),
            "hardened".to_owned(),
        ] {
            let mut r = today.clone();
            r["digest"]["profile"]["meaning"] = json!(stored);
            let out = read_digest(&r);
            assert!(!named_older(&out), "{stored}");
            assert_eq!(out.contradictions.len(), 1, "{stored}");
            assert_eq!(out.contradictions[0].property, "digest.profile.meaning");
        }
        let mut bare = today;
        bare["profile"]["flags_source"] = json!("none");
        bare["profile"]["cflags"] = json!([]);
        bare["digest"] =
            serde_json::to_value(derive(&bare, "consistent").expect("derives")).expect("JSON");
        bare["digest"]["profile"]["meaning"] = json!(USER_MEANING_RETIRED);
        let out = read_digest(&bare);
        assert!(!named_older(&out) && out.contradictions.len() == 1);
    }

    /// The derivation hands `meaning` what the report says of the profile: `--env` pairs by
    /// `profile.id`'s `+env:` suffix, a configuration file by `toolchain.config_files`.
    #[test]
    fn the_meaning_follows_the_reports_env_pairs_and_configuration_file() {
        use serde_json::json;
        let report = |id: &str, config_files: serde_json::Value| {
            json!({
                "chard_schema": "1",
                "run": {"id": "i", "harness_version": "0", "probe_corpus_sha256": "c",
                        "decoders_sha256": "d"},
                "toolchain": {"id": "t", "config_files": config_files},
                "profile": {"id": id, "flags_source": "none", "cflags": []},
                "environment": {"execution": {"mode": "host"}},
                "coverage": {"checks_expected": 0, "checks_attempted": 0,
                             "all_checks_attempted": true, "all_verdicts_published": true},
                "observations": [],
            })
        };
        let meaning_of =
            |r: &serde_json::Value| derive(r, "consistent").expect("derives").profile.meaning;
        let plain = meaning_of(&report("bare", json!([])));
        assert!(
            !plain.contains("`--env`") && !plain.contains("configuration file"),
            "{plain}"
        );
        let env = meaning_of(&report("bare+env:0123456789ab", json!([])));
        assert!(env.contains("`--env`"), "{env}");
        let config = meaning_of(&report("bare", json!(["/etc/clang/x.cfg"])));
        assert!(config.contains("configuration file"), "{config}");
    }

    /// A reason is the gating rule's sentence, else the withholding triple's, else the
    /// detector's reading, folded onto one line; a triple that discriminated lends none.
    #[test]
    fn the_reason_is_the_rules_then_the_triples_then_the_detectors() {
        use serde_json::json;
        let withheld = json!({"discriminating": false, "withheld_because": "positive-absent",
                              "failure_reason": "the triple's\nsentence"});
        let observation = |check: &str, verdict: &str, extra: serde_json::Value| {
            let mut o = json!({"check": check, "verdict": verdict, "polarity": "harden",
                               "channel": "macro", "evidence": {"observed": "the detector's"}});
            for (k, v) in extra.as_object().expect("an object") {
                o[k] = v.clone();
            }
            o
        };
        let report = json!({
            "chard_schema": "1",
            "run": {"id": "i", "harness_version": "0", "probe_corpus_sha256": "c",
                    "decoders_sha256": "d"},
            "toolchain": {"id": "t"},
            "profile": {"id": "bare", "flags_source": "none", "cflags": []},
            "environment": {"execution": {"mode": "host"}},
            "coverage": {"checks_expected": 4, "checks_attempted": 4,
                         "all_checks_attempted": true, "all_verdicts_published": false},
            "observations": [
                observation("rule", "unsupported", json!({
                    "gating": {"rule": "arch-gated", "reason": "the rule's"},
                    "controls": withheld})),
                observation("triple", "probe-invalid", json!({"controls": withheld})),
                // A sentence beside a triple that discriminated, which `measure` never
                // writes, is not the triple's reason.
                observation("detector", "indeterminate",
                            json!({"controls": {"discriminating": true,
                                                "failure_reason": "a stray sentence"}})),
                observation("measured", "on", json!({})),
                // The profile's refused flag before the rest, as `table` reads it; a blank
                // rule sentence passes over to the next.
                observation("rejected", "build-failed", json!({
                    "gating": {"rule": "x", "reason": " "},
                    "build_rejection": "gcc: unrecognized -fwhatever"})),
                observation("blank", "probe-invalid", json!({
                    "gating": {"rule": "x", "reason": " "}, "controls": withheld})),
            ],
        });
        let digest = derive(&report, "consistent").expect("derives");
        let reasons: Vec<(&str, Option<&str>, &str)> = digest
            .reasons
            .iter()
            .map(|r| (r.check.as_str(), r.reason.as_deref(), r.standing))
            .collect();
        assert_eq!(
            reasons,
            [
                ("rule", Some("the rule's"), "earned-limitation"),
                (
                    "triple",
                    Some("the triple's sentence"),
                    "instrument-withholding"
                ),
                ("detector", Some("the detector's"), "instrument-withholding"),
                (
                    "rejected",
                    Some("gcc: unrecognized -fwhatever"),
                    "instrument-withholding"
                ),
                (
                    "blank",
                    Some("the triple's sentence"),
                    "instrument-withholding"
                ),
            ]
        );
        assert_eq!(digest.reasons[0].cause.as_deref(), Some("positive-absent"));
        assert_eq!(digest.reasons[2].cause, None);
    }
}
