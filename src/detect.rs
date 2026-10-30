// SPDX-License-Identifier: BSD-3-Clause

//! `chard detect`: one check's decoder, run alone over evidence a reader supplies.
//!
//! A report states each predicate reading as a value (`report::Decoded`) beside the
//! predicate that produced it (`decoders`) and the facts it read (`facts`), and
//! `decoded-reading-disagrees-with-facts` replays every one before the report is
//! published. That rule runs inside the chard that measured. This module is the same replay
//! run from outside: it reads a report as JSON, through `serde_json::Value` and the types
//! that deserialize (`predicate::Predicate`, `elf::ElfFacts`, the fixture records), never
//! through the in-memory `report::Report` a measurement builds, so a report copied off the
//! machine that produced it can be checked with nothing but this binary.
//!
//! # Inputs
//!
//! `--evidence FILE` is sniffed, in this order:
//!
//! - **report**, an object that is not `chard elf` output (below) with a `chard_schema` and
//!   an `observations` list: every
//!   reading of the check, on the measured build and on each control arm, is re-evaluated
//!   with the report's own `decoders` predicate over the report's `facts` through the
//!   Published view
//!   (`predicate::Published`), and compared with its `decoded`. See [`replay_report`].
//!   The environment is not read: `kernel.ownership` and `is_host_kernel` are held by
//!   `table` and `matrix` (`report::reread_contradictions`), and a report without the first,
//!   or with either edited, replays as it would otherwise. An object with a `chard_schema`
//!   string and no `observations` list has the shape of chard's other documents (a matrix, a
//!   probe listing, `detect`'s own output, whose `observations` is a count, or an error
//!   envelope, each versioned under the same key), and is refused as not a
//!   report rather than replayed as a report missing its readings. Either shape, and an
//!   `observations` list with no `chard_schema` or a `chard_schema` of any type, is first
//!   held to the version this chard reads (`dataset::refuse_other_schema`, the comparison
//!   `table` makes): a report of another version is refused, not replayed, and one whose
//!   version was removed or retyped is not read as a record. A report without a `digest` is replayed, as
//!   a quarantined one is: the replay re-derives readings from the report's facts rather
//!   than rendering its verdicts.
//! - **`chard elf` output**, an object whose every value is an object with `elf_class`
//!   and `machine`: one path and its `ElfFacts`. Tested before every other shape, the
//!   report's included, because its keys are the paths a caller typed, and a path named
//!   `chard_schema`, `kind`, `run` or `elf` would otherwise read as one of them. A record whose only member is `elf` has
//!   this shape too, and is read as an object named `elf` with its self-report as the
//!   macro source; a record that names its `check` is not.
//! - **store entry**, an object with `kind`: one `facts` entry, evaluated alone.
//! - **record**, an object with any of `macros`, `elf`, `build` or `run`, the shape of a
//!   fixture in `tests/fixtures/detectors.json`: run through `probe::Check::decode`, the
//!   entry point a measurement reads through, for a code decoder as well as a predicate.
//!
//! `--artifact FILE` reads an ELF object with `elf::facts_for` and evaluates the check's
//! predicate over it, with the artifact's `.chard.report` as the macro source by the rule
//! `measure` applies: present when the section parses to at least one macro, and otherwise
//! absent, which the predicate reads as `@no-source:macros` where it needs macros.
//!
//! Everything but a report prints a **detection**: one decoder over one set of facts, with
//! no control triple behind it, so never a verdict. A standalone `elf` entry, `chard elf`
//! output and an artifact are read with the Live view, whose watch list is this binary's
//! `elf::WATCHED_SYMBOLS`; a report is read with the watch list it publishes. A standalone
//! `macro-dump` entry is read with this binary's macro filter when the entry names that
//! filter's digest, and otherwise with the entry's own names as the filter, so a name the
//! entry does not hold is `Incomplete` rather than undefined.
//!
//! # Counting
//!
//! A report replay counts the readings it was owed against what it did with them:
//! `expected == replayed + not_replayable.len()`, published in the output and held by
//! [`Replay::closes`]. A reading is owed at the measured build of an observation that
//! reached its decoder (built its control triple, or published `on`, `off`, `partial` or
//! `probe-invalid`, the rule (a) `report::decoded_readings_agree` holds a report to) and
//! at every control arm with an `outcome`, and at any site that publishes a `decoded`
//! whatever else it carries. A check whose every observation was withheld before its
//! decoder ran owes none: `expected: 0` is its complete account, and exits 0.
//!
//! The work is counted from the report, so the report's count is published beside it:
//! `observations` is the number of observations of the check, and a report with none is
//! refused (exit 2) rather than closed at `expected: 0`. Closed there, the two cases would
//! print the same output, and a report stripped of a check's observations would replay as
//! a clean zero.
//!
//! # Restatement
//!
//! A reading re-derived from its facts says nothing about the verdict published beside it
//! unless the verdict is held to the reading too. `restated` holds, at every site that
//! publishes a reading, what the report's consistency rules (c) and (d) hold
//! (`report::decoded_readings_agree`): a control arm's `outcome` is its reading's outcome,
//! and a measured `on`, `off` or `partial` with its `level` is what
//! [`crate::report::restated_verdict`] gives the measured reading on this binary's scale
//! for the check. Each reading's `facts` and `macros` keys are held to the digests its own
//! site's record publishes (`report::unbound_reading_keys`, the first half of the report's
//! rule (b)), so a reading moved to another build's facts disagrees even where it replays;
//! and a measured `on`, `off` or `partial` is held to the control triple published beside
//! it, as the report's rule `verdict-unearned-by-controls` holds it: a positive arm
//! `present`, a negative arm `absent`, any regime arm `absent`, and `discriminating`.
//! Without either, a `probe-invalid` edited to the `off` its measured reading licenses, or
//! an `off` with its `controls` deleted, would replay as agreeing. The triple needs no
//! reading, so it is restated on every check, a code decoder's included, with each arm's
//! `outcome` read as published where no reading restates it. Restated on a predicate check
//! only, an `off` with its `controls` deleted from a `runtime` or `compiler-diag` check
//! would exit 0.
//! Whether a regime arm is owed is derived, not read off the triple: this binary's
//! declaration of the check and the report's `profile`
//! ([`Check::owes_regime_control`]), and an owed arm that is unpublished or states no
//! `outcome` withholds. A `probe-invalid` beside a triple is held to it too, and
//! disagrees where the triple discriminated, as in the report's rule. Owing an arm only
//! where one is published would let an `on` with its regime arm deleted from a report
//! measured under a profile exit 0, and would leave a measured verdict relabelled
//! `probe-invalid` unrestated. `indeterminate`,
//! `unsupported` and `not-applicable` beside a discriminating triple are not restated:
//! they are what a gating rule or the fortify ratchet leaves, a replay re-derives
//! neither, and so a measurement relabelled as one of them replays as agreeing. That is
//! the limit of this command; `THREAT_MODEL.md` names what holds those three instead.
//! A measured verdict is restated whether or not the observation carries a
//! `gating`: the report's rule (d) skips a gated observation because
//! `gating_verdict_agrees` pins its verdict to the rule's premise, and no premise publishes
//! a measurement. A replay does not re-derive that rule, so a measured verdict beside a
//! `gating` is held to its reading here, and a verdict moved to `off` with a `gating`
//! added exits 1. A replay that skipped such a verdict would read that edit as agreeing.
//!
//! A reading not replayed is named with its reason:
//!
//! - `code-decoder`: an arm of a code-decoded check whose decoder reads an artifact the
//!   store does not keep ([`READS_UNSTORED_ARTIFACT`]). A record that does not read as the
//!   decoder's input, or an artifact key the store does not resolve, is a report that
//!   cannot be used, and is refused;
//! - `record-cut`: a code decoder's site whose build or run record carries the excerpt
//!   budget's cut marker (`probe::CUT_MARKER`), so no replay could be exact;
//! - `unkept-c-int-follow`: a `c-int` term followed a value to a macro name outside the
//!   published filter (`report::NotReplayable`). A value stated beside such a reading (a
//!   measured verdict, an arm's `outcome`) is restated to nothing and disagrees, since
//!   no replay verified the reading it would be held to; held to the published reading, it
//!   would agree;
//! - `reading-absent`: a site that owes a reading publishes none. This one is a
//!   disagreement, and exits 1.
//!
//! A code decoder, which a report cannot carry, is replayed through this binary's own
//! decoder over the records its site publishes (`replay_code`): the build and run as
//! published, the ELF facts the store holds under the build's artifact, and the macros that
//! artifact's `.chard.report` carries, with the two gates `measure` applies after a code
//! decoder. The replay trusts this binary's decoder source, which `run.decoders_sha256`
//! fingerprints; a report from another revision replays against today's decoder. Its
//! reading is restated against what the site states, an arm's `outcome` or the measured
//! verdict. Counting every such reading `code-decoder` would let a measured `on` swapped for
//! `off` beside an intact triple exit 0.
//!
//! # Exit codes
//!
//! The statuses are the CLI's contract (`DESIGN.md`, "The command-line contract").
//! For `detect`: `0` when every replayed reading agrees and nothing owed is absent, or a
//! detection was made; `1` (`error::EXIT_GATE`) on any disagreement, a tripped gate with the
//! document written, as `measure --fail-on-missing` trips one, including a stated
//! outcome or verdict its reading does not license, a stated outcome or verdict beside a
//! reading the replay could not re-derive, a measured verdict its triple did not
//! earn, a reading key its site's record does not publish, a published
//! predicate whose digest is not its canonical form's, a record whose `expected` or
//! `expected_level` the decoder does not reproduce, and a reading whose facts cannot answer
//! its own predicate; `2` for an input that cannot be used, through the error envelope. A
//! required input that is missing is named and refused, never read as absent: a report with
//! a reading of the check and no `decoders` entry for it, a report with no observation of
//! the check, a key naming no store entry, a store entry of a kind this binary does not
//! know. A disagreement is a finding about the input, so it is never `3`, which is chard's
//! own contradiction alone (`error::EXIT_CONTRADICTION`): a caller routing `3` to a chard bug
//! report would otherwise file one for every report that fails here.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::compile::BuildRecord;
use crate::elf::ElfFacts;
use crate::error::UserError;
use crate::predicate::{self, Evaluation, Fact, Incomplete, Live, Predicate, ReadKey};
use crate::probe::{self, Channel, Check, Evidence};
use crate::run::RunRecord;

/// Which reading of an observation to replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmSel {
    /// The measured build's, `evidence.decoded`.
    Measured,
    /// `controls.positive.decoded`.
    Positive,
    /// `controls.negative.decoded`.
    Negative,
    /// `controls.regime_negative.decoded`.
    Regime,
}

impl ArmSel {
    /// Every arm, in the order a replay visits them.
    pub const ALL: [Self; 4] = [Self::Measured, Self::Positive, Self::Negative, Self::Regime];

    /// The name `--arm` takes and the output uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Regime => "regime",
        }
    }

    /// The member of `controls` the arm is published under; `None` for the measured build.
    const fn controls_field(self) -> Option<&'static str> {
        match self {
            Self::Measured => None,
            Self::Positive => Some("positive"),
            Self::Negative => Some("negative"),
            Self::Regime => Some("regime_negative"),
        }
    }

    /// The arm `name` names.
    ///
    /// # Errors
    ///
    /// A [`UserError`] listing the four names, for any other.
    pub fn parse(name: &str) -> Result<Self, UserError> {
        Self::ALL
            .into_iter()
            .find(|arm| arm.as_str() == name)
            .ok_or_else(|| {
                UserError::with_hint(
                    format!("unknown arm `{name}`"),
                    "--arm takes measured, positive, negative or regime",
                )
            })
    }
}

/// The check `id` names in this binary's corpus.
///
/// # Errors
///
/// A [`UserError`] pointing at `chard probes` when no check has that id.
pub fn check_by_id(id: &str) -> Result<&'static Check, UserError> {
    probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .find(|c| c.id == id)
        .ok_or_else(|| {
            UserError::with_hint(
                format!("no check `{id}` in this binary's corpus"),
                "`chard probes --format text` lists every check id",
            )
        })
}

/// The decoder a replay or detection used.
#[derive(Debug, Clone, Serialize)]
pub struct DecoderId {
    /// `predicate` or `code`, as `chard probes` publishes it.
    pub kind: &'static str,
    /// The predicate language, for a predicate; `None` for code.
    pub language: Option<String>,
    /// The report's `decoders.predicates[CHECK].sha256` when a report published one, and
    /// otherwise this binary's `probe::Decoder::sha256`.
    pub sha256: String,
    /// `report` or `corpus`: which of the two `sha256` and the predicate came from.
    pub source: &'static str,
    /// Whether a published predicate's canonical form has the digest it is published
    /// under. Always `true` for the corpus's own.
    pub digest_agrees: bool,
}

impl DecoderId {
    fn corpus(check: &Check) -> Self {
        Self {
            kind: check.decoder.kind(),
            language: check.predicate().map(|_| predicate::LANGUAGE.to_owned()),
            sha256: check.decoder.sha256(),
            source: "corpus",
            digest_agrees: true,
        }
    }
}

/// A reading a replay was owed and did not re-evaluate, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotReplayed {
    pub probe: String,
    pub arm: &'static str,
    /// `code-decoder`, `record-cut`, `unkept-c-int-follow` or `reading-absent`.
    pub reason: &'static str,
    /// The key the Published view stopped at, for `unkept-c-int-follow`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// A reading as a report published it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Stated {
    pub clause: String,
    pub outcome: String,
    pub level: Option<String>,
}

/// One reading re-evaluated.
#[derive(Debug, Clone, Serialize)]
pub struct Replayed {
    pub probe: String,
    pub arm: &'static str,
    /// The reading's `facts` key.
    pub facts_key: String,
    /// The reading's `macros` key, on an `elf-static` reading that names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macros_key: Option<String>,
    /// Each read the evaluation made, by published key, with the value it returned
    /// (`null` for undefined).
    pub reads: Map<String, Value>,
    /// The re-evaluation's clause, outcome and level; `None` where it stopped at
    /// `incomplete`.
    pub clause: Option<String>,
    pub outcome: Option<&'static str>,
    pub level: Option<String>,
    /// The key the published facts do not hold, where the evaluation stopped at one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<String>,
    /// The reading as the report states it.
    pub published: Stated,
    pub agrees: bool,
}

/// A value a report states beside a reading, held to what the reading licenses: an arm's
/// `outcome` against its `decoded.outcome` (rule (c) of the report's own consistency
/// check), a measured `verdict` and `level` against the verdict the measured
/// reading licenses on the check's scale (rule (d), [`crate::report::restated_verdict`]),
/// a measured `verdict` against the triple beside it (`earned`), and a reading's keys
/// against its site's record (`keys_restated`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Restated {
    pub probe: String,
    pub arm: &'static str,
    /// `outcome` for a control arm; `verdict` (against the reading) and `controls` (against
    /// the triple) for the measured build; `facts` and `macros` for a reading's keys.
    pub field: &'static str,
    /// The value the report states: the arm's `outcome` (`None` where it states none), or
    /// the measured `verdict`.
    pub stated: Option<String>,
    /// The measured `level` the report states beside its verdict; `None` on an arm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stated_level: Option<String>,
    /// The value the reading licenses: its `outcome`, or the verdict it restates to
    /// (`None` where it licenses no measured verdict).
    pub restated: Option<String>,
    /// The reading's `level`, which a measured verdict's level restates to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restated_level: Option<String>,
    pub agrees: bool,
}

/// `chard_schema` in both of `detect`'s output shapes: the major version of
/// `schema/chard-detect.schema.json`, under the rule the CLI's contract states.
pub const SCHEMA_VERSION: &str = "1";

/// A report's readings of one check, replayed.
#[derive(Debug, Clone, Serialize)]
pub struct Replay {
    /// [`SCHEMA_VERSION`].
    pub chard_schema: &'static str,
    /// Always `replay`.
    pub kind: &'static str,
    pub check: String,
    pub run_id: String,
    pub inputs_sha256: String,
    pub decoder: DecoderId,
    /// The arm `--arm` restricted the replay to, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arm: Option<&'static str>,
    /// The report's observations of the check: at least one, since a report with none
    /// is refused rather than closed at zero.
    pub observations: usize,
    /// Readings the report owed for the check (and arm).
    pub expected: usize,
    pub replayed: usize,
    pub not_replayable: Vec<NotReplayed>,
    pub replays: Vec<Replayed>,
    /// Every arm outcome and measured verdict stated beside a published reading,
    /// against the reading.
    pub restated: Vec<Restated>,
}

impl Replay {
    /// `expected == replayed + not_replayable.len()`, and `replayed` is the replays listed.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.replayed == self.replays.len()
            && self.expected == self.replayed.saturating_add(self.not_replayable.len())
    }

    /// Whether the report agrees with itself on this check: the counts close, the
    /// published predicate has its own digest, every replayed reading agrees, every value
    /// stated beside a reading is the one the reading licenses, and no owed reading is
    /// absent.
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.closes()
            && self.decoder.digest_agrees
            && self.replays.iter().all(|r| r.agrees)
            && self.restated.iter().all(|r| r.agrees)
            && self
                .not_replayable
                .iter()
                .all(|n| n.reason != REASON_READING_ABSENT)
    }
}

const REASON_CODE: &str = "code-decoder";

/// The code-decoded checks whose decoder reads the artifact without declaring a table.
///
/// The store keeps an arm's artifact only for a check that reads one
/// (`report::stores_arm_artifacts`: the macro and `elf-static` channels, and any check
/// declaring the tables it reads), so an arm of any other code-decoded check is replayed
/// over its build and run records alone. That is exact for a decoder that reads nothing
/// else, and these are the ones that do: `cxx-stdlib-assertions` reads which C++ standard
/// library the artifact's `.chard.report` names. Their arms stay `code-decoder` where the
/// store holds no artifact. `tests/detector_replay.rs` holds the list to the recorded
/// evidence in both directions: every other such decoder reads the same with the artifact
/// taken away, and every one listed here does not.
pub const READS_UNSTORED_ARTIFACT: &[&str] = &["cxx-stdlib-assertions"];
const REASON_CUT: &str = "record-cut";
const REASON_FOLLOW: &str = "unkept-c-int-follow";
const REASON_READING_ABSENT: &str = "reading-absent";

/// A value `path` names in `doc`, or a [`UserError`] naming it as the input the report
/// lacks.
fn required<'a>(doc: &'a Value, path: &[&str]) -> Result<&'a Value, UserError> {
    let mut at = doc;
    for member in path {
        at = at.get(*member).ok_or_else(|| missing(&path.join(".")))?;
    }
    Ok(at)
}

fn missing(what: &str) -> UserError {
    UserError::with_hint(
        format!("the report has no `{what}`, which the replay needs"),
        "a report chard writes carries it; pass one, or the file the \
         reading's facts are in with --evidence",
    )
}

fn string_at(doc: &Value, path: &[&str]) -> Result<String, UserError> {
    required(doc, path)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| missing(&path.join(".")))
}

fn names_at(doc: &Value, path: &[&str]) -> Result<Vec<String>, UserError> {
    required(doc, path)?
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .ok_or_else(|| missing(&path.join(".")))
}

/// One site of an observation that may carry a reading.
struct Site<'a> {
    arm: ArmSel,
    /// The site's `decoded`, when it publishes one.
    decoded: Option<&'a Value>,
    /// The value stated beside the reading that restates it, with a level: an arm's
    /// `outcome`, or a measured `verdict` of `on`, `off` or `partial` and its
    /// `level`. `None` where no rule holds the site to its reading.
    stated: Option<(Option<&'a str>, Option<&'a str>)>,
    /// Whether the site owes a reading.
    owed: bool,
    build: Option<&'a Value>,
    run: Option<&'a Value>,
    /// The digests the site's record publishes, which its reading's keys are held to.
    keys: crate::report::SiteKeys<'a>,
    /// The observation's `controls`, on the measured site: the triple a measured verdict
    /// is held to. `None` on an arm, and where the observation publishes none.
    controls: Option<&'a Value>,
    /// The observation's `verdict`, whatever it is, on the measured site: the value
    /// [`earned`] holds to the triple. `None` on an arm.
    verdict: Option<&'a str>,
}

/// The digests a site's record publishes: its `build`'s artifact, and the `macro_source`
/// and dump digest that `holder` (an arm, or the measured build's `evidence`) carries.
fn site_keys<'a>(
    build: Option<&'a Value>,
    holder: Option<&'a Value>,
) -> crate::report::SiteKeys<'a> {
    let text =
        |v: Option<&'a Value>, member: &str| v.and_then(|v| v.get(member)).and_then(Value::as_str);
    crate::report::SiteKeys {
        artifact: text(build, "artifact_sha256"),
        macro_source: text(holder, "macro_source"),
        dump: text(holder.and_then(|h| h.get("macro_dump")), "stdout_sha256"),
    }
}

/// The measured build of `o`, then each of its control arms that is published.
fn sites_of(o: &Value) -> Vec<Site<'_>> {
    let verdict = o.get("verdict").and_then(Value::as_str);
    let controls = o.get("controls").filter(|c| c.is_object());
    let reached =
        controls.is_some() || matches!(verdict, Some("on" | "off" | "partial" | "probe-invalid"));
    let measured_decoded = o.get("evidence").and_then(|e| e.get("decoded"));
    // Every measured verdict is restated, whatever `gating` says: no gating premise
    // publishes `on`, `off` or `partial` (`gating_rule::Premise::verdict`), and a replay
    // does not re-derive the gating rule the report's rule (d) leans on to skip one.
    let measurement = matches!(verdict, Some("on" | "off" | "partial"));
    let mut out = vec![Site {
        arm: ArmSel::Measured,
        decoded: measured_decoded,
        stated: measurement.then(|| (verdict, o.get("level").and_then(Value::as_str))),
        owed: reached || measured_decoded.is_some(),
        build: o.get("build"),
        run: o.get("run"),
        keys: site_keys(o.get("build"), o.get("evidence")),
        controls,
        verdict,
    }];
    for arm in ArmSel::ALL {
        let Some(field) = arm.controls_field() else {
            continue;
        };
        let Some(published) = controls.and_then(|c| c.get(field)) else {
            continue;
        };
        let decoded = published.get("decoded");
        out.push(Site {
            arm,
            decoded,
            stated: Some((published.get("outcome").and_then(Value::as_str), None)),
            owed: published.get("outcome").is_some() || decoded.is_some(),
            build: published.get("build"),
            run: published.get("run"),
            keys: site_keys(published.get("build"), Some(published)),
            controls: None,
            verdict: None,
        });
    }
    out
}

/// Whether a published build or run record carries the excerpt budget's cut marker in a
/// stream a code decoder reads.
fn record_cut(record: Option<&Value>) -> bool {
    record.is_some_and(|r| {
        ["stdout", "stderr"].iter().any(|stream| {
            r.get(*stream)
                .and_then(Value::as_str)
                .is_some_and(probe::carries_a_cut)
        })
    })
}

/// The report's published predicate for `check`, checked against its digest and
/// validated, with the decoder it is identified as.
fn published_predicate(report: &Value, check: &Check) -> Result<(Predicate, DecoderId), UserError> {
    let decoders = report.get("decoders").ok_or_else(|| missing("decoders"))?;
    let language = string_at(decoders, &["language"]).map_err(|_e| missing("decoders.language"))?;
    if language != predicate::LANGUAGE {
        return Err(UserError::with_hint(
            format!(
                "the report's predicates are written in {language}, and this binary reads {}",
                predicate::LANGUAGE
            ),
            "replay the report with a chard that reads its language",
        ));
    }
    let what = format!("decoders.predicates.{}", check.id);
    let entry = decoders
        .get("predicates")
        .and_then(|p| p.get(check.id))
        .ok_or_else(|| missing(&what))?;
    let sha256 = string_at(entry, &["sha256"]).map_err(|_e| missing(&format!("{what}.sha256")))?;
    let body = entry
        .get("predicate")
        .ok_or_else(|| missing(&format!("{what}.predicate")))?;
    let parsed = Predicate::deserialize(body).map_err(|e| {
        UserError::new(format!(
            "{what}.predicate is not a {} predicate: {e}",
            predicate::LANGUAGE
        ))
    })?;
    predicate::validate(&parsed)
        .map_err(|why| UserError::new(format!("{what}.predicate does not validate: {why}")))?;
    let canonical = predicate::canonical(&parsed)
        .map_err(|e| UserError::new(format!("{what}.predicate has no canonical form: {e}")))?;
    let digest = crate::digest::sha256_hex(canonical.as_bytes());
    Ok((
        parsed,
        DecoderId {
            kind: check.decoder.kind(),
            language: Some(language),
            digest_agrees: digest == sha256,
            sha256,
            source: "report",
        },
    ))
}

/// The value a read returned, as JSON.
fn fact_value(fact: &Fact) -> Value {
    match fact {
        Fact::Undefined => Value::Null,
        Fact::Bool(b) => Value::Bool(*b),
        Fact::Int(i) => Value::from(*i),
        Fact::Text(t) => Value::String(t.clone()),
        Fact::List(items) => Value::from(items.as_slice()),
    }
}

/// A read's key as published, one key per read: `macros.NAME`, `elf.FIELD`,
/// `elf.watched_symbols.NAME`, `elf.watched_symbols` and `elf.truncations`.
fn read_key(key: &ReadKey) -> String {
    match key {
        ReadKey::Symbol(name) => format!("elf.watched_symbols.{name}"),
        other => other.published_key(),
    }
}

fn reads_of(eval: &Evaluation) -> Map<String, Value> {
    eval.reads
        .iter()
        .map(|r| (read_key(&r.key), fact_value(&r.value)))
        .collect()
}

/// A `decoded` value's members.
fn stated(decoded: &Value, at: &str) -> Result<(String, Option<String>, Stated), UserError> {
    let text = |member: &str| {
        decoded
            .get(member)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let need = |member: &str| text(member).ok_or_else(|| missing(&format!("{at}.{member}")));
    Ok((
        need("facts")?,
        text("macros"),
        Stated {
            clause: need("clause")?,
            outcome: need("outcome")?,
            level: text("level"),
        },
    ))
}

/// The inputs every reading of a report replays against.
struct ReportInputs<'a> {
    store: &'a Value,
    macro_filter: Vec<String>,
    watch_list: Vec<String>,
}

/// The outcome `name` spells, if it spells one.
fn outcome_named(name: &str) -> Option<probe::Outcome> {
    [
        probe::Outcome::Present,
        probe::Outcome::Absent,
        probe::Outcome::Indeterminate,
    ]
    .into_iter()
    .find(|o| o.as_str() == name)
}

/// The value `site` states beside `decoded`, held to the one `decoded` licenses on
/// `check`; `None` where no rule holds the site to its reading.
fn restate(check: &Check, probe_id: &str, site: &Site<'_>, decoded: &Value) -> Option<Restated> {
    let (stated, stated_level) = site.stated?;
    let outcome = decoded.get("outcome").and_then(Value::as_str);
    let level = decoded.get("level").and_then(Value::as_str);
    let (field, restated) = if site.arm == ArmSel::Measured {
        let verdict = outcome_named(outcome?)
            .and_then(|o| crate::report::restated_verdict(o, level, check.levels.grade()));
        ("verdict", verdict.map(|v| v.as_str().to_owned()))
    } else {
        ("outcome", outcome.map(ToOwned::to_owned))
    };
    let agrees = restated.is_some()
        && restated.as_deref() == stated
        && (site.arm != ArmSel::Measured || stated_level == level);
    Some(Restated {
        probe: probe_id.to_owned(),
        arm: site.arm.as_str(),
        field,
        stated: stated.map(ToOwned::to_owned),
        stated_level: stated_level.map(ToOwned::to_owned),
        restated,
        restated_level: (site.arm == ArmSel::Measured)
            .then(|| level.map(ToOwned::to_owned))
            .flatten(),
        agrees,
    })
}

/// `stated` beside a reading the replay could not re-derive: the reading licenses
/// nothing a reader can check, so the value stated beside it restates to nothing and
/// disagrees. Held as agreeing, a verdict edited to the one a forged reading licenses
/// would be certified by a reading no replay verified.
fn unverified(stated: Restated) -> Restated {
    Restated {
        restated: None,
        restated_level: None,
        agrees: false,
        ..stated
    }
}

/// The arm `name` of a published triple, where it is published.
fn published_arm<'a>(controls: &'a Value, name: &str) -> Option<&'a Value> {
    controls.get(name).filter(|a| !a.is_null())
}

/// A published arm's `outcome`, where it states one.
fn outcome_of(arm: &Value) -> Option<&str> {
    arm.get("outcome").and_then(Value::as_str)
}

/// A measured verdict held to the control triple published beside it: the report's rule
/// `verdict-unearned-by-controls`, restated from the JSON.
///
/// The triple earns a measurement when its positive arm's `outcome` is `present`, its
/// negative arm's `absent`, any regime arm's `absent`, and `discriminating` is `true`; each
/// arm's `outcome` is itself restated against its reading. A regime arm is owed where
/// `regime_owed` says so ([`Check::owes_regime_control`] over the report's `profile`),
/// and an owed arm that is unpublished or states no `outcome` withholds, as the required
/// arm that could not be evaluated does in `decide`.
///
/// Two verdicts are held to it. A measured `on`, `off` or `partial` restates to itself
/// where the triple earned it, and to `probe-invalid` where a triple is published and did
/// not. A `probe-invalid` beside a triple restates to `probe-invalid` where the triple
/// withheld and to nothing where it discriminated, since a discriminating triple reaches
/// `decide`'s verdict arm and nothing later writes `probe-invalid`. `None` on an arm, on a
/// `probe-invalid` with no triple, and on every other verdict: `indeterminate`,
/// `unsupported` and `not-applicable` beside a discriminating triple are what a gating
/// rule or the fortify ratchet leaves, and a replay re-derives neither.
fn earned(probe_id: &str, site: &Site<'_>, regime_owed: bool) -> Option<Restated> {
    if site.arm != ArmSel::Measured {
        return None;
    }
    let verdict = site.verdict?;
    let measurement = matches!(verdict, "on" | "off" | "partial");
    if !measurement && (verdict != "probe-invalid" || site.controls.is_none()) {
        return None;
    }
    let discriminates = site.controls.is_some_and(|c| {
        let regime = published_arm(c, "regime_negative");
        published_arm(c, "positive").and_then(outcome_of) == Some("present")
            && published_arm(c, "negative").and_then(outcome_of) == Some("absent")
            && if regime_owed {
                regime.and_then(outcome_of) == Some("absent")
            } else {
                regime.is_none_or(|a| outcome_of(a) == Some("absent"))
            }
            && c.get("discriminating").and_then(Value::as_bool) == Some(true)
    });
    let restated = match (discriminates, measurement) {
        (true, true) => Some(verdict.to_owned()),
        (true, false) => None,
        (false, _) => site.controls.map(|_| "probe-invalid".to_owned()),
    };
    Some(Restated {
        probe: probe_id.to_owned(),
        arm: site.arm.as_str(),
        field: "controls",
        stated: Some(verdict.to_owned()),
        stated_level: None,
        agrees: restated.as_deref() == Some(verdict),
        restated,
        restated_level: None,
    })
}

/// Whether the report's observations of `check` owe a regime-matched negative arm: the
/// check's declaration in this binary's corpus and the report's `profile`, read as
/// `measure::Conditions::profile_is_clean` reads it, a flag list the report omits being
/// an empty one. The `profile` is read only for a check that can owe the arm, and is
/// refused as missing where it is absent or a flag list is not a list of strings.
fn regime_owed(report: &Value, check: &Check) -> Result<bool, UserError> {
    if !check.owes_regime_control(false) {
        return Ok(false);
    }
    let profile = required(report, &["profile"])?;
    let mut clean = true;
    for member in ["cflags", "cxxflags", "ldflags"] {
        let Some(flags) = profile.get(member) else {
            continue;
        };
        let flags = flags
            .as_array()
            .filter(|f| f.iter().all(Value::is_string))
            .ok_or_else(|| missing(&format!("profile.{member}")))?;
        clean &= flags.is_empty();
    }
    Ok(check.owes_regime_control(clean))
}

/// A reading's `facts` and `macros` keys held to the digests its site's record publishes
/// ([`crate::report::unbound_reading_keys`]): one entry for `facts`, one for `macros`
/// where the reading names one or the record requires one, and one for each key that
/// is not the record's.
fn keys_restated(
    inputs: &ReportInputs<'_>,
    predicate: &Predicate,
    channel: Channel,
    probe_id: &str,
    site: &Site<'_>,
    decoded: &Value,
) -> Vec<Restated> {
    // A reading with no `facts` is refused as unusable input by `replay_one`.
    let Some(facts) = decoded.get("facts").and_then(Value::as_str) else {
        return Vec::new();
    };
    let macros = decoded.get("macros").and_then(Value::as_str);
    let unbound = crate::report::unbound_reading_keys(
        inputs.store,
        channel,
        site.keys,
        predicate::needs_macros(predicate),
        facts,
        macros,
    );
    let entry =
        |field: &'static str, stated: Option<&str>, restated: Option<&str>, agrees| Restated {
            probe: probe_id.to_owned(),
            arm: site.arm.as_str(),
            field,
            stated: stated.map(ToOwned::to_owned),
            stated_level: None,
            restated: restated.map(ToOwned::to_owned),
            restated_level: None,
            agrees,
        };
    let mut out = Vec::new();
    let named = [("facts", Some(facts)), ("macros", macros)];
    for (member, stated) in named {
        let Some(stated) = stated else { continue };
        if !unbound.iter().any(|u| u.member == member) {
            out.push(entry(member, Some(stated), Some(stated), true));
        }
    }
    for u in &unbound {
        out.push(entry(
            u.member,
            u.stated.as_deref(),
            u.bound.as_deref(),
            false,
        ));
    }
    out
}

/// Re-evaluate one published reading.
fn replay_one(
    inputs: &ReportInputs<'_>,
    predicate: &Predicate,
    channel: Channel,
    probe_id: &str,
    arm: ArmSel,
    decoded: &Value,
    at: &str,
) -> Result<Result<Replayed, NotReplayed>, UserError> {
    let (facts_key, macros_key, published) = stated(decoded, at)?;
    let sources = crate::report::reading_sources(
        inputs.store,
        predicate,
        channel,
        &facts_key,
        macros_key.as_deref(),
    )
    .ok_or_else(|| {
        UserError::with_hint(
            format!(
                "{at} names facts[{facts_key}]{} and the report's `facts` holds no entry of a \
                 kind that can serve it",
                macros_key
                    .as_deref()
                    .map_or_else(String::new, |k| format!(" and facts[{k}]"))
            ),
            "the store is incomplete or holds a kind this binary does not know; a reading is \
             never replayed over facts it does not name",
        )
    })?;
    let view = predicate::Published::new(
        sources.macros.as_ref(),
        sources.filtered.then_some(inputs.macro_filter.as_slice()),
        sources.elf.as_ref(),
        Some(inputs.watch_list.as_slice()),
    );
    let base = |reads, clause, outcome, level, incomplete| Replayed {
        probe: probe_id.to_owned(),
        arm: arm.as_str(),
        facts_key: facts_key.clone(),
        macros_key: macros_key.clone(),
        reads,
        clause,
        outcome,
        level,
        incomplete,
        agrees: false,
        published: published.clone(),
    };
    match view.and_then(|view| predicate::evaluate(predicate, &view)) {
        Ok(eval) => {
            let mut replayed = base(
                reads_of(&eval),
                Some(eval.clause.clone()),
                Some(eval.outcome.as_str()),
                eval.level.clone(),
                None,
            );
            replayed.agrees = eval.clause == published.clause
                && eval.outcome.as_str() == published.outcome
                && eval.level == published.level;
            Ok(Ok(replayed))
        }
        Err(Incomplete(key)) => {
            let followed = key.strip_prefix("macros.").is_some_and(|name| {
                sources.filtered && predicate::reached_only_by_following(predicate, name)
            });
            if followed {
                return Ok(Err(NotReplayed {
                    probe: probe_id.to_owned(),
                    arm: arm.as_str(),
                    reason: REASON_FOLLOW,
                    key: Some(key),
                }));
            }
            Ok(Ok(base(Map::new(), None, None, None, Some(key))))
        }
    }
}

/// The report's observations of `check`, at least one.
///
/// Counting from the input being audited would close a report that never measured the
/// check at `expected: 0`, the same output as a check withheld before its decoder ran: a
/// loop over nothing that exits 0. So none is a refusal.
fn observations_of<'a>(report: &'a Value, check: &Check) -> Result<Vec<&'a Value>, UserError> {
    let mine: Vec<&Value> = required(report, &["observations"])?
        .as_array()
        .ok_or_else(|| missing("observations"))?
        .iter()
        .filter(|o| o.get("check").and_then(Value::as_str) == Some(check.id))
        .collect();
    if mine.is_empty() {
        return Err(UserError::with_hint(
            format!("the report has no observation of {}", check.id),
            "a report observes every check of the corpus it was measured with; this one \
             was measured with another corpus, or was cut",
        ));
    }
    Ok(mine)
}

/// Every site of `observations` that owes a reading, restricted to `arm` where one is
/// named, with its observation's probe id and index.
fn owed_sites<'a>(
    observations: &[&'a Value],
    arm: Option<ArmSel>,
) -> Result<Vec<(String, usize, Site<'a>)>, UserError> {
    let mut sites = Vec::new();
    for (index, o) in observations.iter().enumerate() {
        let probe_id = string_at(o, &["probe"]).map_err(|_e| missing("observations[].probe"))?;
        for site in sites_of(o) {
            if site.owed && arm.is_none_or(|a| a == site.arm) {
                sites.push((probe_id.clone(), index, site));
            }
        }
    }
    Ok(sites)
}

/// A site of a code-decoded check, replayed through this binary's decoder over the records
/// the site publishes: the build and run as published, the ELF facts stored under the
/// build's artifact, and the macros that artifact's `.chard.report` carries, which is the
/// map `measure` hands a probe with no macro-channel check. The reading passes the two
/// gates `measure` applies after a code decoder (`report::truncated_reading`, then
/// `report::cut_stream_reading`), so a replay withholds where the measurement did.
///
/// `Err` where the site cannot be replayed exactly: a record cut by an excerpt budget
/// (`record-cut`), or a record that does not read as the type the decoder takes, or an
/// artifact the store cannot resolve (`code-decoder`).
fn replay_code(
    store: &crate::report::FactStore,
    check: &Check,
    probe_id: &str,
    site: &Site<'_>,
) -> Result<Result<(Replayed, Option<Restated>), NotReplayed>, UserError> {
    let skipped = |reason| NotReplayed {
        probe: probe_id.to_owned(),
        arm: site.arm.as_str(),
        reason,
        key: None,
    };
    if record_cut(site.build) || record_cut(site.run) {
        return Ok(Err(skipped(REASON_CUT)));
    }
    // A published record that does not read as the decoder's input, or an artifact key
    // the store does not resolve, is a report that cannot be used, refused with its cause
    // rather than counted as a reading no replay could reach.
    let unusable = |what: &str, why: String| {
        UserError::new(format!(
            "{probe_id}'s {} {what} does not read: {why}",
            site.arm.as_str()
        ))
    };
    let build = site
        .build
        .map(BuildRecord::deserialize)
        .transpose()
        .map_err(|e| unusable("build record", e.to_string()))?;
    let run = site
        .run
        .map(RunRecord::deserialize)
        .transpose()
        .map_err(|e| unusable("run record", e.to_string()))?;
    let artifact = site.keys.artifact;
    // An `unreadable` entry is an artifact the reader refused, which `measure` handed the
    // decoder as no facts. No entry is an arm of a check whose artifact the store does not
    // keep, replayed over its records where the decoder reads nothing else.
    let elf = match artifact.map(|key| (key, store.get(key))) {
        None | Some((_, Some(crate::report::FactEntry::Unreadable { .. }))) => None,
        Some((key, Some(_))) => Some(store.elf_facts(key).ok_or_else(|| {
            unusable(
                "artifact",
                format!("the store's entry under {key} does not resolve to ELF facts"),
            )
        })?),
        Some((_, None)) if !READS_UNSTORED_ARTIFACT.contains(&check.id) => None,
        Some((_, None)) => return Ok(Err(skipped(REASON_CODE))),
    };
    // The artifact's own `.chard.report`, or no macros where it carries none: the map
    // `measure` hands a probe that has no macro-channel check.
    let macros = artifact
        .and_then(|key| store.macro_view(key))
        .unwrap_or_default();
    let evidence = Evidence {
        macros: &macros,
        elf: elf.as_deref(),
        build: build.as_ref(),
        run: run.as_ref(),
        workdir: None,
    };
    let mut detection = check.decode(&evidence).detection;
    if crate::report::truncated_reading(check, elf.as_deref())
        .or_else(|| crate::report::cut_stream_reading(check, run.as_ref()))
        .is_some()
    {
        detection.outcome = probe::Outcome::Indeterminate;
        detection.level = None;
    }
    let reading = serde_json::json!({
        "outcome": detection.outcome.as_str(),
        "level": detection.level,
    });
    let restated = restate(check, probe_id, site, &reading);
    let (stated, stated_level) = site.stated.unwrap_or((None, None));
    let replayed = Replayed {
        probe: probe_id.to_owned(),
        arm: site.arm.as_str(),
        facts_key: artifact.map(ToOwned::to_owned).unwrap_or_default(),
        macros_key: None,
        reads: Map::new(),
        clause: None,
        outcome: Some(detection.outcome.as_str()),
        level: detection.level,
        incomplete: None,
        published: Stated {
            clause: REASON_CODE.to_owned(),
            outcome: stated.map(ToOwned::to_owned).unwrap_or_default(),
            level: stated_level.map(ToOwned::to_owned),
        },
        agrees: restated.as_ref().is_none_or(|r| r.agrees),
    };
    Ok(Ok((replayed, restated)))
}

/// Every owed site of a code-decoded check, replayed with [`replay_code`] into `out`.
fn replay_code_sites(
    report_store: &Value,
    check: &Check,
    sites: &[(String, usize, Site<'_>)],
    out: &mut Replay,
) -> Result<(), UserError> {
    let store = crate::report::FactStore::deserialize(report_store)
        .map_err(|e| UserError::new(format!("the report's `facts` do not read: {e}")))?;
    for (probe_id, _, site) in sites {
        match replay_code(&store, check, probe_id, site)? {
            Ok((replayed, restated)) => {
                out.replayed = out.replayed.saturating_add(1);
                out.replays.push(replayed);
                out.restated.extend(restated);
            }
            Err(skipped) => out.not_replayable.push(skipped),
        }
    }
    Ok(())
}

/// Replay every reading `report` publishes for `check`, or for its `arm` alone.
///
/// # Errors
///
/// A [`UserError`] for a report that cannot be replayed: not a report, no observation of
/// the check, no `facts`, a reading of the check with no `decoders` entry, a key naming no
/// usable store entry, a predicate in another language or one that does not validate. See
/// the module documentation for what is counted and what disagrees.
pub fn replay_report(
    report: &Value,
    check: &Check,
    arm: Option<ArmSel>,
) -> Result<Replay, UserError> {
    let mine = observations_of(report, check)?;
    let store = required(report, &["facts"])?;
    if !store.is_object() {
        return Err(missing("facts"));
    }
    let mut out = Replay {
        chard_schema: SCHEMA_VERSION,
        kind: "replay",
        check: check.id.to_owned(),
        run_id: string_at(report, &["run", "id"])?,
        inputs_sha256: string_at(report, &["run", "inputs_sha256"])?,
        decoder: DecoderId::corpus(check),
        arm: arm.map(ArmSel::as_str),
        observations: mine.len(),
        expected: 0,
        replayed: 0,
        not_replayable: Vec::new(),
        replays: Vec::new(),
        restated: Vec::new(),
    };
    let sites = owed_sites(&mine, arm)?;
    out.expected = sites.len();
    // The triple needs no reading, so every measured verdict is held to it, a code
    // decoder's included.
    let owed = regime_owed(report, check)?;
    for (probe_id, _, site) in &sites {
        out.restated.extend(earned(probe_id, site, owed));
    }
    if check.predicate().is_none() {
        replay_code_sites(store, check, &sites, &mut out)?;
        return Ok(out);
    }
    if sites.iter().all(|(_, _, s)| s.decoded.is_none()) {
        // No reading of the check is published, so the report owes no `decoders` entry
        // for it: a check withheld before its decoder ran
        // owes no reading either, and closes at `expected: 0`. A site that did owe one is
        // named as absent.
        for (probe_id, _, site) in &sites {
            out.not_replayable.push(NotReplayed {
                probe: probe_id.clone(),
                arm: site.arm.as_str(),
                reason: REASON_READING_ABSENT,
                key: None,
            });
        }
        return Ok(out);
    }
    let (published, decoder) = published_predicate(report, check)?;
    out.decoder = decoder;
    let inputs = ReportInputs {
        store,
        macro_filter: names_at(report, &["evidence_filters", "macros", "names"])?,
        watch_list: names_at(report, &["evidence_filters", "symbols", "names"])?,
    };
    for (probe_id, index, site) in &sites {
        let Some(decoded) = site.decoded else {
            out.not_replayable.push(NotReplayed {
                probe: probe_id.clone(),
                arm: site.arm.as_str(),
                reason: REASON_READING_ABSENT,
                key: None,
            });
            continue;
        };
        let stated = restate(check, probe_id, site, decoded);
        out.restated.extend(keys_restated(
            &inputs,
            &published,
            check.channel(),
            probe_id,
            site,
            decoded,
        ));
        let at = match site.arm.controls_field() {
            None => format!("observations[{}#{index}].evidence.decoded", check.id),
            Some(field) => format!(
                "observations[{}#{index}].controls.{field}.decoded",
                check.id
            ),
        };
        match replay_one(
            &inputs,
            &published,
            check.channel(),
            probe_id,
            site.arm,
            decoded,
            &at,
        )? {
            Ok(replayed) => {
                out.replayed = out.replayed.saturating_add(1);
                out.replays.push(replayed);
                out.restated.extend(stated);
            }
            Err(skipped) => {
                out.not_replayable.push(skipped);
                out.restated.extend(stated.map(unverified));
            }
        }
    }
    Ok(out)
}

/// One decoder over one set of facts: a detection, never a verdict.
#[derive(Debug, Clone, Serialize)]
pub struct Detected {
    /// [`SCHEMA_VERSION`].
    pub chard_schema: &'static str,
    /// Always `detection`: no control triple ran, so nothing here is a verdict.
    pub kind: &'static str,
    pub check: String,
    /// `artifact`, `elf-facts`, `store-entry` or `record`.
    pub input: &'static str,
    /// The store key the facts would have in a report: the artifact's SHA-256, for
    /// `--artifact`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_key: Option<String>,
    pub decoder: DecoderId,
    /// Whether the detection comes with a predicate evaluation (`clause`, `reads`):
    /// `false` for a code decoder, and for a predicate the facts could not answer.
    pub proof: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clause: Option<String>,
    pub outcome: &'static str,
    pub level: Option<String>,
    pub observed: String,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub reads: Map<String, Value>,
    /// The key the facts do not hold, where the predicate stopped at one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<String>,
    /// A record's `expected`, `expected_level` and whether the detection reproduces them,
    /// when the record states an expectation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agrees: Option<bool>,
}

impl Detected {
    fn new(check: &Check, input: &'static str) -> Self {
        Self {
            chard_schema: SCHEMA_VERSION,
            kind: "detection",
            check: check.id.to_owned(),
            input,
            facts_key: None,
            decoder: DecoderId::corpus(check),
            proof: false,
            clause: None,
            outcome: probe::Outcome::Indeterminate.as_str(),
            level: None,
            observed: String::new(),
            reads: Map::new(),
            incomplete: None,
            expected: None,
            expected_level: None,
            agrees: None,
        }
    }

    /// The evaluation of `p`, or the key it stopped at, as this detection.
    fn evaluated(mut self, p: &Predicate, result: Result<Evaluation, Incomplete>) -> Self {
        match result {
            Ok(eval) => {
                self.proof = true;
                self.observed = predicate::render_observed(p, &eval);
                self.reads = reads_of(&eval);
                self.outcome = eval.outcome.as_str();
                self.level = eval.level;
                self.clause = Some(eval.clause);
            }
            Err(Incomplete(key)) => {
                self.observed = format!("the predicate read {key}, which the facts do not hold");
                self.incomplete = Some(key);
            }
        }
        self
    }

    /// Whether the detection disagrees with nothing it was handed.
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.agrees != Some(false)
    }
}

/// The check's predicate, or a [`UserError`] saying the input cannot serve a code decoder.
fn predicate_for(check: &Check, input: &str) -> Result<&'static Predicate, UserError> {
    check.predicate().ok_or_else(|| {
        UserError::with_hint(
            format!(
                "{} is decoded by code from a build or run record, and {input} carries \
                 neither",
                check.id
            ),
            "pass a record (`macros`, `elf`, `build`, `run`) with --evidence",
        )
    })
}

/// The macro map an artifact testifies to, by `measure`'s rule (`report::self_report_entries`,
/// the reading `Gatherer::gather` takes the artifact's macros through): its `.chard.report`
/// where that holds a report, a report whose fields all read undefined included, which is the
/// artifact's account that nothing is defined and reads as an empty map rather than as no
/// account. Reading `parse_self_report` directly and taking a non-empty map as the account
/// would replay an all-`?` report that `measure` published `off` over with no macros, and
/// the replay would disagree.
fn self_reported(elf: &ElfFacts) -> Option<BTreeMap<String, String>> {
    crate::report::self_report_entries(elf).ok()
}

/// `check`'s predicate over ELF facts this binary's reader wrote, with the self-report as
/// the macro source.
fn over_elf(check: &Check, input: &'static str, elf: &ElfFacts) -> Result<Detected, UserError> {
    let p = predicate_for(check, input)?;
    let macros = self_reported(elf);
    let view = Live {
        macros: macros.as_ref(),
        elf: Some(elf),
    };
    Ok(Detected::new(check, input).evaluated(p, predicate::evaluate(p, &view)))
}

/// Read an ELF object and run `check`'s predicate over it.
///
/// # Errors
///
/// The reader's [`crate::elf::ElfError`] for an object it refuses, and a [`UserError`] for a
/// check decoded by code.
pub fn decode_artifact(path: &Path, check: &Check) -> anyhow::Result<Detected> {
    predicate_for(check, "an artifact")?;
    let elf = crate::elf::facts_for(path)?;
    let mut detected = over_elf(check, "artifact", &elf)?;
    detected.facts_key = crate::digest::sha256_file(path);
    Ok(detected)
}

/// A fixture or record: the evidence `probe::Evidence` carries, and an expectation.
#[derive(Debug, Deserialize)]
struct Record {
    #[serde(default)]
    check: Option<String>,
    #[serde(default)]
    expected: Option<String>,
    #[serde(default)]
    expected_level: Option<String>,
    #[serde(default)]
    macros: BTreeMap<String, String>,
    #[serde(default)]
    elf: Option<ElfFacts>,
    #[serde(default)]
    build: Option<BuildRecord>,
    #[serde(default)]
    run: Option<RunRecord>,
}

fn decode_record(value: &Value, check: &Check) -> Result<Detected, UserError> {
    let record = Record::deserialize(value)
        .map_err(|e| UserError::new(format!("the record does not read: {e}")))?;
    if let Some(named) = record.check.as_deref()
        && named != check.id
    {
        return Err(UserError::with_hint(
            format!("the record is evidence for {named}, not {}", check.id),
            "name the check the record was gathered for",
        ));
    }
    let evidence = Evidence {
        macros: &record.macros,
        elf: record.elf.as_ref(),
        build: record.build.as_ref(),
        run: record.run.as_ref(),
        workdir: None,
    };
    let decoding = check.decode(&evidence);
    let mut detected = Detected::new(check, "record");
    detected.outcome = decoding.detection.outcome.as_str();
    detected.level = decoding.detection.level;
    detected.observed = decoding.detection.observed;
    if let Some(eval) = decoding.proof {
        detected.proof = true;
        detected.reads = reads_of(&eval);
        detected.clause = Some(eval.clause);
    }
    if let Some(expected) = record.expected {
        detected.agrees =
            Some(expected == detected.outcome && record.expected_level == detected.level);
        detected.expected = Some(expected);
        detected.expected_level = record.expected_level;
    }
    Ok(detected)
}

fn decode_store_entry(entry: &Value, check: &Check) -> Result<Detected, UserError> {
    let Some(kind) = entry.get("kind").and_then(Value::as_str) else {
        return Err(unrecognised());
    };
    match kind {
        "elf" => {
            let elf = entry
                .get("elf")
                .map(ElfFacts::deserialize)
                .transpose()
                .map_err(|e| UserError::new(format!("the entry's `elf` does not read: {e}")))?
                .ok_or_else(|| UserError::new("the `elf` entry has no `elf` member"))?;
            over_elf(check, "store-entry", &elf)
        }
        "unreadable" => {
            let p = predicate_for(check, "a store entry")?;
            let view = Live {
                macros: None,
                elf: None,
            };
            Ok(Detected::new(check, "store-entry").evaluated(p, predicate::evaluate(p, &view)))
        }
        "macro-dump" => {
            let p = predicate_for(check, "a store entry")?;
            let macros = entry
                .get("macros")
                .ok_or_else(|| UserError::new("the `macro-dump` entry has no `macros` object"))?;
            let names = macros
                .as_object()
                .ok_or_else(|| UserError::new("the `macro-dump` entry has no `macros` object"))?;
            let own = crate::report::evidence_filters().macros;
            let filter: Vec<String> = if entry.get("macros_filter").and_then(Value::as_str)
                == Some(own.sha256.as_str())
            {
                own.names
            } else {
                names.keys().cloned().collect()
            };
            let result = predicate::Published::new(Some(macros), Some(&filter), None, None)
                .and_then(|view| predicate::evaluate(p, &view));
            Ok(Detected::new(check, "store-entry").evaluated(p, result))
        }
        "elf-delta" => Err(UserError::with_hint(
            "an `elf-delta` entry states only how an arm differs from its base",
            "pass the report the entry is from, which holds the base",
        )),
        other => Err(UserError::with_hint(
            format!("a store entry of kind `{other}` is not understood by this binary"),
            "an unknown kind is not read as absent facts; use a chard that writes it",
        )),
    }
}

/// `chard elf` output: one path and its facts.
fn decode_elf_output(map: &Map<String, Value>, check: &Check) -> Result<Detected, UserError> {
    let mut entries = map.values();
    let (Some(only), None) = (entries.next(), entries.next()) else {
        return Err(UserError::with_hint(
            format!("the `chard elf` output describes {} objects", map.len()),
            "pass the output of `chard elf` over one object",
        ));
    };
    let elf = ElfFacts::deserialize(only)
        .map_err(|e| UserError::new(format!("the `chard elf` output does not read: {e}")))?;
    over_elf(check, "elf-facts", &elf)
}

/// What `--evidence` was handed.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Output {
    Replay(Replay),
    Detected(Detected),
}

impl Output {
    /// Whether the input agrees with itself, which decides between exit 0 and exit 1.
    #[must_use]
    pub fn agrees(&self) -> bool {
        match self {
            Self::Replay(r) => r.agrees(),
            Self::Detected(d) => d.agrees(),
        }
    }
}

/// Sniff `value` and replay or decode it for `check` (module documentation, Inputs).
///
/// # Errors
///
/// A [`UserError`] for input of no recognised shape, for `arm` given with anything but a
/// report, and for every refusal [`replay_report`] makes.
pub fn decode_evidence(
    value: &Value,
    check: &Check,
    arm: Option<ArmSel>,
) -> Result<Output, UserError> {
    let Some(map) = value.as_object() else {
        return Err(unrecognised());
    };
    // `chard elf` output first, by its every value: its keys are the paths a caller typed,
    // so one named `chard_schema` or `observations` is a path and not a version. Any other
    // object carrying `chard_schema`, of whatever type, or an `observations` list (which only
    // a report carries; `detect`'s own replay carries `observations` as a count) is held to
    // the version this chard reads before anything else, as `table` holds it
    // (`dataset::refuse_other_schema`), so a report with its version removed or retyped is
    // not read as a record by its `run`.
    let elf_output = !map.is_empty()
        && map
            .values()
            .all(|v| v.get("elf_class").is_some() && v.get("machine").is_some());
    if !elf_output
        && (map.contains_key("chard_schema")
            || map.get("observations").is_some_and(Value::is_array))
    {
        crate::dataset::refuse_other_schema("the evidence", value)?;
        if map.get("observations").is_some_and(Value::is_array) {
            return replay_report(value, check, arm).map(Output::Replay);
        }
        return Err(UserError::with_hint(
            "the evidence carries a `chard_schema` version and no `observations` list, so it \
             is not a report: chard's matrix, probe listing, `detect` output and error envelope \
             have that shape",
            "pass the report itself",
        ));
    }
    if arm.is_some() {
        return Err(UserError::with_hint(
            "--arm selects among a report's readings, and the evidence is not a report",
            "drop --arm, or pass a report",
        ));
    }
    let detected = if elf_output {
        decode_elf_output(map, check)?
    } else if map.contains_key("kind") {
        decode_store_entry(value, check)?
    } else if ["macros", "elf", "build", "run"]
        .iter()
        .any(|k| map.contains_key(*k))
    {
        decode_record(value, check)?
    } else {
        return Err(unrecognised());
    };
    Ok(Output::Detected(detected))
}

fn unrecognised() -> UserError {
    UserError::with_hint(
        "the evidence is not a report, a store entry, a record or `chard elf` output",
        "pass a chard report, one entry of its `facts`, a fixture record, or `chard elf` \
         output over one object",
    )
}

/// Read `path` as JSON and hand it to [`decode_evidence`].
///
/// # Errors
///
/// The io error for a file that cannot be read, and a [`UserError`] for one that is not
/// JSON (a file that is not UTF-8 among them) or that [`decode_evidence`] refuses.
pub fn decode_file(path: &Path, check: &Check, arm: Option<ArmSel>) -> anyhow::Result<Output> {
    use std::os::unix::fs::FileTypeExt as _;
    // Bytes, not a `String`, as `dataset::read_reports` reads them: a file that is not UTF-8
    // is then the parser's refusal and the caller's input, where `read_to_string` failed
    // with `InvalidData`, which the envelope classes as chard's own (`INTERNAL`) while
    // `table` and `matrix` called the same file `USER_INPUT`.
    // Refused from the metadata for a shape no read could turn into evidence, as
    // `dataset::read_report_bytes` refuses it for `table`: a character device such as
    // `/dev/zero` would be read without bound. The name refusals that function also makes
    // (a quarantined, set-aside or partial report) are not made here on purpose: `detect`
    // replays a report's readings, and a quarantined report is one a reader has reason to
    // replay.
    let reading = || format!("reading {}", path.display());
    let kind = std::fs::metadata(path).with_context(reading)?.file_type();
    if !(kind.is_file() || kind.is_fifo()) {
        return Err(UserError::with_hint(
            format!(
                "{} is not evidence chard can read: it is {}",
                path.display(),
                crate::error::file_type_name(kind)
            ),
            "--evidence reads a report, a store entry, a record or `chard elf` output",
        )
        .into());
    }
    let bytes = std::fs::read(path).with_context(reading)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        UserError::with_hint(
            format!("{} is not JSON: {e}", path.display()),
            "--evidence reads a report, a store entry, a record or `chard elf` output",
        )
    })?;
    Ok(decode_evidence(&value, check, arm)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A value stated beside a reading no replay verified restates to nothing and
    /// disagrees, whatever it restated to before.
    #[test]
    fn a_value_beside_an_unverified_reading_restates_to_nothing() {
        let stated = Restated {
            probe: "p".to_owned(),
            arm: "measured",
            field: "verdict",
            stated: Some("on".to_owned()),
            stated_level: Some("2".to_owned()),
            restated: Some("on".to_owned()),
            restated_level: Some("2".to_owned()),
            agrees: true,
        };
        assert_eq!(
            unverified(stated.clone()),
            Restated {
                restated: None,
                restated_level: None,
                agrees: false,
                ..stated
            }
        );
    }
}
