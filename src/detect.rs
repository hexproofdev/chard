// SPDX-License-Identifier: BSD-3-Clause

//! `chard detect`: one check's decoder, run alone over evidence a reader supplies.

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
/// `outcome` against its `decoded.outcome` (the report's rule (c)), a measured `verdict` and
/// `level` against the verdict the measured reading licenses on the check's scale (rule (d),
/// [`crate::report::restated_verdict`]), a measured `verdict` against the triple beside it
/// (`earned`), and a reading's keys against its site's record (`keys_restated`).
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

/// What a replay of one observation's gating found: [`crate::listings::GateReplay`], and
/// `listings-unpublished` for a report that publishes no `listings` and was not measured by
/// this binary's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateOutcome {
    Agrees,
    Disagrees,
    NotReached,
    Overwritten,
    ListingsUnpublished,
}

impl From<crate::listings::GateReplay> for GateOutcome {
    fn from(replay: crate::listings::GateReplay) -> Self {
        match replay {
            crate::listings::GateReplay::Agrees => Self::Agrees,
            crate::listings::GateReplay::Disagrees => Self::Disagrees,
            crate::listings::GateReplay::NotReached => Self::NotReached,
            crate::listings::GateReplay::Overwritten => Self::Overwritten,
        }
    }
}

/// One observation's gating, held to the listing rules re-derived from the driver's answers
/// the report publishes for its probe ([`crate::listings`]).
#[derive(Debug, Clone, Serialize)]
pub struct GateReplayed {
    pub probe: String,
    /// The published verdict.
    pub verdict: String,
    /// The published `gating.rule`; `None` where the observation carries no gating.
    pub rule: Option<String>,
    pub outcome: GateOutcome,
    /// The rule the listing rules give over the published listings, `None` where none
    /// fires: one entry for the published verdict, or one per verdict the rules tell apart
    /// where the published rule is one of theirs ([`crate::listings::replay_gate`]). Empty
    /// where no replay ran.
    pub rederived: Vec<Option<&'static str>>,
    /// Why the replay disagrees without a rederived rule to show it, or what it could not
    /// read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

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
    /// Every observation's gating against the listing rules, one per observation where the
    /// replay covers the measured build (no `--arm`, or `--arm measured`).
    pub gates: Vec<GateReplayed>,
}

impl Replay {
    /// `expected == replayed + not_replayable.len()`, and `replayed` is the replays listed.
    #[must_use]
    pub fn closes(&self) -> bool {
        let gates_owed = if self.arm.is_none_or(|a| a == ArmSel::Measured.as_str()) {
            self.observations
        } else {
            0
        };
        self.replayed == self.replays.len()
            && self.expected == self.replayed.saturating_add(self.not_replayable.len())
            && self.gates.len() == gates_owed
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
                .gates
                .iter()
                .all(|g| g.outcome != GateOutcome::Disagrees)
            && self
                .not_replayable
                .iter()
                .all(|n| n.reason != REASON_READING_ABSENT)
    }
}

const REASON_CODE: &str = "code-decoder";

/// The code-decoded checks whose decoder reads the artifact without declaring a table.
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
        "a report chard writes carries it; pass one, or the file the reading's facts are in with --evidence",
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
    /// An arm's `outcome`, or a measured `on`, `off` or `partial` and its `level`: what
    /// [`restate`] holds to the reading. `None` where no rule holds the site to its reading.
    stated: Option<(Option<&'a str>, Option<&'a str>)>,
    /// Whether the site owes a reading.
    owed: bool,
    build: Option<&'a Value>,
    run: Option<&'a Value>,
    /// The digests the site's record publishes, which its reading's keys are held to.
    keys: crate::report::SiteKeys<'a>,
    /// The observation's `controls`, on the measured site; `None` on an arm, and where the
    /// observation publishes none.
    controls: Option<&'a Value>,
    /// The observation's `verdict`, whatever it is, on the measured site, which [`earned`]
    /// holds to the triple; `None` on an arm.
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
    // publishes `on`, `off` or `partial` (`gating_rule::Premise::verdict`).
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

/// `stated` beside a reading the replay could not re-derive, restated to nothing and
/// disagreeing. Held as agreeing, a verdict edited to the one a forged reading licenses
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
fn earned(
    probe_id: &str,
    site: &Site<'_>,
    regime_owed: bool,
    regime_flags: &RegimeFlags,
) -> Option<Restated> {
    if site.arm != ArmSel::Measured {
        return None;
    }
    let entry = |restated: Option<String>| Restated {
        probe: probe_id.to_owned(),
        arm: site.arm.as_str(),
        field: "controls",
        stated: site.verdict.map(ToOwned::to_owned),
        stated_level: None,
        agrees: restated.is_some() && restated.as_deref() == site.verdict,
        restated,
        restated_level: None,
    };
    let unbuilt_regime = site
        .controls
        .and_then(|c| published_arm(c, "regime_negative"))
        .is_some_and(|a| !regime_flags.hold(a));
    if unbuilt_regime {
        return Some(entry(None));
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
    Some(entry(restated))
}

/// Whether the report's observations of `check` owe a regime-matched negative arm, from the
/// check's declaration in this binary's corpus and whether the report's `profile` is clean
/// (a flag list it omits is empty). The `profile` is read only for a check that can owe the
/// arm, and is refused as missing where it is absent or a flag list is not a list of strings.
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

/// What a published regime arm's `flags` are held to, for [`earned`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum RegimeFlags {
    /// A report of another corpus, whose checks may declare other arms: the flags are read
    /// as written.
    Unheld,
    /// The list `measure` builds the arm with ([`crate::measure::regime_arm_flags`]) under
    /// the report's `profile`.
    Owed(Vec<String>),
    /// The check declares no regime arm, so in a report of this corpus a published one was
    /// built by no chard.
    Undeclared,
}

impl RegimeFlags {
    /// Whether `arm`'s published `flags` are the ones held: a list of strings equal to the
    /// owed list, word for word and in order.
    fn hold(&self, arm: &Value) -> bool {
        match self {
            Self::Unheld => true,
            Self::Undeclared => false,
            Self::Owed(owed) => arm
                .get("flags")
                .and_then(Value::as_array)
                .is_some_and(|flags| {
                    flags.len() == owed.len()
                        && flags
                            .iter()
                            .zip(owed)
                            .all(|(f, o)| f.as_str() == Some(o.as_str()))
                }),
        }
    }
}

/// What the report's regime arms of `check` are held to, as the report's rule
/// `verdict-unearned-by-controls` holds them at publication. The declared arm is this
/// binary's corpus's, so the list is held only in a report whose `run.probe_corpus_sha256`
/// is this binary's. The `profile` is read only for a check that declares an arm, and is
/// refused as missing where it is absent or a flag list is not a list of strings.
fn regime_flags(report: &Value, check: &Check) -> Result<RegimeFlags, UserError> {
    if !crate::report::of_this_corpus(report) {
        return Ok(RegimeFlags::Unheld);
    }
    // `check` is this corpus's, so its probe is found.
    let (Some(probe), Some(_)) = (probe::probe_of_check(check.id), check.regime_arm()) else {
        return Ok(RegimeFlags::Undeclared);
    };
    let (c, cxx, ld) = profile_lists(report)?;
    Ok(
        crate::measure::regime_arm_flags((&c, &cxx, &ld), probe.lang, check)
            .map_or(RegimeFlags::Undeclared, RegimeFlags::Owed),
    )
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
            "the store is incomplete or holds a kind this binary does not know",
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

/// The report's observations of `check`, at least one: closed at `expected: 0`, a report
/// that never measured the check would print what a check withheld before its decoder ran
/// prints, a loop over nothing that exits 0, so none is a refusal.
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
            "a report observes every check of the corpus it was measured with",
        ));
    }
    Ok(mine)
}

/// A profile's three flag lists: `cflags`, `cxxflags` and `ldflags`.
type ProfileLists = (Vec<String>, Vec<String>, Vec<String>);

/// The report's `profile` as its three lists, a list the report omits read as empty.
fn profile_lists(report: &Value) -> Result<ProfileLists, UserError> {
    let profile = required(report, &["profile"])?;
    let list = |member: &str| -> Result<Vec<String>, UserError> {
        let Some(flags) = profile.get(member) else {
            return Ok(Vec::new());
        };
        flags
            .as_array()
            .and_then(|f| {
                f.iter()
                    .map(|w| w.as_str().map(ToOwned::to_owned))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| missing(&format!("profile.{member}")))
    };
    Ok((list("cflags")?, list("cxxflags")?, list("ldflags")?))
}

/// The flags the report's `profile` hands a `lang` build ([`crate::measure::profile_flags_for`]),
/// a list the report omits read as empty, and whether the profile adds none.
fn published_profile(report: &Value) -> Result<(Vec<String>, Vec<String>, bool), UserError> {
    let (c, cxx, ld) = profile_lists(report)?;
    let clean = c.is_empty() && cxx.is_empty() && ld.is_empty();
    let lists = (c.as_slice(), cxx.as_slice(), ld.as_slice());
    Ok((
        crate::measure::profile_flags_for(lists, probe::Lang::C),
        crate::measure::profile_flags_for(lists, probe::Lang::Cxx),
        clean,
    ))
}

/// Every observation of `check` held to the listing rules re-derived from the report's
/// `listings` ([`crate::listings::replay_gate`]): the published rule, or its absence, must be
/// what the rules give over the driver's answers published for the observation's probe.
fn replay_gates(
    report: &Value,
    check: &Check,
    observations: &[&Value],
) -> Result<Vec<GateReplayed>, UserError> {
    let (c_flags, cxx_flags, clean) = published_profile(report)?;
    let published = PublishedListings {
        member: report.get("listings"),
        ours: report
            .get("run")
            .and_then(|r| r.get("decoders_sha256"))
            .and_then(Value::as_str)
            == Some(probe::decoders_sha256().as_str()),
        c_flags,
        cxx_flags,
        clean,
    };
    observations
        .iter()
        .enumerate()
        .map(|(index, o)| gate_of(&published, check, index, o))
        .collect()
}

/// What [`replay_gates`] reads of a report beside each observation: its `listings` member, whether
/// its `run.decoders_sha256` is this binary's, and its profile's flags for each language.
struct PublishedListings<'a> {
    member: Option<&'a Value>,
    ours: bool,
    c_flags: Vec<String>,
    cxx_flags: Vec<String>,
    clean: bool,
}

/// One observation's gate ([`replay_gates`]).
fn gate_of(
    published: &PublishedListings<'_>,
    check: &Check,
    index: usize,
    o: &Value,
) -> Result<GateReplayed, UserError> {
    let at = |what: &str| format!("observations[{}#{index}].{what}", check.id);
    let probe_id = o
        .get("probe")
        .and_then(Value::as_str)
        .ok_or_else(|| missing(&at("probe")))?;
    let verdict_text = o
        .get("verdict")
        .and_then(Value::as_str)
        .ok_or_else(|| missing(&at("verdict")))?;
    let verdict: crate::report::Verdict = serde_json::from_value(Value::from(verdict_text))
        .map_err(|_unknown| missing(&at("verdict")))?;
    let gated = o.get("gating").is_some_and(|g| !g.is_null());
    let rule = o
        .get("gating")
        .and_then(|g| g.get("rule"))
        .and_then(Value::as_str);
    let mut gate = GateReplayed {
        probe: probe_id.to_owned(),
        verdict: verdict_text.to_owned(),
        rule: rule.map(ToOwned::to_owned),
        outcome: GateOutcome::Disagrees,
        rederived: Vec::new(),
        detail: None,
    };
    if gated && rule.is_none() {
        gate.detail = Some(format!(
            "{} carries no rule, so its place on the ladder cannot be shown",
            at("gating")
        ));
        return Ok(gate);
    }
    // The triple's state is the published `controls.discriminating`, not re-derived from its
    // arms as `earned` reads them: a declared rule's gating beside a triple edited from
    // discriminating to withheld agrees, a relabel that withholds a cell and publishes no
    // `on` or `off`.
    let triple = match o.get("controls").filter(|c| c.is_object()) {
        None => crate::listings::TripleSeen::Absent,
        Some(c) if c.get("discriminating").and_then(Value::as_bool) == Some(true) => {
            crate::listings::TripleSeen::Discriminating
        }
        Some(_) => crate::listings::TripleSeen::Withheld,
    };
    match crate::listings::before_listings(verdict, rule, triple) {
        Ok(Some(placed)) => {
            gate.outcome = placed.into();
            if placed == crate::listings::GateReplay::Disagrees {
                gate.detail = Some(
                    "the gating is not one the ladder publishes beside this verdict and control triple"
                        .to_owned(),
                );
            }
            return Ok(gate);
        }
        Ok(None) => {}
        Err(id) => {
            gate.detail = Some(format!("the rule {id} is not one this binary knows"));
            return Ok(gate);
        }
    }
    match against_listings(published, check, probe_id, verdict, rule)? {
        Ok((outcome, rederived)) => {
            gate.outcome = outcome;
            gate.rederived = rederived;
        }
        Err(Unreplayed::Unpublished) => gate.outcome = GateOutcome::ListingsUnpublished,
        Err(Unreplayed::Disagrees(why)) => gate.detail = Some(why),
    }
    Ok(gate)
}

/// A gate's outcome and its rederived rules, or why no rule was replayed.
type ListingReplay = Result<(GateOutcome, Vec<Option<&'static str>>), Unreplayed>;

/// Why [`against_listings`] replayed no rule: a report with no record whose
/// `run.decoders_sha256` is not this binary's, or one whose record cannot be the one `measure`
/// writes.
enum Unreplayed {
    Unpublished,
    Disagrees(String),
}

/// One observation reached by the listing rules, held to them over its probe's published
/// record ([`crate::listings::replay_gate`]).
fn against_listings(
    published: &PublishedListings<'_>,
    check: &Check,
    probe_id: &str,
    verdict: crate::report::Verdict,
    rule: Option<&str>,
) -> Result<ListingReplay, UserError> {
    let Some(member) = published.member else {
        return Ok(Err(if published.ours {
            Unreplayed::Disagrees(
                "the report names this binary's decoders_sha256 and publishes no listings"
                    .to_owned(),
            )
        } else {
            Unreplayed::Unpublished
        }));
    };
    let Some(probe) = probe::CORPUS
        .iter()
        .find(|p| p.id == probe_id && p.checks.iter().any(|c| c.id == check.id))
    else {
        return Ok(Err(Unreplayed::Disagrees(format!(
            "the probe {probe_id} is not one of this binary's corpus that holds {}",
            check.id
        ))));
    };
    let record: crate::listings::Listings = match member.get(probe_id) {
        None => crate::listings::Listings::default(),
        Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
            UserError::with_hint(
                format!("listings[{probe_id}] does not read as the driver's answers: {e}"),
                "a record this binary cannot read is refused rather than replayed as empty",
            )
        })?,
    };
    let findings = match held_listings(published, probe, &record) {
        Ok(findings) => findings,
        Err(why) => return Ok(Err(Unreplayed::Disagrees(why))),
    };
    let measured = match probe.lang {
        probe::Lang::C => &published.c_flags,
        probe::Lang::Cxx => &published.cxx_flags,
    };
    let classes = crate::listings::arm_optimization_classes(check, measured, published.clean);
    let held = findings.for_check(check, &classes);
    let branches = crate::measure::branches_on_macros(probe.id);
    Ok(
        match crate::listings::replay_gate(check, verdict, rule, branches, &held) {
            Ok((replay, rederived)) => Ok((replay.into(), rederived)),
            Err(id) => Err(Unreplayed::Disagrees(format!(
                "the rule {id} is not one this binary knows"
            ))),
        },
    )
}

/// The findings `record` gives `probe`, or why it is not the record `measure` writes for the
/// probe under the published profile: comparisons other than the ones the probe owes
/// ([`crate::listings::Owed`]), an answer out of the comparisons' order, a path its
/// comparisons read that it does not answer, or arm class listings other than the ones the
/// compile comparison owes ([`class_shortfall`]).
fn held_listings(
    published: &PublishedListings<'_>,
    probe: &probe::Probe,
    record: &crate::listings::Listings,
) -> Result<crate::listings::Findings, String> {
    let unmet = crate::listings::Owed::of(probe, published.clean).unmet_by(record);
    if !unmet.is_empty() {
        return Err(format!(
            "listings[{}] does not hold the comparisons the probe owes under this profile: {}",
            probe.id,
            unmet.join(", ")
        ));
    }
    let paths = crate::listings::Recorded::new(&record.paths);
    let findings = crate::listings::findings(record, &paths)
        .map_err(|crate::listings::Malformed(why)| format!("listings[{}]: {why}", probe.id))?;
    let unanswered = paths.unanswered();
    if !unanswered.is_empty() {
        let named: Vec<&str> = unanswered.iter().map(String::as_str).collect();
        return Err(format!(
            "listings[{}].paths answers none of {}",
            probe.id,
            named.join(", ")
        ));
    }
    let measured = match probe.lang {
        probe::Lang::C => &published.c_flags,
        probe::Lang::Cxx => &published.cxx_flags,
    };
    match class_shortfall(probe, record, &findings, measured, published.clean) {
        Some(why) => Err(why),
        None => Ok(findings),
    }
}

/// Where `record`'s arm class listings are not the ones the compile comparison owes
/// ([`crate::listings::owed_classes`]): it asks for them, in that order, exactly where the
/// measured listing and the stand-in were read and agree, which is where `findings` names no
/// whole-probe difference. `None` where they are.
fn class_shortfall(
    probe: &probe::Probe,
    record: &crate::listings::Listings,
    findings: &crate::listings::Findings,
    measured: &[String],
    clean: bool,
) -> Option<String> {
    let compile = record.compile.as_ref()?;
    let words: Vec<&Vec<String>> = compile.classes.iter().map(|c| &c.words).collect();
    let owed = if findings.compile.whole.is_none() {
        crate::listings::owed_classes(probe, measured, clean)
    } else {
        Vec::new()
    };
    let same = words.len() == owed.len() && words.iter().zip(&owed).all(|(w, o)| *w == o);
    (!same).then(|| {
        format!(
            "listings[{}].compile.classes are not the arm classes the probe's checks owe",
            probe.id
        )
    })
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
/// build's artifact, and the macros that artifact's `.chard.report` carries. The reading
/// passes the two gates `measure` applies after a code decoder (`report::truncated_reading`,
/// then `report::cut_stream_reading`), so a replay withholds where the measurement did.
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
    // decoder as no facts.
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
        gates: Vec::new(),
    };
    if arm.is_none_or(|a| a == ArmSel::Measured) {
        out.gates = replay_gates(report, check, &mine)?;
    }
    let sites = owed_sites(&mine, arm)?;
    out.expected = sites.len();
    // The triple needs no reading, so a code decoder's measured verdict is held to it too.
    let owed = regime_owed(report, check)?;
    let flags = regime_flags(report, check)?;
    for (probe_id, _, site) in &sites {
        out.restated.extend(earned(probe_id, site, owed, &flags));
    }
    if check.predicate().is_none() {
        replay_code_sites(store, check, &sites, &mut out)?;
        return Ok(out);
    }
    if sites.iter().all(|(_, _, s)| s.decoded.is_none()) {
        // No reading is published, so the report owes no `decoders` entry: a check withheld
        // before its decoder ran closes at `expected: 0`, and a site that owed one is named
        // as absent.
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
    /// The store key the facts would have in a report. Always present for `--artifact`: the
    /// SHA-256 of the bytes the reader parsed, from the one read the facts came from.
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
/// which `Gatherer::gather` reads too): its `.chard.report` where that holds a report, one
/// whose fields all read undefined included, which is an empty map and not no account.
/// Taking only a non-empty map as the account would replay with no macros an all-`?` report
/// that `measure` published `off` over, and disagree.
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
    // One read serves the facts and the key, because a FIFO yields its bytes once.
    let bytes = crate::elf::read_object(path)?;
    let elf = crate::elf::facts_from(path, &bytes)?;
    let mut detected = over_elf(check, "artifact", &elf)?;
    detected.facts_key = Some(crate::digest::sha256_hex(&bytes));
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
            "an unknown kind is not read as absent facts",
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
    // so one named `chard_schema` or `observations` is a path and not a version.
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
            "the evidence carries a `chard_schema` version and no `observations` list",
            "pass the report itself",
        ));
    }
    if arm.is_some() {
        return Err(UserError::with_hint(
            "--arm selects among a report's readings",
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
        "pass a chard report, one entry of its `facts`, a fixture record",
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
    // is then the parser's refusal and the caller's input (`USER_INPUT`), as `table` and
    // `matrix` class it, not an io error the envelope classes as chard's own (`INTERNAL`).
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

    #[test]
    fn a_regime_arm_is_held_to_its_probe_s_language() {
        let profile = serde_json::json!({
            "cflags": ["-O2"],
            "cxxflags": ["-O1"],
            "ldflags": ["-Wl,-z,now"],
        });
        let report = |corpus: String| {
            serde_json::json!({
                "run": {"probe_corpus_sha256": corpus},
                "profile": profile,
            })
        };
        let this = report(probe::corpus_sha256());
        for (probe, lead) in [(probe::Lang::C, "-O2"), (probe::Lang::Cxx, "-O1")] {
            let check = probe::CORPUS
                .iter()
                .filter(|p| p.lang == probe)
                .find_map(|p| p.checks.iter().find(|c| c.regime_arm().is_some()))
                .expect("a check of the language that declares a regime arm");
            let mut owed = vec![lead.to_owned(), "-Wl,-z,now".to_owned()];
            owed.extend(
                check
                    .regime_arm()
                    .into_iter()
                    .flatten()
                    .map(|f| (*f).to_owned()),
            );
            assert_eq!(
                regime_flags(&this, check).expect("the profile reads"),
                RegimeFlags::Owed(owed),
                "{}",
                check.id
            );
            assert_eq!(
                regime_flags(&report("another".to_owned()), check).expect("reads"),
                RegimeFlags::Unheld,
                "{}",
                check.id
            );
        }
        let undeclared = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.regime_arm().is_none())
            .expect("a check that declares no regime arm");
        assert_eq!(
            regime_flags(&this, undeclared).expect("reads"),
            RegimeFlags::Undeclared
        );
        assert_eq!(
            regime_flags(&report("another".to_owned()), undeclared).expect("reads"),
            RegimeFlags::Unheld,
            "a report of another corpus is read as written, whatever this corpus declares"
        );
    }

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

    /// The class listings of `record`'s compile comparison.
    fn classes_of(record: &mut crate::listings::Listings) -> &mut Vec<crate::listings::ClassAsked> {
        &mut record.compile.as_mut().expect("a compile record").classes
    }

    /// The compile comparison's answer to `flags`, as the record of the tests below holds it.
    fn asked(flags: &[String]) -> crate::listings::Asked<crate::compile_inputs::CompileInputs> {
        crate::listings::Asked {
            flags: flags.to_vec(),
            answer: crate::listings::Answer::Answer(crate::compile_inputs::CompileInputs {
                programs: vec!["/".to_owned()],
                headers: vec![("-isystem".to_owned(), "/".to_owned())],
                macros: Vec::new(),
                removals: Vec::new(),
                targets: Vec::new(),
                sanitizers: Vec::new(),
                lto: Vec::new(),
                relocation: Vec::new(),
                exception_models: Vec::new(),
            }),
        }
    }

    /// A probe that owes class listings under its own language's flags and not the other's;
    /// the profile it is published under; the record `measure` writes for it, its paths
    /// unanswered; and its language's flags.
    fn owing_record() -> (
        &'static probe::Probe,
        PublishedListings<'static>,
        crate::listings::Listings,
        Vec<String>,
    ) {
        use crate::listings::{ClassAsked, CompileAsked, Listings, Owed};
        let probe = probe::CORPUS
            .iter()
            .find(|p| p.checks.iter().any(|c| c.id == "optimization-enabled"))
            .expect("a probe holds optimization-enabled");
        let flags = vec!["-isystem".to_owned(), "/".to_owned()];
        let other = vec!["-O3".to_owned(), "-isystem".to_owned(), "/".to_owned()];
        let (c_flags, cxx_flags) = match probe.lang {
            probe::Lang::C => (flags.clone(), other.clone()),
            probe::Lang::Cxx => (other.clone(), flags.clone()),
        };
        let published = PublishedListings {
            member: None,
            ours: true,
            c_flags,
            cxx_flags,
            clean: false,
        };
        assert_ne!(
            crate::listings::owed_classes(probe, &flags, false),
            crate::listings::owed_classes(probe, &other, false),
            "the two languages' flags owe different classes"
        );
        assert!(Owed::of(probe, false).compile);
        let owed_classes = crate::listings::owed_classes(probe, &flags, false);
        assert!(!owed_classes.is_empty(), "the probe owes class listings");
        let record = Listings {
            compile: Some(CompileAsked {
                measured: asked(&flags),
                stand_in: Some(asked(&flags)),
                classes: owed_classes
                    .iter()
                    .map(|words| ClassAsked {
                        words: words.clone(),
                        listing: asked(words),
                    })
                    .collect(),
            }),
            ..Listings::default()
        };
        (probe, published, record, flags)
    }

    #[test]
    fn a_record_short_of_the_one_measure_writes_is_named() {
        use crate::listings::ClassAsked;
        let (probe, published, mut record, flags) = owing_record();
        let mut named = 0;
        let unanswered = held_listings(&published, probe, &record).expect_err("paths unanswered");
        assert!(unanswered.contains("paths answers none of"), "{unanswered}");
        named += 1;
        let host = crate::link_inputs::Host::default();
        crate::listings::findings(&record, &host).expect("a well-formed record");
        record.paths = host.answers();
        assert!(held_listings(&published, probe, &record).is_ok());
        let mut extra_class = record.clone();
        classes_of(&mut extra_class).push(ClassAsked {
            words: vec!["-O3".to_owned()],
            listing: asked(&flags),
        });
        let mut dropped = record.clone();
        classes_of(&mut dropped).pop();
        let mut reworded = record.clone();
        classes_of(&mut reworded)[0]
            .words
            .push("-fno-inline".to_owned());
        for (edited, what) in [
            (&extra_class, "a class unowed"),
            (&dropped, "a class dropped"),
            (&reworded, "a class reworded"),
        ] {
            let why = held_listings(&published, probe, edited).expect_err(what);
            assert!(why.contains("compile.classes"), "{what}: {why}");
            named += 1;
        }
        let mut unowed = record.clone();
        unowed.measured_compile = Some(asked(&flags));
        let owes = held_listings(&published, probe, &unowed).expect_err("an unowed comparison");
        assert!(owes.contains("measured_compile"), "{owes}");
        named += 1;
        assert_eq!(named, 5);
    }

    #[test]
    fn a_gating_is_placed_by_the_triple_its_observation_publishes() {
        use crate::report::gating_rule::{self, Rule, Stage};
        let published = PublishedListings {
            member: None,
            ours: false,
            c_flags: Vec::new(),
            cxx_flags: Vec::new(),
            clean: true,
        };
        let probe = probe::CORPUS
            .iter()
            .find(|p| p.checks.iter().any(|c| c.id == "cet-marked"))
            .expect("a probe holds cet-marked");
        let check = probe
            .checks
            .iter()
            .find(|c| c.id == "cet-marked")
            .expect("cet-marked");
        let declared = &gating_rule::COMPILER_DECLARED;
        let early = gating_rule::ALL
            .iter()
            .find(|r| r.stage == Stage::Applicability)
            .expect("an applicability-stage rule");
        let observation = |rule: &Rule, controls: Option<Value>| {
            let mut o = serde_json::json!({
                "probe": probe.id,
                "verdict": rule.verdict(),
                "gating": { "rule": rule.id },
            });
            if let Some(c) = controls {
                o["controls"] = c;
            }
            o
        };
        let said =
            |discriminating: bool| Some(serde_json::json!({ "discriminating": discriminating }));
        let rows = [
            (declared, said(true), GateOutcome::Disagrees),
            (declared, said(false), GateOutcome::ListingsUnpublished),
            (
                declared,
                Some(serde_json::json!({})),
                GateOutcome::ListingsUnpublished,
            ),
            (early, None, GateOutcome::NotReached),
            (early, Some(Value::Null), GateOutcome::NotReached),
            (early, said(false), GateOutcome::Disagrees),
        ];
        let mut placed = 0;
        for (rule, controls, expected) in rows {
            let o = observation(rule, controls.clone());
            let gate = gate_of(&published, check, 0, &o).expect("a readable observation");
            assert_eq!(gate.outcome, expected, "{} beside {controls:?}", rule.id);
            placed += 1;
        }
        assert_eq!(placed, 6);
    }
}
