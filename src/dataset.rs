// SPDX-License-Identifier: BSD-3-Clause

//! Whether a set of reports may be compared with each other at all.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::Context as _;
use serde_json::Value;

use crate::error::UserError;
use crate::report::ConsistencyStatus;

/// What the identity fields say across a set of reports.
#[derive(Debug, Clone, Default)]
pub struct Identity {
    /// Distinct `probe_corpus_sha256` values seen, mapped to the reports carrying them.
    pub corpora: BTreeMap<String, Vec<String>>,
    /// Distinct `decoders_sha256` values seen, mapped to the reports carrying them.
    pub decoders: BTreeMap<String, Vec<String>>,
    /// Distinct revision keys seen ([`revision_key`]), mapped to the reports carrying them.
    pub revisions: BTreeMap<String, Vec<String>>,
    /// Reports whose revision carries the `-dirty` suffix, so they correspond to no
    /// commit and cannot be cited.
    pub dirty: Vec<String>,
    /// Reports whose revision was asserted with `CHARD_REVISION` when chard was built, which
    /// nothing checked against the tree: a modified tree built under a clean hash is among
    /// them, with no `-dirty`.
    pub asserted: Vec<String>,
    /// Reports measured by a chard built under rustflags (`run.harness_rustflags_sha256`).
    pub rustflags: Vec<String>,
    /// Distinct `environment.execution.mode` values seen, mapped to the reports
    /// carrying them.
    pub executions: BTreeMap<String, Vec<String>>,
    /// Reports whose image was named on an operator's word, with nothing carried in to
    /// support the name.
    pub unattested: Vec<String>,
}

/// The sentinel for a report that names no such field. Spelled rather than skipped:
/// see the module note on why absence is not permission.
const UNKNOWN: &str = "(absent)";

fn field(report: &Value, key: &str) -> String {
    report
        .get("run")
        .and_then(|r| r.get(key))
        .and_then(Value::as_str)
        .unwrap_or(UNKNOWN)
        .to_owned()
}

/// The `run.harness_revision_source` spellings of a revision read from the tree the harness
/// compiled: git, a `git archive`'s `REVISION` file, a crate archive's `.cargo_vcs_info.json`.
/// `asserted`, `CHARD_REVISION`'s, is not among them. `tests/build_revision.rs` holds this
/// list to `build/revision.rs`'s `Source`.
pub const TREE_SOURCES: [&str; 3] = ["git", "archive", "cargo-vcs"];

/// The revision a report joins on: `run.harness_revision`, with `[<source>]` after it unless
/// a tree source named it, and `[rustflags <digest>]` where the harness was built under
/// rustflags. One commit read from a clone, an archive or a crate archive is one key; the same
/// hash asserted with `CHARD_REVISION` is another, since an asserted label is the builder's
/// word and a modified tree built under a clean hash carries no `-dirty`; so is a revision
/// whose report names no source, since absence is not permission. Reports asserted alike
/// join among themselves.
pub fn revision_key(report: &Value) -> String {
    let run = report.get("run");
    let get = |key: &str| run.and_then(|r| r.get(key)).and_then(Value::as_str);
    let source = match get("harness_revision_source") {
        _ if get("harness_revision").is_none() => String::new(),
        Some(source) if TREE_SOURCES.contains(&source) => String::new(),
        Some(source) => format!(" [{source}]"),
        None => format!(" [source {UNKNOWN}]"),
    };
    let rustflags = match get("harness_rustflags_sha256") {
        Some(digest) => format!(" [rustflags {digest}]"),
        None => String::new(),
    };
    format!("{}{source}{rustflags}", field(report, "harness_revision"))
}

/// This build's own [`revision_key`] ([`build_key`] of its stamps).
pub fn this_build_key() -> Option<String> {
    use crate::report::{HARNESS_REVISION, HARNESS_REVISION_SOURCE, HARNESS_RUSTFLAGS_SHA256};
    build_key(
        HARNESS_REVISION,
        HARNESS_REVISION_SOURCE,
        HARNESS_RUSTFLAGS_SHA256,
    )
}

/// The [`revision_key`] of a build with these stamps, where it names one tree: `None` where
/// there is no revision or no source, the revision is dirty, or the source is not a tree
/// source (an asserted label, which two builds of two different trees can share). The one
/// place a build's own key is decided, so a reader holding a report to its own table never
/// takes a dirty or an asserted revision for its own.
pub fn build_key(
    revision: Option<&str>,
    source: Option<&str>,
    rustflags: Option<&str>,
) -> Option<String> {
    let (revision, source) = (revision?, source?);
    if revision.ends_with("-dirty") || !TREE_SOURCES.contains(&source) {
        return None;
    }
    let mut run = serde_json::Map::new();
    run.insert("harness_revision".to_owned(), revision.into());
    run.insert("harness_revision_source".to_owned(), source.into());
    if let Some(digest) = rustflags {
        run.insert("harness_rustflags_sha256".to_owned(), digest.into());
    }
    Some(revision_key(&serde_json::json!({ "run": run })))
}

impl Identity {
    /// Collect the identity fields from `(name, report)` pairs.
    pub fn of(reports: &[(String, Value)]) -> Self {
        let mut id = Self::default();
        for (name, report) in reports {
            let corpus = field(report, "probe_corpus_sha256");
            let decoders = field(report, "decoders_sha256");
            let revision = revision_key(report);
            if field(report, "harness_revision").ends_with("-dirty") {
                id.dirty.push(name.clone());
            }
            let run = report.get("run");
            let run_str = |key: &str| run.and_then(|r| r.get(key)).and_then(Value::as_str);
            if run_str("harness_revision_source") == Some("asserted") {
                id.asserted.push(name.clone());
            }
            if run_str("harness_rustflags_sha256").is_some() {
                id.rustflags.push(name.clone());
            }
            let execution = report
                .get("environment")
                .and_then(|e| e.get("execution"))
                .and_then(|e| e.get("mode"))
                .and_then(Value::as_str)
                .unwrap_or(UNKNOWN)
                .to_owned();
            // Absent reads as unattested rather than as nothing to say: a report that
            // carries no attestation has established nothing about its image.
            let status = report
                .get("environment")
                .and_then(|e| e.get("execution"))
                .and_then(|e| e.get("image_attestation"))
                .and_then(|a| a.get("status"))
                .and_then(Value::as_str);
            // Matched against `AttestationStatus`'s own spellings; a status it does not
            // recognise counts as unattested, which says less than the report claimed rather
            // than more.
            let established = crate::env::AttestationStatus::ALL
                .iter()
                .find(|s| Some(s.as_str()) == status)
                .is_some_and(|s| s.is_established());
            if !established {
                id.unattested.push(name.clone());
            }
            id.corpora.entry(corpus).or_default().push(name.clone());
            id.decoders.entry(decoders).or_default().push(name.clone());
            id.revisions.entry(revision).or_default().push(name.clone());
            id.executions
                .entry(execution)
                .or_default()
                .push(name.clone());
        }
        id
    }

    /// True when every report came from one corpus, one harness revision and one execution
    /// mode.
    pub fn is_joinable(&self) -> bool {
        self.corpora.len() <= 1 && self.revisions.len() <= 1 && self.executions.len() <= 1
    }

    /// Why these reports are not joinable, one line per differing field. Empty when
    /// they are.
    pub fn conflicts(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.corpora.len() > 1 {
            out.push(format!(
                "probe corpora differ, so these reports do not measure the same set of \
                 checks or do not read them alike: {}; {}",
                describe(&self.corpora),
                self.decoder_movement()
            ));
        }
        if self.revisions.len() > 1 {
            out.push(format!(
                "harness revisions differ, so the same evidence may have been read by \
                 different code (one revision asserted with CHARD_REVISION, built under \
                 rustflags, or naming no source is a revision of its own): {}",
                describe(&self.revisions)
            ));
        }
        if self.executions.len() > 1 {
            out.push(format!(
                "execution modes differ, so some of these rows ran on a kernel that was \
                 not their distribution's and their kernel-enforced verdicts are not \
                 comparable: {}",
                describe(&self.executions)
            ));
        }
        out
    }

    /// Whether the decoders moved between the differing corpora, in the words a refusal
    /// carries, so its reader is told which of the declared corpus and its decoders changed.
    fn decoder_movement(&self) -> String {
        if self.decoders.contains_key(UNKNOWN) {
            format!(
                "run.decoders_sha256 is absent from some of them (a report an earlier chard \
                 wrote carries none), so whether the decoders moved is not stated: {}",
                describe(&self.decoders)
            )
        } else if self.decoders.len() > 1 {
            format!(
                "the decoders moved too, so the same evidence may read differently \
                 (run.decoders_sha256): {}",
                describe(&self.decoders)
            )
        } else {
            format!(
                "the decoders did not move (run.decoders_sha256 {} throughout)",
                self.decoders.keys().next().map_or(UNKNOWN, String::as_str)
            )
        }
    }

    /// Warnings that do not make the set unjoinable but must not go unsaid.
    pub fn cautions(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.dirty.is_empty() {
            out.push(format!(
                "{} report(s) were measured from a modified tree and correspond to no \
                 commit, so they cannot be cited: {}",
                self.dirty.len(),
                self.dirty.join(", ")
            ));
        }
        if !self.asserted.is_empty() {
            out.push(format!(
                "{} report(s) name a revision asserted with CHARD_REVISION when chard was \
                 built, which nothing checked against the tree it was built from, so the commit \
                 rests on the builder's word: {}",
                self.asserted.len(),
                describe_list(&self.asserted)
            ));
        }
        if !self.rustflags.is_empty() {
            out.push(format!(
                "{} report(s) were measured by a chard built under rustflags \
                 (run.harness_rustflags_sha256), so the binary is not the one its revision \
                 alone names: {}",
                self.rustflags.len(),
                describe_list(&self.rustflags)
            ));
        }
        if !self.unattested.is_empty() {
            out.push(format!(
                "{} of {} report(s) name an image that nothing establishes, so their \
                 distribution attribution rests on an operator-supplied label: {}",
                self.unattested.len(),
                self.corpora.values().map(Vec::len).sum::<usize>(),
                describe_list(&self.unattested)
            ));
        }
        out
    }
}

/// A report list, truncated, so a caution naming 108 files stays readable.
fn describe_list(names: &[String]) -> String {
    let shown: Vec<&str> = names.iter().take(6).map(String::as_str).collect();
    let more = names.len().saturating_sub(shown.len());
    if more == 0 {
        shown.join(", ")
    } else {
        format!("{}, +{more} more", shown.join(", "))
    }
}

/// `value (report, report) | value (report)`, with long report lists truncated.
fn describe(groups: &BTreeMap<String, Vec<String>>) -> String {
    groups
        .iter()
        .map(|(value, names)| {
            let shown: Vec<&str> = names.iter().take(3).map(String::as_str).collect();
            let more = names.len().saturating_sub(shown.len());
            if more == 0 {
                format!("{value} ({})", shown.join(", "))
            } else {
                format!("{value} ({}, +{more} more)", shown.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Reports whose own copies of a verdict disagree with each other.
pub fn self_contradicted(reports: &[(String, Value)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, report) in reports {
        // A report `measure` published passes the re-run rules by construction, so a finding
        // is an edit, a file assembled elsewhere, or a rule whose contract changed since; an
        // older shape is typed as that where it is made (`report::Reread::older`).
        let reread = crate::report::reread_contradictions(report);
        let mut found = Vec::new();
        contradictions_of(name, report, &reread, &mut found);
        let finding = |kind, text| Finding {
            report: name.clone(),
            kind,
            text,
        };
        out.extend(
            found
                .into_iter()
                .map(|text| finding(FindingKind::Contradiction, text)),
        );
        out.extend(
            reread
                .older
                .iter()
                .map(|o| finding(FindingKind::Older, format!("{name}: {o}"))),
        );
    }
    out
}

/// One reason [`self_contradicted`] names a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The report's name in the set, as the caller gave it.
    pub report: String,
    pub kind: FindingKind,
    /// The finding as printed, naming the report.
    pub text: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Whose next action a [`Finding`] calls for, which decides the refusal's hint
/// ([`refuse_self_contradicted`]). Typed where the finding is made
/// ([`crate::report::Reread::older`]), never recognised by its words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// The report disagrees with itself or does not read as chard writes it: an edit, a file
    /// assembled elsewhere, or a chard defect in the run that wrote it.
    Contradiction,
    /// A subtree in a report shape this revision does not write and this build does not read:
    /// the report is from another revision, to be read with that revision or measured again.
    /// A claim about the shape alone, not about who wrote the file: an edit that leaves only
    /// such a shape behind reads as this too, and is refused all the same.
    Older,
}

/// [`self_contradicted`]'s contradictions in one report, `reread` its re-run rules' findings,
/// into `out`.
fn contradictions_of(
    name: &str,
    report: &Value,
    reread: &crate::report::Reread,
    out: &mut Vec<String>,
) {
    if report.get("consistency").is_none() {
        out.push(format!("{name} carries no `consistency` block"));
    }
    let consistency = report.get("consistency");
    let listed = consistency
        .and_then(|c| c.get("contradictions"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if listed > 0 {
        out.push(format!(
            "{name} reports {listed} contradiction(s) of its own"
        ));
    }
    // The status word, for what the list alone does not show (`status_disagrees`).
    if let Some(consistency) = consistency {
        out.extend(status_disagrees(name, consistency));
    }

    for c in &reread.contradictions {
        out.push(format!(
            "{name} fails `{}` when the rule is re-run on read ({}: {})",
            c.rule,
            c.property,
            c.claims.join(" vs ")
        ));
    }
    for u in &reread.unreadable {
        out.push(format!("{name}: {u}"));
    }

    // Returned from explicitly rather than defaulted to an empty map, which would read as
    // checked and consistent.
    let Some(observations) = report.get("observations").and_then(Value::as_array) else {
        return;
    };
    let verdicts: BTreeMap<&str, &str> = observations
        .iter()
        .filter_map(|o| Some((o.get("check")?.as_str()?, o.get("verdict")?.as_str()?)))
        .collect();

    let mut disagreements = Vec::new();
    for composite in report
        .get("composites")
        .and_then(Value::as_array)
        .map_or(&[][..], |c| c.as_slice())
    {
        let id = composite.get("id").and_then(Value::as_str).unwrap_or("?");
        for c in composite
            .get("constituents")
            .and_then(Value::as_array)
            .map_or(&[][..], |c| c.as_slice())
        {
            let (Some(check), Some(said)) = (
                c.get("check").and_then(Value::as_str),
                c.get("verdict").and_then(Value::as_str),
            ) else {
                continue;
            };
            if let Some(observed) = verdicts.get(check)
                && *observed != said
            {
                disagreements.push(format!("{id}/{check}: {said} vs {observed}"));
            }
        }
    }
    if !disagreements.is_empty() {
        out.push(format!(
            "{name} states a verdict twice and the copies disagree, so its verdicts are \
             not safe to read: {}",
            disagreements.join(", ")
        ));
    }
}

/// Each gating rule a report wrote under a class this build's table does not give it, or
/// that this build's table lacks ([`crate::report::moved_rules`]), as a note naming the
/// report. `table` and `matrix` carry these beside their other cautions; none is printed
/// when no rule moved.
pub fn moved_rule_notes(reports: &[(String, Value)]) -> Vec<String> {
    reports
        .iter()
        .flat_map(|(name, report)| {
            crate::report::moved_rules(report)
                .into_iter()
                .map(move |m| format!("{}: {name}: {m}", m.heading()))
        })
        .collect()
}

/// The `flag` of each of a report's observations: the flags its own corpus contained, for
/// telling "this corpus never had that flag" apart from "not measured here" (`table`'s `~`).
pub fn flags_of(report: &Value) -> BTreeSet<String> {
    report
        .get("observations")
        .and_then(Value::as_array)
        .map(|obs| {
            obs.iter()
                .filter_map(|o| o.get("flag").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// A file the caller handed `table` or `matrix` that is not a chard measurement report.
pub fn not_a_report(name: &str, why: &str) -> UserError {
    UserError::with_hint(
        format!("{name} is not a chard measurement report: {why}"),
        "pass the JSON that `chard measure -o` wrote",
    )
}

/// The bytes of a file the caller handed `table` or `matrix`, refused from its metadata
/// when no `read` could turn it into a report.
///
/// # Errors
///
/// Errors with [`UserError`] for a name chard gives a report it did not publish, for a
/// directory, a device or a socket, and with the io error under `reading <path>` when the
/// metadata or the bytes could not be read.
pub fn read_report_bytes(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::fs::FileTypeExt as _;
    let name = path.as_os_str().as_encoded_bytes();
    if name.ends_with(crate::report::QUARANTINE_SUFFIX.as_bytes()) {
        return Err(unpublished(
            path,
            "it is the quarantine `measure` writes for a report that contradicts itself",
            "it is evidence for a chard bug report, readable as JSON",
        )
        .into());
    }
    if name.ends_with(crate::report::SET_ASIDE_SUFFIX.as_bytes()) {
        return Err(unpublished(
            path,
            "it is an earlier report a later run set aside and has not replaced",
            "the run that set it aside did not publish",
        )
        .into());
    }
    if crate::report::is_partial_name(name) {
        return Err(unpublished(
            path,
            "it is the temporary file a publication writes before renaming it into place, \
             left by a run that stopped between the two",
            "it may be truncated and was never published",
        )
        .into());
    }
    let reading = || format!("reading {}", path.display());
    let kind = std::fs::metadata(path).with_context(reading)?.file_type();
    if !(kind.is_file() || kind.is_fifo()) {
        return Err(not_a_report(
            &path.display().to_string(),
            &format!("it is {}", crate::error::file_type_name(kind)),
        )
        .into());
    }
    std::fs::read(path).with_context(reading)
}

/// Read and parse every path of a `table` or `matrix` input set, each through
/// [`read_report_bytes`], into the `(name, value)` pairs the renderers judge.
///
/// # Errors
///
/// Those of [`read_report_bytes`], [`not_a_report`] for bytes that are not JSON, and those
/// of [`refuse_unread`]. The `UserError` is the context object, so the parser's own text
/// stays in the chain and `error::classify` still finds the marker above it.
pub fn read_reports(paths: &[std::path::PathBuf]) -> anyhow::Result<Vec<(String, Value)>> {
    paths.iter().map(|p| read_report(p)).collect()
}

/// One path of [`read_reports`], read, parsed and held to [`refuse_unread`]: what `chard
/// digest` reads.
///
/// # Errors
///
/// Those of [`read_reports`].
pub fn read_report(path: &Path) -> anyhow::Result<(String, Value)> {
    use anyhow::Context as _;
    // Bytes rather than a `String`, so a file that is not valid Unicode text is the parser's
    // refusal and the caller's input, where `read_to_string`'s `InvalidData` would read as
    // chard's own.
    let bytes = read_report_bytes(path)?;
    let name = path.display().to_string();
    let value: Value =
        serde_json::from_slice(&bytes).with_context(|| not_a_report(&name, "it is not JSON"))?;
    refuse_unread(&name, &value)?;
    Ok((name, value))
}

/// A report this chard does not read, refused before any rule runs over it: first one
/// whose `chard_schema` is not [`crate::report::SCHEMA_VERSION`] ([`refuse_other_schema`]),
/// then a document with no `observations` list, which is not a report at all (chard's other
/// documents carry the version and no list), then one whose `decoders.language` is not
/// [`crate::predicate::LANGUAGE`], which the schema holds that version to, then one whose
/// `digest` is absent or not an object ([`missing_digest`]).
///
/// # Errors
///
/// A [`UserError`] naming the file's version and the binary's, a document that is not a
/// report, a predicate language this chard does not read, or the missing digest.
pub fn refuse_unread(name: &str, report: &Value) -> Result<(), UserError> {
    refuse_other_schema(name, report)?;
    if !report.get("observations").is_some_and(Value::is_array) {
        return Err(not_a_report(name, "it carries no observations"));
    }
    if let Some(decoders) = report.get("decoders") {
        let language = decoders.get("language");
        if language.and_then(Value::as_str) != Some(crate::predicate::LANGUAGE) {
            let carries = language.map_or_else(|| "no `language`".to_owned(), bounded);
            return Err(UserError::with_hint(
                format!(
                    "{name} carries `chard_schema` \"{}\" and `decoders.language` {carries}, \
                     where a report at that version names \"{}\"",
                    crate::report::SCHEMA_VERSION,
                    crate::predicate::LANGUAGE
                ),
                "pass the JSON that `chard measure -o` wrote with this chard",
            ));
        }
    }
    match report.get("digest") {
        Some(digest) if digest.is_object() => Ok(()),
        Some(other) => Err(UserError::with_hint(
            format!(
                "{name} carries `digest` {}, which is not the object every report chard \
                 publishes leads with",
                bounded(other)
            ),
            "pass the JSON that `chard measure -o` wrote",
        )),
        None => Err(missing_digest(name)),
    }
}

/// `value` as JSON, cut to [`SHOWN`] characters with an ellipsis, so a file's own value in
/// a refusal cannot make the envelope as long as the file.
fn bounded(value: &Value) -> String {
    let text = value.to_string();
    if text.chars().count() <= SHOWN {
        return text;
    }
    let mut cut: String = text.chars().take(SHOWN).collect();
    cut.push_str("...");
    cut
}

/// How much of a file's own value a refusal quotes.
const SHOWN: usize = 64;

/// A report version a published chard wrote and this one does not read.
#[derive(Debug, Clone, Copy)]
pub struct PublishedReportVersion {
    /// The `chard_schema` the release wrote reports at.
    pub version: &'static str,
    /// The release.
    pub release: &'static str,
    /// The release's `run.decoders_sha256`, which every report it wrote carries. A
    /// development build near that release wrote the same version, and where its decoders
    /// differ its reports carry another digest.
    pub decoders_sha256: &'static str,
}

/// Each report version a published chard wrote and this one does not read, so a refusal of a
/// report at one can name the chard that reads it (`published_version_hint`).
pub const PUBLISHED_REPORT_VERSIONS: &[PublishedReportVersion] = &[PublishedReportVersion {
    version: "1",
    release: "0.1.0",
    decoders_sha256: "eb6b19cbc50e65139c2c085658d067b5e504223cb2400378b6c1bc61f650c07f",
}];

/// The hint for a report-shaped file at a version [`PUBLISHED_REPORT_VERSIONS`] names: the
/// release, where the file's `run.decoders_sha256` is the release's; a development build or an
/// edit, where it carries another digest; and neither where it carries none, since nothing in
/// the file then says which chard wrote it. The development build's hint names
/// `run.harness_revision` only where the file carries one.
fn published_version_hint(
    report: &Value,
    at: &Value,
    published: &PublishedReportVersion,
) -> String {
    let release = published.release;
    let run = report.get("run");
    let decoders = run
        .and_then(|run| run.get("decoders_sha256"))
        .and_then(Value::as_str);
    match decoders {
        Some(digest) if digest == published.decoders_sha256 => format!(
            "`chard_schema` {} is the version chard {release} published reports at, and this report's `run.decoders_sha256` is chard {release}'s: read this one with chard {release}",
            bounded(at)
        ),
        Some(_) => {
            let build = if run
                .and_then(|run| run.get("harness_revision"))
                .is_some_and(Value::is_string)
            {
                "the build its `run.harness_revision` names"
            } else {
                "the build that wrote it"
            };
            format!(
                "`chard_schema` {} with a `run.decoders_sha256` that is not chard {release}'s: chard {release} did not write this report as it stands, so a development build did, under rules chard {release} may not apply, or it was edited; read it with {build}",
                bounded(at)
            )
        }
        None => format!(
            "`chard_schema` {} is the version chard {release} and the development builds around it wrote reports at",
            bounded(at)
        ),
    }
}

/// The `chard_schema` of each document this chard writes that is not a report: a matrix,
/// `detect`'s output, the probe listing and the error envelope.
const OTHER_DOCUMENT_VERSIONS: [&str; 4] = [
    crate::matrix::MATRIX_SCHEMA_VERSION,
    crate::detect::SCHEMA_VERSION,
    crate::probe::LISTING_SCHEMA_VERSION,
    crate::error::SCHEMA_VERSION,
];

/// The version half of [`refuse_unread`]: `report`'s `chard_schema` absent, not a string,
/// or a string other than [`crate::report::SCHEMA_VERSION`] (`"1 "` among them) is refused,
/// naming what the file carries as JSON, so a number reads apart from a string.
///
/// # Errors
///
/// A [`UserError`] for any `chard_schema` but this binary's, except another document's
/// version on a file that is not report-shaped.
pub fn refuse_other_schema(name: &str, report: &Value) -> Result<(), UserError> {
    let reads = crate::report::SCHEMA_VERSION;
    let report_shaped = report.get("observations").is_some_and(Value::is_array);
    let mut hint = "pass the JSON that `chard measure -o` wrote with this chard".to_owned();
    let carries = match report.get("chard_schema") {
        Some(Value::String(version)) if version == reads => return Ok(()),
        Some(Value::String(version))
            if !report_shaped && OTHER_DOCUMENT_VERSIONS.contains(&version.as_str()) =>
        {
            return Ok(());
        }
        Some(other) => {
            if let Some(published) = other.as_str().filter(|_| report_shaped).and_then(|v| {
                PUBLISHED_REPORT_VERSIONS
                    .iter()
                    .find(|published| published.version == v)
            }) {
                hint = published_version_hint(report, other, published);
            }
            format!("it carries `chard_schema` {}", bounded(other))
        }
        None => "it carries no `chard_schema`".to_owned(),
    };
    Err(UserError::with_hint(
        format!(
            "{name} is not a report this chard reads: {carries}, and this chard reads \
             `chard_schema` \"{reads}\" alone"
        ),
        hint,
    ))
}

/// A report with no `digest`, refused by [`refuse_unread`] and by `chard digest`.
#[must_use]
pub fn missing_digest(name: &str) -> UserError {
    UserError::with_hint(
        format!("{name} carries no `digest`: every report chard publishes leads with one"),
        "pass the JSON that `chard measure -o` wrote",
    )
}

/// A file `table` or `matrix` refuses because chard did not publish it as a measurement.
fn unpublished(path: &Path, why: &str, hint: &str) -> UserError {
    UserError::with_hint(
        format!(
            "{} is not a published chard measurement report: {why}",
            path.display()
        ),
        hint,
    )
}

/// What is wrong with a `consistency` block's `status` word, if it carries one and anything
/// is: no `contradictions` list beside it, no rule in `rules_applied`, or a word other than
/// the one [`ConsistencyStatus`] derives from the list. A block with no word (a report
/// written before it existed) is left to the list.
fn status_disagrees(name: &str, consistency: &Value) -> Option<String> {
    let status = consistency.get("status")?;
    let Some(list) = consistency.get("contradictions").and_then(Value::as_array) else {
        return Some(format!(
            "{name} carries `consistency.status` {status} and no `contradictions` list"
        ));
    };
    let rules = consistency
        .get("rules_applied")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if rules == 0 {
        return Some(format!(
            "{name} carries `consistency.status` {status} and no rule in `rules_applied`"
        ));
    }
    let derived = if list.is_empty() {
        ConsistencyStatus::Consistent
    } else {
        ConsistencyStatus::Contradicted
    };
    if status.as_str() == Some(derived.as_str()) {
        return None;
    }
    let beside = if list.is_empty() {
        "an empty `contradictions` list".to_owned()
    } else {
        format!("{} contradiction(s)", list.len())
    };
    Some(format!(
        "{name} carries `consistency.status` {status} beside {beside}"
    ))
}

/// Refuse a set of reports any one of which [`self_contradicted`] names.
///
/// # Errors
///
/// Errors with [`UserError`] naming each finding when there is one.
pub fn refuse_self_contradicted(reports: &[(String, Value)]) -> Result<(), UserError> {
    let found = self_contradicted(reports);
    if found.is_empty() {
        return Ok(());
    }
    Err(UserError::with_hint(
        format!(
            "refusing a set holding a report not safe to read as a measurement:\n  {}",
            found
                .iter()
                .map(|f| f.text.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        ),
        refusal_hint(&found),
    ))
}

/// What to do about the reports `found` names, opening with the action they call for
/// ([`refuse_self_contradicted`]).
fn refusal_hint(found: &[Finding]) -> String {
    const CONTRADICTION: &str = "leave out of the set a report that contradicts itself";
    // In the order the set named them; a report is older when every finding naming it is.
    let mut named: Vec<&str> = Vec::new();
    for f in found {
        if !named.contains(&f.report.as_str()) {
            named.push(&f.report);
        }
    }
    let older: Vec<&str> = named
        .iter()
        .copied()
        .filter(|name| {
            found
                .iter()
                .filter(|f| f.report == *name)
                .all(|f| is_older(f.kind))
        })
        .collect();
    if named.is_empty() || older.len() < named.len() {
        match older.as_slice() {
            [] => CONTRADICTION.to_owned(),
            [one] => format!(
                "{CONTRADICTION}. {one} is in a shape this revision does not write, which \
                 this build cannot hold to its rules: {}",
                remedies(1)
            ),
            many => format!(
                "{CONTRADICTION}. {} are in shapes this revision does not write, which this \
                 build cannot hold to its rules: {}",
                many.join(", "),
                remedies(many.len())
            ),
        }
    } else {
        let which = if named.len() == 1 {
            "the report named above"
        } else {
            "every report named above"
        };
        format!(
            "{which} is in a shape this revision does not write, which this build cannot \
             hold to its rules: {}",
            remedies(named.len())
        )
    }
}

/// Whether a finding of `kind` leaves its report older rather than contradicting, matched
/// whole so that a kind added later is placed here rather than defaulted.
fn is_older(kind: FindingKind) -> bool {
    match kind {
        FindingKind::Older => true,
        FindingKind::Contradiction => false,
    }
}

/// The two ways on for `reports` older reports.
fn remedies(reports: usize) -> String {
    let (it, report) = if reports > 1 {
        ("each", "reports")
    } else {
        ("it", "report")
    };
    format!(
        "read {it} with the chard its `run.harness_revision` names, or run `chard measure` \
         again with this build and render the new {report}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_without_a_revision_keys_on_no_source() {
        let bare = revision_key(&serde_json::json!({"run": {}}));
        assert!(!bare.contains('['), "{bare}");
        assert_eq!(
            revision_key(&serde_json::json!({"run": {"harness_revision_source": "asserted"}})),
            bare
        );
    }

    #[test]
    fn a_report_at_a_published_version_names_the_chard_its_digest_names() {
        use serde_json::json;
        let mut fed = 0;
        for published in PUBLISHED_REPORT_VERSIONS {
            let (version, release) = (published.version, published.release);
            assert_ne!(version, crate::report::SCHEMA_VERSION);
            assert_eq!(published.decoders_sha256.len(), 64);
            let other = "ab".repeat(32);
            let named = format!("read this one with chard {release}");
            let built = format!("chard {release} did not write this report as it stands");
            let unnamed = "carries no `run.decoders_sha256` to say which".to_owned();
            for (run, _, _) in [
                (
                    Some(json!({"decoders_sha256": published.decoders_sha256})),
                    &named,
                    false,
                ),
                (Some(json!({"decoders_sha256": other})), &built, false),
                (
                    Some(json!({"decoders_sha256": other, "harness_revision": null})),
                    &built,
                    false,
                ),
                (
                    Some(json!({"decoders_sha256": other, "harness_revision": "0123abc"})),
                    &built,
                    true,
                ),
                (Some(json!({"decoders_sha256": null})), &unnamed, false),
                (Some(json!({"decoders_sha256": 7})), &unnamed, false),
                (Some(json!({})), &unnamed, false),
                (None, &unnamed, false),
            ] {
                for with_digest in [true, false] {
                    let mut report = json!({"chard_schema": version, "observations": []});
                    if let Some(run) = &run {
                        report["run"] = run.clone();
                    }
                    if with_digest {
                        report["digest"] = json!({});
                    }
                    let refused = refuse_unread("r.json", &report).expect_err("refused");
                    fed += 1;
                    assert!(
                        refused
                            .message
                            .contains(&format!("carries `chard_schema` \"{version}\",")),
                        "{}",
                        refused.message
                    );
                    assert!(refused.hint.is_some(), "a refusal carries a hint");
                }
            }
        }
        assert_eq!(fed, 16 * PUBLISHED_REPORT_VERSIONS.len());
    }

    #[test]
    fn a_report_in_another_language_is_refused_and_other_documents_are_named() {
        use serde_json::json;
        // Another language, none, or a `decoders` with no `language` is refused; a report
        // with no `decoders` carries no predicate to misread.
        let current = |decoders: Option<Value>| {
            let mut report = json!({"chard_schema": crate::report::SCHEMA_VERSION,
                                    "observations": [], "digest": {}});
            if let Some(decoders) = decoders {
                report["decoders"] = decoders;
            }
            refuse_unread("r.json", &report)
        };
        current(None).expect("no decoders");
        current(Some(
            json!({"language": crate::predicate::LANGUAGE, "predicates": []}),
        ))
        .expect("this chard's language");
        for decoders in [
            json!({"language": "chard-predicate/1", "predicates": []}),
            json!({"language": 2, "predicates": []}),
            json!({"predicates": []}),
            json!(null),
        ] {
            let refused = current(Some(decoders.clone())).expect_err("another language");
            assert!(
                refused.message.contains("`decoders.language`"),
                "{decoders}: {}",
                refused.message
            );
        }
        // The release is named for a report's shape alone: the same version on a document
        // with no observations list, or as a number, names none.
        let unshaped = refuse_unread("r.json", &json!({"chard_schema": 1, "observations": []}))
            .expect_err("a number is refused");
        assert!(
            !unshaped
                .hint
                .expect("a refusal carries a hint")
                .contains("0.1.0")
        );
        // Each of chard's other documents at the version this chard writes for it is named
        // as not a report, not refused for its version.
        for version in OTHER_DOCUMENT_VERSIONS {
            let said = refuse_unread("m.json", &json!({"chard_schema": version, "cells": []}))
                .expect_err("not a report")
                .to_string();
            assert!(
                said.contains("carries no observations"),
                "{version}: {said}"
            );
            assert!(!said.contains("`chard_schema`"), "{version}: {said}");
        }
        // A version neither a report nor another document carries is refused for it, list
        // or none.
        for report in [
            json!({"chard_schema": "99", "observations": []}),
            json!({"chard_schema": "99"}),
        ] {
            let said = refuse_unread("r.json", &report)
                .expect_err("refused")
                .to_string();
            assert!(said.contains("carries `chard_schema` \"99\","), "{said}");
        }
    }

    #[test]
    fn a_report_of_another_chard_schema_or_without_a_digest_is_not_read() {
        use serde_json::json;
        let reads = format!("`chard_schema` \"{}\"", crate::report::SCHEMA_VERSION);
        let honest = json!({"chard_schema": crate::report::SCHEMA_VERSION,
                            "observations": [], "digest": {}});
        assert!(refuse_unread("r.json", &honest).is_ok(), "the control");
        let mut fed = 0;
        for (version, carries) in [
            (Some(json!("99")), "carries `chard_schema` \"99\","),
            (Some(json!("1 ")), "carries `chard_schema` \"1 \","),
            (Some(json!(1)), "carries `chard_schema` 1,"),
            (Some(json!(null)), "carries `chard_schema` null,"),
            (
                Some(json!({"v": "1"})),
                "carries `chard_schema` {\"v\":\"1\"},",
            ),
            (None, "carries no `chard_schema`,"),
        ] {
            for with_digest in [true, false] {
                let mut report = json!({});
                if let Some(v) = &version {
                    report["chard_schema"] = v.clone();
                }
                if with_digest {
                    report["digest"] = json!({});
                }
                let said = refuse_unread("r.json", &report)
                    .expect_err("another version is refused")
                    .to_string();
                fed += 1;
                assert!(
                    said.contains("r.json") && said.contains(carries) && said.contains(&reads),
                    "{version:?} digest {with_digest}: {said}"
                );
                assert!(!said.contains("`digest`"), "the version first: {said}");
            }
        }
        assert_eq!(fed, 12, "six versions, with and without a digest");
        let said = refuse_unread(
            "r.json",
            &json!({"chard_schema": crate::report::SCHEMA_VERSION, "observations": []}),
        )
        .expect_err("a report with no digest is refused")
        .to_string();
        assert!(said.contains("r.json carries no `digest`"), "{said}");
        for (digest, shown) in [
            (json!(null), "null"),
            (json!("x"), "\"x\""),
            (json!([]), "[]"),
        ] {
            let said = refuse_unread(
                "r.json",
                &json!({"chard_schema": crate::report::SCHEMA_VERSION, "observations": [],
                        "digest": digest}),
            )
            .expect_err("a digest that is not an object is refused")
            .to_string();
            assert!(
                said.contains(&format!(
                    "carries `digest` {shown}, which is not the object"
                )),
                "{said}"
            );
        }
        // A matrix's shape: the version and no `observations` list, named as not a report.
        let said = refuse_unread(
            "m.json",
            &json!({"chard_schema": crate::report::SCHEMA_VERSION, "cells": []}),
        )
        .expect_err("a matrix is not a report")
        .to_string();
        assert!(
            said.contains("m.json is not a chard measurement report"),
            "{said}"
        );
        assert!(!said.contains("`digest`"), "{said}");
        // A long value is cut in the message.
        let long = "9".repeat(500);
        let said = refuse_unread("r.json", &json!({"chard_schema": long}))
            .expect_err("a long version")
            .to_string();
        assert!(said.len() < 300 && said.contains("..."), "{said}");
        let said = refuse_unread(
            "r.json",
            &json!({"chard_schema": crate::report::SCHEMA_VERSION, "observations": [],
                    "digest": "9".repeat(500)}),
        )
        .expect_err("a long digest")
        .to_string();
        assert!(said.len() < 300 && said.contains("..."), "{said}");
        // Neither refusal is made over anything but the report itself: a non-object is a
        // report without a version.
        let said = refuse_unread("r.json", &json!([]))
            .expect_err("an array")
            .to_string();
        assert!(said.contains("carries no `chard_schema`"), "{said}");
    }

    #[test]
    fn a_report_path_that_cannot_hold_a_report_is_refused_from_its_metadata() {
        let dir = std::env::temp_dir().join(format!("chard-notreport-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let err = read_report_bytes(&dir).expect_err("a directory is not a report");
        let user = err
            .downcast_ref::<UserError>()
            .unwrap_or_else(|| panic!("classified as the caller's: {err:#}"));
        assert!(
            user.message.contains("it is a directory") && user.message.contains("chard-notreport"),
            "{}",
            user.message
        );
        let missing = read_report_bytes(&dir.join("absent.json")).expect_err("no such file");
        assert!(
            missing
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound),
            "the errno is the root for the envelope to classify: {missing:#}"
        );
        crate::error::best_effort(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn a_truncated_list_says_so_and_a_complete_one_does_not() {
        let names = |n: usize| -> Vec<String> { (0..n).map(|i| format!("r{i}")).collect() };

        assert_eq!(describe_list(&names(2)), "r0, r1");
        assert_eq!(
            describe_list(&names(6)),
            "r0, r1, r2, r3, r4, r5",
            "exactly at the limit is not truncation"
        );
        assert_eq!(
            describe_list(&names(8)),
            "r0, r1, r2, r3, r4, r5, +2 more",
            "one past it names how many were left out"
        );
        assert_eq!(describe_list(&[]), "");

        let groups = |n: usize| {
            let mut g: BTreeMap<String, Vec<String>> = BTreeMap::new();
            g.insert("v".to_owned(), names(n));
            g
        };
        assert_eq!(describe(&groups(3)), "v (r0, r1, r2)");
        assert_eq!(describe(&groups(5)), "v (r0, r1, r2, +2 more)");
    }

    /// The `environment` the kernel rule reads on read, as a run on the default writes it.
    fn environment() -> Value {
        json!({
            "kernel": {"is_host_kernel": false, "ownership": "unsettled"},
            "execution": {"mode": "host", "mode_evidence": {"basis": "assumed-host"}},
        })
    }

    #[test]
    fn only_a_report_that_contradicts_itself_is_named() {
        let with = |contradictions: Value| {
            serde_json::json!({
                "consistency": {"contradictions": contradictions},
                "environment": environment(),
                "observations": [],
                "coverage": {"checks_expected": 0, "checks_valid": 0, "checks_attempted": 0, "corpus_checks_total": 0,
                             "verdict_counts": {}, "all_verdicts_published": true,
                             "withholding": {"published": 0,
                                             "earned_limitations": {"count": 0, "no_named_cause": 0},
                                             "instrument_withholdings": {"count": 0, "no_named_cause": 0}}},
            })
        };

        let clean = with(serde_json::json!([]));
        let dirty = with(serde_json::json!([{"rule": "r", "property": "p"}]));

        // The status word: agreeing with the list adds nothing, disagreeing is named once.
        let worded = |contradictions: Value, status: &str| {
            let mut r = with(contradictions);
            r["consistency"]["status"] = serde_json::json!(status);
            r["consistency"]["rules_applied"] = json!(["r"]);
            r
        };
        assert!(
            self_contradicted(&[("clean".to_owned(), worded(json!([]), "consistent"))]).is_empty(),
            "a consistent report with no contradiction is not self-contradicted"
        );
        let quarantined = worded(json!([{"rule": "r", "property": "p"}]), "contradicted");
        assert_eq!(self_contradicted(&[("q".to_owned(), quarantined)]).len(), 1);
        for (status, list) in [
            ("contradicted", json!([])),
            ("consistent", json!([{"rule": "r", "property": "p"}])),
            ("unchecked", json!([])),
            ("unchecked", json!([{"rule": "r", "property": "p"}])),
        ] {
            let found = self_contradicted(&[("r".to_owned(), worded(list.clone(), status))]);
            assert!(
                found.iter().any(|f| f.text.contains("consistency.status")),
                "{status} beside {list}: {found:?}"
            );
        }
        // A worded block missing the list, or naming no rule, is a shape `measure` never
        // writes; neither reads as clean.
        let mut no_list = worded(json!([]), "consistent");
        no_list["consistency"]
            .as_object_mut()
            .expect("an object")
            .remove("contradictions");
        let mut no_rule = worded(json!([]), "consistent");
        no_rule["consistency"]["rules_applied"] = json!([]);
        for (what, report) in [("no list", no_list), ("no rule", no_rule)] {
            let found = self_contradicted(&[("r".to_owned(), report)]);
            assert!(
                found.iter().any(|f| f.text.contains("consistency.status")),
                "{what}: {found:?}"
            );
        }

        assert!(
            self_contradicted(&[("clean".to_owned(), clean)]).is_empty(),
            "an empty contradictions list is the normal state of every published report"
        );
        let found = self_contradicted(&[("dirty".to_owned(), dirty)]);
        assert_eq!(found.len(), 1);
        assert!(
            found[0].text.contains("1 contradiction"),
            "the count is what makes it actionable: {}",
            found[0]
        );
    }

    #[test]
    fn a_report_whose_two_copies_of_a_verdict_disagree_is_named() {
        let honest = json!({
            "environment": environment(),
            "observations": [{"check": "pie", "flag": "-pie", "verdict": "off",
                              "observes": "protection"}],
            "composites": [{"id": "fhardened-effective",
                            "constituents": [{"check": "pie", "verdict": "off"}]}],
            "consistency": {"rules_applied": [], "fields_checked": []},
            "coverage": {"checks_expected": 1, "checks_valid": 0, "checks_attempted": 1, "corpus_checks_total": 1,
                         "verdict_counts": {"off": 1}, "all_verdicts_published": true,
                         "withholding": {"published": 1,
                                         "earned_limitations": {"count": 0, "no_named_cause": 0},
                                         "instrument_withholdings": {"count": 0, "no_named_cause": 0}}},
        });
        assert!(
            self_contradicted(&[("r.json".to_owned(), honest.clone())]).is_empty(),
            "a report that agrees with itself must render without a caveat"
        );

        let mut tampered = honest;
        tampered["observations"][0]["verdict"] = json!("on");
        let found = self_contradicted(&[("r.json".to_owned(), tampered)]);
        // The tally is recounted on read too, and the flipped verdict does not agree with
        // `coverage.verdict_counts` either.
        assert_eq!(
            found.len(),
            2,
            "the disagreement must be reported: {found:?}"
        );
        assert!(
            found[0]
                .text
                .contains("coverage-disagrees-with-observations")
                && found[0].text.contains("\"off\": 1")
                && found[0].text.contains("\"on\": 1"),
            "the recount names both tallies: {}",
            found[0]
        );
        assert!(
            found[1].text.contains("pie") && found[1].text.contains("off vs on"),
            "the caveat has to name which verdict and both readings: {}",
            found[1]
        );

        // A report with no `consistency` block cannot say whether it checked itself.
        let stripped = json!({
            "environment": environment(),
            "observations": [], "composites": [],
            "coverage": {"checks_expected": 0, "checks_valid": 0, "checks_attempted": 0, "corpus_checks_total": 0,
                         "verdict_counts": {}, "all_verdicts_published": true,
                         "withholding": {"published": 0,
                                         "earned_limitations": {"count": 0, "no_named_cause": 0},
                                         "instrument_withholdings": {"count": 0, "no_named_cause": 0}}},
        });
        assert_eq!(
            self_contradicted(&[("r.json".to_owned(), stripped)]).len(),
            1
        );
    }

    #[test]
    fn a_derived_field_edited_alone_is_named_by_its_rule() {
        let honest = json!({
            "environment": environment(),
            "observations": [{"check": "pie", "flag": "-pie", "verdict": "off",
                              "defects": ["address-layout-disclosure"],
                              "observes": "protection", "polarity": "harden"}],
            "defect_coverage": {"address-layout-disclosure": {
                "status": "not-mitigated", "from_checks": ["pie"],
                "verdict_counts": {"off": 1}}},
            "coverage": {"checks_expected": 1, "checks_valid": 0, "checks_attempted": 1, "corpus_checks_total": 1,
                         "verdict_counts": {"off": 1}, "all_verdicts_published": true,
                         "withholding": {"published": 1,
                                         "earned_limitations": {"count": 0, "no_named_cause": 0},
                                         "instrument_withholdings": {"count": 0, "no_named_cause": 0}}},
            "consistency": {"contradictions": []},
        });
        assert!(
            self_contradicted(&[("r.json".to_owned(), honest.clone())]).is_empty(),
            "the unedited report agrees with itself"
        );
        let mut edited = honest;
        edited["defect_coverage"]["address-layout-disclosure"]["status"] = json!("mitigated");
        let found = self_contradicted(&[("r.json".to_owned(), edited)]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0]
                .text
                .contains("defect-status-disagrees-with-bearing-checks")
                && found[0].text.contains("address-layout-disclosure"),
            "the finding names the rule and the defect: {}",
            found[0]
        );
    }
    use serde_json::json;

    fn report(corpus: &str, revision: Option<&str>) -> Value {
        execution_report(corpus, revision, "vm")
    }

    fn execution_report(corpus: &str, revision: Option<&str>, mode: &str) -> Value {
        attested_report(corpus, revision, mode, Some("attested"))
    }

    /// `status: None` omits the field entirely, which is how a report written before the
    /// field existed looks.
    fn attested_report(
        corpus: &str,
        revision: Option<&str>,
        mode: &str,
        status: Option<&str>,
    ) -> Value {
        let mut run = serde_json::Map::new();
        run.insert("probe_corpus_sha256".to_owned(), json!(corpus));
        run.insert("decoders_sha256".to_owned(), json!("d0"));
        if let Some(r) = revision {
            run.insert("harness_revision".to_owned(), json!(r));
        }
        let mut execution = serde_json::Map::new();
        execution.insert("mode".to_owned(), json!(mode));
        if let Some(s) = status {
            execution.insert("image_attestation".to_owned(), json!({"status": s}));
        }
        json!({
            "run": run,
            "environment": {"execution": execution},
            // The keys `measure` actually emits, so a caution that fires here fires on a
            // real report too.
            "toolchain": {
                "id": "gcc-16.1.1-glibc2.43-fedora44",
                "kind": "gcc",
                "version": "16.1.1",
                "driver": "/usr/bin/cc",
            },
        })
    }

    #[test]
    fn a_container_row_is_not_joinable_with_a_vm_row() {
        let mixed = Identity::of(&[
            (
                "vm.json".to_owned(),
                execution_report("abc", Some("1111"), "vm"),
            ),
            (
                "container.json".to_owned(),
                execution_report("abc", Some("1111"), "container"),
            ),
        ]);
        assert!(!mixed.is_joinable());
        let why = mixed.conflicts().join(" ");
        assert!(why.contains("execution modes differ"), "{why}");
        assert!(why.contains("not their distribution's"), "{why}");

        // One mode throughout is joinable, container or otherwise: the hazard is the
        // mixture, not the container.
        for mode in ["vm", "container", "host"] {
            let same = Identity::of(&[
                (
                    "a.json".to_owned(),
                    execution_report("abc", Some("1"), mode),
                ),
                (
                    "b.json".to_owned(),
                    execution_report("abc", Some("1"), mode),
                ),
            ]);
            assert!(same.is_joinable(), "{mode} against itself must join");
        }
    }

    #[test]
    fn reports_from_two_corpora_are_not_joinable() {
        let same = [
            ("a.json".to_owned(), report("abc", Some("1111"))),
            ("b.json".to_owned(), report("abc", Some("1111"))),
        ];
        assert!(Identity::of(&same).is_joinable());
        assert!(
            Identity::of(&same).conflicts().is_empty(),
            "two reports of one identity conflict on nothing"
        );

        let mixed = [
            ("old.json".to_owned(), report("abc", Some("1111"))),
            ("new.json".to_owned(), report("def", Some("1111"))),
        ];
        let id = Identity::of(&mixed);
        assert!(!id.is_joinable());
        let why = id.conflicts().join(" ");
        assert!(why.contains("corpora differ"), "{why}");
        assert!(why.contains("abc") && why.contains("def"), "{why}");
        assert!(
            why.contains("old.json") && why.contains("new.json"),
            "{why}"
        );
    }

    #[test]
    fn a_corpus_refusal_names_whether_the_decoders_moved() {
        let with_decoders = |corpus: &str, decoders: Option<&str>| {
            let mut r = report(corpus, Some("1111"));
            let run = r["run"].as_object_mut().expect("run is an object");
            match decoders {
                Some(d) => run.insert("decoders_sha256".to_owned(), json!(d)),
                None => run.remove("decoders_sha256"),
            };
            r
        };
        let refusal = |a: Option<&str>, b: Option<&str>| {
            Identity::of(&[
                ("old.json".to_owned(), with_decoders("abc", a)),
                ("new.json".to_owned(), with_decoders("def", b)),
            ])
            .conflicts()
            .join(" ")
        };
        let same = refusal(Some("d1"), Some("d1"));
        assert!(same.contains("the decoders did not move"), "{same}");
        assert!(same.contains("d1"), "{same}");
        let moved = refusal(Some("d1"), Some("d2"));
        assert!(moved.contains("the decoders moved too"), "{moved}");
        assert!(
            moved.contains("d1 (old.json)") && moved.contains("d2 (new.json)"),
            "{moved}"
        );
        let unstated = refusal(None, Some("d2"));
        assert!(unstated.contains("is not stated"), "{unstated}");
        assert!(unstated.contains("(absent) (old.json)"), "{unstated}");
        // One corpus is joinable whatever the field says, since the corpus carries it.
        assert!(
            Identity::of(&[
                ("a.json".to_owned(), with_decoders("abc", Some("d1"))),
                ("b.json".to_owned(), with_decoders("abc", Some("d1"))),
            ])
            .is_joinable()
        );
    }

    #[test]
    fn reports_from_two_harness_revisions_are_not_joinable() {
        let id = Identity::of(&[
            ("a.json".to_owned(), report("abc", Some("1111"))),
            ("b.json".to_owned(), report("abc", Some("2222"))),
        ]);
        assert!(!id.is_joinable());
        assert!(id.conflicts().join(" ").contains("revisions differ"));
    }

    #[test]
    fn an_asserted_revision_joins_only_reports_asserted_alike() {
        let at = |source: Option<&str>, rustflags: Option<&str>| {
            let mut r = report("abc", Some("1111"));
            if let Some(s) = source {
                r["run"]["harness_revision_source"] = json!(s);
            }
            if let Some(d) = rustflags {
                r["run"]["harness_rustflags_sha256"] = json!(d);
            }
            r
        };
        let joins = |a: Value, b: Value| {
            Identity::of(&[("a.json".to_owned(), a), ("b.json".to_owned(), b)]).is_joinable()
        };
        let flags = "ab".repeat(32);
        assert!(joins(at(Some("git"), None), at(Some("archive"), None)));
        assert!(joins(at(Some("git"), None), at(Some("cargo-vcs"), None)));
        assert!(joins(
            at(Some("asserted"), None),
            at(Some("asserted"), None)
        ));
        assert!(!joins(at(Some("git"), None), at(Some("asserted"), None)));
        assert!(!joins(at(Some("git"), None), at(None, None)));
        assert!(!joins(at(Some("git"), None), at(Some("git"), Some(&flags))));
        assert!(!joins(
            at(Some("git"), Some(&flags)),
            at(Some("git"), Some(&"cd".repeat(32)))
        ));
        assert!(joins(
            at(Some("git"), Some(&flags)),
            at(Some("archive"), Some(&flags))
        ));
        let mixed = Identity::of(&[
            ("clone.json".to_owned(), at(Some("git"), None)),
            ("fleet.json".to_owned(), at(Some("asserted"), None)),
        ]);
        let refusal = mixed.conflicts().join(" ");
        let cautions = mixed.cautions().join(" ");
        assert!(
            cautions.contains("1 report(s) name a revision asserted")
                && cautions.contains("fleet.json"),
            "{cautions}"
        );
        let built = Identity::of(&[("flags.json".to_owned(), at(Some("git"), Some(&flags)))]);
        assert!(
            built.cautions().join(" ").contains("built under rustflags"),
            "{:?}",
            built.cautions()
        );
        assert!(
            refusal.contains("1111 (clone.json)")
                && refusal.contains("1111 [asserted] (fleet.json)"),
            "{refusal}"
        );
    }

    #[test]
    fn only_a_clean_revision_read_from_the_tree_is_a_builds_own_key() {
        use crate::report::{HARNESS_REVISION, HARNESS_REVISION_SOURCE, HARNESS_RUSTFLAGS_SHA256};
        assert_eq!(
            this_build_key(),
            build_key(
                HARNESS_REVISION,
                HARNESS_REVISION_SOURCE,
                HARNESS_RUSTFLAGS_SHA256
            )
        );
        let flags = "ab".repeat(32);
        assert_eq!(
            build_key(Some("1111"), Some("git"), None).as_deref(),
            Some("1111")
        );
        assert_eq!(
            build_key(Some("1111"), Some("archive"), Some(&flags)),
            Some(format!("1111 [rustflags {flags}]"))
        );
        assert_eq!(build_key(Some("1111-dirty"), Some("git"), None), None);
        assert_eq!(
            build_key(Some("1111-dirty"), Some("git"), Some(&flags)),
            None
        );
        assert_eq!(build_key(Some("1111"), Some("asserted"), None), None);
        assert_eq!(build_key(Some("1111"), None, None), None);
        assert_eq!(build_key(None, Some("git"), None), None);
    }

    #[test]
    fn a_missing_revision_is_unknown_rather_than_permission() {
        let id = Identity::of(&[
            ("known.json".to_owned(), report("abc", Some("1111"))),
            ("silent.json".to_owned(), report("abc", None)),
        ]);
        assert!(
            !id.is_joinable(),
            "an absent revision must not be treated as matching"
        );
        assert!(id.conflicts().join(" ").contains("(absent)"));
    }

    #[test]
    fn a_dirty_revision_is_named_without_blocking_the_render() {
        let id = Identity::of(&[
            ("a.json".to_owned(), report("abc", Some("1111-dirty"))),
            ("b.json".to_owned(), report("abc", Some("1111-dirty"))),
        ]);
        assert!(
            id.is_joinable(),
            "dirty alone does not make reports unjoinable"
        );
        let caution = id.cautions().join(" ");
        assert!(caution.contains("no commit"), "{caution}");
        assert!(
            caution.contains("a.json") && caution.contains("b.json"),
            "{caution}"
        );
        assert!(
            Identity::of(&[("c.json".to_owned(), report("abc", Some("1111")))])
                .cautions()
                .is_empty(),
            "a single report carries no caution"
        );
    }

    #[test]
    fn an_unattested_image_is_cautioned_and_still_joinable() {
        let id = Identity::of(&[
            (
                "a.json".to_owned(),
                attested_report("abc", Some("1111"), "vm", Some("unattested")),
            ),
            (
                "b.json".to_owned(),
                attested_report("abc", Some("1111"), "vm", Some("attested")),
            ),
        ]);
        assert!(id.is_joinable(), "attestation status is not a join key");
        let caution = id.cautions().join(" ");
        assert!(caution.contains("operator-supplied label"), "{caution}");
        assert!(caution.contains("a.json"), "{caution}");
        assert!(
            !caution.contains("b.json"),
            "an attested report must not be named: {caution}"
        );
        assert!(caution.contains("1 of 2"), "{caution}");
    }

    #[test]
    fn an_absent_attestation_reads_as_unattested_rather_than_as_nothing_to_say() {
        let id = Identity::of(&[(
            "old.json".to_owned(),
            attested_report("abc", Some("1111"), "vm", None),
        )]);
        assert_eq!(id.unattested, vec!["old.json".to_owned()]);
        assert!(
            id.cautions().join(" ").contains("operator-supplied label"),
            "silence about the image must not read as an established image"
        );
    }

    /// A report of the shape `measure` emits draws no caution about its toolchain.
    ///
    /// Asserted on input the tool can produce (`attested_report` writes the keys `measure`
    /// emits), so a toolchain caution must read a field a report carries: one reading the
    /// absent `toolchain.provenance.status` would fire on every stock compiler's render.
    #[test]
    fn a_report_measure_could_have_written_draws_no_toolchain_caution() {
        let id = Identity::of(&[(
            "real.json".to_owned(),
            attested_report("abc", Some("1111"), "host", Some("not-applicable")),
        )]);
        let caution = id.cautions().join(" ");
        assert!(
            caution.is_empty(),
            "a clean report must render without a caution: {caution}"
        );
    }

    /// `host` mode has no image to attest to; a caution there would train a reader to skip it.
    #[test]
    fn measuring_the_running_system_is_not_cautioned() {
        let id = Identity::of(&[(
            "host.json".to_owned(),
            attested_report("abc", Some("1111"), "host", Some("not-applicable")),
        )]);
        assert!(
            id.unattested.is_empty(),
            "a host report whose attestation is not-applicable is not unattested: {:?}",
            id.unattested
        );
        assert!(
            id.cautions().is_empty(),
            "a host report whose attestation is not-applicable carries no caution: {:?}",
            id.cautions()
        );
    }
}
