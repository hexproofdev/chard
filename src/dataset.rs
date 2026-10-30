// SPDX-License-Identifier: BSD-3-Clause

//! Whether a set of reports may be compared with each other at all.
//!
//! Every report identifies the dataset it belongs to by the pair
//! (`run.probe_corpus_sha256`, `run.harness_revision`), the revision read with the source that
//! named it and the rustflags the harness was built under ([`revision_key`]). The corpus hash
//! covers the declared corpus (probe sources, control flags, gates) and the decoders that
//! read it (`run.decoders_sha256`, folded in: the predicates and the decoder source). The
//! revision covers the rest of the code that interprets it, which the hash cannot reach:
//! which code decoder a check names, the triple, the gating. A refusal over differing
//! corpora says whether the decoders moved.
//!
//! Both fields are recorded on every report, and a reader that ignored them would be the
//! failure this module exists to prevent: the identity is available, the constraint is
//! known, and without a check the only thing enforcing it would be an operator remembering
//! it. A `table` that rendered an archived report beside a current one and said nothing
//! would be saying nothing because saying something was nobody's job.
//!
//! ## Why absence is not permission
//!
//! A report that carries no revision at all is not evidence that it matches the others.
//! It is a report built from a tree none of `build.rs`'s sources names a commit for (no git,
//! no filled `REVISION`, no crate archive's `.cargo_vcs_info.json`), so it is *unknown*, and
//! mixing an unknown with a known is exactly as unjoinable as mixing two knowns. Absence is
//! tracked as its own value rather than skipped.
//!
//! ## What is deliberately not cautioned
//!
//! Whether the compiler measured is the one its distribution ships is not checked. A
//! wrapper on `PATH` can make a published comparison wrong: a Wolfi row that reported
//! `cflags: []` with fortify 3, CET and full RELRO had all of them injected by
//! `exec /usr/bin/gcc -specs openssf.spec` from a script the sweep's own `PATH` reached
//! first, so every column in that row was a statement about a spec file, presented as the
//! distribution's compiler defaults.
//!
//! A caution keyed on what the package manager says owns the driver would fire on every
//! report, including a stock distribution gcc. A warning that cannot be satisfied is worse
//! than none: it trains a reader to skip the line where the attestation and dirty-tree
//! cautions also appear.
//!
//! Nothing here can be re-derived from what a report carries. `configure_args` is the
//! real driver's, so a wrapper is invisible to it, and matching it against a table of known
//! distribution builds would be a list of its own to maintain. The facts are in the
//! report: `toolchain.driver` is the path that was actually invoked and `profile.cflags` is
//! what chard passed it, and reading them is the caller's, which the README says.

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
    ///
    /// Not a join key of its own: the corpus hash folds it in, so decoders that differ
    /// already differ the corpora. It is read to say which of the two moved when the
    /// corpora differ, since a moved decoder means the same evidence may read differently
    /// and a moved declaration alone does not.
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
    ///
    /// A container shares the host's kernel, so a kernel-enforced verdict from one is
    /// not the distribution's. The field is recorded on every report, and four of the
    /// rows in this project's own dataset are containers; `matrix` carries execution as an
    /// axis, and the README says container and VM results "are not compared".
    pub executions: BTreeMap<String, Vec<String>>,
    /// Reports whose image was named on an operator's word, with nothing carried in to
    /// support the name.
    ///
    /// Not a conflict: two unattested rows are as comparable with each other as two
    /// attested ones, because the property is about what justifies the *label* rather
    /// than about what was measured. It is a caution because a table is read as a claim
    /// about distributions, and a row whose distribution rests on a typed string is a
    /// weaker claim than one whose image matched a signed manifest — a difference that
    /// must be visible in the rendering rather than discoverable in the JSON.
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
/// hash asserted with `CHARD_REVISION` is another, as a `-dirty` one is, since an asserted
/// label is the builder's word and a modified tree built under a clean hash carries no
/// `-dirty`; so is a revision whose report names no source (written before the field, or
/// with it removed), since absence is not permission. Reports asserted alike join among
/// themselves, as a fleet built from one `git archive` under `CHARD_REVISION=<hash>` does.
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
            // Compared against `AttestationStatus`'s own spellings rather than against a
            // second copy of them here. A status this does not recognise — a rename, a
            // typo, a field from a newer schema — counts as unattested, which is the safe
            // direction: it says less than the report claimed rather than more.
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

    /// True when every report came from one corpus and one harness revision.
    pub fn is_joinable(&self) -> bool {
        self.corpora.len() <= 1 && self.revisions.len() <= 1 && self.executions.len() <= 1
    }

    /// Why these reports are not joinable, one line per differing field. Empty when
    /// they are.
    ///
    /// The values are named rather than counted. "2 corpora" tells a reader they have a
    /// problem; naming both, with the reports carrying each, tells them which pile is
    /// the old one.
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
    /// carries: the corpus hash folds `run.decoders_sha256` in, so a reader of the refusal
    /// is told which of the declared corpus and the code that reads it changed.
    fn decoder_movement(&self) -> String {
        if self.decoders.contains_key(UNKNOWN) {
            format!(
                "run.decoders_sha256 is absent from some of them (a report written before \
                 2026-09-29 carries none), so whether the decoders moved is not stated: {}",
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
                "the decoders did not move (run.decoders_sha256 {} throughout), so the \
                 declared corpus did",
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

/// Which checks a report's own corpus contained, for telling "this corpus never had
/// that check" apart from "that check was not measured here".
///
/// Read from the observations rather than from the corpus hash, because the hash
/// identifies a corpus without describing it. Two reports from one corpus list the same
/// flags whatever their verdicts, so a flag present in one and absent from another with a
/// *different* hash is a corpus difference rather than a measurement gap.
///
/// The set is the check keys of each report's observations, and it is worth naming
/// what it feeds, because an empty answer here is not visibly wrong: `corpus_flags` in
/// `table` decides the `~` glyph, which distinguishes "this corpus never had that check"
/// from "not measured here". Silently returning nothing would print the second where the
/// first is true.
/// Reports whose own copies of a verdict disagree with each other.
///
/// `measure` refuses to write a self-contradicting report to the path the operator asked
/// for: it quarantines it to `<output>.contradicted` and exits 3, because a derived field
/// disagreeing with the observations under it is a defect in chard rather than a finding
/// about the toolchain. A report reaching a renderer should therefore contain no such
/// disagreement, but a report edited after `measure` wrote it can (34 verdicts
/// hand-flipped from `off` to `on`, say), so the renderers refuse the set
/// ([`refuse_self_contradicted`]).
///
/// It names a report with no `consistency` block, one whose `contradictions` list is not
/// empty, and one whose `consistency.status` disagrees with that list, is neither word, or
/// stands beside no list or no rule in `rules_applied`. Each finding carries its
/// [`FindingKind`], which the refusal's hint is chosen by.
///
/// It reads the copies a report carries, and re-runs only the rules in
/// [`crate::report::REREAD_RULES`]. Those are re-run on read by
/// [`crate::report::reread_contradictions`] through the same functions `measure` calls,
/// over read structs that carry only the fields those rules read, so an edit to
/// `defect_coverage[].status`, `fortify_ratchet` or `coverage.withholding` alone is named
/// by the rule it breaks; a subtree those rules cannot read is named too. One of them,
/// `coverage-disagrees-with-observations`, is re-run in part: its statements over
/// `coverage.verdict_counts`, which recount the observations' verdicts key by key, so a
/// tally relabelled between two verdicts with its sum kept is named as well. The remaining
/// rules, `composite_agrees` and every one that reads the binary's own corpus or the
/// profile's expansion, are not re-run: a report's `Report` type is not deserialized on
/// read, and porting those rules to the JSON would be their second implementation.
///
/// What makes that checkable without re-deriving anything is that the report already
/// carries each verdict twice: `composites[].constituents[]` copies the verdict of the
/// observation it names. Comparing the two copies is an equality test on redundant data,
/// not a second implementation of `composite_agrees` — the rule lives in one place still,
/// and this only asks whether the file is internally consistent with itself.
///
/// **Not an integrity control, and it must not be read as one.** It catches an edit that
/// touched one copy and not the other, a truncated or merged file, a report assembled by
/// hand. Anyone who edits both copies defeats it, and nothing inside a self-describing
/// file can do better. Integrity of a report in transit is the caller's: sign it, or
/// obtain it over a channel you trust. `THREAT_MODEL.md` carries the row this makes visible.
pub fn self_contradicted(reports: &[(String, Value)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, report) in reports {
        // The derived-field rules that need nothing outside the file, re-run over it as
        // written. A report `measure` published passes them by construction, so a finding
        // here is an edit, a file assembled elsewhere, or a report held to a rule whose
        // contract changed since it was written; an older shape is typed as that where it is
        // made ([`crate::report::Reread::older`]).
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
        out.push(format!(
            "{name} carries no `consistency` block, so whether its derived fields agree \
             with its observations is unknown — every chard report has one"
        ));
    }
    let consistency = report.get("consistency");
    let listed = consistency
        .and_then(|c| c.get("contradictions"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if listed > 0 {
        out.push(format!(
            "{name} reports {listed} contradiction(s) of its own; `measure` quarantines \
             such a report rather than writing it here"
        ));
    }
    // The status word `measure` derives from that list, read for what the list alone
    // does not show: `contradicted` beside an empty list (a quarantined file edited and
    // renamed), a word that is neither, and a worded block missing the list or naming
    // no rule, which `measure` never writes. A report written before the word existed
    // carries none, and its list is read as above.
    if let Some(consistency) = consistency {
        out.extend(status_disagrees(name, consistency));
    }

    for c in &reread.contradictions {
        out.push(format!(
            "{name} fails `{}` when the rule is re-run on read ({}: {}); `measure` \
             refuses a report that fails it",
            c.rule,
            c.property,
            c.claims.join(" vs ")
        ));
    }
    for u in &reread.unreadable {
        out.push(format!("{name}: {u}"));
    }

    // Explicitly, rather than defaulting an absent list to an empty map: with no
    // observations there is nothing to compare the composites against, and a silent
    // empty map would make that read as "checked, and consistent". The read
    // ([`refuse_unread`]) refuses a document with no observations list before it
    // reaches here, and the renderers refuse one for a caller that skipped it, so skipping is
    // right — leaving it implicit is what would not be.
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
///
/// One constructor for both commands, so the class and the hint agree. It is the
/// caller's invocation to correct: a text file, an empty object or a report of some other
/// tool's are all things `chard measure -o` never wrote, and sending them to `INTERNAL`
/// would tell a sweep across dozens of images to file a bug for a wrong path.
pub fn not_a_report(name: &str, why: &str) -> UserError {
    UserError::with_hint(
        format!("{name} is not a chard measurement report: {why}"),
        "pass the JSON that `chard measure -o` wrote",
    )
}

/// The bytes of a file the caller handed `table` or `matrix`, refused from its metadata
/// when no `read` could turn it into a report.
///
/// A directory, a device or a socket is refused before the open: none carries a report,
/// and a `read` on a socket answers with an errno (`ENOTSUP`, `ENXIO`) the envelope can
/// only report as chard's own. A FIFO is read, since a report piped in (`chard table
/// <(...)`) is a legitimate source, and a path that does not exist is left to the read,
/// so its errno reaches the envelope under the same context as any other io failure.
///
/// A file named as chard names a report it did not publish, `<output>.contradicted` or
/// `<output>.previous`, is refused by its name before anything is read. The name is
/// chard's own statement about the file: the first is a refused report kept as evidence
/// for a bug report, the second an earlier run's report set aside by a run that has not
/// published. Neither is a current measurement, and the case that matters is a glob such
/// as `dir/*` that sweeps one in beside the reports; the content check
/// ([`refuse_self_contradicted`]) catches a quarantine renamed to look published, and this
/// catches one edited to look consistent and an earlier report that is consistent and
/// stale. An operator who means to read one as a measurement renames it, which is a
/// decision on the record rather than a glob's accident. A third name is refused the same
/// way, `<output>.partial`: `report::write_output` writes a publication
/// there and renames it into place, so one is found only where a run stopped between the
/// two, and it may hold part of a report. That name carries the writing process's id and a
/// counter, `<output>.partial.<pid>.<n>`, so two runs sharing one `-o` do not share it, and
/// both forms are refused (`report::is_partial_name`).
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
            "it is evidence for a chard bug report, readable as JSON, not a measurement: \
             leave it out of the set",
        )
        .into());
    }
    if name.ends_with(crate::report::SET_ASIDE_SUFFIX.as_bytes()) {
        return Err(unpublished(
            path,
            "it is an earlier report a later run set aside and has not replaced",
            "the run that set it aside did not publish; re-run it, or rename the file to \
             read it as the earlier measurement it is",
        )
        .into());
    }
    if crate::report::is_partial_name(name) {
        return Err(unpublished(
            path,
            "it is the temporary file a publication writes before renaming it into place, \
             left by a run that stopped between the two",
            "it may be truncated and was never published; re-run the measurement",
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
/// Reading is the invocation's own validation and comes before `main` sets an earlier
/// output aside: a path that is missing, unreadable, not JSON or named as unpublished is
/// the operator's line to fix, and refusing it here leaves the earlier output untouched,
/// where judging the set (its identity, a report that contradicts itself) happens after
/// the set-aside, so a refused set leaves no earlier output at `-o`.
///
/// # Errors
///
/// Those of [`read_report_bytes`], [`not_a_report`] for bytes that are not JSON, and those
/// of [`refuse_unread`]. The `UserError` is the context object, so the parser's own text
/// stays in the chain and `error::classify` still finds the marker above it.
pub fn read_reports(
    paths: &[std::path::PathBuf],
) -> anyhow::Result<Vec<(String, serde_json::Value)>> {
    paths.iter().map(|p| read_report(p)).collect()
}

/// One path of [`read_reports`], read, parsed and held to [`refuse_unread`]: what `chard
/// digest` reads.
///
/// # Errors
///
/// Those of [`read_reports`].
pub fn read_report(path: &Path) -> anyhow::Result<(String, serde_json::Value)> {
    use anyhow::Context as _;
    // Refused from the metadata for a shape no read could turn into a report, then bytes
    // rather than a `String`, so a file that is not UTF-8 (an object handed to `table` by
    // mistake) is the parser's refusal and the caller's input, where a `read_to_string`
    // would have failed with `InvalidData` that the envelope can only report as chard's own.
    let bytes = read_report_bytes(path)?;
    let name = path.display().to_string();
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| not_a_report(&name, "it is not JSON"))?;
    refuse_unread(&name, &value)?;
    Ok((name, value))
}

/// A report this chard does not read, refused before any rule runs over it: first one
/// whose `chard_schema` is not [`crate::report::SCHEMA_VERSION`] ([`refuse_other_schema`]),
/// then a document with no `observations` list, which is not a report at all (chard's
/// matrix, probe listing, `detect` output and error envelope carry the version and no list,
/// and are named as what they are rather than as a report that lost its digest), then one
/// whose `digest` is absent or not an object ([`missing_digest`]).
///
/// The version is the file's own statement of which shape it has, and a binary that reads
/// one shape cannot say what another's fields mean: a later version may rename a key this
/// reader then finds absent, or give a value a meaning this reader takes for its own. So the
/// comparison comes first, before the digest's presence and before every consistency rule,
/// and a report that is both of another version and digest-forged is named for its version.
/// It compares the file with the binary, not the file with itself, so it is a refusal like
/// the quarantine's above and joins neither `report::RULES` nor `report::REREAD_RULES`.
///
/// The digest is required because every report `measure` publishes leads with it and the
/// shipped schema requires it, and because without it `table` and `matrix` would read
/// verdicts from fields no digest restates: an edit to a row, its digest removed, read as
/// written. A development build wrote reports without one before the digest existed; chard
/// is unpublished until 0.1.0, so no published chard did. A `digest` that is present and
/// not an object (`null` among them) is refused the same way, by its presence check and not
/// by the digest rule that would name it later.
///
/// Both are refusals of the read: `main` makes them before it sets an earlier output aside,
/// so an earlier output at `-o` is left in place and no `.previous` is written, since
/// nothing was read as a report. `chard detect` makes the version comparison alone over a
/// report it replays (`detect::decode_evidence`).
///
/// # Errors
///
/// A [`UserError`] naming the file's version and the binary's, a document that is not a
/// report, or the missing digest.
pub fn refuse_unread(name: &str, report: &Value) -> Result<(), UserError> {
    refuse_other_schema(name, report)?;
    if !report.get("observations").is_some_and(Value::is_array) {
        return Err(not_a_report(name, "it carries no observations"));
    }
    match report.get("digest") {
        Some(digest) if digest.is_object() => Ok(()),
        Some(other) => Err(UserError::with_hint(
            format!(
                "{name} carries `digest` {}, which is not the object every report chard \
                 publishes leads with",
                bounded(other)
            ),
            "pass the JSON that `chard measure -o` wrote, or run `chard measure` again with \
             this build",
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

/// The version half of [`refuse_unread`]: `report`'s `chard_schema` absent, not a string,
/// or a string other than [`crate::report::SCHEMA_VERSION`] (`"1 "` among them) is refused,
/// the message naming what the file carries, as JSON so a number reads apart from a
/// string (cut by [`bounded`]), beside the version this chard reads.
///
/// # Errors
///
/// A [`UserError`] for any `chard_schema` but this binary's.
pub fn refuse_other_schema(name: &str, report: &Value) -> Result<(), UserError> {
    let reads = crate::report::SCHEMA_VERSION;
    let carries = match report.get("chard_schema") {
        Some(Value::String(version)) if version == reads => return Ok(()),
        Some(other) => format!("it carries `chard_schema` {}", bounded(other)),
        None => "it carries no `chard_schema`".to_owned(),
    };
    Err(UserError::with_hint(
        format!(
            "{name} is not a report this chard reads: {carries}, and this chard reads \
             `chard_schema` \"{reads}\" alone"
        ),
        "pass the JSON that `chard measure -o` wrote with this chard, or read the file with \
         the chard that wrote it",
    ))
}

/// A report with no `digest`, refused by [`refuse_unread`] and by `chard digest`.
#[must_use]
pub fn missing_digest(name: &str) -> UserError {
    UserError::with_hint(
        format!(
            "{name} carries no `digest`: every report chard publishes leads with one, so this \
             one was edited after it was written, was written by a development build from \
             before the digest, or is not a report"
        ),
        "pass the JSON that `chard measure -o` wrote, or run `chard measure` again with this \
         build",
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
            "{name} carries `consistency.status` {status} and no `contradictions` list; \
             `measure` writes the list beside the word, `[]` when empty"
        ));
    };
    let rules = consistency
        .get("rules_applied")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if rules == 0 {
        return Some(format!(
            "{name} carries `consistency.status` {status} and no rule in `rules_applied`, \
             so neither word is true of it"
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
        "{name} carries `consistency.status` {status} beside {beside}; `measure` writes \
         `consistent` beside an empty list and `contradicted` beside a non-empty one"
    ))
}

/// Refuse a set of reports any one of which [`self_contradicted`] names.
///
/// Rendering such a report with a `CONTRADICTED` note and exit 0 would be the shape
/// `report::publish` refuses for `measure`: a job that ignores the note, as one ignoring an
/// exit status does, would read the verdicts as measured. A note travels with the output only
/// as far as a reader looks. So the set is refused, whole, as the caller's
/// input (`USER_INPUT`, exit 2): the action next is theirs, to leave the file out of the set,
/// and the contradiction is a chard defect only in the run that wrote it, which is not this
/// one; exit 3 says this run disagreed with itself. The rest of the set is not
/// rendered without it, since a column silently dropped from a sweep is a clean-looking
/// absence.
///
/// The hint opens with the action the findings call for, by their [`FindingKind`]: a report
/// every finding of which is [`FindingKind::Older`] is from another revision, to be read with
/// that revision or measured again, and a set holding only such reports is told that first,
/// where the contradiction advice would send its reader to file a bug that is not one. A set
/// holding a contradiction opens with the contradiction advice and names its older reports
/// after it. Either way the set is refused with exit 2.
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
    const CONTRADICTION: &str = "leave out of the set a report that contradicts itself, which \
                                 is evidence for a chard bug report, readable as JSON, not a \
                                 measurement";
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

    /// A report naming no revision keys on the revision word alone, whatever source it
    /// names beside it.
    #[test]
    fn a_report_without_a_revision_keys_on_no_source() {
        let bare = revision_key(&serde_json::json!({"run": {}}));
        assert!(!bare.contains('['), "{bare}");
        assert_eq!(
            revision_key(&serde_json::json!({"run": {"harness_revision_source": "asserted"}})),
            bare
        );
    }

    /// [`refuse_unread`] both ways: a report at this chard's `chard_schema` with a digest
    /// passes; every other `chard_schema` is refused naming what the file carries and the
    /// version this chard reads, with or without a digest and before the digest's absence;
    /// a document with no `observations` list is refused as not a report before its digest
    /// is looked for; and a report at this version whose digest is absent or not an object
    /// is refused naming it.
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

    /// A directory is refused from its metadata as the caller's, with the shape named;
    /// the socket and the device are held through the built binary in
    /// `tests/error_classes.rs`, and a path to nothing keeps its errno.
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

    /// The truncation is a boundary, and both sides of it are rendered differently.
    ///
    /// `describe_list` shows six names and `describe` three, each with a `+N more` tail
    /// that must appear exactly when something was left out. Inverting either equality
    /// prints `+0 more` on a complete list, or drops the tail from a truncated one and
    /// tells a reader they are seeing everything.
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

    /// A report that contradicts itself is named, and one that does not is left alone.
    ///
    /// `measure` exits 3 rather than writing a self-contradicted report, so one appearing
    /// in a dataset means it was assembled from somewhere else. The filter is on the list
    /// being non-empty: without the negation every report with a `contradictions` key —
    /// which is every report, since the field is published unconditionally — would be
    /// accused of contradicting itself.
    #[test]
    fn only_a_report_that_contradicts_itself_is_named() {
        let with = |contradictions: serde_json::Value| {
            serde_json::json!({
                "consistency": {"contradictions": contradictions},
                "environment": environment(),
                "observations": [],
                "coverage": {"checks_attempted": 0, "corpus_checks_total": 0,
                             "verdict_counts": {}, "all_verdicts_published": true,
                             "withholding": {"published": 0,
                                             "earned_limitations": {"count": 0, "no_named_cause": 0},
                                             "instrument_withholdings": {"count": 0, "no_named_cause": 0}}},
            })
        };

        let clean = with(serde_json::json!([]));
        let dirty = with(serde_json::json!([{"rule": "r", "property": "p"}]));

        // The status word: agreeing with the list adds nothing, disagreeing is named once.
        let worded = |contradictions: serde_json::Value, status: &str| {
            let mut r = with(contradictions);
            r["consistency"]["status"] = serde_json::json!(status);
            r["consistency"]["rules_applied"] = json!(["r"]);
            r
        };
        assert!(
            self_contradicted(&[("clean".to_owned(), worded(json!([]), "consistent"))]).is_empty()
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

    /// A hand-edited report is not rendered as a clean bill of health.
    ///
    /// Measured with this check taken out: flipping 34 verdicts from `off` to `on` in a real
    /// report and running `chard table` over it prints `cet on`, `pie on`, `fortify on`
    /// and thirty more, exit 0. The file is contradictory in a way chard knows how to
    /// describe: `composite-verdict-disagrees-with-constituents` is a rule it implements
    /// and names in its own output. But the rules run once inside `measure`, and a
    /// renderer that does not look prints past them.
    ///
    /// The redundancy is what makes it checkable on read: a composite constituent carries
    /// a copy of the verdict of the observation it names.
    #[test]
    fn a_report_whose_two_copies_of_a_verdict_disagree_is_named() {
        let honest = json!({
            "environment": environment(),
            "observations": [{"check": "pie", "flag": "-pie", "verdict": "off",
                              "observes": "protection"}],
            "composites": [{"id": "fhardened-effective",
                            "constituents": [{"check": "pie", "verdict": "off"}]}],
            "consistency": {"rules_applied": [], "fields_checked": []},
            "coverage": {"checks_attempted": 1, "corpus_checks_total": 1,
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
            "coverage": {"checks_attempted": 0, "corpus_checks_total": 0,
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

    /// A derived field edited alone, with every copy of every verdict left agreeing, is
    /// named by the rule it breaks; the same report unedited is not named.
    ///
    /// The copies agree, so only a rule re-run on read can name it.
    #[test]
    fn a_derived_field_edited_alone_is_named_by_its_rule() {
        let honest = json!({
            "environment": environment(),
            "observations": [{"check": "pie", "flag": "-pie", "verdict": "off",
                              "defects": ["address-layout-disclosure"],
                              "observes": "protection"}],
            "defect_coverage": {"address-layout-disclosure": {
                "status": "not-mitigated", "from_checks": ["pie"],
                "verdict_counts": {"off": 1}}},
            "coverage": {"checks_attempted": 1, "corpus_checks_total": 1,
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
            // real report too. A helper writing a `toolchain.provenance.status` that no
            // report carries would let a caution reading that field pass its test while
            // firing on every render.
            "toolchain": {
                "id": "gcc-16.1.1-glibc2.43-fedora44",
                "kind": "gcc",
                "version": "16.1.1",
                "driver": "/usr/bin/cc",
            },
        })
    }

    /// A container shares the host's kernel, so a kernel-enforced verdict from one is
    /// not the distribution's and must not be tabulated beside a VM's.
    ///
    /// Four rows in this project's own dataset are containers (Wolfi, Chimera and both
    /// Gentoo profiles), and the README says such results "are not compared".
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

    /// One corpus and one revision is joinable; either differing is not.
    #[test]
    fn reports_from_two_corpora_are_not_joinable() {
        let same = [
            ("a.json".to_owned(), report("abc", Some("1111"))),
            ("b.json".to_owned(), report("abc", Some("1111"))),
        ];
        assert!(Identity::of(&same).is_joinable());
        assert!(Identity::of(&same).conflicts().is_empty());

        let mixed = [
            ("old.json".to_owned(), report("abc", Some("1111"))),
            ("new.json".to_owned(), report("def", Some("1111"))),
        ];
        let id = Identity::of(&mixed);
        assert!(!id.is_joinable());
        let why = id.conflicts().join(" ");
        assert!(why.contains("corpora differ"), "{why}");
        // Both values named, and the reports carrying each, so a reader can tell which
        // pile is the old one.
        assert!(why.contains("abc") && why.contains("def"), "{why}");
        assert!(
            why.contains("old.json") && why.contains("new.json"),
            "{why}"
        );
    }

    /// A refusal over differing corpora names whether the decoders moved: not at all,
    /// with them, or unstated where a report does not carry the field.
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

    /// A detector change moves verdicts without moving the corpus hash, so the
    /// revision has to be checked on its own.
    #[test]
    fn reports_from_two_harness_revisions_are_not_joinable() {
        let id = Identity::of(&[
            ("a.json".to_owned(), report("abc", Some("1111"))),
            ("b.json".to_owned(), report("abc", Some("2222"))),
        ]);
        assert!(!id.is_joinable());
        assert!(id.conflicts().join(" ").contains("revisions differ"));
    }

    /// One commit read from a clone, an archive or a crate archive is one revision; the same
    /// hash asserted with `CHARD_REVISION`, built under rustflags, or naming no source is
    /// another, and reports asserted alike join among themselves, as a fleet's do.
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

    /// A build's own key names a clean revision read from its tree, with its rustflags, and
    /// nothing else: not a dirty revision (with rustflags or without), not an asserted one,
    /// not one without a source.
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

    /// A report naming no revision is unknown, not compatible. Mixing an unknown with
    /// a known is exactly as unjoinable as mixing two knowns, and treating absence as
    /// permission is how an old report joins a current table unnoticed.
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

    /// A dirty revision is a caution rather than a conflict: it does not make the set
    /// unjoinable, it makes it uncitable, and saying nothing is what let seven such
    /// reports be treated as a dataset for a week.
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
                .is_empty()
        );
    }

    /// An image nobody established is a caution, not a conflict: two unattested rows are
    /// as comparable with each other as two attested ones, because what is unsupported is
    /// the distribution *label* rather than anything measured.
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

    /// A report that carries no attestation has established nothing about its image, so
    /// absence reads as unattested. The opposite reading lets silence stand for a clean
    /// result, the hazard this module exists to end, and the same one an absent
    /// `coverage.complete` or an empty `contradictions` list carries.
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
    /// A caution that read `toolchain.provenance.status` and treated anything but
    /// `distro-packaged` as unestablished would take the safe direction, except that no report
    /// carries the field. Every `table` render, on every stock distribution compiler, would
    /// print "measured a compiler their distribution does not package", and a test that
    /// hand-wrote the field into its fixture would not see it.
    ///
    /// So this asserts on the *absence* of a caution for input the tool can really produce, and
    /// the helper above builds that input. A future caution about the toolchain has to survive
    /// this to ship, which means it has to read a field that exists.
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

    /// `host` mode has no image to attest to, so it must not be cautioned. Reporting a
    /// caution there would train a reader to ignore the caution.
    #[test]
    fn measuring_the_running_system_is_not_cautioned() {
        let id = Identity::of(&[(
            "host.json".to_owned(),
            attested_report("abc", Some("1111"), "host", Some("not-applicable")),
        )]);
        assert!(id.unattested.is_empty());
        assert!(id.cautions().is_empty());
    }

    /// The sample report `measure` wrote, which reads clean.
    fn sample_report() -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-report.json");
        let text = std::fs::read_to_string(path).expect("the sample fixture reads");
        serde_json::from_str(&text).expect("JSON")
    }

    /// The sample as a `user` report another revision wrote: its digest's `user` sentence the
    /// one that revision wrote, as a fleet sweep's OpenBSD `explicit` reports store it.
    fn with_retired_user_sentence() -> Value {
        use crate::report::{digest, flags_source};
        let mut user = sample_report();
        user["profile"]["flags_source"] = json!(flags_source::USER);
        let status = user["consistency"]["status"]
            .as_str()
            .expect("a status")
            .to_owned();
        user["digest"] =
            serde_json::to_value(digest::derive(&user, &status).expect("derives")).expect("JSON");
        user["digest"]["profile"]["meaning"] = json!(
            "the flags given to `measure` (`profile.cflags`, `cxxflags`, `ldflags`), passed to \
             each measured build (a build's `dropped_flags` names any it left out): what a \
             package build that injects exactly these lists gets, and not what a build that \
             also injects anything else gets"
        );
        user
    }

    /// The sample with its `coverage.withholding` in a shape with no two sets, and no
    /// digest, which this revision does not write either.
    fn with_older_withholding() -> Value {
        let mut older = sample_report();
        let published = older["coverage"]["withholding"]["published"].clone();
        older["coverage"]["withholding"] =
            json!({"published": published, "withheld": 0, "percent_withheld": 0.0});
        older.as_object_mut().expect("an object").remove("digest");
        older
    }

    /// A report in a shape without `observes`: one protection check, its rollup counted on that
    /// check as protection, no `observes`, and a corpus other than this build's.
    fn with_older_rollup() -> Value {
        json!({
            "environment": environment(),
            "run": {"probe_corpus_sha256": "cd".repeat(32)},
            "observations": [{"check": "pie", "flag": "-pie", "verdict": "off",
                              "defects": ["address-layout-disclosure"]}],
            "defect_coverage": {"address-layout-disclosure": {
                "status": "not-mitigated", "from_checks": ["pie"],
                "verdict_counts": {"off": 1}}},
            "coverage": {"checks_attempted": 1, "corpus_checks_total": 1,
                         "verdict_counts": {"off": 1}, "all_verdicts_published": true,
                         "withholding": {"published": 1,
                                         "earned_limitations": {"count": 0, "no_named_cause": 0},
                                         "instrument_withholdings": {"count": 0, "no_named_cause": 0}}},
            "consistency": {"contradictions": []},
        })
    }

    /// The sample as `measure` quarantines it: one contradiction of its own.
    fn contradicted() -> Value {
        let mut r = sample_report();
        r["consistency"]["status"] = json!("contradicted");
        r["consistency"]["contradictions"] = json!([{"rule": "r", "property": "p"}]);
        r
    }

    /// The hint `refuse_self_contradicted` gives the set, which it must refuse.
    fn refusal_hint_of(set: &[(&str, Value)]) -> String {
        let set: Vec<(String, Value)> = set
            .iter()
            .map(|(name, r)| ((*name).to_owned(), r.clone()))
            .collect();
        refuse_self_contradicted(&set)
            .expect_err("refused")
            .hint
            .expect("a hint")
    }

    /// Each older shape is typed as older on its own, and the sample reads clean, so the sets
    /// below hold what they are named for.
    #[test]
    fn the_older_shapes_are_typed_as_older() {
        assert!(self_contradicted(&[("s".to_owned(), sample_report())]).is_empty());
        for older in [
            with_retired_user_sentence(),
            with_older_withholding(),
            with_older_rollup(),
        ] {
            let found = self_contradicted(&[("o".to_owned(), older)]);
            assert!(!found.is_empty());
            assert!(
                found.iter().all(|f| f.kind == FindingKind::Older),
                "{found:?}"
            );
        }
        // A contradiction, and a subtree that does not read, are contradictions: only the
        // older shapes are typed apart.
        let mut unreadable = sample_report();
        unreadable["coverage"]["checks_attempted"] = json!("many");
        for (name, report) in [("c", contradicted()), ("u", unreadable.clone())] {
            let found = self_contradicted(&[(name.to_owned(), report)]);
            assert!(!found.is_empty());
            assert!(
                found.iter().all(|f| f.kind == FindingKind::Contradiction),
                "{found:?}"
            );
        }
        assert_eq!(refusal_hint_of(&[("u.json", unreadable)]), ADVICE);
    }

    /// The remedies the hint names for one older report, and for more.
    const REMEDIES_ONE: &str = "read it with the chard its `run.harness_revision` names, or run \
                                `chard measure` again with this build and render the new report";
    const REMEDIES_MANY: &str = "read each with the chard its `run.harness_revision` names, or \
                                 run `chard measure` again with this build and render the new \
                                 reports";
    const ADVICE: &str = "leave out of the set a report that contradicts itself, which is \
                          evidence for a chard bug report, readable as JSON, not a measurement";

    /// A set of older shapes alone is refused, and the hint says first that they are older and
    /// names both remedies, never the contradiction advice.
    #[test]
    fn a_set_of_older_shapes_alone_is_told_it_is_older_first() {
        for one in [
            with_retired_user_sentence(),
            with_older_withholding(),
            with_older_rollup(),
        ] {
            assert_eq!(
                refusal_hint_of(&[("a.json", one)]),
                format!(
                    "the report named above is in a shape this revision does not write, \
                     which this build cannot hold to its rules: {REMEDIES_ONE}"
                )
            );
        }
        assert_eq!(
            refusal_hint_of(&[
                ("a.json", with_retired_user_sentence()),
                ("b.json", with_older_withholding()),
            ]),
            format!(
                "every report named above is in a shape this revision does not write, which this \
                 build cannot hold to its rules: {REMEDIES_MANY}"
            )
        );
    }

    /// A set of contradictions alone keeps the contradiction advice, and says nothing of an
    /// older shape it does not hold.
    #[test]
    fn a_set_of_contradictions_alone_keeps_the_contradiction_advice() {
        let hint = refusal_hint_of(&[("c.json", contradicted()), ("d.json", contradicted())]);
        assert_eq!(hint, ADVICE);
    }

    /// A mixed set opens with the contradiction advice and names its older reports as older,
    /// each once, with both remedies; a report both older and contradicting is a contradicting
    /// one.
    #[test]
    fn a_mixed_set_opens_with_the_contradiction_advice_and_names_the_older_reports() {
        let hint = refusal_hint_of(&[
            ("c.json", contradicted()),
            ("a.json", with_retired_user_sentence()),
        ]);
        assert_eq!(
            hint,
            format!(
                "{ADVICE}. a.json is in a shape this revision does not write, which this build \
                 cannot hold to its rules: {REMEDIES_ONE}"
            )
        );
        // `b.json` older twice over: its sentence and its withholding block.
        let mut twice = with_retired_user_sentence();
        twice["coverage"]["withholding"] =
            with_older_withholding()["coverage"]["withholding"].clone();
        let found = self_contradicted(&[("b.json".to_owned(), twice.clone())]);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found.iter().all(|f| f.kind == FindingKind::Older),
            "{found:?}"
        );
        assert_eq!(
            refusal_hint_of(&[
                ("a.json", with_retired_user_sentence()),
                ("c.json", contradicted()),
                ("b.json", twice),
            ]),
            format!(
                "{ADVICE}. a.json, b.json are in shapes this revision does not write, which this \
                 build cannot hold to its rules: {REMEDIES_MANY}"
            )
        );

        // Older and edited besides: a contradiction, so not named as older.
        let mut both = with_retired_user_sentence();
        both["digest"]["toolchain"] = json!("edited");
        let found = self_contradicted(&[("e.json".to_owned(), both.clone())]);
        assert!(found.iter().any(|f| f.kind == FindingKind::Older));
        assert!(found.iter().any(|f| f.kind == FindingKind::Contradiction));
        assert_eq!(refusal_hint_of(&[("e.json", both)]), ADVICE);
    }

    /// `chard matrix` and `chard digest` refuse an older report through the same refusal, as
    /// the caller's input, with the older hint first.
    #[test]
    fn matrix_and_digest_give_the_older_hint_first() {
        let read = ("a.json".to_owned(), with_retired_user_sentence());
        let hint_of = |e: anyhow::Error| {
            e.downcast::<UserError>()
                .expect("a user error, exit 2")
                .hint
                .expect("a hint")
        };
        let matrix = crate::matrix::build_from_reports(
            std::slice::from_ref(&read),
            false,
            crate::matrix::Repeated::Refuse,
        )
        .expect_err("refused");
        let digest = crate::report::digest::of_read(&read).expect_err("refused");
        for hint in [hint_of(matrix), hint_of(digest)] {
            assert_eq!(
                hint,
                format!(
                    "the report named above is in a shape this revision does not write, \
                     which this build cannot hold to its rules: {REMEDIES_ONE}"
                )
            );
        }
    }

    /// No finding, no hint to choose: the contradiction advice, never "every report named
    /// above is older" over a set that names none.
    #[test]
    fn an_empty_finding_list_reads_as_no_older_report() {
        assert_eq!(refusal_hint(&[]), ADVICE);
    }
}
