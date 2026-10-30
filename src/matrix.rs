// SPDX-License-Identifier: BSD-3-Clause

//! Cross-tabulating many reports without pretending the distribution is the key.
//!
//! A table with one column per distribution encodes an assumption that is wrong
//! often enough to matter: that the distribution is what explains the number. Every
//! result this project has produced says otherwise.
//!
//! `-Werror=implicit-function-declaration` is an error under gcc 16 and a warning
//! under gcc 13.3 — that is a **compiler version** boundary at GCC 14, and it has
//! nothing to do with Fedora or Ubuntu. Ubuntu's clang gets PIE and nothing else
//! while Ubuntu's gcc gets everything, so within one distribution the **compiler**
//! explains more than the distribution does. The fortify rungs that separate level 2
//! from level 1 read `unsupported` under Alpine's fortify-headers and are measurable
//! under glibc, which is the **libc**. Fortify is inert without `-O` on every
//! distribution alive, which is the **optimization level**. And the
//! compiler-versus-build-system split is the **profile**.
//!
//! So the cell key is a tuple (distribution, release, compiler kind, compiler
//! version, libc, architecture, profile, execution mode, what established that mode,
//! and image), and this module joins on it. Reports are the atomic facts; a table is a
//! view over them.
//!
//! ## Naming the axis that explains a flag
//!
//! Beyond tabulating, the interesting question is *which* variable accounts for a
//! flag's variation. The test used here is deliberately strict: an axis explains a
//! flag when every group of observations sharing that axis value agrees on the
//! verdict. If `compiler_version` explains a flag, then all gcc-13 observations
//! agree with each other and all gcc-16 observations agree with each other,
//! whatever distribution or profile they came from.
//!
//! Several axes can explain the same flag when the inputs are too few to separate
//! them — two reports differing in both distribution and compiler make those axes
//! indistinguishable — so the explanation lists every axis that fits and the
//! caller is told how many inputs it had. That is a real limitation of the data
//! rather than an ambiguity to be resolved by picking one.
//!
//! ## Fitting is not explaining
//!
//! "Some axis partitions the observations consistently" is a weaker claim than "that
//! axis causes the difference", and the finer the axis, the more cheaply it satisfies
//! the first. `compiler_version` is the trap: it took a distinct value on almost
//! every configuration in the LTS sweep, so it partitioned nearly everything, and
//! reporting it made Ubuntu's *patched driver* look like upstream GCC behaviour.
//!
//! Two guards, both reusing the standard already applied to a single axis — that a
//! group of one is an identifier while a group of many is a pattern:
//!
//! - [`Variance::confounded_with`] names axes whose partition these inputs cannot
//!   separate from the explaining one, requiring two cross-links rather than one
//!   before it will call them separable.
//! - [`Variance::explained_by_combination`] reports a pair of axes when the pair
//!   holds more agreeing observations in one group than any single axis manages.
//!   That is what recovers `distro` × `compiler` — the actual mechanism — for the
//!   flags Ubuntu patches into gcc.
//!
//! A pair is only offered when both its axes are separable from the single
//! explanation. `-Werror=implicit-function-declaration` is why: it flips at GCC 14,
//! `libc` is confounded with `compiler_version` because each release ships its own
//! glibc, and `compiler` × `libc` scored better than `compiler_version` while being a
//! restatement of it under the libc's name — which a reader would take to mean the C
//! library decides whether an undeclared call is an error. An axis already reported as
//! inseparable cannot contribute a genuinely different explanation, so it is excluded
//! from the pair search, and that flag falls back to `compiler_version` with the
//! confound stated.
//!
//! **What this still cannot express.** The axes are categorical, and some flags flip on
//! an *ordered* threshold. The honest attribution for the flag above is "compiler
//! version ≥ 14", and no partition of version strings says that. What the fields do
//! convey is `explained_by: [compiler_version]` together with
//! `confounded_with: {compiler_version: [libc]}` — the right axis, plus an explicit
//! statement that these inputs cannot separate it from one that moves in lockstep.
//! Recognising the boundary as a threshold, rather than as an unordered partition,
//! still requires knowing that it is one.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::Value;

/// `chard_schema` in a matrix: the major version of `schema/chard-matrix.schema.json`. The rule
/// the CLI's contract states holds from chard's first publication, and every shape is `1` there.
pub const MATRIX_SCHEMA_VERSION: &str = "1";

/// The `execution_basis` of a report that carries no `mode_evidence.basis` (one written before
/// the field existed), a word outside that field's enumeration so it never reads as a basis.
pub const UNPUBLISHED_BASIS: &str = "unpublished";

/// The `kernel_ownership` of a report that carries no `environment.kernel.ownership` (one
/// written before the field existed), a word outside that field's enumeration.
pub const UNPUBLISHED_OWNERSHIP: &str = "unpublished";

/// The axes a cell is keyed on, in the order a reader should scan them.
pub const AXES: &[&str] = &[
    "distro",
    "release",
    "compiler",
    "compiler_version",
    "libc",
    "arch",
    "profile",
    "execution",
    // Beside the mode it qualifies: `host` on the default and an asserted `host` are two inputs.
    "execution_basis",
    // Last because it is the axis of last resort: where it is the *only* thing that varies, two
    // specimens are being compared that agree on everything a reader would think to check.
    "image",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CellKey {
    pub distro: String,
    pub release: String,
    pub compiler: String,
    pub compiler_version: String,
    pub libc: String,
    pub arch: String,
    pub profile: String,
    pub execution: String,
    /// `environment.execution.mode_evidence.basis`: what established `execution`.
    ///
    /// Without it a report on the default (`host` on `assumed-host`) and an asserted
    /// `--execution host` report of one configuration collide into one cell, though the default
    /// withholds the checks that declare `needs_vm` where the assertion measures them, and the
    /// two differ in `run.inputs_sha256`. [`UNPUBLISHED_BASIS`] for a report that carries none:
    /// read as an empty string, which `axes` and the label skip, such a report beside one with a
    /// basis would be a second cell no label told apart.
    pub execution_basis: String,
    /// The image the measurement ran in.
    ///
    /// Without it two Gentoo portage profiles collide into one cell, and the flag they disagree
    /// about comes back `varies: false`, "the same everywhere in this input set", while three of
    /// six inputs say `off`. Treating them as one configuration measured twice, a
    /// reproducibility check, does not apply: these are two specimens, and a key without the
    /// field that distinguishes them cannot tell. Two reports of one key are refused, or the
    /// later replaces the cell whole ([`Repeated`]).
    pub image: String,
}

impl CellKey {
    fn axis(&self, name: &str) -> &str {
        match name {
            "distro" => &self.distro,
            "release" => &self.release,
            "compiler" => &self.compiler,
            "compiler_version" => &self.compiler_version,
            "libc" => &self.libc,
            "arch" => &self.arch,
            "profile" => &self.profile,
            "execution" => &self.execution,
            "execution_basis" => &self.execution_basis,
            "image" => &self.image,
            _ => "",
        }
    }

    /// Every axis by name with its value, in `AXES` order, an empty one as `(none)`: the
    /// configuration in full, for a sentence that names one, where [`Self::label`] names what
    /// varies. An empty axis is printed, so a match that rests on a field both reports lack
    /// shows as one.
    fn describe(&self) -> String {
        AXES.iter()
            .map(|a| match self.axis(a) {
                "" => format!("{a} (none)"),
                v => format!("{a} {v}"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// A short human label, built only from the axes that actually vary, so a
    /// table of two Fedora reports does not repeat "fedora" in every row.
    fn label(&self, varying: &[String]) -> String {
        let parts: Vec<String> = varying
            .iter()
            .map(|a| self.axis(a).to_owned())
            .filter(|v| !v.is_empty())
            .collect();
        if parts.is_empty() {
            "(single configuration)".to_owned()
        } else {
            parts.join(" / ")
        }
    }
}

fn text(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        match cur.get(p) {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
    cur.as_str().unwrap_or("").to_owned()
}

/// The `libc` axis is `environment.libc.impl` and `version` run together, which is the
/// spelling `env::Libc::tag` gives the libc half of `toolchain.id`; this one reads the
/// parsed report, since a matrix is built from files, and `env.rs`'s unit test pins the
/// two to the same strings.
fn key_of(report: &Value) -> CellKey {
    let libc_version = text(report, &["environment", "libc", "version"]);
    let libc_impl = text(report, &["environment", "libc", "impl"]);
    CellKey {
        distro: text(report, &["environment", "distro", "id"]),
        release: text(report, &["environment", "distro", "version_id"]),
        compiler: text(report, &["toolchain", "kind"]),
        compiler_version: text(report, &["toolchain", "version"]),
        libc: if libc_version.is_empty() {
            libc_impl
        } else {
            format!("{libc_impl}{libc_version}")
        },
        arch: text(report, &["environment", "kernel", "arch"]),
        profile: text(report, &["profile", "id"]),
        execution: text(report, &["environment", "execution", "mode"]),
        execution_basis: match text(
            report,
            &["environment", "execution", "mode_evidence", "basis"],
        ) {
            basis if basis.is_empty() => UNPUBLISHED_BASIS.to_owned(),
            basis => basis,
        },
        image: text(report, &["environment", "execution", "image"]),
    }
}

/// `environment.kernel.ownership`, or [`UNPUBLISHED_OWNERSHIP`] where it is absent, empty or
/// not a string.
fn ownership_of(report: &Value) -> String {
    match text(report, &["environment", "kernel", "ownership"]) {
        word if word.is_empty() => UNPUBLISHED_OWNERSHIP.to_owned(),
        word => word,
    }
}

/// A cell of the cross-tabulation: one configuration, and what it measured.
///
/// ## Why there is no `representative` field
///
/// Not every point in the axis cross-product describes a real consumer. Ubuntu can build musl
/// programs — the packages exist — but essentially nothing in the archive is built that way, so an
/// (ubuntu, musl) cell is an artifact of what was installable rather than a configuration anyone
/// ships. A `representative` flag saying so would need a source for that judgement, and the two
/// at hand both fail.
///
/// A hand-maintained table of distribution ids mapped to libc names has the two failure modes a
/// table has: it goes out of date, so a distribution in this project's own dataset and absent
/// from the table reads `representative: true` with no note, right by luck; and it answers from
/// a *list* rather than from the specimen, so it cannot tell a distribution's own compiler from
/// one installed over it.
///
/// What the package manager says owns the invoked driver has the right shape, but chard asks
/// package managers nothing, by design. Every cell would read `representative: false` with a
/// note about a query this tool does not perform, on every matrix, for every reader.
///
/// A third answer would need a third source of evidence, and there is none in a report: the
/// question is about the archive a compiler came from, and chard reads artifacts it built. It is
/// answerable, but from the distribution's package metadata rather than from here. So the cell
/// states what was measured, and whether that configuration is one anyone ships is left to a
/// reader who has `key` in front of them.
#[derive(Debug, Clone, Serialize)]
pub struct Cell {
    pub key: CellKey,
    pub label: String,
    /// `environment.kernel.ownership`: whose kernel the cell's run had (`own`, `borrowed`,
    /// `unsettled`), or [`UNPUBLISHED_OWNERSHIP`].
    ///
    /// Beside the key, not in it: the word is a function of `execution` and
    /// `execution_basis`, which `report::reread_contradictions` holds it to before a report
    /// reaches here, so as an axis it would split no cell and vary only where they do, and
    /// as a key field a report without it would be a second cell under the same label.
    /// A cell holds one report ([`Repeated`]), so it is that report's word, or
    /// [`UNPUBLISHED_OWNERSHIP`] where the report publishes none.
    pub kernel_ownership: String,
    /// flag -> verdict, with the level appended where a graded mechanism has one.
    pub flags: BTreeMap<String, String>,
    /// flag -> the observation's `polarity`, for every flag in `flags` whose observation
    /// carries one. A `weaken` flag's `off` is the protected state, so a verdict read
    /// without it reads the wrong way round; `table` inverts such a row and its legend
    /// says so, and here the word stands beside the verdict instead.
    pub polarity: BTreeMap<String, String>,
}

/// Whether `fine` is a refinement of `coarse` by construction rather than by
/// accident of the input set.
///
/// A compiler version belongs to exactly one compiler, and a release to exactly one
/// distribution, in every possible input set. Reporting those as confounds would be
/// true and useless, and — worse — would bury the confounds that are contingent and
/// therefore fixable by measuring one more configuration.
fn is_structural_refinement(fine: &str, coarse: &str) -> bool {
    matches!(
        (fine, coarse),
        ("compiler_version", "compiler") | ("release" | "libc", "distro")
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct Variance {
    pub varies: bool,
    /// How many configurations actually carried this flag, against how many are in the input set.
    ///
    /// Published because `varies` alone cannot distinguish "measured everywhere and identical" from
    /// "measured in one place" or "measured nowhere", and the note asserted the first for all three.
    /// A reader had to sum the `verdicts` lists and compare against `len(cells)` themselves, which
    /// is exactly the arithmetic a gate must not leave to its reader.
    pub observed_in: usize,
    /// Configurations in the input set, so `observed_in` has a denominator beside it.
    pub of_configurations: usize,
    /// Distinct verdicts seen, and which configurations produced each.
    pub verdicts: BTreeMap<String, Vec<String>>,
    /// Axes under which every group agrees. Empty when nothing explains it.
    pub explained_by: Vec<String>,
    /// `grouped` when at least one axis value covers two or more agreeing
    /// observations; `controlled` when the axis is merely the only thing that
    /// changed, which is weaker; `none` when nothing fits.
    pub strength: String,
    /// Axes whose partition these inputs cannot separate from the explaining one,
    /// because every value of the explainer occurs under exactly one value of the
    /// other. Reported per explaining axis as `explainer -> [coarser axes]`.
    ///
    /// This is the vacuous-explanation problem one level subtler than the
    /// one-report-per-distro case. `compiler_version` grouped two observations at a
    /// time and partitioned `-fstack-protector-strong` perfectly, so it was reported
    /// as the explanation — but every gcc version in the input set was unique to one
    /// distribution (Ubuntu shipped 15.2.0, Fedora 15.2.1), which makes
    /// "the compiler version explains it" indistinguishable from "the distribution's
    /// patch explains it". A reader takes the former to mean upstream GCC behaviour,
    /// which was the exact opposite of the truth.
    ///
    /// Separating them needs one observation pair sharing a compiler version across
    /// two distributions. Such pairs do occur — clang 21.1.8 appeared on both Fedora
    /// 43 and Ubuntu 26.04 — so this is a property of the input set, not a permanent
    /// limit, and naming it is what tells a reader which configuration to add.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub confounded_with: BTreeMap<String, Vec<String>>,
    /// A pair of axes that explains the variation with a *coarser* partition than
    /// any single axis manages.
    ///
    /// Needed because "some axis partitions the data consistently" and "that axis
    /// causes the difference" are not the same claim, and the finer the axis the
    /// more cheaply it satisfies the first. `-fstack-protector-strong` in the LTS
    /// sweep is on for Ubuntu's gcc and off for all fifteen other configurations.
    /// `compiler_version` partitions that perfectly across fifteen groups — but only
    /// because Ubuntu happened to ship 15.2.0 where Fedora shipped 15.2.1. The pair
    /// `distro` × `compiler` partitions it across eight, and is the actual mechanism:
    /// Ubuntu patches its gcc driver.
    ///
    /// Coarseness is the tie-break because a partition with fewer, larger groups
    /// survives more opportunities to be contradicted. It is the same standard as
    /// `groups_something`, applied to the choice between competing explanations
    /// rather than to a single one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explained_by_combination: Option<Vec<String>>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Matrix {
    pub chard_schema: String,
    /// Every axis and the distinct values seen for it.
    pub axes: BTreeMap<String, Vec<String>>,
    /// Axes with exactly one value across the whole input set.
    ///
    /// Stated explicitly because they bound what the table can support: a matrix
    /// where `arch` is invariant says nothing whatsoever about other
    /// architectures, and a reader should not have to infer that from absence.
    pub invariant_axes: Vec<String>,
    pub varying_axes: Vec<String>,
    pub cells: Vec<Cell>,
    pub variance: BTreeMap<String, Variance>,
    pub inputs: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

fn verdict_of(report: &Value, flag: &str) -> Option<String> {
    // One observation per flag: `probe::tests::every_check_has_a_distinct_flag` holds that,
    // and it is the invariant that replaced `report::rollup`'s conflict path.
    let cell = report
        .get("observations")?
        .as_array()?
        .iter()
        .find(|o| o.get("flag").and_then(Value::as_str) == Some(flag))?;
    let verdict = cell.get("verdict")?.as_str()?;
    Some(match cell.get("level").and_then(Value::as_str) {
        Some(level) if !matches!(verdict, "off" | "probe-invalid" | "indeterminate") => {
            format!("{verdict}:{level}")
        }
        _ => verdict.to_owned(),
    })
}

/// The `polarity` of the observation of `flag`, the one [`verdict_of`] reads.
fn polarity_of<'a>(report: &'a Value, flag: &str) -> Option<&'a str> {
    report
        .get("observations")?
        .as_array()?
        .iter()
        .find(|o| o.get("flag").and_then(Value::as_str) == Some(flag))?
        .get("polarity")?
        .as_str()
}

/// What [`build_with`] does with a report of a configuration an earlier report in the set
/// already holds: one whose every [`CellKey`] axis is the earlier one's.
///
/// Never a merge. Writing the later report's verdicts over the earlier's flag by flag lets a cell
/// hold verdicts no one run measured together. Measured with gcc 16.1.1 on Fedora 44 x86_64: a
/// full run, and a `--probe link-defaults` run through a wrapper adding `-no-pie` that keys
/// alike, merged that way made one cell of 72 flags, the two the runs read differently as the
/// wrapper run read them and the rest as the plain run did, and the disagreement, which is
/// what measuring one configuration twice is for, went unreported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeated {
    /// Refuse the set, naming every report that repeats an earlier one and the first report
    /// of its configuration: `chard matrix` without `--replace-repeated`.
    Refuse,
    /// The later report's cell replaces the earlier's whole (its verdicts, polarities, flags
    /// and `kernel.ownership`, nothing of the earlier kept), under a warning that names both
    /// reports, every flag both carry whose verdict or polarity differs, a differing
    /// `kernel.ownership`, and every flag only one of the two carries: `chard matrix
    /// --replace-repeated`. A third report of the configuration replaces the second's cell, and
    /// its warning compares it with the second.
    Replace,
}

/// One report's cell as [`build_with`] holds it while the set is read: what a later report
/// of the configuration replaces whole.
struct Held<'a> {
    name: &'a str,
    /// flag -> verdict, as [`verdict_of`] reads it.
    verdicts: BTreeMap<String, String>,
    /// flag -> polarity, beside each verdict that carries one.
    polarity: BTreeMap<String, String>,
    /// Every flag the report carries, with a verdict or without.
    flags: BTreeSet<String>,
    ownership: String,
}

impl<'a> Held<'a> {
    fn of(name: &'a str, report: &Value, observations: &[Value]) -> Self {
        let mut held = Self {
            name,
            verdicts: BTreeMap::new(),
            polarity: BTreeMap::new(),
            flags: BTreeSet::new(),
            ownership: ownership_of(report),
        };
        for flag in observations
            .iter()
            .filter_map(|o| o.get("flag").and_then(Value::as_str))
        {
            held.flags.insert(flag.to_owned());
            if let Some(v) = verdict_of(report, flag) {
                held.verdicts.insert(flag.to_owned(), v);
                if let Some(p) = polarity_of(report, flag) {
                    held.polarity.insert(flag.to_owned(), p.to_owned());
                }
            }
        }
        held
    }
}

/// The warning [`Repeated::Replace`] writes where `now` replaces `was` as the `unit` (a
/// matrix's cell, a table's column) of the configuration `described`: both reports, then every
/// flag both carry whose verdict (or its absence) or polarity differs, the `kernel.ownership`
/// words where they differ, every flag only `was` carried, which leaves the `unit` with it, and
/// every flag only `now` carries, which joins it.
fn replacement(described: &str, unit: &str, was: &Held, now: &Held) -> String {
    let verdict = |held: &Held, flag: &str| {
        held.verdicts
            .get(flag)
            .map_or_else(|| "no verdict".to_owned(), Clone::clone)
    };
    let differ: Vec<String> = was
        .flags
        .intersection(&now.flags)
        .filter_map(|flag| {
            let polarity_moved = was.polarity.get(flag) != now.polarity.get(flag);
            if was.verdicts.get(flag) == now.verdicts.get(flag) && !polarity_moved {
                return None;
            }
            // The polarity is said where it moved, and only there.
            let read = |held: &Held| match (polarity_moved, held.polarity.get(flag)) {
                (false, _) => verdict(held, flag),
                (true, Some(p)) => format!("{} with polarity {p}", verdict(held, flag)),
                (true, None) => format!("{} with no polarity", verdict(held, flag)),
            };
            Some(format!(
                "`{flag}` {} in {} and {} in {}",
                read(was),
                was.name,
                read(now),
                now.name
            ))
        })
        .collect();
    let mut parts = vec![format!(
        "{} repeats the configuration of {} ({described}) and replaces its whole {unit}, \
         nothing of {} kept",
        now.name, was.name, was.name
    )];
    parts.push(if differ.is_empty() {
        "The two read every flag both carry alike, verdict and polarity".to_owned()
    } else {
        format!(
            "{} flag(s) both carry read differently: {}",
            differ.len(),
            differ.join("; ")
        )
    });
    if was.ownership != now.ownership {
        parts.push(format!(
            "`kernel.ownership` is `{}` in {} and `{}` in {}",
            was.ownership, was.name, now.ownership, now.name
        ));
    }
    let only = |one: &Held, other: &Held| -> Vec<String> {
        one.flags
            .difference(&other.flags)
            .map(|flag| format!("`{flag}`"))
            .collect()
    };
    let left = only(was, now);
    if !left.is_empty() {
        parts.push(format!(
            "{} flag(s) only {} carries leave the {unit} with it: {}",
            left.len(),
            was.name,
            left.join(", ")
        ));
    }
    let joined = only(now, was);
    if !joined.is_empty() {
        parts.push(format!(
            "{} flag(s) only {} carries join the {unit}: {}",
            joined.len(),
            now.name,
            joined.join(", ")
        ));
    }
    parts.join(". ")
}

/// The warning [`Repeated::Replace`] writes where the report `now` replaces `was` as the
/// `unit` of the configuration `described`, read as [`build_with`] reads a cell: what `chard
/// table --replace-repeated` notes under a replaced column, so the two renderers name a
/// replacement in one sentence.
pub(crate) fn replacement_of(
    was: &(String, Value),
    now: &(String, Value),
    described: &str,
    unit: &str,
) -> String {
    fn held((name, report): &(String, Value)) -> Held<'_> {
        let observations = report
            .get("observations")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        Held::of(name, report, observations)
    }
    replacement(described, unit, &held(was), &held(now))
}

/// [`build_with`] refusing a repeated configuration ([`Repeated::Refuse`]).
///
/// # Errors
///
/// Those of [`build_with`].
pub fn build(reports: &[(String, Value)]) -> Result<Matrix> {
    build_with(reports, Repeated::Refuse)
}

/// Build a cross-tab over `reports`, one report per cell: a report of a configuration an
/// earlier one holds is refused or replaces that cell whole, as `repeated` says.
///
/// # Errors
///
/// Errors when a document is not a chard report, and under [`Repeated::Refuse`] when two
/// reports are of one configuration: a [`crate::error::UserError`] naming every repeat.
///
/// # Panics
///
/// Where a cell's polarity map was not made beside its verdicts, which the loop that makes
/// both rules out.
#[allow(
    clippy::too_many_lines,
    reason = "one derivation: ingest, find the varying axes, then per flag decide which \
              axis accounts for it. The axis analysis depends on the axis discovery that \
              precedes it, and splitting them would hide that ordering."
)]
pub fn build_with(reports: &[(String, Value)], repeated: Repeated) -> Result<Matrix> {
    if reports.is_empty() {
        bail!("no reports given");
    }
    let mut warnings = Vec::new();
    let mut held: BTreeMap<CellKey, Held> = BTreeMap::new();
    let mut repeats = Vec::new();

    for (name, report) in reports {
        let Some(observations) = report.get("observations").and_then(Value::as_array) else {
            return Err(crate::dataset::not_a_report(name, "it carries no observations").into());
        };
        let key = key_of(report);
        let now = Held::of(name, report, observations);
        match (held.get(&key), repeated) {
            (Some(was), Repeated::Refuse) => {
                repeats.push(format!("{name} repeats {} ({})", was.name, key.describe()));
                continue;
            }
            (Some(was), Repeated::Replace) => {
                warnings.push(replacement(&key.describe(), "cell", was, &now));
            }
            (None, _) => {}
        }
        held.insert(key, now);
    }
    if !repeats.is_empty() {
        return Err(crate::error::UserError::with_hint(
            format!(
                "these reports repeat a configuration: a matrix cell holds one report, and two \
                 reports alike on every axis of its key ({}) are one cell. The key holds no probe \
                 selection, compiler wrapper or chard revision, so two runs that differ only \
                 there key alike:\n  {}",
                AXES.join(", "),
                repeats.join("\n  ")
            ),
            "leave out all but one report of each configuration, or pass --replace-repeated \
             to keep the later report's whole cell, with every flag the two read differently \
             named in the matrix's warnings",
        )
        .into());
    }

    // The flags are those of the reports the cells hold, so a replaced report's leave with it.
    let flags: BTreeSet<String> = held.values().flat_map(|h| h.flags.clone()).collect();
    let mut cells: BTreeMap<CellKey, BTreeMap<String, String>> = BTreeMap::new();
    let mut polarities: BTreeMap<CellKey, BTreeMap<String, String>> = BTreeMap::new();
    let mut ownership: BTreeMap<CellKey, String> = BTreeMap::new();
    for (key, h) in held {
        cells.insert(key.clone(), h.verdicts);
        polarities.insert(key.clone(), h.polarity);
        ownership.insert(key, h.ownership);
    }

    // Which axes actually move.
    let mut axes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for axis in AXES {
        let mut values: BTreeSet<String> = BTreeSet::new();
        for key in cells.keys() {
            let v = key.axis(axis);
            if !v.is_empty() {
                values.insert(v.to_owned());
            }
        }
        axes.insert((*axis).to_owned(), values.into_iter().collect());
    }
    let varying: Vec<String> = AXES
        .iter()
        .filter(|a| axes.get(**a).is_some_and(|v| v.len() > 1))
        .map(|a| (*a).to_owned())
        .collect();
    let invariant: Vec<String> = AXES
        .iter()
        .filter(|a| axes.get(**a).is_some_and(|v| v.len() <= 1))
        .map(|a| (*a).to_owned())
        .collect();

    // Per flag: what varied, and which axis accounts for it.
    let mut variance = BTreeMap::new();
    for flag in &flags {
        let mut verdicts: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, got) in &cells {
            if let Some(v) = got.get(flag) {
                verdicts
                    .entry(v.clone())
                    .or_default()
                    .push(key.label(&varying));
            }
        }
        let varies = verdicts.len() > 1;

        // An axis explains the flag when every group sharing an axis value agrees
        // AND the axis actually groups something.
        //
        // The second condition is not a nicety. An axis that takes a distinct value
        // for every observation — one report per distribution, say — satisfies
        // "every group agrees" vacuously, because every group has one member. It is
        // then an identifier for the observation rather than an explanation of it,
        // and reporting it would let a table claim the distribution explains a
        // compiler-version boundary purely because the inputs happened to be one
        // report per distribution.
        let mut explained_by = Vec::new();
        let mut vacuous = Vec::new();
        if varies {
            for axis in &varying {
                let mut by_value: BTreeMap<&str, (BTreeSet<&String>, usize)> = BTreeMap::new();
                for (key, got) in &cells {
                    if let Some(v) = got.get(flag) {
                        let slot = by_value.entry(key.axis(axis)).or_default();
                        slot.0.insert(v);
                        slot.1 = slot.1.saturating_add(1);
                    }
                }
                let consistent = by_value.values().all(|(verdicts, _)| verdicts.len() == 1);
                let groups_something = by_value.values().any(|(_, n)| *n >= 2);
                if consistent && groups_something {
                    explained_by.push(axis.clone());
                } else if consistent {
                    vacuous.push(axis.clone());
                }
            }
        }

        // A vacuously-consistent axis is still the answer when it is the only thing
        // that changed: two reports differing solely in libc are a controlled
        // comparison, and the libc explains the difference even though neither
        // group has two members. What must not happen is preferring such an axis
        // when a genuinely grouping one exists — that is the one-report-per-distro
        // trap. So grouping explanations win, and vacuous ones are the fallback,
        // marked weaker.
        let strength = if !explained_by.is_empty() {
            "grouped"
        } else if !vacuous.is_empty() {
            explained_by.clone_from(&vacuous);
            "controlled"
        } else {
            "none"
        };

        // For each explaining axis, which coarser axes it cannot be told apart from.
        //
        // `a` is nested in `b` when every value of `a` occurs under exactly one value
        // of `b`. A nested axis induces a refinement of the coarser partition, so any
        // pattern it appears to explain is equally consistent with the coarser axis
        // explaining it, and the inputs contain no observation that could distinguish
        // them. Identical partitions are mutually nested and reported both ways,
        // which is correct: neither is preferable on this evidence.
        let mut confounded_with: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for axis in &explained_by {
            let mut coarser = Vec::new();
            for other in &varying {
                if other == axis || is_structural_refinement(axis, other) {
                    continue;
                }
                // Over the cells that carry this flag, and only those.
                //
                // This iterated every cell, while `explained_by` above counts only cells
                // where `got.get(flag)` is `Some`. The two therefore ranged over
                // different spans, and the wider one suppressed the warning: a report
                // that does not carry the flag at all still contributed cross-links,
                // pushing the count to the threshold and removing the coarser axis from
                // `confounded_with`.
                //
                // Measured. Three reports carrying `-fPIE`, with distro nested inside
                // compiler_version, report `confounded_with: {compiler_version:
                // [distro, release], distro: [release, compiler_version]}`. Adding two
                // reports that do not carry `-fPIE` leaves the verdicts byte-identical
                // and `observed_in: 3` unchanged, and `confounded_with` disappears — the
                // evidence about the flag did not move, only the span it was counted
                // over. Evidence that cannot speak about a flag must not be allowed to
                // vouch for what explains it.
                let mut companions: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
                for (key, got) in &cells {
                    if !got.contains_key(flag) {
                        continue;
                    }
                    companions
                        .entry(key.axis(axis))
                        .or_default()
                        .insert(key.axis(other));
                }
                // A cross-link is one value of `axis` observed under two values of
                // `other` — the only kind of observation that can tell the two apart.
                // Two are required, for the same reason `groups_something` requires a
                // group of two: a single pair is an anecdote, not a pattern, and the
                // module already refuses to treat one observation as evidence.
                //
                // This threshold is what catches the real case. Every gcc version in
                // the sweep was unique to one distribution, and the sole cross-link
                // was clang 21.1.8 on both Fedora 43 and Ubuntu 26.04 — one pair,
                // sitting inside a single verdict group, so it says nothing about
                // where the boundary comes from.
                let cross_links = companions.values().filter(|seen| seen.len() > 1).count();
                if cross_links < 2 {
                    coarser.push(other.clone());
                }
            }
            if !coarser.is_empty() {
                confounded_with.insert(axis.clone(), coarser);
            }
        }

        // The coarsest explaining pair of axes, when it beats every single axis.
        //
        // Only pairs: a triple would almost always "explain" something by giving
        // each observation its own group, which is the vacuity this whole section
        // guards against, and the mechanisms chard actually models — a distribution
        // patching one compiler — are two-factor.
        // The measure of an explanation is the size of its largest agreeing group,
        // not the number of groups it uses.
        //
        // Counting groups looked reasonable and was not: `compiler` × `libc`
        // partitioned `-Werror=implicit-function-declaration` into fourteen groups
        // where `compiler_version` needed fifteen, won by that one group, and thereby
        // claimed the libc explains a GCC-14 language boundary. libc version is a
        // proxy for the release, which is a proxy for the compiler version, so the
        // margin was an artifact of the correlation rather than evidence.
        //
        // Largest-agreeing-group is the same standard `groups_something` already
        // applies — a group of one is an identifier, a group of many is a pattern —
        // extended to choosing between explanations. `distro` × `compiler` holds
        // Ubuntu's four gcc releases in one agreeing group of four, where no single
        // compiler version groups more than two observations, so it wins on evidence
        // instead of on arithmetic.
        let largest_group = |axes: &[&String]| -> usize {
            let mut sizes: BTreeMap<Vec<String>, usize> = BTreeMap::new();
            for (key, got) in &cells {
                if got.get(flag).is_some() {
                    let k = axes.iter().map(|a| key.axis(a).to_owned()).collect();
                    let n = sizes.entry(k).or_default();
                    *n = n.saturating_add(1);
                }
            }
            sizes.values().copied().max().unwrap_or(0)
        };
        let best_single = explained_by
            .iter()
            .map(|a| largest_group(&[a]))
            .max()
            .unwrap_or(0);
        let mut explained_by_combination: Option<Vec<String>> = None;
        if varies {
            let mut best = best_single;
            // An axis already known to be inseparable from the single explanation
            // cannot contribute a genuinely different one. `-Werror=implicit-
            // function-declaration` is the case: it flips at GCC 14, `libc` is
            // confounded with `compiler_version` because each release ships its own
            // glibc, and the pair `compiler` × `libc` therefore scored better than
            // `compiler_version` while being a restatement of it wearing the libc's
            // name. A reader would take it to mean the C library decides whether an
            // undeclared call is an error.
            let inseparable: BTreeSet<&String> = explained_by
                .iter()
                .filter_map(|a| confounded_with.get(a))
                .flatten()
                .collect();
            for (i, a) in varying.iter().enumerate() {
                for b in varying.iter().skip(i.saturating_add(1)) {
                    if inseparable.contains(a) || inseparable.contains(b) {
                        continue;
                    }
                    let mut by_pair: BTreeMap<(String, String), (BTreeSet<&String>, usize)> =
                        BTreeMap::new();
                    for (key, got) in &cells {
                        if let Some(v) = got.get(flag) {
                            let slot = by_pair
                                .entry((key.axis(a).to_owned(), key.axis(b).to_owned()))
                                .or_default();
                            slot.0.insert(v);
                            slot.1 = slot.1.saturating_add(1);
                        }
                    }
                    let consistent = by_pair.values().all(|(verdicts, _)| verdicts.len() == 1);
                    let n = largest_group(&[a, b]);
                    if consistent && n >= 2 && n > best {
                        best = n;
                        explained_by_combination = Some(vec![a.clone(), b.clone()]);
                    }
                }
            }
        }

        // How many cells actually carried this flag. A flag absent from a cell is dropped by
        // `verdict_of`, so `verdicts` covers a subset of the input set — and the note said "the same
        // everywhere in this input set" over that subset, including over a subset of one and over an
        // empty one. Measured on a real mixed-corpus pair: 22 of 43 flags asserted agreement across
        // "this input set" on a single observation, with `inputs: 2` at the top of the document, and
        // a cell whose `verdict` key was missing produced `verdicts: {}` — zero observations — with
        // the same affirmative note. The global guard (`cells.len() < 2`) cannot fire for a per-flag
        // shortfall.
        let observed_in: usize = verdicts.values().map(Vec::len).sum();
        let note = if observed_in < 2 {
            format!(
                "observed in {observed_in} of {} configurations, which is too few to say whether \
                 it varies — a group of one is an identifier, not a pattern",
                cells.len()
            )
        } else if !varies {
            format!("the same in all {observed_in} configurations that carried it")
        } else if let Some(ref pair) = explained_by_combination {
            let single = explained_by
                .first()
                .cloned()
                .unwrap_or_else(|| "nothing".to_owned());
            format!(
                "best accounted for by {pair:?} together, which holds more agreeing \
                 observations in a single group than any one axis manages. `{single}` also \
                 partitions these observations consistently, but only across smaller groups, \
                 so it fits more cheaply and is the weaker claim."
            )
        } else if explained_by.is_empty() {
            "no single axis accounts for the variation — it needs more than one, or the \
             inputs are too few to separate them"
                .to_owned()
        } else if let [only] = explained_by.as_slice() {
            if let Some(coarser) = confounded_with.get(only) {
                // The confound is the headline when there is one: the axis fits, but
                // so would each of these, and no observation here separates them.
                format!(
                    "consistent with `{only}`, but these inputs cannot separate it from \
                     {coarser:?}: every value of `{only}` occurs under exactly one value of \
                     each. Attributing the pattern to `{only}` would therefore overstate what \
                     was measured. To separate them, add an observation that shares a `{only}` \
                     value across two values of {coarser:?}."
                )
            } else if strength == "grouped" {
                format!(
                    "fully accounted for by `{only}`: every group of observations sharing a \
                     value agrees, at least one such group has more than one member, and no \
                     coarser axis shadows it"
                )
            } else {
                format!(
                    "consistent with `{only}` as the only axis that changed, but no group has \
                     more than one member — a controlled comparison rather than a demonstrated \
                     pattern. More configurations would strengthen it."
                )
            }
        } else {
            format!(
                "consistent with any of {explained_by:?} — these inputs cannot tell them \
                 apart, which is a limit of the data rather than an ambiguity to resolve"
            )
        };

        variance.insert(
            flag.clone(),
            Variance {
                varies,
                observed_in,
                of_configurations: cells.len(),
                verdicts,
                explained_by,
                strength: strength.to_owned(),
                confounded_with,
                explained_by_combination,
                note,
            },
        );
    }

    if cells.len() < 2 {
        warnings.push(
            "only one configuration was supplied, so nothing can be attributed to any axis"
                .to_owned(),
        );
    }

    // A report that contradicts itself is not here: `build_from_reports` refuses the set
    // (`dataset::refuse_self_contradicted`).

    // `polarities` gains a key exactly where `cells` does, so the two walk in step.
    assert!(
        cells.keys().eq(polarities.keys()),
        "every cell's polarity map is made beside its verdicts"
    );
    let out_cells = cells
        .into_iter()
        .zip(polarities.into_values())
        .map(|((key, flags), polarity)| Cell {
            label: key.label(&varying),
            polarity,
            kernel_ownership: ownership
                .get(&key)
                .cloned()
                .unwrap_or_else(|| UNPUBLISHED_OWNERSHIP.to_owned()),
            key,
            flags,
        })
        .collect();

    Ok(Matrix {
        chard_schema: MATRIX_SCHEMA_VERSION.to_owned(),
        axes,
        invariant_axes: invariant,
        varying_axes: varying,
        cells: out_cells,
        variance,
        inputs: reports.len(),
        warnings,
    })
}

/// Read report files and cross-tabulate them.
///
/// Refuses reports that do not belong to one dataset unless `allow_mixed`. A matrix
/// attributes outcomes to axes, so it is a stronger claim than a table: an axis is
/// "explanatory" only if the observations grouped under it were produced by the same
/// instrument. Two probe corpora in one input set can make a *change to chard* look
/// like a property of a distribution, which is the failure mode this whole crate is
/// organised against.
///
/// # Errors
///
/// Errors when a file cannot be read or parsed, is not a chard report, belongs to a
/// different dataset than the others without `allow_mixed`, or repeats another's
/// configuration under [`Repeated::Refuse`].
pub fn build_from_files(
    paths: &[std::path::PathBuf],
    allow_mixed: bool,
    repeated: Repeated,
) -> Result<Matrix> {
    let reports = crate::dataset::read_reports(paths)?;
    build_from_reports(&reports, allow_mixed, repeated)
}

/// [`build_from_files`] over reports already read, as `table::render_reports` is for the
/// table: `main` reads first, sets an earlier `-o` output aside, then judges the set here.
///
/// # Errors
///
/// A set that is not one dataset without `allow_mixed`, one that repeats a configuration
/// under [`Repeated::Refuse`], or one holding a report `dataset::refuse_self_contradicted`
/// names.
pub fn build_from_reports(
    reports: &[(String, Value)],
    allow_mixed: bool,
    repeated: Repeated,
) -> Result<Matrix> {
    let identity = crate::dataset::Identity::of(reports);
    let conflicts = identity.conflicts();
    if !conflicts.is_empty() && !allow_mixed {
        // See the note in `table::render_files`: a mismatched input set is the
        // operator's invocation, not a chard defect, and the error class decides which
        // of those a caller is told.
        return Err(crate::error::UserError::with_hint(
            format!(
                "these reports are not one dataset, so a matrix of them could attribute \
                 a change in chard to a distribution:\n  {}",
                conflicts.join("\n  ")
            ),
            "pass --allow-mixed to build it anyway: the matrix will carry the conflict \
             in its own warnings",
        )
        .into());
    }

    let mut matrix = build_with(reports, repeated)?;
    // As in `table::render_files`: after the shape is read, refused rather than warned.
    crate::dataset::refuse_self_contradicted(reports)?;
    // Into the document, not onto stderr. A matrix is consumed by machines and pasted
    // by people, and neither reads the terminal it was produced in.
    matrix.warnings.splice(
        0..0,
        conflicts
            .into_iter()
            .map(|c| format!("MIXED DATASET: {c}"))
            .chain(identity.cautions())
            .chain(crate::dataset::moved_rule_notes(reports)),
    );
    Ok(matrix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every axis in `AXES` reaches its own field, and no two reach the same one.
    ///
    /// `CellKey::axis` is a string-to-field lookup with a `_ => ""` fallthrough, so a
    /// missing arm does not fail to compile: it makes that axis read as empty on every
    /// specimen, which reads as "this axis does not vary" — the axis vanishes from
    /// `varying`, joins `invariant`, and a difference the sweep actually measured stops
    /// being attributable to it. Four arms could be deleted without any test noticing.
    #[test]
    fn every_axis_reads_its_own_field() {
        let key = CellKey {
            distro: "distro-v".to_owned(),
            release: "release-v".to_owned(),
            compiler: "compiler-v".to_owned(),
            compiler_version: "compiler_version-v".to_owned(),
            libc: "libc-v".to_owned(),
            arch: "arch-v".to_owned(),
            profile: "profile-v".to_owned(),
            execution: "execution-v".to_owned(),
            execution_basis: "execution_basis-v".to_owned(),
            image: "image-v".to_owned(),
        };

        for axis in AXES {
            assert_eq!(
                key.axis(axis),
                format!("{axis}-v"),
                "axis `{axis}` does not read the field of that name — a deleted arm here \
                 makes the axis read empty everywhere, which renders as an axis that does \
                 not vary"
            );
        }

        // The fallthrough is for a name that is not an axis, and must not be reachable
        // from `AXES` itself.
        assert_eq!(key.axis("not-an-axis"), "");
    }

    /// A level is appended only to a verdict that has one to report.
    ///
    /// `off:strong` and `probe-invalid:2` are the readings this guard exists to prevent:
    /// an observation can carry a `level` beside a verdict that withheld, and pasting the
    /// two together renders a strength for a protection that is not there. Three mutants
    /// lived on this one guard — the negation, and forcing it to each constant.
    #[test]
    fn a_level_is_rendered_only_beside_a_verdict_that_earned_one() {
        let cell = |verdict: &str, level: Option<&str>| {
            let mut obs = json!({"flag": "-Dflag", "verdict": verdict});
            if let Some(level) = level {
                obs["level"] = json!(level);
            }
            let report = json!({"observations": [obs]});
            verdict_of(&report, "-Dflag").expect("the flag is in the report")
        };

        assert_eq!(cell("on", Some("strong")), "on:strong");
        assert_eq!(cell("partial", Some("2")), "partial:2");
        assert_eq!(
            cell("on", None),
            "on",
            "no level to report is not an empty level"
        );

        for withheld in ["off", "probe-invalid", "indeterminate"] {
            assert_eq!(
                cell(withheld, Some("strong")),
                withheld,
                "`{withheld}` withheld, so a level beside it describes nothing that happened"
            );
        }

        // A flag the report does not carry is absent rather than empty.
        let report = json!({"observations": [{"flag": "-Dother", "verdict": "on"}]});
        assert!(verdict_of(&report, "-Dflag").is_none());
    }

    /// A distribution that patches one of its compilers must be attributed to
    /// `distro` × `compiler`, not to `compiler_version`.
    ///
    /// This is the LTS sweep's central result reduced to a fixture. Ubuntu's gcc
    /// carries a canary across every release; its clang does not, and neither does
    /// Fedora's gcc. `compiler_version` partitions that perfectly — no version string
    /// appears on both sides — purely because each distribution ships its own patch
    /// level, so reporting it would tell a reader that upstream GCC decides, which is
    /// the opposite of the truth. The pair holds Ubuntu's three gcc observations in
    /// one agreeing group, so it wins on evidence rather than on arithmetic.
    #[test]
    fn a_distro_patching_one_compiler_is_attributed_to_distro_and_compiler() {
        let on = &[("-fstack-protector-strong", "on")][..];
        let off = &[("-fstack-protector-strong", "off")][..];
        let reports = vec![
            (
                "a".to_owned(),
                report("ubuntu", "20.04", "gcc", "9.4.0", "glibc", "bare", on),
            ),
            (
                "b".to_owned(),
                report("ubuntu", "22.04", "gcc", "11.4.0", "glibc", "bare", on),
            ),
            (
                "c".to_owned(),
                report("ubuntu", "24.04", "gcc", "13.3.0", "glibc", "bare", on),
            ),
            (
                "d".to_owned(),
                report("ubuntu", "24.04", "clang", "18.1.3", "glibc", "bare", off),
            ),
            (
                "e".to_owned(),
                report("fedora", "43", "gcc", "15.2.1", "glibc", "bare", off),
            ),
            (
                "f".to_owned(),
                report("fedora", "43", "clang", "21.1.8", "glibc", "bare", off),
            ),
            // These three are what make `distro` separable from `compiler_version`
            // at all, and they are not invented: clang 21.1.8 really does appear on
            // both Fedora 43 and Ubuntu 26.04 in the sweep, and 22.1.8 on both
            // Fedora 44 and openSUSE. Without such a pair the honest answer is
            // "cannot separate", which the next test pins.
            (
                "g".to_owned(),
                report("ubuntu", "26.04", "clang", "21.1.8", "glibc", "bare", off),
            ),
            (
                "h".to_owned(),
                report("fedora", "44", "clang", "22.1.8", "glibc", "bare", off),
            ),
            (
                "i".to_owned(),
                report("opensuse", "2026", "clang", "22.1.8", "glibc", "bare", off),
            ),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-fstack-protector-strong"];
        assert_eq!(
            v.explained_by_combination,
            Some(vec!["distro".to_owned(), "compiler".to_owned()]),
            "the mechanism is a distribution patching one compiler; got note: {}",
            v.note
        );
    }

    /// Without an observation sharing a compiler version across distributions, the
    /// pair must be withheld rather than asserted.
    ///
    /// Same shape as the test above, minus the cross-distro rows. Here every
    /// compiler version belongs to exactly one distribution, so "the distribution
    /// patches its compiler" and "these compiler versions simply differ" predict
    /// the identical table and nothing in the data chooses between them. Reporting
    /// `distro` x `compiler` anyway would be the vacuous-explanation bug in a new
    /// costume: asserting a mechanism the inputs cannot witness.
    #[test]
    fn without_a_cross_distro_version_the_pair_is_withheld() {
        let on = &[("-fstack-protector-strong", "on")][..];
        let off = &[("-fstack-protector-strong", "off")][..];
        let reports = vec![
            (
                "a".to_owned(),
                report("ubuntu", "20.04", "gcc", "9.4.0", "glibc", "bare", on),
            ),
            (
                "b".to_owned(),
                report("ubuntu", "22.04", "gcc", "11.4.0", "glibc", "bare", on),
            ),
            (
                "c".to_owned(),
                report("ubuntu", "24.04", "clang", "18.1.3", "glibc", "bare", off),
            ),
            (
                "d".to_owned(),
                report("fedora", "43", "gcc", "15.2.1", "glibc", "bare", off),
            ),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-fstack-protector-strong"];
        assert_eq!(
            v.explained_by_combination, None,
            "no cross-distro version exists, so the pair is not witnessed: {}",
            v.note
        );
        assert!(
            v.confounded_with
                .get("compiler_version")
                .is_some_and(|c| c.contains(&"distro".to_owned())),
            "and the report must say distro cannot be separated"
        );
    }

    /// A genuine compiler-version boundary must not be displaced by a pair.
    ///
    /// When the same compiler version appears under two distributions and agrees,
    /// that is direct evidence the version is what matters, and no pair should hold a
    /// larger agreeing group than the version itself.
    #[test]
    fn a_version_boundary_witnessed_across_distros_keeps_its_attribution() {
        let reports = vec![
            (
                "a".to_owned(),
                report(
                    "fedora",
                    "43",
                    "gcc",
                    "15.2",
                    "glibc",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "b".to_owned(),
                report(
                    "ubuntu",
                    "26.04",
                    "gcc",
                    "15.2",
                    "glibc",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "c".to_owned(),
                report(
                    "fedora",
                    "41",
                    "gcc",
                    "13.1",
                    "glibc",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
            (
                "d".to_owned(),
                report(
                    "ubuntu",
                    "24.04",
                    "gcc",
                    "13.1",
                    "glibc",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-fx"];
        assert!(
            v.explained_by.contains(&"compiler_version".to_owned()),
            "the version is witnessed on two distros and must be credited"
        );
        assert_eq!(
            v.explained_by_combination, None,
            "no pair should displace a directly witnessed version boundary"
        );
        assert!(
            !v.confounded_with.contains_key("compiler_version"),
            "two cross-distro version pairs separate version from distro"
        );
    }

    /// An axis wholly nested inside the explaining one is reported as inseparable.
    ///
    /// Here every compiler version occurs under exactly one libc, so "the version
    /// explains it" and "the libc explains it" are the same claim about this data.
    /// Saying only the former would overstate what was measured.
    #[test]
    fn an_axis_nested_in_the_explainer_is_named_as_inseparable() {
        let reports = vec![
            (
                "a".to_owned(),
                report(
                    "ubuntu",
                    "20.04",
                    "gcc",
                    "9.4.0",
                    "glibc2.31",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
            (
                "b".to_owned(),
                report(
                    "ubuntu",
                    "22.04",
                    "gcc",
                    "11.4.0",
                    "glibc2.35",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
            (
                "c".to_owned(),
                report(
                    "ubuntu",
                    "24.04",
                    "gcc",
                    "13.3.0",
                    "glibc2.39",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "d".to_owned(),
                report(
                    "ubuntu",
                    "26.04",
                    "gcc",
                    "15.2.0",
                    "glibc2.43",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.contains(&"compiler_version".to_owned()));
        let confounds = v
            .confounded_with
            .get("compiler_version")
            .expect("libc is nested in compiler_version here");
        assert!(
            confounds.contains(&"libc".to_owned()),
            "got {confounds:?} — libc moves in lockstep with the version in this input"
        );
    }

    /// A report of one configuration on `mode` with `basis` (none: no `mode_evidence`, as a
    /// report written before the field existed), reading `noexecstack-enforced` as `verdict`.
    fn on_execution(mode: &str, basis: Option<&str>, verdict: &str) -> Value {
        let mut execution = json!({"mode": mode});
        let mut kernel = json!({"arch": "x86_64"});
        if let Some(basis) = basis {
            execution["mode_evidence"] = json!({"basis": basis, "observation": "no marker"});
            // The word `measure` writes for this mode and basis, from the one derivation.
            let mode_of = crate::env::ExecutionMode::ALL
                .iter()
                .find(|m| m.as_str() == mode)
                .expect("a mode chard writes");
            let basis_of = crate::env::ModeBasis::ALL
                .iter()
                .find(|b| b.as_str() == basis)
                .expect("a basis chard writes");
            let word: crate::env::KernelOwnership =
                crate::env::KernelAttribution::of(*mode_of, *basis_of, "").into();
            kernel["ownership"] = json!(word.as_str());
        }
        json!({
            "environment": {
                "distro": {"id": "fedora", "version_id": "44"},
                "libc": {"impl": "glibc", "version": "2.43"},
                "kernel": kernel,
                "execution": execution,
            },
            "toolchain": {"kind": "gcc", "version": "16.1.1"},
            "profile": {"id": "bare"},
            "observations": [
                {"flag": "noexecstack-enforced", "verdict": verdict},
                {"flag": "pie", "verdict": "on"},
            ],
        })
    }

    /// The labels of a matrix's cells, in cell order.
    fn labels(m: &Matrix) -> Vec<&str> {
        m.cells.iter().map(|c| c.label.as_str()).collect()
    }

    /// A report on the default and an asserted `--execution host` report of one configuration
    /// are two cells.
    ///
    /// Both read `environment.execution.mode` `host`, and only `mode_evidence.basis` tells them
    /// apart (`assumed-host` against `asserted-but-unobservable`); the default withholds the two
    /// `needs_vm` checks where the assertion measures them. Keyed on the mode alone the two
    /// would be one cell, and the check would read `varies: false`.
    #[test]
    fn a_report_on_the_default_and_an_asserted_one_are_two_cells() {
        let reports = [
            (
                "default.json".to_owned(),
                on_execution("host", Some("assumed-host"), "indeterminate"),
            ),
            (
                "asserted.json".to_owned(),
                on_execution("host", Some("asserted-but-unobservable"), "on"),
            ),
        ];
        for order in [[0, 1], [1, 0]] {
            let inputs = order.map(|i| reports[i].clone());
            let m = build(&inputs).expect("two reports build a matrix");

            assert_eq!(
                m.cells.len(),
                2,
                "a report on the default and an asserted one became one cell: {:?}",
                m.cells
            );
            assert!(m.warnings.is_empty(), "{:?}", m.warnings);
            assert_eq!(m.varying_axes, ["execution_basis"]);
            assert_eq!(
                m.axes["execution_basis"],
                ["asserted-but-unobservable", "assumed-host"]
            );
            assert_eq!(labels(&m), ["asserted-but-unobservable", "assumed-host"]);
            let owners: Vec<&str> = m
                .cells
                .iter()
                .map(|c| c.kernel_ownership.as_str())
                .collect();
            assert_eq!(owners, ["own", "unsettled"]);
            let check = &m.variance["noexecstack-enforced"];
            assert!(check.varies, "{check:?}");
            assert_eq!(check.verdicts["indeterminate"], ["assumed-host"]);
            assert_eq!(check.verdicts["on"], ["asserted-but-unobservable"]);
            assert_eq!(check.explained_by, ["execution_basis"]);
            assert!(!m.variance["pie"].varies);
        }
    }

    /// A report that publishes no basis is a cell of its own, named `unpublished`.
    ///
    /// Read as an empty string, the missing basis was skipped by `axes` and by the label, so
    /// beside a report on `assumed-host` the axis read invariant, both cells were labelled
    /// `(single configuration)` and the check that differed between them was explained by
    /// nothing: two cells a reader could not tell apart.
    #[test]
    fn a_report_without_a_basis_is_a_cell_of_its_own() {
        let reports = [
            ("earlier.json".to_owned(), on_execution("host", None, "on")),
            (
                "default.json".to_owned(),
                on_execution("host", Some("assumed-host"), "indeterminate"),
            ),
            (
                "asserted.json".to_owned(),
                on_execution("host", Some("asserted-but-unobservable"), "on"),
            ),
        ];
        for order in [[0, 1, 2], [2, 1, 0]] {
            let inputs = order.map(|i| reports[i].clone());
            let m = build(&inputs).expect("three reports build a matrix");

            assert_eq!(m.cells.len(), 3, "{:?}", m.cells);
            assert!(m.warnings.is_empty(), "{:?}", m.warnings);
            assert_eq!(m.varying_axes, ["execution_basis"]);
            assert_eq!(
                m.axes["execution_basis"],
                [
                    "asserted-but-unobservable",
                    "assumed-host",
                    UNPUBLISHED_BASIS
                ]
            );
            assert_eq!(
                labels(&m),
                [
                    "asserted-but-unobservable",
                    "assumed-host",
                    UNPUBLISHED_BASIS
                ]
            );
            let owners: Vec<&str> = m
                .cells
                .iter()
                .map(|c| c.kernel_ownership.as_str())
                .collect();
            assert_eq!(owners, ["own", "unsettled", UNPUBLISHED_OWNERSHIP]);
            let check = &m.variance["noexecstack-enforced"];
            assert_eq!(check.verdicts["indeterminate"], ["assumed-host"]);
            assert_eq!(
                check.verdicts["on"],
                ["asserted-but-unobservable", UNPUBLISHED_BASIS]
            );
            assert_eq!(check.explained_by, ["execution_basis"]);
        }

        // A basis that is present but not a string, or empty, is no basis either.
        for basis in [json!(7), json!(null), json!("")] {
            let mut report = on_execution("host", Some("assumed-host"), "on");
            report["environment"]["execution"]["mode_evidence"]["basis"] = basis;
            assert_eq!(key_of(&report).execution_basis, UNPUBLISHED_BASIS);
        }
    }

    /// The basis sits beside the mode it qualifies, in `AXES` and so in every label.
    ///
    /// `varying_axes` and the labels follow `AXES` order, and an axis that does not vary drops
    /// out of both, so moving `execution_basis` past `image` passed every other test.
    #[test]
    fn the_basis_follows_the_mode_it_qualifies() {
        let at = |axis: &str| AXES.iter().position(|a| *a == axis);
        assert_eq!(
            at("execution_basis"),
            at("execution").map(|i| i + 1),
            "`execution_basis` must follow `execution` in AXES: {AXES:?}"
        );

        let reports = [
            (
                "container.json".to_owned(),
                on_execution("container", Some("measured"), "indeterminate"),
            ),
            (
                "default.json".to_owned(),
                on_execution("host", Some("assumed-host"), "indeterminate"),
            ),
        ];
        let m = build(&reports).expect("two reports build a matrix");
        assert_eq!(m.varying_axes, ["execution", "execution_basis"]);
        assert_eq!(labels(&m), ["container / measured", "host / assumed-host"]);
        let owners: Vec<&str> = m
            .cells
            .iter()
            .map(|c| c.kernel_ownership.as_str())
            .collect();
        assert_eq!(owners, ["borrowed", "unsettled"]);

        // Two reports of one cell are refused; replaced, the cell's word is the later report's,
        // as its verdicts are, published or not, and a word that differs is named.
        let published = on_execution("host", Some("assumed-host"), "indeterminate");
        let mut older = published.clone();
        older["environment"]["kernel"]
            .as_object_mut()
            .expect("a kernel object")
            .remove("ownership");
        // Two words in one cell, which the reread refuses before `build`.
        let mut other = published.clone();
        other["environment"]["kernel"]["ownership"] = json!("own");
        for (later, word) in [(&older, UNPUBLISHED_OWNERSHIP), (&other, "own")] {
            let pair = [
                ("published.json".to_owned(), published.clone()),
                ("later.json".to_owned(), later.clone()),
            ];
            assert!(build(&pair).is_err(), "a repeated configuration is refused");
            let m = build_with(&pair, Repeated::Replace).expect("replaced");
            assert_eq!(m.cells.len(), 1, "{:?}", m.cells);
            assert_eq!(m.cells[0].kernel_ownership, word);
            let named = format!(
                "`kernel.ownership` is `unsettled` in published.json and `{word}` in later.json"
            );
            assert!(
                m.warnings.iter().any(|w| w.contains(&named)),
                "{named}: {:?}",
                m.warnings
            );
        }
        // A word that is present but not a string, or empty, is unpublished too.
        for word in [json!(7), json!(null), json!("")] {
            let mut report = on_execution("host", Some("assumed-host"), "on");
            report["environment"]["kernel"]["ownership"] = word;
            assert_eq!(ownership_of(&report), UNPUBLISHED_OWNERSHIP);
        }
    }

    fn report(
        distro: &str,
        release: &str,
        kind: &str,
        version: &str,
        libc: &str,
        profile: &str,
        flags: &[(&str, &str)],
    ) -> Value {
        let observations: Vec<Value> = flags
            .iter()
            .map(|(f, v)| json!({"flag": f, "verdict": v}))
            .collect();
        json!({
            "environment": {
                "distro": {"id": distro, "version_id": release},
                "libc": {"impl": libc},
                "kernel": {"arch": "x86_64"},
                "execution": {"mode": "vm"},
            },
            "toolchain": {"kind": kind, "version": version},
            "profile": {"id": profile},
            "observations": Value::Array(observations),
        })
    }

    /// Each cell carries every flag's polarity beside its verdict, from the observation the
    /// verdict came from, and a later report that replaces a cell ([`Repeated::Replace`])
    /// replaces the polarity with the verdict.
    #[test]
    fn a_cell_carries_each_flags_polarity_beside_its_verdict() {
        let with_polarity = |rpath: &str| {
            let mut r = report(
                "fedora",
                "44",
                "gcc",
                "16",
                "glibc",
                "bare",
                &[("-Wl,-rpath", "off"), ("-pie", "on")],
            );
            r["observations"][0]["polarity"] = rpath.into();
            r["observations"][1]["polarity"] = "harden".into();
            r
        };
        let m = build(&[("a.json".to_owned(), with_polarity("weaken"))]).expect("builds");
        let cell = &m.cells[0];
        assert_eq!(cell.flags["-Wl,-rpath"], "off");
        assert_eq!(cell.polarity["-Wl,-rpath"], "weaken");
        assert_eq!(cell.polarity["-pie"], "harden");
        let m = build_with(
            &[
                ("a.json".to_owned(), with_polarity("weaken")),
                ("b.json".to_owned(), with_polarity("harden")),
            ],
            Repeated::Replace,
        )
        .expect("builds");
        assert_eq!(m.cells.len(), 1);
        assert_eq!(
            m.cells[0].polarity["-Wl,-rpath"], "harden",
            "the later report's cell replaces the earlier's"
        );
        let mut silent = with_polarity("harden");
        silent["observations"][0]
            .as_object_mut()
            .expect("an observation")
            .remove("polarity");
        let m = build_with(
            &[
                ("a.json".to_owned(), with_polarity("weaken")),
                ("b.json".to_owned(), silent),
            ],
            Repeated::Replace,
        )
        .expect("builds");
        assert!(
            !m.cells[0].polarity.contains_key("-Wl,-rpath"),
            "a later verdict carrying no polarity keeps no earlier report's word beside it"
        );
    }

    /// The motivating case: an error under gcc 16 and a warning under gcc 13.3,
    /// across two different distributions. The compiler version explains it; the
    /// distribution does not.
    #[test]
    fn a_compiler_version_boundary_is_not_attributed_to_the_distro() {
        let reports = vec![
            (
                "a".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "16.1.1",
                    "glibc",
                    "bare",
                    &[("-Werror=ifd", "on")],
                ),
            ),
            (
                "b".to_owned(),
                report(
                    "ubuntu",
                    "24.04",
                    "gcc",
                    "13.3.0",
                    "glibc",
                    "bare",
                    &[("-Werror=ifd", "off")],
                ),
            ),
            (
                "c".to_owned(),
                report(
                    "debian",
                    "13",
                    "gcc",
                    "16.1.1",
                    "glibc",
                    "bare",
                    &[("-Werror=ifd", "on")],
                ),
            ),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-Werror=ifd"];
        assert!(v.varies);
        assert!(
            v.explained_by.contains(&"compiler_version".to_owned()),
            "compiler_version must explain it, got {:?}",
            v.explained_by
        );
        assert!(
            !v.explained_by.contains(&"distro".to_owned()),
            "the distro must NOT explain it: fedora and debian agree while ubuntu differs"
        );
    }

    /// Two reports differing in several axes at once cannot separate them, and the
    /// output says so rather than picking one.
    #[test]
    fn confounded_axes_are_reported_as_confounded() {
        let reports = vec![
            (
                "a".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "16.1.1",
                    "glibc",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "b".to_owned(),
                report(
                    "ubuntu",
                    "24.04",
                    "clang",
                    "18.1.3",
                    "glibc",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.len() > 1, "several axes should fit");
        assert!(v.note.contains("cannot tell them apart"));
    }

    #[test]
    fn an_invariant_axis_is_named_so_nobody_over_generalises() {
        let reports = vec![
            (
                "a".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "16.1.1",
                    "glibc",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "b".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "16.1.1",
                    "glibc",
                    "distro-buildflags",
                    &[("-fx", "on")],
                ),
            ),
        ];
        let m = build(&reports).expect("built");
        assert!(m.invariant_axes.contains(&"arch".to_owned()));
        assert!(m.invariant_axes.contains(&"distro".to_owned()));
        assert_eq!(m.varying_axes, vec!["profile".to_owned()]);
        // Labels use only the varying axes, so rows stay readable.
        assert!(m.cells.iter().any(|c| c.label == "bare"));
    }

    #[test]
    fn a_libc_difference_is_attributed_to_the_libc() {
        let reports = vec![
            (
                "a".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "16.1.1",
                    "glibc",
                    "bare",
                    &[("-fortify", "off")],
                ),
            ),
            (
                "b".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "16.1.1",
                    "musl",
                    "bare",
                    &[("-fortify", "unsupported")],
                ),
            ),
        ];
        let m = build(&reports).expect("built");
        assert_eq!(m.variance["-fortify"].explained_by, vec!["libc".to_owned()]);
    }

    #[test]
    fn a_single_report_cannot_attribute_anything() {
        let reports = vec![(
            "a".to_owned(),
            report(
                "fedora",
                "44",
                "gcc",
                "16.1.1",
                "glibc",
                "bare",
                &[("-fx", "on")],
            ),
        )];
        let m = build(&reports).expect("built");
        assert!(!m.variance["-fx"].varies);
        assert!(
            m.warnings
                .iter()
                .any(|w| w.contains("only one configuration"))
        );
    }

    #[test]
    fn a_non_report_is_rejected() {
        assert!(build(&[("x".to_owned(), json!({"nope": 1}))]).is_err());
    }

    /// A report that does not carry a flag must not vouch for what explains it.
    ///
    /// `explained_by` is computed over the cells carrying the flag; `confounded_with`
    /// iterated *every* cell. The two ranged over different spans, and the wider one
    /// suppressed the warning — a cell with no verdict for the flag still contributed
    /// cross-links, pushing the count past the threshold and removing the coarser axis.
    ///
    /// The two arms below share the same three carrying reports and produce the same
    /// verdicts and the same `observed_in`. Only `of_configurations` differs. If the
    /// confound answer differs too, the extra reports changed a conclusion about a flag
    /// they hold no evidence about — a correct count over the wrong span, which reads as
    /// measured and is worse than an obvious zero.
    #[test]
    fn cells_without_the_flag_do_not_dissolve_its_confound() {
        // distro is nested inside compiler_version: alpha only ever appears with 10,
        // beta only with 11. So the two cannot be told apart on this evidence.
        let carrying = || {
            vec![
                (
                    "a1".to_owned(),
                    report("alpha", "1", "gcc", "10", "glibc", "bare", &[("-fq", "on")]),
                ),
                (
                    "a2".to_owned(),
                    report("alpha", "2", "gcc", "10", "glibc", "bare", &[("-fq", "on")]),
                ),
                (
                    "b1".to_owned(),
                    report("beta", "1", "gcc", "11", "glibc", "bare", &[("-fq", "off")]),
                ),
            ]
        };

        let narrow = build(&carrying()).expect("built");
        let narrow_v = &narrow.variance["-fq"];
        assert!(
            !narrow_v.confounded_with.is_empty(),
            "distro and compiler_version are nested here and must be reported as \
             confounded: {narrow_v:?}"
        );

        // The same three, plus two that cross-link the axes while saying nothing about
        // `-fq`. They carry a different flag so the cells exist and are non-empty.
        let mut wide = carrying();
        wide.push((
            "c1".to_owned(),
            report(
                "alpha",
                "3",
                "gcc",
                "11",
                "glibc",
                "bare",
                &[("-fother", "on")],
            ),
        ));
        wide.push((
            "c2".to_owned(),
            report(
                "beta",
                "2",
                "gcc",
                "10",
                "glibc",
                "bare",
                &[("-fother", "on")],
            ),
        ));
        let wide = build(&wide).expect("built");
        let wide_v = &wide.variance["-fq"];

        assert_eq!(
            wide_v.observed_in, narrow_v.observed_in,
            "the flag's own evidence must be unchanged between the arms"
        );
        assert_eq!(
            wide_v.verdicts, narrow_v.verdicts,
            "the flag's own verdicts must be unchanged between the arms"
        );
        assert_eq!(
            wide_v.confounded_with, narrow_v.confounded_with,
            "adding reports that carry no verdict for `-fq` changed what is said to \
             explain it:\n  without them: {:?}\n  with them:    {:?}",
            narrow_v.confounded_with, wide_v.confounded_with
        );
    }

    /// One report of one flag, `(name, report)`, for the attribution tests below.
    fn one(
        name: &str,
        release: &str,
        compiler: (&str, &str),
        libc: &str,
        profile: &str,
        verdict: &str,
    ) -> (String, Value) {
        let (kind, version) = compiler;
        let distro = if release == "24.04" {
            "ubuntu"
        } else {
            "fedora"
        };
        (
            name.to_owned(),
            report(
                distro,
                release,
                kind,
                version,
                libc,
                profile,
                &[("-f", verdict)],
            ),
        )
    }

    /// A pair holding an axis inseparable from the single explanation explains nothing of
    /// its own, however large a group it agrees over: here `compiler` x `libc` agrees over a
    /// group of two where each `compiler_version` stands alone, and `libc` is nested in
    /// `compiler_version`.
    #[test]
    fn a_pair_holding_an_axis_inseparable_from_the_explainer_is_not_named() {
        let reports = vec![
            one("1", "39", ("gcc", "13"), "glibc-2.38", "bare", "off"),
            one("2", "40", ("gcc", "14"), "glibc-2.39", "bare", "on"),
            one("3", "39", ("clang", "17"), "glibc-2.38", "bare", "on"),
            one("4", "40", ("clang", "18"), "glibc-2.39", "bare", "on"),
            one("5", "24.04", ("clang", "18.1"), "glibc-2.39", "bare", "on"),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-f"];
        assert_eq!(v.explained_by, ["compiler_version"]);
        assert!(v.confounded_with["compiler_version"].contains(&"libc".to_owned()));
        assert_eq!(v.explained_by_combination, None, "{}", v.note);
    }

    /// A pair whose largest agreeing group is no larger than the single explanation's is
    /// not named beside it, and with the single axis's groups of more than one member the
    /// note says it is fully accounted for; a flag observed in one configuration is said to
    /// be too few to read.
    #[test]
    fn a_pair_that_only_ties_the_single_explanation_is_not_named() {
        let reports = vec![
            one("1", "r1", ("gcc", "16"), "l1", "a", "on"),
            one("2", "r2", ("gcc", "16"), "l1", "a", "on"),
            one("3", "r3", ("gcc", "16"), "l1", "a", "on"),
            one("4", "r1", ("gcc", "16"), "l2", "a", "off"),
            one("5", "r1", ("gcc", "16"), "l2", "b", "off"),
            one("6", "r1", ("gcc", "16"), "l3", "a", "on"),
            one("7", "r1", ("gcc", "16"), "l3", "b", "on"),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-f"];
        assert_eq!(
            (v.explained_by.as_slice(), v.strength.as_str()),
            (["libc".to_owned()].as_slice(), "grouped")
        );
        assert_eq!(v.explained_by_combination, None, "{}", v.note);
        assert!(v.note.starts_with("consistent with `libc`"), "{}", v.note);

        // The same libc split with profiles crossing both libcs: nothing confounds it.
        let crossed = vec![
            one("1", "r1", ("gcc", "16"), "l1", "a", "on"),
            one("2", "r1", ("gcc", "16"), "l1", "b", "on"),
            one("3", "r1", ("gcc", "16"), "l2", "a", "off"),
            one("4", "r1", ("gcc", "16"), "l2", "b", "off"),
        ];
        let v = &build(&crossed).expect("built").variance["-f"];
        assert_eq!(v.strength, "grouped");
        assert!(
            v.note.starts_with("fully accounted for by `libc`"),
            "{}",
            v.note
        );

        // A flag only one of three reports carries.
        let mut lone = crossed[..3].to_vec();
        lone[0].1["observations"] =
            json!([{"flag": "-f", "verdict": "on"}, {"flag": "-g", "verdict": "on"}]);
        let v = &build(&lone).expect("built").variance["-g"];
        assert!(
            v.note.starts_with("observed in 1 of 3 configurations"),
            "{}",
            v.note
        );
    }

    /// A set that is not one dataset is refused unless the caller allows a mixed set.
    #[test]
    fn a_mixed_set_is_refused_unless_allowed() {
        // Two profiles, so the allowed set is two configurations and no repeat.
        let corpus = |name: &str, sha: &str| {
            let mut r = report(
                "fedora",
                "44",
                "gcc",
                "16.1.1",
                "glibc",
                name,
                &[("-f", "on")],
            );
            r["run"] = json!({"probe_corpus_sha256": sha});
            (name.to_owned(), r)
        };
        let mixed = vec![corpus("a", &"a".repeat(64)), corpus("b", &"b".repeat(64))];
        let refused = build_from_reports(&mixed, false, Repeated::Refuse).expect_err("two corpora");
        assert!(
            format!("{refused:#}").contains("these reports are not one dataset"),
            "{refused:#}"
        );
        // Allowed, the set passes the dataset gate and meets the next one: these hand-built
        // reports carry no consistency block, which `dataset::refuse_self_contradicted`
        // refuses in its own words.
        let allowed =
            build_from_reports(&mixed, true, Repeated::Refuse).expect_err("hand-built reports");
        let allowed = format!("{allowed:#}");
        assert!(
            !allowed.contains("not one dataset") && allowed.contains("not safe to read"),
            "{allowed}"
        );
    }

    /// The measured shape ([`Repeated`]): a full run, then a run of fewer checks of the same
    /// configuration through a wrapper that moves two of them, and a report of another
    /// configuration. Beside the measured shape: a flag the wrapper run carries with no
    /// verdict, one whose polarity alone differs, one whose polarity only the full run
    /// publishes, and one only the wrapper run carries.
    fn full_wrapped_and_other() -> [(String, Value); 3] {
        let bare = |flags: &[(&str, &str)], extra: &[Value]| {
            let mut r = report("fedora", "44", "gcc", "16.1.1", "glibc", "bare", flags);
            r["observations"]
                .as_array_mut()
                .expect("observations")
                .extend(extra.iter().cloned());
            r
        };
        let full = bare(
            &[
                ("-pie", "off"),
                ("-Wl,-z,pack-relative-relocs", "not-applicable"),
                ("-fPIE", "on"),
                ("-fstack-protector-strong", "on"),
                ("-fhardened", "on"),
            ],
            &[
                json!({"flag": "-Wl,-rpath", "verdict": "off", "polarity": "weaken"}),
                json!({"flag": "-fno-plt", "verdict": "on", "polarity": "harden"}),
            ],
        );
        let wrapped = bare(
            &[
                ("-pie", "probe-invalid"),
                ("-Wl,-z,pack-relative-relocs", "probe-invalid"),
                ("-fPIE", "on"),
                ("-fcf-protection", "on"),
            ],
            &[
                json!({"flag": "-fhardened"}),
                json!({"flag": "-Wl,-rpath", "verdict": "off", "polarity": "harden"}),
                json!({"flag": "-fno-plt", "verdict": "on"}),
            ],
        );
        let other = (
            "other.json".to_owned(),
            report(
                "fedora",
                "44",
                "gcc",
                "16.1.1",
                "glibc",
                "explicit",
                &[("-pie", "on")],
            ),
        );
        [
            ("full.json".to_owned(), full),
            ("wrapped.json".to_owned(), wrapped),
            other,
        ]
    }

    /// The configuration of [`full_wrapped_and_other`]'s repeated pair, as a refusal and a
    /// warning name it: every axis, the empty one too.
    const BARE: &str = "distro fedora, release 44, compiler gcc, compiler_version 16.1.1, libc \
                        glibc, arch x86_64, profile bare, execution vm, execution_basis \
                        unpublished, image (none)";

    /// Two reports of one configuration are refused, every repeat named, rather than merged flag
    /// by flag; a report of another configuration beside them is no repeat.
    #[test]
    fn a_repeated_configuration_is_refused() {
        let [full, wrapped, other] = full_wrapped_and_other();
        // Refused, whichever comes first, with every repeat named against the report it
        // repeats and the configuration in full; a third report of another configuration is
        // no repeat.
        let refused = build(&[full.clone(), other.clone(), wrapped.clone()])
            .expect_err("a repeated configuration");
        let user = refused
            .downcast_ref::<crate::error::UserError>()
            .expect("the caller's input to fix");
        assert!(
            user.message
                .contains(&format!("wrapped.json repeats full.json ({BARE})"))
                && user
                    .message
                    .contains(&format!("every axis of its key ({})", AXES.join(", ")))
                && user.message.contains("The key holds no probe selection")
                && !user.message.contains("other.json"),
            "{}",
            user.message
        );
        assert!(
            user.hint
                .as_deref()
                .is_some_and(|h| h.contains("--replace-repeated")),
            "{:?}",
            user.hint
        );
        let third = ("third.json".to_owned(), full.1.clone());
        let refused =
            build(&[wrapped.clone(), full.clone(), third]).expect_err("three of one configuration");
        let refused = format!("{refused:#}");
        assert!(
            refused.contains("full.json repeats wrapped.json")
                && refused.contains("third.json repeats wrapped.json"),
            "{refused}"
        );
    }

    /// Replaced ([`Repeated::Replace`]), a repeated configuration's cell is the later report's
    /// whole and every flag the two read differently is named, never a merge of the two.
    #[test]
    fn a_repeated_configuration_is_replaced_whole_never_merged() {
        let [full, wrapped, other] = full_wrapped_and_other();
        // How each report reads each flag the two read differently, as the warning says it.
        let reads = |name: &str| -> [(&str, &str); 5] {
            if name == "full.json" {
                [
                    ("-pie", "off"),
                    ("-Wl,-z,pack-relative-relocs", "not-applicable"),
                    ("-fhardened", "on"),
                    ("-Wl,-rpath", "off with polarity weaken"),
                    ("-fno-plt", "on with polarity harden"),
                ]
            } else {
                [
                    ("-pie", "probe-invalid"),
                    ("-Wl,-z,pack-relative-relocs", "probe-invalid"),
                    ("-fhardened", "no verdict"),
                    ("-Wl,-rpath", "off with polarity harden"),
                    ("-fno-plt", "on with no polarity"),
                ]
            }
        };
        let only = |name: &str| {
            if name == "full.json" {
                "-fstack-protector-strong"
            } else {
                "-fcf-protection"
            }
        };
        // In either order: the cell is the later report's alone, and the warning names the
        // five flags read differently (two verdicts, a verdict against none, a polarity against
        // another and against none), not the one read alike, and the flag only each carries.
        for (earlier, later) in [(&full, &wrapped), (&wrapped, &full)] {
            let m = build_with(
                &[earlier.clone(), later.clone(), other.clone()],
                Repeated::Replace,
            )
            .expect("replaced");
            assert_eq!(m.cells.len(), 2, "{:?}", m.cells);
            let cell = m
                .cells
                .iter()
                .find(|c| c.key.profile == "bare")
                .expect("the repeated configuration's cell");
            let alone = build(std::slice::from_ref(later)).expect("one report");
            assert_eq!(cell.flags, alone.cells[0].flags, "{}'s verdicts", later.0);
            assert_eq!(
                cell.polarity, alone.cells[0].polarity,
                "{}'s polarities",
                later.0
            );
            let named: Vec<&String> = m
                .warnings
                .iter()
                .filter(|w| w.contains("repeats"))
                .collect();
            let [warning] = named.as_slice() else {
                panic!("one warning names the repeat: {:?}", m.warnings);
            };
            let (e, l) = (earlier.0.as_str(), later.0.as_str());
            assert!(
                warning.starts_with(&format!(
                    "{l} repeats the configuration of {e} ({BARE}) and replaces its whole cell"
                )) && warning.contains("5 flag(s) both carry read differently"),
                "{warning}"
            );
            for ((flag, before), (_, after)) in reads(e).into_iter().zip(reads(l)) {
                let said = format!("`{flag}` {before} in {e} and {after} in {l}");
                assert!(warning.contains(&said), "{said}: {warning}");
            }
            assert!(!warning.contains("`-fPIE`"), "read alike: {warning}");
            let left = format!(
                "1 flag(s) only {e} carries leave the cell with it: `{}`",
                only(e)
            );
            let joined = format!("1 flag(s) only {l} carries join the cell: `{}`", only(l));
            assert!(
                warning.contains(&left) && warning.contains(&joined),
                "{warning}"
            );
            assert!(
                !m.variance.contains_key(only(e)) && m.variance.contains_key(only(l)),
                "a flag only the replaced report carried leaves the matrix"
            );
        }

        // Two configurations: no repeat, and the same matrix either way.
        let pair = [full.clone(), other.clone()];
        let refusing = build(&pair).expect("two configurations");
        let replacing = build_with(&pair, Repeated::Replace).expect("two configurations");
        assert!(refusing.warnings.is_empty(), "{:?}", refusing.warnings);
        assert_eq!(
            serde_json::to_string(&refusing).expect("json"),
            serde_json::to_string(&replacing).expect("json")
        );
    }

    /// Three reports of one configuration, replaced: each replaces the cell the one before it
    /// left, under a warning comparing the two, and the cell is the last report's whole.
    #[test]
    fn a_third_report_of_a_configuration_replaces_the_second() {
        let [full, wrapped, _] = full_wrapped_and_other();
        let third = ("third.json".to_owned(), full.1.clone());
        let m = build_with(
            &[full.clone(), wrapped.clone(), third.clone()],
            Repeated::Replace,
        )
        .expect("replaced twice");
        let named: Vec<&str> = m
            .warnings
            .iter()
            .filter(|w| w.contains("repeats"))
            .map(String::as_str)
            .collect();
        let [second, last] = named.as_slice() else {
            panic!("two warnings name the repeats: {:?}", m.warnings);
        };
        assert!(
            second.starts_with("wrapped.json repeats the configuration of full.json"),
            "{second}"
        );
        assert!(
            last.starts_with("third.json repeats the configuration of wrapped.json")
                && last.contains("`-pie` probe-invalid in wrapped.json and off in third.json"),
            "{last}"
        );
        let alone = build(std::slice::from_ref(&third)).expect("one report");
        assert_eq!(m.cells.len(), 1, "{:?}", m.cells);
        assert_eq!(m.cells[0].flags, alone.cells[0].flags);
    }
}
