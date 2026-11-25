// SPDX-License-Identifier: BSD-3-Clause

//! Cross-tabulating many reports without pretending the distribution is the key.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::Value;

/// `chard_schema` in a matrix: the major version of `schema/chard-matrix.schema.json`, which
/// changes under the rule the CLI's contract states.
pub const MATRIX_SCHEMA_VERSION: &str = "2";

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
    // The architecture the toolchain built for, `toolchain.target.arch` ([`arch_of`]).
    "arch",
    // The machine the run had, beside the architecture: one image's toolchain on two machines of
    // one architecture (an Oracle Cloud A1 and an A2) answers the runtime checks differently.
    "machine",
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
    /// The architecture every arch-gated decision was taken under, `toolchain.target.arch`,
    /// marked [`CONTRADICTED`] where the report's own witnesses disagree with it (`arch_of`).
    pub arch: String,
    /// The machine the run had, `env::machine_of` over the report: what names its CPU, then
    /// the features that gate a mechanism (`features:bti,paca,pacg`), `unread` where the report
    /// carries no `environment.cpu`.
    pub machine: String,
    pub profile: String,
    pub execution: String,
    /// `environment.execution.mode_evidence.basis`: what established `execution`.
    pub execution_basis: String,
    /// The image the measurement ran in.
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
            "machine" => &self.machine,
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

/// The `arch` axis of a report, for a matrix cell and a table column alike:
/// `toolchain.target.arch`, the architecture every arch-gated decision was taken under, with
/// [`CONTRADICTED`] appended where one of the report's own witnesses of the target disagrees
/// with it, and empty where the report carries none. Uncontradicted means no witness in the
/// report names another, not that one corroborates it.
pub(crate) fn arch_of(report: &Value) -> String {
    let arch = text(report, &["toolchain", "target", "arch"]);
    // `profile_macros_cxx` is left out: it witnesses the C++ probes alone, so a run whose C
    // probes were built for `arch` is not contradicted by it, and a C++ check its `disagrees`
    // withheld is caught by the gating rule below.
    let disagrees = [
        &["agreement"][..],
        &["abi", "agreement"],
        &["macros", "agreement"],
        &["profile_macros", "agreement"],
    ]
    .iter()
    .any(|path| {
        let mut full = vec!["toolchain", "target"];
        full.extend_from_slice(path);
        text(report, &full) == "disagrees"
    });
    // The gate's own word: a check withheld because a witness contradicted the target.
    let withheld = report
        .get("observations")
        .and_then(Value::as_array)
        .is_some_and(|observations| {
            observations.iter().any(|o| {
                o.get("gating")
                    .and_then(|g| g.get("rule"))
                    .and_then(Value::as_str)
                    .is_some_and(|rule| CONTRADICTING_RULES.contains(&rule))
            })
        });
    let contradicted = disagrees || withheld;
    if contradicted && !arch.is_empty() {
        format!("{arch}{CONTRADICTED}")
    } else {
        arch
    }
}

/// Appended to an `arch` its own report contradicts: a `disagrees` under `toolchain.target`'s
/// `agreement`, `abi.agreement`, `macros.agreement` or `profile_macros.agreement`, or an
/// observation withheld under a rule of `CONTRADICTING_RULES`. A `gcc` wrapper adding
/// `-m32` answers `-dumpmachine` with `x86_64-redhat-linux` while its macro dump defines
/// `__i386__`; one answering `sparc64-linux-gnu` built x86_64 artifacts, every witness read
/// `unmapped`, and four checks were withheld (gcc 16.2.1, Fedora 44 x86_64). Keyed apart from
/// the uncontradicted architecture, and never `known`.
pub const CONTRADICTED: &str = " (contradicted)";

/// The `gating.rule`s under which a check is withheld because the run's target was
/// contradicted.
const CONTRADICTING_RULES: [&str; 2] = ["target-arch-contradicted", "target-abi-contradicted"];

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
        arch: arch_of(report),
        machine: crate::env::machine_of(report),
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
#[derive(Debug, Clone, Serialize)]
pub struct Cell {
    pub key: CellKey,
    pub label: String,
    /// `environment.kernel.ownership`: whose kernel the cell's run had (`own`, `borrowed`,
    /// `unsettled`), or [`UNPUBLISHED_OWNERSHIP`].
    pub kernel_ownership: String,
    /// flag -> verdict, with the level appended where a graded mechanism has one.
    pub flags: BTreeMap<String, String>,
    /// flag -> the observation's `polarity`, for every flag in `flags` whose observation
    /// carries one. A `weaken` flag's `off` is the protected state, so a verdict read
    /// without it reads the wrong way round; `table` inverts such a row and its legend
    /// says so, and here the word stands beside the verdict instead.
    pub polarity: BTreeMap<String, String>,
    /// flag -> the observation's `gating.rule`, for every flag in `flags` whose observation
    /// carries one: why a verdict is `unsupported`, `not-applicable` or a withheld
    /// `indeterminate`. A `?` the machine could not answer (`machine-lacks-bti`) and one the
    /// toolchain's run left unread read alike without it. Absent where no flag carries one.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub gating: BTreeMap<String, String>,
}

/// Whether `fine` is a refinement of `coarse` by construction rather than by
/// accident of the input set.
fn is_structural_refinement(fine: &str, coarse: &str) -> bool {
    matches!(
        (fine, coarse),
        ("compiler_version", "compiler") | ("release" | "libc", "distro")
    )
}

/// Whether a change of `coarse` moves `fine` with it by construction: a compiler version is a
/// version of one compiler, and a release one distribution's release, so a change of compiler or
/// distribution is one change named at two levels of detail.
fn moves_with(fine: &str, coarse: &str) -> bool {
    matches!(
        (fine, coarse),
        ("compiler_version", "compiler") | ("release", "distro")
    )
}

/// Whether an axis value says what the configuration had. An empty value (a field the report
/// lacks; `image` aside, where empty is a run outside any image), `unread` (`machine` without
/// `environment.cpu`), [`UNPUBLISHED_BASIS`], the libc `unknown` and an architecture its own
/// witnesses contradict ([`CONTRADICTED`]) do not: two of them may name one value or two.
fn known(axis: &str, value: &str) -> bool {
    match value {
        "" => axis == "image",
        "unread" | "unknown" | UNPUBLISHED_BASIS => false,
        v => !v.ends_with(CONTRADICTED),
    }
}

/// Whether two configurations are a controlled comparison of `axis`: both name a [`known`]
/// value of it and the values differ, and every other axis of the key is known and equal on
/// both, or moves with `axis` ([`moves_with`]).
fn controls(axis: &str, one: &CellKey, two: &CellKey) -> bool {
    let (was, now) = (one.axis(axis), two.axis(axis));
    known(axis, was)
        && known(axis, now)
        && was != now
        && AXES.iter().all(|other| {
            let held = one.axis(other);
            *other == axis
                || moves_with(other, axis)
                || (held == two.axis(other) && known(other, held))
        })
}

/// The value a cell groups under on `axis`: its value where [`known`], and otherwise one of
/// its own (`index` is the cell's place), so two cells whose values are unknown never form a
/// group: two `unread` machines, or two contradicted architectures, may be one or two. Nor is
/// an axis consistent over a cell whose value is unknown ([`build_with`]): that cell may be of
/// any group, one whose verdict differs among them.
fn group_value(axis: &str, key: &CellKey, index: usize) -> String {
    match key.axis(axis) {
        value if known(axis, value) => value.to_owned(),
        _ => format!("\u{1}unknown {index}"),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Variance {
    pub varies: bool,
    /// How many configurations actually carried this flag, against how many are in the input set.
    pub observed_in: usize,
    /// Configurations in the input set, so `observed_in` has a denominator beside it.
    pub of_configurations: usize,
    /// Distinct verdicts seen, and which configurations produced each.
    pub verdicts: BTreeMap<String, Vec<String>>,
    /// Axes under which every group agrees. Empty when nothing explains it.
    pub explained_by: Vec<String>,
    /// `grouped` when at least one axis value covers two or more agreeing
    /// observations; `controlled` when no group has two members but two configurations that
    /// read the flag differently compare the axis alone (`controls`: every other axis of the
    /// key known and unchanged, but those that move with it), which is weaker; `none` when
    /// nothing fits.
    pub strength: String,
    /// Axes whose partition these inputs cannot separate from the explaining one, because
    /// fewer than two values of the explainer occur under more than one value of the other.
    /// Reported per explaining axis as `explainer -> [coarser axes]`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub confounded_with: BTreeMap<String, Vec<String>>,
    /// A pair of axes that explains the variation and holds a larger agreeing group than any
    /// single explaining axis: the finer an axis, the more cheaply it partitions the data, and
    /// a version string unique to each distribution fits where `distro` × `compiler`, a
    /// distribution patching its compiler's driver, is the mechanism.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explained_by_combination: Option<Vec<String>>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Matrix {
    pub chard_schema: String,
    /// Every axis and the distinct values seen for it.
    pub axes: BTreeMap<String, Vec<String>>,
    /// Axes with exactly one value across the whole input set, stated because they bound what
    /// the table supports: a matrix where `arch` is invariant says nothing about other
    /// architectures.
    pub invariant_axes: Vec<String>,
    pub varying_axes: Vec<String>,
    pub cells: Vec<Cell>,
    pub variance: BTreeMap<String, Variance>,
    pub inputs: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

fn verdict_of(report: &Value, flag: &str) -> Option<String> {
    // One observation per flag: `probe::tests::every_check_has_a_distinct_flag` holds that.
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

/// The `gating.rule` of the observation of `flag`, the one [`verdict_of`] reads.
fn gating_of<'a>(report: &'a Value, flag: &str) -> Option<&'a str> {
    report
        .get("observations")?
        .as_array()?
        .iter()
        .find(|o| o.get("flag").and_then(Value::as_str) == Some(flag))?
        .get("gating")?
        .get("rule")?
        .as_str()
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeated {
    /// Refuse the set, naming every report that repeats an earlier one and the first report
    /// of its configuration: `chard matrix` without `--replace-repeated`.
    Refuse,
    /// The later report's cell replaces the earlier's whole, nothing of the earlier kept, under
    /// a warning that names both reports and everything the two read differently: `chard
    /// matrix --replace-repeated`. A third report of the configuration replaces the second's
    /// cell, and its warning compares it with the second.
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
    /// flag -> `gating.rule`, beside each verdict that carries one.
    gating: BTreeMap<String, String>,
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
            gating: BTreeMap::new(),
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
                if let Some(rule) = gating_of(report, flag) {
                    held.gating.insert(flag.to_owned(), rule.to_owned());
                }
            }
        }
        held
    }
}

/// The warning [`Repeated::Replace`] writes where `now` replaces `was` as the `unit` (a
/// matrix's cell, a table's column) of the configuration `described`: both reports, then every
/// flag both carry whose verdict (or its absence), polarity or gating rule differs, the
/// `kernel.ownership` words where they differ, every flag only `was` carried, which leaves the
/// `unit` with it, and every flag only `now` carries, which joins it.
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
            let gating_moved = was.gating.get(flag) != now.gating.get(flag);
            if was.verdicts.get(flag) == now.verdicts.get(flag) && !polarity_moved && !gating_moved
            {
                return None;
            }
            // The polarity and the gating rule are said where they moved, and only there.
            let read = |held: &Held| {
                let mut read = verdict(held, flag);
                if polarity_moved {
                    match held.polarity.get(flag) {
                        Some(p) => {
                            read.push_str(" with polarity ");
                            read.push_str(p);
                        }
                        None => read.push_str(" with no polarity"),
                    }
                }
                if gating_moved {
                    match held.gating.get(flag) {
                        Some(rule) => {
                            read.push_str(" under gating.rule ");
                            read.push_str(rule);
                        }
                        None => read.push_str(" under no gating rule"),
                    }
                }
                read
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
        "The two read every flag both carry alike, verdict, polarity and gating rule".to_owned()
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
#[expect(
    clippy::too_many_lines,
    reason = "one derivation: ingest, find the varying axes."
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
            "leave out all but one report of each configuration, or pass --replace-repeated",
        )
        .into());
    }

    // The flags are those of the reports the cells hold, so a replaced report's leave with it.
    let flags: BTreeSet<String> = held.values().flat_map(|h| h.flags.clone()).collect();
    // Each cell's verdicts, read in place: the published cells are made from `held` itself at the
    // end, so a cell's polarity, gating and ownership are its own report's by construction.
    let cells: BTreeMap<&CellKey, &BTreeMap<String, String>> =
        held.iter().map(|(key, h)| (key, &h.verdicts)).collect();

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

        // An axis explains the flag when every group sharing an axis value agrees AND the
        // axis groups something: an axis with a distinct value per observation (one report
        // per distribution, say) agrees vacuously, an identifier of the observation rather
        // than an explanation of it.
        let mut explained_by = Vec::new();
        let mut vacuous = Vec::new();
        if varies {
            for axis in &varying {
                let mut by_value: BTreeMap<String, (BTreeSet<&String>, usize)> = BTreeMap::new();
                for (index, (key, got)) in cells.iter().enumerate() {
                    if let Some(v) = got.get(flag) {
                        let slot = by_value.entry(group_value(axis, key, index)).or_default();
                        slot.0.insert(v);
                        slot.1 = slot.1.saturating_add(1);
                    }
                }
                let unknown_member = cells
                    .iter()
                    .any(|(key, got)| got.contains_key(flag) && !known(axis, key.axis(axis)));
                let consistent =
                    !unknown_member && by_value.values().all(|(verdicts, _)| verdicts.len() == 1);
                let groups_something = by_value.values().any(|(_, n)| *n >= 2);
                if consistent && groups_something {
                    explained_by.push(axis.clone());
                } else if consistent {
                    vacuous.push(axis.clone());
                }
            }
        }

        // A vacuously consistent axis is the fallback, marked weaker, only where a grouping
        // one is absent and it is the only thing that changed: some two configurations that
        // read the flag differently compare that axis alone ([`controls`]).
        let mut uncontrolled = Vec::new();
        let strength = if !explained_by.is_empty() {
            "grouped"
        } else if !vacuous.is_empty() {
            let carrying: Vec<(&CellKey, &String)> = cells
                .iter()
                .filter_map(|(key, got)| got.get(flag).map(|v| (*key, v)))
                .collect();
            for axis in vacuous {
                let controlled = carrying.iter().enumerate().any(|(i, (a, va))| {
                    carrying
                        .iter()
                        .skip(i.saturating_add(1))
                        .any(|(b, vb)| va != vb && controls(&axis, a, b))
                });
                if controlled {
                    explained_by.push(axis);
                } else {
                    uncontrolled.push(axis);
                }
            }
            if explained_by.is_empty() {
                "none"
            } else {
                "controlled"
            }
        } else {
            "none"
        };

        // For each explaining axis, which coarser axes it cannot be told apart from: `a` is
        // nested in `b` when every value of `a` occurs under exactly one value of `b`, and then
        // any pattern `a` appears to explain is equally consistent with `b`.
        let mut confounded_with: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for axis in explained_by.iter().chain(&uncontrolled) {
            let mut coarser = Vec::new();
            for other in &varying {
                if other == axis || is_structural_refinement(axis, other) {
                    continue;
                }
                // Over the cells that carry this flag, as `explained_by` is: a report that
                // cannot speak about a flag adds no cross-link to vouch for what explains it
                // (`cells_without_the_flag_do_not_dissolve_its_confound` holds it).
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
                // A cross-link is one value of `axis` observed under two values of `other`,
                // the only observation that tells the two apart.
                let cross_links = companions.values().filter(|seen| seen.len() > 1).count();
                if cross_links < 2 {
                    coarser.push(other.clone());
                }
            }
            if !coarser.is_empty() {
                confounded_with.insert(axis.clone(), coarser);
            }
        }
        // A controlled axis was separated from every axis its witnessing pair held known and
        // equal, which is each axis but those that move with it ([`controls`]): the nesting
        // above is no confound there, and only a version beside its compiler, or a release
        // beside its distribution, stays inseparable.
        if strength == "controlled" {
            for axis in &explained_by {
                if let Some(coarser) = confounded_with.get_mut(axis) {
                    coarser.retain(|other| moves_with(other, axis));
                }
            }
            confounded_with.retain(|_, coarser| !coarser.is_empty());
        }

        // The explaining pair of axes, when it beats every single axis.
        let largest_group = |axes: &[&String]| -> usize {
            let mut sizes: BTreeMap<Vec<String>, usize> = BTreeMap::new();
            for (index, (key, got)) in cells.iter().enumerate() {
                if got.get(flag).is_some() {
                    let k = axes.iter().map(|a| group_value(a, key, index)).collect();
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
            // An axis inseparable from the single explanation cannot contribute a different
            // one: for `-Werror=implicit-function-declaration`, which flips at GCC 14, `libc` is
            // confounded with `compiler_version` because each release ships its own glibc, and
            // `compiler` × `libc` would restate the version under the libc's name.
            let inseparable: BTreeSet<&String> = explained_by
                .iter()
                .chain(&uncontrolled)
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
                    for (index, (key, got)) in cells.iter().enumerate() {
                        if let Some(v) = got.get(flag) {
                            let slot = by_pair
                                .entry((group_value(a, key, index), group_value(b, key, index)))
                                .or_default();
                            slot.0.insert(v);
                            slot.1 = slot.1.saturating_add(1);
                        }
                    }
                    let unknown_member = cells.iter().any(|(key, got)| {
                        got.contains_key(flag) && !(known(a, key.axis(a)) && known(b, key.axis(b)))
                    });
                    let consistent = !unknown_member
                        && by_pair.values().all(|(verdicts, _)| verdicts.len() == 1);
                    let n = largest_group(&[a, b]);
                    if consistent && n >= 2 && n > best {
                        best = n;
                        explained_by_combination = Some(vec![a.clone(), b.clone()]);
                    }
                }
            }
        }

        // Published for the explaining axes alone.
        confounded_with.retain(|axis, _| explained_by.contains(axis));

        // How many cells carried this flag: `verdicts` covers only those, so the note must not
        // claim agreement over one observation or none, and the global guard
        // (`cells.len() < 2`) cannot fire for a per-flag shortfall.
        let observed_in: usize = verdicts.values().map(Vec::len).sum();
        let note = if observed_in < 2 {
            format!(
                "observed in {observed_in} of {} configurations",
                cells.len()
            )
        } else if !varies {
            format!("the same in all {observed_in} configurations that carried it")
        } else if let Some(ref pair) = explained_by_combination {
            // With `explained_by` empty, no axis fits at all: an axis that fits only with a value
            // per configuration (`uncontrolled`) is confounded with every other varying axis, so
            // `inseparable` holds them all and no pair is offered beside it.
            let single = explained_by.first().map_or_else(
                || "No single axis partitions these observations consistently.".to_owned(),
                |single| format!("`{single}` also partitions these observations consistently."),
            );
            format!(
                "best accounted for by {pair:?} together, which holds more agreeing \
                 observations in a single group than any one axis manages. {single}"
            )
        } else if explained_by.is_empty() && !uncontrolled.is_empty() {
            format!(
                "no axis accounts for the variation. Each of {uncontrolled:?} gives every configuration that carried the flag a value of its own."
            )
        } else if explained_by.is_empty() {
            "no single axis accounts for the variation".to_owned()
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
                format!("fully accounted for by `{only}`")
            } else {
                format!(
                    "consistent with `{only}`: two configurations that read it differently differ in `{only}` and in no other axis of the key except those that change with it."
                )
            }
        } else {
            format!("consistent with any of {explained_by:?} — these inputs cannot tell them apart")
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
        warnings.push("only one configuration was supplied".to_owned());
    }

    // A report that contradicts itself is not here: `build_from_reports` refuses the set
    // (`dataset::refuse_self_contradicted`).

    let out_cells = held
        .into_iter()
        .map(|(key, h)| Cell {
            label: key.label(&varying),
            polarity: h.polarity,
            gating: h.gating,
            kernel_ownership: h.ownership,
            key,
            flags: h.verdicts,
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
        // See the note in `table::render_reports`: a mismatched input set is the
        // operator's invocation, not a chard defect, and the error class decides which
        // of those a caller is told.
        return Err(crate::error::UserError::with_hint(
            format!(
                "these reports are not one dataset, so a matrix of them could attribute \
                 a change in chard to a distribution:\n  {}",
                conflicts.join("\n  ")
            ),
            "pass --allow-mixed to build it anyway",
        )
        .into());
    }

    let mut matrix = build_with(reports, repeated)?;
    // As in `table::render_reports`: after the shape is read, refused rather than warned.
    crate::dataset::refuse_self_contradicted(reports)?;
    // Into the document, not onto stderr.
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

    #[test]
    fn every_axis_reads_its_own_field() {
        let key = CellKey {
            distro: "distro-v".to_owned(),
            release: "release-v".to_owned(),
            compiler: "compiler-v".to_owned(),
            compiler_version: "compiler_version-v".to_owned(),
            libc: "libc-v".to_owned(),
            arch: "arch-v".to_owned(),
            machine: "machine-v".to_owned(),
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
            // Fedora 44 and openSUSE.
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
        // Nor is the version alone: it names each configuration, and every two that read the
        // flag differently differ in the release or the compiler too, so no comparison here is
        // controlled, and the note names the axes that only fit.
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(v.strength, "none");
        assert!(
            v.note.contains(r#"["release", "compiler_version"]"#),
            "{}",
            v.note
        );
    }

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

    #[test]
    fn an_axis_nested_in_the_explainer_is_named_as_inseparable() {
        // Two releases per compiler version, so the version groups two observations and is
        // the explanation by itself, not a fit of one value per configuration.
        let ubuntu = |release: &str, version: &str, libc: &str, verdict: &str| {
            (
                release.to_owned(),
                report(
                    "ubuntu",
                    release,
                    "gcc",
                    version,
                    libc,
                    "bare",
                    &[("-fx", verdict)],
                ),
            )
        };
        let reports = vec![
            ubuntu("20.04", "9.4.0", "glibc2.31", "off"),
            ubuntu("20.10", "9.4.0", "glibc2.31", "off"),
            ubuntu("24.04", "13.3.0", "glibc2.39", "on"),
            ubuntu("24.10", "13.3.0", "glibc2.39", "on"),
        ];
        let m = build(&reports).expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.contains(&"compiler_version".to_owned()));
        assert_eq!(v.strength, "grouped");
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
        // A CPU, so the machine is known and a basis alone can be a controlled comparison.
        let cpu = json!({"vendor": "GenuineIntel", "model_name": "Xeon", "relevant_features": []});
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
                "cpu": cpu,
                "execution": execution,
            },
            "toolchain": {"kind": "gcc", "version": "16.1.1", "target": {"arch": "x86_64"}},
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
            // The unpublished basis may be either of the others, so the basis explains nothing.
            assert!(check.explained_by.is_empty(), "{:?}", check.explained_by);
        }

        // A basis that is present but not a string, or empty, is no basis either.
        for basis in [json!(7), json!(null), json!("")] {
            let mut report = on_execution("host", Some("assumed-host"), "on");
            report["environment"]["execution"]["mode_evidence"]["basis"] = basis;
            assert_eq!(key_of(&report).execution_basis, UNPUBLISHED_BASIS);
        }
    }

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
        // A CPU and a basis, as a report chard writes today carries them: `controls` holds a
        // comparison only over axes whose values are known.
        json!({
            "environment": {
                "distro": {"id": distro, "version_id": release},
                "libc": {"impl": libc},
                "kernel": {"arch": "x86_64"},
                "cpu": {"vendor": "GenuineIntel", "model_name": "Xeon", "relevant_features": []},
                "execution": {"mode": "vm", "mode_evidence": {"basis": "measured"}},
            },
            "toolchain": {"kind": kind, "version": version, "target": {"arch": "x86_64"}},
            "profile": {"id": profile},
            "observations": Value::Array(observations),
        })
    }

    #[test]
    fn one_image_on_two_machines_is_two_cells_and_each_names_its_gating() {
        let on = |features: &[&str], verdict: &str, rule: Option<&str>| {
            let mut r = report("ol", "10.2", "gcc", "14.3.1", "glibc", "bare", &[]);
            r["toolchain"]["target"]["arch"] = "aarch64".into();
            r["environment"]["execution"]["image"] = "oci-ol10".into();
            r["environment"]["cpu"] = json!({"relevant_features": features});
            let mut obs =
                json!({"flag": "-mbranch-protection=bti (BTI enforced)", "verdict": verdict});
            if let Some(rule) = rule {
                obs["gating"] = json!({"rule": rule});
            }
            r["observations"] = json!([obs]);
            r
        };
        let m = build(&[
            (
                "a1.json".to_owned(),
                on(&[], "indeterminate", Some("machine-lacks-bti")),
            ),
            (
                "a2.json".to_owned(),
                on(&["bti", "paca", "pacg"], "on", None),
            ),
        ])
        .expect("two machines are two cells, no repeat");
        assert_eq!(m.cells.len(), 2);
        assert!(
            m.varying_axes.contains(&"machine".to_owned()),
            "{:?}",
            m.varying_axes
        );
        let flag = "-mbranch-protection=bti (BTI enforced)";
        let cell = |machine: &str| {
            m.cells
                .iter()
                .find(|c| c.key.machine == machine)
                .unwrap_or_else(|| panic!("a cell on {machine}"))
        };
        // An A1 report written before `arm_parts` names no feature and no identity.
        let a1 = cell("unread");
        assert_eq!(a1.flags[flag], "indeterminate");
        assert_eq!(a1.gating[flag], "machine-lacks-bti");
        let a2 = cell("features:bti,paca,pacg");
        assert_eq!(a2.flags[flag], "on");
        assert!(a2.gating.is_empty(), "{:?}", a2.gating);
        // The A1's machine is unread, so it may be the A2's: the flip is put down to no axis.
        assert_eq!(m.variance[flag].explained_by, Vec::<String>::new());
        assert_eq!(m.variance[flag].strength, "none");
        // With the A1's machine read, the machine is the one axis that moved.
        let mut a1 = on(&[], "indeterminate", Some("machine-lacks-bti"));
        a1["environment"]["cpu"] = json!({"arm_parts": ["0x41:0xd0c"], "relevant_features": []});
        let m = build(&[
            ("a1.json".to_owned(), a1),
            (
                "a2.json".to_owned(),
                on(&["bti", "paca", "pacg"], "on", None),
            ),
        ])
        .expect("two machines");
        assert_eq!(m.variance[flag].explained_by, ["machine"]);
        assert_eq!(m.variance[flag].strength, "controlled");

        // A later report of the configuration that replaces a cell names a moved gating rule.
        let m = build_with(
            &[
                (
                    "a1.json".to_owned(),
                    on(&[], "indeterminate", Some("machine-lacks-bti")),
                ),
                (
                    "a1-again.json".to_owned(),
                    on(&[], "indeterminate", Some("needs-vm")),
                ),
            ],
            Repeated::Replace,
        )
        .expect("replaced");
        assert_eq!(m.cells[0].gating[flag], "needs-vm");
        assert!(
            m.warnings.iter().any(
                |w| w.contains("under gating.rule machine-lacks-bti in a1.json")
                    && w.contains("under gating.rule needs-vm in a1-again.json")
            ),
            "{:?}",
            m.warnings
        );
    }

    #[test]
    fn two_targets_compare_the_architecture_only_on_one_machine() {
        let on = |features: &[&str], verdict: &str, rule: Option<&str>| {
            let mut r = report("ol", "10.2", "gcc", "14.3.1", "glibc", "bare", &[]);
            r["toolchain"]["target"]["arch"] = "aarch64".into();
            r["environment"]["execution"]["image"] = "oci-ol10".into();
            r["environment"]["cpu"] = json!({"relevant_features": features});
            let mut obs =
                json!({"flag": "-mbranch-protection=bti (BTI enforced)", "verdict": verdict});
            if let Some(rule) = rule {
                obs["gating"] = json!({"rule": rule});
            }
            r["observations"] = json!([obs]);
            r
        };
        let flag = "-mbranch-protection=bti (BTI enforced)";
        // Two architectures on two machines: the architecture is the toolchain's target and
        // the machine the CPU the run had, two changes, so neither is a controlled comparison.
        let mut x86 = on(&[], "off", None);
        x86["toolchain"]["target"]["arch"] = "x86_64".into();
        x86["environment"]["cpu"] =
            json!({"vendor": "GenuineIntel", "model_name": "Xeon", "relevant_features": []});
        let m = build(&[
            ("x86.json".to_owned(), x86.clone()),
            (
                "a2.json".to_owned(),
                on(&["bti", "paca", "pacg"], "on", None),
            ),
        ])
        .expect("two architectures");
        assert_eq!(m.variance[flag].explained_by, Vec::<String>::new());
        assert_eq!(m.variance[flag].strength, "none");
        assert!(
            m.variance[flag].note.contains(r#"["arch", "machine"]"#),
            "{}",
            m.variance[flag].note
        );
        // One machine, two targets under one profile (a driver for x86 beside the native one; a
        // `-m32` profile would change the profile too): the architecture alone.
        let m_arch_base = x86.clone();
        let mut x86_32 = x86.clone();
        x86_32["toolchain"]["target"]["arch"] = "x86".into();
        x86_32["observations"] = json!([{"flag": flag, "verdict": "unsupported"}]);
        let m = build(&[
            ("x86.json".to_owned(), x86),
            ("x86-m32.json".to_owned(), x86_32),
        ])
        .expect("two targets on one machine");
        assert_eq!(m.variance[flag].explained_by, ["arch"]);
        assert_eq!(m.variance[flag].strength, "controlled");
        // A `-m32` profile beside a `-m64` one: the profile's flags chose the target, so the
        // profile changed too (its id carries a hash of the flags), and neither is compared.
        let mut m64 = m_arch_base.clone();
        m64["profile"]["id"] = "explicit:c1e6c54d9448".into();
        let mut m32 = m64.clone();
        m32["profile"]["id"] = "explicit:a716de576aa4".into();
        m32["toolchain"]["target"]["arch"] = "x86".into();
        m32["observations"] = json!([{"flag": flag, "verdict": "build-failed"}]);
        let m = build(&[("m64.json".to_owned(), m64), ("m32.json".to_owned(), m32)])
            .expect("two profiles");
        assert_eq!(m.variance[flag].explained_by, Vec::<String>::new());
        assert!(
            m.variance[flag].note.contains(r#"["arch", "profile"]"#),
            "{}",
            m.variance[flag].note
        );
    }

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
        // Each of the four fits, a value per report, and none is the one thing that changed:
        // not `controlled`, and nothing in `explained_by`.
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(v.strength, "none");
        assert!(
            v.note
                .contains(r#"["distro", "release", "compiler", "compiler_version"]"#),
            "{}",
            v.note
        );
    }

    #[test]
    fn the_arch_axis_reads_the_target_the_toolchain_built_for() {
        let flag = "-fcf-protection=full";
        let run = |target: &str, libc: &str, verdict: &str| {
            let mut r = report(
                "fedora",
                "44",
                "gcc",
                "16.2.1",
                libc,
                "bare",
                &[(flag, verdict)],
            );
            r["toolchain"]["target"]["arch"] = target.into();
            r
        };
        let native = run("x86_64", "glibc2.43", "off");
        let cross = run("aarch64", "unknown", "unsupported");
        assert_eq!(
            native["environment"]["kernel"]["arch"],
            cross["environment"]["kernel"]["arch"]
        );
        let m = build(&[
            ("native.json".to_owned(), native.clone()),
            ("cross.json".to_owned(), cross),
        ])
        .expect("two targets are two cells");
        assert_eq!(m.axes["arch"], ["aarch64", "x86_64"]);
        assert_eq!(m.varying_axes, ["libc", "arch"]);
        let v = &m.variance[flag];
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(v.strength, "none");
        // The cross run's libc reads `unknown`, so the libc fits nothing; the architecture
        // identifies the two runs and compares nothing, since the libc may have changed too.
        assert!(v.note.contains(r#"["arch"]"#), "{}", v.note);

        // The kernel's architecture is no axis: a run whose chard was built for aarch64,
        // measuring the same x86_64 target, is a repeat of the native run.
        let mut elsewhere = native.clone();
        elsewhere["environment"]["kernel"]["arch"] = "aarch64".into();
        let err = build(&[
            ("native.json".to_owned(), native),
            ("elsewhere.json".to_owned(), elsewhere),
        ])
        .expect_err("one target is one configuration");
        assert!(
            err.to_string()
                .contains("arch x86_64, machine GenuineIntel/Xeon features:none"),
            "{err}"
        );
    }

    #[test]
    fn controlled_is_one_change_seen_at_its_grains() {
        let fedora = |kind: &str, version: &str, libc: &str, verdict: &str| {
            (
                format!("{kind}-{libc}.json"),
                report(
                    "fedora",
                    "44",
                    kind,
                    version,
                    libc,
                    "bare",
                    &[("-fx", verdict)],
                ),
            )
        };
        let m = build(&[
            fedora("gcc", "16.1.1", "glibc", "on"),
            fedora("clang", "21.1.8", "glibc", "off"),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert_eq!(v.explained_by, ["compiler"]);
        assert_eq!(v.strength, "controlled");
        // The one pair cannot tell the compiler from its version, and the note says so.
        assert_eq!(v.confounded_with["compiler"], ["compiler_version"]);

        let m = build(&[
            fedora("gcc", "16.1.1", "glibc", "on"),
            fedora("clang", "21.1.8", "musl", "off"),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(v.strength, "none");

        // The compiler beside a change of where the run executed: two changes.
        let mut elsewhere = fedora("clang", "21.1.8", "glibc", "off");
        elsewhere.1["environment"]["execution"]["mode"] = "host".into();
        let m = build(&[fedora("gcc", "16.1.1", "glibc", "on"), elsewhere]).expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        // And beside a change of profile.
        let mut hardened = fedora("clang", "21.1.8", "glibc", "off");
        hardened.1["profile"]["id"] = "hardened".into();
        let m = build(&[fedora("gcc", "16.1.1", "glibc", "on"), hardened]).expect("built");
        assert_eq!(m.variance["-fx"].explained_by, Vec::<String>::new());

        // The libc beside any other axis of the key is two changes, each axis in turn: the
        // basis, the image, and a version of the same compiler.
        for (axis, value) in [
            ("execution_basis", json!("asserted-and-corroborated")),
            ("image", json!("fedora-44-image")),
            ("compiler_version", json!("16.2.0")),
        ] {
            let mut other = fedora("gcc", "16.1.1", "musl", "off");
            match axis {
                "execution_basis" => {
                    other.1["environment"]["execution"]["mode_evidence"]["basis"] = value;
                }
                "image" => other.1["environment"]["execution"]["image"] = value,
                _ => other.1["toolchain"]["version"] = value,
            }
            let m = build(&[fedora("gcc", "16.1.1", "glibc", "on"), other]).expect("built");
            let v = &m.variance["-fx"];
            assert!(v.explained_by.is_empty(), "{axis}: {:?}", v.explained_by);
        }

        // A third configuration that changes the libc alone: the libc groups two agreeing
        // reports, which outranks a comparison.
        let m = build(&[
            fedora("gcc", "16.1.1", "glibc", "on"),
            fedora("clang", "21.1.8", "musl", "off"),
            fedora("clang", "21.1.8", "glibc", "on"),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert_eq!(v.explained_by, ["libc"], "{}", v.note);
        assert_eq!(v.strength, "grouped", "glibc groups two agreeing reports");
    }

    #[test]
    fn a_version_is_not_compared_across_compilers() {
        let m = build(&[
            (
                "gcc13.json".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "13",
                    "glibc",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "gcc14.json".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "14",
                    "musl",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
            (
                "clang18.json".to_owned(),
                report(
                    "fedora",
                    "44",
                    "clang",
                    "18",
                    "glibc",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(v.strength, "none");
        // The axes that only fit are named, and none is published as confounded.
        assert!(v.note.contains(r#"["compiler_version"]"#), "{}", v.note);
        assert!(v.confounded_with.is_empty(), "{:?}", v.confounded_with);
    }

    #[test]
    fn a_pair_that_reads_alike_compares_nothing() {
        let one = |release: &str, profile: &str, libc: &str, verdict: &str| {
            (
                format!("{release}-{profile}-{libc}.json"),
                report(
                    "alpine",
                    release,
                    "gcc",
                    "14",
                    libc,
                    profile,
                    &[("-fx", verdict)],
                ),
            )
        };
        let m = build(&[
            one("3.20", "bare", "glibc", "on"),
            one("3.20", "bare", "musl", "on"),
            one("3.20", "hardened", "uclibc", "off"),
            one("3.21", "hardened", "musl1.2", "on"),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.is_empty(), "{:?} {}", v.explained_by, v.note);
        assert_eq!(v.strength, "none");
        assert!(v.note.contains(r#"["libc"]"#), "{}", v.note);
    }

    #[test]
    fn a_distribution_is_compared_with_its_release_and_not_with_its_libc() {
        let m = build(&[
            (
                "debian.json".to_owned(),
                report(
                    "debian",
                    "13",
                    "gcc",
                    "14.2.0",
                    "glibc2.41",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "ubuntu.json".to_owned(),
                report(
                    "ubuntu",
                    "25.04",
                    "gcc",
                    "14.2.0",
                    "glibc2.41",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert_eq!(v.explained_by, ["distro"], "{}", v.note);
        assert_eq!(v.strength, "controlled");

        let m = build(&[
            (
                "debian.json".to_owned(),
                report(
                    "debian",
                    "13",
                    "gcc",
                    "14.2.0",
                    "glibc2.41",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "alpine.json".to_owned(),
                report(
                    "alpine",
                    "3.21",
                    "gcc",
                    "14.2.0",
                    "musl1.2.5",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(v.strength, "none");
    }

    #[test]
    fn a_contradicted_architecture_is_its_own_value_and_never_known() {
        let flag = "-fcf-protection=full";
        let native = report(
            "fedora",
            "44",
            "gcc",
            "16.2.1",
            "glibc2.43",
            "bare",
            &[(flag, "off")],
        );
        let mut wrapped = report(
            "fedora",
            "44",
            "gcc",
            "16.2.1",
            "glibc2.43",
            "bare",
            &[(flag, "indeterminate")],
        );
        wrapped["toolchain"]["target"]["macros"] = json!({"agreement": "disagrees"});
        assert_eq!(arch_of(&wrapped), format!("x86_64{CONTRADICTED}"));
        let m = build(&[
            ("native.json".to_owned(), native.clone()),
            ("wrapped.json".to_owned(), wrapped.clone()),
        ])
        .expect("two cells, not a repeat");
        assert_eq!(m.axes["arch"], ["x86_64", "x86_64 (contradicted)"]);
        assert_eq!(m.variance[flag].explained_by, Vec::<String>::new());
        assert_eq!(m.variance[flag].strength, "none");

        for path in ["agreement", "abi", "profile_macros"] {
            let mut r = native.clone();
            if path == "agreement" {
                r["toolchain"]["target"]["agreement"] = "disagrees".into();
            } else {
                r["toolchain"]["target"][path] = json!({"agreement": "disagrees"});
            }
            assert_eq!(arch_of(&r), "x86_64 (contradicted)", "{path}");
        }
        // Any other word, `overruled` and `superseded` among them, leaves the architecture.
        let mut r = native.clone();
        r["toolchain"]["target"]["macros"] = json!({"agreement": "superseded"});
        assert_eq!(arch_of(&r), "x86_64");
        // A C++ dump's `disagrees` alone does not: it witnesses the C++ probes, and a C++ check
        // it withheld marks the run by its gating rule.
        let mut r = native.clone();
        r["toolchain"]["target"]["profile_macros_cxx"] = json!({"agreement": "disagrees"});
        assert_eq!(arch_of(&r), "x86_64");
        for rule in CONTRADICTING_RULES {
            r["observations"] = json!([
                {"flag": flag, "verdict": "indeterminate", "gating": {"rule": rule}}
            ]);
            assert_eq!(arch_of(&r), "x86_64 (contradicted)", "{rule}");
        }
        // A target without an architecture reads empty, contradicted or not.
        let mut r = wrapped.clone();
        r["toolchain"]["target"]
            .as_object_mut()
            .expect("an object")
            .remove("arch");
        assert_eq!(arch_of(&r), "");
        // An absent target reads empty: never the kernel's architecture.
        let mut r = wrapped;
        r["toolchain"]
            .as_object_mut()
            .expect("an object")
            .remove("target");
        assert_eq!(arch_of(&r), "");
    }

    #[test]
    fn an_unknown_value_compares_nothing() {
        let blank = |libc: &str, verdict: &str| {
            let mut r = report(
                "fedora",
                "44",
                "gcc",
                "16.2.1",
                libc,
                "bare",
                &[("-fx", verdict)],
            );
            r["toolchain"]
                .as_object_mut()
                .expect("an object")
                .remove("target");
            (format!("{libc}.json"), r)
        };
        let m = build(&[blank("glibc", "on"), blank("musl", "off")]).expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(v.strength, "none");
        for (axis, value, is) in [
            ("image", "", true),
            ("arch", "", false),
            ("machine", "unread", false),
            ("libc", "unknown", false),
            ("execution_basis", UNPUBLISHED_BASIS, false),
            ("arch", "x86_64 (contradicted)", false),
            ("arch", "x86_64", true),
        ] {
            assert_eq!(known(axis, value), is, "{axis} {value:?}");
        }
    }

    #[test]
    fn the_machine_and_the_architecture_are_confounded_where_they_move_together() {
        let run = |arch: &str, vendor: &str, release: &str, verdict: &str| {
            let mut r = report(
                "fedora",
                release,
                "gcc",
                "16.2.1",
                "glibc",
                "bare",
                &[("-fx", verdict)],
            );
            r["toolchain"]["target"]["arch"] = arch.into();
            r["environment"]["cpu"] =
                json!({"vendor": vendor, "model_name": "m", "relevant_features": []});
            (format!("{arch}-{release}.json"), r)
        };
        let m = build(&[
            run("x86_64", "GenuineIntel", "43", "off"),
            run("x86_64", "GenuineIntel", "44", "off"),
            run("aarch64", "ARM", "43", "on"),
            run("aarch64", "ARM", "44", "on"),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert_eq!(v.explained_by, ["arch", "machine"]);
        assert_eq!(v.strength, "grouped");
        assert_eq!(v.confounded_with["arch"], ["machine"]);
        assert_eq!(v.confounded_with["machine"], ["arch"]);
        assert!(v.note.contains("cannot tell them apart"), "{}", v.note);
    }

    #[test]
    fn a_controlled_axis_is_not_confounded_with_what_its_pair_held() {
        let m = build(&[
            (
                "glibc.json".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "16",
                    "glibc",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
            (
                "musl.json".to_owned(),
                report(
                    "fedora",
                    "44",
                    "gcc",
                    "16",
                    "musl",
                    "bare",
                    &[("-fx", "off")],
                ),
            ),
            (
                "uclibc.json".to_owned(),
                report(
                    "ubuntu",
                    "26.04",
                    "clang",
                    "21",
                    "uclibc",
                    "bare",
                    &[("-fx", "on")],
                ),
            ),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert_eq!(v.explained_by, ["libc"], "{}", v.note);
        assert_eq!(v.strength, "controlled");
        assert!(v.confounded_with.is_empty(), "{:?}", v.confounded_with);
        assert!(
            v.note
                .contains("differ in `libc` and in no other axis of the key"),
            "{}",
            v.note
        );
    }

    #[test]
    fn unknown_values_form_no_group() {
        let run = |distro: &str, release: &str, contradicted: bool, verdict: &str| {
            let mut r = report(
                distro,
                release,
                "gcc",
                "14",
                "glibc",
                "bare",
                &[("-fx", verdict)],
            );
            if contradicted {
                r["toolchain"]["target"]["macros"] = json!({"agreement": "disagrees"});
            }
            (format!("{distro}-{release}.json"), r)
        };
        let m = build(&[
            run("fedora", "43", true, "off"),
            run("fedora", "44", true, "off"),
            run("debian", "12", false, "on"),
            run("debian", "13", false, "on"),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert_eq!(v.explained_by, ["distro"], "{}", v.note);
        assert_eq!(v.strength, "grouped");
        assert!(
            !v.confounded_with.contains_key("arch"),
            "{:?}",
            v.confounded_with
        );
    }

    #[test]
    fn a_pair_explains_where_no_single_axis_fits() {
        let one = |name: &str, distro: &str, kind: &str, profile: &str, verdict: &str| {
            let version = if kind == "gcc" { "14" } else { "18" };
            (
                format!("{name}.json"),
                report(
                    distro,
                    "1",
                    kind,
                    version,
                    "glibc",
                    profile,
                    &[("-fx", verdict)],
                ),
            )
        };
        let m = build(&[
            one("a", "ubuntu", "gcc", "p1", "on"),
            one("b", "ubuntu", "gcc", "p2", "on"),
            one("c", "ubuntu", "clang", "p1", "off"),
            one("d", "fedora", "gcc", "p2", "off"),
        ])
        .expect("built");
        let v = &m.variance["-fx"];
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(
            v.explained_by_combination.as_deref(),
            Some(&["distro".to_owned(), "compiler".to_owned()][..])
        );
        assert!(
            v.note
                .contains("No single axis partitions these observations consistently."),
            "{}",
            v.note
        );
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
        let v = &m.variance["-fortify"];
        assert_eq!(v.explained_by, vec!["libc".to_owned()]);
        assert_eq!(v.strength, "controlled");
        assert!(
            v.note
                .contains("differ in `libc` and in no other axis of the key"),
            "{}",
            v.note
        );
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

    #[test]
    fn cells_without_the_flag_do_not_dissolve_its_confound() {
        // distro is nested inside compiler_version: alpha only ever appears with 10,
        // beta only with 11.
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
        // `-fq`.
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
        // `compiler_version` fits a value per configuration, and every pair that reads `-f`
        // differently changed the libc or the compiler beside it: it explains nothing, and its
        // confounds still keep the pair out.
        assert!(v.explained_by.is_empty(), "{:?}", v.explained_by);
        assert_eq!(v.strength, "none");
        assert!(v.confounded_with.is_empty(), "{:?}", v.confounded_with);
        assert_eq!(v.explained_by_combination, None, "{}", v.note);
    }

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

    /// The measured shape ([`Repeated`]): a full run, a run of fewer checks of the same
    /// configuration through a wrapper that moves two of them, and a report of another
    /// configuration, with a flag read with no verdict, polarities that differ, and a flag
    /// each of the pair carries alone.
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
                        glibc, arch x86_64, machine GenuineIntel/Xeon features:none, profile bare, \
                        execution vm, execution_basis measured, image (none)";

    #[test]
    fn a_repeated_configuration_is_refused() {
        let [full, wrapped, other] = full_wrapped_and_other();
        // Each repeat is named against the report it repeats, with the configuration in full.
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
        // In either order: the cell is the later report's alone, and the warning names each
        // flag read differently and each flag only one report carries, not the one read alike.
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
