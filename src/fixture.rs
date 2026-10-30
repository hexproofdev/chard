// SPDX-License-Identifier: BSD-3-Clause

//! Replaying recorded evidence through the detectors.
//!
//! chard's detectors are the place a wrong answer gets published, and without this
//! module they would be exercised against exactly one toolchain: whichever compiler
//! happens to be on the developer's machine. That is the configuration least like the
//! ones a sweep meets. A detector that misreads gcc 8.5's diagnostic wording, or musl's
//! ELF shape, or clang 10's phrasing, would produce a wrong verdict silently and no test
//! would notice.
//!
//! The material to test that is on disk. Every archived report carries the literal
//! evidence its detectors consumed: `build.stderr` for the compiler-diag channel,
//! `run.stdout` for runtime, `evidence.elf` for elf-static (or the report's `facts`
//! store, keyed by `build.artifact_sha256`, in the current shape),
//! `evidence.macros` for macro. The compiler versions the fixture file holds are the ones
//! `SUPPORT.md`'s matrix lists, which `tests/support_matrix.rs` holds to it. This module
//! turns that evidence into fixtures and replays them.
//!
//! # Fixtures are curated, not frozen
//!
//! This is the part that matters, and it is a discipline rather than a mechanism.
//!
//! A recorded verdict is what the detector that wrote the report made of its evidence,
//! and that detector is not necessarily right. gcc's `auto-var-init` results in the
//! archive are loader residue rather than measurements, and an archived
//! `format-security` or `int-conversion` verdict can read an unrelated linker error as a
//! hardening escalation. Freezing the archive as expected output would enshrine those
//! readings.
//!
//! So a replay difference is a **question, not a failure**. Each one is either a
//! correction, in which case the fixture's expectation is updated with a note saying
//! why, or a bug just introduced. The harness's job is to make sure no such
//! change passes unnoticed; deciding which kind it is remains a human judgement, and
//! [`Fixture::note`] exists to record that judgement next to the data.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::compile::BuildRecord;
use crate::elf::ElfFacts;
use crate::probe::{self, Evidence};
use crate::run::RunRecord;

/// One recorded (evidence, verdict) pair for a single check on a single toolchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    /// The check this evidence was gathered for.
    pub check: String,
    /// The control arm this evidence is, `positive`, `negative` or `regime`; absent for the
    /// observation's own build.
    ///
    /// Arm rows exist because the cases a triple withholds on live in its arms: a positive
    /// control that did not show the observable, a negative that did. Mining measured builds
    /// alone, such a case would replay only where some measured build happened to share the
    /// arm's facts. [`thin`] groups arm rows apart from
    /// measured ones, so neither spends the other's slots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arm: Option<String>,
    /// The toolchain that produced it, e.g. `gcc-8.5.0-glibc2.28-rocky8.10`. Kept so
    /// a failure names the environment rather than just the check.
    ///
    /// **Not unique on its own.** The id names the compiler, its libc and its
    /// distribution, and says nothing about the architecture they ran on, because a
    /// report already carries that separately. See [`Fixture::arch`].
    pub toolchain: String,
    /// The architecture the evidence was recorded on, from the toolchain's target
    /// triple.
    ///
    /// This exists because the toolchain id does not carry one and the corpus is no
    /// longer single-architecture. `gcc-15.2.0-glibc2.43-ubuntu26.04` names the
    /// toolchain on x86_64 and the toolchain on aarch64 identically, and this file
    /// holds rows from both — the aarch64 ones being what closed the four
    /// `branch-protection`/`gcs` checks. Without this field the two are
    /// indistinguishable, and a reader asking which architecture produced a
    /// `gcs-marked` fixture has nothing to read.
    ///
    /// Derived rather than asserted, so it can be checked: where a fixture also has an
    /// `elf` block, this must agree with the machine the ELF header reports, which is a
    /// fact about the artifact rather than a string the toolchain chose. That agreement
    /// is pinned in `detector_replay.rs`.
    ///
    /// `None` for the hand-authored `synthetic:` fixtures, which stand in for a
    /// compiler's behaviour rather than for a machine, and for evidence mined from a
    /// report too old to name a target triple — the tree contains none of the latter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// The profile in force, since the same check answers differently under `bare` and
    /// under a flag list supplied through `explicit`. Some fixtures name profiles this
    /// build does not have, `distro-buildflags` among them; the field is a label on
    /// archived evidence rather than a profile this build can run.
    pub profile: String,
    /// The detector outcome this fixture is pinned to.
    ///
    /// **Not** taken from the archive. The archived reports record a `verdict`, which
    /// is a different and incomparable thing: it folds in the control triple and the
    /// gating, so `off` there may mean "the detector said absent" or "the controls
    /// discriminated and the measured build lacked it". Replaying a detector against
    /// that would compare two different quantities and fail for the wrong reasons.
    ///
    /// Instead this is a **reviewed baseline**: the evidence is real and comes from a
    /// toolchain we cannot otherwise reach, and the expectation is what today's
    /// detector makes of it, inspected once when the fixture was created. That also
    /// sidesteps the enshrining problem described in the module docs: nothing here
    /// inherits a verdict from the detector that wrote the archive.
    pub expected: String,
    /// The verdict the archive recorded, kept for context only. Never asserted on.
    /// Useful when reviewing a diff: a fixture whose baseline disagrees with the old
    /// published verdict is worth a second look.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_verdict: Option<String>,
    /// The level alongside the outcome, where the check reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_level: Option<String>,
    /// Why this expectation is what it is, when it is not simply "as recorded" —
    /// the place to record that a difference was reviewed and the archive was wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub macros: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf: Option<ElfFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunRecord>,
}

/// The outcome of replaying one fixture.
#[derive(Debug)]
pub struct Replay {
    pub fixture_check: String,
    pub toolchain: String,
    pub expected: String,
    pub got: String,
    pub expected_level: Option<String>,
    pub got_level: Option<String>,
}

impl Replay {
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.expected == self.got && self.expected_level == self.got_level
    }
}

impl Fixture {
    /// Run this fixture's evidence back through its check's decoder, `Check::decode`, the
    /// entry point a measurement reads through.
    ///
    /// Returns `None` when the check does not exist in the corpus, which is a
    /// legitimate outcome (checks get renamed and removed) and is reported by the
    /// caller as a stale fixture rather than as a failure.
    #[must_use]
    pub fn replay(&self) -> Option<Replay> {
        let check = probe::CORPUS
            .iter()
            .flat_map(|p| p.checks)
            .find(|c| c.id == self.check)?;

        let evidence = Evidence {
            macros: &self.macros,
            elf: self.elf.as_ref(),
            build: self.build.as_ref(),
            run: self.run.as_ref(),
            workdir: None,
        };
        let detection = check.decode(&evidence).detection;

        Some(Replay {
            fixture_check: self.check.clone(),
            toolchain: self.toolchain.clone(),
            expected: self.expected.clone(),
            got: detection.outcome.as_str().to_owned(),
            expected_level: self.expected_level.clone(),
            got_level: detection.level.clone(),
        })
    }
}

/// The architecture a target triple names, as its first component.
///
/// `x86_64-pc-linux-gnu` and `aarch64-redhat-linux` give `x86_64` and `aarch64`. Three
/// aliases are normalised. OpenBSD's `amd64` is the same architecture under the name that
/// platform uses; leaving it distinct would split one architecture into two in every count
/// and in [`thin`]'s key. Apple's `arm64` is `aarch64` the same way: its triple spells the
/// machine as the kernel does, chard's own `toolchain.target.arch` reads `-dumpmachine`'s
/// `arm64-apple-darwin` as `aarch64`, and `SUPPORT.md`'s macOS row is keyed on that name;
/// a Darwin row labelled `arm64` would reach no row of the matrix. `i386` through `i686` name
/// one `EM_386` family by the oldest CPU
/// the code may assume, and fold to `i386`, the ELF reader's name for that machine: gcc
/// 12.2.0 in a Debian 12 i386 container reports `i686-linux-gnu`, and a row mined from it
/// would be labelled `i686` against a header reading `i386`, which
/// `the_architecture_label_agrees_with_the_elf_header` refuses. Nothing else is
/// normalised, because a normalisation table is a place for a guess to hide, and the
/// mapping here is checked against the ELF header's machine wherever a fixture carries one.
fn arch_of_triple(triple: &str) -> Option<String> {
    let first = triple.split('-').next()?;
    if first.is_empty() {
        return None;
    }
    Some(match first {
        "amd64" => "x86_64".to_owned(),
        "arm64" => "aarch64".to_owned(),
        "i386" | "i486" | "i586" | "i686" => "i386".to_owned(),
        other => other.to_owned(),
    })
}

/// What a mined fixture says in place of the directory a probe was actually built in.
const WORKDIR_PLACEHOLDER: &str = "<workdir>";

/// Where a person's directory lives on the platforms this corpus is mined from. Not a
/// survey of filesystem layouts — a list of the prefixes under which a path names an
/// operator rather than a toolchain.
const HOME_ROOTS: [&str; 3] = ["/home/", "/Users/", "/root/"];

/// Where one path ends and the next thing begins, in an argv element or in a diagnostic.
///
/// The colon earns its place here: `file.c:45:12: warning:` is the shape most of the
/// paths in this corpus appear in.
const PATH_TERMINATORS: [char; 9] = [' ', '\t', '\n', '"', '\'', ',', ':', ';', ')'];

/// The home-rooted path in `token`, if that is what it is.
///
/// A token is home-rooted when the path it carries *begins* at one of [`HOME_ROOTS`] —
/// not when it contains one. `/opt/rh/gcc-toolset-15/root//usr/lib/...` is the sysroot
/// Red Hat's toolset prints in every diagnostic almalinux 8's clang emits, and it holds
/// `/root/` without being rooted at anybody's home. A substring rule would rewrite a
/// toolchain's own directory into a placeholder: evidence turned into nonsense to satisfy
/// a pattern, which is a worse outcome than the leak it was guarding against.
///
/// Whatever precedes the first `/` must therefore be nothing, or a flag carrying its
/// argument — `-I`, `-L`, `-isystem`. A flag is what a path prefix looks like before it
/// has become a path.
fn home_rooted(token: &str) -> Option<String> {
    let (before_slash, rest) = token.split_once('/')?;
    if !before_slash.is_empty() && !before_slash.starts_with('-') {
        return None;
    }
    let path = format!("/{rest}");
    HOME_ROOTS
        .iter()
        .any(|root| path.starts_with(root))
        .then_some(path)
}

/// Every home-rooted path in `text`, in the order they appear.
///
/// Public because two callers need the same answer from the same rule:
/// [`scrub_operator_paths`] below, and
/// `detector_replay.rs::no_fixture_carries_an_operators_home_path`, which reads the
/// tracked corpus back and fails on anything the first one did not reach. Two spellings
/// of one rule is how a corpus ends up with a path the scrubber missed and the test
/// forgave.
#[must_use]
pub fn home_rooted_paths(text: &str) -> Vec<String> {
    text.split(PATH_TERMINATORS)
        .filter_map(home_rooted)
        .collect()
}

/// Replace the directory part of any home-rooted path in `argv` with
/// [`WORKDIR_PLACEHOLDER`].
///
/// `tests/fixtures/detectors.json` is a tracked file, and a probe's build line names the
/// directory it ran in. Inside a guest that is the harness's own `/home/chard`, which
/// names nobody; mined from a report measured on a development host it is the operator's
/// home, which is the host-specific detail `scripts/leak-gate.sh` exists to refuse. It
/// reached the corpus for the first time in the 2026-09-07 regeneration, that being the
/// first one to name a development host's reports among its sources — the gate would have
/// caught it at the commit, one step after the corpus was already written.
///
/// Only `argv` is scrubbed, and the restraint is the point. A path there is invocation
/// bookkeeping: no detector reads the name of the directory a source file sat in, and the
/// replay re-derives every expectation after the rewrite, so a detector that did read one
/// would surface as a moved expectation rather than as a silent difference. A path inside
/// `stdout` or `stderr` is not the same thing — it sits inside a diagnostic a detector
/// matches on — so those are left exactly as recorded, and the corpus test fails on the
/// ones that are nobody's guest account. A substitution rule is the wrong instrument for
/// evidence; a stop is the right one.
fn scrub_operator_paths(argv: &mut [String]) {
    for arg in argv {
        for path in home_rooted_paths(arg) {
            // `home_rooted` only returns a path that begins at a root, so the separator
            // it splits on is one the path is guaranteed to hold; the `else` is the
            // compiler's requirement rather than a case.
            let Some((_directory, base)) = path.rsplit_once('/') else {
                continue;
            };
            *arg = arg.replace(&path, &format!("{WORKDIR_PLACEHOLDER}/{base}"));
        }
    }
}

/// Pull fixtures out of one archived report.
///
/// Only observations that carry replayable evidence are taken. An observation whose
/// build failed, or which was gated out before any detector ran, has nothing to
/// replay and contributes no fixture — including it would assert that a detector
/// produces `indeterminate` from no input, which tests the harness rather than the
/// detector.
///
/// `raw` is the parsed report JSON rather than a typed `Report`, because the archive
/// spans several schema versions and a typed parse would reject the older ones — the
/// very ones carrying the oldest and most valuable toolchains.
#[must_use]
pub fn extract(raw: &serde_json::Value) -> Vec<Fixture> {
    let toolchain = raw
        .get("toolchain")
        .and_then(|t| t.get("id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    // Every report that names a toolchain also names a target triple — checked across
    // every source the current fixture set was mined from, with no exceptions. The files
    // that lack a triple are the `inspect` and `session` surveys, which carry no
    // toolchain id and no observations either, so they yield no fixture to label. `None`
    // is therefore reachable only from a report shape nobody here has, which is why it
    // is an absent label rather than a failure.
    let arch = raw
        .get("toolchain")
        .and_then(|t| t.get("target_triple"))
        .and_then(serde_json::Value::as_str)
        .and_then(arch_of_triple);
    let profile = raw
        .get("profile")
        .and_then(|p| p.get("id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_owned();

    let Some(observations) = raw
        .get("observations")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    // The typed store the arms' entries resolve through, `elf-delta` included. A report
    // older than the store, or one whose store does not read, yields no arm rows.
    let store = raw
        .get("facts")
        .map(<crate::report::FactStore as serde::Deserialize>::deserialize);

    let mut out = Vec::new();
    for obs in observations {
        let Some(check) = obs.get("check").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let archived_verdict = obs
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);

        let evidence = obs.get("evidence");
        let macros: BTreeMap<String, String> = evidence
            .and_then(|e| e.get("macros"))
            .and_then(|m| serde_json::from_value(m.clone()).ok())
            .unwrap_or_default();
        let Ok(elf) = recorded_elf(raw, obs) else {
            continue;
        };
        let mut build: Option<BuildRecord> = obs
            .get("build")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let mut run: Option<RunRecord> = obs
            .get("run")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        // Before anything keeps a reference to them: the fixture that gets built below is
        // what lands in a tracked file. See [`scrub_operator_paths`].
        if let Some(build) = build.as_mut() {
            scrub_operator_paths(&mut build.argv);
        }
        if let Some(run) = run.as_mut() {
            scrub_operator_paths(&mut run.argv);
        }

        // Nothing to replay: see the doc comment.
        if elf.is_none() && build.is_none() && run.is_none() && macros.is_empty() {
            continue;
        }

        let mut fixture = Fixture {
            check: check.to_owned(),
            arm: None,
            toolchain: toolchain.clone(),
            arch: arch.clone(),
            profile: profile.clone(),
            // Filled from a live replay below — see the field's documentation for why
            // it is not taken from the archive.
            expected: String::new(),
            archived_verdict,
            expected_level: None,
            note: None,
            macros,
            elf,
            build,
            run,
        };

        // Establish the baseline by running this build's detector over this evidence. A
        // check the corpus does not hold yields nothing rather than a fixture
        // pinned to an expectation nobody can reproduce.
        let Some(replay) = fixture.replay() else {
            continue;
        };
        fixture.expected = replay.got;
        fixture.expected_level = replay.got_level;
        out.push(fixture);
        // A store that does not read says nothing about any arm, and yields no arm rows.
        if let Some(Ok(store)) = store.as_ref() {
            out.extend(arm_fixtures(
                store,
                obs,
                check,
                &toolchain,
                arch.as_deref(),
                &profile,
            ));
        }
    }
    out
}

/// One row per evaluated control arm of `obs`: the arm's stored facts, its build and run,
/// and the outcome today's decoder reads in them, with the outcome the report published
/// for the arm kept in `archived_verdict`.
///
/// An arm is mined only where the report can reproduce what its decoder read: its
/// artifact's entry resolves (an `elf`, an `elf-delta` over its base, or `unreadable`,
/// which is no facts), or the store keeps no entry and the check's decoder reads none
/// (`detect::READS_UNSTORED_ARTIFACT` lists the ones that do). Macros come from the arm's
/// own source: the dump for a preprocessor arm, the artifact's `.chard.report` otherwise.
fn arm_fixtures(
    store: &crate::report::FactStore,
    obs: &serde_json::Value,
    check: &str,
    toolchain: &str,
    arch: Option<&str>,
    profile: &str,
) -> Vec<Fixture> {
    use crate::report::FactEntry;
    let Some(controls) = obs.get("controls") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (field, arm) in [
        ("positive", "positive"),
        ("negative", "negative"),
        ("regime_negative", "regime"),
    ] {
        let Some(published) = controls.get(field) else {
            continue;
        };
        let Some(outcome) = published.get("outcome").and_then(serde_json::Value::as_str) else {
            continue;
        };
        // A record the arm publishes and that does not parse is an arm the report cannot
        // reproduce, and is skipped rather than mined as no record.
        let mut build: Option<BuildRecord> = match published.get("build") {
            None => None,
            Some(v) => match serde_json::from_value(v.clone()) {
                Ok(build) => Some(build),
                Err(_) => continue,
            },
        };
        let mut run: Option<RunRecord> = match published.get("run") {
            None => None,
            Some(v) => match serde_json::from_value(v.clone()) {
                Ok(run) => Some(run),
                Err(_) => continue,
            },
        };
        let artifact = build.as_ref().and_then(|b| b.artifact_sha256.clone());
        let elf = match artifact.as_deref().map(|key| (key, store.get(key))) {
            None | Some((_, Some(FactEntry::Unreadable { .. }))) => None,
            Some((key, Some(_))) => match store.elf_facts(key) {
                Some(facts) => Some(facts.into_owned()),
                None => continue,
            },
            Some((_, None)) if !crate::detect::READS_UNSTORED_ARTIFACT.contains(&check) => None,
            Some((_, None)) => continue,
        };
        // The arm's own macro source. A preprocessor dump the store does not hold is a
        // source the report does not say, and skips the arm. Otherwise the macros are the
        // artifact's `.chard.report`: empty where the entry carries none (an artifact the
        // reader refused, or one with no report), and where the store keeps no entry for
        // an arm whose decoder reads none, as the `elf` match above admitted.
        let dump_key = match published
            .get("macro_source")
            .and_then(serde_json::Value::as_str)
        {
            Some("preprocessor") => match published
                .get("macro_dump")
                .and_then(|d| d.get("stdout_sha256"))
                .and_then(serde_json::Value::as_str)
            {
                Some(key) if store.get(key).is_some() => Some(key.to_owned()),
                _ => continue,
            },
            _ => None,
        };
        let macros = dump_key
            .or_else(|| artifact.clone())
            .and_then(|key| store.macro_view(&key))
            .unwrap_or_default();
        if elf.is_none() && build.is_none() && run.is_none() && macros.is_empty() {
            continue;
        }
        if let Some(build) = build.as_mut() {
            scrub_operator_paths(&mut build.argv);
        }
        if let Some(run) = run.as_mut() {
            scrub_operator_paths(&mut run.argv);
        }
        let mut fixture = Fixture {
            check: check.to_owned(),
            arm: Some(arm.to_owned()),
            toolchain: toolchain.to_owned(),
            arch: arch.map(ToOwned::to_owned),
            profile: profile.to_owned(),
            expected: String::new(),
            archived_verdict: Some(outcome.to_owned()),
            expected_level: None,
            note: None,
            macros,
            elf,
            build,
            run,
        };
        let Some(replay) = fixture.replay() else {
            continue;
        };
        fixture.expected = replay.got;
        fixture.expected_level = replay.got_level;
        out.push(fixture);
    }
    out
}

/// An observation's ELF facts, from either shape a report has carried them in.
///
/// Inline as `evidence.elf` in the older shape, and in the current shape in the report's
/// `facts` store, under the observation's `build.artifact_sha256`. The inline
/// shape is read first, because an archive carrying it has no store.
///
/// `Ok(None)` is a report that says the artifact had no facts: no inline block and no
/// store (the older shape, where the block is absent for exactly the observations with
/// none), no artifact digest, or a store entry of kind `unreadable`. [`Unsaid`] is one
/// that does not say: a store with no entry under the digest, an entry of a kind this
/// revision does not know, an `elf` entry that does not parse, or an `elf-delta`, which
/// holds only an arm's changes and which `fact-store-disagrees-with-references` refuses
/// under an observation's own build. A missing
/// `evidence.elf` beside a store is never read as "no facts", since that would replay an
/// elf-static detector over nothing and pin whatever it made of that as the expectation.
fn recorded_elf(
    raw: &serde_json::Value,
    obs: &serde_json::Value,
) -> Result<Option<ElfFacts>, Unsaid> {
    if let Some(inline) = obs.get("evidence").and_then(|e| e.get("elf")) {
        return Ok(Some(serde_json::from_value(inline.clone())?));
    }
    let Some(store) = raw.get("facts") else {
        return Ok(None);
    };
    let Some(key) = obs
        .get("build")
        .and_then(|b| b.get("artifact_sha256"))
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    let entry = store.get(key).ok_or(Unsaid)?;
    match entry.get("kind").and_then(serde_json::Value::as_str) {
        Some("elf") => Ok(Some(serde_json::from_value(
            entry.get("elf").ok_or(Unsaid)?.clone(),
        )?)),
        Some("unreadable") => Ok(None),
        _ => Err(Unsaid),
    }
}

/// A report that does not say what an observation's artifact was: see [`recorded_elf`].
struct Unsaid;

/// Facts that do not parse as [`ElfFacts`] say nothing a detector can be replayed over.
impl From<serde_json::Error> for Unsaid {
    fn from(_: serde_json::Error) -> Self {
        Self
    }
}

/// The reviewed baseline a fixture is pinned to: the outcome name, and the level where the
/// check reports one. Two fixtures with the same pair demonstrate the same thing.
type Baseline = (String, Option<String>);

/// What [`thin`] caps over: a check, a compiler family, the architecture it ran on, and
/// the arm (`None` for a measured build), so arm rows never spend measured rows' slots.
/// `None` for the architecture is a row that never named one, which groups with its like.
type GroupKey = (String, String, Option<String>, Option<String>);

/// Keep at most `per_check` fixtures for each `(check, toolchain-family, arch)` group.
///
/// The archive holds hundreds of near-identical reports, and a fixture set that large
/// is slow to run and — worse — unreviewable, which defeats the curation discipline
/// this module depends on. Diversity of *toolchain* is what buys coverage here, not
/// volume: ten Fedora 44 rows for one check say nothing that one says.
#[must_use]
pub fn thin(mut fixtures: Vec<Fixture>, per_check: usize) -> Vec<Fixture> {
    fixtures.sort_by(|a, b| {
        a.check
            .cmp(&b.check)
            .then_with(|| a.toolchain.cmp(&b.toolchain))
            .then_with(|| a.arch.cmp(&b.arch))
            .then_with(|| a.profile.cmp(&b.profile))
    });

    // Group first, choose second. A cap applied in one pass would make the *sort order
    // above* the tiebreak, and profiles sort with `bare` first, so a group with more rows
    // than slots would keep the unhardened ones and drop the rest. See `choose` for what
    // that costs.
    let mut groups: BTreeMap<GroupKey, Vec<(usize, Baseline)>> = BTreeMap::new();
    for (i, f) in fixtures.iter().enumerate() {
        // Family = the first two dash-separated components of the toolchain id,
        // which for `clang-14.0.6-glibc2.35-ubuntu22.04` is `clang-14.0.6`: the
        // compiler and its *full* version, not its major, and not the libc.
        //
        // Grouping by major-plus-libc would be the better key — that is what
        // actually varies the evidence, since two Ubuntu releases on one gcc major
        // rarely differ while glibc and musl differ constantly. This is deliberately
        // not that: it splits 14.0.0 from 14.0.6 and so keeps strictly more
        // fixtures, and `thin` feeds the replay harness, so narrowing the key would
        // silently drop recorded evidence that tests currently check against.
        //
        // The architecture is part of the key for a sharper reason than diversity: the
        // toolchain id does not carry one, so `gcc-15.2.0-glibc2.43-ubuntu26.04` on
        // aarch64 and the same id on x86_64 land in one group without it, and the cap
        // then drops whichever of the two the input order put second. That is the
        // aarch64 evidence roughly half the time, silently, for every check both
        // architectures answer. Widening the key never drops a row that a narrower one
        // kept, so the x86_64-only groups are untouched by this.
        let family = f.toolchain.split('-').take(2).collect::<Vec<_>>().join("-");
        // The architecture stays an `Option` in the key rather than becoming `""`: a row
        // that never had one groups with the other rows that never had one, which is the
        // honest reading, and no substituted value stands in for a missing fact.
        groups
            .entry((f.check.clone(), family, f.arch.clone(), f.arm.clone()))
            .or_default()
            .push((i, (f.expected.clone(), f.expected_level.clone())));
    }

    let chosen: BTreeSet<usize> = groups
        .values()
        .flat_map(|members| choose(members, per_check))
        .collect();

    let mut kept: Vec<Fixture> = Vec::new();
    for (i, f) in fixtures.into_iter().enumerate() {
        if chosen.contains(&i) {
            kept.push(f);
        }
    }
    kept
}

/// Pick at most `per_check` of one group's rows, spending the slots on distinct
/// outcomes before spending them on more of the same.
///
/// A fixture set that only ever says `absent` for a check tests nothing a detector
/// hardwired to return `absent` would fail, and the cap alone produces exactly that.
/// Profiles sort `bare`, `bare-optimized`, `explicit:cli`, `openssf-tldr`, so the two
/// slots would go to the two profiles that turn hardening *off*; every recording of the
/// feature being present sorts last and would be dropped. On the aarch64 evidence that
/// makes `gcs-macro` and `gcs-marked` unanimously `absent` across all eight rows, while
/// four reports carrying `aarch64_gcs=true` sit in the input and never reach the file.
///
/// The count is the cap's: this returns `min(per_check, members.len())`, so no group
/// loses a row to the reordering. Only *which* rows fill the slots differs.
fn choose(members: &[(usize, Baseline)], per_check: usize) -> Vec<usize> {
    let mut picked: Vec<usize> = Vec::new();
    let mut outcomes: BTreeSet<&Baseline> = BTreeSet::new();

    // First pass: one row per outcome the group can demonstrate, earliest first.
    for (i, outcome) in members {
        if picked.len() >= per_check {
            break;
        }
        if outcomes.insert(outcome) {
            picked.push(*i);
        }
    }
    // Second pass: fill any slot the first pass left, in the same order as before, so
    // a group whose rows all agree keeps exactly what it always kept.
    for (i, _) in members {
        if picked.len() >= per_check {
            break;
        }
        if !picked.contains(i) {
            picked.push(*i);
        }
    }
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `agrees` is the whole verdict of the replay harness, so it is tested directly.
    ///
    /// Nothing else can test it. The harness collects the fixtures that *disagree* and
    /// asserts that list is empty, so on a green tree `agrees` returns `true` every time
    /// it is called and a version hardwired to `true` behaves identically. Without this
    /// test, mutating it that way, and swapping its `&&` for `||`, both survive a
    /// `cargo mutants` run over this file with every test passing. A harness whose
    /// comparison never fires would report `ok` while comparing nothing, which is the same
    /// vacuity `detector_replay.rs` already guards against for stale and unreplayed
    /// fixtures.
    #[test]
    fn a_replay_agrees_only_when_the_outcome_and_the_level_both_match() {
        let replay = |expected: &str, got: &str, el: Option<&str>, gl: Option<&str>| Replay {
            fixture_check: "ssp-level".to_owned(),
            toolchain: "gcc-16.1.1-glibc2.43-fedora44".to_owned(),
            expected: expected.to_owned(),
            got: got.to_owned(),
            expected_level: el.map(ToOwned::to_owned),
            got_level: gl.map(ToOwned::to_owned),
        };
        assert!(replay("present", "present", Some("strong"), Some("strong")).agrees());
        assert!(replay("absent", "absent", None, None).agrees());

        // The outcome moved.
        assert!(!replay("present", "absent", Some("strong"), Some("strong")).agrees());
        // The outcome held and the level moved, which is the case an `||` would pass:
        // `-fstack-protector-strong` silently becoming `-fstack-protector` is a real
        // hardening regression that leaves the outcome at `present`.
        assert!(!replay("present", "present", Some("strong"), Some("basic")).agrees());
        // A level appearing or disappearing counts too.
        assert!(!replay("present", "present", Some("strong"), None).agrees());
        assert!(!replay("present", "present", None, Some("strong")).agrees());
    }

    /// An observation with no evidence at all must not become a fixture: replaying it
    /// would assert what a detector does with nothing, which tests the harness.
    #[test]
    fn observations_without_evidence_are_skipped() {
        let raw = serde_json::json!({
            "toolchain": {"id": "gcc-8.5.0-glibc2.28-rocky8.10"},
            "profile": {"id": "bare"},
            "observations": [
                {"check": "pie", "verdict": "off"},
            ]
        });
        assert!(extract(&raw).is_empty());
    }

    #[test]
    fn evidence_bearing_observations_are_extracted_with_their_toolchain() {
        let raw = serde_json::json!({
            "toolchain": {"id": "gcc-8.5.0-glibc2.28-rocky8.10"},
            "profile": {"id": "bare"},
            "observations": [
                {
                    "check": "ssp-level",
                    "verdict": "on",
                    "evidence": {"macros": {"__SSP_STRONG__": "3"}}
                },
            ]
        });
        let got = extract(&raw);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].check, "ssp-level");
        assert_eq!(got[0].toolchain, "gcc-8.5.0-glibc2.28-rocky8.10");
        assert_eq!(
            got[0].expected, "present",
            "baseline comes from a live replay"
        );
        assert_eq!(got[0].expected_level.as_deref(), Some("strong"));
    }

    /// ELF facts are read from the report's store where the report has one and from the
    /// observation where an archive carries them inline, and a store that cannot say what
    /// the artifact was yields no fixture rather than one replayed over nothing.
    #[test]
    fn extract_reads_facts_from_the_store_and_from_inline_archives() {
        let recorded: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/elf/elf32-le-i386-pie.expected.json"
        ))
        .expect("a checked-in record");
        let facts = recorded["facts"].clone();
        let key = "a".repeat(64);
        let pie = |evidence: serde_json::Value| {
            serde_json::json!({
                "check": "pie",
                "verdict": "on",
                "evidence": evidence,
                "build": {"argv": ["cc"], "exit_status": 0, "stdout": "", "stderr": "",
                          "duration_ms": 0, "artifact_sha256": key},
            })
        };
        let report = |observation: serde_json::Value, store: Option<serde_json::Value>| {
            let mut raw = serde_json::json!({
                "toolchain": {"id": "gcc-16.1.1-glibc2.43-fedora44"},
                "profile": {"id": "bare"},
                "observations": [observation],
            });
            if let Some(store) = store {
                raw["facts"] = store;
            }
            raw
        };

        let inline = extract(&report(pie(serde_json::json!({"elf": facts})), None));
        let stored = extract(&report(
            pie(serde_json::json!({})),
            Some(serde_json::json!({key.clone(): {"kind": "elf", "elf": facts}})),
        ));
        assert_eq!(inline.len(), 1);
        assert_eq!(stored.len(), 1);
        assert!(inline[0].elf.is_some() && stored[0].elf.is_some());
        assert_eq!(
            serde_json::to_value(&inline[0].elf).expect("facts serialize"),
            serde_json::to_value(&stored[0].elf).expect("facts serialize"),
            "the two shapes carry one set of facts"
        );
        assert_eq!(
            (inline[0].expected.as_str(), stored[0].expected.as_str()),
            ("present", "present")
        );

        // An unreadable artifact is a report saying there were no facts; its build still
        // replays.
        let unreadable = extract(&report(
            pie(serde_json::json!({})),
            Some(serde_json::json!({key.clone(): {"kind": "unreadable", "error": "x"}})),
        ));
        assert_eq!(unreadable.len(), 1);
        assert!(unreadable[0].elf.is_none());

        // A store with no entry for the digest, one of a kind this build does not
        // know, or an arm's partial `elf-delta` under the observation's own build does not
        // say, and the observation contributes nothing.
        for store in [
            serde_json::json!({}),
            serde_json::json!({key.clone(): {"kind": "elf-v2", "elf": facts}}),
            serde_json::json!({key.clone(): {"kind": "elf-delta", "base": "b".repeat(64),
                                             "elf_changes": {"pie": true}}}),
        ] {
            assert!(
                extract(&report(pie(serde_json::json!({})), Some(store.clone()))).is_empty(),
                "{store}"
            );
        }
    }

    /// An arm is mined where the store reproduces what its decoder read, and skipped where
    /// it does not. An arm whose artifact the store keeps no entry for is mined only for a
    /// check whose decoder reads no unstored artifact. A preprocessor arm is mined only
    /// where the store holds its dump. A build alone is enough to replay.
    #[test]
    fn an_arm_is_mined_only_where_the_store_reproduces_its_reading() {
        let recorded: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/elf/elf32-le-i386-pie.expected.json"
        ))
        .expect("a checked-in record");
        let (own, arm, dump) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let build = |key: &str| {
            serde_json::json!({"argv": ["cc"], "exit_status": 0, "stdout": "", "stderr": "",
                               "duration_ms": 0, "artifact_sha256": key})
        };
        let arms = |check: &str, positive: &serde_json::Value, store: &serde_json::Value| {
            let raw = serde_json::json!({
                "toolchain": {"id": "gcc-16.1.1-glibc2.43-fedora44"},
                "profile": {"id": "bare"},
                "observations": [{"check": check, "verdict": "on", "evidence": {},
                                  "build": build(&own), "controls": {"positive": positive}}],
                "facts": store,
            });
            extract(&raw)
                .into_iter()
                .filter(|f| f.arm.is_some())
                .collect::<Vec<_>>()
        };
        let mut store = serde_json::json!({own.clone(): {"kind": "elf", "elf": recorded["facts"]}});
        let built = serde_json::json!({"outcome": "present", "build": build(&arm)});
        assert_eq!(arms("pie", &built, &store).len(), 1);
        assert!(crate::detect::READS_UNSTORED_ARTIFACT.contains(&"cxx-stdlib-assertions"));
        assert!(arms("cxx-stdlib-assertions", &built, &store).is_empty());

        let mut preprocessed = built;
        preprocessed["macro_source"] = "preprocessor".into();
        preprocessed["macro_dump"] = serde_json::json!({"stdout_sha256": dump});
        assert!(
            arms("pie", &preprocessed, &store).is_empty(),
            "a dump the store lacks"
        );
        store[dump.as_str()] = serde_json::json!({"kind": "macro-dump", "defines": 1,
                                                  "macros_filter": "f", "macros": {"__PIE__": "2"}});
        let mined = arms("pie", &preprocessed, &store);
        assert_eq!(mined.len(), 1, "a dump the store holds");
        assert_eq!(mined[0].arm.as_deref(), Some("positive"));
        assert_eq!(
            mined[0].macros,
            BTreeMap::from([("__PIE__".to_owned(), "2".to_owned())]),
            "the arm's macros are its dump's"
        );
    }

    /// The architecture comes from the triple's first component, with the aliases folded.
    #[test]
    fn the_architecture_is_the_triples_first_component() {
        // Every triple shape the mined reports actually carry.
        for (triple, want) in [
            ("x86_64-pc-linux-gnu", "x86_64"),
            ("x86_64-redhat-linux", "x86_64"),
            ("x86_64-alpine-linux-musl", "x86_64"),
            ("x86_64-chimera-linux-musl", "x86_64"),
            ("aarch64-redhat-linux", "aarch64"),
            ("aarch64-linux-gnu", "aarch64"),
            // OpenBSD names the same architecture `amd64`. Folded, because two names
            // for one machine would split every count and every `thin` group in two.
            ("amd64-unknown-openbsd7.9", "x86_64"),
            // Apple names aarch64 `arm64`, as chard's own target reading folds it.
            ("arm64-apple-darwin27.0.0", "aarch64"),
            // The i386 family under the CPU it assumes, folded to the ELF reader's name
            // for `EM_386`, which the replay corpus checks every label against.
            ("i686-linux-gnu", "i386"),
            ("i586-alpine-linux-musl", "i386"),
            ("i386-unknown-freebsd15.1", "i386"),
        ] {
            assert_eq!(arch_of_triple(triple).as_deref(), Some(want), "{triple}");
        }
        assert_eq!(
            arch_of_triple(""),
            None,
            "an empty triple names no architecture"
        );
    }

    #[test]
    fn extraction_records_the_architecture_alongside_the_toolchain() {
        let raw = serde_json::json!({
            "toolchain": {
                "id": "gcc-15.2.0-glibc2.43-ubuntu26.04",
                "target_triple": "aarch64-linux-gnu"
            },
            "profile": {"id": "bare"},
            "observations": [
                {"check": "ssp-level", "evidence": {"macros": {"__SSP_STRONG__": "3"}}},
            ]
        });
        let got = extract(&raw);
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].arch.as_deref(),
            Some("aarch64"),
            "the toolchain id names ubuntu26.04 on both architectures; only this \
             field says which one recorded the evidence"
        );
    }

    /// A report too old to name a triple still yields fixtures, with no architecture.
    ///
    /// The alternative — dropping them — would trade the oldest toolchains in the
    /// corpus for a label, and those are the ones that cannot be reinstalled.
    #[test]
    fn a_report_without_a_triple_still_yields_fixtures() {
        let raw = serde_json::json!({
            "toolchain": {"id": "gcc-8.5.0-glibc2.28-rocky8.10"},
            "profile": {"id": "bare"},
            "observations": [
                {"check": "ssp-level", "evidence": {"macros": {"__SSP_STRONG__": "3"}}},
            ]
        });
        let got = extract(&raw);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].arch, None);
    }

    /// A mined build line keeps the driver and the flags, and loses the directory.
    ///
    /// The home is the harness's own account rather than an invented person's.
    /// `scripts/leak-gate.sh` hunts a username through every blob in the object graph and
    /// cannot tell a fictional operator from a real one — this test named an invented
    /// person's home for one commit, on the true observation that the gate scanned only
    /// `/home/`, which was a hole in the gate rather than a licence. The gate scans both roots as of
    /// 2026-09-07 and forgives `chard` under either, so the test uses the name that names
    /// nobody. The rule under test does not distinguish the two.
    #[test]
    fn extraction_scrubs_the_operators_directory_out_of_a_build_line() {
        let raw = serde_json::json!({
            "toolchain": {"id": "gcc-16.2.1-glibc2.43-fedora44"},
            "profile": {"id": "bare"},
            "observations": [{
                "check": "ssp-level",
                "evidence": {"macros": {"__SSP_STRONG__": "3"}},
                "build": {
                    "argv": [
                        "/usr/bin/gcc",
                        "-fstack-protector-strong",
                        "-o",
                        "/Users/chard/chard-work/ssp-clean",
                        "/Users/chard/chard-work/ssp.c"
                    ],
                    "exit_status": 0,
                    "stdout": "",
                    "stderr": "",
                    "duration_ms": 12
                }
            }]
        });
        let got = extract(&raw);
        let argv = &got[0]
            .build
            .as_ref()
            .expect("the build record is kept")
            .argv;
        assert_eq!(
            argv,
            &[
                "/usr/bin/gcc".to_owned(),
                "-fstack-protector-strong".to_owned(),
                "-o".to_owned(),
                "<workdir>/ssp-clean".to_owned(),
                "<workdir>/ssp.c".to_owned(),
            ],
            "the driver and the flags are what the evidence is; the directory is only \
             where the operator happened to stand"
        );
    }

    /// The rewrite is by prefix, so a path riding on a flag is reached too, and a path
    /// naming no home is left alone.
    #[test]
    fn scrubbing_reaches_an_attached_path_and_spares_a_system_one() {
        let mut argv = [
            "-I/home/chard/chard-work/include".to_owned(),
            "-L/Users/chard/build/lib".to_owned(),
            "/usr/lib/gcc/x86_64-linux-gnu/16/crtbegin.o".to_owned(),
            "-Wl,-rpath-link,/root/scratch/chard-work".to_owned(),
            // Red Hat's toolset sysroot, which contains `/root/` and is nobody's home.
            // This row is the reason the rule is token-aware; almalinux 8's clang prints
            // this path in every diagnostic it emits.
            "/opt/rh/gcc-toolset-15/root//usr/bin/ld".to_owned(),
        ];
        scrub_operator_paths(&mut argv);
        assert_eq!(
            argv,
            [
                "-I<workdir>/include".to_owned(),
                "-L<workdir>/lib".to_owned(),
                "/usr/lib/gcc/x86_64-linux-gnu/16/crtbegin.o".to_owned(),
                "-Wl,-rpath-link,<workdir>/chard-work".to_owned(),
                "/opt/rh/gcc-toolset-15/root//usr/bin/ld".to_owned(),
            ],
            "a system path names a toolchain, not a person, and stays as recorded"
        );
    }

    /// One architecture must not crowd the other out of a check's slots.
    ///
    /// This is the failure the `arch` field exists to prevent, and it is silent: the
    /// two rows below carry the same toolchain id and the same profile, so before the
    /// key was widened they shared one group, the cap kept `per_check` of them, and
    /// which architecture survived was decided by the order the directories were read
    /// in. For a check that only aarch64 can answer that is the difference between
    /// evidence and none.
    #[test]
    fn one_architecture_does_not_crowd_out_the_other() {
        let mk = |tc: &str, arch: &str| Fixture {
            check: "pie".to_owned(),
            arm: None,
            toolchain: tc.to_owned(),
            arch: Some(arch.to_owned()),
            profile: "bare".to_owned(),
            expected: "absent".to_owned(),
            archived_verdict: None,
            expected_level: None,
            note: None,
            macros: BTreeMap::from([("X".to_owned(), "1".to_owned())]),
            elf: None,
            build: None,
            run: None,
        };
        let id = "gcc-15.2.0-glibc2.43-ubuntu26.04";
        let got = thin(vec![mk(id, "x86_64"), mk(id, "aarch64")], 1);
        assert_eq!(
            got.len(),
            2,
            "one row per (check, family, arch), not per (check, family)"
        );
        let arches: Vec<&str> = got.iter().filter_map(|f| f.arch.as_deref()).collect();
        assert!(
            arches.contains(&"x86_64") && arches.contains(&"aarch64"),
            "both architectures survive thinning, got {arches:?}"
        );
    }

    /// The slots go to distinct outcomes before they go to more of the same.
    ///
    /// Mutating `choose` back to a plain `take(per_check)` over the sorted order
    /// reproduces the bug this test exists for: `bare` sorts first, so both slots go to rows
    /// saying `absent` and the `present` recording is dropped.
    #[test]
    fn thinning_spends_its_slots_on_distinct_outcomes() {
        let mk = |profile: &str, expected: &str| Fixture {
            check: "gcs-marked".to_owned(),
            arm: None,
            toolchain: "gcc-16.1.1-glibc2.43-fedora44".to_owned(),
            arch: Some("aarch64".to_owned()),
            profile: profile.to_owned(),
            expected: expected.to_owned(),
            archived_verdict: None,
            expected_level: None,
            note: None,
            macros: BTreeMap::from([("X".to_owned(), "1".to_owned())]),
            elf: None,
            build: None,
            run: None,
        };
        // The real shape of the aarch64 evidence: hardening off under both `bare`
        // profiles, on under the two that ask for it, and the latter sort last.
        let got = thin(
            vec![
                mk("bare", "absent"),
                mk("bare-optimized", "absent"),
                mk("explicit:cli", "present"),
                mk("openssf-tldr", "present"),
            ],
            2,
        );
        assert_eq!(got.len(), 2, "the cap still caps");
        let outcomes: BTreeSet<&str> = got.iter().map(|f| f.expected.as_str()).collect();
        assert_eq!(
            outcomes,
            BTreeSet::from(["absent", "present"]),
            "both outcomes survive thinning; a set that is unanimously `absent` would \
             pass a detector hardwired to return `absent`, got {got:?}"
        );
    }

    /// Preferring distinct outcomes must not cost a group any rows.
    #[test]
    fn thinning_keeps_the_same_number_of_rows_when_every_outcome_agrees() {
        let mk = |profile: &str| Fixture {
            check: "pie".to_owned(),
            arm: None,
            toolchain: "gcc-16.1.1-glibc2.43-fedora44".to_owned(),
            arch: Some("x86_64".to_owned()),
            profile: profile.to_owned(),
            expected: "present".to_owned(),
            archived_verdict: None,
            expected_level: None,
            note: None,
            macros: BTreeMap::from([("X".to_owned(), "1".to_owned())]),
            elf: None,
            build: None,
            run: None,
        };
        let got = thin(
            vec![mk("bare"), mk("bare-optimized"), mk("openssf-tldr")],
            2,
        );
        assert_eq!(got.len(), 2, "one outcome, still two slots filled");
        assert_eq!(
            got.iter().map(|f| f.profile.as_str()).collect::<Vec<_>>(),
            vec!["bare", "bare-optimized"],
            "and filled in the order they always were"
        );
    }

    /// Thinning must keep toolchain diversity rather than the first N of anything.
    #[test]
    fn thinning_keeps_one_row_per_toolchain_family() {
        let mk = |check: &str, tc: &str| Fixture {
            check: check.to_owned(),
            arm: None,
            toolchain: tc.to_owned(),
            arch: Some("x86_64".to_owned()),
            profile: "bare".to_owned(),
            expected: "absent".to_owned(),
            archived_verdict: None,
            expected_level: None,
            note: None,
            macros: BTreeMap::from([("X".to_owned(), "1".to_owned())]),
            elf: None,
            build: None,
            run: None,
        };
        let got = thin(
            vec![
                mk("pie", "gcc-8.5.0-glibc2.28-rocky8.10"),
                mk("pie", "gcc-8.5.0-glibc2.28-almalinux8.10"),
                mk("pie", "gcc-16.1.1-glibc2.43-fedora44"),
            ],
            1,
        );
        // Two rocky/alma rows share the gcc-8.5.0 family; fedora is its own.
        assert_eq!(got.len(), 2, "one row per (check, compiler+libc family)");
    }
}
