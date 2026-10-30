// SPDX-License-Identifier: BSD-3-Clause

//! Replay recorded evidence from real toolchains through the detectors.
//!
//! Until this existed, chard's detectors were exercised against exactly one
//! toolchain (whichever compiler was on the developer's machine) which is the
//! configuration least like the ones a sweep meets. These fixtures carry evidence
//! from toolchains that cannot be reproduced here, the ones `SUPPORT.md`'s matrix
//! lists (`tests/support_matrix.rs` holds the matrix to the fixture file).
//!
//! # What a failure means
//!
//! A difference is a **question, not a verdict on the change**. The baseline is what
//! the detectors made of this evidence when the fixture was reviewed, so a diff means
//! behaviour moved on real-world input. That is sometimes exactly right: three
//! detector bugs were fixed the week these were written, and fixing them *should*
//! move baselines. What it must never do is move silently.
//!
//! So when this test fails: read the diff, decide whether the new answer is better,
//! and if it is, regenerate and record why in the fixture's `note` field. Do not
//! regenerate to make the test green.
//!
//! # Regenerating
//!
//! ```sh
//! CHARD_FIXTURE_SOURCES=/path/to/sweep-output \
//!   CHARD_REGENERATE_FIXTURES=1 cargo test --test detector_replay recorded_evidence \
//!   -- --nocapture
//! ```
//!
//! `--nocapture` because libtest holds a passing test's stderr, so without it the
//! accounting below (what was read, what was carried, what was lost) prints only when
//! the run fails. The filter keeps the other tests in this file from reading the fixture
//! file while it is being rewritten.
//!
//! Reads every chard report in the named directories (`:`-separated for several) and
//! rewrites the fixture file. Without `CHARD_FIXTURE_SOURCES` it falls back to the
//! `ARCHIVES` names inside the checkout, which stop resolving once those working
//! directories are deleted.
//!
//! A regeneration that would drop a (toolchain, architecture) pair the file already
//! holds refuses before writing, naming each pair and whether the sources supplied it.
//! Two variables change that. `CHARD_FIXTURE_MERGE=1` carries the previous mined rows of
//! every pair the sources do not supply, so a regeneration from today's reports keeps
//! the compilers only older sweeps reached. `CHARD_FIXTURE_ALLOW_LOSS=1` writes despite
//! the loss, for a retirement someone decided on. See [`assemble`] for the mechanism.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chard::fixture::{self, Fixture};

/// Archived sweep outputs to mine when nothing else is named. These are working
/// directories rather than committed data, so a missing one is skipped rather than
/// failing: a fresh clone has the fixtures but not the archives they came from.
const ARCHIVES: &[&str] = &["chard-v2-out", "chard-final-out", "chard-vm-out"];

/// The environment variable naming where to read reports from, `:`-separated.
const SOURCES_VAR: &str = "CHARD_FIXTURE_SOURCES";

/// Toolchain prefix marking a fixture no sweep can produce, because the toolchain does
/// not exist here to be measured: gcc 4 predating a flag, clang 14 below a version
/// floor, a build that dies without writing anything.
const HAND_AUTHORED: &str = "synthetic:";

/// Mined fixtures, plus the hand-authored ones the mining cannot produce.
///
/// A regeneration that wrote only what it mined would silently delete every hand-authored
/// fixture in the file, each carrying a `note` saying which compiler behaviour it stands in
/// for, and not one of those compilers installable on this host. The documented procedure
/// would destroy the least reproducible evidence in the corpus and say nothing, because the
/// totals go *up*: more checks covered, fewer toolchains, no line naming the loss.
///
/// They bypass [`fixture::thin`] deliberately. Thinning caps fixtures per check and
/// compiler family to keep the file reviewable, which is the right rule for mined
/// evidence (there is more of it than anyone will read) and the wrong rule for a case
/// somebody wrote by hand precisely because nothing else covers it.
fn merge_hand_authored(mined: Vec<Fixture>, previous: &[Fixture]) -> Vec<Fixture> {
    let mut out = mined;
    out.extend(
        previous
            .iter()
            .filter(|f| f.toolchain.starts_with(HAND_AUTHORED))
            .cloned(),
    );
    out.sort_by(|a, b| {
        (&a.check, &a.toolchain, &a.arch, &a.profile).cmp(&(
            &b.check,
            &b.toolchain,
            &b.arch,
            &b.profile,
        ))
    });
    out
}

/// Set to carry previous mined rows whose (toolchain, arch) no source supplies.
const MERGE_VAR: &str = "CHARD_FIXTURE_MERGE";

/// Set to write a regeneration that drops a (toolchain, arch) pair the file held.
const ALLOW_LOSS_VAR: &str = "CHARD_FIXTURE_ALLOW_LOSS";

/// Where a mined row came from: the toolchain id and the architecture it ran on.
///
/// The pair rather than the id, because the id does not name an architecture (see
/// [`Fixture::arch`]): `gcc-15.2.0-glibc2.43-ubuntu26.04` is one string on x86_64 and on
/// aarch64, and keying on the string alone would count the aarch64 rows as kept for as
/// long as the x86_64 ones survived.
type Origin = (String, Option<String>);

fn origin(f: &Fixture) -> Origin {
    (f.toolchain.clone(), f.arch.clone())
}

/// One (toolchain, arch) pair the previous file held and the new one does not.
#[derive(Debug, PartialEq, Eq)]
struct Lost {
    origin: Origin,
    /// Whether any source supplied rows for the pair. `true` means [`fixture::thin`]
    /// spent every slot the pair competed for on another toolchain of the same family;
    /// `false` means the sources never had it, which [`MERGE_VAR`] addresses.
    sourced: bool,
}

/// What a regeneration would write, and what it would cost.
struct Assembly {
    kept: Vec<Fixture>,
    /// Hand-authored rows carried over; see [`merge_hand_authored`].
    hand_authored: usize,
    /// Previous mined rows carried because no source supplied their pair.
    unsourced_rows: usize,
    unsourced_pairs: usize,
    lost: Vec<Lost>,
}

/// Build the fixture set from freshly extracted rows and the file they replace.
///
/// `extracted` is everything the sources yielded, before thinning, so "the sources
/// supplied this pair" is decided on what was read rather than on what thinning kept.
///
/// With `merge`, the previous file's mined rows are carried for every (toolchain, arch)
/// the sources did not supply. They were already thinned when they were written and are
/// carried whole, bypassing a second [`fixture::thin`]: thinning them against today's
/// rows of the same family would spend their slots on whichever sorted first, which is
/// the silent loss this exists to stop. A pair the sources *did* supply is never carried
/// from the old file, so a re-measured toolchain's rows are always today's.
///
/// Loss is computed on pairs, after merging: every pair of the previous file, the
/// hand-authored ones included, that the result lacks.
fn assemble(extracted: Vec<Fixture>, previous: &[Fixture], merge: bool) -> Assembly {
    let sourced: BTreeSet<Origin> = extracted.iter().map(origin).collect();
    let mut mined = fixture::thin(extracted, PER_CHECK);

    let unsourced: Vec<Fixture> = if merge {
        previous
            .iter()
            .filter(|f| !f.toolchain.starts_with(HAND_AUTHORED))
            .filter(|f| !sourced.contains(&origin(f)))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let unsourced_rows = unsourced.len();
    let unsourced_pairs = unsourced.iter().map(origin).collect::<BTreeSet<_>>().len();
    mined.extend(unsourced);

    let kept = merge_hand_authored(mined, previous);
    let hand_authored = previous
        .iter()
        .filter(|f| f.toolchain.starts_with(HAND_AUTHORED))
        .count();

    let now: BTreeSet<Origin> = kept.iter().map(origin).collect();
    let before: BTreeSet<Origin> = previous.iter().map(origin).collect();
    let lost = before
        .difference(&now)
        .map(|o| Lost {
            sourced: sourced.contains(o),
            origin: o.clone(),
        })
        .collect();

    Assembly {
        kept,
        hand_authored,
        unsourced_rows,
        unsourced_pairs,
        lost,
    }
}

/// The line a regeneration prints about lost pairs, zero included.
fn describe_loss(lost: &[Lost]) -> String {
    let mut lines = vec![format!(
        "losing {} toolchain(s) this host cannot reproduce",
        lost.len()
    )];
    lines.extend(lost.iter().map(|l| {
        let (toolchain, arch) = &l.origin;
        format!(
            "  {toolchain} ({}): {}",
            arch.as_deref().unwrap_or("no arch"),
            if l.sourced {
                "in the sources, thinned away"
            } else {
                "absent from the sources"
            }
        )
    }));
    lines.join("\n")
}

/// Refuse a regeneration that drops a pair, unless the caller allowed it.
///
/// A loss printed and then written anyway has only a person reading a line of stderr between
/// it and the file, and a regeneration mined from one sweep can drop eleven toolchains
/// (`tests/fixtures/README.md`). The toolchains are what this file exists to carry, since
/// no host here can install them again.
fn refuse_loss(lost: &[Lost], allow: bool) -> Result<(), String> {
    if lost.is_empty() || allow {
        return Ok(());
    }
    let unsourced = lost.iter().filter(|l| !l.sourced).count();
    Err(format!(
        "refusing to write: {}\nNothing was written. {unsourced} of these the sources did \
         not supply: name the reports that hold them in {SOURCES_VAR}, or set {MERGE_VAR}=1 \
         to carry their previous rows. The rest were thinned away by another toolchain of \
         the same family. To drop them deliberately, set {ALLOW_LOSS_VAR}=1 and record \
         why in the commit.",
        describe_loss(lost)
    ))
}

/// At most this many fixtures per (check, compiler-family, architecture), spent on
/// distinct detector outcomes first; see [`chard::fixture::thin`]. Diversity of
/// toolchain and of answer is what buys coverage; volume just makes the file
/// unreviewable.
const PER_CHECK: usize = 2;

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/detectors.json")
}

/// Where to read reports from, and whether the caller chose it.
///
/// The three `ARCHIVES` names are sweep output directories inside the checkout, and no
/// machine is expected to hold them: they are working state, and working state gets
/// deleted. Regeneration from them would need a directory recreated under a name whose
/// only record is this constant, which is why the bring-up notes list the path as blocked.
///
/// `CHARD_FIXTURE_SOURCES` takes a `:`-separated list of directories holding chard
/// reports, so a caller names a sweep wherever it actually lives. An environment
/// variable rather than a constant because the real paths are outside the checkout: a
/// path to them written here would be host-specific detail in a tracked file, which
/// `scripts/leak-gate.sh` refuses and should.
///
/// A directory named through the variable and absent is an **error**, while a missing
/// `ARCHIVES` entry is skipped. The asymmetry is deliberate: a typo in a path the caller
/// typed would otherwise mine nothing, extract nothing, and be indistinguishable from a
/// sweep that had nothing to give.
fn sources() -> Vec<PathBuf> {
    let Some(named) = std::env::var_os(SOURCES_VAR) else {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        return ARCHIVES.iter().map(|a| root.join(a)).collect();
    };
    let named = named.to_string_lossy().into_owned();
    let dirs: Vec<PathBuf> = named
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    assert!(
        !dirs.is_empty(),
        "{SOURCES_VAR} is set but names no directory"
    );
    for dir in &dirs {
        assert!(
            dir.is_dir(),
            "{SOURCES_VAR} names {}, which is not a directory",
            dir.display()
        );
    }
    dirs
}

/// The fixture file a regeneration replaces, which its losses are counted against.
///
/// An unreadable or unparseable file read as an empty baseline would have nothing to lose: the
/// refusal in [`refuse_loss`] would pass vacuously on exactly the run least able to show what it
/// dropped. Absent is the one state that means "no baseline".
fn baseline(path: &Path) -> Vec<Fixture> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
            panic!(
                "{} exists and does not parse ({e}), so a regeneration has no baseline \
                 to account its losses against",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => panic!("reading {}: {e}", path.display()),
    }
}

fn regenerate() {
    let dirs = sources();
    let mut all = Vec::new();
    let mut seen_dirs = 0;
    let mut files = 0;
    let mut unreadable = 0;
    let mut unparsed = 0;
    let mut barren = 0;

    for dir in &dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        seen_dirs += 1;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            files += 1;
            let Ok(text) = std::fs::read_to_string(&path) else {
                unreadable += 1;
                continue;
            };
            let Ok(raw) = serde_json::from_str::<serde_json::Value>(&text) else {
                unparsed += 1;
                continue;
            };
            let extracted = fixture::extract(&raw);
            // A report with no observations: an error envelope, or a survey from a
            // subcommand that measures nothing. Counted rather than passed over, because
            // "every file was barren" and "there were no files" are different failures
            // and the message below has to be able to tell you which one you have.
            if extracted.is_empty() {
                barren += 1;
            }
            all.extend(extracted);
        }
    }

    // The frame, not just the total. Printed before the assertions so a run that is
    // about to fail still says what it was looking at.
    eprintln!(
        "regenerating from {} of {} source directory(ies): {files} json file(s), \
         {unreadable} unreadable, {unparsed} unparseable, {barren} with no observations, \
         {} fixture(s) extracted",
        seen_dirs,
        dirs.len(),
        all.len()
    );

    assert!(
        seen_dirs > 0,
        "none of the {} source directory(ies) could be read; name a sweep with \
         {SOURCES_VAR}=/path/to/reports (`:`-separated for several)",
        dirs.len()
    );

    assert!(
        !all.is_empty(),
        "extraction produced zero fixtures, which means the archive shape changed \
         rather than that there is nothing to extract"
    );

    let path = fixture_path();
    let previous = baseline(&path);
    let merge = std::env::var_os(MERGE_VAR).is_some();
    let allow_loss = std::env::var_os(ALLOW_LOSS_VAR).is_some();

    let assembly = assemble(all, &previous, merge);
    let carried = assembly.hand_authored;
    let kept = assembly.kept;
    let checks: BTreeSet<&str> = kept.iter().map(|f| f.check.as_str()).collect();
    let toolchains: BTreeSet<&str> = kept.iter().map(|f| f.toolchain.as_str()).collect();

    // What the regeneration costs, named rather than summarised.
    //
    // Mining one sweep where the file was built from three archives trades toolchain
    // diversity for check coverage, and the trade is invisible in the totals: a sweep on
    // one machine can yield more checks across far fewer toolchains than the baseline it
    // replaces, and that reads as progress until you look, and the toolchains are the
    // whole point: they are the compilers
    // this host cannot install. `CHARD_FIXTURE_SOURCES` takes several directories for
    // exactly this reason.
    if !previous.is_empty() {
        let old_checks: BTreeSet<&str> = previous.iter().map(|f| f.check.as_str()).collect();
        let old_tools: BTreeSet<&str> = previous.iter().map(|f| f.toolchain.as_str()).collect();
        let lost_checks: Vec<&&str> = old_checks.difference(&checks).collect();
        eprintln!(
            "baseline was {} fixtures, {} checks, {} toolchains",
            previous.len(),
            old_checks.len(),
            old_tools.len()
        );
        if !lost_checks.is_empty() {
            eprintln!(
                "losing {} check(s) that had evidence: {lost_checks:?}",
                lost_checks.len()
            );
        }
    }
    // Printed unconditionally, zero included: "losing 0 toolchain(s)" is the line a
    // regeneration's reviewer looks for, and a line that appears only on failure cannot
    // be told apart from one that was never computed.
    eprintln!(
        "carried {} row(s) from {} (toolchain, arch) pair(s) the sources did not supply \
         ({MERGE_VAR} {})",
        assembly.unsourced_rows,
        assembly.unsourced_pairs,
        if merge { "set" } else { "unset" }
    );
    eprintln!("{}", describe_loss(&assembly.lost));
    if let Err(refusal) = refuse_loss(&assembly.lost, allow_loss) {
        panic!("{refusal}");
    }

    std::fs::create_dir_all(path.parent().expect("fixture dir")).expect("create fixture dir");
    let json = serde_json::to_string_pretty(&kept).expect("serialize fixtures");
    std::fs::write(&path, json).expect("write fixtures");

    eprintln!(
        "regenerated {} fixtures ({carried} hand-authored, carried over) covering {} \
         checks across {} toolchains -> {}",
        kept.len(),
        checks.len(),
        toolchains.len(),
        path.display()
    );
}

fn load() -> Vec<Fixture> {
    let path = fixture_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).expect("fixture file is valid JSON")
}

#[test]
fn recorded_evidence_still_produces_the_same_detections() {
    if std::env::var_os("CHARD_REGENERATE_FIXTURES").is_some() {
        regenerate();
        return;
    }

    let fixtures = load();
    assert!(!fixtures.is_empty(), "fixture file is empty");

    let mut disagreements = Vec::new();
    let mut stale = Vec::new();
    let mut replayed = 0usize;
    let mut checks_replayed = BTreeSet::new();

    for f in &fixtures {
        match f.replay() {
            Some(replay) => {
                replayed = replayed.saturating_add(1);
                checks_replayed.insert(f.check.as_str());
                if !replay.agrees() {
                    disagreements.push(format!(
                        "  {} on {} [{}]\n      expected {} level={:?}\n      got      {} level={:?}",
                        replay.fixture_check,
                        replay.toolchain,
                        f.profile,
                        replay.expected,
                        replay.expected_level,
                        replay.got,
                        replay.got_level,
                    ));
                }
            }
            // The check was removed or renamed. Not a failure, but the fixture is
            // dead weight and should be regenerated away.
            None => stale.push(f.check.clone()),
        }
    }

    // The frame, not just the count. `replay()` returns `None` for a check that is no
    // longer in the corpus, and every `None` lands in `stale`, which was reported with
    // `eprintln!` and asserted on nowhere. So the only assertion below (that nothing
    // *disagreed*) was vacuously true whenever nothing replayed: rename every check
    // and all 1011 fixtures go stale, `disagreements` stays empty, and the test reports
    // `ok` having run no detector at all. Demonstrated on this tree by filtering the
    // check lookup: 1011 fixtures, zero replays, two tests green, exit 0.
    //
    // A count is checkable only against a span that is also printed, so both are.
    eprintln!(
        "replayed {replayed} of {} fixtures, covering {} of {} corpus checks",
        fixtures.len(),
        checks_replayed.len(),
        chard::probe::total_checks(),
    );
    assert!(
        replayed > 0,
        "not one of the {} fixtures replayed: every check they name is absent from the \
         corpus. Nothing about any detector was verified.",
        fixtures.len()
    );
    assert!(
        stale.is_empty(),
        "{} of {} fixtures name checks no longer in the corpus, so those detectors went \
         unexercised: {:?}.\nRegenerate with CHARD_REGENERATE_FIXTURES=1.",
        stale.len(),
        fixtures.len(),
        stale.iter().collect::<BTreeSet<_>>()
    );

    assert!(
        disagreements.is_empty(),
        "{} of {} fixtures changed behaviour on recorded real-world evidence.\n\
         This is a question, not necessarily a bug: decide whether each new answer is \
         better, and regenerate with CHARD_REGENERATE_FIXTURES=1 only once you have, \
         recording why in the fixture's `note`.\n\n{}",
        disagreements.len(),
        fixtures.len(),
        disagreements.join("\n")
    );
}

/// Which corpus checks the recorded evidence does *not* reach, named rather than counted.
///
/// No row may carry a path naming whoever recorded it.
///
/// This file is tracked, and a mined build line names the directory the probe ran in.
/// From a guest that is the harness's own account; from a report measured on a
/// development host it is an operator's home, and `scripts/leak-gate.sh` refuses to
/// publish one. The gate catches it only at the commit, with the corpus already written.
/// This fails one step earlier and names the row.
///
/// `chard::fixture` rewrites the directory out of `argv`, where a path is bookkeeping no
/// detector reads. Everywhere else (a path quoted inside a diagnostic, most of all) is
/// evidence, and the answer on finding one there is a person deciding what to do about
/// it, not a substitution rule editing compiler output on its way into a test corpus.
///
/// Two prefixes are exempt, by the reasoning `scripts/leak-gate.sh` gives for the first:
/// what the pattern hunts is a *username*, and through it a machine. `/home/chard` is the
/// unprivileged account the sweep harness creates inside every guest, so it names the
/// harness. `/root` is the same on every Unix ever shipped and names nobody at all, the
/// BSD lanes measure as root because that is the account their console login gives, and
/// the gate does not scan for it for this reason. The rows reaching these exemptions are
/// compiler diagnostics quoting the probe source they were compiling.
#[test]
fn no_fixture_carries_an_operators_home_path() {
    /// Roots that identify nobody. See the doc comment.
    const NAMES_NOBODY: [&str; 2] = ["/home/chard/", "/root/"];

    let path = fixture_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

    let mut offenders: Vec<String> = chard::fixture::home_rooted_paths(&text)
        .into_iter()
        .filter(|path| !NAMES_NOBODY.iter().any(|root| path.starts_with(root)))
        .collect();
    offenders.sort_unstable();
    offenders.dedup();

    assert!(
        offenders.is_empty(),
        "{} home-rooted path(s) in {}: {:?}\n  \
         In `argv` this is a scrubbing bug — `chard::fixture` should have rewritten it to \
         `<workdir>/...`. Anywhere else it is inside recorded evidence, and wants a \
         decision rather than a rewrite.",
        offenders.len(),
        path.display(),
        offenders,
    );
}

/// The list is empty: every check in the corpus has recorded evidence behind it. That is
/// the state this test exists to defend rather than to celebrate, because the gap it
/// guards is invisible from the passing run above, which only ever sees the fixtures
/// that exist. A check added without evidence, or a regeneration mined from sources that
/// cannot reach one, fails here rather than quietly reducing what the harness covers.
///
/// The list is kept as a list rather than replaced by `assert!(uncovered.is_empty())` so
/// that a check which genuinely cannot be recorded has somewhere to be written down with
/// its reason.
/// Adding a name here is a claim that no reachable host can produce the evidence, and it
/// should be as hard to write as that sounds.
#[test]
fn the_checks_without_recorded_evidence_are_the_ones_we_know_about() {
    // Empty. A check with no evidence yet is listed here for the gap between adding it and
    // mining reports of the tree that contains it, distinguished from a check no reachable
    // host can record. "Uncoverable" is worth distrusting as a category: it describes the
    // evidence a project happens to have, and reads as a property of the check. A check
    // gated to aarch64 is not uncoverable because the file's fixtures were recorded on
    // x86_64; recording on an aarch64 host covers it, with no change to any detector. A
    // check leaves the list by a sweep at the corpus containing it, mined *alongside* the
    // sources already in the file rather than in place of them. Regenerating from the single
    // host a check was developed on would cover its name while narrowing the corpus to what
    // one machine can see, which is the trade this list exists to make visible rather than
    // to hide.
    // `shadow-stack-enforced`'s rows come from a bare-metal x86_64 host whose CPU implements
    // CET shadow stack: the KVM guests of the fleet enumerate no CET_SS. Two rows do come
    // from guest runs, the corpus's only ones naming a machine without the mechanism.
    const UNCOVERED: &[&str] = &[];

    let fixtures = load();
    let covered: BTreeSet<&str> = fixtures.iter().map(|f| f.check.as_str()).collect();
    let corpus: BTreeSet<&str> = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .map(|c| c.id)
        .collect();

    let uncovered: BTreeSet<&str> = corpus.difference(&covered).copied().collect();
    let expected: BTreeSet<&str> = UNCOVERED.iter().copied().collect();

    assert_eq!(
        uncovered,
        expected,
        "the set of checks with no recorded evidence has changed.\n  \
         newly uncovered: {:?}\n  newly covered: {:?}\n\
         Update UNCOVERED here, and the coverage claim in tests/fixtures/README.md \
         with it.",
        uncovered.difference(&expected).collect::<Vec<_>>(),
        expected.difference(&uncovered).collect::<Vec<_>>(),
    );

    // The denominator too: a corpus that shrank to eleven checks would satisfy the
    // equality above while covering nothing.
    assert_eq!(
        corpus.len(),
        chard::probe::total_checks(),
        "the corpus check ids do not agree with the published total"
    );
}

/// Every level a fixture archives is a word the check declares, and no graded check
/// archived a `present` without one.
///
/// Each check carries its level vocabulary in `probe::Levels`, and this is
/// the evidence that the declared vocabularies are the ones real toolchains produced: every
/// archived `present` word is admitted by its check's `Levels`, a `Levels::None` check
/// archived no word, and the archived `partial` cells are exactly the readings a grade now
/// calls below the ask. The set of graded checks with a `present` and no level has to be
/// empty, and this is what stops the next libstdc++-style exemption arriving unstated:
/// `cxx-hardening-requested` had thirteen such cells, every one archived `on`, and it is
/// informational now for that reason.
///
/// Counts are printed per check so an empty enumeration is visible.
#[test]
fn every_archived_level_is_a_word_the_check_declares() {
    let fixtures = load();
    // check -> (present with a level, present without, graded readings archived partial)
    let mut per_check: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
    let mut problems = Vec::new();
    let mut partial_readings: BTreeSet<(&str, &str)> = BTreeSet::new();
    for f in fixtures.iter().filter(|f| f.expected == "present") {
        // A check the corpus no longer carries is the replay test's business, and it
        // fails there.
        let Some(check) = check_of(&f.check) else {
            continue;
        };
        let entry = per_check.entry(check.id).or_default();
        if let Some(word) = f.expected_level.as_deref() {
            entry.0 = entry.0.saturating_add(1);
            let (problem, partial) = archived_word_reading(check, f, word);
            problems.extend(problem);
            if partial {
                entry.2 = entry.2.saturating_add(1);
                partial_readings.insert((check.id, word));
            }
        } else {
            entry.1 = entry.1.saturating_add(1);
            if check.levels.grade().is_some() {
                problems.push(format!(
                    "{} on {}: present with no level on a graded check, which `decide` \
                     withholds; declare the check informational or give the detector a word",
                    check.id, f.toolchain
                ));
            }
        }
    }
    for (check, (with, without, partial)) in &per_check {
        eprintln!(
            "levels: {check}: {with} present with a level, {without} without, {partial} \
             graded readings archived partial"
        );
    }
    assert!(
        !per_check.is_empty(),
        "no fixture archived a present reading"
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));

    // The archived facts the scales have to reproduce, as recorded over the fixtures mined
    // through 2026-09-28: these are the only graded readings the
    // archive called `partial`, and each is a word below its check's ask.
    let expected_partial: BTreeSet<(&str, &str)> = [
        ("cet-marked", "branch"),
        ("fortify-effective", "1"),
        ("fortify-effective", "2"),
        ("fortify-requested", "2"),
        ("relro", "partial"),
        // From the check's rows: `-fzero-call-used-regs=used-gpr-arg`
        // under gcc 16.1.1 on Fedora 44 x86_64 and clang 22.1.8 on Fedora 44 aarch64,
        // archived `partial` at `arg`, below the ask of `gpr`.
        ("zero-call-used-regs", "arg"),
        // From the check's rows: `-O2 -fcf-protection=full`
        // under gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64 (glibc 2.43), archived
        // `partial` at `opt-in`, enforced under glibc's opt-in and not without it, below the
        // ask of `default`.
        ("shadow-stack-enforced", "opt-in"),
        // From the check's rows: `fortify-printf-flag` at `1` under
        // `-O2 -D_FORTIFY_SOURCE=1` (clang 14.0.0 and 18.1.3, Ubuntu 22.04 and 24.04 x86_64)
        // and at `2` under gcc 11.4.0's `bare-optimized` default on Ubuntu 22.04 x86_64,
        // each below the ask of 3.
        ("fortify-printf-flag", "1"),
        ("fortify-printf-flag", "2"),
        // From the check's rows: `-fstack-protector
        // --param=ssp-buffer-size=128` under gcc 16.1.1 on Fedora 44 x86_64, clang 22.1.8 on
        // Fedora 44 aarch64 and gcc 12.2.0 on Debian 12 i386, archived `partial` at `basic`,
        // below the ask of `strong`.
        ("ssp-level-emitted", "basic"),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        partial_readings, expected_partial,
        "the archived partial readings are not the ones the scales grade below the ask"
    );
    // The frame: a graded scale and an informational vocabulary were each exercised by
    // real evidence, and the check that made the no-level shape live is informational and
    // archives it.
    let exercised = |graded: bool| {
        per_check
            .iter()
            .filter(|(id, (with, _, _))| {
                *with > 0 && check_of(id).is_some_and(|c| c.levels.grade().is_some() == graded)
            })
            .count()
    };
    assert!(exercised(true) > 0, "no graded check archived a level");
    assert!(
        exercised(false) > 0,
        "no informational check archived a level"
    );
    let cxx = per_check
        .get("cxx-hardening-requested")
        .copied()
        .unwrap_or_default();
    assert!(
        cxx.1 > 0
            && check_of("cxx-hardening-requested").is_some_and(|c| c.levels.grade().is_none()),
        "cxx-hardening-requested archives a present with no level ({}) and grades nothing",
        cxx.1
    );
}

/// The corpus check a fixture names.
fn check_of(id: &str) -> Option<&'static chard::probe::Check> {
    chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .find(|c| c.id == id)
}

/// What one archived `present` word says against its check's vocabulary: a problem where
/// the word is one the check does not admit or the archived measurement reads the other
/// way, and whether it is a graded reading the archive called `partial` and the scale calls
/// below the ask.
fn archived_word_reading(
    check: &chard::probe::Check,
    f: &Fixture,
    word: &str,
) -> (Option<String>, bool) {
    use chard::report::{Grading, grade_level};

    if !check.levels.admits(word) {
        return (
            Some(format!(
                "{} on {}: archived level `{word}` is not a word {:?} admits",
                check.id, f.toolchain, check.levels
            )),
            false,
        );
    }
    // The archived verdict folds in the control triple, so it is compared only where it is
    // a graded measurement: `on` is a word at or above the ask, `partial` a word below it.
    let archived = f.archived_verdict.as_deref();
    match (grade_level(check.levels.grade(), Some(word)), archived) {
        (Some(Grading::Meets), Some("partial")) | (Some(Grading::Below), Some("on")) => (
            Some(format!(
                "{} on {}: `{word}` was archived {} and the scale reads it the other way",
                check.id,
                f.toolchain,
                archived.unwrap_or_default()
            )),
            false,
        ),
        (Some(Grading::NoLevel | Grading::OffScale), Some("on" | "partial")) => (
            Some(format!(
                "{} on {}: `{word}` was archived as a measurement and the scale cannot grade it",
                check.id, f.toolchain
            )),
            false,
        ),
        // An ungraded word is `on` by presence and below nothing, so `partial` beside it is
        // a verdict the grade never gives.
        (Some(Grading::Ungraded), Some("partial")) => (
            Some(format!(
                "{} on {}: `{word}` is on no rung of the scale and was archived `partial`, \
                 which only a word below the ask earns",
                check.id, f.toolchain
            )),
            false,
        ),
        (Some(Grading::Below), Some("partial")) => (None, true),
        _ => (None, false),
    }
}

/// The fixtures are only worth having if they reach toolchains this host cannot be.
///
/// Without this, a regeneration run on a machine with one compiler would quietly
/// produce a fixture set that tests nothing the unit tests do not already cover, and
/// the file would still look reassuringly large.
#[test]
fn fixtures_span_toolchains_the_host_cannot_provide() {
    // A pair is a toolchain on one architecture, mined from a measured report, carrying
    // at least a partial cell. The hand-authored `synthetic:` ids are not coverage of a
    // compiler, and a pair with a row or two is a remnant rather than a run.
    const ROWS_PER_PAIR: usize = 20;
    const PAIRS: usize = 8;
    // The gcc major whose defaults the obsolete-C checks measure: from 14 the four
    // constructs are errors, below it warnings.
    const OBSOLETE_C_FLOOR: u32 = 14;
    const OBSOLETE_C: &[&str] = &[
        "implicit-int-is-error",
        "implicit-function-declaration-is-error",
        "int-conversion-is-error",
        "incompatible-pointer-types-is-error",
    ];

    let fixtures = load();
    let mut rows: BTreeMap<(&str, Option<&str>), usize> = BTreeMap::new();
    for f in fixtures
        .iter()
        .filter(|f| !f.toolchain.starts_with("synthetic:"))
    {
        *rows
            .entry((f.toolchain.as_str(), f.arch.as_deref()))
            .or_default() += 1;
    }
    let pairs: Vec<_> = rows.iter().filter(|(_, n)| **n >= ROWS_PER_PAIR).collect();
    assert!(
        pairs.len() >= PAIRS,
        "only {} mined (toolchain, architecture) pairs carry {ROWS_PER_PAIR} rows or more \
         ({} mined pairs in all); the point of these is coverage of compilers not \
         installed here",
        pairs.len(),
        rows.len()
    );

    let gcc_major = |toolchain: &str| -> Option<u32> {
        toolchain
            .strip_prefix("gcc-")?
            .split('.')
            .next()?
            .parse()
            .ok()
    };
    for check in OBSOLETE_C {
        let below: BTreeSet<&str> = fixtures
            .iter()
            .filter(|f| f.check == *check)
            .filter(|f| gcc_major(&f.toolchain).is_some_and(|m| m < OBSOLETE_C_FLOOR))
            .map(|f| f.toolchain.as_str())
            .collect();
        assert!(
            !below.is_empty(),
            "{check} has no row from a gcc below {OBSOLETE_C_FLOOR}, where the construct \
             is still a warning rather than the error this host's gcc makes it; that is \
             exactly where the check has something to say"
        );
    }
}

/// The recorded evidence spans both architectures the corpus gates checks on.
///
/// Four checks, the `branch-protection` and `gcs` pairs, are gated to aarch64, and no
/// x86_64 sweep can produce evidence for them. A file mined from x86_64 archives alone
/// leaves them uncovered, and the way that state arrives is not a code change but a
/// regeneration run against sources that happen to hold one architecture. That would empty those
/// four checks out of the file, and the failure a reader would see is the uncovered-set test
/// complaining about a set difference.
///
/// This test says the actual thing, so the fix is obvious from the message: the aarch64
/// reports were not among the sources.
#[test]
fn the_fixtures_span_both_architectures_the_corpus_gates_on() {
    const AARCH64_GATED: &[&str] = &[
        "branch-protection-macro",
        "branch-protection-marked",
        "gcs-macro",
        "gcs-marked",
    ];

    let fixtures = load();
    let arches: BTreeSet<&str> = fixtures.iter().filter_map(|f| f.arch.as_deref()).collect();
    assert!(
        arches.contains("aarch64") && arches.contains("x86_64"),
        "the fixtures cover {arches:?}; the corpus gates checks on both x86_64 and \
         aarch64, so evidence from one alone leaves detectors unexercised. Regenerate \
         with the aarch64 reports among CHARD_FIXTURE_SOURCES."
    );

    for check in AARCH64_GATED {
        let rows: Vec<&Fixture> = fixtures.iter().filter(|f| &f.check == check).collect();
        assert!(
            !rows.is_empty(),
            "{check} is gated to aarch64 and has no fixtures at all"
        );
        assert!(
            rows.iter().any(|f| f.arch.as_deref() == Some("aarch64")),
            "{check} is gated to aarch64, so its {} fixture(s) recorded on {:?} cannot \
             be exercising it",
            rows.len(),
            rows.iter()
                .map(|f| f.arch.as_deref())
                .collect::<BTreeSet<_>>()
        );
    }
}

/// The architecture label agrees with the artifact it is a label for.
///
/// `arch` is derived from a string the toolchain reports about itself, and the ELF
/// header's machine is a number the linker wrote into the artifact. Where a fixture has
/// both, they must say the same thing, which is what makes the derivation, including
/// folding OpenBSD's `amd64` onto `x86_64`, something checked rather than assumed.
///
/// A fixture with no `elf` block is outside this: a macro-only or diagnostic-only
/// recording has no artifact to disagree with.
#[test]
fn the_architecture_label_agrees_with_the_elf_header() {
    let fixtures = load();
    let mut checked = 0usize;
    let mut wrong = Vec::new();
    for f in &fixtures {
        let (Some(arch), Some(elf)) = (f.arch.as_deref(), f.elf.as_ref()) else {
            continue;
        };
        if elf.machine.is_empty() {
            continue;
        }
        checked = checked.saturating_add(1);
        if arch != elf.machine {
            wrong.push(format!(
                "  {} on {} [{}]: labelled {arch}, ELF header says {}",
                f.check, f.toolchain, f.profile, elf.machine
            ));
        }
    }

    // The frame, so a pass means "compared N pairs" rather than "found no elf blocks".
    eprintln!("compared {checked} architecture labels against their ELF headers");
    assert!(
        checked > 0,
        "no fixture carried both an architecture and an ELF machine, so nothing was \
         compared; the field or the evidence shape has changed"
    );
    assert!(
        wrong.is_empty(),
        "{} fixture(s) are labelled with an architecture their own artifact \
         contradicts:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A regeneration keeps the fixtures it could not have produced.
///
/// The mining path builds its output from archived reports alone, so every hand-authored
/// fixture in the file is absent from it by construction. Writing that output over the
/// file would delete every one of them (gcc 4 predating a flag, clang 14 below a version
/// floor, a build that dies without writing anything), and the totals would go up while it
/// happened, because the newest sweep covers more checks than older archives do. Nothing
/// would fail and nothing would say a word.
///
/// This pins the merge rather than the message: mined output goes in, and what comes out
/// still has every `synthetic:` fixture that was there before, with its note intact.
#[test]
fn a_regeneration_keeps_the_hand_authored_fixtures() {
    let previous = load();
    let hand: Vec<&Fixture> = previous
        .iter()
        .filter(|f| f.toolchain.starts_with(HAND_AUTHORED))
        .collect();
    assert!(
        !hand.is_empty(),
        "no hand-authored fixtures in the file, so this test is guarding nothing — if \
         they were deliberately removed, remove this test in the same commit"
    );

    // Mined fixtures never carry the prefix: `fixture::extract` takes the toolchain id
    // from the report, and a report is a measurement of something real.
    let mined: Vec<Fixture> = previous
        .iter()
        .filter(|f| !f.toolchain.starts_with(HAND_AUTHORED))
        .take(3)
        .cloned()
        .collect();
    let merged = merge_hand_authored(mined.clone(), &previous);

    for f in &hand {
        let kept = merged
            .iter()
            .find(|m| m.check == f.check && m.toolchain == f.toolchain && m.profile == f.profile)
            .unwrap_or_else(|| {
                panic!(
                    "regeneration dropped the hand-authored fixture {} on {}",
                    f.check, f.toolchain
                )
            });
        assert_eq!(
            kept.note, f.note,
            "the note is why the fixture exists; {} on {} kept the fixture and lost it",
            f.check, f.toolchain
        );
        assert_eq!(kept.expected, f.expected);
    }
    assert_eq!(
        merged.len(),
        mined.len().saturating_add(hand.len()),
        "merge changed the count beyond mined + hand-authored"
    );
}

/// A synthetic row for the regeneration tests: nothing here reads or writes the file.
fn row(check: &str, toolchain: &str, arch: Option<&str>, expected: &str) -> Fixture {
    serde_json::from_value(serde_json::json!({
        "check": check,
        "toolchain": toolchain,
        "arch": arch,
        "profile": "bare",
        "expected": expected,
    }))
    .expect("synthetic fixture row")
}

fn pair(toolchain: &str, arch: Option<&str>) -> Origin {
    (toolchain.to_owned(), arch.map(str::to_owned))
}

/// A previous file with a toolchain on two architectures, a toolchain only an older sweep
/// reached, and a hand-authored row; sources that re-supply one pair of the first.
fn regeneration_inputs() -> (Vec<Fixture>, Vec<Fixture>) {
    let previous = vec![
        row(
            "pie",
            "gcc-15.2.0-glibc2.43-ubuntu26.04",
            Some("x86_64"),
            "present",
        ),
        row(
            "pie",
            "gcc-15.2.0-glibc2.43-ubuntu26.04",
            Some("aarch64"),
            "present",
        ),
        row(
            "pie",
            "gcc-8.5.0-glibc2.28-almalinux8.10",
            Some("x86_64"),
            "absent",
        ),
        row(
            "relro",
            "gcc-8.5.0-glibc2.28-almalinux8.10",
            Some("x86_64"),
            "partial",
        ),
        row("pie", "synthetic:hand", None, "absent"),
    ];
    let extracted = vec![row(
        "pie",
        "gcc-15.2.0-glibc2.43-ubuntu26.04",
        Some("x86_64"),
        "present",
    )];
    (extracted, previous)
}

/// Without the merge, a pair the sources lack is a loss, and the loss is refused.
///
/// The aarch64 pair is lost even though the same toolchain id survives on x86_64, which
/// is the case keying on the id alone would have passed.
#[test]
fn a_regeneration_that_loses_a_toolchain_is_refused() {
    let (extracted, previous) = regeneration_inputs();
    let a = assemble(extracted, &previous, false);

    assert_eq!(
        a.lost,
        vec![
            Lost {
                origin: pair("gcc-15.2.0-glibc2.43-ubuntu26.04", Some("aarch64")),
                sourced: false,
            },
            Lost {
                origin: pair("gcc-8.5.0-glibc2.28-almalinux8.10", Some("x86_64")),
                sourced: false,
            },
        ]
    );
    assert_eq!(a.unsourced_rows, 0);
    assert_eq!(a.hand_authored, 1);

    let refusal = refuse_loss(&a.lost, false).expect_err("a loss must be refused");
    assert!(refusal.contains("losing 2 toolchain(s)"), "{refusal}");
    assert!(refusal.contains(ALLOW_LOSS_VAR), "{refusal}");
    assert!(refusal.contains(MERGE_VAR), "{refusal}");
    assert!(
        refusal.contains("gcc-8.5.0-glibc2.28-almalinux8.10 (x86_64): absent from the sources"),
        "{refusal}"
    );

    assert!(
        refuse_loss(&a.lost, true).is_ok(),
        "{ALLOW_LOSS_VAR} lets a decided loss through"
    );
    assert!(
        refuse_loss(&[], false).is_ok(),
        "no loss, nothing to refuse"
    );
    assert_eq!(
        describe_loss(&[]),
        "losing 0 toolchain(s) this host cannot reproduce"
    );
}

/// With the merge, every pair the sources lack is carried whole, notes and all, and a
/// pair the sources supply comes from the sources alone.
#[test]
fn a_merging_regeneration_carries_the_pairs_the_sources_lack() {
    let (extracted, mut previous) = regeneration_inputs();
    previous[2].note = Some("reviewed: an older sweep's evidence".to_owned());
    // A stale row for the re-measured pair: the merge must not resurrect it.
    previous.push(row(
        "relro",
        "gcc-15.2.0-glibc2.43-ubuntu26.04",
        Some("x86_64"),
        "partial",
    ));

    let a = assemble(extracted, &previous, true);

    assert!(a.lost.is_empty(), "lost {:?}", a.lost);
    assert_eq!(refuse_loss(&a.lost, false), Ok(()));
    assert_eq!(a.unsourced_pairs, 2);
    assert_eq!(a.unsourced_rows, 3);

    let old = a
        .kept
        .iter()
        .find(|f| f.check == "pie" && f.toolchain == "gcc-8.5.0-glibc2.28-almalinux8.10")
        .expect("the unsourced row is carried");
    assert_eq!(
        old.note.as_deref(),
        Some("reviewed: an older sweep's evidence")
    );
    assert_eq!(old.expected, "absent");

    let remeasured: Vec<&Fixture> = a
        .kept
        .iter()
        .filter(|f| origin(f) == pair("gcc-15.2.0-glibc2.43-ubuntu26.04", Some("x86_64")))
        .collect();
    assert_eq!(
        remeasured.len(),
        1,
        "a sourced pair keeps only what the sources gave, not the old file's rows"
    );
    assert_eq!(remeasured[0].check, "pie");

    // Five previous rows minus the stale sourced one, plus the one extracted row.
    assert_eq!(a.kept.len(), 5);
}

/// A pair the sources supplied and thinning dropped is still a loss under the merge,
/// and says which kind it is: the merge carries only what the sources lacked.
#[test]
fn a_toolchain_thinned_away_is_a_loss_the_merge_does_not_hide() {
    // Three toolchains of one family (`gcc-15.2.0`) answering one check alike: the
    // per-group cap keeps PER_CHECK of them.
    let ids = [
        "gcc-15.2.0-glibc2.43-ubuntu26.04",
        "gcc-15.2.0-musl1.2.6-alpine3.24.1",
        "gcc-15.2.0-glibc2.43-other",
    ];
    assert!(ids.len() > PER_CHECK, "the case needs more rows than slots");
    let previous: Vec<Fixture> = ids
        .iter()
        .map(|t| row("pie", t, Some("x86_64"), "present"))
        .collect();
    let extracted = previous.clone();

    let a = assemble(extracted, &previous, true);
    assert_eq!(a.lost.len(), ids.len().saturating_sub(PER_CHECK));
    assert!(a.lost.iter().all(|l| l.sourced), "{:?}", a.lost);
    assert_eq!(a.unsourced_rows, 0);
    let refusal = refuse_loss(&a.lost, false).expect_err("a thinned-away pair is refused");
    assert!(
        refusal.contains("in the sources, thinned away"),
        "{refusal}"
    );
}

/// Carried rows bypass a second thinning, so a family the sources re-measure on one
/// toolchain keeps every other toolchain of that family that only the old file held.
///
/// The real corpus has this shape: several toolchain ids per compiler family on one
/// architecture, of which a regeneration's current sources supply one. Thinning the
/// carried rows together with the extracted one would keep `PER_CHECK` of the group
/// and drop the rest, which is the silent loss the merge exists to stop.
#[test]
fn carried_rows_are_not_thinned_against_the_family_the_sources_remeasure() {
    let sourced = "gcc-15.2.0-glibc2.43-ubuntu26.04";
    let carried = [
        "gcc-15.2.0-glibc2.41-debian13",
        "gcc-15.2.0-glibc2.42-fedora43",
        "gcc-15.2.0-musl1.2.5-alpine3.22",
    ];
    assert!(
        carried.len() >= PER_CHECK,
        "the case needs the carried rows alone to fill the group's slots"
    );
    let previous: Vec<Fixture> = std::iter::once(sourced)
        .chain(carried)
        .map(|t| row("pie", t, Some("x86_64"), "present"))
        .collect();
    let extracted = vec![row("pie", sourced, Some("x86_64"), "present")];

    let a = assemble(extracted, &previous, true);

    assert!(a.lost.is_empty(), "lost {:?}", a.lost);
    assert_eq!(a.unsourced_pairs, carried.len());
    for t in std::iter::once(sourced).chain(carried) {
        assert!(
            a.kept.iter().any(|f| origin(f) == pair(t, Some("x86_64"))),
            "{t} was dropped from the family's group"
        );
    }
    assert_eq!(a.kept.len(), carried.len() + 1);
}

/// A path under the system temp directory, unique to this process and test.
fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "chard-detector-replay-{}-{name}",
        std::process::id()
    ))
}

/// A fixture file that exists and does not parse stops the regeneration rather than
/// reading as an empty baseline, against which no loss could be counted.
#[test]
#[should_panic(expected = "does not parse")]
fn an_unparseable_baseline_stops_the_regeneration() {
    let path = scratch("unparseable.json");
    std::fs::write(&path, "[{\"check\": ").expect("write scratch file");
    let result = std::panic::catch_unwind(|| baseline(&path));
    let _ = std::fs::remove_file(&path);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

/// A missing fixture file is the one state that reads as "no baseline".
#[test]
fn a_missing_baseline_is_empty() {
    let path = scratch("missing.json");
    let _ = std::fs::remove_file(&path);
    assert!(!path.exists());
    assert!(baseline(&path).is_empty());
}

/// Every count of probes or checks stated in the shipped documentation is the corpus's.
///
/// A number in prose has nothing holding it up, so the ones that can be checked are checked.
/// A count is written accurately and then outlives its subject, in several documents at
/// once, and a reader has no way to tell a count that moved with the corpus from one that
/// did not. Scope is narrow on purpose: the published documents, and claims of the form
/// "N checks" or "N probes". Every such count is held to the live corpus. A document states
/// no count of a past corpus, since the tree says what chard does and not what it did
/// (CLAUDE.md), and `chard probes` is the authority for the number.
///
/// **What this does not guard.** It compares against the *corpus size*: how many checks and
/// probes exist. The fixture count and the coverage numerator are outside it, and a document
/// stating either can go stale while every sentence here still passes, because the
/// corpus-size half of the claim stays true throughout. Those two are unmodelled on purpose:
/// the numerator rises as hosts are measured, and a guard that fails whenever the project
/// makes progress is one that gets deleted. The remedy is not to write those numbers down:
/// name the authority, or the structural reason behind the number, as `THREAT_MODEL.md` does
/// for the uncovered set.
#[test]
fn the_counts_in_the_docs_are_the_counts_in_the_corpus() {
    let checks = chard::probe::total_checks();
    let probes = chard::probe::CORPUS.len();

    // The output-contract version, checked the same way and for a sharper reason:
    // `chard_schema` is "the number to gate on", so it is the one number in the
    // documentation a consumer is invited to hard-code. It was `2` in both places a reader
    // looked while the binary emitted `4`, because two bumps landed in one day and the prose
    // did not move with them. The current value is stated where the contract is, as "every
    // document is at `N`": in `chard --help` (`src/main.rs`'s `CONTRACT`) and in DESIGN.md,
    // and anywhere else a document says it. The statement is read across line breaks and a
    // Rust string's continuations, and found at least in those two places, so a rewording
    // that drops it fails here rather than leaving nothing checked.
    //
    // Scanned as a phrase rather than through `claimed_counts`, which looks for
    // "<n> checks"-shaped claims and would not see a version.
    let schema = chard::report::SCHEMA_VERSION;
    let mut stated = Vec::new();
    for (name, text) in [
        ("README.md", include_str!("../README.md")),
        ("CHANGELOG.md", include_str!("../CHANGELOG.md")),
        ("DESIGN.md", include_str!("../DESIGN.md")),
        ("src/main.rs", include_str!("../src/main.rs")),
    ] {
        let flat = text
            .replace("\\\n", " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for (at, _) in flat.match_indices("every document is at `") {
            let value = flat[at + "every document is at `".len()..]
                .split('`')
                .next()
                .unwrap_or_default();
            assert_eq!(
                value, schema,
                "{name} states a `chard_schema` the binary does not emit ({schema})"
            );
            stated.push(name);
        }
    }
    assert!(
        stated.contains(&"src/main.rs") && stated.contains(&"DESIGN.md"),
        "the current `chard_schema` is stated in `chard --help` and DESIGN.md as \"every \
         document is at `N`\"; found in {stated:?}"
    );

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let live = [
        // The Makefile states a count too, in the clang lane, and it drifted silently
        // when the corpus grew because it was the one place outside this list holding
        // one. `make clang` is in `check-full` rather than `check`, so nothing routine
        // ran it.
        "Makefile",
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
        // The document a security reader reaches for first was the last one outside this
        // list, and it had drifted furthest: "47 checks", "two checks of 47", and a
        // replay claim naming eleven uncovered detectors where there are fifteen. A
        // stale number in the threat model is worse than one in the README, because the
        // paragraph it sits in is a scope statement.
        "THREAT_MODEL.md",
        "DESIGN.md",
        "QUICKSTART.md",
        "tests/fixtures/README.md",
    ];

    let mut wrong = Vec::new();
    let mut examined = 0usize;
    for name in live {
        let path = root.join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

        // Scanned by paragraph, not by line: markdown wraps sentences, so a count and its
        // noun can sit on different lines, and a line-based scan would read the count bare
        // or miss it.
        let mut line_no = 1usize;
        for para in text.split("\n\n") {
            let joined = para.replace('\n', " ");
            for (word, truth) in [("checks", checks), ("probes", probes)] {
                for claim in claimed_counts(&joined, word) {
                    examined = examined.saturating_add(1);
                    if claim != truth {
                        // Report the line the claim is actually on, not the paragraph's
                        // first: a markdown bullet list is one paragraph, so the paragraph
                        // head is usually a different bullet entirely and sends the reader
                        // to the wrong place.
                        let (at, excerpt) = locate(&text, claim, word);
                        wrong.push(format!(
                            "{name}:{at}: claims {claim} {word}, corpus has {truth}\n    {excerpt}"
                        ));
                    }
                }
            }
            line_no = line_no
                .saturating_add(para.matches('\n').count())
                .saturating_add(2);
        }
    }

    // The frame, so a pass means "checked N claims" rather than "found no files".
    eprintln!(
        "checked {examined} count claims across {} documents",
        live.len()
    );
    // The scanner is proved on planted text, so a tree whose documents state no count at
    // all (the live count is `chard probes`) passes on the control and not on an empty loop.
    assert_eq!(
        claimed_counts("holds 43 checks and two checks of 45 in prose", "checks"),
        [43, 45],
        "the count scanner no longer finds the phrasing it is written for"
    );
    assert!(
        wrong.is_empty(),
        "documentation states counts the corpus does not have:\n{}",
        wrong.join("\n")
    );
}

/// The README's sample table is `chard table` over `tests/fixtures/sample-report.json`,
/// rendered by this build, not typed: its header and rule are the rendering's first two
/// lines and every row it shows is a rendered row, in the rendering's order. The README
/// says the column names no distribution because the system it was measured on had no
/// `os-release`; that is held to the report's `environment.distro` too.
///
/// A change to the table's layout or to how chard reads a report fails here, and the
/// remedy is to render the fixture again and paste the rows, or to measure a new fixture
/// as `tests/fixtures/README.md` says, never to edit the rows by hand.
#[test]
fn the_readme_sample_is_rendered_from_its_fixture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = "tests/fixtures/sample-report.json";
    let readme = std::fs::read_to_string(root.join("README.md")).expect("reading README.md");
    // The sample is the first ```text block after the sentence naming the fixture.
    let block = readme
        .split_once(&format!("chard table {fixture}"))
        .expect("README.md does not name the fixture its sample is rendered from")
        .1
        .split_once("```text\n")
        .and_then(|(_, rest)| rest.split("\n```").next())
        .expect("README.md has a ```text block after naming the fixture");
    let shown: Vec<&str> = block.lines().map(str::trim_end).collect();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_chard"))
        .arg("table")
        .arg(fixture)
        .current_dir(root)
        .env_clear()
        .output()
        .expect("running chard table");
    assert!(
        out.status.success(),
        "chard table {fixture} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rendered = String::from_utf8(out.stdout).expect("chard table writes UTF-8");
    let rendered: Vec<&str> = rendered.lines().map(str::trim_end).collect();

    assert!(rendered.len() > 2, "chard table {fixture} rendered no rows");
    assert!(
        shown.len() > 2 && shown[..2] == rendered[..2],
        "the README's sample does not open on the rendered header and rule:\n{}\n{}",
        rendered[0],
        rendered[1]
    );
    let mut at = 2;
    for row in &shown[2..] {
        let found = rendered[at..].iter().position(|r| r == row);
        let Some(offset) = found else {
            panic!("the README's sample row {row:?} is not a rendered row after the last one");
        };
        at += offset + 1;
    }

    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(fixture)).expect("reading the sample report"),
    )
    .expect("the sample report is JSON");
    assert_eq!(
        report["environment"]["distro"]["id"], "unknown",
        "the README says the sample's column names no distribution"
    );
}

/// The sample's lag: the rules of `report::RULES` the README's sample report does not apply,
/// in `RULES`' order.
///
/// The sample is a measurement in a virtual machine (`tests/fixtures/README.md` has the
/// recipe), so it is not measured again for every rule a change adds. It may lack rules of
/// this build, but only the ones named here. A change that adds a rule to `RULES` does one
/// of two things in the same change. It measures the sample again, and this list is empty.
/// Or it adds the new rule's name here, where review sees it.
const SAMPLE_RULE_LAG: &[&str] = &[];

/// The README's sample applies the consistency rules of this build, except the ones
/// [`SAMPLE_RULE_LAG`] names.
///
/// Every rule in the sample's `consistency.rules_applied` is one `report::RULES` lists. The
/// sample lists each once, in `RULES`' order. The rules of `RULES` it lacks are exactly the
/// ones [`SAMPLE_RULE_LAG`] names. The test fails when the sample lacks a rule
/// [`SAMPLE_RULE_LAG`] does not name, and when [`SAMPLE_RULE_LAG`] names a rule the sample
/// applies.
///
/// Without it, `RULES` can gain rules while the sample still applies the fewer it was
/// measured with, and no test fails.
#[test]
fn the_readme_sample_lacks_only_the_rules_its_lag_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = "tests/fixtures/sample-report.json";
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(fixture)).expect("reading the sample report"),
    )
    .expect("the sample report is JSON");
    let applied: Vec<&str> = report["consistency"]["rules_applied"]
        .as_array()
        .unwrap_or_else(|| panic!("{fixture} has no consistency.rules_applied array"))
        .iter()
        .map(|rule| {
            rule.as_str()
                .unwrap_or_else(|| panic!("{fixture} lists a rule that is not a string: {rule}"))
        })
        .collect();
    let rules = chard::report::RULES;
    assert!(!applied.is_empty(), "{fixture} applies no rule at all");
    let mut distinct = BTreeSet::new();
    for rule in rules {
        assert!(distinct.insert(rule), "report::RULES lists {rule:?} twice");
    }

    // A subsequence of RULES: each applied rule found after the one before it.
    let mut next = 0;
    for rule in &applied {
        match rules.iter().position(|r| r == rule) {
            None => panic!(
                "{fixture} applies {rule:?}, which report::RULES does not list. Measure the \
                 sample again as tests/fixtures/README.md says"
            ),
            Some(at) if at < next => panic!(
                "{fixture} applies {rule:?} out of report::RULES' order, or twice: {applied:?}"
            ),
            Some(at) => next = at + 1,
        }
    }

    let lacking: Vec<&str> = rules
        .iter()
        .copied()
        .filter(|r| !applied.contains(r))
        .collect();
    assert_eq!(
        lacking,
        SAMPLE_RULE_LAG,
        "{fixture} lacks {} of report::RULES' {} rules. SAMPLE_RULE_LAG names {}. \
         Measure the sample again as tests/fixtures/README.md says, or set SAMPLE_RULE_LAG \
         to the rules it lacks in the same change. The sample lacks: {lacking:?}",
        lacking.len(),
        rules.len(),
        SAMPLE_RULE_LAG.len()
    );
}

/// Find the line stating `claim` immediately before `word`, for a readable failure.
///
/// Falls back to line 0 and the claim itself when the two sit on different lines, which
/// markdown wrapping makes possible, enough to grep for, which is what a reader does.
fn locate(text: &str, claim: usize, word: &str) -> (usize, String) {
    for (i, line) in text.lines().enumerate() {
        if claimed_counts(line, word).contains(&claim) {
            return (
                i.saturating_add(1),
                line.trim().chars().take(140).collect::<String>(),
            );
        }
    }
    (0, format!("{claim} {word}"))
}

/// Numbers immediately preceding `word` on a line, e.g. `43` in "43 checks" and in
/// "two checks of 43".
fn claimed_counts(line: &str, word: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let tokens: Vec<&str> = line.split_whitespace().collect();
    for (i, token) in tokens.iter().enumerate() {
        let bare = token.trim_matches(|c: char| !c.is_alphanumeric());
        if bare != word {
            continue;
        }
        // "N checks"
        if let Some(prev) = i.checked_sub(1)
            && let Some(n) = numeric_token(tokens[prev])
        {
            out.push(n);
        }
        // "checks of N": the denominator form, which drifted independently of the first.
        if tokens.get(i.saturating_add(1)).map(|t| t.trim_matches(',')) == Some("of")
            && let Some(n) = tokens
                .get(i.saturating_add(2))
                .and_then(|t| numeric_token(t))
        {
            out.push(n);
        }
    }
    out
}

/// A token counts as a number only if it is *entirely* digits once punctuation is stripped.
///
/// Trimming non-digits from both ends instead reads a trailing number out of a word: "the
/// aarch64 checks are gated" becomes a claim of 64 checks. A guard that invents claims is worse
/// than one that misses them, because the fix looks like editing the prose.
fn numeric_token(token: &str) -> Option<usize> {
    let bare = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if bare.is_empty() || !bare.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    bare.parse().ok()
}

#[test]
fn a_word_ending_in_digits_is_not_a_count() {
    assert!(claimed_counts("the aarch64 checks are gated", "checks").is_empty());
    assert!(claimed_counts("x86_64 checks", "checks").is_empty());
    assert_eq!(
        claimed_counts("51 checks against a guide", "checks"),
        vec![51]
    );
    assert_eq!(claimed_counts("two checks of 51.", "checks"), vec![51]);
}

/// `detect::READS_UNSTORED_ARTIFACT` is exactly the code decoders that read the artifact
/// without declaring a table, held to the recorded evidence in both directions.
///
/// A report stores an arm's artifact only for a check that reads one, so `chard detect`
/// replays an arm of any other code-decoded check over its build and run records alone.
/// That is exact only where the decoder reads nothing else. Every code-decoded check with
/// no declared table and not on the list must read each recorded fixture the same with the
/// artifact taken away, its ELF facts and the macros its `.chard.report` carries; every
/// check on the list must read some evidence differently without them, or the entry is
/// stale and withholds replays for nothing. The listed check's sensitivity is shown by the
/// recorded rows themselves, the libc++ ones whose artifact names its library in its
/// self-report, and again with libc++'s macro added to every recorded run.
#[test]
fn the_code_decoders_that_read_an_unstored_artifact_are_exactly_the_listed_ones() {
    use chard::probe::{Detection, Evidence};
    use std::collections::BTreeMap;

    fn same(a: &Detection, b: &Detection) -> bool {
        a.outcome == b.outcome && a.level == b.level && a.observed == b.observed
    }
    let fixtures = load();
    let checks: Vec<_> = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .filter(|c| c.predicate().is_none() && c.reads().is_empty())
        .collect();
    let empty = BTreeMap::new();
    let mut compared = 0usize;
    for check in &checks {
        let listed = chard::detect::READS_UNSTORED_ARTIFACT.contains(&check.id);
        let rows: Vec<&Fixture> = fixtures.iter().filter(|f| f.check == check.id).collect();
        let mut differs = false;
        let mut injected_differs = false;
        for f in &rows {
            let macros = if f.macros.is_empty() {
                f.elf
                    .as_ref()
                    .and_then(|e| chard::decode::common::parse_self_report(&e.self_report))
                    .unwrap_or_default()
            } else {
                f.macros.clone()
            };
            let with = check.decode(&Evidence {
                macros: &macros,
                elf: f.elf.as_ref(),
                build: f.build.as_ref(),
                run: f.run.as_ref(),
                workdir: None,
            });
            let without = check.decode(&Evidence {
                macros: &empty,
                elf: None,
                build: f.build.as_ref(),
                run: f.run.as_ref(),
                workdir: None,
            });
            compared += 1;
            if !same(&with.detection, &without.detection) {
                differs = true;
                assert!(
                    listed,
                    "{} ({} {}) reads differently without its artifact, so an arm replayed \
                     over its records alone would not be exact: add it to \
                     detect::READS_UNSTORED_ARTIFACT",
                    check.id, f.toolchain, f.profile
                );
            }
            if listed && f.run.is_some() {
                let libcpp = BTreeMap::from([("_LIBCPP_VERSION".to_owned(), "220108".to_owned())]);
                let as_libcpp = check.decode(&Evidence {
                    macros: &libcpp,
                    elf: None,
                    build: f.build.as_ref(),
                    run: f.run.as_ref(),
                    workdir: None,
                });
                injected_differs |= !same(&as_libcpp.detection, &without.detection);
            }
        }
        if listed {
            assert!(
                differs,
                "{} is listed in detect::READS_UNSTORED_ARTIFACT and reads every recorded \
                 fixture the same without its artifact: the entry withholds replays for nothing",
                check.id
            );
            assert!(
                injected_differs,
                "{} reads every recorded run the same with libc++'s macro added",
                check.id
            );
        }
    }
    for listed in chard::detect::READS_UNSTORED_ARTIFACT {
        assert!(
            checks.iter().any(|c| c.id == *listed),
            "{listed} is listed but is not a code-decoded check without declared tables"
        );
    }
    assert!(compared > 100, "only {compared} fixtures compared");
}

/// The measured libc++ builds of `cxx-stdlib-assertions` and how its notes name each: a
/// (toolchain, architecture, profile) the corpus holds, beside the phrase the notes carry,
/// which names the toolchain id's compiler and version, its libc, its distribution and the
/// architecture.
const LIBCPP_MEASURED: &[(&str, &str, &str, &str)] = &[(
    "clang-22.1.7-musl1.2.5_git20240705-chimerarolling",
    "x86_64",
    "bare",
    "Chimera Linux (clang 22.1.7, musl, x86_64)",
)];

/// Whether a row's build is libc++: a `DT_NEEDED` on it, or the library named the way the
/// decoder reads it, in the recorded macros or in the artifact's self-report.
fn is_libcpp(f: &Fixture) -> bool {
    use chard::decode::common::{cxx_stdlib, parse_self_report};
    let elf = f.elf.as_ref();
    elf.is_some_and(|e| e.needed.iter().any(|n| n.starts_with("libc++.so")))
        || cxx_stdlib(&f.macros) == Some("libc++")
        || elf
            .and_then(|e| parse_self_report(&e.self_report))
            .is_some_and(|m| cxx_stdlib(&m) == Some("libc++"))
}

/// Every row of `check` that prints libc++'s failed-precondition message is hand-authored,
/// and one does: a decoder needle in the output of a libc++ build, or of a run naming
/// libc++'s header directory.
fn only_hand_authored_rows_print_libcpps_message(fixtures: &[Fixture], check: &str) {
    use chard::decode::runtime::CXX_ASSERT_MESSAGES;
    let rows = || fixtures.iter().filter(|f| f.check == check);
    let worded: Vec<&Fixture> = rows()
        .filter(|f| {
            f.run.as_ref().is_some_and(|r| {
                CXX_ASSERT_MESSAGES.iter().any(|m| r.output_contains(m))
                    && (is_libcpp(f) || r.output_contains("/c++/v1/"))
            })
        })
        .collect();
    assert!(
        !worded.is_empty(),
        "no row holds libc++'s failed-precondition message"
    );
    for f in &worded {
        assert!(
            f.toolchain.starts_with(HAND_AUTHORED),
            "{} records libc++'s message: the notes say no recorded measurement does",
            f.toolchain
        );
    }
}

/// `phrase` names `toolchain`'s compiler and version, its libc and its distribution, and
/// `arch`.
fn phrase_names_the_build(toolchain: &str, arch: &str, phrase: &str) {
    // `<compiler>-<version>-<libc><version>-<distribution><release>`.
    let fields: Vec<&str> = toolchain.split('-').collect();
    let alpha = |s: &str| -> String { s.chars().take_while(char::is_ascii_alphabetic).collect() };
    let distribution = phrase.split_whitespace().next().unwrap_or("");
    for (part, named) in [
        (
            "compiler and version",
            format!("{} {}", fields[0], fields[1]),
        ),
        ("libc", alpha(fields[2])),
        ("architecture", arch.to_owned()),
    ] {
        assert!(
            phrase.contains(&named),
            "{phrase:?} does not name the {part} {named:?}"
        );
    }
    assert!(
        !distribution.is_empty()
            && alpha(fields[fields.len() - 1]).starts_with(&distribution.to_ascii_lowercase()),
        "{phrase:?} does not begin with {toolchain}'s distribution"
    );
}

/// What `cxx-stdlib-assertions`'s notes say of libc++ is what the corpus holds.
///
/// The notes ship in `chard probes` and in every report, so a sentence about which libc++
/// systems were measured is published under every profile. This derives the claim from the
/// file: the measured libc++ rows are exactly the builds of [`LIBCPP_MEASURED`], each names
/// libc++ in its self-report, trapped, printed none of the decoder's messages, shares one
/// archived verdict and reads `present` from its own records; the notes carry the trap rule,
/// each build with that verdict and "alone"; and every row printing libc++'s message is
/// hand-authored. A regeneration that adds a libc++ build, or a libc++ run that prints the
/// message, fails here until the notes say so.
///
/// The archived verdict is the measured report's, decided by its control triple; the rows'
/// `expected` is `indeterminate` because a replay feeds the recorded macros alone, and the
/// library's name is in the self-report.
#[test]
fn the_libcpp_sentence_in_the_cxx_assertions_notes_is_what_the_corpus_holds() {
    use chard::decode::runtime::CXX_ASSERT_MESSAGES;
    use chard::probe::{Evidence, Outcome};
    const CHECK: &str = "cxx-stdlib-assertions";
    let check = check_of(CHECK).expect("the check is in the corpus");
    let fixtures = load();
    let rows = || fixtures.iter().filter(|f| f.check == CHECK);
    for f in rows().filter(|f| !f.toolchain.starts_with(HAND_AUTHORED) && f.run.is_some()) {
        assert!(
            f.elf.is_some(),
            "{} {} ran without ELF facts, so whether it is libc++ cannot be read",
            f.toolchain,
            f.profile
        );
    }
    let measured: Vec<&Fixture> = rows()
        .filter(|f| !f.toolchain.starts_with(HAND_AUTHORED) && is_libcpp(f))
        .collect();
    let builds: BTreeSet<(&str, &str, &str)> = measured
        .iter()
        .map(|f| {
            (
                f.toolchain.as_str(),
                f.arch.as_deref().unwrap_or(""),
                f.profile.as_str(),
            )
        })
        .collect();
    let listed: BTreeSet<(&str, &str, &str)> = LIBCPP_MEASURED
        .iter()
        .map(|&(t, a, p, _)| (t, a, p))
        .collect();
    assert_eq!(
        builds, listed,
        "the measured libc++ rows of {CHECK} are not the builds LIBCPP_MEASURED names: \
         update it and the check's notes"
    );
    let mut verdicts = BTreeSet::new();
    for f in &measured {
        let elf = f
            .elf
            .as_ref()
            .expect("a measured libc++ row carries its ELF facts");
        let macros = chard::decode::common::parse_self_report(&elf.self_report)
            .expect("a measured libc++ row carries a self-report");
        assert_eq!(
            chard::decode::common::cxx_stdlib(&macros),
            Some("libc++"),
            "{} is libc++ but its self-report does not name it",
            f.toolchain
        );
        let run = f.run.as_ref().expect("a measured run");
        assert!(run.trapped(), "{} did not trap", f.toolchain);
        assert!(
            !CXX_ASSERT_MESSAGES.iter().any(|m| run.output_contains(m)),
            "{} printed a library message: the notes say no recorded measurement does",
            f.toolchain
        );
        verdicts.insert(f.archived_verdict.as_deref().unwrap_or("none"));
        let read = check.decode(&Evidence {
            macros: &macros,
            elf: f.elf.as_ref(),
            build: f.build.as_ref(),
            run: Some(run),
            workdir: None,
        });
        assert_eq!(read.detection.outcome, Outcome::Present, "{}", f.toolchain);
    }
    let [verdict] = verdicts.into_iter().collect::<Vec<_>>()[..] else {
        panic!("the measured libc++ rows do not share one archived verdict")
    };
    only_hand_authored_rows_print_libcpps_message(&fixtures, CHECK);
    let [(toolchain, arch, profile, phrase)] = LIBCPP_MEASURED else {
        panic!("the notes say one libc++ build alone: rewrite them for more")
    };
    phrase_names_the_build(toolchain, arch, phrase);
    let flat = check.notes.split_whitespace().collect::<Vec<_>>().join(" ");
    for needle in [
        format!(
            "On libc++ a bare trap is credited where the build names libc++ as its library; \
             of the measurements in chard's test corpus, a build under the `{profile}` profile \
             on {phrase} alone reached `{verdict}` that way."
        ),
        "matched too, but no recorded measurement holds it, only a hand-written test case."
            .to_owned(),
    ] {
        assert!(
            flat.contains(&needle),
            "{CHECK}'s notes do not say {needle:?}"
        );
    }
}

/// `cxx-hardening-requested` is determinate exactly where its recorded macros name the
/// standard library, as `tests/fixtures/README.md` says of the corpus.
///
/// Without `_CXX_STDLIB` a build with neither library's macro is ambiguous (the check's
/// notes give why), and a replay reads the recorded macros, not the artifact's self-report,
/// which names the library on rows of either kind. A determinate row without the macro, or
/// an indeterminate one with it, is a row the README's sentence does not describe.
#[test]
fn a_cxx_hardening_row_is_determinate_exactly_where_its_recorded_macros_name_the_library() {
    let fixtures = load();
    let rows: Vec<&Fixture> = fixtures
        .iter()
        .filter(|f| f.check == "cxx-hardening-requested")
        .collect();
    let named = |f: &Fixture| {
        matches!(
            f.macros.get("_CXX_STDLIB").map(String::as_str),
            Some("libc++" | "libstdc++")
        )
    };
    let count = rows.iter().filter(|f| named(f)).count();
    assert!(
        count > 0 && count < rows.len(),
        "the corpus no longer holds both kinds of cxx-hardening-requested row"
    );
    assert!(
        rows.iter().any(|f| {
            !named(f)
                && f.elf.as_ref().is_some_and(|e| {
                    chard::decode::common::parse_self_report(&e.self_report)
                        .is_some_and(|m| chard::decode::common::cxx_stdlib(&m).is_some())
                })
        }),
        "no unnamed row's self-report names the library, as the README says some do"
    );
    for f in &rows {
        let determinate = f.expected != "indeterminate";
        assert_eq!(
            determinate,
            named(f),
            "cxx-hardening-requested on {} {} {:?} reads {} with _CXX_STDLIB {:?}",
            f.toolchain,
            f.profile,
            f.arm,
            f.expected,
            f.macros.get("_CXX_STDLIB")
        );
    }
}

/// The corpus carries control-arm rows beside measured ones, and among them the case a
/// triple withholds on: a positive control that did not show the observable.
///
/// Were `fixture::extract` to mine only measured builds, a silent positive arm would replay
/// only where some measured build shared its facts. Each evaluated arm with facts the report
/// can reproduce is a row (`Fixture::arm`), replayed by the same
/// harness as every other row; this holds that regeneration kept doing so. The silent
/// positive arms come from toolchains whose link clears a marking, the `link-drops-marking`
/// cells.
#[test]
fn the_corpus_carries_arm_rows_beside_measured_ones() {
    let fixtures = load();
    let arms: Vec<&Fixture> = fixtures.iter().filter(|f| f.arm.is_some()).collect();
    let measured = fixtures.len() - arms.len();
    eprintln!(
        "{} fixture rows: {measured} measured, {} arm ({} positive, {} negative, {} regime)",
        fixtures.len(),
        arms.len(),
        arms.iter()
            .filter(|f| f.arm.as_deref() == Some("positive"))
            .count(),
        arms.iter()
            .filter(|f| f.arm.as_deref() == Some("negative"))
            .count(),
        arms.iter()
            .filter(|f| f.arm.as_deref() == Some("regime"))
            .count(),
    );
    assert!(
        measured > 0 && !arms.is_empty(),
        "{measured} measured, {} arm rows",
        arms.len()
    );
    for f in &arms {
        assert!(
            matches!(f.arm.as_deref(), Some("positive" | "negative" | "regime")),
            "{} carries arm {:?}",
            f.check,
            f.arm
        );
    }
    assert!(
        arms.iter()
            .any(|f| f.arm.as_deref() == Some("positive") && f.expected == "absent"),
        "no positive arm row reads `absent`, the case a triple withholds on"
    );
}

/// OpenBSD's canary failure handler, `__stack_smash_handler`, is held by a recorded link as
/// well as by `measure`'s unit test over fabricated facts.
///
/// The rows were mined 2026-09-30 from one OpenBSD 7.9 amd64 report at `-fno-ret-protector`
/// and appended between regenerations (`tests/fixtures/README.md`), so a regeneration that
/// does not name that report among its sources drops them without losing a (toolchain,
/// architecture) pair. This is the stop for that: a `canary-emitted` row reading `present`
/// on an undefined `__stack_smash_handler`, and a `-fno-stack-protector` arm of the same
/// toolchain reading `absent`.
#[test]
fn the_corpus_holds_openbsds_canary_handler_in_a_real_link() {
    const HANDLER: &str = "__stack_smash_handler";
    let fixtures = load();
    let references = |f: &Fixture| {
        f.elf
            .as_ref()
            .and_then(|e| e.watched_symbols.get(HANDLER))
            .is_some_and(|s| !s.defined)
    };
    let present: Vec<&Fixture> = fixtures
        .iter()
        .filter(|f| f.check == "canary-emitted" && f.expected == "present" && references(f))
        .collect();
    assert!(
        !present.is_empty(),
        "no canary-emitted row reads present on a {HANDLER} reference"
    );
    for p in &present {
        assert!(
            fixtures.iter().any(|f| {
                f.check == "canary-emitted"
                    && f.toolchain == p.toolchain
                    && f.arch == p.arch
                    && f.arm.as_deref() == Some("negative")
                    && f.expected == "absent"
                    && !references(f)
                    && f.build
                        .as_ref()
                        .is_some_and(|b| b.argv.iter().any(|a| a == "-fno-stack-protector"))
            }),
            "{} carries {HANDLER} with no -fno-stack-protector arm reading absent",
            p.toolchain
        );
    }
}

/// A static link supplies no canary the flags disabled, held by a recorded musl link.
///
/// A static libc does not carry its `__stack_chk_fail` into every link (measured
/// 2026-10-05): a static link pulls only the archive members something references. The rows
/// were mined 2026-10-05 from an Alpine `3.25.0_alpha20260805` x86_64 container (musl 1.2.6,
/// GNU ld 2.45.1; gcc 15.2.0, whose
/// `-static` link is a static PIE, and clang 23.1.2, whose is an `ET_EXEC`) and appended between
/// regenerations (`tests/fixtures/README.md`), so a regeneration that does not name those
/// reports drops them without losing a (toolchain, architecture) pair. This is the stop for
/// that, and for a detector that reads a static link as carrying a canary: per compiler, an
/// `-O2 -static -fno-stack-protector` measured build with no failure handler in any table
/// replays `canary-emitted` `absent`, and its `-fstack-protector-strong` sibling, the handler
/// linked in defined, replays `present`.
#[test]
fn a_static_musl_link_supplies_no_canary_the_flags_disabled() {
    const HANDLERS: [&str; 3] = [
        "__stack_chk_fail",
        "__stack_chk_fail_local",
        "__stack_chk_guard",
    ];
    let fixtures = load();
    let static_musl = |f: &&Fixture, flag: &str| {
        f.check == "canary-emitted"
            && f.arm.is_none()
            && f.toolchain.contains("-musl")
            && f.elf
                .as_ref()
                .is_some_and(|e| e.statically_linked == Some(true) && !e.has_interp)
            && f.build.as_ref().is_some_and(|b| {
                b.argv.iter().any(|a| a == "-static") && b.argv.iter().any(|a| a == flag)
            })
    };
    let disabled: Vec<&Fixture> = fixtures
        .iter()
        .filter(|f| static_musl(f, "-fno-stack-protector"))
        .collect();
    let compilers: BTreeSet<&str> = disabled
        .iter()
        .filter_map(|f| f.toolchain.split('-').next())
        .collect();
    eprintln!(
        "{} static musl -fno-stack-protector canary-emitted row(s), compilers {compilers:?}",
        disabled.len()
    );
    assert_eq!(
        compilers,
        BTreeSet::from(["clang", "gcc"]),
        "the static musl links without a stack protector are not both compilers'"
    );
    for f in &disabled {
        let elf = f.elf.as_ref().expect("filtered on elf");
        let held: Vec<&str> = HANDLERS
            .into_iter()
            .filter(|h| elf.watched_symbols.contains_key(*h))
            .collect();
        assert!(
            held.is_empty() && !elf.symbol_tables.is_empty(),
            "{}: the recorded link holds {held:?} or no symbol table, so it no longer \
             witnesses a static link without the handler",
            f.toolchain
        );
        let replay = f.replay().expect("canary-emitted is in the corpus");
        assert_eq!(
            replay.got, "absent",
            "{}: a static link with no canary failure handler read {}",
            f.toolchain, replay.got
        );
        let strong = fixtures
            .iter()
            .find(|g| {
                static_musl(g, "-fstack-protector-strong")
                    && g.toolchain == f.toolchain
                    && g.arch == f.arch
            })
            .unwrap_or_else(|| {
                panic!(
                    "{} has no static -fstack-protector-strong row beside it",
                    f.toolchain
                )
            });
        let replay = strong.replay().expect("canary-emitted is in the corpus");
        assert_eq!(
            replay.got, "present",
            "{}: the static -fstack-protector-strong link read {}",
            strong.toolchain, replay.got
        );
    }
}

/// How many recorded `no-strict-overflow` rows carry the probe's `gcc-major=` line: gcc
/// 7.5.0's `bare` measured row and both its arms and its explicit `-fno-strict-overflow`
/// row, gcc 8.3.0's explicit row, and the thirteen optimized gcc 4.8.4, 5.4.0 and 7.5.0
/// (x86_64 and i386) rows: the explicit `-O1` measured builds, their arms but 7.5.0
/// x86_64's, and the `bare-optimized` measured builds of 4.8.4, 5.4.0 and 7.5.0 i386, and
/// 7.5.0 x86_64's five explicit builds at `-Og`, `-O`, `-O2 -O1`, `-O2 --optimize=1` and `-Os
/// -fno-strict-overflow` (`tests/fixtures/README.md` names them).
const GCC_MAJOR_ROWS: usize = 23;

/// The recorded runs on each side of gcc 8 read as the decoder says: an unoptimized gcc 7.5.0
/// build that ran the guard is withheld, and gcc 8.3.0's is `present`; an optimized gcc
/// before 8 is read by its compile line's last `-O` word, withheld at `-O1` and read at `-O2`
/// as the guard says (the arms' `present` and `absent`, the flagless build's `absent`).
/// Pinned beside the count, since a row losing its `gcc-major=` line would still replay its
/// new reading.
#[test]
fn the_recorded_gcc_runs_read_by_the_threshold_and_an_old_gccs_by_its_level() {
    let fixtures = load();
    let rows: Vec<&Fixture> = fixtures
        .iter()
        .filter(|f| {
            f.check == "no-strict-overflow"
                && f.run
                    .as_ref()
                    .is_some_and(|r| r.stdout.lines().any(|l| l.starts_with("gcc-major=")))
        })
        .collect();
    assert_eq!(
        rows.len(),
        GCC_MAJOR_ROWS,
        "the corpus's no-strict-overflow rows carrying gcc-major= changed in number"
    );
    let mut unoptimized = BTreeMap::new();
    let mut optimized_before_8 = BTreeMap::new();
    for row in rows {
        let what = format!("{} {} {:?}", row.toolchain, row.profile, row.arm);
        let replay = row
            .replay()
            .unwrap_or_else(|| panic!("{what}: does not replay"));
        assert!(replay.agrees(), "{what}: reads {}", replay.got);
        let stdout = &row.run.as_ref().expect("filtered on its run").stdout;
        let major = row.toolchain.split(['-', '.']).nth(1).unwrap_or("?");
        if stdout.lines().any(|l| l == "optimize=no") {
            unoptimized
                .entry(major.to_owned())
                .or_insert_with(BTreeSet::new)
                .insert(replay.got.clone());
        } else if major.parse::<u32>().is_ok_and(|m| m < 8) {
            // The row's level, read apart from the decoder: the last `-O` or `--optimize`
            // word, the long spelling as gcc reads it.
            let level = row
                .build
                .as_ref()
                .and_then(|b| {
                    b.argv
                        .iter()
                        .rfind(|w| w.starts_with("-O") || w.starts_with("--optimize"))
                })
                .map_or_else(
                    || panic!("{what}: an optimized build with no -O word"),
                    |w| match w.strip_prefix("--optimize=") {
                        Some(value) => format!("-O{value}"),
                        None => w.clone(),
                    },
                );
            optimized_before_8
                .entry((level, row.arm.clone()))
                .or_insert_with(BTreeSet::new)
                .insert(replay.got.clone());
        }
    }
    let set = |word: &str| BTreeSet::from([word.to_owned()]);
    let want: BTreeMap<String, BTreeSet<String>> = [
        ("7".to_owned(), set("indeterminate")),
        ("8".to_owned(), set("present")),
    ]
    .into();
    assert_eq!(unoptimized, want);
    let want: BTreeMap<(String, Option<String>), BTreeSet<String>> = [
        (("-O".to_owned(), None), set("indeterminate")),
        (("-O1".to_owned(), None), set("indeterminate")),
        (("-Og".to_owned(), None), set("indeterminate")),
        (("-Os".to_owned(), None), set("present")),
        (("-O2".to_owned(), None), set("absent")),
        (
            ("-O2".to_owned(), Some("positive".to_owned())),
            set("present"),
        ),
        (
            ("-O2".to_owned(), Some("negative".to_owned())),
            set("absent"),
        ),
    ]
    .into();
    assert_eq!(optimized_before_8, want);
}

/// How many recorded artifacts carry `PT_OPENBSD_NOBTCFI`. A regeneration that drops them
/// leaves the readings below exercised by nothing, so the count is pinned: the OpenBSD 7.9
/// arm64 `branch-protection-marked` row, the OpenBSD 7.9 amd64 `cet-marked` row, and the
/// Fedora 44 x86_64 `cet-marked` row whose header lld wrote for a Linux target.
const NOBTCFI_ROWS: usize = 3;

/// The recorded artifacts carrying `PT_OPENBSD_NOBTCFI`, after asserting their number.
fn nobtcfi_rows(fixtures: &[Fixture]) -> Vec<&Fixture> {
    let rows: Vec<&Fixture> = fixtures
        .iter()
        .filter(|f| f.elf.as_ref().is_some_and(|e| e.openbsd_nobtcfi))
        .collect();
    assert_eq!(
        rows.len(),
        NOBTCFI_ROWS,
        "the corpus's artifacts carrying PT_OPENBSD_NOBTCFI changed in number"
    );
    rows
}

fn replay_libc(name: &str) -> chard::env::Libc {
    chard::env::Libc {
        impl_name: name.to_owned(),
        version: None,
        detection: "replay".to_owned(),
    }
}

/// The observation a measured marking row was published as, with `verdict`, and a store
/// holding `elf` under the row's artifact key.
fn marking_observation(
    row: &Fixture,
    verdict: chard::report::Verdict,
) -> (chard::report::Observation, String) {
    recorded_observation(row, "link-defaults", verdict)
}

/// The observation a measured row of `probe` was published as, with `verdict` and the
/// row's expected level, and the row's artifact key.
fn recorded_observation(
    row: &Fixture,
    probe: &str,
    verdict: chard::report::Verdict,
) -> (chard::report::Observation, String) {
    use chard::report::Observation;
    let build = row.build.clone().expect("a measured row carries its build");
    let key = build
        .artifact_sha256
        .clone()
        .expect("the build names its artifact");
    let check = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == row.check)
        .expect("the check is in the corpus");
    let observation = Observation {
        probe: probe.to_owned(),
        check: row.check.clone(),
        flag: check.flag.to_owned(),
        channel: check.channel(),
        polarity: check.polarity,
        verdict,
        level: row.expected_level.clone(),
        recommended_level: None,
        confidence: "high".to_owned(),
        observable: String::new(),
        boundary: None,
        defects: Vec::new(),
        observes: chard::probe::Observes::Protection,
        references: Vec::new(),
        evidence: chard::report::EvidenceOut::default(),
        build: Some(build),
        run: None,
        controls: None,
        gating: None,
        build_rejection: None,
        structured_diagnostics: None,
        notes: String::new(),
    };
    (observation, key)
}

fn store_of(key: &str, elf: chard::elf::ElfFacts) -> chard::report::FactStore {
    let mut store = chard::report::FactStore::default();
    store
        .insert(
            key.to_owned(),
            chard::report::FactEntry::Elf { elf: Box::new(elf) },
        )
        .expect("one entry");
    store
}

/// The measured `-Wl,-z,nobtcfi` artifact reads `cfi-effective` `off` on every host.
///
/// The `INERT_FORMS` row for the same flag in `tests/inert_flags.rs` runs only where the C
/// library is OpenBSD's, which no host routine verification uses, so this is what exercises
/// the reading everywhere. Each recorded artifact carrying the header is replayed through
/// its marking check's predicate, which must still read both edges marked, and the
/// composite is then reduced over that reading and the recorded facts: `off` under
/// OpenBSD's C library, `not-established` under another, and `on` for the same facts with
/// the header cleared, so the header and nothing else moves it.
///
/// The x86_64 `cet-marked` rows are reduced the same way over their published verdict,
/// which is what their fixture notes cite: a marking `on` beside the header reads as the
/// aarch64 one does, and a marking already `partial` reads `off` with the header or
/// without it, the constituent naming the header only where the artifact carries it.
#[test]
fn the_recorded_nobtcfi_artifact_reads_cfi_effective_off() {
    use chard::report::Verdict;

    let fixtures = load();
    let libc = replay_libc;
    let mut exercised = 0;
    let mut cet_on = 0;
    let mut cet_short = 0;
    for row in nobtcfi_rows(&fixtures) {
        let what = format!("{} {} {}", row.check, row.toolchain, row.profile);
        let replay = row
            .replay()
            .unwrap_or_else(|| panic!("{what}: does not replay"));
        if row.arm.is_some() {
            continue;
        }
        if row.check == "cet-marked" {
            assert!(
                replay.agrees(),
                "{what}: the predicate no longer reads the row"
            );
            if cfi_over_cet_marking(row, &what) {
                cet_on += 1;
            } else {
                cet_short += 1;
            }
            continue;
        }
        if row.check != "branch-protection-marked" {
            continue;
        }
        assert!(
            row.toolchain.contains("-openbsd-"),
            "{what}: not an OpenBSD row"
        );
        assert_eq!(
            (replay.got.as_str(), replay.got_level.as_deref()),
            ("present", Some("full")),
            "{what}: the marking no longer reads both edges"
        );
        let elf = row.elf.clone().expect("filtered on its elf block");
        let (observation, key) = marking_observation(row, Verdict::On);
        let obs = [observation];
        let arch = row
            .arch
            .as_deref()
            .expect("a mined row names its architecture");

        let opted =
            chard::composite::cfi(&obs, arch, &libc("openbsd"), &store_of(&key, elf.clone()));
        assert_eq!(opted.verdict, Verdict::Off, "{what}: {}", opted.reason);
        let elsewhere =
            chard::composite::cfi(&obs, arch, &libc("glibc"), &store_of(&key, elf.clone()));
        assert_eq!(
            elsewhere.verdict,
            Verdict::Indeterminate,
            "{what}: {}",
            elsewhere.reason
        );
        let mut cleared = elf;
        cleared.openbsd_nobtcfi = false;
        let bare = chard::composite::cfi(&obs, arch, &libc("openbsd"), &store_of(&key, cleared));
        assert_eq!(bare.verdict, Verdict::On, "{what}: {}", bare.reason);
        exercised += 1;
    }
    assert!(
        exercised > 0,
        "no recorded artifact marks both edges beside the header, so the reading that turns \
         `on` into `off` was exercised by nothing"
    );
    assert!(
        cet_on > 0 && cet_short > 0,
        "the recorded x86_64 artifacts no longer cover a CET marking on ({cet_on}) and one \
         short ({cet_short}) beside the header"
    );
}

/// The recorded x86_64 marking reads `marked`, and names what the same toolchain's
/// recorded `shadow-stack-enforced` row measured of enforcement.
///
/// The fixture pairs: each measured `shadow-stack-enforced` row (the Fedora 44 x86_64 rows,
/// gcc 16.1.1 and clang 22.1.8, a kernel and CPU with the user shadow stack: `partial` at
/// `opt-in` under `-fcf-protection=full`, the state upstream glibc 2.39 and later gives, and
/// `off` under `bare`) beside its toolchain's measured `cet-marked` row published `on`
/// over an artifact without the opt-out header. The pair is by toolchain, not by report:
/// the marking row was mined from another profile's run, so the composite is reduced over
/// two recorded readings no one report holds (the `off` pairing is the shape of a library on
/// the link line turning the shadow stack off beside a marking kept). Both rows are replayed
/// through their detectors first, which must still read them as recorded. The composite
/// over the pair reads `on` with the constituent `marked`, never `in-force`, and the
/// constituent's note and the reason end with the enforcement row's verdict and level; the
/// same marking beside no enforcement row says the check is not in the report. The guard
/// counts what was fed: each toolchain with both verdicts, and at least two toolchains. No
/// recorded row reads `on` at `default`, which no measured C library enables; that shape is
/// a unit test in `composite.rs`.
#[test]
fn the_recorded_marking_reads_marked_beside_the_recorded_enforcement_reading() {
    use chard::composite::ConstituentState as S;
    use chard::report::Verdict;

    let fixtures = load();
    let libc = replay_libc;
    let enforcement: Vec<&Fixture> = fixtures
        .iter()
        .filter(|f| f.check == "shadow-stack-enforced" && f.arm.is_none())
        .collect();
    let mut covered: std::collections::BTreeMap<&str, (bool, bool)> =
        std::collections::BTreeMap::new();
    for row in &enforcement {
        let what = format!("{} {} {}", row.check, row.toolchain, row.profile);
        let replay = row
            .replay()
            .unwrap_or_else(|| panic!("{what}: does not replay"));
        assert!(
            replay.agrees(),
            "{what}: the detector no longer reads the row"
        );
        let verdict = match row.archived_verdict.as_deref() {
            Some("partial") => Verdict::Partial,
            Some("off") => Verdict::Off,
            other => panic!("{what}: an enforcement row published {other:?}"),
        };
        let marking = fixtures
            .iter()
            .find(|f| {
                f.check == "cet-marked"
                    && f.arm.is_none()
                    && f.toolchain == row.toolchain
                    && f.archived_verdict.as_deref() == Some("on")
                    && f.elf.as_ref().is_some_and(|e| !e.openbsd_nobtcfi)
            })
            .unwrap_or_else(|| panic!("{what}: no recorded cet-marked `on` row of its toolchain"));
        let marking_replay = marking
            .replay()
            .unwrap_or_else(|| panic!("{what}: the marking row does not replay"));
        assert!(
            marking_replay.agrees(),
            "{what}: the predicate no longer reads the marking row"
        );
        let (marked, key) = marking_observation(marking, Verdict::On);
        let (enforced, _) = recorded_observation(row, "shadow-stack", verdict);
        let arch = marking
            .arch
            .as_deref()
            .expect("a mined row names its architecture");
        let elf = marking.elf.clone().expect("filtered on its elf block");
        let store = store_of(&key, elf);

        let want = format!(
            "shadow-stack-enforced, which runs a program built with the same flags and \
             measures the backward edge's enforcement, reads {}{}; no check measures IBT \
             enforcement",
            verdict.as_str(),
            row.expected_level
                .as_deref()
                .map_or_else(String::new, |l| format!(
                    " at {l}{}",
                    match l {
                        "opt-in" => " (enforced only under glibc's opt-in tunable)",
                        "default" => " (enforced without the opt-in tunable)",
                        _ => "",
                    }
                ))
        );
        let c = chard::composite::cfi(&[marked.clone(), enforced], arch, &libc("glibc"), &store);
        assert_eq!(c.verdict, Verdict::On, "{what}: {}", c.reason);
        let k = &c.constituents[0];
        assert_eq!(k.state, S::Marked, "{what}: {:?}", k.note);
        assert!(
            k.note.as_deref().is_some_and(|n| n.ends_with(&want)),
            "{what}: {:?}",
            k.note
        );
        assert!(c.reason.ends_with(&want), "{what}: {}", c.reason);

        let alone = chard::composite::cfi(&[marked], arch, &libc("glibc"), &store);
        assert_eq!(alone.constituents[0].state, S::Marked, "{what}");
        assert!(
            alone.reason.ends_with(
                "shadow-stack-enforced, which runs a program built with the same flags and \
                 measures the backward edge's enforcement, is not in this report; no check \
                 measures IBT enforcement"
            ),
            "{what}: {}",
            alone.reason
        );
        let seen = covered.entry(row.toolchain.as_str()).or_default();
        match verdict {
            Verdict::Partial => seen.0 = true,
            _ => seen.1 = true,
        }
    }
    assert!(
        covered.len() >= 2 && covered.values().all(|(partial, off)| *partial && *off),
        "the recorded enforcement rows no longer cover, for each of two toolchains, a shadow \
         stack enforced under the opt-in and one turned off: {covered:?}"
    );
}

/// `cfi-effective` over one recorded x86_64 `cet-marked` row carrying the header, at its
/// published verdict, for [`the_recorded_nobtcfi_artifact_reads_cfi_effective_off`];
/// whether that marking was `on`.
fn cfi_over_cet_marking(row: &Fixture, what: &str) -> bool {
    use chard::report::Verdict;
    let libc = replay_libc;
    let verdict = match row.archived_verdict.as_deref() {
        Some("on") => Verdict::On,
        Some("partial") => Verdict::Partial,
        other => panic!("{what}: a marking row published {other:?}"),
    };
    let elf = row.elf.clone().expect("filtered on its elf block");
    let (observation, key) = marking_observation(row, verdict);
    let obs = [observation];
    let arch = row
        .arch
        .as_deref()
        .expect("a mined row names its architecture");
    let on = verdict == Verdict::On;
    for (under, want) in [
        ("openbsd", Verdict::Off),
        (
            "glibc",
            if on {
                Verdict::Indeterminate
            } else {
                Verdict::Off
            },
        ),
    ] {
        let c = chard::composite::cfi(&obs, arch, &libc(under), &store_of(&key, elf.clone()));
        assert_eq!(c.verdict, want, "{what} under {under}: {}", c.reason);
        assert_eq!(
            c.constituents[0]
                .opt_out
                .as_ref()
                .map(|o| (o.header, o.facts.as_str())),
            Some((chard::composite::PT_OPENBSD_NOBTCFI, key.as_str())),
            "{what} under {under}"
        );
    }
    let mut cleared = elf;
    cleared.openbsd_nobtcfi = false;
    let bare = chard::composite::cfi(&obs, arch, &libc("openbsd"), &store_of(&key, cleared));
    assert_eq!(
        (bare.verdict, bare.constituents[0].opt_out.is_some()),
        (if on { Verdict::On } else { Verdict::Off }, false),
        "{what} with the header cleared: {}",
        bare.reason
    );
    on
}

/// The recorded artifacts carrying `PT_OPENBSD_NOBTCFI` read `fhardened-effective`'s CET
/// slot as `cfi-effective` reads them, on every host.
///
/// Each `cet-marked` row is replayed through its predicate, which must still read what the
/// row recorded, and the umbrella is reduced over the published verdict and the recorded
/// facts on x86_64. A marking `on` beside the header is `absent` under OpenBSD's C library
/// and `not-established` under another, and `marked` with the header cleared; a marking
/// already `partial`, as OpenBSD 7.9's clang writes it, is `absent` with the header or
/// without it, and names the header only when it is there. The arm64 row's slot is
/// inapplicable, header or not, since the umbrella names no aarch64 control-flow flag.
#[test]
fn the_recorded_nobtcfi_artifacts_read_the_fhardened_cet_slot() {
    use chard::composite::ConstituentState as S;
    use chard::report::Verdict;

    let fixtures = load();
    let libc = replay_libc;
    let slot = |c: &chard::composite::Composite| {
        c.constituents
            .iter()
            .find(|k| k.check == "cet-marked")
            .cloned()
            .expect("the umbrella carries its CET slot")
    };
    let mut marked_on = 0;
    let mut marked_short = 0;
    let mut inapplicable = 0;
    for row in nobtcfi_rows(&fixtures) {
        let what = format!("{} {} {}", row.check, row.toolchain, row.profile);
        let replay = row
            .replay()
            .unwrap_or_else(|| panic!("{what}: does not replay"));
        assert!(
            replay.agrees(),
            "{what}: the predicate no longer reads the row"
        );
        if row.arm.is_some() {
            continue;
        }
        let arch = row
            .arch
            .as_deref()
            .expect("a mined row names its architecture");
        let elf = row.elf.clone().expect("filtered on its elf block");
        let verdict = match row.archived_verdict.as_deref() {
            Some("on") => Verdict::On,
            Some("partial") => Verdict::Partial,
            other => panic!("{what}: a marking row published {other:?}"),
        };
        let (observation, key) = marking_observation(row, verdict);
        let obs = [observation];
        let umbrella = |under: &str, elf: chard::elf::ElfFacts| {
            chard::composite::fhardened(
                &obs,
                arch,
                &refused_fhardened(),
                &libc(under),
                None,
                &store_of(&key, elf),
            )
        };
        let mut cleared = elf.clone();
        cleared.openbsd_nobtcfi = false;

        if row.check == "branch-protection-marked" {
            let k = slot(&umbrella("openbsd", elf));
            assert_eq!(
                (k.state, k.opt_out.is_some()),
                (S::NotApplicable, false),
                "{what}"
            );
            inapplicable += 1;
            continue;
        }
        assert_eq!(
            row.check, "cet-marked",
            "{what}: an unexpected marking check"
        );
        let on = verdict == Verdict::On;
        for (under, state) in [
            ("openbsd", S::Absent),
            ("glibc", if on { S::NotEstablished } else { S::Absent }),
        ] {
            let c = umbrella(under, elf.clone());
            let k = slot(&c);
            assert_eq!(k.state, state, "{what} under {under}: {:?}", k.note);
            assert_eq!(
                k.opt_out.as_ref().map(|o| (o.header, o.facts.as_str())),
                Some((chard::composite::PT_OPENBSD_NOBTCFI, key.as_str())),
                "{what} under {under}"
            );
        }
        let k = slot(&umbrella("openbsd", cleared));
        assert_eq!(
            (k.state, k.opt_out.is_some()),
            (if on { S::Marked } else { S::Absent }, false),
            "{what} with the header cleared"
        );
        if on {
            marked_on += 1;
        } else {
            marked_short += 1;
        }
    }
    assert!(
        marked_on > 0 && marked_short > 0 && inapplicable > 0,
        "the recorded artifacts no longer cover a CET marking on ({marked_on}), one short \
         ({marked_short}) and an aarch64 marking ({inapplicable}) beside the header"
    );
}

/// The recorded forged CET marking re-decides `probe-invalid` from its own rows.
///
/// A `cet-marked` regime arm reading `present` is a marking the profile forced: the profile
/// followed by `-fcf-protection=none` still carries the property bits. The rows were mined
/// 2026-10-05 from explicit `-O2 -fcf-protection=none -Wl,-z,ibt -Wl,-z,shstk` under gcc
/// 16.1.1 and clang 22.1.8 on Fedora 44 x86_64, where GNU ld 2.46.1 forced both bits over
/// code with no `endbr64` (`tests/fixtures/README.md`). For each, the measured build and its
/// three arms are replayed through the predicate, which must still read each row as
/// recorded, and the triple is decided again as `measure` decides it: the regime arm goes in
/// where `Check::owes_regime_control` says a profile that adds flags owes it, which a regime
/// row's existence shows this profile did. The plain arms discriminate, so the regime arm is
/// what withholds, and the verdict is the one the report published.
///
/// `tests/elf_fixtures.rs` holds the same reading over a synthetic artifact; this holds it
/// over what two real linkers wrote, on any host.
#[test]
fn the_recorded_forged_cet_marking_withholds_on_its_regime_arm() {
    use chard::probe::Outcome;
    use chard::report::{Discrimination, Verdict, WithheldBecause};

    let fixtures = load();
    let check = check_of("cet-marked").expect("cet-marked is in the corpus");
    let detection = |row: &Fixture| replayed_detection(check, row);

    let forged: Vec<&Fixture> = fixtures
        .iter()
        .filter(|f| {
            f.check == check.id && f.arm.as_deref() == Some("regime") && f.expected == "present"
        })
        .collect();
    let mut decided: BTreeSet<String> = BTreeSet::new();
    for regime in &forged {
        let what = format!("{} {}", regime.toolchain, regime.profile);
        let sibling = |arm: Option<&str>| {
            let rows: Vec<&Fixture> = fixtures
                .iter()
                .filter(|f| {
                    f.check == check.id
                        && f.toolchain == regime.toolchain
                        && f.arch == regime.arch
                        && f.profile == regime.profile
                        && f.arm.as_deref() == arm
                })
                .collect();
            let [row] = rows.as_slice() else {
                panic!("{what}: {} rows for arm {arm:?}", rows.len());
            };
            *row
        };
        let (measured, positive, negative) = (
            sibling(None),
            sibling(Some("positive")),
            sibling(Some("negative")),
        );
        let bare = detection(measured);
        let (pos, neg, reg) = (detection(positive), detection(negative), detection(regime));
        assert_eq!(
            (pos.outcome, neg.outcome, reg.outcome),
            (Outcome::Present, Outcome::Absent, Outcome::Present),
            "{what}: the plain arms discriminate and the regime arm shows the marking"
        );
        let (verdict, controls) = chard::report::decide(
            &bare,
            recorded_arm(&pos, positive),
            recorded_arm(&neg, negative),
            check
                .owes_regime_control(false)
                .then(|| recorded_arm(&reg, regime)),
            check.levels.grade(),
        );
        assert_eq!(
            (verdict, controls.discrimination),
            (
                Verdict::ProbeInvalid,
                Discrimination::Withheld(WithheldBecause::RegimeConfounded)
            ),
            "{what}: the forged marking is credited to the flag"
        );
        assert_eq!(
            measured.archived_verdict.as_deref(),
            Some(verdict.as_str()),
            "{what}: the report published another verdict"
        );
        decided.insert(
            regime
                .toolchain
                .split('-')
                .next()
                .unwrap_or_default()
                .to_owned(),
        );
    }
    eprintln!(
        "{} forged cet-marked triple(s) re-decided, compilers {decided:?}",
        forged.len()
    );
    assert_eq!(
        decided,
        BTreeSet::from(["clang".to_owned(), "gcc".to_owned()]),
        "the corpus no longer holds a forged marking from both compilers"
    );
}

/// A recorded row's detection through its check's decoder, after asserting the replay still
/// reads the row as recorded.
fn replayed_detection(check: &chard::probe::Check, row: &Fixture) -> chard::probe::Detection {
    let what = format!("{} {} {:?}", row.toolchain, row.profile, row.arm);
    let replay = row
        .replay()
        .unwrap_or_else(|| panic!("{what}: does not replay"));
    assert!(
        replay.agrees(),
        "{what}: the predicate no longer reads the row as recorded"
    );
    check
        .decode(&chard::probe::Evidence {
            macros: &row.macros,
            elf: row.elf.as_ref(),
            build: row.build.as_ref(),
            run: row.run.as_ref(),
            workdir: None,
        })
        .detection
}

/// A recorded arm as `decide` takes it, with the argv its row's build recorded.
fn recorded_arm<'a>(
    detection: &'a chard::probe::Detection,
    row: &Fixture,
) -> chard::report::ArmInput<'a> {
    chard::report::ArmInput {
        detection: Some(detection),
        flags: row
            .build
            .as_ref()
            .map(|b| b.argv.clone())
            .unwrap_or_default(),
    }
}

/// A driver that refuses `-fhardened`, as clang does, so the umbrella's fortify bar is read
/// from the library alone.
fn refused_fhardened() -> chard::toolchain::FhardenedFortify {
    chard::toolchain::FhardenedFortify {
        flags: Vec::new(),
        exit_status: 1,
        stdout_unterminated: false,
        macros_defined: 0,
        diagnostic: None,
        fortify_source: None,
        baseline: chard::toolchain::FortifyBaseline {
            flags: Vec::new(),
            exit_status: 0,
            stdout_unterminated: false,
            macros_defined: 0,
            fortify_source: None,
        },
    }
}

/// DESIGN.md's "Containers vs VMs" names the checks that declare `needs_vm`, by count and by
/// id, and the corpus is what decides both: a sentence held by nothing but its prose can say
/// no check declares it while one does.
#[test]
fn design_names_every_check_that_declares_needs_vm() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("DESIGN.md")).expect("reading DESIGN.md");
    let declaring: BTreeSet<&str> = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .filter(|c| c.gate.needs_vm)
        .map(|c| c.id)
        .collect();
    assert!(
        !declaring.is_empty(),
        "no check declares needs_vm: the scan read nothing"
    );
    let marker = " checks declare `needs_vm`: ";
    let Some(at) = text.find(marker) else {
        panic!("DESIGN.md has no sentence naming the checks that declare needs_vm");
    };
    let line_start = text[..at].rfind('\n').map_or(0, |i| i.saturating_add(1));
    let count_word = text[line_start..at]
        .trim_start_matches(['-', ' '])
        .to_ascii_lowercase();
    let words = ["no", "one", "two", "three", "four", "five", "six"];
    let stated = words.iter().position(|w| *w == count_word);
    assert_eq!(
        stated,
        Some(declaring.len()),
        "DESIGN.md says {count_word:?} checks declare needs_vm; the corpus has {declaring:?}"
    );
    let rest = &text[at.saturating_add(marker.len())..];
    let sentence = &rest[..rest.find('.').expect("the sentence ends")];
    let named: BTreeSet<&str> = sentence.split('`').skip(1).step_by(2).collect();
    assert_eq!(
        named, declaring,
        "DESIGN.md names other checks than the corpus declares"
    );
}

/// How many recorded rows come from the FreeBSD guests with their libc named: the 25 of the
/// FreeBSD guest reports `tests/fixtures/README.md` names. The `pie` row recorded without its
/// libc identified carries `unknown` in its id and is not among them.
const FREEBSD_ROWS: usize = 25;

/// What a recorded FreeBSD row reads, by its check, release and build: the verdict word and
/// the level. On 15.1 the known-object kills under `openssf-tldr` are credited (the measured
/// build and the positive arm died by SIGABRT; the negative arm survived), the settled
/// `__SSP_FORTIFY_LEVEL=2` reads present at 2 beside optimization and is withheld without it,
/// and the rungs FreeBSD's wrappers do not implement survive; on 14.5, whose headers carry no
/// `<ssp/ssp.h>`, everything but the request is absent.
fn freebsd_reading(row: &Fixture) -> (&'static str, Option<&'static str>) {
    let release_15 = row.toolchain.contains("-freebsd15-");
    let optimized = row.profile == "openssf-tldr";
    let died = row
        .run
        .as_ref()
        .is_some_and(|r| r.signal.as_deref() == Some("SIGABRT"));
    let requested = row
        .elf
        .as_ref()
        .is_some_and(|e| e.self_report.contains("_FORTIFY_SOURCE=3"));
    match (row.check.as_str(), release_15, optimized) {
        ("fortify-requested", _, true) => ("present", Some("3")),
        ("fortify-requested", _, false) | ("fortify-effective", true, false) => {
            ("indeterminate", None)
        }
        ("fortify-enforced-known", true, true) if died => ("present", None),
        ("fortify-effective", true, true) if requested => ("present", Some("2")),
        ("fortify-printf-flag", true, _) => ("present", Some("1")),
        _ => ("absent", None),
    }
}

/// The recorded FreeBSD runs read as [`freebsd_reading`] says, pinned beside the count, and
/// a credited kill names `__chk_fail`'s channel and the checking call in its reason.
#[test]
fn the_recorded_freebsd_runs_read_as_their_implementation_says() {
    let fixtures = load();
    let rows: Vec<&Fixture> = fixtures
        .iter()
        .filter(|f| f.toolchain.contains("-freebsd15-") || f.toolchain.contains("-freebsd14-"))
        .collect();
    assert_eq!(
        rows.len(),
        FREEBSD_ROWS,
        "the corpus's rows with FreeBSD's libc named changed in number"
    );
    let mut seen = BTreeMap::new();
    for row in rows {
        let what = format!("{} {} {}", row.check, row.toolchain, row.profile);
        let replay = row
            .replay()
            .unwrap_or_else(|| panic!("{what}: does not replay"));
        assert!(replay.agrees(), "{what}: {replay:?}");
        let (verdict, level) = freebsd_reading(row);
        assert_eq!(
            (replay.got.as_str(), replay.got_level.as_deref()),
            (verdict, level),
            "{what}"
        );
        if row.check == "fortify-enforced-known" && verdict == "present" {
            let stderr = row.run.as_ref().map_or("", |r| r.stderr.as_str());
            assert!(
                stderr.is_empty(),
                "{what}: FreeBSD's abort says nothing in band"
            );
            let observed = chard::probe::CORPUS
                .iter()
                .flat_map(|p| p.checks)
                .find(|c| c.id == row.check)
                .expect("the check")
                .decode(&chard::probe::Evidence {
                    macros: &row.macros,
                    elf: row.elf.as_ref(),
                    build: row.build.as_ref(),
                    run: row.run.as_ref(),
                    workdir: None,
                })
                .detection
                .observed;
            // The credit names the three witnesses chard read, not FreeBSD's log line.
            assert!(
                observed.contains("SIGABRT with nothing on stderr")
                    && observed.contains("no survival marker on stdout")
                    && observed.contains("__memcpy_chk")
                    && !observed.contains("syslog"),
                "{what}: {observed}"
            );
        }
        let release = if row.toolchain.contains("-freebsd15-") {
            "15.1"
        } else {
            "14.5"
        };
        *seen.entry((row.check.clone(), release)).or_insert(0usize) += 1;
    }
    assert_eq!(seen.len(), 13, "check and release pairs: {seen:?}");
    // 15.1's `fortify-enforced-known` and `fortify-effective` hold four each: the measured
    // build and both arms under `openssf-tldr`, and the unoptimized explicit build.
    assert_eq!(
        seen.values().filter(|n| **n == 4).count(),
        2,
        "two groups hold both arms and the unoptimized build: {seen:?}"
    );
}
