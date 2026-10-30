// SPDX-License-Identifier: BSD-3-Clause

//! A sweep cell leaves no core file behind, and the gate that says so can see one.
//!
//! Several probes abort by design, and chard cannot lower `RLIMIT_CORE` for its children;
//! `run::execute` gives the reason. `make sweep` owns the limit instead: its recipe's first
//! statement is `ulimit -c 0`, and `scripts/sweep-gate.sh` is handed the limit that shell
//! reads back and each cell's workdir, fails a limit other than 0 and a core file under the
//! workdir, and prints `core_pattern`. This file holds both halves to what they claim.
//!
//! The gate's search is a detector, and a detector is trusted only once it has
//! discriminated. [`the_gate_fails_a_nonzero_limit_and_finds_a_core_by_its_content`] feeds
//! it planted files, which runs on every host. [`a_cell_under_the_recipe_limit_leaves_no_core`]
//! drives the built binary the way the recipe does, twice where the host allows it: under
//! `ulimit -c 0`, where the gate must find no core, and under `ulimit -c unlimited`, where it
//! must find at least one off Linux. On Linux the probe is non-dumpable, so there the
//! second arm must find none, and the gate's discrimination rests on the planted files.
//! The second arm needs a relative `core_pattern`, the only kind that writes a core into
//! the probe's working directory.
//! Under a pipe (Fedora 44 hands every crash to systemd-coredump), an absolute path (Darwin
//! writes to `/cores`) or a pattern the host does not expose, the kernel puts the core where
//! no search of the workdir can reach, so an empty search there is not evidence. The arm is
//! announced through `tests/common`'s capability gap rather than passed, and the forced-off
//! arm's clean line is then a statement about the workdir alone.
//!
//! The limit does not reach a handler: a `core_pattern` that pipes to one (systemd-coredump
//! on Fedora) ignores it and starts the handler for every crash, whose time lands in the
//! run's `duration_ms`. So the probes that crash in their own process make themselves
//! non-dumpable (`CHARD_NOT_DUMPABLE` in `probes/chard_selfreport.h`), and the tests at the
//! end of this file hold the list of them, [`NON_DUMPABLE`], to the sources, to the recorded
//! runs that crashed and to this host's own runs.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod common;

const GATE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/sweep-gate.sh");

/// A probe whose positive control dies on a signal: SIGABRT from glibc's fortify wrapper,
/// SIGTRAP from Apple's. `bare` still builds and runs the control arms, so one probe under
/// one profile is enough to put a crash in the workdir. On Linux the probe is
/// non-dumpable, so its crash writes no core there whatever the limit.
const ABORTING_PROBE: &str = "fortify-known-object";

fn chard_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chard"))
}

/// Is there a `bash` to run the gate with?
fn require_bash(verifies: &str) -> bool {
    if Command::new("bash").arg("-c").arg(":").output().is_err() {
        common::refuse("no bash on PATH to run scripts/sweep-gate.sh", verifies);
        return false;
    }
    true
}

/// The gate's stdout for one report and workdir, with its exit status.
///
/// The expectation directory is the report's own, which holds no expectation file, so a
/// report that withholds nothing is the only kind that passes.
fn gate(limit: &str, workdir: &Path, report: &Path) -> (String, Option<i32>) {
    let output = Command::new("bash")
        .arg(GATE)
        .arg("--expected")
        .arg(report.parent().expect("a report path has a parent"))
        .arg("--core-limit")
        .arg(limit)
        .arg("--workdir")
        .arg(workdir)
        .arg(report)
        .arg(chard::probe::total_checks().to_string())
        .arg("0")
        .output()
        .expect("spawning bash for scripts/sweep-gate.sh");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.code(),
    )
}

/// The first 18 bytes of an ELF file of this `e_type`: little-endian when `little`.
fn elf_header(e_type: u16, little: bool) -> Vec<u8> {
    let mut bytes = vec![0x7f, b'E', b'L', b'F', 2, if little { 1 } else { 2 }, 1];
    bytes.resize(16, 0);
    if little {
        bytes.extend_from_slice(&e_type.to_le_bytes());
    } else {
        bytes.extend_from_slice(&e_type.to_be_bytes());
    }
    bytes
}

fn assert_line(output: &str, line: &str) {
    assert!(
        output.lines().any(|l| l.starts_with(line)),
        "the gate printed no line starting {line:?}; it printed:\n{output}"
    );
}

/// A report that passes every section after the core section: one check, attempted and
/// published, and a measurement exit status of 0 that agrees with it. With it in place the
/// gate's exit status is decided by the core section alone.
fn passing_report(corpus_total: usize) -> String {
    serde_json::json!({
        "toolchain": { "id": "planted" },
        "profile": { "id": "planted" },
        "coverage": {
            "checks_attempted": corpus_total,
            "corpus_checks_total": corpus_total,
            "checks_valid": corpus_total,
            "checks_not_applicable_here": 0,
            "verdict_counts": { "on": corpus_total },
            "withholding": {
                "published": corpus_total,
                "earned_limitations": { "count": 0, "no_named_cause": 0 },
                "instrument_withholdings": { "count": 0, "no_named_cause": 0 }
            },
            "all_checks_attempted": true,
            "all_verdicts_published": true
        },
        "observations": [ { "check": "planted", "verdict": "on" } ]
    })
    .to_string()
}

/// Is there a `jq` for the gate's report sections?
fn have_jq() -> bool {
    Command::new("jq")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The gate's core section on planted files: the limit is read, a core is known by its
/// ELF `e_type` whatever its name and byte order, other ELF files are not cores, and a
/// search over nothing fails rather than passing.
///
/// The gate is handed a report that passes every later section, so each exit status below
/// is the core section's: 0 for the clean run under limit 0, 1 for the same workdir under
/// an unlimited limit, and 1 once a core is planted. The printed lines need `bash`, `od`
/// and `find`; the exit statuses need `jq` too, because the gate reads the report with
/// it, and without `jq` that arm is announced as a gap.
#[test]
fn the_gate_fails_a_nonzero_limit_and_finds_a_core_by_its_content() {
    if !require_bash("that the sweep gate fails a nonzero core limit and finds a core file") {
        return;
    }
    let work = common::Work::new("core-files", "planted");
    let report = work.write(
        "planted.json",
        &passing_report(chard::probe::total_checks()),
    );
    let statuses = have_jq();
    if !statuses {
        common::capability_gap(
            "the sweep gate's exit status on planted cores",
            "no jq on PATH, so the gate exits 2 at the report and only its printed lines are held",
        );
    }
    let dir = work.path("cell");
    std::fs::create_dir_all(dir.join("probe")).expect("creating the planted workdir");
    std::fs::write(dir.join("probe/plain.stdout"), "text\n").expect("planting");
    std::fs::write(dir.join("probe/a-shared-object"), elf_header(3, true)).expect("planting");
    std::fs::write(dir.join("probe/an-executable"), elf_header(2, false)).expect("planting");

    let (clean, clean_status) = gate("0", &dir, &report);
    assert_line(&clean, "ok    planted: core limit 0");
    assert_line(&clean, "ok    planted: no core file among 3 file(s)");
    assert!(
        clean.contains("core_pattern ("),
        "the gate printed no core_pattern:\n{clean}"
    );
    assert!(
        !clean.contains("FAIL  planted"),
        "the clean run failed a section:\n{clean}"
    );
    if statuses {
        assert_eq!(
            clean_status,
            Some(0),
            "limit 0 and no core passes the cell:\n{clean}"
        );
    }

    let (unlimited, status) = gate("unlimited", &dir, &report);
    assert_line(&unlimited, "FAIL  planted: the core limit is unlimited");
    if statuses {
        assert_eq!(
            status,
            Some(1),
            "a nonzero limit fails the cell:\n{unlimited}"
        );
    }

    std::fs::write(dir.join("probe/named-anything"), elf_header(4, true)).expect("planting");
    std::fs::write(dir.join("probe/big-endian"), elf_header(4, false)).expect("planting");
    let (cored, cored_status) = gate("0", &dir, &report);
    assert_line(&cored, "FAIL  planted: 2 core file(s) among 5 file(s)");
    if statuses {
        assert_eq!(
            cored_status,
            Some(1),
            "a core under the workdir fails the cell:\n{cored}"
        );
    }
    for name in ["named-anything", "big-endian"] {
        assert!(
            cored.contains(&format!("probe/{name}\n")),
            "the gate did not name the core {name}:\n{cored}"
        );
    }

    let empty = work.path("empty");
    std::fs::create_dir_all(&empty).expect("creating an empty workdir");
    let (nothing, _) = gate("0", &empty, &report);
    assert_line(&nothing, "FAIL  planted: the workdir");
    assert!(
        nothing.contains("a search over nothing finds nothing"),
        "{nothing}"
    );

    let (absent, _) = gate("0", &work.path("never-made"), &report);
    assert_line(&absent, "FAIL  planted: no workdir at");

    let unlabelled = Command::new("bash")
        .arg(GATE)
        .arg(&report)
        .arg("1")
        .arg("0")
        .output()
        .expect("spawning bash for scripts/sweep-gate.sh");
    assert_eq!(
        unlabelled.status.code(),
        Some(2),
        "the gate ran without being told the core limit or the workdir"
    );
}

/// How many run records in the report ended on a signal.
fn signalled_runs(value: &Value) -> usize {
    match value {
        Value::Object(map) => {
            let own = usize::from(
                map.contains_key("exit_status") && map.get("signal").is_some_and(|s| !s.is_null()),
            );
            own + map.values().map(signalled_runs).sum::<usize>()
        }
        Value::Array(items) => items.iter().map(signalled_runs).sum(),
        _ => 0,
    }
}

/// One cell the way the recipe runs it: the limit set first in one shell, chard measuring
/// under it, and the gate handed the limit that shell reads back. Returns the gate's
/// stdout and the report, or `None` when the shell could not set the limit.
fn cell(limit: &str, work: &common::Work, tag: &str) -> Option<(String, Value)> {
    let workdir = work.path(&format!("work-{tag}"));
    let report = work.path(&format!("{tag}.json"));
    let script = format!(
        "ulimit -c {limit} || exit 97\n\
         \"$0\" measure --profile bare --probe {ABORTING_PROBE} --workdir \"$1\" --output \"$2\"\n\
         rc=$?\n\
         exec bash \"$3\" --core-limit \"$(ulimit -c)\" --workdir \"$1\" \"$2\" {total} \"$rc\"",
        total = chard::probe::total_checks(),
    );
    let output = Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(chard_binary())
        .arg(&workdir)
        .arg(&report)
        .arg(GATE)
        .output()
        .expect("spawning sh for one sweep cell");
    if output.status.code() == Some(97) {
        return None;
    }
    let text = std::fs::read_to_string(&report).unwrap_or_else(|e| {
        panic!(
            "no report under `ulimit -c {limit}` ({e}); stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let parsed = serde_json::from_str(&text).expect("the report is JSON");
    Some((String::from_utf8_lossy(&output.stdout).into_owned(), parsed))
}

/// Where this host's kernel puts a core, if a search of the probe's working directory can
/// see it; otherwise why not.
fn core_pattern_is_relative() -> Result<String, String> {
    let Ok(pattern) = std::fs::read_to_string("/proc/sys/kernel/core_pattern") else {
        return Err("this host exposes no /proc/sys/kernel/core_pattern".into());
    };
    let pattern = pattern.trim_end().to_owned();
    if pattern.starts_with('|') {
        Err(format!(
            "core_pattern is a pipe ({pattern}); the kernel hands each crash to that program, \
             so no core reaches the workdir whatever the limit"
        ))
    } else if pattern.starts_with('/') {
        Err(format!(
            "core_pattern is an absolute path ({pattern}), outside the workdir"
        ))
    } else {
        Ok(pattern)
    }
}

/// The gate's two lists sort by the verdict word, and the report's `coverage.withholding`
/// by the verdict and the gating rule beside it; a limitation verdict no rule earns is in
/// the report's instrument set and on the gate's earned list, and the cell fails naming it,
/// where the same report with its rule passes that section.
#[test]
fn the_gate_holds_its_lists_to_the_reports_withholding_sets() {
    let verifies = "that the sweep gate holds its earned and withheld lists to the report";
    if !require_bash(verifies) {
        return;
    }
    if !have_jq() {
        common::capability_gap(verifies, "no jq on PATH, so the gate exits 2 at the report");
        return;
    }
    let total = chard::probe::total_checks();
    let work = common::Work::new("core-files", "withholding-sets");
    let dir = work.path("cell");
    std::fs::create_dir_all(dir.join("probe")).expect("creating the workdir");
    std::fs::write(dir.join("probe/plain.stdout"), "text\n").expect("planting");
    let with = |gating: Value, earned: usize| {
        let mut r: Value = serde_json::from_str(&passing_report(total)).expect("json");
        r["observations"]
            .as_array_mut()
            .expect("observations")
            .push(
                serde_json::json!({"check": "lacking", "verdict": "unsupported",
                                     "gating": gating}),
            );
        let set = |count: usize| {
            serde_json::json!({"count": count, "by_verdict": {"unsupported": count},
                               "no_named_cause": count})
        };
        let mut earned_set = set(earned);
        if earned == 1 {
            earned_set["by_rule"] = serde_json::json!({"arch-gated": 1});
            earned_set["no_named_cause"] = 0.into();
        }
        r["coverage"]["withholding"]["earned_limitations"] = earned_set;
        r["coverage"]["withholding"]["instrument_withholdings"] = set(1 - earned);
        r
    };
    let unearned = work.write("unearned.json", &with(Value::Null, 0).to_string());
    let (out, status) = gate("0", &dir, &unearned);
    assert_line(
        &out,
        "FAIL  unearned: this gate lists 1 earned and 0 withheld by verdict word, and \
         coverage.withholding counts 0 and 1",
    );
    assert!(
        out.contains("lacking: unsupported under no gating rule"),
        "{out}"
    );
    assert_eq!(status, Some(1), "{out}");

    // A rule whose premise publishes `indeterminate`: the report counts the member as the
    // instrument's, and the gate names it under that rule.
    let misfiled = work.write(
        "misfiled.json",
        &with(serde_json::json!({"rule": "cpu-lacks-shadow-stack"}), 0).to_string(),
    );
    let (out, status) = gate("0", &dir, &misfiled);
    assert!(
        out.contains("lacking: unsupported under cpu-lacks-shadow-stack"),
        "{out}"
    );
    assert_eq!(status, Some(1), "{out}");

    let earned = work.write(
        "earned.json",
        &with(serde_json::json!({"rule": "arch-gated"}), 1).to_string(),
    );
    let (out, _) = gate("0", &dir, &earned);
    assert!(
        !out.contains("by verdict word"),
        "the lists agree with the sets:\n{out}"
    );
}

/// The built binary under the recipe's limit leaves no core the gate can find. Where the
/// host writes cores into the working directory, the same cell under an unlimited limit
/// leaves one the gate does find, except on Linux, where the crashing probe is
/// non-dumpable and must leave none.
#[test]
fn a_cell_under_the_recipe_limit_leaves_no_core() {
    let verifies = "that a sweep cell under `ulimit -c 0` leaves no core file in its workdir";
    if !(common::require_binary(&chard_binary(), verifies)
        && common::require_cc(verifies)
        && require_bash(verifies))
    {
        return;
    }
    let work = common::Work::new("core-files", "cell");
    let mut exercised = 0_usize;

    let (off, report) =
        cell("0", &work, "off").expect("`ulimit -c 0` lowers a limit, which never fails");
    eprint!("{off}");
    let signalled = signalled_runs(&report);
    eprintln!("cores: {signalled} probe run(s) under `ulimit -c 0` ended on a signal");
    assert_line(&off, "ok    off: core limit 0");
    assert_line(&off, "ok    off: no core file among");
    if signalled == 0 {
        common::capability_gap(
            "a crash under `ulimit -c 0`",
            &format!(
                "no run of {ABORTING_PROBE} ended on a signal on this toolchain, so the \
                 empty workdir says nothing about cores"
            ),
        );
    } else {
        exercised += 1;
    }

    match core_pattern_is_relative() {
        Err(why) => common::capability_gap("a core written into the workdir", &why),
        Ok(pattern) => {
            let Some((on, report)) = cell("unlimited", &work, "on") else {
                common::capability_gap(
                    "a core written into the workdir",
                    "the hard core limit is below unlimited, so the forced-on arm cannot run",
                );
                return;
            };
            eprint!("{on}");
            assert!(
                signalled_runs(&report) > 0,
                "no probe run ended on a signal under `ulimit -c unlimited`, so the \
                 forced-on arm fed the gate nothing"
            );
            assert_line(&on, "FAIL  on: the core limit is unlimited");
            if cfg!(target_os = "linux") {
                // The probe made itself non-dumpable, so even an unlimited limit and a
                // pattern into the workdir leave no core: the non-dumpable property, live. The
                // gate's search is held to a core by the planted files above instead.
                assert_line(&on, "ok    on: no core file among");
            } else {
                assert!(
                    on.lines()
                        .any(|l| l.starts_with("FAIL  on: ") && l.contains(" core file(s) among ")),
                    "core_pattern {pattern:?} writes into the probe's working directory and \
                     the gate found no core after a crash under an unlimited limit: its \
                     search cannot discriminate, so its clean line under `ulimit -c 0` is \
                     not evidence:\n{on}"
                );
            }
            exercised += 1;
        }
    }
    eprintln!("cores: {exercised} of 2 arm(s) exercised");
}

// --- the probes that crash in their own process leave no core ---------------

/// The probes whose own process dies by a signal in some arm, each of which makes itself
/// non-dumpable at the top of `main` through `CHARD_NOT_DUMPABLE` in `chard_selfreport.h`.
///
/// `ulimit -c 0` above keeps a core out of the workdir, and a `core_pattern` that pipes to a
/// handler ignores it: the kernel starts the handler for every crash, and its time lands in
/// the run's `duration_ms`.
///
/// Not here, each for its reason:
/// - `strict_flex_arrays_enforced.c`: its crashes are forked rows, no run of it ends on a
///   signal, and it makes its own call before the first fork, which
///   `src/decode/runtime_tests.rs` pins.
/// - `stack_clash.c`, `stack_exec_runtime.c` and `shadow_stack.c`: each catches its fault in
///   a handler that ends in `_exit(0)`, so its process does not die by the signal (and
///   `shadow_stack.c` re-executes itself, which makes it dumpable again).
/// - the fault reporter in `chard_selfreport.h` (`CHARD_WANT_FAULT_REPORT`): no probe uses
///   it; `tests/fault_classes.c` does, and the test that builds it is not a probe run.
///
/// A probe among these that died by its signal on some toolchain would fail the two tests
/// below that read crash runs, naming it.
const NON_DUMPABLE: &[&str] = &[
    "cxx_assertions.cpp",
    "fortify_dynamic_object.c",
    "fortify_known_object.c",
    "fortify_percent_n.c",
    "fortify_subobject.c",
    "trapv.c",
    "ub_null_check.c",
];

/// What `main` may hold before `CHARD_NOT_DUMPABLE`, comments and blank lines aside: the
/// self-report (which must be the first statement where a probe prints one), a
/// declaration with no call in it, and the cxx probe's unbuffering of stdout, which must
/// precede any output on the stream, the note included. Anything else, a crash above all,
/// fails the source pin.
const BEFORE_THE_CALL: &[&str] = &[
    "{",
    "CHARD_PRINT_REPORT;",
    "int written = 0;",
    "int *p = opaque;",
    "std::setvbuf(stdout, nullptr, _IONBF, 0);",
    "std::setvbuf(stdout, NULL, _IONBF, 0);",
];

/// `source` with each `/* ... */` comment cut out and each `//` comment cut to the end of its
/// line, so a call or a define written in a comment is not read as code. Line breaks inside
/// a block comment are kept, so lines stay lines.
fn without_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while !rest.is_empty() {
        let block = rest.find("/*");
        let line = rest.find("//");
        match (block, line) {
            (Some(b), l) if l.is_none_or(|l| b < l) => {
                out.push_str(&rest[..b]);
                let end = rest[b..].find("*/").map_or(rest.len(), |e| b + e + 2);
                out.extend(rest[b..end].chars().filter(|c| *c == '\n'));
                rest = &rest[end..];
            }
            (_, Some(l)) => {
                out.push_str(&rest[..l]);
                rest = &rest[l..];
                rest = &rest[rest.find('\n').unwrap_or(rest.len())..];
            }
            _ => {
                out.push_str(rest);
                rest = "";
            }
        }
    }
    out
}

/// Signals whose default action writes a core, by signal(7)'s table, as the run record
/// spells them.
const DUMPING_SIGNALS: &[&str] = &[
    "SIGABRT", "SIGBUS", "SIGFPE", "SIGILL", "SIGQUIT", "SIGSEGV", "SIGSYS", "SIGTRAP", "SIGXCPU",
    "SIGXFSZ",
];

/// Signals whose default action writes none. A signal in neither list fails the tests
/// below, so an unfamiliar spelling is read before it is sorted.
const NON_DUMPING_SIGNALS: &[&str] = &["SIGKILL", "SIGTERM", "SIGINT", "SIGHUP", "SIGPIPE"];

/// Does a run that ended on `signal` leave a core where the process is dumpable?
fn dumps(signal: &str) -> bool {
    assert!(
        DUMPING_SIGNALS.contains(&signal) || NON_DUMPING_SIGNALS.contains(&signal),
        "{signal} is in neither signal list, so whether it leaves a core is unread"
    );
    DUMPING_SIGNALS.contains(&signal)
}

/// The probe source a check is measured through.
fn source_of_check(check: &str) -> Option<&'static str> {
    chard::probe::CORPUS
        .iter()
        .find(|p| p.checks.iter().any(|c| c.id == check))
        .map(|p| p.source_name)
}

/// The note `CHARD_NOT_DUMPABLE` writes where the call fails, read back from the header
/// with a sample errno, so the replay below feeds the spelling the probes print.
fn dumpable_note() -> String {
    let header = include_str!("../probes/chard_selfreport.h");
    let start = header
        .find("\"chard-note dumpable-unset")
        .expect("the header spells the note");
    let quoted = &header[start + 1..];
    let end = quoted.find('"').expect("the note's closing quote");
    quoted[..end].replace("%d", "1").replace("\\n", "\n")
}

/// Each listed probe opts in before the header and calls `CHARD_NOT_DUMPABLE` in `main`,
/// after the self-report where it prints one; no other probe opts in; and the header's
/// Linux definition makes the call and writes its failure on stdout. Pinned on the source,
/// since no run on a host whose handler is fast can tell a call is gone.
#[test]
fn every_probe_that_crashes_in_its_own_process_is_non_dumpable_at_the_top_of_main() {
    let header = include_str!("../probes/chard_selfreport.h");
    let linux = header
        .split_once("#if defined(CHARD_WANT_NOT_DUMPABLE) && defined(__linux__)")
        .and_then(|(_, rest)| rest.split_once("#elif defined(CHARD_WANT_NOT_DUMPABLE)"))
        .map(|(linux, _)| linux)
        .expect("the header defines CHARD_NOT_DUMPABLE for Linux apart from elsewhere");
    assert!(
        linux.contains("prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0"),
        "{linux}"
    );
    assert!(
        linux.contains("fprintf(stdout, \"chard-note dumpable-unset"),
        "a failed call is said on stdout, since a detector reads an empty stderr:\n{linux}"
    );

    let mut fed = std::collections::BTreeSet::new();
    for probe in chard::probe::CORPUS {
        if probe.source.is_empty() || !fed.insert(probe.source_name) {
            continue;
        }
        let name = probe.source_name;
        let code = without_comments(probe.source);
        let wants = code
            .lines()
            .any(|l| l.trim() == "#define CHARD_WANT_NOT_DUMPABLE");
        assert_eq!(
            wants,
            NON_DUMPABLE.contains(&name),
            "{name}: opting in to CHARD_NOT_DUMPABLE and being on NON_DUMPABLE disagree"
        );
        if !wants {
            continue;
        }
        let define = code.find("\n#define CHARD_WANT_NOT_DUMPABLE\n");
        let include = code.find("\n#include \"chard_selfreport.h\"\n");
        assert!(
            define.is_some() && define < include,
            "{name}: the opt-in is not defined, on a line of its own, before the header"
        );
        let above = &code[..define.unwrap_or(0)];
        let opened = above
            .lines()
            .filter(|l| l.trim_start().starts_with("#if"))
            .count();
        let closed = above
            .lines()
            .filter(|l| l.trim_start().starts_with("#endif"))
            .count();
        assert_eq!(
            opened, closed,
            "{name}: the opt-in sits inside a conditional"
        );
        let main = code
            .split_once("\nint main(")
            .and_then(|(_, rest)| rest.split_once('\n'))
            .map_or_else(|| panic!("{name} has no main"), |(_, body)| body);
        let mut depth = 0_usize;
        let mut called = false;
        let mut reported = false;
        for line in main.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if line == "CHARD_NOT_DUMPABLE;" {
                assert_eq!(depth, 0, "{name}: the call sits inside a conditional");
                assert!(
                    reported || !main.contains("CHARD_PRINT_REPORT;"),
                    "{name}: the call precedes the self-report, which must be main's first \
                     statement"
                );
                called = true;
                break;
            }
            reported |= line == "CHARD_PRINT_REPORT;";
            if line.starts_with("#if") {
                depth += 1;
            } else if line.starts_with("#endif") {
                depth = depth.saturating_sub(1);
            } else if !line.starts_with("#else") {
                assert!(
                    BEFORE_THE_CALL.contains(&line),
                    "{name}: `{line}` comes before CHARD_NOT_DUMPABLE in main, and only the \
                     self-report, declarations and stdout's buffering may"
                );
            }
        }
        assert!(called, "{name}: main does not call CHARD_NOT_DUMPABLE");
    }
    eprintln!(
        "non-dumpable: {} of {} probe sources opt in",
        NON_DUMPABLE.len(),
        fed.len()
    );
    for name in NON_DUMPABLE {
        assert!(
            chard::probe::CORPUS.iter().any(|p| p.source_name == *name),
            "{name} is on NON_DUMPABLE and is no probe's source"
        );
    }
}

/// The recorded evidence, every toolchain the fixtures carry: a run that ended on a signal
/// that dumps came from a listed probe, and each listed probe has such a run, so the list
/// is the probes seen to crash and holds none on a guess. A hand-authored fixture (its
/// toolchain starts `synthetic:`) is no run of a probe and is left out, counted.
#[test]
fn the_non_dumpable_list_is_the_probes_whose_recorded_runs_crash() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/detectors.json");
    let text = std::fs::read_to_string(&path).expect("reading the fixture file");
    let fixtures: Vec<chard::fixture::Fixture> =
        serde_json::from_str(&text).expect("the fixture file is JSON");
    let mut crashed = std::collections::BTreeSet::new();
    let (mut signalled, mut hand_authored) = (0_usize, 0_usize);
    for f in &fixtures {
        let Some(signal) = f.run.as_ref().and_then(|r| r.signal.as_deref()) else {
            continue;
        };
        if f.toolchain.starts_with("synthetic:") {
            hand_authored += 1;
            continue;
        }
        if !dumps(signal) {
            continue;
        }
        signalled += 1;
        let source =
            source_of_check(&f.check).unwrap_or_else(|| panic!("{} is no corpus check", f.check));
        assert!(
            NON_DUMPABLE.contains(&source),
            "{} on {} ended on {signal} in its own process, and {source} is not on \
             NON_DUMPABLE: each such crash starts the host's core handler",
            f.check,
            f.toolchain
        );
        crashed.insert(source);
    }
    eprintln!(
        "non-dumpable: {} fixtures, {signalled} recorded runs ended on a dumping signal, \
         from {} probe sources; {hand_authored} hand-authored left out",
        fixtures.len(),
        crashed.len()
    );
    let listed: std::collections::BTreeSet<&str> = NON_DUMPABLE.iter().copied().collect();
    assert_eq!(
        crashed, listed,
        "NON_DUMPABLE names a probe no recorded run shows crashing"
    );
}

/// Where the call fails the probe prints `chard-note dumpable-unset errno=N` on stdout,
/// after the self-report where it prints one and first otherwise, and that line changes
/// no reading: every recorded run of a listed probe reads the same with it.
#[test]
fn a_failed_call_s_note_changes_no_reading() {
    let note = dumpable_note();
    assert!(
        note.starts_with("chard-note dumpable-unset errno=1\n"),
        "{note:?}"
    );
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/detectors.json");
    let text = std::fs::read_to_string(&path).expect("reading the fixture file");
    let fixtures: Vec<chard::fixture::Fixture> =
        serde_json::from_str(&text).expect("the fixture file is JSON");
    let mut fed = 0_usize;
    let mut sources = std::collections::BTreeSet::new();
    for f in &fixtures {
        let Some(source) = source_of_check(&f.check).filter(|s| NON_DUMPABLE.contains(s)) else {
            continue;
        };
        let Some(run) = f.run.as_ref() else {
            continue;
        };
        sources.insert(source);
        let end = "CHARD-REPORT-END\n";
        let stdout = match run.stdout.find(end) {
            Some(at) => format!(
                "{}{note}{}",
                &run.stdout[..at + end.len()],
                &run.stdout[at + end.len()..]
            ),
            None => format!("{note}{}", run.stdout),
        };
        let mut noted = f.clone();
        noted.run.as_mut().expect("the run").stdout = stdout;
        let (plain, with) = (
            f.replay().expect("a corpus check"),
            noted.replay().expect("a corpus check"),
        );
        assert_eq!(
            (plain.got.as_str(), plain.got_level.as_deref()),
            (with.got.as_str(), with.got_level.as_deref()),
            "{} on {}: the note moved the reading",
            f.check,
            f.toolchain
        );
        fed += 1;
    }
    eprintln!(
        "non-dumpable: the note fed to {fed} recorded runs of {} listed probe sources",
        sources.len()
    );
    let listed: std::collections::BTreeSet<&str> = NON_DUMPABLE.iter().copied().collect();
    assert_eq!(
        sources, listed,
        "the note reached no recorded run of some listed probe"
    );
}

/// One run record of a report: its check, its probe's source, the signal it ended on, and
/// whether its stdout carries the note a failed `CHARD_NOT_DUMPABLE` prints.
struct RunSeen {
    check: String,
    source: &'static str,
    signal: Option<String>,
    noted: bool,
}

/// Every run record of one report: the value of a `run` key, holding `exit_status` and
/// `stdout`, and `signal` only where the run ended on one. A `run` holding neither of the
/// first two fails rather than reading as a run that ended cleanly.
fn report_runs(report: &Value) -> Vec<RunSeen> {
    fn walk(value: &Value, out: &mut Vec<(Option<String>, bool)>) {
        match value {
            Value::Object(map) => {
                if let Some(run) = map.get("run").filter(|r| !r.is_null()) {
                    assert!(
                        run.get("exit_status").is_some(),
                        "a run record without `exit_status`: {run:?}"
                    );
                    let stdout = run
                        .get("stdout")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| panic!("a run record without `stdout`: {run:?}"));
                    out.push((
                        run.get("signal").and_then(Value::as_str).map(str::to_owned),
                        stdout.contains("chard-note dumpable-unset"),
                    ));
                }
                map.values().for_each(|v| walk(v, out));
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut runs = Vec::new();
    for observation in report["observations"].as_array().expect("observations") {
        let check = observation["check"].as_str().expect("a check id");
        let probe = observation["probe"].as_str().expect("a probe id");
        let source = chard::probe::find(probe)
            .unwrap_or_else(|| panic!("{probe} is no corpus probe"))
            .source_name;
        let mut seen = Vec::new();
        walk(observation, &mut seen);
        runs.extend(seen.into_iter().map(|(signal, noted)| RunSeen {
            check: check.to_owned(),
            source,
            signal,
            noted,
        }));
    }
    runs
}

/// This host's compiler, under `bare` and `openssf-tldr`: every run that ended on a signal
/// that dumps came from a listed probe, at least one did, and no run printed the note, so
/// on this host the call took effect. This is the arm that sees a new crashing probe before
/// any fixture records it.
#[test]
fn no_run_on_this_host_crashes_outside_the_non_dumpable_list() {
    let verifies = "that every probe crashing in its own process on this host is non-dumpable";
    if !(common::require_binary(&chard_binary(), verifies) && common::require_cc(verifies)) {
        return;
    }
    let work = common::Work::new("core-files", "non-dumpable");
    for profile in ["bare", "openssf-tldr"] {
        let report = work.path(&format!("{profile}.json"));
        let output = Command::new(chard_binary())
            .args(["measure", "--profile", profile, "--workdir"])
            .arg(work.path(&format!("work-{profile}")))
            .arg("--output")
            .arg(&report)
            .output()
            .expect("spawning chard measure");
        let text = std::fs::read_to_string(&report).unwrap_or_else(|e| {
            panic!(
                "no {profile} report ({e}); stderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        let report: Value = serde_json::from_str(&text).expect("the report is JSON");
        let fed = report["observations"].as_array().map_or(0, Vec::len);
        assert_eq!(
            fed,
            chard::probe::total_checks(),
            "{profile}: the report carries {fed} observations"
        );
        let runs = report_runs(&report);
        let signalled = runs.iter().filter(|r| r.signal.is_some()).count();
        let dumping = runs
            .iter()
            .filter(|r| r.signal.as_deref().is_some_and(dumps))
            .count();
        eprintln!(
            "non-dumpable: {profile}: {fed} observations, {} run records, {signalled} ended \
             on a signal, {dumping} on one that dumps",
            runs.len()
        );
        for run in &runs {
            if let Some(signal) = run.signal.as_deref().filter(|s| dumps(s)) {
                assert!(
                    NON_DUMPABLE.contains(&run.source),
                    "{profile}: {} ended on {signal} in its own process, and {} is not on \
                     NON_DUMPABLE",
                    run.check,
                    run.source
                );
            }
            assert!(
                !run.noted,
                "{profile}: {}: the probe could not make itself non-dumpable on this host",
                run.check
            );
        }
        assert!(
            dumping > 0,
            "{profile}: no run of {} records ended on a signal that dumps, so the list was \
             held to no crash: the fortify, trapv and cxx positive arms crash on every \
             toolchain measured",
            runs.len()
        );
    }
}
