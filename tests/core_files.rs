// SPDX-License-Identifier: BSD-3-Clause

//! A sweep cell leaves no core file behind, and the gate that says so can see one.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::string_slice,
    reason = "test code lays out fixture bytes, counts results and slices text at offsets it \
              found in the same string, from constants and the sizes of data in memory; the \
              test profile keeps overflow checks, and an overflow, or a slice off a character \
              boundary or past the end, panics and fails the test. Its casts widen a length or \
              a u32, take the offset between two addresses in one string, or name a function \
              pointer type or a closure's trait object. clippy has no test knob for these three \
              lints, and src/lib.rs's crate-root relief does not reach tests/"
)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

mod common;

use common::chard_binary;

const GATE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/sweep-gate.sh");

/// A probe whose positive control dies on a signal: SIGABRT from glibc's fortify wrapper,
/// SIGTRAP from Apple's. `bare` still builds and runs the control arms, so one probe under
/// one profile is enough to put a crash in the workdir. On Linux the probe is
/// non-dumpable, so its crash writes no core there whatever the limit.
const ABORTING_PROBE: &str = "fortify-known-object";

/// Is there a `bash` to run the gate with?
fn require_bash(verifies: &str) -> bool {
    if Command::new("bash").arg("-c").arg(":").output().is_err() {
        common::refuse("no bash on PATH to run scripts/sweep-gate.sh", verifies);
        return false;
    }
    true
}

/// The gate's stdout for one report and workdir, with its exit status.
fn gate(limit: &str, workdir: &Path, report: &Path) -> (String, Option<i32>) {
    gate_after(limit, workdir, report, "0")
}

/// [`gate`], handed `measure_rc` as the measurement's exit status.
fn gate_after(
    limit: &str,
    workdir: &Path,
    report: &Path,
    measure_rc: &str,
) -> (String, Option<i32>) {
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
        .arg(measure_rc)
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

/// The planted reports [`the_gate_holds_exit_4_to_the_report_both_ways`] feeds the gate, each
/// with `true` where the report supports exit 4 (every check attempted, every unsettled one
/// `indeterminate` under a machine-limit or target-limit rule, at least one a machine limit)
/// and `false` where it supports exit 1 alone.
fn exit_4_cells(work: &common::Work, total: usize) -> Vec<(std::path::PathBuf, bool)> {
    let report = |held: &[(&str, &str, Option<&str>)]| {
        let mut r: Value = serde_json::from_str(&passing_report(total)).expect("json");
        r["coverage"]["all_verdicts_published"] = false.into();
        let observations = r["observations"].as_array_mut().expect("observations");
        for (check, verdict, rule) in held {
            let mut o = serde_json::json!({"check": check, "verdict": verdict});
            if let Some(rule) = rule {
                o["gating"] = serde_json::json!({"rule": rule});
            }
            observations.push(o);
        }
        r
    };
    // An aarch64 machine without BTI or PAC: those two checks held by a machine limit,
    // `shadow-stack-enforced` by a target limit, and every other check settled, one row of
    // each settled verdict (`on` is the planted report's own row).
    let shape = [
        ("bti-enforced", "indeterminate", Some("machine-lacks-bti")),
        (
            "pac-ret-enforced",
            "indeterminate",
            Some("machine-lacks-pac"),
        ),
        (
            "shadow-stack-enforced",
            "indeterminate",
            Some("no-check-on-target"),
        ),
        ("fortify-source", "off", None),
        ("stack-protector", "partial", None),
    ];
    let beside = |rows: &[(&'static str, &'static str, Option<&'static str>)]| {
        let mut all = shape.to_vec();
        all.extend_from_slice(rows);
        report(&all)
    };
    // A machine-limit rule beside a verdict other than `indeterminate`.
    let mut invalid_rows = shape.to_vec();
    invalid_rows[0] = ("bti-enforced", "probe-invalid", Some("machine-lacks-bti"));
    // The same with `build-failed` and with `run-failed`, so a gate that refused only
    // `probe-invalid` beside a machine limit would take them.
    let mut build_failed_rows = shape.to_vec();
    build_failed_rows[0] = ("bti-enforced", "build-failed", Some("machine-lacks-bti"));
    let mut run_failed_rows = shape.to_vec();
    run_failed_rows[0] = ("bti-enforced", "run-failed", Some("machine-lacks-bti"));
    // The shape in a report that did not attempt every check.
    let mut unattempted = report(&shape);
    unattempted["coverage"]["all_checks_attempted"] = false.into();
    [
        ("limited.json", report(&shape), true),
        // A withheld check with no rule.
        (
            "mixed.json",
            beside(&[("gcs-macro", "probe-invalid", None)]),
            false,
        ),
        // A target limit alone.
        ("target-only.json", report(&shape[2..3]), false),
        // Limitations a gating rule earned, one of each verdict, each under a rule that
        // publishes it.
        (
            "beside-earned.json",
            beside(&[
                ("gcs-macro", "unsupported", Some("arch-gated")),
                (
                    "libcxx-hardening",
                    "not-applicable",
                    Some("stdlib-lacks-observable"),
                ),
            ]),
            true,
        ),
        // A limitation verdict no gating rule earns is a shortfall with no rule.
        (
            "beside-unearned.json",
            beside(&[("gcs-macro", "unsupported", None)]),
            false,
        ),
        // A check held `indeterminate` by a rule of neither list.
        (
            "other-rule.json",
            beside(&[(
                "sanitizer-bounds",
                "indeterminate",
                Some("sanitizer-group-unmeasured"),
            )]),
            false,
        ),
        ("machine-rule-invalid.json", report(&invalid_rows), false),
        (
            "machine-rule-build-failed.json",
            report(&build_failed_rows),
            false,
        ),
        (
            "machine-rule-run-failed.json",
            report(&run_failed_rows),
            false,
        ),
        ("unattempted.json", unattempted, false),
    ]
    .into_iter()
    .map(|(name, report, limited)| (work.write(name, &report.to_string()), limited))
    .collect()
}

#[test]
fn the_gate_holds_exit_4_to_the_report_both_ways() {
    let verifies = "that the sweep gate holds exit 1 and exit 4 to the report";
    if !require_bash(verifies) {
        return;
    }
    if !have_jq() {
        common::capability_gap(verifies, "no jq on PATH, so the gate exits 2 at the report");
        return;
    }
    let total = chard::probe::total_checks();
    let work = common::Work::new("core-files", "exit-4");
    let dir = work.path("cell");
    std::fs::create_dir_all(dir.join("probe")).expect("creating the workdir");
    std::fs::write(dir.join("probe/plain.stdout"), "text\n").expect("planting");
    let status_failure = |out: &str, rc: &str| {
        out.lines()
            .any(|l| l.starts_with("FAIL") && l.contains(&format!("chard measure exited {rc}")))
    };
    let cells = exit_4_cells(&work, total);
    assert_eq!(cells.len(), 10, "every planted report is fed to the gate");
    for (path, rc, fails) in cells
        .iter()
        .flat_map(|(path, limited)| [(path, "4", !limited), (path, "1", *limited)])
    {
        let (out, _) = gate_after("0", &dir, path, rc);
        assert_eq!(
            status_failure(&out, rc),
            fails,
            "{} at exit {rc}: the gate printed:\n{out}",
            path.display()
        );
    }
}

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
                "no probe run ended on a signal under `ulimit -c unlimited`"
            );
            assert_line(&on, "FAIL  on: the core limit is unlimited");
            if cfg!(target_os = "linux") {
                // The probe made itself non-dumpable, so even an unlimited limit and a
                // pattern into the workdir leave no core: the non-dumpable property, live.
                assert_line(&on, "ok    on: no core file among");
            } else {
                assert!(
                    on.lines()
                        .any(|l| l.starts_with("FAIL  on: ") && l.contains(" core file(s) among ")),
                    "the gate found no core in the workdir under core_pattern {pattern:?}:\n{on}"
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
const NON_DUMPABLE: &[&str] = &[
    "bti_enforced.c",
    "cxx_assertions.cpp",
    "fortify_dynamic_object.c",
    "fortify_known_object.c",
    "fortify_percent_n.c",
    "fortify_subobject.c",
    "pac_ret_enforced.c",
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
    "int (*target)(void) = chard_bti_target;",
    "int returned;",
    "unsigned long hwcap2;",
    "unsigned long hwcap;",
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
                    "{name}: the call precedes the self-report"
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
                    "{name}: `{line}` comes before CHARD_NOT_DUMPABLE in main"
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
                    "{profile}: {} ended on {signal}, and {} is not on NON_DUMPABLE",
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
            "{profile}: no run of {} records ended on a signal that dumps",
            runs.len()
        );
    }
}
