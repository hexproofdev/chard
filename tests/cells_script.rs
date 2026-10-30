// SPDX-License-Identifier: BSD-3-Clause

//! `scripts/cells.sh` over reports whose differences are known.
//!
//! The six-cell frame every item's record quotes comes from this script, so what it calls a
//! move, a fed cell and a difference is held here: the sample report against itself with one
//! thing changed at a time (`--compare`), and the measuring form over two stub binaries that
//! write it, so the script's own invocation of a binary is held too.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

mod common;

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/cells.sh");
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/sample-report.json"
);

/// bash and jq, or the test fails unless skipping is allowed (`common::refuse`): the frame is
/// a gate's evidence, and a suite that could not run it should not read as having held it.
fn tools_present(verifies: &str) -> bool {
    for tool in ["bash", "jq"] {
        if Command::new(tool).arg("--version").output().is_err() {
            common::refuse(
                &format!("no {tool} on PATH to run scripts/cells.sh"),
                verifies,
            );
            return false;
        }
    }
    true
}

fn fixture() -> Value {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("the fixture report"))
        .expect("the fixture parses")
}

/// The fixture as the head binary would write it: a revision of its own.
fn head() -> Value {
    let mut head = fixture();
    head["run"]["harness_revision"] = Value::from("head-revision");
    head["run"]["id"] = Value::from("head-id");
    head["run"]["inputs_sha256"] = Value::from("head-inputs");
    head["digest"]["run"]["harness_revision"] = Value::from("head-revision");
    head
}

fn as_profile(mut report: Value, profile: &str) -> Value {
    report["profile"]["id"] = Value::from(profile);
    report
}

fn write(dir: &Path, name: &str, report: &Value) {
    std::fs::write(dir.join(name), report.to_string()).expect("writing a report");
}

struct Run {
    status: Option<i32>,
    out: String,
}

fn run(args: &[&str], dir: &Path) -> Run {
    let out = Command::new(SCRIPT)
        .args(args)
        .arg(dir)
        .output()
        .expect("running scripts/cells.sh directly, as its mode allows");
    Run {
        status: out.status.code(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// `--compare` over one gcc/bare cell holding `base` and `head` (`None`: not written).
fn one_cell(work: &common::Work, tag: &str, base: Option<&Value>, head: Option<&Value>) -> Run {
    let dir = work.dir().join(tag);
    std::fs::create_dir_all(&dir).expect("the cell directory");
    if let Some(base) = base {
        write(&dir, "base-gcc-bare.json", base);
    }
    if let Some(head) = head {
        write(&dir, "head-gcc-bare.json", head);
    }
    run(&["--cc", "gcc", "--profiles", "bare", "--compare"], &dir)
}

fn pairs_of(report: &Value) -> usize {
    report["observations"]
        .as_array()
        .expect("observations")
        .len()
        + report["composites"].as_array().map_or(0, Vec::len)
}

#[test]
fn identity_alone_is_clean_and_the_frame_sums_its_cells() {
    if !tools_present("that the cells frame is clean over identity alone and sums its cells") {
        return;
    }
    let work = common::Work::new("cells", "identity");
    let dir = work.dir().join("two");
    std::fs::create_dir_all(&dir).expect("the directory");
    for profile in ["bare", "openssf-tldr"] {
        write(
            &dir,
            &format!("base-gcc-{profile}.json"),
            &as_profile(fixture(), profile),
        );
        write(
            &dir,
            &format!("head-gcc-{profile}.json"),
            &as_profile(head(), profile),
        );
    }
    let r = run(
        &[
            "--cc",
            "gcc",
            "--profiles",
            "bare openssf-tldr",
            "--compare",
        ],
        &dir,
    );
    assert_eq!(r.status, Some(0), "{}", r.out);
    let pairs = 2 * pairs_of(&fixture());
    assert!(
        r.out.contains(&format!(
            "cells: fed 2 of 2, pairs {pairs}, moves 0, diagnostics equal in 2 of 2, other \
             fields differ in 0 of 2, exits recorded in 0 of 2"
        )),
        "{}",
        r.out
    );
}

#[test]
fn a_verdict_a_level_a_composite_and_a_one_sided_check_are_moves() {
    if !tools_present("that the cells frame counts every kind of move") {
        return;
    }
    let work = common::Work::new("cells", "moves");
    let base = fixture();
    let check = base["observations"][0]["check"]
        .as_str()
        .expect("a check")
        .to_owned();
    let was = base["observations"][0]["verdict"]
        .as_str()
        .expect("a verdict")
        .to_owned();
    let to = if was == "on" { "off" } else { "on" };
    let level = |o: &Value| o["level"].as_str().unwrap_or("-").to_owned();
    let was_level = level(&base["observations"][0]);

    let mut verdict = head();
    verdict["observations"][0]["verdict"] = Value::from(to);
    let r = one_cell(&work, "verdict", Some(&base), Some(&verdict));
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains(&format!(
            "  MOVE {check} base={was}/{was_level} head={to}/{was_level}\n"
        )),
        "{}",
        r.out
    );

    let mut levelled = head();
    levelled["observations"][0]["level"] = Value::from("a-level-no-check-has");
    let r = one_cell(&work, "level", Some(&base), Some(&levelled));
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains(&format!("head={was}/a-level-no-check-has\n")),
        "{}",
        r.out
    );

    let composite = base["composites"][0]["id"]
        .as_str()
        .expect("a composite")
        .to_owned();
    let mut composed = head();
    composed["composites"][0]["verdict"] = Value::from("a-verdict-no-composite-has");
    let r = one_cell(&work, "composite", Some(&base), Some(&composed));
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains(&format!("  MOVE composite:{composite} ")),
        "{}",
        r.out
    );

    let mut dropped = head();
    dropped["observations"]
        .as_array_mut()
        .expect("observations")
        .remove(0);
    let r = one_cell(&work, "dropped", Some(&base), Some(&dropped));
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains(&format!(
            "  MOVE {check} base={was}/{was_level} head=absent\n"
        )),
        "{}",
        r.out
    );
}

#[test]
fn a_cell_that_cannot_be_compared_is_not_fed_and_says_why() {
    if !tools_present("that the cells frame counts an uncomparable cell as not fed") {
        return;
    }
    let work = common::Work::new("cells", "unfed");
    let base = fixture();
    let mut empty = head();
    empty["observations"] = serde_json::json!([]);
    let mut twice = head();
    let first = twice["observations"][0].clone();
    twice["observations"]
        .as_array_mut()
        .expect("observations")
        .push(first);
    let mut unnamed = head();
    unnamed["observations"][0]
        .as_object_mut()
        .expect("an observation")
        .remove("check");
    let shapes: [(&str, Option<Value>, Option<Value>, &str); 7] = [
        (
            "no-head",
            Some(base.clone()),
            None,
            "a report is missing or does not parse",
        ),
        (
            "no-base",
            None,
            Some(head()),
            "a report is missing or does not parse",
        ),
        (
            "empty",
            Some(base.clone()),
            Some(empty),
            "the head report: no observations",
        ),
        (
            "twice",
            Some(base.clone()),
            Some(twice),
            "the head report: a check is observed twice",
        ),
        (
            "unnamed",
            Some(base.clone()),
            Some(unnamed),
            "the head report: an observation names no check",
        ),
        (
            "profile",
            Some(base.clone()),
            Some(as_profile(head(), "openssf-tldr")),
            "the head report: the report is of profile openssf-tldr, not bare",
        ),
        (
            "one-revision",
            Some(base.clone()),
            Some(base.clone()),
            "base and head name one revision",
        ),
    ];
    for (tag, b, h, why) in shapes {
        let r = one_cell(&work, tag, b.as_ref(), h.as_ref());
        assert_eq!(r.status, Some(1), "{tag}: {}", r.out);
        assert!(
            r.out.contains(&format!("cell gcc bare: NOT FED: {why}")),
            "{tag}: {}",
            r.out
        );
        assert!(r.out.contains("cells: fed 0 of 1,"), "{tag}: {}", r.out);
    }
}

#[test]
fn a_fault_on_either_side_or_of_another_kind_is_not_fed() {
    if !tools_present("that the cells frame refuses a fault on the base side and a wrong kind") {
        return;
    }
    let work = common::Work::new("cells", "faults");
    let base = fixture();

    // The same faults on the base side, and a toolchain of another kind than the cell's.
    let mut base_empty = base.clone();
    base_empty["observations"] = serde_json::json!([]);
    let r = one_cell(&work, "base-empty", Some(&base_empty), Some(&head()));
    assert!(
        r.out.contains("NOT FED: the base report: no observations"),
        "{}",
        r.out
    );
    let mut clang = head();
    clang["toolchain"]["kind"] = Value::from("clang");
    let r = one_cell(&work, "kind", Some(&base), Some(&clang));
    assert!(
        r.out
            .contains("NOT FED: the head report: the report is of a clang toolchain, not gcc"),
        "{}",
        r.out
    );
    let mut composite = head();
    let first = composite["composites"][0].clone();
    composite["composites"]
        .as_array_mut()
        .expect("composites")
        .push(first);
    let r = one_cell(&work, "composite-twice", Some(&base), Some(&composite));
    assert!(
        r.out
            .contains("NOT FED: the head report: a composite is published twice"),
        "{}",
        r.out
    );
    let mut blank = head();
    blank["observations"][0]["check"] = Value::from("");
    let r = one_cell(&work, "blank", Some(&base), Some(&blank));
    assert!(
        r.out
            .contains("NOT FED: the head report: an observation names no check"),
        "{}",
        r.out
    );
}

#[test]
fn a_cell_is_counted_whatever_its_reports_hold() {
    if !tools_present("that the cells frame counts unparsed, failed and mixed cells") {
        return;
    }
    let work = common::Work::new("cells", "counted");
    let base = fixture();

    // Text that is not JSON, and a recorded nonzero measurement.
    let dir = work.dir().join("garbled");
    std::fs::create_dir_all(&dir).expect("the directory");
    write(&dir, "base-gcc-bare.json", &base);
    std::fs::write(dir.join("head-gcc-bare.json"), "{\"cut\": ").expect("a cut report");
    let r = run(&["--cc", "gcc", "--profiles", "bare", "--compare"], &dir);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out
            .contains("NOT FED: a report is missing or does not parse"),
        "{}",
        r.out
    );
    write(&dir, "head-gcc-bare.json", &head());
    std::fs::write(dir.join("head-gcc-bare.exit"), "2\n").expect("an exit file");
    let r = run(&["--cc", "gcc", "--profiles", "bare", "--compare"], &dir);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains("NOT FED: the head measurement exited 2"),
        "{}",
        r.out
    );

    // One fed and one unfed cell: the frame counts both.
    let dir = work.dir().join("mixed");
    std::fs::create_dir_all(&dir).expect("the directory");
    write(&dir, "base-gcc-bare.json", &base);
    write(&dir, "head-gcc-bare.json", &head());
    write(&dir, "base-clang-bare.json", &base);
    let r = run(
        &["--cc", "gcc clang", "--profiles", "bare", "--compare"],
        &dir,
    );
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(r.out.contains("cells: fed 1 of 2,"), "{}", r.out);

    // Moves sum across cells, and a move outranks another field's difference (exit 1, not 3).
    let dir = work.dir().join("summed");
    std::fs::create_dir_all(&dir).expect("the directory");
    let mut moved = head();
    let to = if moved["observations"][0]["verdict"] == "on" {
        "off"
    } else {
        "on"
    };
    moved["observations"][0]["verdict"] = Value::from(to);
    for profile in ["bare", "openssf-tldr"] {
        write(
            &dir,
            &format!("base-gcc-{profile}.json"),
            &as_profile(base.clone(), profile),
        );
    }
    write(
        &dir,
        "head-gcc-bare.json",
        &as_profile(moved.clone(), "bare"),
    );
    let mut both = moved;
    both["toolchain"]["version_raw"] = Value::from("another banner");
    write(
        &dir,
        "head-gcc-openssf-tldr.json",
        &as_profile(both, "openssf-tldr"),
    );
    let r = run(
        &[
            "--cc",
            "gcc",
            "--profiles",
            "bare openssf-tldr",
            "--compare",
        ],
        &dir,
    );
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(r.out.contains("cells: fed 2 of 2, pairs "), "{}", r.out);
    assert!(r.out.contains(", moves 2, "), "{}", r.out);
}

#[test]
fn another_field_differing_with_no_move_is_named() {
    if !tools_present("that the cells frame names a differing field with no move") {
        return;
    }
    let work = common::Work::new("cells", "fields");
    let base = fixture();
    let mut toolchain = head();
    toolchain["toolchain"]["version_raw"] = Value::from("another banner");
    let mut corpus = head();
    corpus["run"]["probe_corpus_sha256"] = Value::from("another corpus");
    let mut severity = head();
    let was = severity["diagnostics"][0]["severity"]
        .as_str()
        .unwrap_or("warning")
        .to_owned();
    severity["diagnostics"][0]["severity"] =
        Value::from(if was == "warning" { "error" } else { "warning" });
    let shapes = [
        (
            "toolchain",
            toolchain,
            "fields differing: toolchain\n",
            "equal",
        ),
        ("corpus", corpus, "fields differing: run\n", "equal"),
        (
            "severity",
            severity,
            "fields differing: diagnostics\n",
            "differ",
        ),
    ];
    for (tag, h, named, diagnostics) in shapes {
        let r = one_cell(&work, tag, Some(&base), Some(&h));
        assert_eq!(r.status, Some(3), "{tag}: {}", r.out);
        assert!(r.out.contains(named), "{tag}: {}", r.out);
        assert!(
            r.out
                .contains(&format!("moves 0, diagnostics 1/1 {diagnostics},")),
            "{tag}: {}",
            r.out
        );
    }
}

#[test]
fn usage_and_a_missing_directory_exit_2() {
    if !tools_present("that the cells script refuses a malformed invocation") {
        return;
    }
    let work = common::Work::new("cells", "usage");
    let missing = work.dir().join("not-there");
    assert_eq!(
        run(&["--compare"], &missing).status,
        Some(2),
        "a missing directory"
    );
    assert_eq!(
        run(&["--bogus"], work.dir()).status,
        Some(2),
        "an unknown option"
    );
    assert_eq!(
        run(&[], work.dir()).status,
        Some(2),
        "one argument where three are needed"
    );
    let r = run(&["--cc", "", "--compare"], work.dir());
    assert_eq!(r.status, Some(1), "no cell named: {}", r.out);
    assert!(r.out.contains("cells: no cell named"), "{}", r.out);
}

/// A stand-in for chard: writes `report` with `revision` to the path after `-o`, with the
/// `--profile` it was handed, and exits `status`.
fn stub(dir: &Path, name: &str, revision: &str, status: i32) -> PathBuf {
    let report = dir.join(format!("{name}.json"));
    let mut value = fixture();
    value["run"]["harness_revision"] = Value::from(revision);
    write(dir, &format!("{name}.json"), &value);
    common::executable(
        &dir.join(name),
        &format!(
            "#!/bin/sh\nout= profile=\nwhile [ $# -gt 0 ]; do case $1 in -o) out=$2; shift ;; \
             --profile) profile=$2; shift ;; esac; shift; done\n\
             jq --arg p \"$profile\" '.profile.id = $p' '{}' > \"$out\"\nexit {status}\n",
            report.display()
        ),
    )
}

#[test]
fn the_measuring_form_runs_both_binaries_into_one_frame() {
    if !tools_present("that the cells script measures with both binaries and compares") {
        return;
    }
    let work = common::Work::new("cells", "measure");
    let base = stub(work.dir(), "base-chard", "base-revision", 0);
    let head = stub(work.dir(), "head-chard", "head-revision", 0);
    let out = work.dir().join("cells");
    let args = |b: &Path, h: &Path| {
        vec![
            "--cc".to_owned(),
            "gcc".to_owned(),
            "--profiles".to_owned(),
            "bare openssf-tldr".to_owned(),
            b.display().to_string(),
            h.display().to_string(),
        ]
    };
    let a = args(&base, &head);
    let r = run(&a.iter().map(String::as_str).collect::<Vec<_>>(), &out);
    assert_eq!(r.status, Some(0), "{}", r.out);
    assert!(
        r.out.contains("measured head gcc openssf-tldr: exit 0"),
        "{}",
        r.out
    );
    assert!(r.out.contains("cells: fed 2 of 2,"), "{}", r.out);
    assert!(r.out.contains("exits recorded in 2 of 2"), "{}", r.out);

    let failing = stub(work.dir(), "failing-chard", "failing-revision", 2);
    let a = args(&base, &failing);
    let r = run(&a.iter().map(String::as_str).collect::<Vec<_>>(), &out);
    assert_eq!(r.status, Some(1), "{}", r.out);
    assert!(
        r.out.contains("NOT FED: the head measurement exited 2"),
        "{}",
        r.out
    );

    let a = args(&base, &work.dir().join("no-such-binary"));
    assert_eq!(
        run(&a.iter().map(String::as_str).collect::<Vec<_>>(), &out).status,
        Some(2)
    );
}
