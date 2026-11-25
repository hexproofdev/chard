// SPDX-License-Identifier: BSD-3-Clause

//! A reader that closes the pipe has left, and chard keeps its exit status.

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

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod common;

use common::chard_binary;

fn ready(verifies: &str) -> bool {
    common::require_binary(&chard_binary(), verifies)
}

fn fixture_object() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/elf/elf64-le-x86_64-exec-relro-lazy.elf")
}

/// Run chard with `args` and its stdout on a pipe nobody reads: the read end is closed
/// before chard starts.
fn into_closed_pipe(args: &[&OsStr]) -> Output {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    Command::new(chard_binary())
        .args(args)
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("spawning chard")
}

/// Run chard with `args` and a reader on stdout.
fn read(args: &[&OsStr]) -> Output {
    Command::new(chard_binary())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("spawning chard")
}

/// The closed pipe kept the exit status a reader saw, and chard said nothing about it: its
/// stderr is the one the same invocation writes with a reader, byte for byte.
fn assert_left_quietly(args: &[&OsStr], expected: i32) {
    let with_reader = read(args);
    assert_eq!(
        with_reader.status.code(),
        Some(expected),
        "with a reader, {args:?} exits {expected}; stderr was:\n{}",
        String::from_utf8_lossy(&with_reader.stderr)
    );
    assert!(
        !with_reader.stdout.is_empty(),
        "with a reader, {args:?} printed something, so the closed pipe below refused a write"
    );
    let closed = into_closed_pipe(args);
    let stderr = String::from_utf8_lossy(&closed.stderr);
    assert_eq!(
        closed.status.code(),
        Some(expected),
        "{args:?} into a closed pipe keeps its exit status; stderr was:\n{stderr}"
    );
    assert_eq!(
        stderr,
        String::from_utf8_lossy(&with_reader.stderr),
        "{args:?} into a closed pipe says nothing of it"
    );
}

/// `/dev/full` for chard's stdout, where this system has one; any other failure to open it
/// fails the test rather than reading as its absence.
fn dev_full() -> Option<std::fs::File> {
    match std::fs::OpenOptions::new().write(true).open("/dev/full") {
        Ok(full) => Some(full),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            common::capability_gap(
                "a stdout that refuses with ENOSPC",
                "this system has no /dev/full",
            );
            None
        }
        Err(err) => panic!("opening /dev/full: {err}"),
    }
}

/// A stdout that refuses for another reason than a closed pipe fails `args` with exit 2,
/// and the envelope it could not print reaches stderr, naming the operation.
fn assert_full_stdout_fails(args: &[&OsStr], operation: &str) {
    let Some(full) = dev_full() else {
        return;
    };
    let output = Command::new(chard_binary())
        .args(args)
        .stdin(Stdio::null())
        .stdout(full)
        .stderr(Stdio::piped())
        .output()
        .expect("spawning chard");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "{args:?}; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("\"operation\": \"{operation}\""))
            && stderr.contains("the error envelope could not be written to stdout"),
        "{args:?}: the envelope reaches stderr; stderr was:\n{stderr}"
    );
    assert!(!stderr.contains("panicked"), "stderr was:\n{stderr}");
}

#[test]
fn probes_into_a_closed_pipe_exits_zero() {
    if !ready("that `chard probes | head` exits quietly") {
        return;
    }
    assert_left_quietly(&[OsStr::new("probes")], 0);
}

#[test]
fn elf_into_a_closed_pipe_exits_zero() {
    if !ready("that `chard elf OBJECT | head` exits quietly") {
        return;
    }
    let object = fixture_object();
    assert_left_quietly(&[OsStr::new("elf"), object.as_os_str()], 0);
}

#[test]
fn detect_into_a_closed_pipe_exits_zero() {
    if !ready("that `chard detect --artifact OBJECT | head` exits quietly") {
        return;
    }
    let object = fixture_object();
    assert_left_quietly(
        &[
            OsStr::new("detect"),
            OsStr::new("relro"),
            OsStr::new("--artifact"),
            object.as_os_str(),
        ],
        0,
    );
}

#[test]
fn a_failure_into_a_closed_pipe_keeps_its_exit_status() {
    if !ready("that a failure into a closed pipe keeps exit 2") {
        return;
    }
    assert_left_quietly(
        &[
            OsStr::new("elf"),
            OsStr::new("/nonexistent/chard-closed-pipe/x"),
        ],
        2,
    );
}

#[test]
fn measure_table_matrix_and_detect_into_a_closed_pipe_keep_their_status() {
    let verifies = "that `chard measure`, `table`, `matrix` and `detect` into `head` exit quietly";
    if !ready(verifies) || !common::require_cc(verifies) {
        return;
    }
    let work = common::Work::new("closedpipe", "measure");
    let workdir = work.path("wd");
    let report = work.path("report.json");
    // `-o -`: the report is the stdout the pipe closes on; by default it goes to a file.
    let measure = [
        OsStr::new("measure"),
        OsStr::new("-o"),
        OsStr::new("-"),
        OsStr::new("--workdir"),
        workdir.as_os_str(),
        OsStr::new("--probe"),
        OsStr::new("stack-canary"),
        OsStr::new("--probe"),
        OsStr::new("link-defaults"),
    ];
    assert_left_quietly(&measure, 0);
    let mut gated = measure.to_vec();
    gated.push(OsStr::new("--fail-on-missing"));
    assert_left_quietly(&gated, 1);
    assert_full_stdout_fails(&measure, "measure");

    let written = read(&[
        OsStr::new("measure"),
        OsStr::new("--workdir"),
        workdir.as_os_str(),
        OsStr::new("-o"),
        report.as_os_str(),
        OsStr::new("--probe"),
        OsStr::new("stack-canary"),
        OsStr::new("--probe"),
        OsStr::new("link-defaults"),
    ]);
    assert_eq!(
        written.status.code(),
        Some(0),
        "measure -o: {}",
        String::from_utf8_lossy(&written.stderr)
    );
    for command in ["table", "matrix", "digest"] {
        let args = [OsStr::new(command), report.as_os_str()];
        assert_left_quietly(&args, 0);
        assert_full_stdout_fails(&args, command);
    }

    // One elf-static verdict turned over: the replay disagrees with what the report states.
    let mut parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).expect("reading the report"))
            .expect("the report is JSON");
    let observation = parsed["observations"]
        .as_array_mut()
        .expect("observations")
        .iter_mut()
        .find(|o| {
            o["channel"] == "elf-static" && matches!(o["verdict"].as_str(), Some("on" | "off"))
        })
        .expect("an elf-static measurement to turn over");
    let check = observation["check"]
        .as_str()
        .expect("a check id")
        .to_owned();
    let turned = if observation["verdict"] == "on" {
        "off"
    } else {
        "on"
    };
    observation["verdict"] = turned.into();
    let tampered = work.write("tampered.json", &parsed.to_string());
    assert_left_quietly(
        &[
            OsStr::new("detect"),
            OsStr::new(&check),
            OsStr::new("--evidence"),
            tampered.as_os_str(),
        ],
        1,
    );
}

#[test]
fn a_full_stdout_fails_with_the_envelope_on_stderr() {
    if !ready("that a stdout refusing with ENOSPC fails the run") {
        return;
    }
    assert_full_stdout_fails(&[OsStr::new("probes")], "probes");
    assert_full_stdout_fails(
        &[
            OsStr::new("elf"),
            OsStr::new("/nonexistent/chard-closed-pipe/x"),
        ],
        "elf",
    );
}
