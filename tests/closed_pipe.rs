// SPDX-License-Identifier: BSD-3-Clause

//! A reader that closes the pipe has left, and chard keeps its exit status.
//!
//! `chard probes | head -1` panicked with "failed printing to stdout: Broken pipe" and
//! exited 101: Rust ignores `SIGPIPE`, so the write returns `EPIPE` where a C program
//! would have been killed, and `println!` panics on it. Each case here hands chard a pipe
//! whose read end is already closed, so every write chard makes is refused with `EPIPE`
//! and the result does not depend on how much chard prints or on when a reader stops.
//! The case runs the same invocation with a reader first, and asserts that it printed
//! something, then that the closed pipe kept its exit status (`0`, `1` and `2` each appear;
//! `3` is `measure`'s own contradiction, which no run reaches short of a defect in chard, and
//! its envelope goes through the writer `error::emit`'s does) and its stderr byte for byte. Each of the six subcommands is held here, and each
//! writes its output through `write_stdout` in `src/main.rs`, and an error's envelope
//! through `error::emit`; one failing `elf` holds the second path. A stdout that refuses
//! for any other reason (`/dev/full`) is a failure, exit `2`, and the envelope it could not
//! take goes to stderr: held for `probes`, a failing `elf`, `measure`, `table` and `matrix`.
//! Where this system has no `/dev/full` that half is a capability gap, announced.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod common;

fn chard_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("chard")
}

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

/// The envelope's path: a failing `elf` into a closed pipe keeps its `2`. `error::emit` reads
/// its write's result, and this test holds that path.
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

/// `measure` publishes its report on stdout last, and `table`, `matrix` and `detect`
/// read one back: each is held against one measurement, into a closed pipe and into
/// `/dev/full`. The measurement also carries both gates' `1` into the closed pipe: the
/// coverage gate's, from a run narrowed by `--probe` (the gate counts the whole corpus, so it
/// fails on any host), and `detect`'s, from the report with one published verdict turned
/// over.
#[test]
fn measure_table_matrix_and_detect_into_a_closed_pipe_keep_their_status() {
    let verifies = "that `chard measure`, `table`, `matrix` and `detect` into `head` exit quietly";
    if !ready(verifies) || !common::require_cc(verifies) {
        return;
    }
    let work = common::Work::new("closedpipe", "measure");
    let workdir = work.path("wd");
    let report = work.path("report.json");
    // `-o -`: the report is the stdout the pipe closes on; by default it goes to a file. Two
    // probes, not the corpus: the pipe's read end is closed before chard starts, so its first
    // write fails whatever the report's size; and the replay below needs an elf-static check
    // reading on or off, which link-defaults' `pie` and `relro` do on every ELF host where
    // stack-canary's `canary-emitted` can withhold (OpenBSD's clang, RETGUARD). The whole
    // corpus here was four full measurements, 71 s of the suite; a full-corpus
    // report and its exit 0 are error_classes' to hold.
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

/// A stdout that refuses for another reason is not a reader leaving: the run fails and
/// the envelope it could not print reaches stderr. `print_json`'s path here, a failing
/// command's own envelope under `elf`, and the direct writes beside the measurement above.
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
