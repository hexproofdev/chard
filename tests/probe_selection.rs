// SPDX-License-Identifier: BSD-3-Clause

//! What `chard measure` does with a `--probe` selection it cannot honour.
//!
//! Through the binary, because the refusal is a property of the command line rather than
//! of the measurement: the selection is settled before the compiler is touched, so these
//! need the built `chard` and nothing else. A repeated id, if accepted, would produce a run
//! that counts one probe's checks twice against two identical observations and reports
//! itself whole.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

mod common;

fn chard_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("chard")
}

/// Run `chard measure` with `args` and return the exit status and the JSON it printed.
fn measure(args: &[&str]) -> (Option<i32>, Value) {
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(["-o", "-"])
        .args(args)
        .output()
        .expect("spawning chard");
    let text = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    (output.status.code(), parsed)
}

/// A repeated `--probe` is refused as the caller's mistake, before anything runs.
#[test]
fn a_repeated_probe_is_refused_as_user_input() {
    if !common::require_binary(
        &chard_binary(),
        "that a repeated --probe is refused rather than counted twice",
    ) {
        return;
    }
    // `--cc` names nothing that exists, and the refusal must arrive before chard finds
    // that out: a selection error reported after a toolchain interrogation would be a
    // different error on a machine with no compiler.
    let (code, out) = measure(&[
        "--cc",
        "/nonexistent/chard-test-compiler",
        "--probe",
        "stack-canary",
        "--probe",
        "stack-canary",
    ]);
    assert_eq!(code, Some(2), "a refused invocation exits 2: {out}");
    assert_eq!(
        out["error"]["code"].as_str(),
        Some("USER_INPUT"),
        "the refusal is the caller's to fix: {out}"
    );
    let message = out["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains("stack-canary") && message.contains("more than once"),
        "the message names the repeated id: {message}"
    );
    assert!(
        out["error"]["hint"]
            .as_str()
            .is_some_and(|h| h.contains("once")),
        "the hint says what to do instead: {out}"
    );
}

/// An unknown `--probe` is refused the same way, and the refusal names the id.
#[test]
fn an_unknown_probe_is_refused_as_user_input() {
    if !common::require_binary(&chard_binary(), "that an unknown --probe is refused") {
        return;
    }
    let (code, out) = measure(&[
        "--cc",
        "/nonexistent/chard-test-compiler",
        "--probe",
        "no-such-probe",
    ]);
    assert_eq!(code, Some(2));
    assert_eq!(out["error"]["code"].as_str(), Some("USER_INPUT"));
    assert!(
        out["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no-such-probe")),
        "{out}"
    );
}
