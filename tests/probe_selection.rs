// SPDX-License-Identifier: BSD-3-Clause

//! What `chard measure` does with a `--probe` selection it cannot honour.

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

use std::process::Command;

use serde_json::Value;

mod common;

use common::chard_binary;

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
