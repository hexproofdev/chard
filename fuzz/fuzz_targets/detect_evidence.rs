// SPDX-License-Identifier: BSD-3-Clause
//! `chard detect --evidence` over arbitrary JSON: every corpus check, alone and with each
//! arm selected. A report handed to `chard detect` is the one input chard reads that a
//! third party may have written, so a malformed one is a `UserError`, never a panic.
//!
//! Two invariants hold for every input, not only for an unedited report. A replay's counts
//! close (`Replay::closes`: every reading the report owed is replayed or named as not
//! replayable, and `replayed` is the replays listed), since a replay that lost a reading
//! would agree with itself over less than it was handed. And the decoding is deterministic:
//! the same input decoded twice serializes the same, or is refused with the same message,
//! since `chard detect`'s output is evidence a reader compares across runs.

#![no_main]

use chard::detect::{ArmSel, Output, decode_evidence};
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

#[path = "json_mutator.rs"]
mod json_mutator;

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    json_mutator::mutate(data, size, max_size, seed)
});

/// What `chard detect` would print: the output's JSON, or the refusal's message and hint.
fn printed(decoded: &Result<Output, chard::error::UserError>) -> String {
    match decoded {
        Ok(output) => serde_json::to_string(output).expect("an Output serializes"),
        Err(e) => format!("{e} / {:?}", e.hint),
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    for check in chard::probe::CORPUS.iter().flat_map(|p| p.checks.iter()) {
        for arm in [
            None,
            Some(ArmSel::Measured),
            Some(ArmSel::Positive),
            Some(ArmSel::Negative),
            Some(ArmSel::Regime),
        ] {
            let first = decode_evidence(&value, check, arm);
            if let Ok(Output::Replay(replay)) = &first {
                assert!(
                    replay.closes(),
                    "the replay of {} does not close: expected {}, replayed {} of {} listed, \
                     {} not replayable",
                    check.id,
                    replay.expected,
                    replay.replayed,
                    replay.replays.len(),
                    replay.not_replayable.len()
                );
            }
            let second = decode_evidence(&value, check, arm);
            assert_eq!(
                printed(&first),
                printed(&second),
                "decoding the same evidence twice for {} differs",
                check.id
            );
        }
    }
});
