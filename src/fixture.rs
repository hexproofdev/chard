// SPDX-License-Identifier: BSD-3-Clause

//! A recorded (evidence, expectation) row replayed through a check's detector, as a
//! measurement reads it: `tests/synthetic_rows.rs` replays the hand-written rows of
//! `tests/fixtures/synthetic-rows.json`.

use std::collections::BTreeMap;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arm: Option<String>,
    /// The toolchain that produced it, e.g. `gcc-8.5.0-glibc2.28-rocky8.10`, so a failure
    /// names the environment rather than just the check. **Not unique on its own**: the id
    /// names no architecture ([`Fixture::arch`]).
    pub toolchain: String,
    /// The architecture the evidence was recorded on, from the toolchain's target
    /// triple.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// The machine the evidence was recorded on, `env::machine_of` over its report: what names
    /// the CPU, then the features that gate a mechanism (`features:bti,paca,pacg`), or `unread`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// The profile in force, since the same check answers differently under `bare` and
    /// under a flag list supplied through `explicit`. Some fixtures name profiles this
    /// build does not have, `distro-buildflags` among them; the field is a label on
    /// archived evidence rather than a profile this build can run.
    pub profile: String,
    /// The detector outcome this fixture is pinned to.
    pub expected: String,
    /// The verdict the archive recorded. The replay holds the detector's reading, not this.
    /// Useful when reviewing a diff:
    /// a fixture whose baseline disagrees with the old published verdict is worth a second look.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
