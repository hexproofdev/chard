// SPDX-License-Identifier: BSD-3-Clause

//! Every check states whether it owes a regime-matched negative arm, and why not where it
//! does not.

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

use std::collections::BTreeSet;

use chard::probe::{self, Regime};
use chard::toolchain::Kind;

/// Every check that declares a regime arm, in corpus order.
const OWNS_REGIME_ARM: &[&str] = &[
    "cet-marked",
    "gcs-marked",
    "branch-protection-marked",
    "pic-shared-link",
    "pic-object-relocs",
    "noexecstack-enforced",
    "zero-init-padding-bits",
    "zero-call-used-regs",
    "auto-var-init-active",
    "auto-var-init-pattern",
    "cxx-stdlib-assertions",
    "cxx-assertions-symbol",
    "stack-clash-guard-page",
];

/// The checks whose declared arm is not their negative list. Every arm was copied from its
/// negative when the enum landed; these four are their negative without its `-O`, dropped
/// because the arm sits on the profile and takes the profile's level (the
/// `Regime::Arm` doc). An arm re-spelled again is added here, so a reader of that doc knows
/// which to look at.
const ARM_DIFFERS_FROM_NEGATIVE: &[&str] = &[
    "auto-var-init-active",
    "auto-var-init-pattern",
    "cxx-assertions-symbol",
    "stack-clash-guard-page",
];

/// The arms that carry an optimization flag, which under a profile at another level puts
/// the arm outside the measured regime (the `Regime::Arm` doc). Empty, so
/// an arm that gains an `-O` fails here and has to be named with its reason.
const ARMS_CARRYING_AN_O: &[&str] = &[];

/// Reasons whose frame names fewer compiler families than the gate leaves measured, each
/// with the family left out and why: `ret-protector-emitted`'s flag exists on OpenBSD clang
/// alone, and gcc, which the gate does not list, has nothing to argue over.
const NARROWER_TOOLCHAIN_FRAME: &[(&str, &str)] = &[("ret-protector-emitted", "gcc")];

fn checks() -> Vec<&'static probe::Check> {
    probe::CORPUS.iter().flat_map(|p| p.checks.iter()).collect()
}

#[test]
fn the_checks_owning_a_regime_arm_are_exactly_the_listed_ones() {
    let all = checks();
    let declared: Vec<&str> = all
        .iter()
        .filter(|c| c.regime_arm().is_some())
        .map(|c| c.id)
        .collect();
    assert_eq!(
        declared, OWNS_REGIME_ARM,
        "the checks declaring Regime::Arm, in corpus order, are not the list this test pins"
    );
    let ids: BTreeSet<&str> = all.iter().map(|c| c.id).collect();
    for id in OWNS_REGIME_ARM {
        assert!(ids.contains(id), "{id} is not a check in the corpus");
    }
    eprintln!(
        "regime_arms: {} checks in the corpus, {} declare an arm, {} state why none is owed",
        all.len(),
        declared.len(),
        all.len() - declared.len()
    );
}

#[test]
fn every_arm_is_a_countermand_and_its_content_is_a_stated_choice() {
    let mut differs = Vec::new();
    let mut with_o = Vec::new();
    let mut arms = 0usize;
    for check in checks() {
        let Regime::Arm(flags) = check.regime else {
            continue;
        };
        arms += 1;
        if flags != check.negative {
            differs.push(check.id);
        }
        if flags.iter().any(|f| f.starts_with("-O")) {
            with_o.push(check.id);
        }
        for flag in flags {
            assert!(
                !check.positive.contains(flag) || check.negative.contains(flag),
                "{}: the regime arm spells `{flag}`, a positive-control flag the negative lacks",
                check.id
            );
        }
        assert_ne!(
            flags, check.positive,
            "{}: the regime arm is the positive control",
            check.id
        );
    }
    assert_eq!(
        differs, ARM_DIFFERS_FROM_NEGATIVE,
        "the checks whose arm differs from their negative list are not the list this test pins"
    );
    assert_eq!(
        with_o, ARMS_CARRYING_AN_O,
        "the arms carrying an -O are not the list this test pins"
    );
    assert!(arms > 0, "no arm declared, so this test holds over nothing");
    eprintln!(
        "regime_arms: {arms} arms, {} differing from their negative, {} carrying an -O",
        differs.len(),
        with_o.len()
    );
}

#[test]
fn every_reason_for_owing_no_arm_is_framed_over_every_profile_and_measured_toolchain() {
    let families: BTreeSet<&str> = [Kind::Gcc.as_str(), Kind::Clang.as_str()]
        .into_iter()
        .collect();
    assert_eq!(
        probe::PROFILES_WITH_FLAGS,
        ["bare-optimized", chard::report::OPENSSF_TLDR_ID],
        "the profiles a reason is argued over are the built-in ones that add flags"
    );
    let mut reasons = 0usize;
    let mut problems = Vec::new();
    for check in checks() {
        let Regime::NotOwed(specific) = check.regime else {
            continue;
        };
        reasons += 1;
        if specific.profiles != probe::PROFILES_WITH_FLAGS {
            problems.push(format!(
                "`{}` frames its reason over {:?}; NotOwed exempts the check under every \
                 profile, so the frame is the whole of PROFILES_WITH_FLAGS",
                check.id, specific.profiles
            ));
        }
        let named: BTreeSet<&str> = specific.toolchains.iter().copied().collect();
        if named.len() != specific.toolchains.len() {
            problems.push(format!(
                "`{}` names a compiler family twice: {:?}",
                check.id, specific.toolchains
            ));
        }
        for t in &named {
            if !families.contains(t) {
                problems.push(format!(
                    "`{}` argues its reason over `{t}`, which is not a compiler family chard \
                     measures",
                    check.id
                ));
            }
        }
        for family in &families {
            let gated = check.gate.compiler_unsupported.contains(family);
            let allowed = NARROWER_TOOLCHAIN_FRAME.contains(&(check.id, *family));
            if !gated && !allowed && !named.contains(family) {
                problems.push(format!(
                    "`{}` is measured on {family} and its reason does not cover it \
                     (toolchains: {:?})",
                    check.id, specific.toolchains
                ));
            }
            if allowed && named.contains(family) {
                problems.push(format!(
                    "`{}` is allowed a frame without {family} and names it anyway: drop the \
                     allowance",
                    check.id
                ));
            }
        }
    }
    for (check, family) in NARROWER_TOOLCHAIN_FRAME {
        assert!(
            checks().iter().any(|c| c.id == *check),
            "{check} (allowed a frame without {family}) is not a check in the corpus"
        );
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        reasons > 0,
        "no check states a reason, so this test holds over nothing"
    );
    eprintln!(
        "regime_arms: {reasons} reasons, each framed over {:?} and the families of {:?} its \
         gate leaves measured ({} allowance)",
        probe::PROFILES_WITH_FLAGS,
        families,
        NARROWER_TOOLCHAIN_FRAME.len()
    );
}

#[test]
fn owing_an_arm_derives_from_the_declaration_and_the_profile_alone() {
    let mut owed = 0usize;
    for check in checks() {
        assert!(
            !check.owes_regime_control(true),
            "{}: a clean profile owes no regime arm to any check",
            check.id
        );
        assert_eq!(
            check.owes_regime_control(false),
            check.regime_arm().is_some(),
            "{}: under a profile that adds flags an arm is owed exactly where one is declared",
            check.id
        );
        owed += usize::from(check.owes_regime_control(false));
    }
    assert_eq!(owed, OWNS_REGIME_ARM.len());
}
