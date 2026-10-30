// SPDX-License-Identifier: BSD-3-Clause

//! Every check states whether it owes a regime-matched negative arm, and why not where it
//! does not.
//!
//! The control triple's plain arms are profile-free, so they validate the detector and not
//! the attribution: a profile flag other than the one under test can produce a generic
//! observable, and only the regime arm, the negative re-run on the profile, catches it
//! (`DESIGN.md`, "The third control arm"). A bool asking for the arm would let a check decline
//! it with no reason stated, and a confounder could hide in that set. `probe::Regime` is
//! `Arm(flags)` or `NotOwed(Specific { reason, profiles, toolchains })`, with no default. The type,
//! and a compile-time check beside `CORPUS` in `src/probe.rs`, refuse an omitted field, an empty
//! arm, an empty arm flag and an unframed reason. This file holds what they cannot:
//!
//! - the checks that own an arm are exactly [`OWNS_REGIME_ARM`], so an arm gained or lost
//!   is a stated change here and not a silent one in a five-thousand-line literal;
//! - an arm's content: the checks whose arm differs from their negative list are an explicit
//!   list ([`ARM_DIFFERS_FROM_NEGATIVE`]), no arm carries an `-O` ([`ARMS_CARRYING_AN_O`],
//!   empty, as the `Regime::Arm` doc argues), and no arm re-enables the mechanism
//!   by spelling a flag of the positive control that the negative does not share (a flag in
//!   both controls, an `-O` or a `-U`, is setup, not the mechanism);
//! - every reason's frame: `profiles` is the whole of [`probe::PROFILES_WITH_FLAGS`], since
//!   `NotOwed` exempts the check under every profile; `toolchains` names every compiler family
//!   the gate leaves measured, without duplicates, save the allowances in
//!   [`NARROWER_TOOLCHAIN_FRAME`]; and the reason says, as a whole word, whether it is argued
//!   or measured;
//! - the flag lists those frames were argued over, pinned: the guide revision and the
//!   composed `openssf-tldr` list per architecture, and `bare-optimized`'s `-O2` as the
//!   binary spells it, so a change fails here with the instruction to re-read every reason;
//! - `owes_regime_control` derives from the declaration and the profile alone.
//!
//! The counts are printed with the frame they were taken over (checks in the corpus, arms,
//! reasons), so a run's output is checkable against the corpus and not only against itself.

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

/// The `openssf-tldr` flag list the reasons were argued over, per architecture, at guide
/// revision [`PINNED_GUIDE_REVISION`]: the block's rows, the architecture rows, the
/// executables row (`report::openssf_tldr_cflags`).
const PINNED_GUIDE_REVISION: &str = "2026-08-20";
const PINNED_TLDR_COMMON: &[&str] = &[
    "-O2",
    "-Wall",
    "-Wformat",
    "-Wformat=2",
    "-Wconversion",
    "-Wimplicit-fallthrough",
    "-Werror=format-security",
    "-U_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE=3",
    "-D_GLIBCXX_ASSERTIONS",
    "-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST",
    "-fstrict-flex-arrays=3",
    "-fstack-clash-protection",
    "-fstack-protector-strong",
    "-Wl,-z,nodlopen",
    "-Wl,-z,noexecstack",
    "-Wl,-z,relro",
    "-Wl,-z,now",
    "-Wl,--as-needed",
    "-Wl,--no-copy-dt-needed-entries",
];
const PINNED_TLDR_ARCH: &[(&str, &[&str])] = &[
    (
        "x86_64",
        &["-fcf-protection=full", "-fzero-call-used-regs=used-gpr"],
    ),
    (
        "aarch64",
        &[
            "-mbranch-protection=standard",
            "-fzero-call-used-regs=used-gpr",
        ],
    ),
];
const PINNED_TLDR_EXECUTABLE: &[&str] = &["-fPIE", "-pie"];
/// How the binary spells `bare-optimized` (`src/main.rs`), the other profile argued over.
const PINNED_BARE_OPTIMIZED: &[&str] = &[
    r#"cflags: vec!["-O2".to_owned()],"#,
    "cxxflags: Vec::new(),",
    "ldflags: Vec::new(),",
];

const REOPEN: &str = "a profile the reasons were argued over changed: re-read every \
                      `Regime::NotOwed` reason in src/probe.rs (each names \
                      `PROFILES_WITH_FLAGS`), then move this pin";

fn checks() -> Vec<&'static probe::Check> {
    probe::CORPUS.iter().flat_map(|p| p.checks.iter()).collect()
}

/// Whether `word` occurs in `text` as a whole word (letters and digits on neither side).
fn has_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| w == word)
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
        "the checks declaring Regime::Arm, in corpus order, against the list this test pins: \
         a check that gains or loses an arm is a stated change here"
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
                "{}: the regime arm spells `{flag}`, a flag of the positive control that the \
                 negative does not share, so the arm meant to show the mechanism absent turns \
                 it on",
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
        "the checks whose arm differs from their negative list, against the list this test \
         pins: a re-spelled arm, or a return to the arm being the negative, is a stated change"
    );
    assert_eq!(
        with_o, ARMS_CARRYING_AN_O,
        "the arms carrying an -O, against the list this test pins: an arm's -O overrides the \
         profile's level, so the arm is built outside the measured regime"
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
        if specific.reason.len() < 60 {
            problems.push(format!(
                "`{}`'s reason is {} characters, which does not state one",
                check.id,
                specific.reason.len()
            ));
        }
        if !(has_word(specific.reason, "argued") || has_word(specific.reason, "measured")) {
            problems.push(format!(
                "`{}`'s reason says neither `argued` nor `measured` as a word, so a reader \
                 cannot tell a belief from a result",
                check.id
            ));
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
fn the_flag_lists_the_reasons_were_argued_over_are_pinned() {
    assert_eq!(chard::guide::REVISION, PINNED_GUIDE_REVISION, "{REOPEN}");
    for (arch, arch_rows) in PINNED_TLDR_ARCH {
        let expected: Vec<&str> = PINNED_TLDR_COMMON
            .iter()
            .chain(arch_rows.iter())
            .chain(PINNED_TLDR_EXECUTABLE)
            .copied()
            .collect();
        assert_eq!(
            chard::report::openssf_tldr_cflags(arch),
            expected,
            "openssf-tldr on {arch}: {REOPEN}"
        );
    }
    // `bare-optimized` is composed in the binary, not the library, so its spelling is read
    // from the source: the block that builds the profile, up to its closing.
    let main_rs = include_str!("../src/main.rs");
    let start = main_rs
        .find(r#""bare-optimized" => Ok(Profile {"#)
        .expect("src/main.rs builds the bare-optimized profile");
    let block = &main_rs[start..];
    let end = block.find("}),").expect("the profile literal closes");
    let block = &block[..end];
    for line in PINNED_BARE_OPTIMIZED {
        assert!(
            block.contains(line),
            "bare-optimized no longer spells `{line}`: {REOPEN}"
        );
    }
    eprintln!(
        "regime_arms: pinned guide revision {PINNED_GUIDE_REVISION}, openssf-tldr on {} \
         architectures ({} common flags), bare-optimized's {} lines",
        PINNED_TLDR_ARCH.len(),
        PINNED_TLDR_COMMON.len(),
        PINNED_BARE_OPTIMIZED.len()
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
