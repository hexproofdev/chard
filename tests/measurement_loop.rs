// SPDX-License-Identifier: BSD-3-Clause

//! Drive the measurement loop directly, without the CLI.
//!
//! This file could not exist until the loop moved into the library. It had lived in the
//! binary crate root, so the control-triple wiring, the coverage denominator and the
//! profile-versus-control distinction were reachable only by running a sweep and reading
//! the JSON, which meant every claim about them was verified by a person looking at
//! output, three times in one session.
//!
//! What is asserted here is the part a report cannot show you: not that a verdict is
//! right on this machine, which depends on whoever packaged the compiler, but that the
//! *control triple did its job*: that a forced-on build and a forced-off build actually
//! discriminated before any verdict was trusted. A green run on a hardened toolchain and
//! a green run on a bare one must both pass, because the property under test is the
//! instrument's, not the distribution's.

use std::time::Duration;

mod common;

use chard::env;
use chard::measure::{self, Conditions, Driver};
use chard::probe;
use chard::report::{self, Profile, Verdict};
use chard::toolchain;

/// A work directory that is removed when the test ends.
/// Can this machine drive the measurement loop? Checked once, at the top of each test.
///
/// The one legitimate reason it cannot is the absence of a C compiler, which is a
/// property of the environment and knowable before any work starts. Anything that goes
/// wrong after that (a toolchain that detects but will not build, a probe that vanishes
/// from the corpus) is a real failure and panics.
///
/// Returns `false` only when the operator opted into skipping; otherwise
/// [`common::refuse`] panics.
fn can_run(verifies: &str) -> bool {
    common::require_cc(verifies)
}

/// A failure that arrived after [`can_run`] said the machine was capable.
///
/// Not a skip: a compiler is present, so whatever went wrong here is chard's.
fn cannot_run(reason: &str) -> ! {
    panic!(
        "cannot drive the measurement loop ({reason}).\n\nA C compiler is present — \
         `can_run` checked — so this is a real failure, not an unrunnable machine."
    );
}

fn profile_with_flags(cflags: &[&str]) -> Profile {
    let mut p = bare_profile();
    "explicit".clone_into(&mut p.id);
    "user".clone_into(&mut p.flags_source);
    p.cflags = cflags.iter().map(|s| (*s).to_string()).collect();
    p
}

fn bare_profile() -> Profile {
    Profile {
        id: "bare".to_owned(),
        flags_source: "none".to_owned(),
        cflags: Vec::new(),
        cxxflags: Vec::new(),
        ldflags: Vec::new(),
        toolchain_note: None,
        compiler_environment: chard::compile::CompilerEnvironment::of_this_run(),
    }
}

/// Stand up a work directory, toolchain and driver for one probe, and hand them to a
/// closure.
///
/// The setup is a dozen lines that every test here needs and that no test is about, and
/// the borrows make it awkward to return: `Driver` holds the toolchain and the work
/// directory, and the work directory deletes itself on drop. A closure keeps all three
/// alive for exactly as long as the body needs them.
fn with_bench<T>(
    probe_id: &str,
    tag: &str,
    profile: &Profile,
    body: impl FnOnce(&Driver<'_>, &'static probe::Probe, &Conditions<'_>) -> T,
) -> T {
    with_bench_on(None, probe_id, tag, profile, body)
}

/// [`with_bench`] through a driver of the test's making: `wrapper` is the body of a
/// script placed in the work directory with `$REAL` bound to the host's `cc`, or `None`
/// for the host's `cc` itself.
fn with_bench_on<T>(
    wrapper: Option<&str>,
    probe_id: &str,
    tag: &str,
    profile: &Profile,
    body: impl FnOnce(&Driver<'_>, &'static probe::Probe, &Conditions<'_>) -> T,
) -> T {
    let work = common::Work::new("loop", tag);
    let Some(probe) = probe::find(probe_id) else {
        panic!("probe {probe_id} is not in the corpus");
    };

    let cc = match wrapper {
        None => "cc".to_owned(),
        Some(script) => {
            let real = std::process::Command::new("sh")
                .args(["-c", "command -v cc"])
                .output()
                .expect("sh is available");
            let real = String::from_utf8_lossy(&real.stdout).trim().to_owned();
            common::executable(&work.path("fakecc"), &format!("REAL='{real}'\n{script}"))
                .display()
                .to_string()
        }
    };
    let toolchain = match toolchain::detect(&cc, work.dir(), false) {
        Ok(t) => t,
        Err(e) => cannot_run(&format!("no usable C toolchain: {e}")),
    };
    let environment = env::detect(toolchain.headers_dump(), None, None, None)
        .expect("no attestation was supplied, so classification cannot fail");

    std::fs::write(
        work.dir().join(probe::SELFREPORT_HEADER_NAME),
        probe::SELFREPORT_HEADER,
    )
    .expect("writing the self-report header");
    if !probe.source.is_empty() {
        std::fs::write(work.dir().join(probe.source_name), probe.source)
            .expect("writing probe source");
    }

    let target_arch = toolchain
        .target_arch()
        .unwrap_or_else(|| environment.kernel.arch.clone());
    let conditions = Conditions {
        env: &environment,
        profile,
        toolchain_kind: toolchain.kind,
        target_arch: &target_arch,
        profile_is_clean: Conditions::profile_is_clean(profile),
    };
    let driver = Driver {
        toolchain: &toolchain,
        workdir: work.dir(),
        timeout: Duration::from_secs(60),
        structured: None,
    };
    body(&driver, probe, &conditions)
}

/// Measure one probe end to end, through the library, under a given profile.
fn run_with(probe_id: &str, tag: &str, profile: &Profile) -> Vec<report::Observation> {
    // No `Result` to unwrap: a probe that cannot be measured reports that in its
    // observations rather than destroying the run, which is the property the
    // `unmeasured` path exists to hold.
    with_bench(probe_id, tag, profile, |driver, probe, conditions| {
        measure::run_probe(driver, probe, conditions).observations
    })
}

/// Measure one probe end to end, through the library.
fn run(probe_id: &str, tag: &str) -> Vec<report::Observation> {
    run_with(probe_id, tag, &bare_profile())
}

/// Every control arm that was built publishes what built it.
///
/// The triple is the trust mechanism, and a report that published only an arm's flags, a
/// three-valued outcome and a prose excerpt, with the argv, exit status and artifact digest
/// kept inside the harness, would ask to be believed about it. An `off` rests on the negative arm
/// having demonstrated absence, so a reader who doubts that needs the arm's own build line, and
/// `probe-invalid` is a verdict *about* the arms.
///
/// Publishing both arms grows a report, on the bare profile, from 203,645 to 254,040 bytes on
/// Darwin with Apple clang 21, and under `openssf-tldr` from 409,308 to 499,419 bytes on
/// Fedora 44 x86_64 with gcc 16.1.1, a little under a quarter in both. Retaining each arm's full
/// `evidence` instead costs about two thirds again, which is why that stays on the withheld arms
/// alone.
///
/// Asserted over the arms that were built rather than over all of them: an arm whose
/// build never happened has nothing to publish, and `outcome: None` is how it says so.
/// The probe is a `compiler-diag` one because that channel answers on every host chard
/// runs on; the canary's arms are `elf-static` and produce nothing to examine where the
/// compiler emits Mach-O.
#[test]
fn every_control_arm_that_was_built_publishes_what_built_it() {
    if !can_run("that every control arm publishes its own build record") {
        return;
    }
    let observations = run("implicit-function-declaration", "arm-records");
    let mut examined = 0usize;
    for obs in &observations {
        let Some(controls) = obs.controls.as_ref() else {
            continue;
        };
        let arms = [
            ("positive", &controls.positive),
            ("negative", &controls.negative),
        ];
        for (name, arm) in arms {
            // `outcome: None` is an arm that could not be built or run at all.
            if arm.outcome.is_none() {
                continue;
            }
            let build = arm.build.as_ref().unwrap_or_else(|| {
                panic!(
                    "{}'s {name} arm reported `{:?}` with no build record, so the outcome \
                     cannot be checked against what produced it",
                    obs.check, arm.outcome
                )
            });
            assert!(
                !build.argv.is_empty(),
                "{}'s {name} arm published a build record with no argv",
                obs.check
            );
            examined = examined.saturating_add(1);
        }
    }
    assert!(
        examined > 0,
        "no control arm was examined, so nothing about the arms' records was checked"
    );
    eprintln!("measurement_loop: {examined} control arm(s) carry the line that built them");
}

/// Every control arm publishes the flags that built it, and its build line agrees.
///
/// `controls.*.flags` is the field a reader uses to interpret an arm's `outcome`. It used
/// to leave `decide` empty and be filled in afterwards by the loop, and an arm the loop
/// forgot read as the clean build; the flags now arrive with the detection as a
/// `report::ArmInput`. What is held here is what the loop publishes against what the
/// corpus declares: the plain arms carry exactly the check's control lists, the regime
/// arm carries the profile's flags followed by the arm the check declares, and every flag an arm
/// claims is in its build's argv or named in `dropped_flags`, the reconciliation the
/// dropped-flag test performs for the profile. The compiler-diag probe answers on every
/// host and floors the count; the canary supplies elf-static arms where the host emits
/// ELF, and `auto-var-init` under a hardened profile supplies the regime arm.
#[test]
fn every_control_arm_publishes_the_flags_that_built_it() {
    if !can_run("that every control arm publishes the flags that built it") {
        return;
    }
    let plain = bare_profile();
    let hardened = profile_with_flags(&["-O2", "-fstack-protector-strong"]);
    let runs: Vec<(Vec<report::Observation>, &Profile)> = vec![
        (run("implicit-function-declaration", "flags-diag"), &plain),
        (run("stack-canary", "flags-canary"), &plain),
        (
            run_with("auto-var-init", "flags-regime", &hardened),
            &hardened,
        ),
    ];

    let mut examined = 0usize;
    let mut regime_examined = 0usize;
    for (observations, profile) in &runs {
        for obs in observations {
            let Some(controls) = obs.controls.as_ref() else {
                continue;
            };
            let (probe, check) = probe::CORPUS
                .iter()
                .find_map(|p| p.checks.iter().find(|c| c.id == obs.check).map(|c| (p, c)))
                .unwrap_or_else(|| panic!("{} is not a check in the corpus", obs.check));
            assert_eq!(
                controls.positive.flags, check.positive,
                "{}: the positive arm claims flags other than the declared control",
                obs.check
            );
            assert_eq!(
                controls.negative.flags, check.negative,
                "{}: the negative arm claims flags other than the declared control \
                 (empty exactly when the clean build stood in)",
                obs.check
            );
            let mut arms = vec![
                ("positive", &controls.positive),
                ("negative", &controls.negative),
            ];
            if let Some(arm) = controls.regime_negative.as_ref() {
                let declared = check.regime_arm().unwrap_or_else(|| {
                    panic!("{}: publishes a regime arm and declares none", obs.check)
                });
                assert_eq!(
                    arm.flags,
                    measure::variant_flags(profile, probe.lang, declared),
                    "{}: the regime arm claims flags other than the profile plus the \
                     declared arm",
                    obs.check
                );
                regime_examined = regime_examined.saturating_add(1);
                arms.push(("regime_negative", arm));
            }
            for (name, arm) in arms {
                let Some(build) = arm.build.as_ref() else {
                    continue;
                };
                for flag in &arm.flags {
                    assert!(
                        build.argv.contains(flag) || build.dropped_flags.contains(flag),
                        "{}'s {name} arm claims `{flag}` and its build neither passed it nor \
                         names it dropped. argv={:?} dropped={:?}",
                        obs.check,
                        build.argv,
                        build.dropped_flags
                    );
                }
                examined = examined.saturating_add(1);
            }
        }
    }
    assert!(
        examined > 0,
        "no built control arm was examined, so nothing about the flags was checked"
    );
    if common::ELF_HOST {
        assert!(
            regime_examined > 0,
            "no regime arm was examined, so the profile-dependent flags went unchecked"
        );
    } else if regime_examined == 0 {
        common::capability_gap(
            "the regime arm's flags",
            "no regime arm was built for auto-var-init on this host",
        );
    }
    eprintln!(
        "measurement_loop: {examined} built control arm(s) carry the flags that built them, \
         {regime_examined} of them regime arms"
    );
}

/// `zero-call-used-regs` owes a regime arm, and the arm reads `absent` under the guide's own
/// flags.
///
/// The arm is the profile followed by `-fzero-call-used-regs=skip`, which wins last on the
/// line; no profile flag is known to clear the registers by another route (the check's
/// comment names the one measured not to), so under `-O2 -fzero-call-used-regs=used-gpr`,
/// what `openssf-tldr` carries on x86_64 and aarch64, the arm is built, reads `absent`, and
/// the verdict stays `on`. Under `bare` nothing is owed and no arm is built. The arm's
/// withholding branch is `report::decide`'s and is held by its unit tests; no confounder is
/// known to exercise it here.
#[test]
fn the_zero_call_used_regs_regime_arm_is_built_under_a_profile_and_reads_absent() {
    if !can_run(
        "that zero-call-used-regs builds its regime arm under a profile and reads it absent",
    ) {
        return;
    }
    let guide = profile_with_flags(&["-O2", "-fzero-call-used-regs=used-gpr"]);
    let under_profile = run_with("zero-call-used-regs", "zcur-regime", &guide);
    let o = under_profile
        .iter()
        .find(|o| o.check == "zero-call-used-regs")
        .unwrap_or_else(|| cannot_run("the probe published no zero-call-used-regs observation"));
    let Some(controls) = o.controls.as_ref() else {
        // The check is gated to x86_64 and aarch64; elsewhere it publishes a gating and no
        // triple, and the arm cannot be exercised on this host.
        assert!(
            o.gating.is_some(),
            "{}: neither a triple nor a gating",
            o.check
        );
        common::capability_gap(
            "the zero-call-used-regs regime arm",
            "the check is gated off this host's architecture",
        );
        return;
    };
    let arm = controls
        .regime_negative
        .as_ref()
        .expect("zero-call-used-regs owes a regime arm under a profile that adds flags");
    assert_eq!(
        arm.flags,
        [
            "-O2",
            "-fzero-call-used-regs=used-gpr",
            "-fzero-call-used-regs=skip"
        ],
        "the arm is the profile followed by the declared countermand"
    );
    assert_eq!(
        arm.outcome,
        Some(probe::Outcome::Absent),
        "=skip last on the line clears nothing, so the arm reads absent: {arm:?}"
    );
    assert_eq!(
        (o.verdict, controls.discrimination),
        (Verdict::On, report::Discrimination::Discriminating),
        "the guide's flag reads on, and the arm did not confound it: {controls:?}"
    );
    eprintln!(
        "measurement_loop: zero-call-used-regs under {:?} read {:?} with its regime arm {:?} \
         reading {:?}",
        guide.cflags, o.verdict, arm.flags, arm.outcome
    );
    let mut clean_triples = 0usize;
    for o in run("zero-call-used-regs", "zcur-clean") {
        if let Some(controls) = o.controls.as_ref() {
            clean_triples += 1;
            assert!(
                controls.regime_negative.is_none(),
                "{}: a clean profile has no regime to match",
                o.check
            );
        }
    }
    assert!(
        clean_triples > 0,
        "the clean run published no triple to hold"
    );
}

/// A verdict is only trusted when the controls discriminated, and the report says so.
///
/// The stack canary is the probe used because it is measurable through two channels on
/// every toolchain chard supports, and because its controls are unambiguous:
/// `-fstack-protector-all` must produce the observable and `-fno-stack-protector` must
/// not. If those two ever stop disagreeing, no `off` from this check means anything.
///
/// Deliberately not asserted: which verdict this machine produces. That is a property of
/// whoever packaged the compiler (Fedora's bare `cc` emits no canary, Ubuntu's does)
/// and a test that pinned it would fail on a correctly-working chard measuring a
/// different distribution.
#[test]
fn a_trusted_verdict_carries_controls_that_actually_discriminated() {
    if !can_run("that a trusted verdict rests on controls that actually discriminated") {
        return;
    }
    let observations = run("stack-canary", "canary");
    assert!(
        !observations.is_empty(),
        "the probe produced no observations at all"
    );

    let mut examined = 0usize;
    for obs in &observations {
        // A measurement must rest on controls that disagreed with each other.
        if obs.verdict.is_measurement() {
            let controls = obs
                .controls
                .as_ref()
                .unwrap_or_else(|| panic!("{} is a measurement with no controls", obs.check));
            assert!(
                controls.discriminating(),
                "{} was trusted while its controls did not discriminate: {controls:?}",
                obs.check
            );
            examined = examined.saturating_add(1);
        }
        // And the converse: a check whose controls failed must not report a verdict.
        if let Some(controls) = obs.controls.as_ref()
            && !controls.discriminating()
        {
            assert!(
                !obs.verdict.is_measurement(),
                "{} published `{}` on controls that did not discriminate",
                obs.check,
                obs.verdict.as_str()
            );
        }
    }

    // Without this the test passes on a machine that produced no measurements at all,
    // having verified nothing. The canary is measurable on every toolchain chard
    // supports, so zero here is a harness fault rather than a distribution's choice.
    if common::ELF_HOST {
        assert!(
            examined > 0,
            "no measurement was examined, so nothing about the control triple was checked"
        );
    } else if examined == 0 {
        common::capability_gap(
            "the control-triple floor",
            "this host emits no ELF, so the canary produces no measurement to examine",
        );
    }
}

/// Every check handed in comes back, whatever happened to it.
///
/// The coverage block counts checks against observations, and a check that vanished
/// mid-loop would shrink the numerator and the denominator together: an incomplete
/// measurement that looks complete. Each check must produce exactly one observation,
/// including the ones gated out, which is why `not-applicable` and `unsupported` are
/// verdicts rather than omissions.
#[test]
fn every_check_handed_in_produces_exactly_one_observation() {
    if !can_run("that every check handed in comes back, so coverage cannot shrink silently") {
        return;
    }
    for probe_id in ["stack-canary", "link-defaults", "toolchain-macros"] {
        let probe = probe::find(probe_id).expect("probe in corpus");
        let observations = run(probe_id, &format!("count-{probe_id}"));
        assert_eq!(
            observations.len(),
            probe.checks.len(),
            "{probe_id} was handed {} checks and returned {} observations",
            probe.checks.len(),
            observations.len()
        );
        let ids: Vec<&str> = observations.iter().map(|o| o.check.as_str()).collect();
        for check in probe.checks {
            assert!(ids.contains(&check.id), "{} did not come back", check.id);
        }
    }
}

/// A check gated out by architecture or libc is reported, not dropped, and says why.
///
/// Unlike the invariants above, this one cannot guarantee a sample: whether anything is
/// gated depends on the host's architecture and libc, and on x86_64 with glibc most
/// probes gate nothing. So it asserts the property where it applies and says plainly
/// that finding none is a valid outcome rather than a silent pass.
#[test]
fn a_gated_check_is_reported_with_its_reason() {
    if !can_run("that a gated check is reported with its reason rather than dropped") {
        return;
    }
    for obs in run("link-defaults", "gating") {
        if matches!(obs.verdict, Verdict::Unsupported | Verdict::NotApplicable) {
            let gating = obs
                .gating
                .as_ref()
                .unwrap_or_else(|| panic!("{} was gated with no reason recorded", obs.check));
            assert!(
                !gating.reason.is_empty(),
                "{} was gated with an empty reason",
                obs.check
            );
        }
    }
}

/// A flag the harness removes is named in the build that removed it.
///
/// `profile.cflags` records what the operator asked for. `LinkMode::conflicts_with` then
/// removes what cannot coexist with the probe's output kind (`-pie` and its siblings against
/// `-shared`). Unrecorded, that removal leaves the report naming a flag list some of its
/// builds did not use, and a reader comparing `cflags` against `build.argv` cannot tell a
/// deliberate resolution from a harness bug.
///
/// This is the sibling of an `extra_flags` that *appends* over a stated choice, as with
/// `-fPIC`. Both are the same failure, a report naming a flag list it did not measure, which
/// is the thing chard exists to detect, occurring in chard.
///
/// The assertion is the reconciliation, not the mechanism: everything in `cflags` either
/// reached `argv` or is named in `dropped_flags`.
#[test]
fn a_flag_the_harness_drops_is_recorded_in_the_build_that_dropped_it() {
    if !can_run("that a dropped profile flag is named in the build record") {
        return;
    }
    let work = common::Work::new("loop", "dropped");
    let probe = probe::find("shared-object-defaults").expect("probe is in the corpus");
    let toolchain = match toolchain::detect("cc", work.dir(), false) {
        Ok(t) => t,
        Err(e) => cannot_run(&format!("no usable C toolchain: {e}")),
    };
    let environment = env::detect(toolchain.headers_dump(), None, None, None)
        .expect("no attestation was supplied");
    std::fs::write(
        work.dir().join(probe::SELFREPORT_HEADER_NAME),
        probe::SELFREPORT_HEADER,
    )
    .expect("writing the self-report header");
    std::fs::write(work.dir().join(probe.source_name), probe.source).expect("writing probe source");

    // `-pie` cannot coexist with `-shared`, so the harness must drop it. `-O2` must
    // survive, or the test would pass on a harness that dropped everything.
    let profile = profile_with_flags(&["-pie", "-O2"]);
    let target_arch = toolchain
        .target_arch()
        .unwrap_or_else(|| environment.kernel.arch.clone());
    let conditions = Conditions {
        env: &environment,
        profile: &profile,
        toolchain_kind: toolchain.kind,
        target_arch: &target_arch,
        profile_is_clean: Conditions::profile_is_clean(&profile),
    };
    let driver = Driver {
        toolchain: &toolchain,
        workdir: work.dir(),
        timeout: Duration::from_secs(60),
        structured: None,
    };

    let observations = measure::run_probe(&driver, probe, &conditions).observations;
    let build = observations
        .iter()
        .find_map(|o| o.build.as_ref())
        .unwrap_or_else(|| cannot_run("the probe produced no build record"));

    assert!(
        build.dropped_flags.iter().any(|f| f == "-pie"),
        "`-pie` conflicts with `-shared` and was removed, but the build does not say so. \
         cflags={:?} dropped={:?} argv={:?}",
        profile.cflags,
        build.dropped_flags,
        build.argv
    );
    assert!(
        build.argv.iter().any(|a| a == "-O2"),
        "`-O2` does not conflict with `-shared` and must have survived: argv={:?}",
        build.argv
    );

    // The property, stated over the whole list rather than the one flag: nothing the
    // operator asked for may go missing without being named.
    for flag in &profile.cflags {
        assert!(
            build.argv.contains(flag) || build.dropped_flags.contains(flag),
            "`{flag}` is in profile.cflags but reached neither the build nor dropped_flags, \
             so the report names a flag list it did not measure. argv={:?} dropped={:?}",
            build.argv,
            build.dropped_flags
        );
    }
}

/// A build the *profile* broke is labelled as such, and a build that succeeded is not
/// labelled at all.
///
/// `build-failed` beside an `exit_status: 0` build record is a contradiction a reader
/// cannot resolve, and `build-failed` with no reason at all leaves a bare failure in every
/// cell, on Darwin twenty-three of them, whose single shared cause is reachable only by
/// opening each build's stderr. The classifier itself is unit-tested;
/// what is asserted here is that the loop attaches it, and attaches it only where the
/// verdict says the build is why.
///
/// This arm returns before the first `driver.gather`, so no control is compiled for it.
///
/// On every channel: the compiler-diagnostic checks (`warn-all`, and `pic-shared-link`,
/// whose regime arm the same refusal fails) read the measured build's stderr as their
/// observable, and must withhold on a refused build rather than read it;
/// `Variant::sufficient_for_measured` says why they are held to the profile too.
#[test]
fn a_profile_that_will_not_compile_names_itself_in_every_cell_it_broke() {
    if !can_run("that a build broken by the profile is labelled with the flag that broke it") {
        return;
    }
    let broken = profile_with_flags(&["-fchard-not-a-real-flag"]);
    for probe_id in ["stack-canary", "warn-all", "pic-shared-link"] {
        let observations = run_with(probe_id, &format!("rejected-{probe_id}"), &broken);
        assert!(
            !observations.is_empty(),
            "{probe_id} produced no observations"
        );

        for observation in &observations {
            assert_eq!(
                observation.verdict,
                Verdict::BuildFailed,
                "{}: a flag no compiler accepts must fail the build",
                observation.check
            );
            let named = observation
                .build_rejection
                .as_deref()
                .unwrap_or_else(|| panic!("{}: build-failed with no reason", observation.check));
            assert!(
                named.contains("-fchard-not-a-real-flag"),
                "{}: the reason does not name the flag: {named}",
                observation.check
            );
            assert!(
                observation.controls.is_none(),
                "{}: no control is built for a measured build the driver refused: {:?}",
                observation.check,
                observation.controls
            );
        }
    }

    // The other direction: a verdict the measurement actually reached carries no
    // rejection, whatever the build record says.
    for probe_id in ["stack-canary", "warn-all"] {
        for observation in run(probe_id, &format!("rejected-control-{probe_id}")) {
            if observation.verdict != Verdict::BuildFailed {
                assert!(
                    observation.build_rejection.is_none(),
                    "{} reached {:?} and still blamed the profile: {:?}",
                    observation.check,
                    observation.verdict,
                    observation.build_rejection
                );
            }
        }
    }
}

/// The regime-matched control arm is built when, and only when, all three of its
/// conditions hold.
///
/// The arm re-runs the negative control on top of the profile, to establish that a
/// runtime signal seen in the measured build is attributable to the flag rather than to
/// the regime around it: `-fstack-protector-strong` makes uninitialized locals read as
/// zero, which is also what `-ftrivial-auto-var-init=zero` produces. Building it when it
/// is not wanted costs a compile and a run per check; not building it when it is wanted
/// removes the only constraint standing between a regime artefact and a published `on`.
#[test]
fn the_regime_control_is_built_exactly_when_all_three_conditions_hold() {
    if !can_run("that the regime-matched control arm is built exactly when it is wanted") {
        return;
    }
    let hardened = profile_with_flags(&["-O2", "-fstack-protector-strong"]);

    // A check that requires the arm, under a profile that is not clean.
    let wanted = run_with("auto-var-init", "regime-wanted", &hardened);
    let mut required = 0;
    for observation in &wanted {
        let controls = observation
            .controls
            .as_ref()
            .unwrap_or_else(|| panic!("{}: no controls", observation.check));
        if observation.check.starts_with("auto-var-init-") {
            required += 1;
            assert!(
                controls.regime_negative.is_some(),
                "{}: requires a regime control and none was built",
                observation.check
            );
        }
    }
    assert!(
        required > 0,
        "no check in this probe still requires a regime control, so this test asserts \
         nothing — the corpus has moved"
    );

    // The same checks under a clean profile: the arm would duplicate the profile-free
    // negative, so it is not built.
    for observation in run("auto-var-init", "regime-clean") {
        let controls = observation
            .controls
            .as_ref()
            .unwrap_or_else(|| panic!("{}: no controls", observation.check));
        assert!(
            controls.regime_negative.is_none(),
            "{}: a clean profile has no regime to match",
            observation.check
        );
    }

    // A check that does not require the arm, under the same non-clean profile.
    for observation in run_with("stack-canary", "regime-unwanted", &hardened) {
        if let Some(controls) = observation.controls.as_ref() {
            assert!(
                controls.regime_negative.is_none(),
                "{}: does not require a regime control and one was built",
                observation.check
            );
        }
    }
}

/// A macro the flag list defined itself measures the flag list, and is withheld.
///
/// The control triple cannot catch this and is not failing when it happens: forced on
/// shows the macro, forced off does not, so the detector is demonstrably working. What
/// the triple establishes is that chard can *see* the macro, not that the compiler is
/// the one that set it. `-D__SSP_STRONG__=3` in a supplied flag list satisfies every
/// control and publishes `on (strong)` over a binary with no canary, the false `on`
/// `THREAT_MODEL.md` defends against first.
///
/// Host-independent: the profile forces the macro, so what the machine's own `cc` defines
/// does not enter into it.
#[test]
fn a_macro_the_flag_list_forged_is_withheld_rather_than_published() {
    if !can_run("that a macro supplied by the flag list is not published as the compiler's") {
        return;
    }
    let forged = profile_with_flags(&["-D__SSP_STRONG__=3"]);
    let spoofed = run_with("toolchain-macros", "spoofed", &forged);

    let ssp = spoofed
        .iter()
        .find(|o| o.check == "ssp-level")
        .expect("ssp-level is in the corpus");
    assert_eq!(
        ssp.verdict,
        Verdict::Indeterminate,
        "a forged macro was published as a measurement: {:?}",
        ssp.level
    );
    let reason = &ssp
        .gating
        .as_ref()
        .expect("a withheld observation says why")
        .reason;
    assert!(
        reason.contains("__SSP_STRONG__"),
        "the reason does not name the forged macro: {reason}"
    );

    // A profile that hardens without defining anything is not forging, and must not be
    // withheld: the rule has to distinguish `-D` from the mechanism it imitates.
    let honest = profile_with_flags(&["-fstack-protector-strong"]);
    let measured = run_with("toolchain-macros", "unspoofed", &honest);
    let ssp = measured
        .iter()
        .find(|o| o.check == "ssp-level")
        .expect("ssp-level is in the corpus");
    assert!(
        ssp.gating
            .as_ref()
            .is_none_or(|g| !g.reason.contains("the flag list defines")),
        "a profile that defined no macro was accused of forging one: {:?}",
        ssp.gating
    );
}

/// A `_FORTIFY_SOURCE` request above the guide's `3` is `on` at its own number, end to end.
///
/// Under the one shared ranking table `4` was a word the table lacked, so it fell to string
/// equality against `3` and the cell read `partial`: a request above the ask graded as
/// below it. The scale is numeric now (`probe::FORTIFY_LEVELS`), so the request reads `on`
/// with level `4`, and `fortify-effective` beside it reports what the C library settled,
/// which is the check that says whether `4` bought anything.
///
/// The profile defines `_FORTIFY_SOURCE` itself and is still measured rather than
/// withheld as `macro-supplied-by-profile`: `spoofed_macros` matches only the macros the
/// compiler defines (`__SSP_STRONG__`, `__USE_FORTIFY_LEVEL`, `__PIE__` and their kin),
/// and `_FORTIFY_SOURCE` is the operator's own request, which is what this check reads.
///
/// Host-independent on the request: the macro channel answers on every host chard runs on.
/// The effective level is asserted only as a word on the same scale, because Apple's
/// `<secure/_common.h>` clamps it at `2`, glibc settles `3`, and a musl without
/// fortify-headers declines the request altogether.
#[test]
fn a_fortify_request_above_the_guide_reads_on_at_its_own_number() {
    if !can_run("that a fortify request above the guide's level is on at its own number") {
        return;
    }
    let profile = profile_with_flags(&["-O2", "-D_FORTIFY_SOURCE=4"]);
    let observations = run_with("toolchain-macros", "fortify-four", &profile);
    let find = |id: &str| {
        observations
            .iter()
            .find(|o| o.check == id)
            .unwrap_or_else(|| panic!("{id} is in the corpus"))
    };
    let requested = find("fortify-requested");
    match requested.verdict {
        Verdict::Unsupported | Verdict::ProbeInvalid => {
            common::capability_gap(
                "fortify-requested at _FORTIFY_SOURCE=4",
                &format!(
                    "the toolchain's own controls did not discriminate ({}: {:?})",
                    requested.verdict.as_str(),
                    requested.gating.as_ref().map(|g| g.reason.as_str())
                ),
            );
            return;
        }
        _ => {}
    }
    assert_eq!(
        requested.verdict,
        Verdict::On,
        "a request above the ask was not credited: {:?} {:?}",
        requested.level,
        requested.gating
    );
    assert_eq!(requested.level.as_deref(), Some("4"));
    assert_eq!(requested.recommended_level.as_deref(), Some("3"));
    assert!(
        requested.gating.is_none(),
        "no rule withheld it: {:?}",
        requested.gating
    );

    let effective = find("fortify-effective");
    assert!(
        effective
            .gating
            .as_ref()
            .is_none_or(|g| g.rule != report::gating_rule::LEVEL_OFF_SCALE),
        "the settled level is a number on the same scale: {:?}",
        effective.gating
    );
    if effective.verdict.is_measurement() {
        let level = effective.level.as_deref().unwrap_or_default();
        assert!(
            probe::FORTIFY_LEVELS.admits(level),
            "the settled level `{level}` is a word on the fortify scale"
        );
    }
    eprintln!(
        "measurement_loop: fortify-requested {} level {:?}; fortify-effective {} level {:?}",
        requested.verdict.as_str(),
        requested.level,
        effective.verdict.as_str(),
        effective.level
    );
}

/// An observation carries the macros its own channel reads, and no others.
///
/// The evidence is what a reader reproduces a verdict from, so a macro-channel
/// observation has to carry the macro state and an elf-static one must not: attaching the
/// dump to every observation would put a hundred irrelevant macros beside a verdict taken
/// from a program header, and dropping it from the macro ones leaves a verdict its own
/// evidence cannot support.
#[test]
fn an_observation_carries_the_evidence_its_channel_was_read_from() {
    if !can_run("that an observation's evidence matches the channel its verdict came from") {
        return;
    }
    // Only observations that reached the end of `run_check` have evidence to carry. A
    // check gated as inapplicable (`gcs-macro` on x86_64) returns before the controls
    // are attached, and `controls` is the field that says which of the two happened.
    let mut macro_checks = 0;
    for observation in run("toolchain-macros", "evidence-macro") {
        if observation.controls.is_none() {
            continue;
        }
        macro_checks += 1;
        assert!(
            observation.evidence.macros.is_some(),
            "{}: a macro-channel verdict with no macros in its evidence cannot be \
             reproduced from it",
            observation.check
        );
    }
    assert!(
        macro_checks > 0,
        "no macro-channel check was measured on this host, so this asserts nothing"
    );

    let mut elf_checks = 0;
    for observation in run("link-defaults", "evidence-elf") {
        if observation.controls.is_none() {
            continue;
        }
        elf_checks += 1;
        assert!(
            observation.evidence.macros.is_none(),
            "{}: an elf-static verdict carried a macro dump it did not read",
            observation.check
        );
    }
    if common::ELF_HOST {
        assert!(
            elf_checks > 0,
            "no elf-static check was measured on this host, so this asserts nothing"
        );
    } else if elf_checks == 0 {
        common::capability_gap(
            "the elf-static evidence arm",
            "this host emits no ELF, so no elf-static check reaches a verdict",
        );
    }
}

/// Every observation's build resolves in the store, a macro reading taken from the
/// artifact is the filter over the `.chard.report` its stored facts carry, and no stored
/// fact names the work directory.
///
/// There is one copy of the self-report, inside the stored `elf` entry, and what is held is the
/// claim a reader re-derives from it: the inline macros are the published filter over it.
#[test]
fn every_observation_build_resolves_in_the_store_and_its_self_report_gives_its_macros() {
    if !can_run("that every observation's build has a store entry") {
        return;
    }
    let (outcome, workdir) = with_bench(
        "toolchain-macros",
        "self-report",
        &bare_profile(),
        |driver, probe, conditions| {
            (
                measure::run_probe(driver, probe, conditions),
                driver.workdir.display().to_string(),
            )
        },
    );
    // The store is published as read, so nothing chard chose may be in it: the reason an
    // unreadable entry carries names `<artifact>`, and an ELF reader's facts name no path.
    let stored = serde_json::to_string(&outcome.facts).expect("the store serializes");
    assert!(
        !stored.contains(&workdir),
        "a stored fact names the work directory {workdir}"
    );
    let (mut builds, mut from_artifact) = (0, 0);
    for observation in &outcome.observations {
        let Some(key) = observation
            .build
            .as_ref()
            .and_then(|b| b.artifact_sha256.as_deref())
        else {
            continue;
        };
        builds += 1;
        let entry = outcome.facts.get(key).unwrap_or_else(|| {
            panic!(
                "{}: build sha256:{key} has no entry in the store",
                observation.check
            )
        });
        assert!(
            ["elf", "unreadable"].contains(&entry.kind()),
            "{}: a build's digest names a {} entry",
            observation.check,
            entry.kind()
        );
        if observation.evidence.macro_source.as_deref() == Some("compiled-artifact") {
            from_artifact += 1;
            let report::FactEntry::Elf { elf } = entry else {
                panic!(
                    "{}: read from an artifact the store calls unread",
                    observation.check
                );
            };
            assert_eq!(
                observation.evidence.macros.as_ref(),
                Some(&measure::relevant_macros(
                    &probe::parse_self_report(&elf.self_report)
                        .expect("an artifact's report reads")
                )),
                "{}: the inline macros are not the filter over the stored self-report",
                observation.check
            );
        }
    }
    assert!(
        builds > 0,
        "no observation carried a build, so this asserts nothing"
    );
    if from_artifact == 0 {
        common::capability_gap(
            "self-report in the store",
            "no macro reading came from an artifact, so this platform's container was not read",
        );
    }
}

/// Every evaluated arm of a check that reads artifacts resolves in the store, counted: the
/// arms the triple evaluated (`outcome` present) fed against the arms whose every
/// reference resolved.
///
/// The arms are the part of a run a report can describe least. With their `ElfFacts`
/// unpublished, and their macros published only where the triple withheld, an `off` would
/// rest on a negative arm whose artifact the report does not describe. The wrapper
/// turns `-fstack-protector-strong` into `-fno-stack-protector`, so `ssp-level`'s positive
/// arm is silent and its triple withholds, and the count covers a withheld triple beside
/// the discriminating ones. Nothing is counted on a probe whose measured build could not
/// be read: its checks return before any arm is built.
#[test]
fn every_arm_of_an_artifact_reading_check_resolves_in_the_store() {
    const SILENCE_SSP: &str = r#"for arg do
  shift
  if [ "$arg" = "-fstack-protector-strong" ]; then arg=-fno-stack-protector; fi
  set -- "$@" "$arg"
done
exec "$REAL" "$@""#;
    if !can_run("that every arm an artifact-reading check evaluated has a store entry") {
        return;
    }
    let (mut fed, mut resolved, mut withheld) = (0_usize, 0_usize, 0_usize);
    let mut unresolved: Vec<String> = Vec::new();
    for probe_id in ["toolchain-macros", "link-defaults"] {
        let outcome = with_bench_on(
            Some(SILENCE_SSP),
            probe_id,
            &format!("arms-{probe_id}"),
            &bare_profile(),
            measure::run_probe,
        );
        for observation in &outcome.observations {
            let Some(controls) = observation.controls.as_ref() else {
                continue;
            };
            let check = probe::find(probe_id)
                .and_then(|p| p.checks.iter().find(|c| c.id == observation.check))
                .expect("a corpus check");
            if !report::stores_arm_artifacts(check) {
                continue;
            }
            if !controls.discriminating() {
                withheld += 1;
            }
            let arms = [
                Some(&controls.positive),
                Some(&controls.negative),
                controls.regime_negative.as_ref(),
            ];
            for (name, arm) in ["positive", "negative", "regime"]
                .into_iter()
                .zip(arms)
                .filter_map(|(name, arm)| Some((name, arm?)))
            {
                // Fed from the arms the triple evaluated, not from the references they
                // publish: an evaluated arm whose build digest went missing is one arm fed
                // and none resolved, rather than nothing counted.
                let evaluated = arm.outcome.is_some();
                if evaluated {
                    fed += 1;
                }
                let mut wanted = Vec::new();
                match arm.build.as_ref().and_then(|b| b.artifact_sha256.clone()) {
                    Some(key) => wanted.push((key, &["elf", "unreadable"][..])),
                    None if evaluated => unresolved.push(format!(
                        "{}: the evaluated {name} arm publishes no artifact digest",
                        observation.check
                    )),
                    None => {}
                }
                if arm.macro_source.as_deref() == Some("preprocessor") {
                    match arm
                        .macro_dump
                        .as_ref()
                        .and_then(|d| d.stdout_sha256.clone())
                    {
                        Some(key) => wanted.push((key, &["macro-dump"][..])),
                        None => unresolved.push(format!(
                            "{}: the {name} arm read a dump it names no digest of",
                            observation.check
                        )),
                    }
                }
                let before = unresolved.len();
                for (key, kinds) in wanted {
                    if !outcome
                        .facts
                        .get(&key)
                        .is_some_and(|e| kinds.contains(&e.kind()))
                    {
                        unresolved.push(format!(
                            "{} {name}: sha256:{key} {kinds:?}",
                            observation.check
                        ));
                    }
                }
                if evaluated && unresolved.len() == before {
                    resolved += 1;
                }
            }
        }
    }
    assert!(fed > 0, "no evaluated arm was fed, so this asserts nothing");
    assert_eq!(
        (fed, unresolved.len()),
        (resolved, 0),
        "fed {fed} evaluated arm(s), resolved {resolved}: {unresolved:?}"
    );
    assert!(
        withheld > 0,
        "the wrapper silences ssp-level's positive arm, so a triple must have withheld"
    );
}

/// Every macro and `elf-static` observation that built its triple publishes its measured
/// reading, and every arm with an outcome publishes its own, counted: the readings the
/// loop fed against the readings it published.
///
/// A reading that was only a sentence in `observed` or an arm's `detail` would leave an `off`
/// resting on a negative arm whose reading nothing could replay.
/// `decoded-reading-disagrees-with-facts` replays each one against the store; this
/// holds the loop to publishing them on a real compiler. On a Mach-O host the
/// `elf-static` checks return before their triple, so the count there is the macro
/// channel's, and `cxx-stdlib-assertions` feeds its `elf-static` reading where the C++
/// probe links an ELF artifact.
#[test]
fn every_predicate_reading_the_loop_took_is_published() {
    if !can_run("that every predicate reading a triple took is published as a value") {
        return;
    }
    let (mut fed, mut published, mut observations) = (0_usize, 0_usize, 0_usize);
    let mut missing: Vec<String> = Vec::new();
    for probe_id in ["toolchain-macros", "link-defaults", "cxx-stdlib-assertions"] {
        let outcome = with_bench(
            probe_id,
            &format!("decoded-{probe_id}"),
            &bare_profile(),
            measure::run_probe,
        );
        for observation in &outcome.observations {
            let check = probe::find(probe_id)
                .and_then(|p| p.checks.iter().find(|c| c.id == observation.check))
                .expect("a corpus check");
            if check.predicate().is_none() {
                assert!(
                    observation.evidence.decoded.is_none(),
                    "{}: a code decoder publishes no predicate reading",
                    observation.check
                );
                continue;
            }
            let Some(controls) = observation.controls.as_ref() else {
                continue;
            };
            observations += 1;
            let mut readings = vec![("evidence", observation.evidence.decoded.as_ref())];
            for (name, arm) in controls.arms() {
                if arm.outcome.is_some() {
                    readings.push((name, arm.decoded.as_ref()));
                }
            }
            for (name, decoded) in readings {
                fed += 1;
                match decoded {
                    Some(_) => published += 1,
                    None => missing.push(format!("{}: {name}", observation.check)),
                }
            }
            for (name, arm) in controls.arms() {
                if let Some(decoded) = arm.decoded.as_ref() {
                    assert_eq!(
                        arm.outcome,
                        Some(decoded.outcome),
                        "{}: the {name} arm's outcome is its reading's",
                        observation.check
                    );
                }
            }
        }
    }
    assert!(
        observations > 0 && fed > observations,
        "fed {fed} reading(s) over {observations} observation(s), so this asserts nothing"
    );
    assert_eq!(
        fed, published,
        "fed {fed} reading(s), published {published}: {missing:?}"
    );
}

/// `gather` collects a macro dump only for a probe that has a macro-channel check, and
/// prefers the compiled artifact's own report over a separate preprocessor job.
///
/// `-dM -E` is driven by `*cpp_options` and code generation by `*cc1_options`, so a spec
/// file patching one and not the other makes them disagree; and the artifact is the side
/// that decides what the code does. Reading the section is also what makes the swap
/// visible: relabelling the source while assigning an empty map would report the stronger
/// provenance over the weaker evidence.
#[test]
fn gather_reads_macros_only_where_a_check_needs_them_and_prefers_the_artifact() {
    if !can_run("that gather collects macros only where a check reads them") {
        return;
    }
    let bare = bare_profile();
    with_bench(
        "toolchain-macros",
        "gather-macros",
        &bare,
        |driver, probe, _| {
            let variant = driver
                .gather(probe, &[], "clean")
                .expect("the probe builds on a working toolchain");
            assert!(
                !variant.macros_preprocessor.is_empty(),
                "a probe whose checks are all macro-channel got no preprocessor dump"
            );
            if variant.elf.is_some() {
                assert_eq!(
                    variant.macro_source, "compiled-artifact",
                    "an artifact carrying a self-report is the stronger source and was not used"
                );
                assert!(
                    !variant.macros.is_empty(),
                    "the source was relabelled `compiled-artifact` over an empty map, so the \
                 provenance claims more than the evidence carries"
                );
            } else {
                common::capability_gap(
                    "compiled-artifact macro source",
                    "the artifact carried no ELF facts, so this platform's container was not read",
                );
            }
        },
    );

    with_bench(
        "link-defaults",
        "gather-nomacros",
        &bare,
        |driver, probe, _| {
            let variant = driver
                .gather(probe, &[], "clean")
                .expect("the probe builds on a working toolchain");
            assert!(
                variant.macros_preprocessor.is_empty(),
                "a probe with no macro-channel check paid for a preprocessor job it never reads"
            );
        },
    );
}

/// A build that exits 0 and writes nothing leaves no artifact, and no fabricated reason
/// for one.
///
/// `-fsyntax-only` is the honest way to reach it (a caller can ask for it through
/// `--profile explicit`) and a wrapper that swallows `-o` is the hostile one. Both the
/// ELF read and the run must be skipped: reaching for a file that is not there produces
/// an `elf_error`, which reports a harness fault chard did not have and sends a reader
/// looking for an unreadable artifact that was never written.
#[test]
fn a_build_that_produced_no_artifact_is_not_read_as_an_unreadable_one() {
    if !can_run("that a build producing no artifact is not reported as an unreadable one") {
        return;
    }
    let syntax_only = profile_with_flags(&["-fsyntax-only"]);
    with_bench(
        "link-defaults",
        "syntax-only",
        &syntax_only,
        |driver, probe, conditions| {
            let flags = measure::variant_flags(conditions.profile, probe.lang, &[]);
            let variant = driver
                .gather(probe, &flags, "measured")
                .expect("the compiler accepted -fsyntax-only");
            let build = variant.build.as_ref().expect("a build was attempted");
            assert!(
                build.succeeded(),
                "-fsyntax-only should compile cleanly: {}",
                build.stderr
            );
            assert!(
                build.artifact_sha256.is_none(),
                "-fsyntax-only wrote an artifact, so this no longer reaches the case"
            );
            assert!(
                variant.elf_error.is_none(),
                "no artifact was written and chard reported one it could not read: {:?}",
                variant.elf_error
            );
            assert!(variant.elf.is_none());
            assert!(
                variant.run.is_none(),
                "an artifact that does not exist was executed"
            );
        },
    );
}

/// One compiler stream measured under two work directories publishes one excerpt.
///
/// The decoder tests pin the cut against hand-built evidence; this one pins that a real
/// measurement hands the detectors the directory the cut is made relative to. A gather
/// path that dropped it, or built its variant without it, would cut the captured stream
/// again, and the excerpt would move with `--workdir` (`probe::Evidence::published` has
/// the fleet measurement that found it). The probe's own stream is under the excerpt
/// budget once its paths are made relative, and the compiler is handed
/// the source by its file name and quotes no work directory at all (`compile::build`);
/// the wrapper appends lines naming the source by its absolute path, so every build of
/// the probe is over budget whatever the directory, and the work directory is in the
/// stream the cut is made from. Under directories that differ in length by 120 characters, the published
/// `observed` strings and the positive arm's `detail` carry a cut marker and are
/// byte-identical. Measured on 2026-10-01 on macOS arm64 with Apple clang: with
/// `Driver::gather` handing the detectors no work directory, the test fails on the
/// positive arm's `detail`, which then counts 3298 characters omitted under the shorter
/// directory and 6697 under the longer. The counts include the temporary directories'
/// paths, whose length differs between runs, so another run reads other figures; a
/// review's run of the same break read 3323 and 6723. With the `detail` assertion also
/// disabled, that review's run failed on `observed`, whose cut under the longer directory
/// left a fragment of the directory's name that the byte-equality assertion catches and
/// the `contains` check on the whole directory does not.
#[test]
fn one_measurement_under_two_work_directories_publishes_one_excerpt() {
    if !can_run("that a measured excerpt does not depend on the work directory") {
        return;
    }
    let wrapper = r#""$REAL" "$@"
status=$?
dir=$(dirname "$0")
case " $* " in
*" implicit_fallthrough.c "*)
    for i in $(seq 1 24); do
        printf '%s/implicit_fallthrough.c:1:1: note: a path-bearing line %s\n' "$dir" "$i" >&2
    done
    ;;
esac
exit $status
"#;
    let measure = |tag: &str| {
        with_bench_on(
            Some(wrapper),
            "implicit-fallthrough",
            tag,
            &bare_profile(),
            |driver, probe, conditions| {
                let dir = driver.workdir.display().to_string();
                let observations = measure::run_probe(driver, probe, conditions).observations;
                let published: Vec<(String, String, String)> = observations
                    .iter()
                    .map(|o| {
                        let value = serde_json::to_value(o).expect("an observation serializes");
                        let text = |v: &serde_json::Value| v.as_str().unwrap_or("").to_owned();
                        (
                            o.check.clone(),
                            text(&value["evidence"]["observed"]),
                            text(&value["controls"]["positive"]["detail"]),
                        )
                    })
                    .collect();
                (dir, published)
            },
        )
    };
    let (short_dir, short) = measure("cut");
    let (long_dir, long) = measure(&format!("cut-{}", "w".repeat(120)));
    assert!(
        long_dir.len() > short_dir.len().saturating_add(100),
        "the two work directories differ in length: {short_dir} {long_dir}"
    );
    assert!(!short.is_empty(), "the probe returned no observation");
    let marker = chard::probe::CUT_MARKER;
    for ((check, observed, detail), (_, long_observed, long_detail)) in short.iter().zip(&long) {
        assert!(
            detail.contains(marker),
            "{check}: the positive arm's stream must be over budget for the cut to be exercised: {detail}"
        );
        assert!(
            observed.contains(marker),
            "{check}: the observed stream must be over budget for the cut to be exercised: {observed}"
        );
        assert!(
            !detail.contains(&short_dir) && !long_detail.contains(&long_dir),
            "{check}: the published detail names no work directory"
        );
        assert_eq!(
            detail, long_detail,
            "{check}: the positive arm's excerpt does not depend on the work directory"
        );
        assert_eq!(
            observed, long_observed,
            "{check}: the observed excerpt does not depend on the work directory"
        );
    }
}
