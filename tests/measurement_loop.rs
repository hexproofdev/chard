// SPDX-License-Identifier: BSD-3-Clause

//! Drive the measurement loop directly, without the CLI.

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

use std::time::Duration;

mod common;

use chard::env;
use chard::measure::{self, Conditions, Driver};
use chard::probe;
use chard::report::{self, Profile, Verdict};
use chard::toolchain;

/// A work directory that is removed when the test ends.
/// Can this machine drive the measurement loop? Checked once, at the top of each test.
fn can_run(verifies: &str) -> bool {
    common::require_cc(verifies)
}

/// A failure that arrived after [`can_run`] said the machine was capable.
fn cannot_run(reason: &str) -> ! {
    panic!("cannot drive the measurement loop ({reason}) with a C compiler present");
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
    with_bench_as(wrapper, None, true, probe_id, tag, profile, body)
}

/// [`with_bench_on`] with the execution mode the operator would assert (`None` leaves it
/// to what chard observes) and with or without the run's witness. A run without one is
/// what a macOS run is (`measure::Driver::witness`), stood up here on any host so that
/// what the loop does with an artifact the reader refused, there, has a live reading.
fn with_bench_as<T>(
    wrapper: Option<&str>,
    execution: Option<env::ExecutionMode>,
    witnessed: bool,
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
    let environment = env::detect(toolchain.headers_dump(), execution, None, None)
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
    let witness = chard::compile::RunWitness::derived_in(["measurement-loop"], work.dir())
        .expect("writing the run-witness header");
    let driver = Driver {
        toolchain: &toolchain,
        workdir: work.dir(),
        timeout: Duration::from_secs(60),
        structured: None,
        witness: witnessed.then_some(&witness),
    };
    body(&driver, probe, &conditions)
}

/// The real driver builds everything, and where it linked an executable the wrapper moves
/// it aside and writes a shell script that execs it in its place, so the probe runs as
/// built while chard's reader refuses the artifact it is handed.
const SCRIPT_IN_PLACE_OF_THE_EXECUTABLE: &str = r#"out=""; link=1; prev=""
for a in "$@"; do
  case "$a" in -c|-S|-E|-fsyntax-only|-shared|-M|-MM|-dM) link=0;; esac
  [ "$prev" = "-o" ] && out="$a"
  case "$a" in -o?*) out="${a#-o}";; esac
  prev="$a"
done
"$REAL" "$@" || exit $?
if [ "$link" = 1 ] && [ -n "$out" ] && [ "$out" != "-" ] && [ -f "$out" ]; then
  mv "$out" "$out.real"
  printf '#!/bin/sh\nLINE\nexec "%s" "$@"\n' "$(realpath "$out.real")" > "$out"
  chmod +x "$out"
fi
exit 0"#;

/// A probe's observations over builds whose executable is a script the reader refuses
/// ([`SCRIPT_IN_PLACE_OF_THE_EXECUTABLE`], the script running `line` before the probe), on
/// a run with no witness and the kernel asserted the host's, so a `needs_vm` check reaches
/// its run.
fn over_a_refused_record(probe_id: &str, tag: &str, line: &str) -> Vec<report::Observation> {
    let script = SCRIPT_IN_PLACE_OF_THE_EXECUTABLE.replace("LINE", line);
    with_bench_as(
        Some(&script),
        Some(env::ExecutionMode::Host),
        false,
        probe_id,
        tag,
        &bare_profile(),
        |driver, probe, conditions| measure::run_probe(driver, probe, conditions).observations,
    )
}

/// What a check's run reading rests on, by the check's id.
fn run_basis(check: &str) -> Option<probe::RunBasis> {
    probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == check)
        .and_then(probe::Check::run_basis)
}

#[test]
fn a_machine_reading_over_a_refused_artifact_is_withheld_on_a_run_without_a_witness() {
    if !can_run("that an artifact the reader refuses withholds a machine reading") {
        return;
    }
    let (mut machine, mut program) = (0, 0);
    for probe_id in ["stack-clash", "stack-exec-runtime", "ub-null-check"] {
        for o in over_a_refused_record(probe_id, &format!("refused-{probe_id}"), ":") {
            let rule = o.gating.as_ref().map(|g| g.rule.id);
            assert_ne!(
                rule,
                Some("artifact-lacks-run-witness"),
                "{}: a run with no witness withheld for one",
                o.check
            );
            match run_basis(&o.check) {
                Some(probe::RunBasis::Machine) => {
                    machine += 1;
                    assert_eq!(o.verdict, Verdict::Indeterminate, "{}", o.check);
                    assert_eq!(rule, Some("run-under-emulation"), "{}", o.check);
                    let reason = &o.gating.as_ref().expect("a gating").reason;
                    assert!(
                        reason.contains("the reader refused it")
                            && reason.contains("not an ELF file"),
                        "{}: the reason quotes the reader's refusal: {reason}",
                        o.check
                    );
                }
                Some(probe::RunBasis::Program) => {
                    program += 1;
                    assert_ne!(rule, Some("run-under-emulation"), "{}", o.check);
                }
                None => {}
            }
        }
    }
    assert!(
        machine >= 2 && program >= 1,
        "{machine} machine reading(s) and {program} program reading(s) over refused records"
    );
}

#[test]
fn a_translation_line_off_macos_settles_nothing_on_a_run_without_a_witness() {
    if !can_run("that a translation line off macOS settles nothing") {
        return;
    }
    if cfg!(target_os = "macos") {
        common::capability_gap(
            "a translation line off macOS",
            "this host is macOS, where the line is the instrument and settles the reading",
        );
        return;
    }
    let mut machine = 0;
    for probe_id in ["stack-clash", "stack-exec-runtime"] {
        let line = r#"echo "CHARD-TRANSLATION 0""#;
        for o in over_a_refused_record(probe_id, &format!("translation-{probe_id}"), line) {
            if run_basis(&o.check) != Some(probe::RunBasis::Machine) {
                continue;
            }
            let opens_with_the_line = o
                .run
                .as_ref()
                .is_some_and(|run| run.stdout.starts_with("CHARD-TRANSLATION 0"));
            if !opens_with_the_line {
                continue;
            }
            machine += 1;
            assert_eq!(o.verdict, Verdict::Indeterminate, "{}", o.check);
            let gating = o.gating.as_ref().expect("a gating");
            assert_eq!(gating.rule.id, "run-under-emulation", "{}", o.check);
            assert!(
                gating.reason.contains("the reader refused it")
                    && !gating.reason.contains("proc_translated"),
                "{}: the reason without the line's clause: {}",
                o.check,
                gating.reason
            );
        }
    }
    assert!(
        machine >= 1,
        "no machine reading ran with the line in its stdout"
    );
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
                    "{}'s {name} arm reported `{:?}` with no build record",
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
                "{}: the negative arm claims flags other than the declared control",
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
                    "{}: the regime arm claims flags other than the profile plus the declared arm",
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
                        "{}'s {name} arm claims `{flag}`, in neither argv={:?} nor dropped={:?}",
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
    // having verified nothing.
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

    // `-pie` cannot coexist with `-shared`, so the harness must drop it.
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
    let witness = chard::compile::RunWitness::derived_in(["measurement-loop"], work.dir())
        .expect("writing the run-witness header");
    let driver = Driver {
        toolchain: &toolchain,
        workdir: work.dir(),
        timeout: Duration::from_secs(60),
        structured: None,
        witness: Some(&witness),
    };

    let observations = measure::run_probe(&driver, probe, &conditions).observations;
    let build = observations
        .iter()
        .find_map(|o| o.build.as_ref())
        .unwrap_or_else(|| cannot_run("the probe produced no build record"));

    assert!(
        build.dropped_flags.iter().any(|f| f == "-pie"),
        "`-pie` beside `-shared` is not named dropped: cflags={:?} dropped={:?} argv={:?}",
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
            "`{flag}` of profile.cflags is in neither argv={:?} nor dropped={:?}",
            build.argv,
            build.dropped_flags
        );
    }
}

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
        "no check in this probe requires a regime control, so this test asserts nothing"
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

#[test]
fn an_observation_carries_the_evidence_its_channel_was_read_from() {
    if !can_run("that an observation's evidence matches the channel its verdict came from") {
        return;
    }
    // Only observations that reached the end of `run_check` have evidence to carry.
    let mut macro_checks = 0;
    for observation in run("toolchain-macros", "evidence-macro") {
        if observation.controls.is_none() {
            continue;
        }
        macro_checks += 1;
        assert!(
            observation.evidence.macros.is_some(),
            "{}: a macro-channel verdict with no macros in its evidence",
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
                    "the source was relabelled `compiled-artifact` over an empty map"
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
    let marker = probe::CUT_MARKER;
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
