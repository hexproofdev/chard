// SPDX-License-Identifier: BSD-3-Clause

//! Measurements taken through a driver that misbehaves in one named way.

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

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use std::ffi::OsStr;

mod common;

use common::chard_binary;

fn can_run(verifies: &str) -> bool {
    common::require_binary(&chard_binary(), verifies) && common::require_cc(verifies)
}

/// The real driver the wrapper proxies to, as an absolute path.
fn real_cc() -> String {
    let output = Command::new("sh")
        .args(["-c", "command -v cc"])
        .output()
        .expect("sh is available");
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(
        output.status.success() && !path.is_empty(),
        "`can_run` said a C compiler is present and `command -v cc` found none"
    );
    path
}

/// Write a wrapper whose body is `script`, with `$REAL` bound to the host's `cc`.
fn fake_driver(work: &Path, script: &str) -> PathBuf {
    fake_driver_named(work, "fakecc", &real_cc(), script)
}

/// [`fake_driver`] under a name of the test's choosing, proxying to `real`.
fn fake_driver_named(work: &Path, name: &str, real: &str, script: &str) -> PathBuf {
    common::executable(&work.join(name), &format!("REAL='{real}'\n{script}"))
}

/// The real C++ driver beside the host's `cc`, as an absolute path; `None` on a host
/// with `cc` and no `c++`, which is an environment gap for the caller to announce
/// through `common::capability_gap`, the same way a missing `ld.lld` is.
fn real_cxx() -> Option<String> {
    let output = Command::new("sh")
        .args(["-c", "command -v c++"])
        .output()
        .expect("sh is available");
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && !path.is_empty()).then_some(path)
}

/// Does the report's toolchain target x86_64, where `linker-default-execstack` builds?
fn targets_x86_64(report: &Value) -> bool {
    report["toolchain"]["target_triple"]
        .as_str()
        .is_some_and(|t| t.starts_with("x86_64") || t.starts_with("amd64"))
}

/// Off x86_64, `linker-default-execstack` is gated in every one of its observations, under
/// the one rule the mechanism table decides for the report's target (`arch-gated` where the
/// target lacks the mechanism, `no-check-on-target` where it has one no check reads there, as
/// on aarch64, `arch-outside-table` where the table has no row), and the linker's evidence
/// names it as a probe that contributed no artifact.
fn assert_default_probe_gated(report: &Value) {
    let gated: Vec<&Value> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o["probe"].as_str() == Some("linker-default-execstack"))
        .collect();
    assert!(
        !gated.is_empty(),
        "the probe was selected, so it has observations: {}",
        report["coverage"]
    );
    let arch = report["toolchain"]["target"]["arch"]
        .as_str()
        .expect("the report names the architecture the gate read");
    for o in gated {
        let check = o["check"].as_str().expect("an observation names its check");
        let expected = match chard::mechanism::decide(check, arch) {
            chard::mechanism::Decision::Absent { .. } => "arch-gated",
            chard::mechanism::Decision::Unread { .. } => "no-check-on-target",
            chard::mechanism::Decision::Outside => "arch-outside-table",
            chard::mechanism::Decision::Measured => {
                panic!("{check} is measured on {arch}, so this assertion's premise fails: {o}")
            }
        };
        assert_eq!(
            o["gating"]["rule"].as_str(),
            Some(expected),
            "off x86_64 the probe is not gated by the table's decision for {arch}: {o}"
        );
    }
    let evidence = report["toolchain"]["linker"]["artifact"]["evidence"]
        .as_str()
        .unwrap_or("");
    assert!(
        evidence.contains("contributed no readable artifact")
            && evidence.contains("linker-default-execstack"),
        "a probe that contributed no artifact is named: {evidence}"
    );
}

/// Is `program` on `PATH`?
fn on_path(program: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Measure one probe through `driver` and return the report.
fn measure(driver: &Path, workdir: &Path, args: &[&str]) -> Value {
    measure_in_env(driver, workdir, args, &[])
}

/// [`measure`], and, where the report reads `host` on an `assumed-host` basis and `args`
/// selects a probe carrying a check that declares `needs_vm`, [`measure`] again with
/// `--execution host` in a fresh workdir inside the first (`asserted-host`), handing back
/// that report, whose basis is held to be the asserted one.
fn measure_establishing_the_kernel(driver: &Path, workdir: &Path, args: &[&str]) -> Value {
    let report = measure(driver, workdir, args);
    let by_default = report["environment"]["execution"]["mode_evidence"]["basis"].as_str()
        == Some("assumed-host");
    let reads_kernel_policy = args.windows(2).any(|pair| {
        pair[0] == "--probe"
            && chard::probe::find(pair[1]).is_some_and(|p| p.checks.iter().any(|c| c.gate.needs_vm))
    });
    if !(by_default && reads_kernel_policy) {
        return report;
    }
    let again = workdir.join("asserted-host");
    std::fs::create_dir_all(&again).expect("a second workdir inside the first");
    let mut asserted: Vec<&str> = args.to_vec();
    asserted.extend(["--execution", "host"]);
    let report = measure(driver, &again, &asserted);
    assert_eq!(
        report["environment"]["execution"]["mode_evidence"]["basis"].as_str(),
        Some("asserted-but-unobservable"),
        "the second run is on the operator's word: {}",
        report["environment"]["execution"]
    );
    report
}

/// The probe deadline every measurement in this file runs under (`--timeout`): long enough
/// that load alone cannot reach it, short enough that a probe that really hangs still ends the
/// test. Every measurement here passes it: `.arg("measure")` is followed by
/// `.args(PROBE_DEADLINE)`, and an argument list naming `"measure"` carries both words.
const PROBE_DEADLINE: [&str; 2] = ["--timeout", "60"];

/// [`measure`], with `envs` set in chard's own environment.
fn measure_in_env(driver: &Path, workdir: &Path, args: &[&str], envs: &[(&str, &Path)]) -> Value {
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .args(["-o", "-"])
        .arg("--cc")
        .arg(driver)
        .arg("--workdir")
        .arg(workdir)
        .args(args)
        .envs(envs.iter().map(|(k, v)| (*k, *v)))
        .output()
        .expect("spawning chard");
    let text = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    assert!(
        parsed.get("error").is_none(),
        "chard refused to measure through the wrapper: {}",
        parsed["error"]
    );
    parsed
}

fn macro_observations(report: &Value) -> Vec<&Value> {
    let observations = report["observations"]
        .as_array()
        .expect("observations is an array");
    let macro_channel: Vec<&Value> = observations
        .iter()
        .filter(|o| o["channel"].as_str() == Some("macro"))
        .collect();
    assert!(
        !macro_channel.is_empty(),
        "no macro-channel observation was produced, so nothing here is being tested"
    );
    macro_channel
}

#[test]
fn a_macro_dump_that_exits_nonzero_withholds_every_macro_verdict() {
    if !can_run(
        "that a failing preprocessor dump withholds the macro channel rather than publishing over its prefix",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "dump-exits-1");
    let driver = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*macros-toolchain-macros-*)
    "$REAL" "$@"
    echo "fakecc: fatal error: late.h: No such file or directory" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
    );

    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "toolchain-macros"],
    );

    for obs in macro_observations(&report) {
        let check = obs["check"].as_str().unwrap_or("?");
        if obs["gating"]["rule"].as_str() == Some("arch-gated") {
            continue;
        }
        assert_eq!(
            obs["verdict"].as_str(),
            Some("indeterminate"),
            "{check}: a verdict was published over a dump that exited 1"
        );
        assert_eq!(
            obs["evidence"]["macro_dump"]["exit_status"].as_i64(),
            Some(1),
            "{check}: the dump's own record must be attached, with its exit status"
        );
        let observed = obs["evidence"]["observed"].as_str().unwrap_or("");
        assert!(
            observed.contains("exited 1") && observed.contains("late.h"),
            "{check}: the observation must name the exit status and the stderr line: {observed}"
        );
        // The defines the dump printed before failing are not evidence, and are not
        // published as such.
        assert!(
            obs["evidence"].get("macros").is_none(),
            "{check}: macros were published from a dump that failed"
        );
    }

    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    assert!(
        diagnostics.iter().any(|d| {
            d["severity"].as_str() == Some("error")
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("exited 1") && m.contains("late.h"))
        }),
        "no error diagnostic names the failed dump: {diagnostics:?}"
    );
    assert_eq!(
        report["coverage"]["checks_valid"].as_u64(),
        Some(0),
        "a check read through a failed dump has not been validated"
    );
}

#[test]
fn a_macro_dump_that_defines_nothing_withholds_every_macro_verdict() {
    if !can_run("that an empty preprocessor dump withholds the macro channel and says so") {
        return;
    }
    let work = common::Work::new("fakedriver", "dump-empty");
    let driver = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*macros-toolchain-macros-*) exit 0 ;;
esac
exec "$REAL" "$@""#,
    );

    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "toolchain-macros"],
    );

    for obs in macro_observations(&report) {
        let check = obs["check"].as_str().unwrap_or("?");
        if obs["gating"]["rule"].as_str() == Some("arch-gated") {
            continue;
        }
        assert_eq!(
            obs["verdict"].as_str(),
            Some("indeterminate"),
            "{check}: a verdict was published from a dump that defined nothing"
        );
        assert_eq!(
            obs["evidence"]["macro_dump"]["exit_status"].as_i64(),
            Some(0)
        );
        let observed = obs["evidence"]["observed"].as_str().unwrap_or("");
        assert!(
            observed.contains("defined no macros"),
            "{check}: the observation must say the dump was empty: {observed}"
        );
    }
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    assert!(
        diagnostics.iter().any(|d| d["message"]
            .as_str()
            .is_some_and(|m| m.contains("defined no macros"))),
        "no diagnostic names the empty dump: {diagnostics:?}"
    );
}

#[test]
fn a_control_arm_whose_dump_fails_names_the_dump_and_carries_its_record() {
    if !can_run(
        "that an unevaluable control arm names the dump that failed it and keeps its record",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "arm-dump-exits-1");
    let driver = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*macros-toolchain-macros-*-pos.c*)
    "$REAL" "$@"
    echo "fakecc: fatal error: late.h: No such file or directory" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
    );

    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "toolchain-macros"],
    );

    for obs in macro_observations(&report) {
        let check = obs["check"].as_str().unwrap_or("?");
        if obs["gating"]["rule"].as_str() == Some("arch-gated") {
            continue;
        }
        // The measured variant's own dump was fine, and its record says so.
        assert_eq!(
            obs["evidence"]["macro_dump"]["exit_status"].as_i64(),
            Some(0),
            "{check}: the measured dump was not the one the wrapper failed"
        );
        let controls = &obs["controls"];
        assert_eq!(
            controls["discriminating"].as_bool(),
            Some(false),
            "{check}: a triple whose positive arm could not be read must not discriminate"
        );
        assert_eq!(
            controls["withheld_because"].as_str(),
            Some("positive-unevaluable"),
            "{check}: {controls}"
        );
        let detail = controls["positive"]["detail"].as_str().unwrap_or("");
        assert!(
            detail.contains("exited 1") && detail.contains("late.h"),
            "{check}: the arm must name the dump that failed it: {controls}"
        );
        assert_eq!(
            controls["positive"]["macro_dump"]["exit_status"].as_i64(),
            Some(1),
            "{check}: the arm's dump record must travel with the withheld arm: {controls}"
        );
        // The dump's defines are not carried, and the note in their place says so.
        assert!(
            obs["evidence"]["macro_dump"]["stdout"]
                .as_str()
                .is_some_and(|s| s.contains("#define line(s) omitted")),
            "{check}: the measured dump's defines were published whole"
        );
    }
}

#[test]
fn a_macro_reading_beside_a_measured_build_that_failed_to_link_is_withheld() {
    if !can_run("that a macro reading beside a failed measured build is withheld") {
        return;
    }
    let work = common::Work::new("fakedriver", "measured-link-fails");
    let driver = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*) exec "$REAL" "$@" ;;
  *toolchain-macros-measured*)
    echo "ld: unknown options: -z" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
    );

    let report = measure_probes_under(
        &driver,
        work.dir(),
        &["--profile", "openssf-tldr"],
        &["toolchain-macros"],
    );

    let mut withheld = 0;
    for obs in macro_observations(&report) {
        let check = obs["check"].as_str().unwrap_or("?");
        if obs["gating"]["rule"].as_str() == Some("arch-gated") {
            continue;
        }
        withheld += 1;
        assert_eq!(
            obs["verdict"].as_str(),
            Some("build-failed"),
            "{check}: a macro verdict was published beside a build that failed: {obs}"
        );
        assert_eq!(
            obs["build"]["exit_status"].as_i64(),
            Some(1),
            "{check}: the failed build travels with the observation"
        );
        assert_eq!(
            obs["evidence"]["macro_dump"]["exit_status"].as_i64(),
            Some(0),
            "{check}: the dump was not the job the wrapper failed"
        );
        let observed = obs["evidence"]["observed"].as_str().unwrap_or("");
        assert!(
            observed.contains("exited 1") && observed.contains("unknown options: -z"),
            "{check}: the observation names the build that failed: {observed}"
        );
        assert!(
            obs["evidence"].get("macros").is_none(),
            "{check}: macros were published beside a build that failed"
        );
        assert!(
            obs.get("controls").is_none_or(Value::is_null),
            "{check}: a withheld measured build reaches no triple"
        );
    }
    assert!(
        withheld > 0,
        "every macro check was arch-gated, so nothing here was tested"
    );
    assert_eq!(
        report["coverage"]["checks_valid"].as_u64(),
        Some(0),
        "a check over a build that failed has not been validated"
    );
}

#[test]
fn a_macro_control_arm_whose_build_failed_is_unevaluable_and_names_the_build() {
    if !can_run("that a macro control arm whose build failed is unevaluable") {
        return;
    }
    let work = common::Work::new("fakedriver", "arm-link-fails");
    let driver = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*) exec "$REAL" "$@" ;;
  *toolchain-macros-*-pos*)
    echo "fakecc: error: linker command failed with exit code 1" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
    );

    let report = measure_probes(&driver, work.dir(), &["toolchain-macros"]);

    let mut unevaluable = 0;
    for obs in macro_observations(&report) {
        let check = obs["check"].as_str().unwrap_or("?");
        if obs["gating"]["rule"].as_str() == Some("arch-gated") {
            continue;
        }
        unevaluable += 1;
        let controls = &obs["controls"];
        assert_eq!(
            controls["withheld_because"].as_str(),
            Some("positive-unevaluable"),
            "{check}: {controls}"
        );
        let verdict = obs["verdict"].as_str();
        assert!(
            verdict != Some("on") && verdict != Some("off"),
            "{check}: a verdict stood on an arm that did not build: {obs}"
        );
        let detail = controls["positive"]["detail"].as_str().unwrap_or("");
        assert!(
            detail.contains("the build exited 1") && detail.contains("linker command failed"),
            "{check}: the arm names the build that failed it: {controls}"
        );
        assert_eq!(
            controls["positive"]["macro_dump"]["exit_status"].as_i64(),
            Some(0),
            "{check}: the arm's dump succeeded and its record says so: {controls}"
        );
    }
    assert!(
        unevaluable > 0,
        "every macro check was arch-gated, so nothing here was tested"
    );
}

/// The checks whose negative arm builds position-dependent code and links it.
const POSITION_MACRO_CHECKS: [&str; 2] = ["pie-macro", "pic-macro"];

/// A wrapper that links PIE unless told `-no-pie`, failing a position-dependent link with
/// GNU ld's sentence, and logs every link it was handed that carried a flag turning
/// position independence off: `refused` where it failed the link, `linked` where it did not.
/// linker to reproduce, while the wrapper produces the same stderr and exit status there
/// and elsewhere. The dumps, the compile-only jobs and every other link pass through.
fn pie_default_driver(work: &Path) -> (PathBuf, PathBuf) {
    let log = work.join("position-dependent-links.log");
    let script = format!(
        r#"LOG='{log}'
nopic=; nopie=; nolink=
for a in "$@"; do
  case "$a" in
    -fno-PIE|-fno-pie|-fno-PIC|-fno-pic) nopic=1 ;;
    -no-pie) nopie=1 ;;
    -c|-E|-S|-dM) nolink=1 ;;
  esac
done
if [ -n "$nopic" ] && [ -z "$nolink" ]; then
  if [ -z "$nopie" ]; then
    echo refused >>"$LOG"
    echo "ld: /tmp/ccPIEdefault.o: relocation R_X86_64_32 against \`.chard.report' can not be used when making a PIE object; recompile with -fPIE" >&2
    echo "collect2: error: ld returned 1 exit status" >&2
    exit 1
  fi
  echo linked >>"$LOG"
fi
exec "$REAL" "$@""#,
        log = log.display()
    );
    (fake_driver(work, &script), log)
}

#[test]
fn a_pie_default_driver_links_the_position_dependent_negative_arms() {
    if !can_run("that the pie-macro and pic-macro negative arms link on a PIE-default driver") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "PIE-default negative arms",
            "the arms' readings are taken from an ELF artifact, and this host's cc writes Mach-O",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "pie-default");
    let (driver, log) = pie_default_driver(work.dir());

    let report = measure_probes(&driver, work.dir(), &["toolchain-macros"]);

    let mut seen = 0;
    for obs in macro_observations(&report) {
        let check = obs["check"].as_str().unwrap_or("?");
        if !POSITION_MACRO_CHECKS.contains(&check) {
            continue;
        }
        seen += 1;
        let controls = &obs["controls"];
        let negative = &controls["negative"];
        assert_eq!(
            negative["build"]["exit_status"].as_i64(),
            Some(0),
            "{check}: the negative arm did not link: {controls}"
        );
        assert!(
            negative["flags"]
                .as_array()
                .is_some_and(|f| f.iter().any(|f| f.as_str() == Some("-no-pie"))),
            "{check}: the negative arm links without -no-pie: {controls}"
        );
        assert_eq!(
            negative["macro_source"].as_str(),
            Some("compiled-artifact"),
            "{check}: the negative arm read the dump, not the build: {controls}"
        );
        assert_eq!(
            negative["outcome"].as_str(),
            Some("absent"),
            "{check}: {controls}"
        );
        assert_eq!(
            controls["positive"]["outcome"].as_str(),
            Some("present"),
            "{check}: {controls}"
        );
        assert_eq!(
            controls["discriminating"].as_bool(),
            Some(true),
            "{check}: {controls}"
        );
        let verdict = obs["verdict"].as_str();
        assert!(
            verdict == Some("on") || verdict == Some("off"),
            "{check}: a discriminating triple published {verdict:?}: {obs}"
        );
    }
    assert_eq!(
        seen,
        POSITION_MACRO_CHECKS.len(),
        "every position-independence macro check was observed"
    );
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    let refused = logged.lines().filter(|l| *l == "refused").count();
    let linked = logged.lines().filter(|l| *l == "linked").count();
    assert_eq!(
        (refused, linked),
        (0, POSITION_MACRO_CHECKS.len()),
        "one position-dependent link per check, the negative arm's, and none refused: {logged:?}"
    );
}

#[test]
fn a_driver_that_does_not_know_no_pie_withholds_the_position_macro_checks_by_name() {
    if !can_run("that a driver without -no-pie withholds the position macro checks by name") {
        return;
    }
    let work = common::Work::new("fakedriver", "no-no-pie");
    let driver = fake_driver(
        work.dir(),
        r#"for a in "$@"; do
  case "$a" in
    -no-pie)
      echo "fakecc: error: unrecognized command line option '-no-pie'" >&2
      exit 1 ;;
  esac
done
exec "$REAL" "$@""#,
    );

    let report = measure_probes(&driver, work.dir(), &["toolchain-macros", "link-defaults"]);

    // `pie` beside the two, as the witness that this is the withholding the flag already
    // earned there rather than a new one.
    let expected = ["pie-macro", "pic-macro", "pie"];
    let mut seen = 0;
    for obs in report["observations"].as_array().expect("observations") {
        let check = obs["check"].as_str().unwrap_or("?");
        if !expected.contains(&check) {
            continue;
        }
        seen += 1;
        let verdict = obs["verdict"].as_str();
        assert!(
            verdict != Some("on") && verdict != Some("off"),
            "{check}: a verdict stood on a triple with no absent arm: {obs}"
        );
        assert_eq!(
            obs["gating"]["rule"].as_str(),
            Some("unhardened-state-unbuildable"),
            "{check}: the refused control is named: {obs}"
        );
        let reason = obs["gating"]["reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("unrecognized command line option '-no-pie'"),
            "{check}: the withholding quotes the driver: {reason}"
        );
    }
    assert_eq!(
        seen,
        expected.len(),
        "every check carrying -no-pie was observed"
    );
}

#[test]
fn the_driver_is_not_handed_the_operators_tmpdir() {
    if !can_run("that TMPDIR is cleared from the driver's environment") {
        return;
    }
    let work = common::Work::new("fakedriver", "tmpdir");
    let driver = fake_driver(
        work.dir(),
        r#"echo "fakecc: TMPDIR=${TMPDIR-unset}" >&2
exec "$REAL" "$@""#,
    );
    let report = measure_in_env(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "stack-canary"],
        &[("TMPDIR", work.dir())],
    );
    let builds: Vec<&str> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter_map(|o| o["build"]["stderr"].as_str())
        .collect();
    assert!(
        !builds.is_empty(),
        "no observation carries a build record, so nothing here is being tested"
    );
    for stderr in builds {
        assert!(
            stderr.contains("TMPDIR=unset"),
            "the driver saw the operator's TMPDIR: {stderr}"
        );
    }
}

#[test]
fn a_response_file_in_the_profile_is_refused_before_any_build() {
    if !can_run("that a response file in the profile's flags is refused before a build") {
        return;
    }
    let work = common::Work::new("fakedriver", "response-file");
    let rsp = work.write("m32.rsp", "-m32\n");
    let log = work.path("argv.log");
    let driver = fake_driver(
        work.dir(),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nexec \"$REAL\" \"$@\"",
            log.display()
        ),
    );
    let flags = format!("-O2 @{}", rsp.display());
    let output = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(chard_binary());
        cmd.arg("measure")
            .args(PROBE_DEADLINE)
            .args(["-o", "-"])
            .arg("--cc")
            .arg(&driver)
            .arg("--workdir")
            .arg(work.path("w"))
            .args([
                "--profile",
                "explicit",
                "--probe",
                "stack-canary",
                "--flags",
            ])
            .arg(&flags);
        cmd
    });
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(2), "a refusal exits 2:\n{text}");
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    let error = &parsed["error"];
    assert_eq!(error["code"].as_str(), Some("CONFIGURATION"), "{error}");
    let message = error["message"].as_str().unwrap_or("");
    assert!(
        message.contains(&format!("{:?} in --flags", format!("@{}", rsp.display()))),
        "the refusal names the argument and its list: {message}"
    );
    let argv = std::fs::read_to_string(&log).expect("the wrapper ran and logged");
    assert!(
        argv.lines().count() > 0,
        "the toolchain interrogation reached the wrapper, so its log is read"
    );
    assert!(
        !argv.contains("m32.rsp"),
        "an invocation carried the response file before the refusal:\n{argv}"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the twenty-three spellings, the loop over them, and the control run that shows \
              the empty wrapper log is the refusal's doing, read as one test"
)]
fn an_x32_sixteen_bit_or_ilp32_profile_is_refused_before_any_build() {
    if !can_run("that an x32, 16-bit or aarch64 ILP32 profile is refused before a build") {
        return;
    }
    let work = common::Work::new("fakedriver", "unsupported-target");
    let log = work.path("argv.log");
    let driver = fake_driver(
        work.dir(),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nexec \"$REAL\" \"$@\"",
            log.display()
        ),
    );
    let whole = |list: &'static str, spelling: &'static str| (list, spelling, spelling);
    let refused = [
        whole("--flags", "-mx32"),
        whole("--cxxflags", "-m16"),
        whole("--ldflags", "--target=x86_64-linux-gnux32"),
        whole("--flags", "-target x86_64-pc-linux-gnux32"),
        whole(
            "--cxxflags",
            "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
        ),
        whole("--ldflags", "-Xclang -triple=i386-pc-linux-code16"),
        whole("--flags", "-Wa,--x32"),
        whole("--flags", "-Xassembler --x32"),
        whole("--flags", "-Wa,-x32"),
        whole("--cxxflags", "-Xassembler --x3"),
        whole("--cxxflags", "--for-assembler -x32"),
        whole("--flags", "--for-assembler=--x3"),
        whole("--ldflags", "-Wp,-mx32"),
        whole("--flags", "--target=gnux32-x86_64"),
        whole("--flags", "-Xclang=-triple=x86_64-pc-linux-gnux32"),
        whole("--flags", "-mabi=ilp32"),
        whole("--cxxflags", "--target=aarch64-linux-gnu_ilp32"),
        whole("--ldflags", "-Wa,-mabi=ilp32"),
        whole("--flags", "-Xassembler -mabi=ilp32"),
        whole("--flags", "-target arm64_32-apple-watchos"),
        whole("--cxxflags", "-arch arm64_32"),
        (
            "--cxxflags",
            "-Xclang -triple -O2 -Xclang x86_64-pc-linux-gnux32",
            "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
        ),
        (
            "--flags",
            "-Xlinker -Xclang -Xclang -triple -Xclang x86_64-pc-linux-gnux32",
            "-Xclang -triple -Xclang x86_64-pc-linux-gnux32",
        ),
    ];
    let mut fed = 0_usize;
    for (list, spelling, named) in refused {
        let output = common::output_waiting_out_etxtbsy(|| {
            let mut cmd = Command::new(chard_binary());
            cmd.arg("measure")
                .args(PROBE_DEADLINE)
                .args(["-o", "-"])
                .arg("--cc")
                .arg(&driver)
                .arg("--workdir")
                .arg(work.path("w"))
                .args(["--profile", "explicit", "--probe", "stack-canary"]);
            if list == "--flags" {
                cmd.args(["--flags", &format!("-O2 {spelling}")]);
            } else {
                cmd.args(["--flags", "-O2", list, spelling]);
            }
            cmd
        });
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{spelling}: a refusal exits 2:\n{text}"
        );
        let parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
        let error = &parsed["error"];
        assert_eq!(error["code"].as_str(), Some("CONFIGURATION"), "{error}");
        let message = error["message"].as_str().unwrap_or("");
        assert!(
            message.contains("chard does not measure x32, 16-bit or aarch64 ILP32 targets"),
            "{message}"
        );
        for word in named.split_whitespace() {
            assert!(
                message.contains(&format!("{word:?} in {list}")),
                "the refusal names {word} and its list: {message}"
            );
        }
        fed = fed.saturating_add(1);
    }
    assert_eq!(fed, refused.len(), "every spelling was put through chard");
    // The refusal comes before the toolchain interrogation too, so no refused run reaches the
    // wrapper at all.
    let invocations = |argv: &str| argv.lines().filter(|l| !l.is_empty()).count();
    let before_control = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        invocations(&before_control),
        0,
        "a refused run reached the driver: {before_control:?}"
    );
    let control = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(chard_binary());
        cmd.arg("measure")
            .args(PROBE_DEADLINE)
            .args(["-o", "-"])
            .arg("--cc")
            .arg(&driver)
            .arg("--workdir")
            .arg(work.path("w-control"))
            .args(["--profile", "explicit", "--probe", "stack-canary"])
            .args(["--flags", "-O2"]);
        cmd
    });
    assert_eq!(
        control.status.code(),
        Some(0),
        "the control run measures: {}",
        String::from_utf8_lossy(&control.stdout)
    );
    let argv = std::fs::read_to_string(&log).expect("the control run reached the wrapper");
    assert!(
        invocations(&argv) >= 1,
        "the control run's toolchain interrogation reached the wrapper, so its log is read"
    );
    for line in argv.lines() {
        assert!(
            !["-mx32", "-m16", "gnux32", "code16", "-x32", "--x3"]
                .iter()
                .any(|word| line.contains(word)),
            "an invocation carried a refused selection before the refusal: {line}"
        );
    }
}

#[test]
fn the_driver_is_handed_none_of_the_removed_variables() {
    if !can_run("that every listed variable is cleared from the driver's environment") {
        return;
    }
    let removed = chard::compile::COMPILER_ENV_NAMED;
    let pinned = chard::compile::COMPILER_ENV_PINNED;
    let work = common::Work::new("fakedriver", "env-removed");
    // One `echo` per variable, each reporting the value the wrapper was handed.
    let report_lines: Vec<String> = removed
        .iter()
        .chain(pinned.iter().map(|(name, _)| name))
        .map(|name| format!("echo \"fakecc-env: {name}=${{{name}-unset}}\" >&2\n"))
        .collect();
    let report_lines = report_lines.concat();
    let driver = fake_driver(work.dir(), &format!("{report_lines}exec \"$REAL\" \"$@\""));
    let envs: Vec<(&str, &Path)> = removed
        .iter()
        .chain(pinned.iter().map(|(name, _)| name))
        .map(|name| (*name, work.dir()))
        .collect();
    let report = measure_in_env(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "stack-canary"],
        &envs,
    );
    let builds: Vec<&str> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter_map(|o| o["build"]["stderr"].as_str())
        .collect();
    assert!(
        !builds.is_empty(),
        "no observation carries a build record, so nothing here is being tested"
    );
    // Whole lines, so `HOME=unset` is not satisfied by a longer line that ends in it.
    let reported = |stderr: &str, name: &str, value: &str| {
        let line = format!("fakecc-env: {name}={value}");
        stderr.lines().any(|l| l == line)
    };
    for stderr in builds {
        for name in removed {
            assert!(
                reported(stderr, name, "unset"),
                "the driver saw the operator's {name}: {stderr}"
            );
        }
        for (name, value) in pinned {
            assert!(
                reported(stderr, name, value),
                "the driver did not receive {name}={value}: {stderr}"
            );
        }
    }
}

#[test]
fn the_variables_the_inventory_found_are_not_handed_to_the_driver() {
    const FOUND: &[&str] = &[
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "TVOS_DEPLOYMENT_TARGET",
        "WATCHOS_DEPLOYMENT_TARGET",
        "XROS_DEPLOYMENT_TARGET",
        "DRIVERKIT_DEPLOYMENT_TARGET",
        "RC_DEBUG_PREFIX_MAP",
        "RC_DEBUG_OPTIONS",
        "SDKROOT",
        "GCC_COMPARE_DEBUG",
        "GCC_EXTRA_DIAGNOSTIC_OUTPUT",
        "GCC_URLS",
        "GCC_DIAGNOSTICS_LOG",
        "EXPERIMENTAL_SARIF_SOCKET",
        "SOURCE_DATE_EPOCH",
        "CLANG_MODULE_CACHE_PATH",
        "CLANG_CRASH_DIAGNOSTICS_DIR",
        "FORCE_CLANG_DIAGNOSTICS_CRASH",
        "LDEMULATION",
        "GNUTARGET",
        "COLLECT_NO_DEMANGLE",
        "LPATH",
        "GCC_ROOT",
        "BINUTILS_ROOT",
        "DEPENDENCIES_OUTPUT",
        "SUNPRO_DEPENDENCIES",
        "CC_PRINT_OPTIONS",
        "CC_PRINT_HEADERS",
        "CC_PRINT_HEADERS_FILE",
        "CC_PRINT_HEADERS_FORMAT",
        "CC_PRINT_HEADERS_FILTERING",
        "CC_LOG_DIAGNOSTICS",
        "CC_LOG_DIAGNOSTICS_FILE",
        "CC_PRINT_INTERNAL_STAT",
        "CC_PRINT_INTERNAL_STAT_FILE",
        "CC_PRINT_PROC_STAT",
        "CC_PRINT_PROC_STAT_FILE",
    ];
    if !can_run("that each variable the inventory found a toolchain reading is cleared") {
        return;
    }
    let work = common::Work::new("fakedriver", "env-found");
    let report_lines: Vec<String> = FOUND
        .iter()
        .map(|name| format!("echo \"fakecc-env: {name}=${{{name}-unset}}\" >&2\n"))
        .collect();
    let report_lines = report_lines.concat();
    let driver = fake_driver(work.dir(), &format!("{report_lines}exec \"$REAL\" \"$@\""));
    let envs: Vec<(&str, &Path)> = FOUND.iter().map(|name| (*name, work.dir())).collect();
    let report = measure_in_env(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "stack-canary"],
        &envs,
    );
    let builds: Vec<&str> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter_map(|o| o["build"]["stderr"].as_str())
        .collect();
    assert!(
        !builds.is_empty(),
        "no observation carries a build record, so nothing here is being tested"
    );
    for stderr in builds {
        for name in FOUND {
            let line = format!("fakecc-env: {name}=unset");
            assert!(
                stderr.lines().any(|l| l == line),
                "the driver saw the operator's {name}: {stderr}"
            );
        }
    }
}

#[test]
fn the_driver_is_handed_only_the_passed_variables_and_the_pins() {
    const SHELL_ADDS: &[&str] = &["PWD", "SHLVL", "_"];
    if !can_run("that the driver's environment holds nothing chard did not choose") {
        return;
    }
    let work = common::Work::new("fakedriver", "env-whole");
    let driver = fake_driver(
        work.dir(),
        "env | awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/ { print \"fakecc-envname: \" $1 }' >&2\n\
         echo \"fakecc-ccache-disable: ${CCACHE_DISABLE-unset}\" >&2\n\
         exec \"$REAL\" \"$@\"",
    );
    let envs: Vec<(&str, &Path)> = [
        "CHARD_TEST_VARIABLE_NO_LIST_NAMES",
        "LD_LIBRARY_PATH",
        "CCACHE_DIR",
        "CCACHE_DISABLE",
    ]
    .iter()
    .map(|name| (*name, work.dir()))
    .collect();
    let report = measure_in_env(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "stack-canary"],
        &envs,
    );
    let builds: Vec<&str> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter_map(|o| o["build"]["stderr"].as_str())
        .collect();
    assert!(
        !builds.is_empty(),
        "no observation carries a build record, so nothing here is being tested"
    );
    let pinned: Vec<&str> = chard::compile::COMPILER_ENV_PINNED
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let disable = chard::compile::COMPILER_ENV_PINNED
        .iter()
        .find(|(name, _)| *name == "CCACHE_DISABLE")
        .map(|(_, value)| format!("fakecc-ccache-disable: {value}"))
        .expect("CCACHE_DISABLE is a pin");
    for stderr in builds {
        assert!(
            stderr.lines().any(|l| l == disable),
            "the driver was not handed the pinned CCACHE_DISABLE: {stderr}"
        );
        let names: Vec<&str> = stderr
            .lines()
            .filter_map(|l| l.strip_prefix("fakecc-envname: "))
            .collect();
        for name in &pinned {
            assert!(
                names.contains(name),
                "the driver was not handed the pinned {name}: {stderr}"
            );
        }
        assert!(
            names.contains(&"PATH"),
            "the driver was not handed chard's PATH: {stderr}"
        );
        for name in names {
            assert!(
                chard::compile::COMPILER_ENV_PASSED.contains(&name)
                    || pinned.contains(&name)
                    || SHELL_ADDS.contains(&name),
                "the driver was handed {name}, which chard did not choose: {stderr}"
            );
        }
    }
}

/// The program `name` resolves to on `path`, by `command -v` under that `PATH` alone.
fn resolved_on(path: &OsStr, name: &str) -> Option<PathBuf> {
    let output = Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .env("PATH", path)
        .output()
        .expect("sh is available");
    let found = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && found.starts_with('/')).then(|| PathBuf::from(found))
}

/// `measure` through `--cc clang` with `path` as chard's whole `PATH` and `pairs` as its
/// `--env` pairs: shape A of the compiler-cache finding, a `-fstack-protector-strong` build
/// read by the two checks that read the emitted protector.
fn measure_canary_on(path: &OsStr, work: &Path, pairs: &[String]) -> Value {
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .args(["-o", "-", "--cc", "clang", "--profile", "explicit"])
        .args(["--flags", "-O2 -fstack-protector-strong"])
        .args(["--probe", "stack-canary", "--probe", "ssp-function-map"])
        .arg("--workdir")
        .arg(work)
        .args(pairs.iter().flat_map(|pair| ["--env", pair.as_str()]))
        .env_clear()
        .env("PATH", path)
        .output()
        .expect("spawning chard");
    let text = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    assert!(
        parsed.get("error").is_none(),
        "chard refused to measure: {}",
        parsed["error"]
    );
    parsed
}

/// The verdict of each of the two canary checks, by check.
fn canary_verdicts(report: &Value) -> Vec<(String, String)> {
    let mut verdicts: Vec<(String, String)> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| {
            matches!(
                o["check"].as_str(),
                Some("canary-emitted" | "ssp-level-emitted")
            )
        })
        .map(|o| {
            let check = o["check"].as_str().unwrap_or_default().to_owned();
            (check, o["verdict"].as_str().unwrap_or_default().to_owned())
        })
        .collect();
    verdicts.sort();
    let checks: Vec<&str> = verdicts.iter().map(|(check, _)| check.as_str()).collect();
    assert_eq!(
        checks,
        ["canary-emitted", "ssp-level-emitted"],
        "the run did not observe both canary checks once each, so nothing is compared"
    );
    verdicts
}

/// The files under `dir`, as `(all, results)`: `all` counts every file, and `results` the
/// ones a hit is served from ([`stored_result`]). A cache that stored nothing leaves both at
/// none; a cache in another layout reads no result, so the poisoning control fails rather
/// than passing on bookkeeping. An absent directory holds none; any other error reading one
/// panics, so a cache that cannot be read is never counted as one that stored nothing.
fn files_under(dir: &Path) -> (usize, usize) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, 0),
        Err(e) => panic!("reading the cache directory {}: {e}", dir.display()),
    };
    entries
        .map(|entry| entry.expect("a directory entry").path())
        .map(|path| {
            if path.is_dir() {
                return files_under(&path);
            }
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            (1, usize::from(name.as_deref().is_some_and(stored_result)))
        })
        .fold((0, 0), |(files, kept), (f, k)| (files + f, kept + k))
}

/// Is `name` a file a ccache hit is served from? A result or a manifest, matched by name as
/// ccache 4.12.3 writes it: at least 20 lower-case letters and digits, then `R` (result) or
/// `M` (manifest). Its bookkeeping (`stats`, `CACHEDIR.TAG`, a lock or a temporary file) is not.
fn stored_result(name: &str) -> bool {
    name.len() > 20
        && (name.ends_with('R') || name.ends_with('M'))
        && name[..name.len() - 1]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[test]
fn a_cache_of_bookkeeping_holds_no_stored_result() {
    let work = common::Work::new("fakedriver", "ccache-layout");
    let cache = work.dir().join("cache");
    let nested = cache.join("a").join("b");
    std::fs::create_dir_all(&nested).expect("the cache's directories");
    std::fs::create_dir_all(cache.join("tmp")).expect("the cache's tmp");
    let result = "0f3k9q2b7n1m4c8x5z6v0a9s8d7f6g5R";
    let manifest = "0f3k9q2b7n1m4c8x5z6v0a9s8d7f6g5M";
    // The shortest name read as stored: 20 hash characters, then the suffix.
    let shortest = "0f3k9q2b7n1m4c8x5z6vR";
    for (dir, name) in [
        (&cache, "CACHEDIR.TAG"),
        (&cache, "stats"),
        (&cache.join("tmp"), "tmp.cpp_stdout.x1Y2"),
        (&nested, "stats"),
        (&nested, result),
        (&nested, manifest),
        (&nested, shortest),
        // Too short by one, a capital in the hash, and a third suffix: none is stored.
        (&nested, "0f3k9q2b7n1m4c8x5z6R"),
        (&nested, "0f3k9q2bR"),
        (&nested, "0F3K9Q2B7N1M4C8X5Z6V0A9S8D7F6G5R"),
        (&nested, "0f3k9q2b7n1m4c8x5z6v0a9s8d7f6g5W"),
    ] {
        std::fs::write(dir.join(name), b"x").expect("a cache file");
    }
    assert_eq!(files_under(&cache), (11, 3));
    assert_eq!(files_under(&work.dir().join("absent")), (0, 0));
    // A path that exists and cannot be read as a directory is not an empty cache.
    let not_a_directory = work.dir().join("not-a-directory");
    std::fs::write(&not_a_directory, b"x").expect("a plain file");
    let payload = std::panic::catch_unwind(|| files_under(&not_a_directory))
        .expect_err("a plain file read as a cache directory");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(
        message.contains("reading the cache directory"),
        "files_under panicked for another reason: {message:?}"
    );
    for name in [result, manifest, shortest] {
        assert!(stored_result(name), "{name}");
    }
    for name in [
        "stats",
        "CACHEDIR.TAG",
        "0f3k9q2b7n1m4c8x5z6R",
        "0f3k9q2bR",
        "lock",
    ] {
        assert!(!stored_result(name), "{name}");
    }
}

/// The host's `ccache`, resolved, and the host's `PATH` without its own masquerade
/// directories (an entry whose `clang` is that ccache), where a clang remains on it; `None`,
/// with the gap in the ledger, where either is missing.
fn ccache_and_clean_path(test: &str) -> Option<(PathBuf, std::ffi::OsString)> {
    let host_path = std::env::var_os("PATH").unwrap_or_default();
    let Some(ccache) = resolved_on(&host_path, "ccache") else {
        common::capability_gap(
            test,
            "no ccache on PATH, so no masquerade directory to measure through",
        );
        return None;
    };
    let ccache = std::fs::canonicalize(&ccache).expect("ccache resolves");
    let clean: Vec<PathBuf> = std::env::split_paths(&host_path)
        .filter(|dir| std::fs::canonicalize(dir.join("clang")).map_or(true, |real| real != ccache))
        .collect();
    let clean = std::env::join_paths(&clean).expect("a PATH");
    if resolved_on(&clean, "clang").is_none() {
        common::capability_gap(
            test,
            "no clang on PATH, and shape A's route is clang's CCC_OVERRIDE_OPTIONS",
        );
        return None;
    }
    Some((ccache, clean))
}

#[test]
fn a_ccache_directory_on_path_serves_chard_nothing() {
    const TEST: &str = "a_ccache_directory_on_path_serves_chard_nothing";
    if !common::require_binary(
        &chard_binary(),
        "that a ccache masquerade directory on PATH serves chard no object",
    ) {
        return;
    }
    let Some((ccache, clean)) = ccache_and_clean_path(TEST) else {
        return;
    };
    let work = common::Work::new("fakedriver", "ccache-shim");
    let shim = work.dir().join("shim");
    let poison = work.dir().join("poison");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::fs::create_dir_all(&poison).expect("the poisoning directory");
    std::os::unix::fs::symlink(&ccache, shim.join("clang")).expect("the masquerade entry");
    let shimmed =
        std::env::join_paths(std::iter::once(shim.clone()).chain(std::env::split_paths(&clean)))
            .expect("a PATH");
    let poisoning = std::env::join_paths(
        std::iter::once(poison.clone()).chain(std::env::split_paths(&shimmed)),
    )
    .expect("a PATH");
    // The wrapper unsets every boolean ccache pin (`compile::ccache_boolean_pin`), whatever
    // the list holds, and keeps the other pins: ccache hashes `LC_ALL` among them, so the
    // honest run's entries key as the route's do.
    let unpinned: Vec<&str> = chard::compile::COMPILER_ENV_PINNED
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| chard::compile::ccache_boolean_pin(name) == Some(true))
        .collect();
    common::executable(
        &poison.join("clang"),
        &format!(
            "[ $# -eq 0 ] && exit 0\nunset {}\nPATH='{}'\nexport PATH\nexec clang \"$@\"",
            unpinned.join(" "),
            shimmed.to_string_lossy()
        ),
    );

    // A private cache; `CCACHE_CONFIGPATH=/dev/null`, a pin the wrapper keeps, keeps every
    // ccache configuration file out of both runs.
    let cache = work.dir().join("cache");
    let cache_pair = format!("CCACHE_DIR={}", cache.display());
    let route = "CCC_OVERRIDE_OPTIONS=+-fno-stack-protector".to_owned();
    let honest = canary_verdicts(&measure_canary_on(
        &poisoning,
        &work.dir().join("honest"),
        std::slice::from_ref(&cache_pair),
    ));
    assert!(
        honest
            .iter()
            .any(|(check, verdict)| check == "ssp-level-emitted" && verdict == "on"),
        "the honest run did not read ssp-level-emitted on: {honest:?}"
    );
    let poisoned = files_under(&cache);
    assert!(
        poisoned.1 > 0,
        "the honest run stored no result in {} with the ccache pins unset ({} bookkeeping files)",
        cache.display(),
        poisoned.0
    );
    let served_report = measure_canary_on(
        &shimmed,
        &work.dir().join("route"),
        &[cache_pair, route.clone()],
    );
    let driver = served_report["toolchain"]["driver"]
        .as_str()
        .map(PathBuf::from);
    assert_eq!(
        driver,
        Some(shim.join("clang")),
        "the route's driver was not the masquerade entry, so the cache was never in front of it"
    );
    let served = canary_verdicts(&served_report);
    let uncached = canary_verdicts(&measure_canary_on(
        &clean,
        &work.dir().join("uncached"),
        &[route],
    ));
    assert!(
        !uncached.iter().any(|(_, verdict)| verdict == "on"),
        "the route read on with no cache on PATH: {uncached:?}"
    );
    assert_eq!(
        served, uncached,
        "through the cache the route read the honest run's object, not its own"
    );
    assert_eq!(
        files_under(&cache),
        poisoned,
        "the route stored files in the cache {}",
        cache.display()
    );
}

/// A program that records each invocation of it in `mark`, one line holding its arguments,
/// and then runs `then` with them: with `then` empty, the rest of its arguments (a ccache
/// `prefix_command` or `CCACHE_PREFIX` stand-in); with a compiler's path, that compiler (a
/// `CCACHE_COMPILER` or `CCACHE_PATH` stand-in). It ends without running anything when called
/// with no argument, which is how `common::executable` tries it.
fn marking_program(at: &Path, mark: &Path, then: &str) -> PathBuf {
    let then = if then.is_empty() {
        String::new()
    } else {
        format!("'{then}' ")
    };
    common::executable(
        at,
        &format!(
            "[ $# -eq 0 ] && exit 0\nprintf '%s\\n' \"$*\" >> '{}'\nexec {then}\"$@\"",
            mark.display()
        ),
    )
}

/// The line `marking_program` writes for `toolchain::detect`'s intrinsic macro dump, the query
/// `toolchain.kind` and `toolchain.version` are read from: no flags, and the source
/// `compile::macro_dump` names from its tag, handed over by its file name alone.
const INTRINSIC_DUMP: &str = "-dM -E macros-intrinsic.c";

/// Does a line `marking_program` wrote record a compile, an invocation carrying `-c`, rather
/// than a query such as `--version` or a macro dump?
fn marks_a_compile(line: &str) -> bool {
    line.split_whitespace().any(|word| word == "-c")
}

/// One arm of [`a_ccache_configuration_file_decides_nothing`]: the configuration file ccache
/// reads in that arm, the cache directory it uses there, and the pairs that lead ccache to
/// both, every path under the arm's `dir`. The last two arms are ccache's default branch, with
/// no `CCACHE_DIR` set: they name `HOME` so that the test user's own home decides nothing.
/// Every arm but the system file's names an empty file (`no-system-ccache.conf`, which the
/// caller writes) as `CCACHE_CONFIGPATH2`. Where the host's ccache reads that variable, the
/// host's own system file, whose `cache_dir` would move where ccache looks for the operator's
/// file, decides nothing in the control.
fn configuration_arm(arm: &str, dir: &Path) -> (PathBuf, PathBuf, Vec<(&'static str, PathBuf)>) {
    let no_system = ("CCACHE_CONFIGPATH2", dir.join("no-system-ccache.conf"));
    let home = || vec![("HOME", dir.to_path_buf()), no_system.clone()];
    match arm {
        "cache-directory" => {
            let cache = dir.join("cache");
            (
                cache.join("ccache.conf"),
                cache.clone(),
                vec![("CCACHE_DIR", cache), no_system.clone()],
            )
        }
        "system" => {
            let file = dir.join("system-ccache.conf");
            let cache = dir.join("cache");
            (
                file.clone(),
                cache.clone(),
                vec![("CCACHE_DIR", cache), ("CCACHE_CONFIGPATH2", file)],
            )
        }
        // The operator's file where no legacy `.ccache` directory exists.
        "operator" => (
            dir.join(".config").join("ccache").join("ccache.conf"),
            dir.join(".cache").join("ccache"),
            home(),
        ),
        // A legacy `.ccache` directory under `HOME` is both the cache and the file's directory,
        // and outranks the operator's file where it exists.
        "legacy" => {
            let cache = dir.join(".ccache");
            (cache.join("ccache.conf"), cache, home())
        }
        _ => panic!("no configuration arm {arm}"),
    }
}

#[test]
fn a_ccache_configuration_file_decides_nothing() {
    const TEST: &str = "a_ccache_configuration_file_decides_nothing";
    if !common::require_binary(
        &chard_binary(),
        "that a ccache configuration file decides nothing in a run",
    ) {
        return;
    }
    let Some((ccache, clean)) = ccache_and_clean_path(TEST) else {
        return;
    };
    let work = common::Work::new("fakedriver", "ccache-config");
    let shim = work.dir().join("shim");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::os::unix::fs::symlink(&ccache, shim.join("clang")).expect("the masquerade entry");
    let shimmed =
        std::env::join_paths(std::iter::once(shim.clone()).chain(std::env::split_paths(&clean)))
            .expect("a PATH");
    let mut exercised = 0;
    let mut system_gap = false;
    let arms = ["cache-directory", "system", "operator", "legacy"];
    for arm in arms {
        let dir = work.dir().join(arm);
        let mark = dir.join("prefix-ran");
        let (file, cache, pairs) = configuration_arm(arm, &dir);
        std::fs::create_dir_all(&cache).expect("the cache directory");
        std::fs::create_dir_all(file.parent().expect("the file's directory"))
            .expect("the configuration file's directory");
        let prefix = marking_program(&dir.join("prefix"), &mark, "");
        std::fs::write(&file, format!("prefix_command = {}\n", prefix.display()))
            .expect("the configuration file");
        if arm != "system" {
            std::fs::write(dir.join("no-system-ccache.conf"), b"").expect("the empty system file");
        }

        let direct = Command::new(shim.join("clang"))
            .arg("--version")
            .env_clear()
            .env("PATH", &shimmed)
            .envs(pairs.iter().map(|(name, value)| (name, value)))
            .env("CCACHE_DISABLE", "1")
            .output()
            .expect("spawning the masquerade entry");
        assert!(
            direct.status.success(),
            "{arm}: the masquerade entry failed: {direct:?}"
        );
        if !mark.exists() {
            assert_eq!(
                arm,
                "system",
                "the prefix command in {} did not run under CCACHE_DISABLE alone",
                file.display()
            );
            common::capability_gap(
                &format!("{TEST} (the system file)"),
                "this ccache did not read the file CCACHE_CONFIGPATH2 names",
            );
            system_gap = true;
            continue;
        }
        std::fs::remove_file(&mark).expect("clearing the mark");

        let env: Vec<String> = pairs
            .iter()
            .map(|(name, value)| format!("{name}={}", value.display()))
            .collect();
        let report = measure_canary_on(&shimmed, &dir.join("run"), &env);
        assert_eq!(
            report["toolchain"]["driver"].as_str().map(PathBuf::from),
            Some(shim.join("clang")),
            "{arm}: the run's driver was not the masquerade entry"
        );
        // A run that built nothing would leave no mark either: the canary checks read `on`
        // only over objects this run compiled.
        let verdicts = canary_verdicts(&report);
        assert!(
            verdicts.iter().all(|(_, verdict)| verdict == "on"),
            "{arm}: the run did not read both canary checks on: {verdicts:?}"
        );
        assert!(
            !mark.exists(),
            "{arm}: the prefix command {} named ran in chard's run",
            file.display()
        );
        assert_eq!(
            files_under(&cache).1,
            0,
            "{arm}: the run stored a result under {}",
            cache.display()
        );
        exercised += 1;
    }
    assert_eq!(
        exercised,
        arms.len() - usize::from(system_gap),
        "an arm neither compared a run nor was the system file's gap"
    );
}

#[test]
fn a_published_ccache_pair_naming_a_program_acts_and_is_published() {
    const TEST: &str = "a_published_ccache_pair_naming_a_program_acts_and_is_published";
    if !common::require_binary(
        &chard_binary(),
        "that a published ccache pair naming a program acts and the report carries it",
    ) {
        return;
    }
    let Some((ccache, clean)) = ccache_and_clean_path(TEST) else {
        return;
    };
    let real = resolved_on(&clean, "clang").expect("ccache_and_clean_path found a clang");
    let real = real.to_str().expect("a clang path in UTF-8");
    let work = common::Work::new("fakedriver", "ccache-pair");
    let shim = work.dir().join("shim");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::os::unix::fs::symlink(&ccache, shim.join("clang")).expect("the masquerade entry");
    let shimmed =
        std::env::join_paths(std::iter::once(shim.clone()).chain(std::env::split_paths(&clean)))
            .expect("a PATH");
    for name in [
        "CCACHE_PREFIX",
        "CCACHE_COMPILER",
        "CCACHE_CC",
        "CCACHE_PATH",
    ] {
        let dir = work.dir().join(name);
        let cache = dir.join("cache");
        let programs = dir.join("programs");
        std::fs::create_dir_all(&cache).expect("the cache directory");
        std::fs::create_dir_all(&programs).expect("the programs directory");
        let mark = dir.join("marks");
        let value = match name {
            "CCACHE_PREFIX" => marking_program(&programs.join("prefix"), &mark, ""),
            "CCACHE_COMPILER" | "CCACHE_CC" => {
                marking_program(&programs.join("clang"), &mark, real)
            }
            _ => {
                marking_program(&programs.join("clang"), &mark, real);
                programs.clone()
            }
        };
        let pairs = [
            format!("CCACHE_DIR={}", cache.display()),
            format!("{name}={}", value.display()),
        ];
        let report = measure_canary_on(&shimmed, &dir.join("run"), &pairs);
        assert_eq!(
            report["toolchain"]["driver"].as_str().map(PathBuf::from),
            Some(shim.join("clang")),
            "{name}: the run's driver was not the masquerade entry"
        );
        let set = &report["profile"]["compiler_environment"]["set"];
        assert_eq!(
            set[name].as_str(),
            value.to_str(),
            "the report does not publish the {name} pair: {set}"
        );
        let marks = std::fs::read_to_string(&mark).unwrap_or_default();
        assert!(
            marks.lines().any(marks_a_compile),
            "{name}: the published pair's program ran in no compile; its invocations: {marks:?}"
        );
        if name != "CCACHE_PREFIX" {
            assert!(
                marks.lines().any(|line| line == INTRINSIC_DUMP),
                "{name}: the pair's program never answered the intrinsic macro dump: {marks:?}"
            );
            assert!(
                marks.lines().any(|line| line == "--version"),
                "{name}: the pair's program never answered chard's --version query: {marks:?}"
            );
        }
        assert_eq!(
            files_under(&cache).1,
            0,
            "{name}: the run stored a result under {}",
            cache.display()
        );
    }
}

/// The masquerade directory, a private cache and the host's gcc for the two forwarding
/// tests below: a `PATH` with a `clang` linked to the host's ccache first, the cache
/// directory's pair, and gcc's path; `None`, with the gap in the ledger, where ccache, clang
/// or gcc is missing.
fn forwarding_host(
    test: &str,
    work: &common::Work,
) -> Option<(std::ffi::OsString, String, String)> {
    let (ccache, clean) = ccache_and_clean_path(test)?;
    let Some(gcc) = resolved_on(&clean, "gcc") else {
        common::capability_gap(test, "no gcc on PATH, so no other compiler to forward to");
        return None;
    };
    let shim = work.dir().join("shim");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::os::unix::fs::symlink(&ccache, shim.join("clang")).expect("the masquerade entry");
    let shimmed = std::env::join_paths(std::iter::once(shim).chain(std::env::split_paths(&clean)))
        .expect("a PATH");
    let cache = work.dir().join("cache");
    std::fs::create_dir_all(&cache).expect("the cache directory");
    Some((
        shimmed,
        format!("CCACHE_DIR={}", cache.display()),
        gcc.to_str().expect("a gcc path in UTF-8").to_owned(),
    ))
}

#[test]
fn a_compile_a_ccache_prefix_sends_to_another_compiler_is_withheld() {
    const TEST: &str = "a_compile_a_ccache_prefix_sends_to_another_compiler_is_withheld";
    const RULE: &str = "artifact-compiled-by-another-compiler";
    if !common::require_binary(
        &chard_binary(),
        "that an object another compiler built under a forwarding prefix is withheld",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "ccache-forward");
    let Some((shimmed, cache_pair, gcc)) = forwarding_host(TEST, &work) else {
        return;
    };
    let mark = work.dir().join("forwarded");
    let forwarding = common::executable(
        &work.dir().join("forward"),
        &format!(
            "[ $# -eq 0 ] && exit 0\nfor a in \"$@\"; do\n  if [ \"$a\" = -c ]; then\n    \
             printf '%s\\n' \"$*\" >> '{}'\n    shift\n    exec '{gcc}' \"$@\"\n  fi\ndone\n\
             exec \"$@\"",
            mark.display()
        ),
    );
    let report = measure_canary_on(
        &shimmed,
        &work.dir().join("run"),
        &[
            cache_pair.clone(),
            format!("CCACHE_PREFIX={}", forwarding.display()),
        ],
    );
    assert_eq!(
        report["toolchain"]["kind"].as_str(),
        Some("clang"),
        "the dumps did not stay with clang: {}",
        report["toolchain"]
    );
    let forwarded = std::fs::read_to_string(&mark).unwrap_or_default();
    assert!(
        forwarded.lines().any(marks_a_compile),
        "the prefix forwarded no compile, so nothing here was built by gcc: {forwarded:?}"
    );
    let level = observation(&report, "ssp-level-emitted");
    assert_eq!(level["verdict"].as_str(), Some("indeterminate"), "{level}");
    assert_eq!(level["gating"]["rule"].as_str(), Some(RULE), "{level}");
    let reason = level["gating"]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("`GCC: (") && reason.contains("where `toolchain` is clang "),
        "the reason quotes neither gcc's line nor the compiler the report names: {reason}"
    );
    let diagnosed = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| d["context"].as_str() == Some("ssp-function-map"))
        .filter_map(|d| d["message"].as_str())
        .any(|m| m.starts_with("the measured artifact") && m.contains(RULE));
    assert!(
        diagnosed,
        "no diagnostic names the measured build: {}",
        report["diagnostics"]
    );
    let canary = observation(&report, "canary-emitted");
    assert_eq!(
        canary["verdict"].as_str(),
        Some("on"),
        "the linked program the prefix left with clang is not read as it is uncached: {canary}"
    );

    let passed = work.dir().join("passed");
    let passing = marking_program(&work.dir().join("pass"), &passed, "");
    let control = measure_canary_on(
        &shimmed,
        &work.dir().join("control"),
        &[
            cache_pair.clone(),
            format!("CCACHE_PREFIX={}", passing.display()),
        ],
    );
    let passed = std::fs::read_to_string(&passed).unwrap_or_default();
    assert!(
        passed.lines().any(marks_a_compile),
        "the control's prefix ran in no compile: {passed:?}"
    );
    assert_eq!(
        canary_verdicts(&control),
        [
            ("canary-emitted".to_owned(), "on".to_owned()),
            ("ssp-level-emitted".to_owned(), "on".to_owned())
        ],
        "a prefix that forwards nothing did not read both checks on"
    );
    assert!(
        !linked_warning(&control),
        "the control named a linked artifact with another compiler's line: {}",
        control["diagnostics"]
    );
}

#[test]
fn a_linked_program_another_compiler_built_is_named() {
    const TEST: &str = "a_linked_program_another_compiler_built_is_named";
    const RULE: &str = "artifact-compiled-by-another-compiler";
    if !common::require_binary(
        &chard_binary(),
        "that a linked program another compiler built under a forwarding prefix is named",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "ccache-forward-builds");
    let Some((shimmed, cache_pair, gcc)) = forwarding_host(TEST, &work) else {
        return;
    };
    let builds = common::executable(
        &work.dir().join("builds"),
        &format!(
            "[ $# -eq 0 ] && exit 0\nfor a in \"$@\"; do\n  case \"$a\" in\n    \
             -E|--version|-v|-###|-dumpmachine|-print-*) exec \"$@\";;\n  esac\ndone\n\
             shift\nexec '{gcc}' \"$@\""
        ),
    );
    let every = measure_canary_on(
        &shimmed,
        &work.dir().join("every-build"),
        &[cache_pair, format!("CCACHE_PREFIX={}", builds.display())],
    );
    assert_eq!(
        every["toolchain"]["kind"].as_str(),
        Some("clang"),
        "{}",
        every["toolchain"]
    );
    assert_eq!(
        observation(&every, "ssp-level-emitted")["gating"]["rule"].as_str(),
        Some(RULE),
        "{}",
        observation(&every, "ssp-level-emitted")
    );
    assert!(
        linked_warning(&every),
        "the linked program gcc built under a report naming clang is not named: {}",
        every["diagnostics"]
    );
}

#[test]
fn an_assembly_probe_is_not_named_for_its_startup_objects_lines() {
    const TEST: &str = "an_assembly_probe_is_not_named_for_its_startup_objects_lines";
    if !common::require_binary(
        &chard_binary(),
        "that an assembly probe's link is not named",
    ) {
        return;
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    let Some(clang) = resolved_on(&path, "clang") else {
        common::capability_gap(TEST, "no clang on PATH");
        return;
    };
    let work = common::Work::new("fakedriver", "assembly-link");
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .args(["-o", "-", "--cc"])
        .arg(&clang)
        .args([
            "--profile",
            "bare",
            "--probe",
            "linker-default-execstack",
            "--workdir",
        ])
        .arg(work.dir().join("run"))
        .output()
        .expect("spawning chard");
    let report: Value = serde_json::from_slice(&output.stdout).expect("a report on stdout");
    if report["run"]["artifact_witness"].is_null() {
        common::capability_gap(
            TEST,
            "this run has no witness, so its artifacts are not ELF",
        );
        return;
    }
    let sha = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .find_map(|o| o["build"]["artifact_sha256"].as_str())
        .expect("a build with an artifact");
    let lines: Vec<&str> = report["facts"][sha]["elf"]["comment"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let names_compiler = lines
        .iter()
        .any(|l| l.starts_with("GCC: (") || l.contains("clang version"));
    if !names_compiler || lines.iter().any(|l| l.contains("clang version")) {
        common::capability_gap(
            TEST,
            "the program's .comment names no compiler, or names clang, so the exclusion decides \
             nothing here",
        );
        return;
    }
    assert!(
        !report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .filter_map(|d| d["message"].as_str())
            .any(|m| m.contains("linked artifact(s)")),
        "an assembly unit's link is named for its startup objects' lines ({lines:?}): {}",
        report["diagnostics"]
    );
}

/// Whether `report` carries the run's warning that a linked artifact names another compiler
/// and not the report's, for the `stack-canary` program.
fn linked_warning(report: &Value) -> bool {
    report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| d["context"].as_str() == Some("toolchain"))
        .filter_map(|d| d["message"].as_str())
        .any(|m| m.contains("linked artifact(s)") && m.contains("stack-canary sha256:"))
}

#[test]
fn an_object_that_shows_no_compiler_is_read_and_named() {
    const TEST: &str = "an_object_that_shows_no_compiler_is_read_and_named";
    if !can_run("that an object with no compiler line is read and named") {
        return;
    }
    let work = common::Work::new("fakedriver", "no-ident");
    let run = |flags: &str, dir: &str| -> Value {
        let output = Command::new(chard_binary())
            .arg("measure")
            .args(PROBE_DEADLINE)
            .args(["-o", "-", "--cc", &real_cc(), "--profile", "explicit"])
            .args(["--flags", flags, "--probe", "ssp-function-map", "--workdir"])
            .arg(work.dir().join(dir))
            .output()
            .expect("spawning chard");
        serde_json::from_slice(&output.stdout).expect("a report on stdout")
    };
    let unnamed = run("-O2 -fstack-protector-strong -fno-ident", "no-ident");
    if unnamed["run"]["artifact_witness"].is_null() {
        common::capability_gap(
            TEST,
            "this run has no witness, so no object is held to a line",
        );
        return;
    }
    let level = observation(&unnamed, "ssp-level-emitted");
    assert_eq!(level["verdict"].as_str(), Some("on"), "{level}");
    let named = |report: &Value| {
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .filter(|d| d["context"].as_str() == Some("toolchain"))
            .filter_map(|d| d["message"].as_str())
            .any(|m| {
                m.contains("relocatable object(s)")
                    && m.contains("ssp-function-map sha256:")
                    && m.contains("carries no `.comment` line")
            })
    };
    assert!(
        named(&unnamed),
        "the object is not named: {}",
        unnamed["diagnostics"]
    );
    let control = run("-O2 -fstack-protector-strong", "control");
    assert!(
        !named(&control),
        "an object with its line is named: {}",
        control["diagnostics"]
    );
    assert_eq!(
        observation(&control, "ssp-level-emitted")["verdict"].as_str(),
        Some("on")
    );
}

#[test]
fn a_ccache_compiler_answering_the_dump_as_gcc_is_read_and_named() {
    const TEST: &str = "a_ccache_compiler_answering_the_dump_as_gcc_is_read_and_named";
    if !common::require_binary(
        &chard_binary(),
        "that the report reads the intrinsic dump's answer and names a banner of another compiler",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "ccache-gcc-dump");
    let Some((shimmed, cache_pair, gcc)) = forwarding_host(TEST, &work) else {
        return;
    };
    let clean = std::env::split_paths(&shimmed).skip(1).collect::<Vec<_>>();
    let clean = std::env::join_paths(clean).expect("a PATH");
    let clang = resolved_on(&clean, "clang").expect("forwarding_host found a clang");
    let answering = common::executable(
        &work.dir().join("clang"),
        &format!(
            "[ $# -eq 0 ] && exit 0\n[ \"$*\" = '{INTRINSIC_DUMP}' ] && exec '{gcc}' \"$@\"\n\
             exec '{}' \"$@\"",
            clang.display()
        ),
    );
    let report = measure_canary_on(
        &shimmed,
        &work.dir().join("run"),
        &[
            cache_pair,
            format!("CCACHE_COMPILER={}", answering.display()),
        ],
    );
    let toolchain = &report["toolchain"];
    assert_eq!(
        toolchain["kind"].as_str(),
        Some("gcc"),
        "the report did not read the intrinsic dump's answer: {toolchain}"
    );
    let banner = toolchain["version_raw"].as_str().unwrap_or_default();
    assert!(banner.contains("clang version"), "{toolchain}");
    let named = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .find(|d| d["context"].as_str() == Some("toolchain.version_raw"))
        .unwrap_or_else(|| {
            panic!(
                "a banner naming clang under a dump naming gcc is not named: {}",
                report["diagnostics"]
            )
        });
    assert_eq!(named["severity"].as_str(), Some("error"), "{named}");
    let message = named["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(banner) && message.contains("names gcc "),
        "{message}"
    );
    let level = observation(&report, "ssp-level-emitted");
    assert_eq!(
        level["gating"]["rule"].as_str(),
        Some("artifact-compiled-by-another-compiler"),
        "clang's object under a report naming gcc was read: {level}"
    );
}

#[test]
fn a_driver_that_needs_a_cleared_variable_is_refused_with_its_environment_in_the_hint() {
    if !can_run("that a driver needing a cleared variable is refused with exit 2 and a hint") {
        return;
    }
    let work = common::Work::new("fakedriver", "needs-cleared");
    let driver = fake_driver(
        work.dir(),
        "[ -n \"$CHARD_TEST_DRIVER_NEEDS\" ] || exit 1\nexec \"$REAL\" \"$@\"",
    );
    let direct = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(&driver);
        cmd.args(["-dM", "-E", "-x", "c", "/dev/null"])
            .env("CHARD_TEST_DRIVER_NEEDS", "1");
        cmd
    });
    assert!(
        direct.status.success() && !direct.stdout.is_empty(),
        "the wrapper dumps no macros even with its variable, so the refusal tests nothing"
    );
    let output = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(chard_binary());
        cmd.arg("measure")
            .args(PROBE_DEADLINE)
            .args(["-o", "-"])
            .arg("--cc")
            .arg(&driver)
            .arg("--workdir")
            .arg(work.path("w"))
            .args(["--profile", "bare", "--probe", "stack-canary"])
            .env("CHARD_TEST_DRIVER_NEEDS", "1");
        cmd
    });
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(2), "a refusal exits 2:\n{text}");
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    let error = &parsed["error"];
    assert!(
        error["message"]
            .as_str()
            .unwrap_or("")
            .contains("produced no predefined macros"),
        "{error}"
    );
    let hint = error["hint"].as_str().unwrap_or("");
    assert!(
        hint.contains("`env -i "),
        "the hint spells no env -i command: {hint}"
    );
    for (name, value) in chard::compile::COMPILER_ENV_PINNED {
        assert!(
            hint.contains(&format!(" {name}={value} ")),
            "the hint does not spell the pinned {name}: {hint}"
        );
    }
    assert!(
        !hint.contains("CHARD_TEST_DRIVER_NEEDS"),
        "the hint spells a variable the compiler is not given: {hint}"
    );
}

/// A driver whose flagless `-dM -E` dump prints its whole listing and then exits non-zero is
/// refused at detection, with the exit status and the first stderr line in the message, as
/// one a signal ends after its listing is, and the same driver exiting 0 after the same stderr
/// line is measured.
/// that ran on past an error would read as a clean one there, where every variant's dump is
/// refused on its status, the shape
/// `a_macro_dump_that_exits_nonzero_withholds_every_macro_verdict` holds. The
/// wrapper fails `macros-intrinsic.c` alone, the name `toolchain::detect` gives that dump.
#[test]
fn an_intrinsic_dump_that_exits_nonzero_is_refused_with_its_status_and_stderr() {
    if !can_run("that a failing intrinsic dump is refused at detection with its status") {
        return;
    }
    let work = common::Work::new("fakedriver", "intrinsic-exits-1");
    let failing = fake_driver_named(
        work.dir(),
        "fakecc-fails",
        &real_cc(),
        r#"case "$*" in
  *-dM*macros-intrinsic.c)
    "$REAL" "$@"
    echo "fakecc: fatal error: late.h: No such file or directory" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
    );
    let succeeding = fake_driver_named(
        work.dir(),
        "fakecc-warns",
        &real_cc(),
        r#"case "$*" in
  *-dM*macros-intrinsic.c)
    "$REAL" "$@"
    echo "fakecc: warning: late.h is late" >&2
    exit 0 ;;
esac
exec "$REAL" "$@""#,
    );
    let killed = fake_driver_named(
        work.dir(),
        "fakecc-killed",
        &real_cc(),
        r#"case "$*" in
  *-dM*macros-intrinsic.c)
    "$REAL" "$@"
    echo "fakecc: about to be killed" >&2
    kill -9 $$ ;;
esac
exec "$REAL" "$@""#,
    );
    let run = |driver: &Path, dir: &str| {
        common::output_waiting_out_etxtbsy(|| {
            let mut cmd = Command::new(chard_binary());
            cmd.arg("measure")
                .args(PROBE_DEADLINE)
                .args(["-o", "-"])
                .arg("--cc")
                .arg(driver)
                .arg("--workdir")
                .arg(work.path(dir))
                .args(["--profile", "bare", "--probe", "stack-canary"]);
            cmd
        })
    };

    let refused = run(&failing, "w-fails");
    let text = String::from_utf8_lossy(&refused.stdout);
    assert_eq!(refused.status.code(), Some(2), "a refusal exits 2:\n{text}");
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    let error = &parsed["error"];
    assert_eq!(error["code"].as_str(), Some("USER_INPUT"), "{error}");
    let message = error["message"].as_str().unwrap_or("");
    assert!(
        message.contains(
            "macro definitions and exited 1: fakecc: fatal error: late.h: No such file or directory"
        ),
        "the refusal names no exit status or stderr line: {error}"
    );
    assert!(
        !message.contains("produced no predefined macros"),
        "the dump printed its listing, and the refusal says it printed none: {error}"
    );

    // A child a signal ended has no exit status, and is refused in those words.
    let signalled = run(&killed, "w-killed");
    let text = String::from_utf8_lossy(&signalled.stdout);
    assert_eq!(
        signalled.status.code(),
        Some(2),
        "a refusal exits 2:\n{text}"
    );
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    assert!(
        parsed["error"]["message"].as_str().is_some_and(|m| m
            .contains("macro definitions and was killed by a signal: fakecc: about to be killed")),
        "{}",
        parsed["error"]
    );

    let measured = run(&succeeding, "w-warns");
    let text = String::from_utf8_lossy(&measured.stdout);
    assert_eq!(
        measured.status.code(),
        Some(0),
        "a dump that exits 0 after a warning is not refused:\n{text}"
    );
    let report: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not a report ({e}):\n{text}"));
    assert!(report["error"].is_null(), "{}", report["error"]);
}

/// A with-headers dump that prints its listing and then exits non-zero identifies the C
/// library its macros name, as the same listing exiting 0 does, and says it failed: the
/// detection names the exit status and stderr line, as `toolchain.libc_headers_error` does.
/// silent on it. The twin exits 0 after the same stderr line, and the two must name one libc and
/// version, which `fhardened-effective`'s fortify bar is read from, beside the driver's triple.
#[test]
fn a_with_headers_dump_that_exits_nonzero_names_its_failure_in_the_libc_detection() {
    if !can_run("that a failing with-headers dump's libc detection names the failure") {
        return;
    }
    let work = common::Work::new("fakedriver", "headers-exits-1");
    let wrapper = |name: &str, status: u8| {
        fake_driver_named(
            work.dir(),
            name,
            &real_cc(),
            &format!(
                r#"case "$*" in
  *-dM*macros-with-headers.c)
    "$REAL" "$@"
    echo "$PWD/macros-with-headers.c:1:10: fatal error: late.h: No such file or directory" >&2
    exit {status} ;;
esac
exec "$REAL" "$@""#
            ),
        )
    };
    let args = ["--profile", "bare", "--probe", "stack-canary"];
    let failing = work.path("fails");
    std::fs::create_dir_all(&failing).expect("a workdir");
    let report = measure(&wrapper("fakecc-fails", 1), &failing, &args);
    let control_dir = work.path("warns");
    std::fs::create_dir_all(&control_dir).expect("a workdir");
    let control = measure(&wrapper("fakecc-warns", 0), &control_dir, &args);

    let libc = &report["environment"]["libc"];
    let clean = &control["environment"]["libc"];
    assert_eq!(
        (&libc["impl"], &libc["version"]),
        (&clean["impl"], &clean["version"]),
        "a failed dump named another libc than the same listing exiting 0: {libc} against {clean}"
    );
    // The stderr line names the dump's absolute path, and both sentences publish it relative
    // to the work directory, as every other quoted line in a report is.
    let said =
        "exited 1: macros-with-headers.c:1:10: fatal error: late.h: No such file or directory";
    let detection = libc["detection"].as_str().unwrap_or("");
    assert!(
        detection.contains(&format!("in a with-headers macro dump that {said}")),
        "the detection does not name the failed dump: {libc}"
    );
    assert_eq!(
        report["toolchain"]["libc_headers_error"].as_str(),
        Some(said),
        "{}",
        report["toolchain"]
    );
    assert!(
        control["toolchain"].get("libc_headers_error").is_none(),
        "a dump that exited 0 was recorded as failed: {}",
        control["toolchain"]
    );
    assert!(
        !clean["detection"].as_str().unwrap_or("").contains("exited"),
        "the clean dump's detection names a failure: {clean}"
    );

    // Which define a listing ends on is the compiler's order, so a failed dump whose last line
    // ended is read whole: `__GLIBC__` listed last still names glibc 2.43.
    let printing = |name: &str, listing: &str, end: &str| {
        let driver = fake_driver_named(
            work.dir(),
            name,
            &real_cc(),
            &format!(
                "case \"$*\" in\n  *-dM*macros-with-headers.c)\n    printf '{listing}'\n    {end} ;;\nesac\nexec \"$REAL\" \"$@\""
            ),
        );
        let dir = work.path(&format!("w-{name}"));
        std::fs::create_dir_all(&dir).expect("a workdir");
        measure(&driver, &dir, &args)["environment"]["libc"].clone()
    };
    let last = printing(
        "fakecc-glibc-last",
        "#define __GLIBC_MINOR__ 43\\n#define __GLIBC__ 2\\n",
        "exit 1",
    );
    assert_eq!(
        (last["impl"].as_str(), last["version"].as_str()),
        (Some("glibc"), Some("2.43")),
        "{last}"
    );
    let cut = printing(
        "fakecc-glibc-cut",
        "#define __GLIBC__ 2\\n#define __GLIBC_MINOR__ 4",
        "kill -9 $$",
    );
    assert_eq!(cut["impl"].as_str(), Some("glibc"), "{cut}");
    assert!(cut.get("version").is_none_or(Value::is_null), "{cut}");
}

#[test]
fn a_with_headers_dump_cut_off_under_a_driver_that_exits_0_reads_no_version_from_the_cut() {
    if !can_run("that a with-headers dump cut off under exit 0 reads no version from the cut") {
        return;
    }
    let work = common::Work::new("fakedriver", "headers-cut-exit-0");
    let driver = fake_driver_named(
        work.dir(),
        "fakecc",
        &real_cc(),
        "case \"$*\" in\n  *-dM*macros-with-headers.c)\n    printf '#define __GLIBC__ 2\\n#define __GLIBC_MINOR__ 4'\n    exit 0 ;;\nesac\nexec \"$REAL\" \"$@\"",
    );
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "stack-canary"],
    );
    let libc = &report["environment"]["libc"];
    assert_eq!(libc["impl"].as_str(), Some("glibc"), "{libc}");
    assert!(
        libc.get("version").is_none_or(Value::is_null),
        "a define cut short was read as a version: {libc}"
    );
    let said = "exited 0 with its output cut off partway through a line";
    assert!(
        libc["detection"].as_str().is_some_and(|d| d.contains(said)),
        "{libc}"
    );
    assert_eq!(
        report["toolchain"]["libc_headers_error"].as_str(),
        Some(said),
        "{}",
        report["toolchain"]
    );
}

/// A wrapper that prints the real driver's `-dM -E` listing for the jobs `pattern` matches
/// (a `case` pattern over the arguments) cut off two bytes short of its end, partway through
/// its last define, and exits 0, as gcc's driver does when its `cc1` dies of a closed pipe
/// under `-wrapper` (gcc 16.1.1, Fedora 44 x86_64). `$(...)` drops the listing's final
/// newline, and `printf '%s'` adds none.
fn cut_listing_driver(work: &Path, name: &str, pattern: &str) -> PathBuf {
    fake_driver_named(
        work,
        name,
        &real_cc(),
        &format!(
            r#"case "$*" in
  {pattern})
    out=$("$REAL" "$@") || exit $?
    printf '%s' "${{out%??}}"
    exit 0 ;;
esac
exec "$REAL" "$@""#
        ),
    )
}

#[test]
fn a_macro_dump_cut_off_under_a_driver_that_exits_0_withholds_every_macro_verdict() {
    if !can_run("that a dump cut off mid-define under exit 0 withholds the macro channel") {
        return;
    }
    let work = common::Work::new("fakedriver", "dump-cut-exit-0");
    let driver = cut_listing_driver(work.dir(), "fakecc", "*-dM*macros-toolchain-macros-*");
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "toolchain-macros"],
    );

    let mut read = 0;
    for obs in macro_observations(&report) {
        let check = obs["check"].as_str().unwrap_or("?");
        if obs["gating"]["rule"].as_str() == Some("arch-gated") {
            continue;
        }
        read += 1;
        assert_eq!(
            obs["verdict"].as_str(),
            Some("indeterminate"),
            "{check}: a verdict was published over a dump cut off partway through a line"
        );
        let dump = &obs["evidence"]["macro_dump"];
        assert_eq!(dump["exit_status"].as_i64(), Some(0), "{check}: {dump}");
        assert_eq!(
            dump["stdout_unterminated"].as_bool(),
            Some(true),
            "{check}: the record does not say the output was cut: {dump}"
        );
        let observed = obs["evidence"]["observed"].as_str().unwrap_or("");
        assert!(
            observed.contains("exited 0 with its output cut off partway through a line"),
            "{check}: the observation does not name the cut: {observed}"
        );
        assert!(
            obs["evidence"].get("macros").is_none(),
            "{check}: macros were published from a dump that was cut off"
        );
    }
    assert!(read > 0, "no macro observation was checked:\n{report}");
    assert_eq!(
        report["coverage"]["checks_valid"].as_u64(),
        Some(0),
        "a check read through a cut dump has not been validated"
    );
}

#[test]
fn an_intrinsic_dump_cut_off_under_a_driver_that_exits_0_is_refused() {
    if !can_run("that an intrinsic dump cut off under exit 0 is refused at detection") {
        return;
    }
    let work = common::Work::new("fakedriver", "intrinsic-cut-exit-0");
    let driver = cut_listing_driver(work.dir(), "fakecc", "*-dM*macros-intrinsic.c");
    let refused = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(chard_binary());
        cmd.arg("measure")
            .args(PROBE_DEADLINE)
            .args(["-o", "-"])
            .arg("--cc")
            .arg(&driver)
            .arg("--workdir")
            .arg(work.path("w"))
            .args(["--profile", "bare", "--probe", "stack-canary"]);
        cmd
    });
    let text = String::from_utf8_lossy(&refused.stdout);
    assert_eq!(refused.status.code(), Some(2), "a refusal exits 2:\n{text}");
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    assert!(
        parsed["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains(
                "macro definitions and exited 0 with its output cut off partway through a line"
            )),
        "{}",
        parsed["error"]
    );
}

#[test]
fn a_profile_dump_cut_off_under_a_driver_that_exits_0_witnesses_no_target() {
    if !can_run("that a profile dump cut off under exit 0 is dump-failed") {
        return;
    }
    let work = common::Work::new("fakedriver", "profile-cut-exit-0");
    let driver = cut_listing_driver(work.dir(), "fakecc", "*-dM*macros-intrinsic-profile.c");
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            "-O0",
            "--probe",
            "stack-canary",
        ],
    );
    let profile = &report["toolchain"]["target"]["profile_macros"];
    assert_eq!(
        profile["agreement"].as_str(),
        Some("dump-failed"),
        "a dump cut off partway through a line witnessed a target: {profile}"
    );
    assert_eq!(profile["exit_status"].as_i64(), Some(0), "{profile}");
    assert_eq!(
        profile["stdout_unterminated"].as_bool(),
        Some(true),
        "{profile}"
    );
    assert!(
        profile["evidence"]
            .as_str()
            .is_some_and(|e| e.contains("with its output cut off partway through a line")),
        "{profile}"
    );
}

/// The verdict `canary-emitted` reads, from the one observation of it.
fn canary_verdict(report: &Value) -> String {
    let found: Vec<&Value> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o["check"].as_str() == Some("canary-emitted"))
        .collect();
    assert_eq!(found.len(), 1, "one canary-emitted observation: {found:?}");
    found[0]["verdict"].as_str().expect("a verdict").to_owned()
}

#[test]
fn an_env_pair_configures_the_toolchain_and_is_published_in_the_profile() {
    if !can_run("that an --env pair reaches the toolchain and the report") {
        return;
    }
    let work = common::Work::new("fakedriver", "env-pair");
    let driver = fake_driver(
        work.dir(),
        "if [ \"$CHARD_TEST_HARDEN\" = canary ]; then\n\
         \texec \"$REAL\" -fstack-protector-strong \"$@\"\n\
         fi\n\
         exec \"$REAL\" -fno-stack-protector \"$@\"",
    );
    let run = |workdir: &str, extra: &[&str], ambient: Option<&str>| -> Value {
        let output = common::output_waiting_out_etxtbsy(|| {
            let mut cmd = Command::new(chard_binary());
            cmd.arg("measure")
                .args(PROBE_DEADLINE)
                .args(["-o", "-"])
                .arg("--cc")
                .arg(&driver)
                .arg("--workdir")
                .arg(work.path(workdir))
                .args(["--profile", "bare", "--probe", "stack-canary"])
                .args(extra);
            if let Some(value) = ambient {
                cmd.env("CHARD_TEST_HARDEN", value);
            }
            cmd
        });
        let text = String::from_utf8_lossy(&output.stdout);
        let parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
        assert!(
            parsed.get("error").is_none(),
            "chard refused: {}",
            parsed["error"]
        );
        parsed
    };
    let with = run("with", &["--env", "CHARD_TEST_HARDEN=canary"], None);
    let ambient = run("ambient", &[], Some("canary"));
    let other = run("other", &["--env", "CHARD_TEST_HARDEN=other"], None);

    assert_eq!(
        canary_verdict(&with),
        "on",
        "the pair did not reach the driver"
    );
    assert_eq!(
        canary_verdict(&ambient),
        "off",
        "chard's own environment reached the driver"
    );
    assert_eq!(canary_verdict(&other), "off");

    let environment = &with["profile"]["compiler_environment"];
    assert_eq!(
        environment["set"]["CHARD_TEST_HARDEN"].as_str(),
        Some("canary"),
        "the pair is not published: {environment}"
    );
    for (name, value) in chard::compile::COMPILER_ENV_PINNED {
        assert_eq!(
            environment["set"][*name].as_str(),
            Some(*value),
            "{environment}"
        );
    }
    assert_eq!(
        environment["passed"],
        serde_json::json!(["PATH"]),
        "{environment}"
    );
    assert!(
        ambient["profile"]["compiler_environment"]["set"]
            .get("CHARD_TEST_HARDEN")
            .is_none(),
        "a variable chard's environment held is published as set"
    );

    let id = |report: &Value| report["profile"]["id"].as_str().expect("an id").to_owned();
    assert_eq!(id(&ambient), "bare", "a run with no pair keeps its id");
    for report in [&with, &other] {
        let suffix = id(report)
            .strip_prefix("bare+env:")
            .unwrap_or_else(|| panic!("no +env suffix: {}", id(report)))
            .to_owned();
        assert!(
            suffix.len() == 12 && suffix.chars().all(|c| c.is_ascii_hexdigit()),
            "{suffix}"
        );
    }
    assert_ne!(id(&with), id(&other), "two pairs joined as one column");
}

#[test]
fn an_env_pair_naming_a_passed_or_pinned_variable_is_refused_before_any_toolchain_runs() {
    if !can_run("that a refused --env pair exits 2 before the toolchain runs") {
        return;
    }
    let work = common::Work::new("fakedriver", "env-refused");
    let log = work.path("invocations");
    let driver = fake_driver(
        work.dir(),
        &format!("echo ran >> '{}'\nexec \"$REAL\" \"$@\"", log.display()),
    );
    // `common::executable` runs the wrapper once to wait out `ETXTBSY`, which logs a run.
    if log.exists() {
        std::fs::remove_file(&log).expect("clearing the wrapper's first run from its log");
    }
    for pair in [
        "PATH=/nowhere",
        "LC_ALL=en_US.UTF-8",
        "TERM=xterm",
        "NOVALUE",
        "1X=y",
        "COMPILER_PATH=rel/bin",
        "NIX_CFLAGS_COMPILE=-isystem inc",
    ] {
        let output = common::output_waiting_out_etxtbsy(|| {
            let mut cmd = Command::new(chard_binary());
            cmd.arg("measure")
                .args(PROBE_DEADLINE)
                .args(["-o", "-"])
                .arg("--cc")
                .arg(&driver)
                .arg("--workdir")
                .arg(work.path("w"))
                .args([
                    "--profile",
                    "bare",
                    "--probe",
                    "stack-canary",
                    "--env",
                    pair,
                ]);
            cmd
        });
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{pair}: a refusal exits 2:\n{text}"
        );
        let parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
        let message = parsed["error"]["message"].as_str().unwrap_or("");
        assert!(
            message.contains("--env") && message.contains(&format!("{pair:?}")),
            "{pair}: {message}"
        );
        assert!(
            !log.exists(),
            "{pair}: the toolchain ran before the refusal"
        );
    }
}

#[test]
fn an_ambient_deployment_target_moves_nothing_in_a_darwin_triples_report() {
    if !can_run("that an ambient deployment target cannot move a Darwin triple's macro dump") {
        return;
    }
    let Some(clang) = Command::new("sh")
        .args(["-c", "command -v clang"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|p| !p.is_empty())
    else {
        common::capability_gap(
            "deployment target against a Darwin triple",
            "no clang on PATH, and the variable is read by the Darwin driver in clang",
        );
        return;
    };
    let work = common::Work::new("fakedriver", "darwin-target");
    let driver = fake_driver_named(
        work.dir(),
        "fakeclang",
        &clang,
        "exec \"$REAL\" --target=arm64-apple-darwin25.0.0 \"$@\"",
    );
    let args = [
        "--profile",
        "bare",
        "--probe",
        "stack-canary",
        "--emit-macros",
    ];
    let (unset_dir, set_dir) = (work.dir().join("unset"), work.dir().join("set"));
    std::fs::create_dir_all(&unset_dir).expect("work directory");
    std::fs::create_dir_all(&set_dir).expect("work directory");
    let unset = measure_in_env(&driver, &unset_dir, &args, &[]);
    let set = measure_in_env(
        &driver,
        &set_dir,
        &args,
        &[("MACOSX_DEPLOYMENT_TARGET", Path::new("10.15"))],
    );
    let dump = &unset["toolchain"]["predefined_macros"];
    let Some(version) = dump["__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__"].as_str() else {
        // A clang built without the Darwin target: nothing reaches the variable.
        common::capability_gap(
            "deployment target against a Darwin triple",
            &format!("the dump carries no deployment-target macro: {dump}"),
        );
        return;
    };
    assert_ne!(
        version, "101500",
        "the unset run already reads 10.15, so the two runs cannot tell the variable apart"
    );
    assert_eq!(
        set["toolchain"]["predefined_macros"], *dump,
        "an ambient MACOSX_DEPLOYMENT_TARGET changed the macro dump the report publishes"
    );
    assert_eq!(
        set["toolchain"]["predefined_macros_sha256"],
        unset["toolchain"]["predefined_macros_sha256"],
        "an ambient MACOSX_DEPLOYMENT_TARGET changed the macro dump digest"
    );
}

#[test]
fn a_wrapper_that_changes_nothing_publishes_macro_verdicts_with_their_dump_attached() {
    if !can_run(
        "that the fake driver is a faithful proxy and a healthy dump is attached to its verdicts",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "dump-healthy");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "toolchain-macros"],
    );

    let mut published = 0usize;
    for obs in macro_observations(&report) {
        let check = obs["check"].as_str().unwrap_or("?");
        if obs["gating"]["rule"].as_str() == Some("arch-gated") {
            continue;
        }
        assert_eq!(
            obs["evidence"]["macro_dump"]["exit_status"].as_i64(),
            Some(0),
            "{check}: a healthy dump is attached with its exit status"
        );
        assert!(
            matches!(
                obs["evidence"]["macro_source"].as_str(),
                Some("compiled-artifact" | "preprocessor")
            ),
            "{check}: the source of the macros is named"
        );
        if matches!(obs["verdict"].as_str(), Some("on" | "off" | "partial")) {
            published += 1;
        }
    }
    assert!(
        published > 0,
        "the wrapper suppressed every macro verdict, so it is not a faithful proxy"
    );
}

/// A driver that reports a configuration file puts the mechanism where a reader of a
/// bare column looks, and the file's name where a reader of any column looks.
///
/// `profile.flags_source: none` is reserved for compiled-in defaults, and a clang
/// auto-loading `<triple>.cfg` was published under it with the file named only in
/// `toolchain.config_files`, three fields away and unlinked. The wrapper appends clang's
/// own `Configuration file:` line to the `-v` output `toolchain::detect` parses, which is
/// the only place the file is announced.
#[test]
fn a_driver_configuration_file_is_named_as_the_mechanism_behind_a_bare_column() {
    if !can_run(
        "that a bare column measured through a driver configuration file names that mechanism",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "config-file");
    let driver = fake_driver(
        work.dir(),
        r#"case " $* " in
  *" -v "*)
    "$REAL" "$@"
    status=$?
    echo "Configuration file: /some.cfg" >&2
    exit $status ;;
esac
exec "$REAL" "$@""#,
    );

    let bare = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "stack-canary"],
    );
    assert_eq!(
        bare["toolchain"]["config_files"],
        serde_json::json!(["/some.cfg"]),
        "the wrapper's line must reach the parsed field, or nothing below is being tested"
    );
    assert_eq!(
        bare["profile"]["flags_source"].as_str(),
        Some("driver-config-file"),
        "a bare column behind a configuration file is not marked driver-config-file: {}",
        bare["profile"]
    );
    assert!(
        bare["profile"]["toolchain_note"]
            .as_str()
            .is_some_and(|n| n.contains("/some.cfg")),
        "the note names the file: {}",
        bare["profile"]
    );
    let names_file = |report: &Value| {
        report["diagnostics"].as_array().is_some_and(|d| {
            d.iter().any(|x| {
                x["severity"].as_str() == Some("warning")
                    && x["context"].as_str() == Some("toolchain.config_files")
                    && x["message"]
                        .as_str()
                        .is_some_and(|m| m.contains("/some.cfg"))
            })
        })
    };
    assert!(
        names_file(&bare),
        "no diagnostic names the file: {}",
        bare["diagnostics"]
    );

    // Under a profile whose flags have a source of their own, that source stays and the
    // file is still announced.
    let optimized = measure(
        &driver,
        work.dir(),
        &["--profile", "bare-optimized", "--probe", "stack-canary"],
    );
    assert_eq!(
        optimized["profile"]["flags_source"].as_str(),
        Some("chard-enabling-condition"),
        "the -O2 chard passed keeps its attribution"
    );
    assert!(
        optimized["profile"]["toolchain_note"]
            .as_str()
            .is_some_and(|n| n.contains("/some.cfg")),
        "{}",
        optimized["profile"]
    );
    assert!(names_file(&optimized));
}

/// A driver query that fails is refused and recorded, never read as its partial output.
///
/// The wrapper's `-dumpmachine` prints a plausible triple and is then killed by a signal,
/// and its `-v` prints the real driver's report and a `Configuration file:` line and then
/// exits 1. Were only a spawn error refused, the first would publish the triple as
/// `toolchain.target_triple`, which the arch gate and the fortify bar read, and the second
/// would move a bare column's `flags_source` to `driver-config-file`.
#[test]
fn a_driver_query_that_fails_is_refused_and_recorded() {
    if !can_run("that a failed -dumpmachine or -v is refused and recorded") {
        return;
    }
    let work = common::Work::new("fakedriver", "failed-queries");
    let driver = fake_driver(
        work.dir(),
        r#"case " $* " in
  " -dumpmachine ")
    echo riscv64-linux-musl
    kill -KILL $$ ;;
  *" -v "*)
    "$REAL" "$@"
    echo "Configuration file: /some.cfg" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
    );

    let bare = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "stack-canary"],
    );
    let toolchain = &bare["toolchain"];
    assert!(
        toolchain.get("target_triple").is_none(),
        "a killed -dumpmachine's line is not the driver's triple: {toolchain}"
    );
    assert_eq!(
        toolchain["target"]["source"].as_str(),
        Some("kernel"),
        "the gate reads no triple: {}",
        toolchain["target"]
    );
    assert!(
        toolchain["target"]
            .to_string()
            .contains("since -dumpmachine gave no triple chard read"),
        "the gate's evidence says the triple went unread: {}",
        toolchain["target"]
    );
    assert!(
        toolchain.get("config_files").is_none() && toolchain.get("configure_args").is_none(),
        "a failed -v's lines are not the driver's configuration: {toolchain}"
    );
    assert_eq!(bare["profile"]["flags_source"].as_str(), Some("none"));
    let fhardened = bare["composites"]
        .as_array()
        .and_then(|c| c.iter().find(|x| x["id"] == "fhardened-effective"))
        .expect("the composite is published");
    let fortify = fhardened["constituents"]
        .as_array()
        .and_then(|c| c.iter().find(|x| x["check"] == "fortify-effective"))
        .expect("the fortify slot is published");
    assert!(
        !fortify.to_string().contains("riscv64-linux-musl"),
        "the fortify bar reads no triple a killed job printed: {fortify}"
    );
    let warned = |context: &str, ended: &str| {
        bare["diagnostics"].as_array().is_some_and(|d| {
            d.iter().any(|x| {
                x["severity"].as_str() == Some("warning")
                    && x["context"].as_str() == Some(context)
                    && x["message"].as_str().is_some_and(|m| {
                        m.starts_with(&format!("the driver's `{ended}, so chard read nothing"))
                    })
            })
        })
    };
    assert!(
        warned(
            "toolchain.target_triple",
            "-dumpmachine` was killed by a signal"
        ),
        "the refused triple is recorded, and the signal named: {}",
        bare["diagnostics"]
    );
    assert!(
        warned("toolchain.config_files", "-v -E -x c /dev/null` exited 1"),
        "the refused -v is recorded: {}",
        bare["diagnostics"]
    );
}

/// A driver whose `--version` fails is published with no `toolchain.version_raw`, a
/// warning naming the field, and a `run.id` taken without it; the same wrapper with its
/// `--version` passed through publishes the banner, and nothing else the identity reads
/// moves between the two.
#[test]
fn a_driver_version_that_fails_is_refused_and_recorded() {
    if !can_run("that a failed driver --version is refused and recorded") {
        return;
    }
    let work = common::Work::new("fakedriver", "failed-version");
    let switch = work.dir().join("fail-version");
    let driver = fake_driver(
        work.dir(),
        &format!(
            r#"case " $* " in
  " --version ")
    if [ -e '{switch}' ]; then echo 'gcc (Wrapper) 99.0.0'; exit 1; fi ;;
esac
exec "$REAL" "$@""#,
            switch = switch.display()
        ),
    );
    let run = |name: &str| {
        let dir = work.dir().join(name);
        std::fs::create_dir_all(&dir).expect("a workdir per run");
        measure(
            &driver,
            &dir,
            &["--profile", "bare", "--probe", "stack-canary"],
        )
    };
    let warned = |report: &Value| {
        report["diagnostics"].as_array().is_some_and(|d| {
            d.iter().any(|x| {
                x["severity"].as_str() == Some("warning")
                    && x["context"].as_str() == Some("toolchain.version_raw")
                    && x["message"].as_str().is_some_and(|m| {
                        m.starts_with("the driver's `--version` exited 1, so chard read nothing")
                    })
            })
        })
    };

    let honest = run("honest");
    assert!(
        honest["toolchain"]["version_raw"]
            .as_str()
            .is_some_and(|v| !v.is_empty() && !v.contains("Wrapper")),
        "a --version that exited 0 is read: {}",
        honest["toolchain"]
    );
    assert!(!warned(&honest), "{}", honest["diagnostics"]);

    std::fs::write(&switch, "").expect("the switch");
    let failed = run("failed");
    assert!(
        failed["toolchain"].get("version_raw").is_none(),
        "a failed --version's line is not the driver's banner: {}",
        failed["toolchain"]
    );
    assert!(
        warned(&failed),
        "the refused --version is recorded: {}",
        failed["diagnostics"]
    );
    assert_ne!(
        honest["run"]["id"], failed["run"]["id"],
        "run.id is taken without the refused banner"
    );
    // Each input the identity reads, and whether the honest run publishes it, so two
    // absent values are not taken for a key that was fed.
    let inputs: [(&[&str], bool); 12] = [
        (&["toolchain", "id"], true),
        (&["toolchain", "kind"], true),
        (&["toolchain", "version"], true),
        (&["toolchain", "target_triple"], true),
        (&["toolchain", "driver"], true),
        (&["toolchain", "configure_args"], false),
        (&["toolchain", "config_files"], false),
        (&["toolchain", "predefined_macros_sha256"], true),
        (&["toolchain", "linker", "kind"], true),
        (&["toolchain", "linker", "version"], false),
        (&["toolchain", "linker", "path"], true),
        (&["toolchain", "linker", "profile_flags"], false),
    ];
    for (path, fed) in inputs {
        let at = |r: &Value| path.iter().fold(r.clone(), |v, k| v[*k].clone());
        assert!(!fed || !at(&honest).is_null(), "{path:?} is published");
        assert_eq!(
            at(&honest),
            at(&failed),
            "{path:?} does not move with the banner"
        );
    }
    assert_schema_valid("honest", &honest);
    assert_schema_valid("failed", &failed);
}

/// `report` validates against the report schema as chard's producer reads it.
fn assert_schema_valid(label: &str, report: &Value) {
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/chard-report.schema.json"),
        )
        .expect("the report schema"),
    )
    .expect("the schema is JSON");
    let mut errors = Vec::new();
    common::schema::validate(report, &schema, &schema, "", &mut errors);
    assert!(errors.is_empty(), "{label}: {}", errors.join("\n"));
}

/// gcc's form of the same mechanism reaches the same fields.
///
#[test]
fn a_gcc_specs_file_is_named_as_the_mechanism_behind_a_bare_column() {
    if !can_run("that a bare column measured through a gcc specs file names that mechanism") {
        return;
    }
    let work = common::Work::new("fakedriver", "specs-file");
    let driver = fake_driver(
        work.dir(),
        r#"case " $* " in
  *" -v "*)
    echo "Reading specs from /some/specs" >&2
    exec "$REAL" "$@" ;;
esac
exec "$REAL" "$@""#,
    );

    let bare = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "stack-canary"],
    );
    assert_eq!(
        bare["toolchain"]["config_files"],
        serde_json::json!(["/some/specs"]),
        "gcc's line must reach the parsed field, or nothing below is being tested"
    );
    assert_eq!(
        bare["profile"]["flags_source"].as_str(),
        Some("driver-config-file"),
        "{}",
        bare["profile"]
    );
    assert!(
        bare["profile"]["toolchain_note"]
            .as_str()
            .is_some_and(|n| n.contains("/some/specs")),
        "{}",
        bare["profile"]
    );
    assert!(
        bare["diagnostics"]
            .as_array()
            .is_some_and(|d| d.iter().any(|x| {
                x["context"].as_str() == Some("toolchain.config_files")
                    && x["message"]
                        .as_str()
                        .is_some_and(|m| m.contains("/some/specs"))
            })),
        "no diagnostic names the specs file: {}",
        bare["diagnostics"]
    );
}

/// A wrapper whose `-print-prog-name=ld` and `-###` link line both name a shim `ld` that
/// answers `--version` with `banner` and hands everything else to the real linker.
/// reads `driver`.
fn driver_with_ld_banner(work: &Path, banner: &str) -> PathBuf {
    let shim_dir = work.join("ld");
    std::fs::create_dir_all(&shim_dir).expect("the shim directory");
    let shim = common::executable(
        &shim_dir.join("ld"),
        &format!(
            r#"case "$1" in
  --version) echo '{banner}' ;;
  *) real=$("{real}" -print-prog-name=ld); exec "$real" "$@" ;;
esac"#,
            real = real_cc()
        ),
    );
    fake_driver(
        work,
        &format!(
            r#"case " $* " in
  *" -print-prog-name=ld "*) echo '{shim}'; exit 0 ;;
  *" -### "*) echo ' "{shim}" "-o" "/dev/null"' >&2; exit 0 ;;
esac
exec "$REAL" "$@""#,
            shim = shim.display()
        ),
    )
}

/// A wrapper that selects its own linker is published with the linker its link line runs.
/// lld's while `-print-prog-name=ld` keeps printing the real default, so the published
/// kind says which of the two chard read. Runs on any host: only detection is under test.
#[test]
fn a_wrapper_that_selects_its_own_linker_is_published_with_the_linker_it_runs() {
    if !can_run("that a wrapper's own linker selection reaches toolchain.linker") {
        return;
    }
    let work = common::Work::new("fakedriver", "wrapper-selects-linker");
    let shim_dir = work.dir().join("lld");
    std::fs::create_dir_all(&shim_dir).expect("the shim directory");
    let shim = common::executable(
        &shim_dir.join("ld.lld"),
        "case \"$1\" in --version) echo 'LLD 99.0.0 (compatible with GNU linkers)' ;; esac",
    );
    let driver = fake_driver(
        work.dir(),
        &format!(
            r#"case " $* " in
  *" -### "*) echo ' "{}" "-o" "/dev/null"' >&2; exit 0 ;;
esac
exec "$REAL" "$@""#,
            shim.display()
        ),
    );
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "toolchain-macros"],
    );
    let linker = &report["toolchain"]["linker"];
    assert_eq!(linker["kind"].as_str(), Some("lld"), "{linker}");
    assert_eq!(
        linker["path"].as_str(),
        Some(shim.display().to_string().as_str()),
        "{linker}"
    );
    assert_eq!(linker["path_source"].as_str(), Some("driver"), "{linker}");
    assert!(
        linker["detection"]
            .as_str()
            .is_some_and(|d| d.starts_with("the driver's -### link line runs ")),
        "{linker}"
    );
}

/// A wrapper whose `-###` listing names a linker and exits 1 has no linker published from it.
/// was read. Runs on any host: only detection is under test.
#[test]
fn a_wrapper_whose_listing_exits_nonzero_has_no_linker_published_from_it() {
    if !can_run("that a -### listing the driver exited 1 on reaches toolchain.linker nowhere") {
        return;
    }
    let work = common::Work::new("fakedriver", "listing-exits-nonzero");
    let shim_dir = work.dir().join("lld");
    std::fs::create_dir_all(&shim_dir).expect("the shim directory");
    let banner = "LLD 99.0.0 (compatible with GNU linkers)";
    let shim = common::executable(
        &shim_dir.join("ld.lld"),
        &format!("case \"$1\" in --version) echo '{banner}' ;; esac"),
    );
    let driver = fake_driver(
        work.dir(),
        &format!(
            r#"case " $* " in
  *" -### "*) echo 'fakecc: error: unsupported option' >&2; echo ' "{}" "-o" "/dev/null"' >&2; exit 1 ;;
esac
exec "$REAL" "$@""#,
            shim.display()
        ),
    );
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "toolchain-macros"],
    );
    let linker = &report["toolchain"]["linker"];
    assert_ne!(
        linker["path"].as_str(),
        Some(shim.display().to_string().as_str()),
        "the shim named by a listing the driver exited 1 on is not the linker: {linker}"
    );
    assert_ne!(
        linker["version"].as_str(),
        Some(banner),
        "the shim's banner was read, so its path was: {linker}"
    );
    assert!(
        linker["path"].as_str().is_some(),
        "the fallback route resolves the real driver's linker: {linker}"
    );
    let detection = linker["detection"].as_str().unwrap_or_default();
    assert!(
        detection.starts_with(
            "the driver exited 1 on its -### listing with no link-selection flag (fakecc: \
             error: unsupported option), so its link line was not read, and "
        ) && detection.contains("-print-prog-name=ld")
            && !detection.contains("link line runs"),
        "the detection opens with the status and query scope, then names the fallback: {linker}"
    );
}

/// A wrapper exiting 1 on `-###` under a profile with flags: the detection names the scope
#[test]
fn a_rejected_listing_under_a_profile_with_flags_names_the_querys_scope() {
    if !can_run("that the linker detection names a rejected query's scope, not the profile's") {
        return;
    }
    let work = common::Work::new("fakedriver", "listing-scope");
    let driver = fake_driver(
        work.dir(),
        r#"case " $* " in
  *" -### "*) echo 'fakecc: error: unsupported option' >&2; exit 1 ;;
esac
exec "$REAL" "$@""#,
    );
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "openssf-tldr", "--probe", "toolchain-macros"],
    );
    let flags = report["profile"]["cflags"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default();
    assert!(flags > 0, "openssf-tldr has flags: {}", report["profile"]);
    let linker = &report["toolchain"]["linker"];
    let detection = linker["detection"].as_str().unwrap_or_default();
    assert!(
        !detection.contains("no flags"),
        "a profile with {flags} flags is not called flagless: {linker}"
    );
    assert!(
        detection.starts_with(
            "the driver exited 1 on its -### listing with no link-selection flag (fakecc: \
             error: unsupported option), so its link line was not read, and "
        ),
        "the detection names the scope the query ran under: {linker}"
    );
    assert!(
        linker
            .get("profile_flags")
            .is_none_or(|flags| flags == &serde_json::json!([])),
        "openssf-tldr selects no linker: {linker}"
    );
}

/// A wrapper whose error line on `-###` names a file under the work directory has that
#[test]
fn a_rejected_listings_error_line_is_published_relative_to_the_work_directory() {
    if !can_run("that the quoted error line in toolchain.linker.detection is published") {
        return;
    }
    let work = common::Work::new("fakedriver", "listing-error-path");
    let spelled = work.dir().display().to_string();
    let driver = fake_driver(
        work.dir(),
        &format!(
            r#"case " $* " in
  *" -### "*) echo 'fakecc: error: cannot read {spelled}/late.rsp' >&2; exit 1 ;;
esac
exec "$REAL" "$@""#
        ),
    );
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "toolchain-macros"],
    );
    let linker = &report["toolchain"]["linker"];
    let detection = linker["detection"].as_str().unwrap_or_default();
    assert!(
        !detection.contains(&spelled),
        "the work directory's absolute spelling is not published: {linker}"
    );
    assert!(
        detection.contains("(fakecc: error: cannot read late.rsp), so its link line was not read"),
        "the error line is quoted with its path made relative: {linker}"
    );
}

/// A profile naming the linker file outright, under a wrapper exiting 1 on `-###`: the
/// file is the linker, as the profile said, and the detection opens with the rejected
/// query before the profile's naming.
/// that rejects `-###` as if the line had agreed with the profile. The wrapper
/// drops the `--ld-path=` before the real driver sees it, since gcc knows no such flag and
/// the builds are not what is under test; the shim answers `--version` with a GNU ld
/// banner, which no artifact contradicts. Runs on any host: only detection is under test.
#[test]
fn a_profile_naming_the_linker_file_keeps_the_rejected_querys_cause() {
    if !can_run("that a rejected -### under --ld-path= reaches the detection") {
        return;
    }
    let work = common::Work::new("fakedriver", "ldpath-listing-exits-nonzero");
    let shim_dir = work.dir().join("ld");
    std::fs::create_dir_all(&shim_dir).expect("the shim directory");
    let banner = "GNU ld (shim) 2.99";
    let shim = common::executable(
        &shim_dir.join("ld.shim"),
        &format!("case \"$1\" in --version) echo '{banner}' ;; esac"),
    );
    let driver = fake_driver(
        work.dir(),
        r#"case " $* " in
  *" -### "*) echo 'fakecc: error: unsupported option' >&2; exit 1 ;;
esac
for a; do shift; case "$a" in --ld-path=*) ;; *) set -- "$@" "$a" ;; esac; done
exec "$REAL" "$@""#,
    );
    let ld_path = format!("--ld-path={}", shim.display());
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            &ld_path,
            "--probe",
            "toolchain-macros",
        ],
    );
    let linker = &report["toolchain"]["linker"];
    assert_eq!(
        linker["path"].as_str(),
        Some(shim.display().to_string().as_str()),
        "the profile named the file: {linker}"
    );
    assert_eq!(linker["path_source"].as_str(), Some("profile"), "{linker}");
    assert_eq!(linker["version"].as_str(), Some(banner), "{linker}");
    assert_eq!(
        linker["detection"].as_str(),
        Some(
            format!(
                "the driver exited 1 on its -### listing under the link-selection flag \
                 {ld_path} (fakecc: error: unsupported option), so its link line was not \
                 read, and the profile names {} outright; its --version banner names the kind",
                shim.display()
            )
            .as_str()
        ),
        "the detection opens with the rejected query, then the profile's naming: {linker}"
    );
}

/// Does any observation carry ELF facts? `false` on a Mach-O host, where the artifact
/// channel has nothing to read and the cross-check can only report that.
fn any_elf_read(report: &Value) -> bool {
    report["observations"]
        .as_array()
        .is_some_and(|o| o.iter().any(|x| !stored_elf(report, x).is_null()))
}

/// The ELF facts the report's store holds for an observation's build, or `null` where
/// it holds none: no artifact, or one the reader refused.
fn stored_elf<'a>(report: &'a Value, observation: &Value) -> &'a Value {
    observation["build"]["artifact_sha256"]
        .as_str()
        .map_or(&Value::Null, |key| &report["facts"][key]["elf"])
}

fn linker_diagnostic(report: &Value, context: &str) -> Option<Value> {
    report["diagnostics"].as_array().and_then(|d| {
        d.iter()
            .find(|x| x["context"].as_str() == Some(context))
            .cloned()
    })
}

#[test]
fn a_banner_the_artifact_does_not_corroborate_is_published_as_uncorroborated() {
    if !can_run("that a bfd or gold banner over unsigned artifacts is published as uncorroborated")
    {
        return;
    }
    let work = common::Work::new("fakedriver", "ld-banner-gold");
    let driver = driver_with_ld_banner(work.dir(), "GNU gold (GNU Binutils 1.2.3) 1.16");
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "link-defaults"],
    );
    let linker = &report["toolchain"]["linker"];
    assert_eq!(
        linker["kind"].as_str(),
        Some("gold"),
        "the shim's banner must reach the published kind, or nothing below is tested: {linker}"
    );
    assert_eq!(linker["path_source"].as_str(), Some("driver"), "{linker}");
    let artifact = &linker["artifact"];
    assert!(
        linker_diagnostic(&report, "toolchain.linker").is_none(),
        "an uncorroborated banner is not a disagreement: {}",
        report["diagnostics"]
    );
    if common::ELF_HOST {
        assert!(
            any_elf_read(&report),
            "an ELF host read no artifact facts from link-defaults: {}",
            report["observations"]
        );
        assert_eq!(
            artifact["agreement"].as_str(),
            Some("no-signature"),
            "{artifact}"
        );
        assert_eq!(
            artifact["artifacts_read"].as_u64(),
            Some(1),
            "one probe links one artifact, whatever the number of its checks: {artifact}"
        );
        let evidence = artifact["evidence"].as_str().unwrap_or("");
        assert!(
            evidence.contains("cannot be corroborated")
                && (evidence.contains("GCC:") || evidence.contains("clang version")),
            "the evidence quotes the compiler's line: {evidence}"
        );
        assert!(artifact.get("signature").is_none(), "{artifact}");
    } else {
        common::capability_gap(
            "no-signature arm",
            "this host's cc emits Mach-O, so no linked ELF artifact was read; the \
             no-linked-artifact arm is what ran",
        );
        assert_eq!(
            artifact["agreement"].as_str(),
            Some("no-linked-artifact"),
            "{artifact}"
        );
        assert_eq!(artifact["artifacts_read"].as_u64(), Some(0), "{artifact}");
    }
}

#[test]
fn a_banner_the_artifact_contradicts_is_published_as_a_disagreement() {
    if !can_run("that a banner the artifacts contradict is published as a disagreement") {
        return;
    }
    let work = common::Work::new("fakedriver", "ld-banner-lld");
    let driver = driver_with_ld_banner(work.dir(), "LLD 18.1.3 (compatible with GNU linkers)");
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "link-defaults"],
    );
    let linker = &report["toolchain"]["linker"];
    assert_eq!(linker["kind"].as_str(), Some("lld"), "{linker}");
    let artifact = &linker["artifact"];
    if !common::ELF_HOST {
        common::capability_gap(
            "disagrees arm",
            "this host's cc emits Mach-O, so no linked ELF artifact was read and the \
             contradiction cannot be exercised here; run this test on an ELF host",
        );
        assert_eq!(
            artifact["agreement"].as_str(),
            Some("no-linked-artifact"),
            "{artifact}"
        );
        assert!(linker_diagnostic(&report, "toolchain.linker").is_none());
        return;
    }
    assert!(
        any_elf_read(&report),
        "an ELF host read no artifact facts from link-defaults: {}",
        report["observations"]
    );
    assert_eq!(
        artifact["agreement"].as_str(),
        Some("disagrees"),
        "{artifact}"
    );
    assert_eq!(
        artifact["artifacts_read"].as_u64(),
        Some(1),
        "one probe links one artifact, whatever the number of its checks: {artifact}"
    );
    assert!(
        artifact["evidence"]
            .as_str()
            .is_some_and(|e| e.contains("lld-and-mold-sign-every-output")),
        "{artifact}"
    );
    let diagnostic = linker_diagnostic(&report, "toolchain.linker").unwrap_or_else(|| {
        panic!(
            "no diagnostic under toolchain.linker: {}",
            report["diagnostics"]
        )
    });
    assert_eq!(
        diagnostic["severity"].as_str(),
        Some("error"),
        "{diagnostic}"
    );
    assert!(
        report["consistency"]["contradictions"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "a lying PATH is an environment finding, carried as a diagnostic: {}",
        report["consistency"]
    );
}

#[test]
fn a_profile_that_selects_lld_or_mold_is_corroborated_by_the_artifact() {
    if !can_run("that a profile selecting lld or mold is corroborated by the linked artifact") {
        return;
    }
    let mut exercised = 0usize;
    for (name, kind, prefix) in [("ld.lld", "lld", "Linker: "), ("mold", "mold", "mold ")] {
        if !common::ELF_HOST || !on_path(name) {
            common::capability_gap(
                &format!("{kind} corroboration"),
                &format!(
                    "{name} is not on PATH of an ELF host, so the profile cannot select it here"
                ),
            );
            continue;
        }
        let work = common::Work::new("fakedriver", &format!("selects-{kind}"));
        let report = measure(
            Path::new(&real_cc()),
            work.dir(),
            &[
                "--profile",
                "explicit",
                "--flags",
                &format!("-fuse-ld={kind}"),
                "--probe",
                "link-defaults",
                "--probe",
                "linker-default-execstack",
            ],
        );
        let linker = &report["toolchain"]["linker"];
        assert_eq!(linker["kind"].as_str(), Some(kind), "{linker}");
        assert_eq!(
            linker["profile_flags"],
            serde_json::json!([format!("-fuse-ld={kind}")]),
            "{linker}"
        );
        let artifact = &linker["artifact"];
        assert_eq!(artifact["agreement"].as_str(), Some("agrees"), "{artifact}");
        assert!(
            artifact["signature"]
                .as_str()
                .is_some_and(|s| s.starts_with(prefix)),
            "{artifact}"
        );
        assert_eq!(
            artifact["artifacts_read"].as_u64(),
            Some(1),
            "link-defaults links the one counted artifact: {artifact}"
        );
        if targets_x86_64(&report) {
            let evidence = artifact["evidence"].as_str().unwrap_or("");
            assert!(
                evidence.contains("linker-default-execstack-clean")
                    && evidence.contains(&format!("while the profile selected `-fuse-ld={kind}`")),
                "the clean-build artifact is not named beside the selection: {evidence}"
            );
        } else {
            assert_default_probe_gated(&report);
        }
        assert!(linker_diagnostic(&report, "toolchain.linker").is_none());
        exercised += 1;
    }
    if exercised == 0 {
        common::capability_gap(
            "linker corroboration",
            "neither lld nor mold was available, so `agrees` was reached by no report here",
        );
    }
}

#[test]
fn a_control_arm_links_with_the_linker_the_profile_selects() {
    if !can_run("that a control arm carries the profile's linker selection") {
        return;
    }
    let work = common::Work::new("fakedriver", "arm-linker-selection");
    let prefix = work.dir().join("empty-prefix");
    std::fs::create_dir_all(&prefix).expect("creating the empty -B directory");
    let selection = format!("-B{}", prefix.display());
    let mut probes = vec!["ub-null-check", "warn-all", "toolchain-macros"];
    if common::ELF_HOST {
        probes.push("link-defaults");
    } else {
        common::capability_gap(
            "elf-static control arms under a linker selection",
            "a Mach-O artifact is unread, so the elf-static checks withhold before their \
             controls are built",
        );
    }
    let mut args = vec![
        "--profile".to_owned(),
        "explicit".to_owned(),
        "--flags".to_owned(),
        format!("-O2 {selection}"),
    ];
    for probe in &probes {
        args.push("--probe".to_owned());
        args.push((*probe).to_owned());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let report = measure(Path::new(&real_cc()), work.dir(), &args);
    let arm = |check: &str, which: &str| -> Value {
        let o = report["observations"]
            .as_array()
            .and_then(|all| all.iter().find(|o| o["check"] == check))
            .unwrap_or_else(|| panic!("no observation for {check}"));
        o["controls"][which].clone()
    };
    let flags = |check: &str, which: &str| -> Vec<String> {
        arm(check, which)["flags"]
            .as_array()
            .unwrap_or_else(|| panic!("{check} publishes no {which} arm flags"))
            .iter()
            .map(|f| f.as_str().unwrap_or_default().to_owned())
            .collect()
    };
    let mut linked = vec!["no-delete-null-pointer-checks", "warn-all"];
    if common::ELF_HOST {
        linked.push("pie");
    }
    for check in linked {
        for which in ["positive", "negative"] {
            let got = flags(check, which);
            assert_eq!(
                got.first(),
                Some(&selection),
                "{check}'s {which} arm links without the profile's selection: {got:?}"
            );
            assert_eq!(
                got.iter().filter(|f| **f == selection).count(),
                1,
                "{check}'s {which} arm carries the prefix once: {got:?}"
            );
        }
    }
    if common::ELF_HOST {
        // No negative control of its own: the arm is the selection alone, and it is built
        // rather than stood in for by the clean build, which linked with the default.
        assert_eq!(flags("rpath-absent", "negative"), vec![selection.clone()]);
        assert!(
            arm("rpath-absent", "negative")["build"].is_object(),
            "rpath-absent's negative arm publishes no build of its own"
        );
    }
    for which in ["positive", "negative"] {
        let got = flags("ssp-level", which);
        assert_eq!(
            got.first(),
            Some(&selection),
            "a macro check's {which} arm reads without the profile's prefix: {got:?}"
        );
    }
}

/// A wrapper body that runs the host's `cc` with every runtime selection
/// `toolchain::runtime_selecting_flags` takes stripped, in POSIX `sh`.
const STRIP_RUNTIME_SELECTION: &str = "skip=0
for a; do
  shift
  if [ \"$skip\" = 1 ]; then skip=0; continue; fi
  case \"$a\" in
    --stdlib|--rtlib|-stdlib++-isystem|-resource-dir) skip=1; continue;;
    -B|--prefix|-ccc-install-dir) skip=1; continue;;
    -stdlib=*|--stdlib=*|-stdlib++-isystem*|--rtlib=*|-rtlib=*) continue;;
    --unwindlib=*|-unwindlib=*|--gcc-toolchain=*|--gcc-install-dir=*) continue;;
    --gcc-triple=*|-resource-dir=*|-B*|--prefix=*) continue;;
    --config-system-dir=*|--config-user-dir=*|--no-default-config) continue;;
    -static-libgcc|-shared-libgcc|-static-libstdc++|-static-lib*san|-shared-libsan) continue;;
    -static-openmp) continue;;
    -fsjlj-exceptions|-fdwarf-exceptions|-fseh-exceptions|-fwasm-exceptions) continue;;
  esac
  set -- \"$@\" \"$a\"
done
exec \"$REAL\" \"$@\"";

/// What a logged argument vector built, by the output it names, or `None` for an
/// interrogation.
fn probe_build_class(words: &[&str], workdir: &str) -> Option<&'static str> {
    let in_work = |w: &&&str| w.starts_with(workdir);
    let output = words
        .iter()
        .position(|w| *w == "-o")
        .and_then(|i| words.get(i.saturating_add(1)))
        .filter(in_work);
    let dump = words.iter().filter(in_work).find(|w| {
        Path::new(w)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("c") || e.eq_ignore_ascii_case("cpp"))
    });
    let output = *output.or(dump)?;
    let named = |suffix: &str| output.ends_with(suffix);
    Some(
        if named("/macros-intrinsic.c") || named("/macros-with-headers.c") {
            "flagless interrogation"
        } else if output.contains("/macros-intrinsic-profile") {
            "profile interrogation"
        } else if output.contains("/lib")
            && Path::new(output)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("so"))
        {
            "chain library"
        } else if output.contains("-regime-neg") {
            "regime arm"
        } else if output.contains("-pos") {
            "positive arm"
        } else if output.contains("-neg") {
            "negative arm"
        } else if output.contains("clean") {
            "clean build"
        } else if output.contains("measured") {
            "measured build"
        } else {
            "other"
        },
    )
}

/// Every runtime selection spelling gcc 16.1.1 or clang 22.1.8 accepts
/// (`toolchain::runtime_selecting_flags` lists them), split between `--flags` and `--ldflags` so a selection made in either list
/// is fed, with its paths under `dir`.
fn runtime_selection(dir: &str) -> (Vec<String>, Vec<String>) {
    let in_flags: Vec<String> = [
        "-stdlib=libstdc++".to_owned(),
        "--stdlib libstdc++".to_owned(),
        format!("-stdlib++-isystem {dir}/v1"),
        format!("-stdlib++-isystem{dir}/v2"),
        "--rtlib=libgcc".to_owned(),
        "-rtlib=libgcc".to_owned(),
        "--gcc-triple=x86_64-other-linux-gnu".to_owned(),
        format!("-resource-dir {dir}/rd"),
        format!("-B{dir}/b1"),
        format!("--prefix {dir}/p1"),
        format!("-ccc-install-dir {dir}/i/bin"),
        format!("--config-system-dir={dir}/cs"),
        "--no-default-config".to_owned(),
        "-static-libgcc".to_owned(),
        "-static-libstdc++".to_owned(),
        "-static-libasan".to_owned(),
        "-static-libtsan".to_owned(),
        "-static-liblsan".to_owned(),
        "-fsjlj-exceptions".to_owned(),
        "-fdwarf-exceptions".to_owned(),
    ]
    .into();
    let in_ldflags: Vec<String> = [
        "--stdlib=libstdc++".to_owned(),
        "--rtlib libgcc".to_owned(),
        "--unwindlib=libgcc".to_owned(),
        "-unwindlib=libgcc".to_owned(),
        format!("--gcc-toolchain={dir}/g"),
        format!("--gcc-install-dir={dir}/g/lib/gcc/t/16"),
        format!("-resource-dir={dir}/rd2"),
        format!("-B {dir}/b2"),
        format!("--prefix={dir}/p2"),
        format!("--config-user-dir={dir}/cu"),
        "-shared-libgcc".to_owned(),
        "-static-libubsan".to_owned(),
        "-static-libhwasan".to_owned(),
        "-static-libsan".to_owned(),
        "-shared-libsan".to_owned(),
        "-static-openmp".to_owned(),
        "-fseh-exceptions".to_owned(),
        "-fwasm-exceptions".to_owned(),
    ]
    .into();
    (in_flags, in_ldflags)
}

#[test]
fn every_probe_build_carries_the_runtime_the_profile_selects() {
    if !can_run("that every probe build carries the profile's runtime selection") {
        return;
    }
    let work = common::Work::new("fakedriver", "arm-runtime-selection");
    let log = work.path("argv.log");
    let dir = work.dir().display().to_string();
    let driver = fake_driver(
        work.dir(),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\n{STRIP_RUNTIME_SELECTION}",
            log.display()
        ),
    );
    let (in_flags, in_ldflags) = runtime_selection(&dir);
    let mut args = vec![
        "--profile".to_owned(),
        "explicit".to_owned(),
        "--flags".to_owned(),
        format!("-O2 {}", in_flags.join(" ")),
        "--ldflags".to_owned(),
        in_ldflags.join(" "),
    ];
    let probes = [
        "link-defaults",
        "toolchain-macros",
        "warn-all",
        "copy-dt-needed",
        "stack-canary",
    ];
    for probe in probes {
        args.push("--probe".to_owned());
        args.push(probe.to_owned());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let report = measure(&driver, &work.path("w"), &args);
    assert!(
        report["observations"]
            .as_array()
            .is_some_and(|o| !o.is_empty()),
        "the run published no observation: {}",
        report["coverage"]
    );
    let argv = std::fs::read_to_string(&log).expect("the wrapper ran and logged");
    let selection: Vec<Vec<&str>> = in_flags
        .iter()
        .chain(in_ldflags.iter())
        .map(|s| s.split_whitespace().collect())
        .collect();
    assert_eq!(
        selection.len(),
        38,
        "every accepted spelling is in the profile"
    );
    every_build_class_carries(&argv, &work, &selection, |_| Some(true), "runtime");
}

/// Every logged probe build of `argv` whose class `held` answers `Some(true)` carries each
/// spelling of `selection`, one it answers `Some(false)` carries none of them, and one it
/// answers `None` is held elsewhere; every class was seen, so a run that built no arm
/// cannot pass, and no build was left unclassified.
fn every_build_class_carries(
    argv: &str,
    work: &common::Work,
    selection: &[Vec<&str>],
    held: impl Fn(&str) -> Option<bool>,
    what: &str,
) {
    let workdir = format!("{}/", work.path("w").display());
    let mut classes: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut builds = 0_usize;
    for line in argv.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(class) = probe_build_class(&words, &workdir) else {
            continue;
        };
        if class == "flagless interrogation" {
            *classes.entry(class).or_default() += 1;
            continue;
        }
        builds = builds.saturating_add(1);
        *classes.entry(class).or_default() += 1;
        let Some(carries) = held(class) else {
            continue;
        };
        for spelling in selection {
            let carried = words
                .windows(spelling.len())
                .any(|w| w == spelling.as_slice());
            assert_eq!(
                carried,
                carries,
                "a {class} was built {} `{}`:\n{line}",
                if carried { "with" } else { "without" },
                spelling.join(" ")
            );
        }
    }
    for class in [
        "positive arm",
        "negative arm",
        "clean build",
        "measured build",
        "chain library",
    ] {
        assert!(
            classes.get(class).copied().unwrap_or(0) > 0,
            "no {class} was logged; seen {classes:?} over {builds} probe builds"
        );
    }
    assert!(
        !classes.contains_key("other"),
        "a probe build was not classified, so its class was not held to anything: {classes:?}"
    );
    eprintln!("{what} selection checked on {builds} probe builds: {classes:?}");
}

/// Every header selection spelling gcc 16.1.1 or clang 22.1.8 accepts
/// (`toolchain::header_selecting_flags` lists them), gcc's `-I-` among them, which names no
/// directory (`compile::relative_path_readings`), split between `--flags` and `--ldflags` so a
/// selection made in either list is fed, with its paths under `dir`.
fn header_selection(dir: &str) -> (Vec<String>, Vec<String>) {
    let in_flags: Vec<String> = [
        format!("-I{dir}/i1"),
        "-I=inc1".to_owned(),
        format!("-isystem {dir}/s1"),
        "-isystem=sys1".to_owned(),
        format!("-idirafter{dir}/a1"),
        format!("-iquote {dir}/q1"),
        format!("-include{dir}/f1.h"),
        format!("-imacros {dir}/m1.h"),
        "-undef".to_owned(),
        "-I-".to_owned(),
    ]
    .into();
    let in_ldflags: Vec<String> = [
        format!("-I {dir}/i2"),
        "-I =inc2".to_owned(),
        format!("-isystem{dir}/s2"),
        "-isystem =sys2".to_owned(),
        format!("-idirafter {dir}/a2"),
        format!("-iquote{dir}/q2"),
        format!("-include {dir}/f2.h"),
        format!("-imacros{dir}/m2.h"),
        "-pthread".to_owned(),
    ]
    .into();
    (in_flags, in_ldflags)
}

/// A wrapper body that runs the host's `cc` with every header selection
/// `toolchain::header_selecting_flags` takes stripped, in POSIX `sh`. chard's own forced
/// include, the run-witness header, is no part of the profile's selection and stays: with
/// it stripped every artifact would be unwitnessed and nothing past the first build of a
/// variant would be made.
const STRIP_HEADER_SELECTION: &str = "skip=0
for a; do
  shift
  if [ \"$skip\" = 1 ]; then skip=0; continue; fi
  if [ \"$a\" = -include ] && [ \"$1\" = chard_run_witness.h ]; then set -- \"$@\" \"$a\"; continue; fi
  case \"$a\" in
    -I|-isystem|-idirafter|-iquote|-include|-imacros) skip=1; continue;;
    -I*|-isystem*|-idirafter*|-iquote*|-include*|-imacros*) continue;;
    -undef|-pthread) continue;;
  esac
  set -- \"$@\" \"$a\"
done
exec \"$REAL\" \"$@\"";

#[test]
fn every_probe_build_carries_the_headers_the_profile_selects() {
    if !can_run("that every probe build carries the profile's header selection") {
        return;
    }
    let work = common::Work::new("fakedriver", "arm-header-selection");
    let log = work.path("argv.log");
    let dir = work.dir().display().to_string();
    let driver = fake_driver(
        work.dir(),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\n{STRIP_HEADER_SELECTION}",
            log.display()
        ),
    );
    let (in_flags, in_ldflags) = header_selection(&dir);
    let mut args = vec![
        "--profile".to_owned(),
        "explicit".to_owned(),
        "--flags".to_owned(),
        format!("-O2 {}", in_flags.join(" ")),
        "--ldflags".to_owned(),
        in_ldflags.join(" "),
    ];
    let probes = [
        "link-defaults",
        "toolchain-macros",
        "warn-all",
        "copy-dt-needed",
        "stack-canary",
    ];
    for probe in probes {
        args.push("--probe".to_owned());
        args.push(probe.to_owned());
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let report = measure(&driver, &work.path("w"), &args);
    assert!(
        report["observations"]
            .as_array()
            .is_some_and(|o| !o.is_empty()),
        "the run published no observation: {}",
        report["coverage"]
    );
    let argv = std::fs::read_to_string(&log).expect("the wrapper ran and logged");
    let selection: Vec<Vec<&str>> = in_flags
        .iter()
        .chain(in_ldflags.iter())
        .map(|s| s.split_whitespace().collect())
        .collect();
    assert_eq!(
        selection.len(),
        19,
        "every accepted spelling is in the profile"
    );
    chain_libraries_follow_their_build(&argv, &work, &selection);
    every_build_class_carries(
        &argv,
        &work,
        &selection,
        |class| match class {
            "clean build" => Some(false),
            // Attributed and held above.
            "chain library" => None,
            "positive arm"
            | "negative arm"
            | "regime arm"
            | "measured build"
            | "profile interrogation" => Some(true),
            other => panic!("no rule for a build class called {other}"),
        },
        "header",
    );
}

#[test]
fn a_two_token_value_reaches_every_build_once_as_the_measured_pair() {
    if !can_run("that a two-token value reaches every probe build once, as the pair") {
        return;
    }
    let work = common::Work::new("fakedriver", "arm-two-token-value");
    let log = work.path("argv.log");
    let driver = fake_driver(
        work.dir(),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nexec \"$REAL\" \"$@\"",
            log.display()
        ),
    );
    let prefix = format!("{}/px/", work.dir().display());
    let flags = format!("-O2 --library-directory {prefix}");
    let mut args = vec!["--profile", "explicit", "--flags", &flags];
    for probe in [
        "link-defaults",
        "toolchain-macros",
        "warn-all",
        "copy-dt-needed",
        "stack-canary",
    ] {
        args.push("--probe");
        args.push(probe);
    }
    let report = measure(&driver, &work.path("w"), &args);
    assert!(
        report["observations"]
            .as_array()
            .is_some_and(|o| !o.is_empty()),
        "the run published no observation: {}",
        report["coverage"]
    );
    let linker = &report["toolchain"]["linker"];
    assert!(
        linker["kind"].is_string(),
        "the linker was not detected and published: {linker}"
    );
    assert!(
        linker["profile_flags"].is_null()
            || linker["profile_flags"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "the linker was detected under a flag the profile never handed the driver: {}",
        linker["profile_flags"]
    );
    let argv = std::fs::read_to_string(&log).expect("the wrapper ran and logged");
    let pair: Vec<&str> = vec!["--library-directory", prefix.as_str()];
    every_build_class_carries(
        &argv,
        &work,
        std::slice::from_ref(&pair),
        |class| match class {
            // Attributed to its build by `aux_lib_flags`; what matters here is the line below.
            "chain library" => None,
            "clean build"
            | "positive arm"
            | "negative arm"
            | "regime arm"
            | "measured build"
            | "profile interrogation" => Some(true),
            other => panic!("no rule for a build class called {other}"),
        },
        "two-token value",
    );
    let mut lines = 0_usize;
    for line in argv.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            if *word == prefix {
                assert!(
                    i > 0 && words[i - 1] == "--library-directory",
                    "`{prefix}` reached the driver as a word of its own:\n{line}"
                );
            }
        }
        lines = lines.saturating_add(1);
    }
    assert!(lines > 0, "the wrapper logged no argument vector");
}

#[test]
fn a_long_spelling_with_a_relative_value_is_refused_as_the_short_one() {
    if !can_run("that a long spelling's relative value is refused as the short one's") {
        return;
    }
    let work = common::Work::new("fakedriver", "arm-two-token-relative");
    let log = work.path("argv.log");
    let driver = fake_driver(
        work.dir(),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nexec \"$REAL\" \"$@\"",
            log.display()
        ),
    );
    let spellings = ["--library-directory", "-L", "--li"];
    let mut fed = 0_usize;
    for option in spellings {
        let relative = format!("-O2 {option} -B{}/px/", work.dir().display());
        let output = common::output_waiting_out_etxtbsy(|| {
            let mut cmd = Command::new(chard_binary());
            cmd.arg("measure")
                .args(PROBE_DEADLINE)
                .args(["-o", "-"])
                .arg("--cc")
                .arg(&driver)
                .arg("--workdir")
                .arg(work.path("w"))
                .args([
                    "--profile",
                    "explicit",
                    "--probe",
                    "stack-canary",
                    "--flags",
                ])
                .arg(&relative);
            cmd
        });
        let text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{option}: a refusal exits 2:\n{text}"
        );
        let parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
        let message = parsed["error"]["message"].as_str().unwrap_or("");
        assert!(
            message.contains("a relative path")
                && message.contains(&format!("{option} -B{}/px/", work.dir().display())),
            "{option}: the refusal names the pair as a relative path: {message}"
        );
        fed = fed.saturating_add(1);
    }
    assert_eq!(fed, spellings.len(), "every spelling was fed");
    assert!(
        !std::fs::read_to_string(&log).is_ok_and(|argv| argv.contains("/px/")),
        "a refused pair reached the wrapper"
    );
}

#[test]
fn a_value_taking_options_value_reaches_no_build_as_a_selection() {
    if !can_run("that a value-taking option's value reaches no probe build as a selection") {
        return;
    }
    let work = common::Work::new("fakedriver", "arm-value-taking");
    let log = work.path("argv.log");
    let driver = fake_driver(
        work.dir(),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nexec \"$REAL\" \"$@\"",
            log.display()
        ),
    );
    let prefix = format!("-B{}/px/", work.dir().display());
    let flags = format!("-O2 -u {prefix}");
    let mut args = vec!["--profile", "explicit", "--flags", &flags];
    for probe in [
        "link-defaults",
        "toolchain-macros",
        "warn-all",
        "copy-dt-needed",
        "stack-canary",
    ] {
        args.push("--probe");
        args.push(probe);
    }
    let report = measure(&driver, &work.path("w"), &args);
    assert!(
        report["observations"]
            .as_array()
            .is_some_and(|o| !o.is_empty()),
        "the run published no observation: {}",
        report["coverage"]
    );
    let linker = &report["toolchain"]["linker"];
    assert!(
        linker["kind"].is_string(),
        "the linker was not detected and published: {linker}"
    );
    assert!(
        linker["profile_flags"].is_null()
            || linker["profile_flags"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "the linker was detected under a flag the profile never handed the driver: {}",
        linker["profile_flags"]
    );
    let argv = std::fs::read_to_string(&log).expect("the wrapper ran and logged");
    let pair: Vec<&str> = vec!["-u", prefix.as_str()];
    every_build_class_carries(
        &argv,
        &work,
        std::slice::from_ref(&pair),
        |class| match class {
            // Attributed to its build by `aux_lib_flags`; what matters here is the line below.
            "chain library" => None,
            // The regime arm is the measured line with one flag reverted, so it carries the
            // profile's own words as the measured build does.
            "measured build" | "profile interrogation" | "regime arm" => Some(true),
            "clean build" | "positive arm" | "negative arm" => Some(false),
            other => panic!("no rule for a build class called {other}"),
        },
        "value-taking pair",
    );
    let mut lines = 0_usize;
    for line in argv.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (i, word) in words.iter().enumerate() {
            if *word == prefix {
                assert!(
                    i > 0 && words[i - 1] == "-u",
                    "`{prefix}` reached the driver as a word of its own:\n{line}"
                );
            }
        }
        lines = lines.saturating_add(1);
    }
    assert!(lines > 0, "the wrapper logged no argument vector");
}

/// Each chain library of `argv`, attributed to the probe build it precedes in log order,
/// carries every spelling of `selection` where that build is not the clean build and none
/// where it is; the clean build's pair and a carrying pair of the measured build and of an
/// arm were seen.
fn chain_libraries_follow_their_build(argv: &str, work: &common::Work, selection: &[Vec<&str>]) {
    // A chain library is logged without its parent's name, and `build_aux_libs` links the
    // chain just before the build it feeds, so each chain line is attributed to the next
    // probe build in log order and held to that build's class: the clean build's pair
    // carries nothing, every other pair carries the selection.
    let workdir = format!("{}/", work.path("w").display());
    let carries_all = |words: &[&str]| -> bool {
        selection.iter().all(|spelling| {
            words
                .windows(spelling.len())
                .any(|w| w == spelling.as_slice())
        })
    };
    let carries_none = |words: &[&str]| -> bool {
        selection.iter().all(|spelling| {
            !words
                .windows(spelling.len())
                .any(|w| w == spelling.as_slice())
        })
    };
    let mut pending: Vec<(String, bool)> = Vec::new();
    let mut attributed: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for line in argv.lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        match probe_build_class(&words, &workdir) {
            Some("chain library") => {
                assert!(
                    carries_all(&words) || carries_none(&words),
                    "a chain library carried part of the selection:\n{line}"
                );
                pending.push((line.to_owned(), carries_all(&words)));
            }
            Some("flagless interrogation") | None => {}
            Some(class) => {
                for (chain, carried) in pending.drain(..) {
                    assert_eq!(
                        carried,
                        class != "clean build",
                        "a chain library of a {class} was built {} the selection:\n{chain}",
                        if carried { "with" } else { "without" }
                    );
                    *attributed.entry(class).or_default() += 1;
                }
            }
        }
    }
    assert!(
        pending.is_empty(),
        "a chain library followed no probe build: {pending:?}"
    );
    assert_eq!(
        attributed.get("clean build").copied().unwrap_or(0),
        2,
        "the clean build's two chain libraries were attributed and held: {attributed:?}"
    );
    assert!(
        attributed.get("measured build").copied().unwrap_or(0) >= 2
            && attributed.get("positive arm").copied().unwrap_or(0) >= 2,
        "the measured build's and an arm's chain libraries were held: {attributed:?}"
    );
}

#[test]
fn a_profile_that_selects_no_linker_counts_the_clean_build() {
    if !can_run("that a profile selecting no linker counts the clean-build artifact") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "clean build counted",
            "this host's cc emits Mach-O, so no linked ELF artifact is read here",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "selects-nothing");
    let report = measure(
        Path::new(&real_cc()),
        work.dir(),
        &[
            "--profile",
            "bare-optimized",
            "--probe",
            "link-defaults",
            "--probe",
            "linker-default-execstack",
        ],
    );
    let linker = &report["toolchain"]["linker"];
    assert!(
        linker["profile_flags"].is_null(),
        "bare-optimized selects no linker: {linker}"
    );
    assert!(
        any_elf_read(&report),
        "an ELF host read no artifact facts from link-defaults: {}",
        report["observations"]
    );
    let artifact = &linker["artifact"];
    let evidence = artifact["evidence"].as_str().unwrap_or("");
    assert!(
        !evidence.contains("while the profile selected"),
        "no selection was made, so none is named: {evidence}"
    );
    assert_ne!(
        artifact["agreement"].as_str(),
        Some("no-linked-artifact"),
        "{artifact}"
    );
    if targets_x86_64(&report) {
        assert_eq!(
            artifact["artifacts_read"].as_u64(),
            Some(2),
            "both probes' artifacts count under one link line: {artifact}"
        );
        assert!(
            !evidence.contains("left uncounted")
                && !evidence.contains("contributed no readable artifact"),
            "everything read was counted: {evidence}"
        );
    } else {
        assert_eq!(artifact["artifacts_read"].as_u64(), Some(1), "{artifact}");
        assert_default_probe_gated(&report);
    }
}

#[test]
fn a_cxxflags_only_linker_selection_reaches_the_report() {
    if !can_run("that a linker selection present only in cxxflags is published as the C++ linker") {
        return;
    }
    let Some(cxx) = real_cxx() else {
        common::capability_gap(
            "cxxflags linker selection",
            "no c++ on PATH beside cc, so the C++ probe cannot link here",
        );
        return;
    };
    let work = common::Work::new("fakedriver", "cxxflags-linker");
    let driver = fake_driver_named(work.dir(), "fake-cc", &real_cc(), r#"exec "$REAL" "$@""#);
    fake_driver_named(work.dir(), "fake-c++", &cxx, r#"exec "$REAL" "$@""#);
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            "-O2",
            "--cxxflags",
            "-fuse-ld=lld",
            "--probe",
            "link-defaults",
            "--probe",
            "cxx-stdlib-assertions",
        ],
    );
    assert!(
        report["toolchain"]["cxx_driver"]
            .as_str()
            .is_some_and(|p| p.ends_with("fake-c++")),
        "the C++ wrapper must be found beside the C one, or the C++ probe never links: {}",
        report["toolchain"]
    );
    let linker = &report["toolchain"]["linker"];
    assert!(
        linker["profile_flags"].is_null(),
        "the C link selected nothing: {linker}"
    );
    let cxx = &linker["cxx"];
    assert_eq!(
        cxx["profile_flags"],
        serde_json::json!(["-fuse-ld=lld"]),
        "the cxxflags-only selection is published under linker.cxx: {linker}"
    );
    assert!(cxx.get("cxx").is_none(), "cxx never carries a cxx: {cxx}");
    assert!(
        cxx["artifact"].is_object(),
        "the C++ linker carries its own artifact verdict: {cxx}"
    );

    if !common::ELF_HOST || !on_path("ld.lld") {
        common::capability_gap(
            "cxxflags lld corroboration",
            "ld.lld is not on PATH of an ELF host, so the C++ link cannot be corroborated here",
        );
        return;
    }
    assert_eq!(cxx["kind"].as_str(), Some("lld"), "{cxx}");
    assert_eq!(
        cxx["artifact"]["agreement"].as_str(),
        Some("agrees"),
        "{cxx}"
    );
    let cxx_artifacts: Vec<&Value> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o["probe"].as_str() == Some("cxx-stdlib-assertions"))
        .map(|o| stored_elf(&report, o))
        .filter(|elf| !elf.is_null())
        .collect();
    assert!(
        !cxx_artifacts.is_empty(),
        "the C++ probe produced no ELF facts"
    );
    for elf in cxx_artifacts {
        assert!(
            elf["comment"].as_array().is_some_and(|c| c
                .iter()
                .any(|l| l.as_str().is_some_and(|l| l.contains("LLD ")))),
            "the C++ artifact's .comment carries lld's line: {}",
            elf["comment"]
        );
    }
    // The C artifacts were held to the C linker, whose verdict is its own.
    assert_ne!(
        linker["artifact"]["agreement"].as_str(),
        Some("no-linked-artifact"),
        "link-defaults linked a C artifact for the C linker to be held to: {}",
        linker["artifact"]
    );
}

#[test]
fn a_measured_artifact_cut_on_a_read_table_withholds_the_check_that_reads_it() {
    if !can_run(
        "that a measured artifact the reader could not finish withholds the checks reading the cut table and no others",
    ) {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "artifact-unreadable end to end",
            "this host's cc emits Mach-O, so the control arms cannot be read as ELF and the \
             triple would withhold for that reason rather than for the cut table",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "artifact-unreadable");
    let driver = artifact_swapping_driver(work.dir());
    let asked = [
        "--profile",
        "bare",
        "--probe",
        "stack-canary",
        "--probe",
        "link-defaults",
    ];
    let report = measure(&driver, &work.path("cut"), &asked);
    // The same build with its section headers in place, for what the finished tables read.
    let whole = measure(
        &fake_driver_named(
            work.dir(),
            "fakecc-whole",
            &real_cc(),
            r#"exec "$REAL" "$@""#,
        ),
        &work.path("whole"),
        &asked,
    );
    let observations = report["observations"]
        .as_array()
        .expect("observations is an array");
    let find = |id: &str| {
        observations
            .iter()
            .find(|o| o["check"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("{id} was not measured"))
    };

    assert_withheld_for_the_cut_table(&report, find("canary-emitted"));

    for id in ["relro", "noexecstack"] {
        assert_reads_as_the_whole_build(&report, &whole, id);
    }

    assert_withheld_for_its_own_table(find("separate-code"), "section-names");

    let mut unreadable: Vec<&str> = observations
        .iter()
        .filter(|o| o["gating"]["rule"].as_str() == Some("artifact-unreadable"))
        .filter_map(|o| o["check"].as_str())
        .collect();
    unreadable.sort_unstable();
    assert_eq!(
        unreadable,
        ["canary-emitted", "separate-code"],
        "the checks gated artifact-unreadable are not those reading a cut table alone"
    );
    // One cut artifact is one error: under `bare` the clean build is the measured one,
    // and `measure::fault_roles` lists it once, under the label the build was read under.
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    let naming: Vec<&Value> = diagnostics
        .iter()
        .filter(|d| {
            d["severity"].as_str() == Some("error")
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("symbols table"))
        })
        .collect();
    let mut probes: Vec<&str> = naming
        .iter()
        .filter_map(|d| d["context"].as_str())
        .collect();
    probes.sort_unstable();
    assert_eq!(
        probes,
        ["link-defaults", "stack-canary"],
        "one error diagnostic names the cut table per swapped artifact: {diagnostics:?}"
    );
    for d in naming {
        assert!(
            d["message"]
                .as_str()
                .is_some_and(|m| m.contains("the clean artifact's")),
            "the build is named under clean: {}",
            d["message"]
        );
    }
}

/// `id` over the cut artifact of `report`, read through tables the reader finished: what
/// the whole build of `whole` reads, a measurement, and under no rule.
fn assert_reads_as_the_whole_build(report: &Value, whole: &Value, id: &str) {
    let obs = observation(report, id);
    let uncut = observation(whole, id);
    assert!(
        matches!(uncut["verdict"].as_str(), Some("on" | "partial" | "off")),
        "{id} is not measured over the whole build, so the cut one shows nothing: {uncut}"
    );
    assert_eq!(
        (&obs["verdict"], &obs["level"]),
        (&uncut["verdict"], &uncut["level"]),
        "{id}: the cut artifact's verdict and level differ from the whole build's: {obs}"
    );
    assert!(obs["gating"].is_null(), "{id}: no rule withheld it: {obs}");
    assert_eq!(
        stored_elf(report, obs)["truncations"][0]["table"].as_str(),
        Some("symbols"),
        "{id}: the artifact is the cut one"
    );
}

/// A wrapper that builds every variant with the real driver and then strips the
/// section-header table from the two clean artifacts, as `objcopy
/// --strip-section-headers` does to the file's header: `e_shoff`, `e_shnum` and
/// `e_shstrndx` zeroed in place, at the offsets of the file's own class.
///
/// The artifact stays the one this run built, so it carries the run's witness in its note
/// segment and is read; a checked-in object swapped into its place is another build's and
/// is withheld whole under `artifact-lacks-run-witness`
/// (`an_object_a_command_line_cache_kept_from_another_run_is_withheld_and_never_run`).
fn artifact_swapping_driver(work: &Path) -> PathBuf {
    fake_driver(
        work,
        r#""$REAL" "$@"
status=$?
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ] && [ -f "$arg" ]; then
    case "$(basename "$arg")" in
      stack-canary-clean|link-defaults-clean)
        class=$(dd if="$arg" bs=1 skip=4 count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
        if [ "$class" = 2 ]; then shoff=40; width=8; shnum=60; else shoff=32; width=4; shnum=48; fi
        dd if=/dev/zero of="$arg" bs=1 seek="$shoff" count="$width" conv=notrunc 2>/dev/null || exit 96
        dd if=/dev/zero of="$arg" bs=1 seek="$shnum" count=4 conv=notrunc 2>/dev/null || exit 96
        ;;
    esac
  fi
  prev="$arg"
done
exit $status"#,
    )
}

/// `canary-emitted` over the swapped artifact: withheld under the rule that names the
/// symbol tables, with the reason in every field a reader consults, over a triple that
/// discriminated.
/// A second check over the cut artifact withholds for the table it reads itself:
/// `separate-code` reads `.text`'s neighbours by section header and name, and the cut
/// artifact has neither.
fn assert_withheld_for_its_own_table(obs: &Value, table: &str) {
    assert_eq!(
        obs["gating"]["rule"].as_str(),
        Some("artifact-unreadable"),
        "{} reads the {table} table the artifact lacks: {obs}",
        obs["check"]
    );
    assert!(
        obs["gating"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains(&format!("{table} table"))),
        "the reason names the table: {}",
        obs["gating"]
    );
}

fn assert_withheld_for_the_cut_table(report: &Value, canary: &Value) {
    assert_eq!(
        canary["verdict"].as_str(),
        Some("indeterminate"),
        "a symbol table the reader could not reach must not read off: {canary}"
    );
    assert_eq!(
        canary["gating"]["rule"].as_str(),
        Some("artifact-unreadable"),
        "{canary}"
    );
    assert!(
        canary["gating"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("symbols table")),
        "the reason names the table: {}",
        canary["gating"]
    );
    let truncation = &stored_elf(report, canary)["truncations"][0];
    assert_eq!(
        truncation["table"].as_str(),
        Some("symbols"),
        "{truncation}"
    );
    assert_eq!(truncation["kind"].as_str(), Some("unread"), "{truncation}");
    // The predicate's `@truncated` sentence: the unread tables, then the reason.
    assert!(
        canary["evidence"]["observed"]
            .as_str()
            .is_some_and(|o| o.contains(r#"unread_tables=["symbols""#)),
        "the reason a `?` cell prints is the observed string: {}",
        canary["evidence"]["observed"]
    );
    assert_eq!(
        canary["controls"]["discriminating"].as_bool(),
        Some(true),
        "the instrument worked and the reading is what is unreadable: {}",
        canary["controls"]
    );
}

/// The checks of `link-defaults` and `toolchain-macros` whose gate names an architecture.
const ARCH_GATED: &[&str] = &[
    "cet-macro",
    "gcs-macro",
    "branch-protection-macro",
    "cet-marked",
    "gcs-marked",
    "branch-protection-marked",
];

/// Measure `link-defaults` and `toolchain-macros` through `driver`, refusing a report
/// that contradicted itself.
fn measure_arch_probes(driver: &Path, workdir: &Path) -> Value {
    measure_probes(driver, workdir, &["link-defaults", "toolchain-macros"])
}

/// Measure `probes` under `bare` through `driver`, refusing a report that contradicted
/// itself.
fn measure_probes(driver: &Path, workdir: &Path, probes: &[&str]) -> Value {
    measure_probes_under(driver, workdir, &["--profile", "bare"], probes)
}

/// [`measure_probes`] under the profile `profile` names, as `measure`'s own arguments.
fn measure_probes_under(driver: &Path, workdir: &Path, profile: &[&str], probes: &[&str]) -> Value {
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .args(["-o", "-"])
        .arg("--cc")
        .arg(driver)
        .arg("--workdir")
        .arg(workdir)
        .args(profile)
        .args(probes.iter().flat_map(|p| ["--probe", p]))
        .output()
        .expect("spawning chard");
    assert_ne!(
        output.status.code(),
        Some(3),
        "the report contradicted itself: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("a JSON report");
    assert!(report.get("error").is_none(), "{}", report["error"]);
    assert!(
        report["consistency"]["contradictions"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && report["consistency"]["status"] == "consistent",
        "{}",
        report["consistency"]
    );
    report
}

/// The observation of `check` in `report`.
fn observation<'r>(report: &'r Value, check: &str) -> &'r Value {
    report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .find(|o| o["check"].as_str() == Some(check))
        .unwrap_or_else(|| panic!("{check} was selected and has no observation"))
}

/// `report`'s target block reads `agreement`, its macro witness agrees, and no arch-gated
/// verdict was withheld on either.
fn assert_gate_stands(report: &Value, agreement: &str) {
    let target = &report["toolchain"]["target"];
    assert_eq!(target["agreement"].as_str(), Some(agreement), "{target}");
    assert_eq!(
        target["macros"]["agreement"].as_str(),
        Some("agrees"),
        "an honest driver's macro dump names its own target: {target}"
    );
    for check in ARCH_GATED {
        assert_ne!(
            observation(report, check)["gating"]["rule"].as_str(),
            Some("target-arch-contradicted"),
            "{check}: nothing contradicts the gate under {agreement}"
        );
    }
}

/// A driver that builds 32-bit x86 code while its `-dumpmachine` names x86_64, as gcc does
/// under `-m32`, is refused under `openssf-tldr` before any build, and `bare` through the same
/// driver is measured.
#[expect(
    clippy::too_many_lines,
    reason = "one arm: the refused run and the shadow-stack report under the same wrapper, which share its setup and its gap"
)]
#[test]
fn a_driver_building_for_another_architecture_than_it_names_is_refused_under_openssf_tldr() {
    if !can_run(
        "that a profile chosen by architecture is refused where the macro dump names another",
    ) {
        return;
    }
    let real = real_cc();
    let triple = Command::new(&real)
        .arg("-dumpmachine")
        .output()
        .expect("the host's cc runs");
    let triple = String::from_utf8_lossy(&triple.stdout).trim().to_owned();
    let dump = Command::new(&real)
        .args(["-m32", "-dM", "-E", "-x", "c", "/dev/null"])
        .output()
        .expect("the host's cc runs");
    let defines_i386 = dump.status.success()
        && String::from_utf8_lossy(&dump.stdout)
            .lines()
            .any(|l| l.starts_with("#define __i386__ "));
    if !(triple.starts_with("x86_64") && defines_i386) {
        common::capability_gap(
            "a driver building for another architecture than its -dumpmachine names",
            "the host's cc is not an x86_64 driver that defines __i386__ under -m32",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "m32-under-an-x86-64-triple");
    let log = work.path("argv.log");
    let driver = fake_driver(
        work.dir(),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in\n  -dumpmachine) exec \"$REAL\" -dumpmachine ;;\nesac\nexec \"$REAL\" -m32 \"$@\"",
            log.display()
        ),
    );
    let output = common::output_waiting_out_etxtbsy(|| {
        let mut cmd = Command::new(chard_binary());
        cmd.arg("measure")
            .args(PROBE_DEADLINE)
            .args(["-o", "-"])
            .arg("--cc")
            .arg(&driver)
            .arg("--workdir")
            .arg(work.path("w-tldr"))
            .args(["--profile", "openssf-tldr", "--probe", "stack-canary"]);
        cmd
    });
    let text = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(2), "a refusal exits 2:\n{text}");
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("chard's output was not JSON ({e}):\n{text}"));
    let error = &parsed["error"];
    assert_eq!(error["code"].as_str(), Some("CONFIGURATION"), "{error}");
    let message = error["message"].as_str().unwrap_or("");
    assert!(
        message.contains("under x86, the architecture") && message.contains("than under x86_64"),
        "the refusal names the dump's architecture and the gate's: {message}"
    );
    let argv = std::fs::read_to_string(&log).expect("the wrapper ran and logged");
    assert!(
        argv.lines().any(|l| l.contains("-dM")),
        "the macro dump reached the wrapper, so its log is read: {argv}"
    );
    assert!(
        !argv.lines().any(|l| l.contains("stack_canary")),
        "a probe was built before the refusal: {argv}"
    );

    // The shadow-stack probe beside it: its check declares `needs_vm`, so the kernel gate
    // withholds it first on this run (under the default, or in a container the suite
    // recognises), and the target witness then writes `target-arch-contradicted` over it, as
    // over every arch-gated observation.
    let report = measure(
        &driver,
        &work.path("w-bare"),
        &[
            "--profile",
            "bare",
            "--probe",
            "stack-canary",
            "--probe",
            "shadow-stack",
        ],
    );
    assert_eq!(report["profile"]["id"].as_str(), Some("bare"));
    let target = &report["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some("x86_64"), "{target}");
    assert_eq!(
        target["macros"]["agreement"].as_str(),
        Some("disagrees"),
        "bare is measured and the contradiction is published: {target}"
    );
    let shadow = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .find(|o| o["check"] == "shadow-stack-enforced")
        .expect("the shadow-stack probe's check is observed");
    assert_eq!(
        shadow["gating"]["rule"].as_str(),
        Some("target-arch-contradicted"),
        "the target witness wrote over the kernel gate's withholding: {shadow}"
    );
    // The list is omitted when empty, and a non-empty one never reaches here: chard exits 3
    // and writes the report beside the requested path, which `measure` refuses to parse.
    assert!(
        report["consistency"]["contradictions"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && report["consistency"]["status"] == "consistent",
        "{}",
        report["consistency"]
    );
}

/// A `-dumpmachine` the artifacts contradict withholds every verdict its arch gate
/// decided, and the report names the machine that contradicted it; the same driver
/// telling the truth corroborates the gate and moves nothing.
/// which `a_dumpmachine_the_macro_dump_contradicts_withholds_with_no_elf_artifact` holds.
#[test]
fn a_dumpmachine_the_artifacts_contradict_withholds_the_arch_gated_verdicts() {
    if !can_run("that the arch gate's -dumpmachine is held to the artifacts' e_machine") {
        return;
    }
    let real = Command::new(real_cc())
        .arg("-dumpmachine")
        .output()
        .expect("the host's cc runs");
    let triple = String::from_utf8_lossy(&real.stdout).trim().to_owned();
    let x86 = triple.starts_with("x86_64") || triple.starts_with("amd64");
    let (lie, lie_arch) = if x86 {
        ("aarch64-linux-gnu", "aarch64")
    } else {
        ("x86_64-linux-gnu", "x86_64")
    };

    let work = common::Work::new("fakedriver", "dumpmachine-truth");
    let honest = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let truth = measure_arch_probes(&honest, work.dir());
    let work = common::Work::new("fakedriver", "dumpmachine-lies");
    let lying = fake_driver(
        work.dir(),
        &format!(
            r#"case "$*" in
  -dumpmachine) echo {lie}; exit 0 ;;
esac
exec "$REAL" "$@""#
        ),
    );
    let report = measure_arch_probes(&lying, work.dir());

    let target = &report["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some(lie_arch), "{target}");
    assert_eq!(target["source"].as_str(), Some("dumpmachine"), "{target}");

    if !common::ELF_HOST {
        // The macro dump still speaks, and withholds by its own machine; that half is
        // `a_dumpmachine_the_macro_dump_contradicts_withholds_with_no_elf_artifact`'s.
        assert_gate_stands(&truth, "no-elf-artifact");
        assert_eq!(target["agreement"].as_str(), Some("no-elf-artifact"));
        assert_eq!(
            target["macros"]["agreement"].as_str(),
            Some("disagrees"),
            "{target}"
        );
        common::capability_gap(
            "a -dumpmachine the artifacts contradict",
            "the host's cc emits no ELF, so no e_machine exists to hold the gate to",
        );
        return;
    }

    assert_gate_stands(&truth, "agrees");

    assert_eq!(
        target["agreement"].as_str(),
        Some("disagrees"),
        "the artifacts are of the host's architecture, not {lie}: {target}"
    );
    let native = if x86 { "x86_64" } else { "aarch64" };
    assert!(
        target["machines"][native].as_u64().is_some_and(|n| n > 0),
        "the machine the artifacts carry is counted: {target}"
    );
    for check in ARCH_GATED {
        let o = observation(&report, check);
        assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{check}: {o}");
        assert_eq!(
            o["gating"]["rule"].as_str(),
            Some("target-arch-contradicted"),
            "{check}: {}",
            o["gating"]
        );
        assert!(
            o["gating"]["reason"]
                .as_str()
                .is_some_and(|r| r.contains(&format!("e_machine {native}"))),
            "{check}: the reason names the machine: {}",
            o["gating"]["reason"]
        );
    }
    let pie = observation(&report, "pie");
    assert_ne!(
        pie["gating"]["rule"].as_str(),
        Some("target-arch-contradicted"),
        "a portable check was read from the artifact and stands: {pie}"
    );
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["severity"].as_str() == Some("error")
                && d["context"].as_str() == Some("toolchain.target")),
        "the disagreement is an error diagnostic under toolchain.target: {}",
        report["diagnostics"]
    );
}

/// A `-dumpmachine` the macro dump contradicts, on a run that reads no ELF artifact,
/// withholds every verdict whose arch gate the dump's machine decides otherwise.
/// host's own machine, which the dump names, each is measured or gated out instead, so
/// every arch-gated check of the selection is withheld, whichever host runs it. The gate's
/// decision is compared whole: compared only for the checks measured under the host's
#[test]
fn a_dumpmachine_the_macro_dump_contradicts_withholds_with_no_elf_artifact() {
    if !can_run("that the arch gate's -dumpmachine is held to the intrinsic macro dump") {
        return;
    }
    let real = Command::new(real_cc())
        .arg("-dumpmachine")
        .output()
        .expect("the host's cc runs");
    let triple = String::from_utf8_lossy(&real.stdout).trim().to_owned();
    let x86 = triple.starts_with("x86_64") || triple.starts_with("amd64");
    let (macro_name, machine) = if x86 {
        ("__x86_64__", "x86_64")
    } else {
        ("__aarch64__", "aarch64")
    };

    let work = common::Work::new("fakedriver", "dumpmachine-macros");
    let lying = fake_driver(
        work.dir(),
        r#"case "$*" in
  -dumpmachine) echo riscv64-linux-gnu; exit 0 ;;
esac
exec "$REAL" "$@""#,
    );
    let mut probes = vec!["cet-object"];
    if !common::ELF_HOST {
        probes.push("toolchain-macros");
    }
    let report = measure_probes(&lying, work.dir(), &probes);

    let target = &report["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some("riscv64"), "{target}");
    assert_eq!(
        target["agreement"].as_str(),
        Some("no-elf-artifact"),
        "the selection builds no ELF artifact under the lie: {target}"
    );
    assert_eq!(target["artifacts_read"].as_u64(), Some(0), "{target}");
    let witness = &target["macros"];
    assert_eq!(
        witness["defined"],
        serde_json::json!([macro_name]),
        "the dump names the host's own machine: {witness}"
    );
    assert_eq!(
        witness["agreement"].as_str(),
        Some("disagrees"),
        "{witness}"
    );
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["severity"].as_str() == Some("error")
                && d["context"].as_str() == Some("toolchain.target")
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("intrinsic macro dump"))),
        "the disagreement is an error diagnostic naming the dump: {}",
        report["diagnostics"]
    );

    let mut contradicted = vec!["cet-marked-object"];
    if !common::ELF_HOST {
        contradicted.extend(["cet-macro", "gcs-macro", "branch-protection-macro"]);
    }
    contradicted.sort_unstable();
    let witness = format!("macro dump defines {macro_name}, the macro of e_machine {machine}");
    let mut withheld = Vec::new();
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("a check id");
        if o["gating"]["rule"].as_str() == Some("target-arch-contradicted") {
            assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{check}: {o}");
            assert!(
                o["gating"]["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains(&witness)
                        && r.contains("left outside the table for riscv64")),
                "{check}: the reason names the witness and the decision it contradicts: {}",
                o["gating"]["reason"]
            );
            withheld.push(check);
        }
    }
    withheld.sort_unstable();
    assert_eq!(
        withheld, contradicted,
        "every arch-gated check of the selection is withheld under the {machine} witness"
    );
}

/// A macro dump that defines no architecture macro, under a `-dumpmachine` of a family
/// that has one, contradicts the gate's architecture on a run that reads no ELF artifact.
///
/// The wrapper answers `-dumpmachine` with `aarch64-linux-gnu` and strips the
#[test]
fn a_macro_dump_with_no_arch_macro_contradicts_a_mapped_dumpmachine() {
    if !can_run("that a dump with no architecture macro contradicts a mapped -dumpmachine") {
        return;
    }
    let work = common::Work::new("fakedriver", "dumpmachine-no-arch-macro");
    let lying = fake_driver(
        work.dir(),
        r#"case "$*" in
  -dumpmachine) echo aarch64-linux-gnu; exit 0 ;;
  *-dM*)
    out=$("$REAL" "$@"); st=$?
    printf '%s\n' "$out" | grep -v -E '^#define (__x86_64__|__i386__|__aarch64__) '
    exit $st ;;
esac
exec "$REAL" "$@""#,
    );
    let mut probes = vec!["cet-object"];
    if !common::ELF_HOST {
        probes.push("toolchain-macros");
    }
    let report = measure_probes(&lying, work.dir(), &probes);

    let target = &report["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some("aarch64"), "{target}");
    assert_eq!(
        target["agreement"].as_str(),
        Some("no-elf-artifact"),
        "the selection builds no ELF artifact under the claim: {target}"
    );
    assert_eq!(target["artifacts_read"].as_u64(), Some(0), "{target}");
    let witness = &target["macros"];
    assert_eq!(witness["defined"], serde_json::json!([]), "{witness}");
    assert_eq!(
        witness["agreement"].as_str(),
        Some("disagrees"),
        "a dump with no architecture macro is a target outside aarch64's family: {witness}"
    );
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["severity"].as_str() == Some("error")
                && d["context"].as_str() == Some("toolchain.target")
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("defines none of"))),
        "the absence is an error diagnostic: {}",
        report["diagnostics"]
    );

    let mut contradicted = vec!["cet-marked-object"];
    if !common::ELF_HOST {
        contradicted.extend(["cet-macro", "gcs-macro", "branch-protection-macro"]);
    }
    contradicted.sort_unstable();
    let mut withheld = Vec::new();
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("a check id");
        if o["gating"]["rule"].as_str() == Some("target-arch-contradicted") {
            assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{check}: {o}");
            assert!(
                o["gating"]["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains("macro dump defines none of __x86_64__")
                        && r.contains("the verdict it had (")),
                "{check}: the reason names the absence and the verdict it had: {}",
                o["gating"]["reason"]
            );
            withheld.push(check);
        }
    }
    withheld.sort_unstable();
    assert_eq!(
        withheld, contradicted,
        "every arch-gated check of the selection is withheld, the aarch64 one included"
    );
    let gated_out = observation(&report, "cet-marked-object");
    assert!(
        gated_out["gating"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("it was gated out for aarch64")
                && r.contains("unsupported under arch-gated")),
        "the withholding quotes the unsupported it replaced: {}",
        gated_out["gating"]["reason"]
    );
}

/// A macro dump the artifacts overrule is published as overruled, with a warning of its
/// own, and withholds nothing.
/// The wrapper adds `-undef` to every `-dM` invocation and passes every build through, so
/// the flagless dump defines none of the architecture macros while every ELF artifact the
/// run built carries the host's own machine: the shape a profile's `-undef` makes of the
#[test]
fn a_dump_the_artifacts_overrule_is_published_as_overruled_and_withholds_nothing() {
    if !common::ELF_HOST {
        common::capability_gap(
            "that a dump the artifacts overrule is published as overruled",
            "the overrule needs an ELF artifact of the host's family",
        );
        return;
    }
    if !can_run("that a dump the artifacts overrule is published as overruled") {
        return;
    }
    let work = common::Work::new("fakedriver", "dump-overruled");
    let undef = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*) exec "$REAL" -undef "$@" ;;
esac
exec "$REAL" "$@""#,
    );
    let report = measure_probes(&undef, work.dir(), &["cet-object"]);

    let target = &report["toolchain"]["target"];
    assert_eq!(
        target["agreement"].as_str(),
        Some("agrees"),
        "the artifacts carry the host's own machine: {target}"
    );
    assert!(
        target["artifacts_read"].as_u64().is_some_and(|n| n > 0),
        "{target}"
    );
    let witness = &target["macros"];
    assert_eq!(witness["defined"], serde_json::json!([]), "{witness}");
    assert_eq!(
        witness["agreement"].as_str(),
        Some("overruled"),
        "{witness}"
    );
    assert!(
        witness["evidence"]
            .as_str()
            .is_some_and(|e| e.contains("from C probes")
                && e.contains("taken with no profile flag")
                && !e.contains("-undef")),
        "the flagless dump's evidence names the artifacts and no flag: {witness}"
    );

    let under_target: Vec<&Value> = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| d["context"].as_str() == Some("toolchain.target"))
        .collect();
    assert_eq!(under_target.len(), 1, "{under_target:?}");
    assert_eq!(under_target[0]["severity"].as_str(), Some("warning"));
    assert!(
        under_target[0]["message"].as_str().is_some_and(|m| m
            .starts_with("a macro dump defining none of the architecture macros is overruled")
            && !m.contains("contradicts")
            && !m.contains("no verdict moved")),
        "{}",
        under_target[0]["message"]
    );
    for o in report["observations"].as_array().expect("observations") {
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("target-arch-contradicted"),
            "an overruled dump withholds nothing: {o}"
        );
    }
    // A report with no contradiction carries an empty `contradictions` list and says so.
    assert!(
        report["consistency"]["contradictions"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && report["consistency"]["status"] == "consistent",
        "{}",
        report["consistency"]
    );
}

#[test]
fn an_overruled_dump_under_flags_that_silence_nothing_names_no_cause() {
    if !common::ELF_HOST {
        common::capability_gap(
            "that an overruled dump under flags that silence nothing names no cause",
            "the overrule needs an ELF artifact of the host's family",
        );
        return;
    }
    if !can_run("that an overruled dump under flags that silence nothing names no cause") {
        return;
    }
    let work = common::Work::new("fakedriver", "dump-overruled-optimized");
    let undef = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*) exec "$REAL" -undef "$@" ;;
esac
exec "$REAL" "$@""#,
    );
    let report = measure_probes_under(
        &undef,
        work.dir(),
        &["--profile", "bare-optimized"],
        &["cet-object"],
    );
    let target = &report["toolchain"]["target"];
    assert_eq!(target["agreement"].as_str(), Some("agrees"), "{target}");
    assert_eq!(
        target["macros"]["agreement"].as_str(),
        Some("overruled"),
        "{target}"
    );
    let under = &target["profile_macros"];
    assert_eq!(under["agreement"].as_str(), Some("overruled"), "{under}");
    let under_target: Vec<&Value> = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| d["context"].as_str() == Some("toolchain.target"))
        .collect();
    assert_eq!(under_target.len(), 1, "{under_target:?}");
    assert_eq!(under_target[0]["severity"].as_str(), Some("warning"));
    assert!(
        under_target[0]["message"].as_str().is_some_and(|m| m
            .contains("under the profile's C flags")
            && !m.contains("contradicts")),
        "{}",
        under_target[0]["message"]
    );
    for o in report["observations"].as_array().expect("observations") {
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("target-arch-contradicted"),
            "{o}"
        );
    }
}

#[test]
fn an_artifact_at_the_other_width_or_byte_order_withholds_the_gated_checks() {
    if !can_run("that the other width or byte order withholds the gated checks") {
        return;
    }
    let cross = Command::new("sh")
        .args(["-c", "command -v aarch64-linux-gnu-gcc"])
        .output()
        .expect("sh is available");
    let cross = String::from_utf8_lossy(&cross.stdout).trim().to_owned();
    if cross.is_empty() {
        common::capability_gap(
            "the other width or byte order",
            "an aarch64 cross gcc (aarch64-linux-gnu-gcc) is not installed",
        );
        return;
    }
    for (flag, abi, class) in [
        ("-mbig-endian", "ELF64 big-endian", 64),
        ("-mabi=ilp32", "ELF32 little-endian", 32),
    ] {
        let work = common::Work::new("fakedriver", &format!("abi-{}", abi.replace(' ', "-")));
        let driver = fake_driver_named(
            work.dir(),
            "fakecc",
            &cross,
            &format!("exec \"$REAL\" {flag} \"$@\""),
        );
        let report = measure_probes_under(
            &driver,
            work.dir(),
            &["--profile", "bare"],
            // `pic-object` is measured on aarch64 and compiles to an object, so the run
            // reads an artifact of the read family at the other width or order;
            // `cet-object` is gated out under aarch64, and its withholding names that.
            &["pic-object", "cet-object"],
        );
        assert_the_other_abi_withholds(&report, flag, abi, class);
    }
}

/// What one run of `an_artifact_at_the_other_width_or_byte_order_withholds_the_gated_checks`
/// publishes: the machine agrees, the abi witness disagrees naming `abi`, every artifact
/// carries `class` and `abi`'s order, every gated check is withheld under the rule and
/// nothing else is, and one error stands under `toolchain.target`.
fn assert_the_other_abi_withholds(report: &Value, flag: &str, abi: &str, class: u64) {
    {
        let target = &report["toolchain"]["target"];
        assert_eq!(target["arch"].as_str(), Some("aarch64"), "{flag}: {target}");
        // The cross driver here has no C library headers, so every probe fails to compile
        // and no artifact is read; where one is (a cross toolchain with a sysroot), the
        // machine agrees and the artifacts carry the other width or order.
        assert!(
            matches!(
                target["agreement"].as_str(),
                Some("agrees" | "no-elf-artifact")
            ),
            "{flag}: the machine does not disagree: {target}"
        );
        let witness = &target["abi"];
        assert_eq!(
            witness["agreement"].as_str(),
            Some("disagrees"),
            "{flag}: {witness}"
        );
        assert_eq!(
            witness["expected"].as_str(),
            Some("ELF64 little-endian"),
            "{flag}"
        );
        if target["agreement"].as_str() == Some("agrees") {
            assert!(
                witness["artifacts"][abi].as_u64().is_some_and(|n| n >= 1),
                "{flag}: the object probe's artifacts carry {abi}: {witness}"
            );
        } else {
            assert!(
                witness["artifacts"]
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty),
                "{flag}: no artifact, so none is listed: {witness}"
            );
        }
        assert_eq!(
            witness["dumps"]["intrinsic macro dump"].as_str(),
            Some(abi),
            "{flag}: the flagless dump through this driver names it too: {witness}"
        );
        let mut gated_seen = 0;
        for o in report["observations"].as_array().expect("observations") {
            let elf = o["build"]["artifact_sha256"]
                .as_str()
                .and_then(|sha| report["facts"][sha]["elf"].as_object());
            if let Some(elf) = elf {
                assert_eq!(elf["elf_class"].as_u64(), Some(class), "{flag}: {o}");
                assert_eq!(
                    elf["elf_data"].as_str(),
                    Some(abi.split(' ').nth(1).expect("an order")),
                    "{flag}: {o}"
                );
            }
            let check = o["check"].as_str().expect("a check id");
            let gated = !chard::mechanism::archs_of(check).is_empty();
            let rule = o["gating"]["rule"].as_str();
            if gated {
                gated_seen += 1;
                assert_eq!(rule, Some("target-abi-contradicted"), "{flag}: {o}");
                assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{flag}: {o}");
                assert!(
                    o["gating"]["reason"]
                        .as_str()
                        .is_some_and(|r| r.contains(abi)
                            && r.contains("stand for ELF64 little-endian")
                            && r.contains("(toolchain.target.abi)")),
                    "{flag}: {o}"
                );
            } else {
                assert_ne!(rule, Some("target-abi-contradicted"), "{flag}: {o}");
            }
        }
        assert!(
            gated_seen >= 1,
            "{flag}: the run published no arch-gated observation to withhold"
        );
        let errors: Vec<&Value> = report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .filter(|d| {
                d["context"].as_str() == Some("toolchain.target")
                    && d["severity"].as_str() == Some("error")
            })
            .collect();
        assert_eq!(errors.len(), 1, "{flag}: {errors:?}");
        assert!(
            errors[0]["message"]
                .as_str()
                .is_some_and(|m| m.contains("target-abi-contradicted") && m.contains(abi)),
            "{flag}: {}",
            errors[0]["message"]
        );
        assert_eq!(
            report["consistency"]["contradictions"]
                .as_array()
                .map(Vec::len),
            Some(0),
            "{flag}"
        );
    }
}

#[test]
fn a_wrapper_adding_mx32_to_the_host_driver_withholds_from_the_dump_alone() {
    if !cfg!(target_arch = "x86_64") || !common::ELF_HOST {
        common::capability_gap(
            "that a wrapper adding -mx32 withholds the gated checks from the dump alone",
            "-mx32 is an x86_64 ELF driver's flag",
        );
        return;
    }
    if !can_run("that a wrapper adding -mx32 withholds the gated checks from the dump alone") {
        return;
    }
    let work = common::Work::new("fakedriver", "abi-x32-dump");
    let driver = fake_driver(work.dir(), "exec \"$REAL\" -mx32 \"$@\"");
    let report = measure_probes_under(
        &driver,
        work.dir(),
        &["--profile", "bare"],
        &["pic-object", "cet-object"],
    );
    let target = &report["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some("x86_64"), "{target}");
    let witness = &target["abi"];
    assert_eq!(
        witness["agreement"].as_str(),
        Some("disagrees"),
        "{witness}"
    );
    assert_eq!(
        witness["dumps"]["intrinsic macro dump"].as_str(),
        Some("ELF32 little-endian"),
        "{witness}"
    );
    assert_eq!(
        target["macros"]["abi"].as_str(),
        Some("ELF32 little-endian")
    );
    let mut gated_seen = 0;
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("a check id");
        let rule = o["gating"]["rule"].as_str();
        if chard::mechanism::archs_of(check).is_empty() {
            assert_ne!(rule, Some("target-abi-contradicted"), "{o}");
        } else {
            gated_seen += 1;
            assert_eq!(rule, Some("target-abi-contradicted"), "{o}");
        }
    }
    assert!(gated_seen >= 1);
    let errors = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| {
            d["context"].as_str() == Some("toolchain.target")
                && d["severity"].as_str() == Some("error")
        })
        .count();
    assert_eq!(errors, 1, "{}", report["diagnostics"]);
    assert_eq!(
        report["consistency"]["contradictions"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
}

/// Under `bare` through the wrapper of
/// `a_target_the_profile_flags_select_is_witnessed_with_no_elf_artifact`: both witnesses
/// that read agree with riscv64, no dump under profile flags is published, and the gate
/// stands: riscv64 has no row in the mechanism table, so the decision taken before any
/// build is `arch-outside-table`, and no witness overwrites it.
fn assert_gate_stands_unflagged(bare: &Value) {
    let target = &bare["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some("riscv64"), "{target}");
    assert_eq!(
        target["agreement"].as_str(),
        Some("no-elf-artifact"),
        "{target}"
    );
    assert_eq!(
        target["macros"]["agreement"].as_str(),
        Some("no-arch-macro"),
        "{target}"
    );
    assert!(
        target.get("profile_macros").is_none(),
        "bare gives no flags to dump under: {target}"
    );
    let gated = observation(bare, "cet-marked-object");
    assert_eq!(
        gated["gating"]["rule"].as_str(),
        Some("arch-outside-table"),
        "{gated}"
    );
}

#[test]
fn a_target_the_profile_flags_select_is_witnessed_with_no_elf_artifact() {
    if !can_run("that a target the profile's flags select is held to the arch gate") {
        return;
    }
    let script = r#"case "$*" in
  -dumpmachine) echo riscv64-linux-gnu; exit 0 ;;
  *-dM*)
    out=$("$REAL" "$@"); st=$?
    printf '%s\n' "$out" | grep -v -E '^#define (__x86_64__|__i386__|__aarch64__) '
    case "$*" in *-DCHARD_SELECTS_X86_64*) echo '#define __x86_64__ 1' ;; esac
    exit $st ;;
esac
exec "$REAL" "$@""#;

    let work = common::Work::new("fakedriver", "profile-target-bare");
    let driver = fake_driver(work.dir(), script);
    assert_gate_stands_unflagged(&measure_probes(&driver, work.dir(), &["cet-object"]));

    let work = common::Work::new("fakedriver", "profile-target-explicit");
    let driver = fake_driver(work.dir(), script);
    let report = measure_probes_under(
        &driver,
        work.dir(),
        &["--profile", "explicit", "--flags", "-DCHARD_SELECTS_X86_64"],
        &["cet-object"],
    );
    let target = &report["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some("riscv64"), "{target}");
    assert_eq!(
        target["agreement"].as_str(),
        Some("no-elf-artifact"),
        "the selection builds no ELF artifact: {target}"
    );
    assert_eq!(
        target["macros"]["agreement"].as_str(),
        Some("no-arch-macro"),
        "the flagless dump agrees with -dumpmachine by construction: {target}"
    );
    let profile = &target["profile_macros"];
    assert_eq!(
        profile["flags"],
        serde_json::json!(["-DCHARD_SELECTS_X86_64"]),
        "{profile}"
    );
    assert_eq!(profile["exit_status"].as_i64(), Some(0), "{profile}");
    assert_eq!(
        profile["defined"],
        serde_json::json!(["__x86_64__"]),
        "{profile}"
    );
    assert_eq!(
        profile["agreement"].as_str(),
        Some("disagrees"),
        "{profile}"
    );

    let withheld = observation(&report, "cet-marked-object");
    assert_eq!(
        withheld["verdict"].as_str(),
        Some("indeterminate"),
        "{withheld}"
    );
    assert_eq!(
        withheld["gating"]["rule"].as_str(),
        Some("target-arch-contradicted"),
        "{withheld}"
    );
    assert!(
        withheld["gating"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("under the profile's C flags defines __x86_64__")),
        "the reason names the witness: {}",
        withheld["gating"]["reason"]
    );
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["severity"].as_str() == Some("error")
                && d["context"].as_str() == Some("toolchain.target")
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("under the profile's C flags"))),
        "the disagreement is an error diagnostic naming the witness: {}",
        report["diagnostics"]
    );
}

/// The wrappers of `a_target_only_the_cxxflags_select_is_witnessed_with_no_elf_artifact`:
/// the C one answers `-dumpmachine` with `riscv64-linux-gnu` and strips the three
/// architecture macros from every dump, and the C++ one strips them too and defines
/// `__x86_64__` in a dump run under `-DCHARD_CXX_SELECTS_X86_64`.
const CXX_TARGET_C_SCRIPT: &str = r#"case "$*" in
  -dumpmachine) echo riscv64-linux-gnu; exit 0 ;;
  *-dM*)
    out=$("$REAL" "$@"); st=$?
    printf '%s\n' "$out" | grep -v -E '^#define (__x86_64__|__i386__|__aarch64__) '
    exit $st ;;
esac
exec "$REAL" "$@""#;
const CXX_TARGET_CXX_SCRIPT: &str = r#"case "$*" in
  *-dM*)
    out=$("$REAL" "$@"); st=$?
    printf '%s\n' "$out" | grep -v -E '^#define (__x86_64__|__i386__|__aarch64__) '
    case "$*" in *-DCHARD_CXX_SELECTS_X86_64*) echo '#define __x86_64__ 1' ;; esac
    exit $st ;;
esac
exec "$REAL" "$@""#;

/// The profile of `a_target_only_the_cxxflags_select_is_witnessed_with_no_elf_artifact`:
/// C flags that select nothing, and C++ flags carrying the sentinel.
const CXX_TARGET_PROFILE: &[&str] = &[
    "--profile",
    "explicit",
    "--flags",
    "-O0",
    "--cxxflags",
    "-O0 -DCHARD_CXX_SELECTS_X86_64",
];

/// The C probe's gated verdict in `report` stands (`arch-outside-table`, since the gate
/// read riscv64, which the mechanism table has no row for): the dumps under profile flags
/// witness the builds of the language whose flags they ran under, and `cet-object` is a
/// C probe built under the C flags.
fn assert_c_probe_stands(report: &Value) {
    let gated = observation(report, "cet-marked-object");
    assert_eq!(
        gated["gating"]["rule"].as_str(),
        Some("arch-outside-table"),
        "a C++ witness does not withhold a C probe's verdict: {gated}"
    );
    assert_eq!(
        report["toolchain"]["target"]["profile_macros"]["agreement"].as_str(),
        Some("no-arch-macro"),
        "the C flags select nothing the flagless dump does not: {}",
        report["toolchain"]["target"]
    );
}

#[test]
fn a_target_only_the_cxxflags_select_is_witnessed_with_no_elf_artifact() {
    if !can_run("that a target only the profile's C++ flags select is witnessed") {
        return;
    }
    let work = common::Work::new("fakedriver", "cxx-target-no-driver");
    let driver = fake_driver(work.dir(), CXX_TARGET_C_SCRIPT);
    let report = measure_probes_under(&driver, work.dir(), CXX_TARGET_PROFILE, &["cet-object"]);
    assert!(
        report["toolchain"]["cxx_driver"].is_null(),
        "fakecc has none"
    );
    assert!(
        report["toolchain"]["target"]
            .get("profile_macros_cxx")
            .is_none(),
        "no C++ driver, no C++ dump: {}",
        report["toolchain"]["target"]
    );
    assert_c_probe_stands(&report);

    let Some(cxx) = real_cxx() else {
        common::capability_gap(
            "C++ macro dump under cxxflags",
            "no c++ on PATH beside cc, so no C++ driver can be dumped under its flags",
        );
        return;
    };
    let work = common::Work::new("fakedriver", "cxx-target");
    let driver = fake_driver_named(work.dir(), "fake-cc", &real_cc(), CXX_TARGET_C_SCRIPT);
    fake_driver_named(work.dir(), "fake-c++", &cxx, CXX_TARGET_CXX_SCRIPT);
    let report = measure_probes_under(&driver, work.dir(), CXX_TARGET_PROFILE, &["cet-object"]);
    let target = &report["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some("riscv64"), "{target}");
    assert_eq!(
        target["agreement"].as_str(),
        Some("no-elf-artifact"),
        "{target}"
    );
    let cxx = &target["profile_macros_cxx"];
    assert_eq!(
        cxx["flags"],
        serde_json::json!(["-O0", "-DCHARD_CXX_SELECTS_X86_64"]),
        "{cxx}"
    );
    assert_eq!(cxx["exit_status"].as_i64(), Some(0), "{cxx}");
    assert_eq!(cxx["defined"], serde_json::json!(["__x86_64__"]), "{cxx}");
    assert_eq!(cxx["agreement"].as_str(), Some("disagrees"), "{cxx}");
    assert_c_probe_stands(&report);
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["severity"].as_str() == Some("error")
                && d["context"].as_str() == Some("toolchain.target")
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("under the profile's C++ flags"))),
        "the disagreement is an error diagnostic naming the witness: {}",
        report["diagnostics"]
    );
}

/// A wrapper that answers `-dumpmachine` with `riscv64-linux-gnu` and strips the three
/// architecture macros from every dump, except a dump run under `--target=chard-host`, which
/// it removes from every invocation before passing it to the host's `cc`. So the flag is a
/// target selection to chard's parser (`toolchain::selects_target`), the flagless answers name
/// a target outside the three families, and the dump under the profile's flags, and every
/// build, are of the host's own target: the shape of `--target=aarch64-linux-gnu` on an x86_64
/// driver, whose `-dumpmachine` names x86_64.
const SELECTED_TARGET_SCRIPT: &str = r#"selected=no
for a do
  shift
  if [ "$a" = "--target=chard-host" ]; then selected=yes; else set -- "$@" "$a"; fi
done
case "$*" in
  -dumpmachine) echo riscv64-linux-gnu; exit 0 ;;
  *-dM*)
    out=$("$REAL" "$@"); st=$?
    if [ "$selected" = yes ]; then
      printf '%s\n' "$out"
    else
      printf '%s\n' "$out" | grep -v -E '^#define (__x86_64__|__i386__|__aarch64__) '
    fi
    exit $st ;;
esac
exec "$REAL" "$@""#;

#[test]
fn a_target_the_profile_selects_is_the_target_the_gate_reads() {
    if !can_run("that the arch gate reads the target the profile's flags select") {
        return;
    }
    let work = common::Work::new("fakedriver", "selected-target-bare");
    let driver = fake_driver(work.dir(), SELECTED_TARGET_SCRIPT);
    let bare = measure_arch_probes(&driver, work.dir());
    let target = &bare["toolchain"]["target"];
    assert_eq!(target["arch"].as_str(), Some("riscv64"), "{target}");
    assert_eq!(target["source"].as_str(), Some("dumpmachine"), "{target}");

    let work = common::Work::new("fakedriver", "selected-target-explicit");
    let driver = fake_driver(work.dir(), SELECTED_TARGET_SCRIPT);
    let report = measure_probes_under(
        &driver,
        work.dir(),
        &["--profile", "explicit", "--flags", "--target=chard-host"],
        &["link-defaults", "toolchain-macros"],
    );
    let target = &report["toolchain"]["target"];
    assert_eq!(
        report["toolchain"]["target_triple"].as_str(),
        Some("riscv64-linux-gnu"),
        "the flagless triple is published as the driver gave it"
    );
    let host = &target["profile_macros"]["defined"];
    let host_arch = match host.as_array().map(Vec::as_slice) {
        Some([m]) if m == "__x86_64__" => "x86_64",
        Some([m]) if m == "__aarch64__" => "aarch64",
        Some([m]) if m == "__i386__" => "x86",
        _ => panic!("the host's dump names one of the three: {target}"),
    };
    assert_eq!(target["arch"].as_str(), Some(host_arch), "{target}");
    assert_eq!(
        target["source"].as_str(),
        Some("profile-macros"),
        "{target}"
    );
    assert_eq!(
        target["profile_macros"]["agreement"].as_str(),
        Some("agrees"),
        "{target}"
    );
    assert_eq!(
        target["macros"]["agreement"].as_str(),
        Some("superseded"),
        "{target}"
    );
    assert_eq!(
        target["macros"]["defined"],
        serde_json::json!([]),
        "{target}"
    );
    let agreement = if common::ELF_HOST {
        "agrees"
    } else {
        "no-elf-artifact"
    };
    assert_eq!(target["agreement"].as_str(), Some(agreement), "{target}");
    for check in ARCH_GATED {
        let o = observation(&report, check);
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("target-arch-contradicted"),
            "{check}: every witness agrees with the selected target: {o}"
        );
    }
    assert!(
        !report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["severity"].as_str() == Some("error")
                && d["context"].as_str() == Some("toolchain.target")),
        "no witness contradicts the selected target: {}",
        report["diagnostics"]
    );
}

#[test]
fn a_published_report_replaces_the_one_set_aside() {
    use std::os::unix::fs::PermissionsExt as _;
    if !can_run("that a published report replaces the earlier one and keeps no set-aside copy") {
        return;
    }
    let work = common::Work::new("fakedriver", "set-aside");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let output_path = work.path("report.json");
    let previous = work.path("report.json.previous");
    std::fs::write(&output_path, "an earlier report\n").expect("an earlier report");
    std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o444))
        .expect("chmod 444");
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .arg("--cc")
        .arg(&driver)
        .arg("--workdir")
        .arg(work.path("w"))
        .args(["--profile", "bare", "--probe", "toolchain-macros"])
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("spawning chard");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let text = std::fs::read_to_string(&output_path).expect("the report was written");
    let report: Value = serde_json::from_str(&text).expect("the report is JSON");
    assert!(
        report["observations"]
            .as_array()
            .is_some_and(|o| !o.is_empty()),
        "the requested path holds this run's report"
    );
    assert!(
        !previous.exists(),
        "nothing stays set aside after a publication"
    );
    assert_eq!(
        common::temporary_files_beside(&work.path("report.json")),
        Vec::<PathBuf>::new(),
        "the temporary file was renamed into place"
    );
}

#[test]
fn a_report_in_a_directory_chard_cannot_write_is_still_published() {
    use std::os::unix::fs::PermissionsExt as _;
    if !can_run("that a report whose directory refuses a rename is still published") {
        return;
    }
    let work = common::Work::new("fakedriver", "locked-dir");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let locked = work.path("locked");
    std::fs::create_dir(&locked).expect("mkdir");
    let output_path = locked.join("report.json");
    std::fs::write(&output_path, "an earlier report\n").expect("an earlier report");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).expect("chmod 555");
    if std::fs::write(locked.join("probe"), "").is_ok() {
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 755");
        common::capability_gap(
            "a report in a mode-555 directory",
            "this process writes in it anyway, so the mode stops nothing here",
        );
        return;
    }
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .arg("--cc")
        .arg(&driver)
        .arg("--workdir")
        .arg(work.path("w"))
        .args(["--profile", "bare", "--probe", "toolchain-macros"])
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("spawning chard");
    let text = std::fs::read_to_string(&output_path);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value =
        serde_json::from_str(&text.expect("the report was written")).expect("the report is JSON");
    assert!(
        report["observations"]
            .as_array()
            .is_some_and(|o| !o.is_empty()),
        "the requested path holds this run's report"
    );
    assert_eq!(
        common::temporary_files_beside(&locked.join("report.json")),
        Vec::<PathBuf>::new(),
        "no temporary file in the directory chard cannot write"
    );
}

/// Every check that declares a regime arm (`probe::Regime::Arm`), with the probe that
/// measures it, read from the corpus: the C probes only, since a driver named `fakecc` has
/// no C++ driver beside it. The test below measures exactly these probes and holds the
/// report to them in both directions. A hand-written list that also chose the probes measured
/// would let a check gaining the arm in a probe the list did not name go unmeasured here
/// while the test passed; the pinned list of checks owning an
/// arm is `tests/regime_arms.rs`'s, where a gain or a loss is a stated change.
fn owes_regime_arm() -> Vec<(&'static str, &'static str)> {
    chard::probe::CORPUS
        .iter()
        .filter(|p| matches!(p.lang, chard::probe::Lang::C))
        .flat_map(|p| {
            p.checks
                .iter()
                .filter(|c| c.regime_arm().is_some())
                .map(move |c| (p.id, c.id))
        })
        .collect()
}

#[test]
fn a_regime_arm_the_driver_rejects_is_published_unevaluable() {
    if !can_run("that a regime arm the driver rejects is published unevaluable") {
        return;
    }
    let work = common::Work::new("fakedriver", "regime-rejected");
    let (report, rejected) = measure_rejecting_regime_arms(&work);

    // The list above is the corpus's, in both directions: every check it names is
    // observed (`observation` panics otherwise), and no observation outside it publishes
    // a regime arm.
    let observations = report["observations"].as_array().expect("observations");
    let owed_pairs = owes_regime_arm();
    let owed: Vec<&str> = owed_pairs.iter().map(|(_, c)| *c).collect();
    for o in observations {
        let check = o["check"].as_str().unwrap_or("?");
        assert!(
            owed.contains(&check) || o["controls"]["regime_negative"].is_null(),
            "{check} publishes a regime arm and declares none"
        );
    }

    let mut published = 0usize;
    let mut unevaluable = Vec::new();
    let mut gated = Vec::new();
    for check in owed {
        let o = observation(&report, check);
        let arm = &o["controls"]["regime_negative"];
        if arm.is_null() {
            assert!(
                o["controls"].is_null() && !o["gating"].is_null(),
                "{check} owes a regime arm, built a triple and published none: {o}"
            );
            gated.push(check);
            continue;
        }
        published += 1;
        let verdict = o["verdict"].as_str().unwrap_or("?");
        assert!(
            !matches!(verdict, "on" | "off" | "partial"),
            "{check}: a measurement stood on a regime arm that did not build: {o}"
        );
        assert!(
            o["controls"]["withheld_because"].is_string(),
            "{check}: a triple with an unevaluable regime arm withholds: {}",
            o["controls"]
        );
        let detail = arm["detail"].as_str().unwrap_or("");
        assert!(
            detail.contains("-fregime-arm"),
            "{check}: the arm names the rejection that failed it: {arm}"
        );
        assert_eq!(
            arm["build"]["exit_status"].as_i64(),
            Some(1),
            "{check}: the arm publishes the build that failed: {arm}"
        );
        // The compiler-diag channel reads the build itself, so a rejected build is a
        // reading there, with an outcome; on every other channel there is no reading,
        // and so neither an outcome nor a `decoded`.
        if o["channel"].as_str() == Some("compiler-diag") {
            assert_ne!(arm["outcome"].as_str(), Some("absent"), "{check}: {arm}");
        } else {
            assert!(
                arm["outcome"].is_null() && arm["decoded"].is_null(),
                "{check}: an arm with no reading publishes no outcome: {arm}"
            );
            unevaluable.push(check);
        }
    }
    eprintln!(
        "{} owed: {published} regime arms published ({} unevaluable: {unevaluable:?}), \
         gated {gated:?}; the wrapper rejected {rejected} regime builds",
        owed_pairs.len(),
        unevaluable.len()
    );
    assert_eq!(
        published + gated.len(),
        owed_pairs.len(),
        "every owed check was either gated or published its arm"
    );
    assert_eq!(
        rejected, published,
        "each published regime arm is one build the wrapper rejected, and no other"
    );
    assert!(
        unevaluable.contains(&"pic-object-relocs"),
        "the predicate-decoded arm the replay rule reads was not exercised: {unevaluable:?}"
    );
}

#[test]
fn a_profile_flag_gcc_refuses_is_build_failed_on_the_diagnostic_channel() {
    if !can_run("that a profile flag gcc refuses fails the diagnostic cells too") {
        return;
    }
    // A name with no `gcc`, `clang` or `cc` component, so no C++ driver is found beside it
    // and the run stays about the C driver (see `fake_driver`).
    profile_refusal_is_build_failed("fakegnu", "unrecognized command-line option 'FLAG'");
}

#[test]
fn a_profile_flag_clang_refuses_is_build_failed_on_the_diagnostic_channel() {
    if !can_run("that a profile flag clang refuses fails the diagnostic cells too") {
        return;
    }
    profile_refusal_is_build_failed("fakellvm", "unknown argument: 'FLAG'");
}

#[test]
fn a_profile_flag_the_driver_only_warns_about_keeps_the_measured_reading() {
    if !can_run("that a flag the driver warns about and goes on without is not a refusal") {
        return;
    }
    let work = common::Work::new("fakedriver", "profile-warned");
    let probes = [
        "implicit-function-declaration",
        "format-security",
        "warn-all",
    ];
    let lines = [
        (
            "fakellvm",
            "fakellvm: warning: unknown warning option '-Wchard-no-such-flag' \
             [-Wunknown-warning-option]",
        ),
        (
            "fakegnu",
            "cc1: note: unrecognized command-line option '-Wchard-no-such-flag' may have \
             been intended to silence earlier diagnostics",
        ),
    ];
    for (name, line) in lines {
        let driver = fake_driver_named(
            work.dir(),
            name,
            &real_cc(),
            &format!(
                r#"n=$#; seen=0
for a in "$@"; do
  shift
  if [ "$a" = '-Wchard-no-such-flag' ]; then seen=1; else set -- "$@" "$a"; fi
done
[ "$seen" = 1 ] && echo "{line}" >&2
exec "$REAL" "$@""#
            ),
        );
        let report = measure_explicit_published(
            &work,
            &driver,
            &format!("{name}-warned"),
            "-O2 -Wall -Wformat -Werror=implicit-function-declaration \
             -Werror=format-security -Wchard-no-such-flag",
            &probes,
        );
        for (check, verdict) in [
            ("implicit-function-declaration-is-error", "on"),
            ("format-security-is-error", "on"),
        ] {
            let o = observation(&report, check);
            assert_eq!(
                o["verdict"].as_str(),
                Some(verdict),
                "{name}: {check} did not read on over its own diagnostic: {o}"
            );
            assert_eq!(
                o["build"]["exit_status"].as_i64(),
                Some(1),
                "{name}: {check}'s measured build failed, as the reading needs: {o}"
            );
            assert!(
                o["build_rejection"].is_null(),
                "{name}: {check}: a flag the driver went on without is no refusal: {o}"
            );
        }
        let o = observation(&report, "warn-all");
        assert_ne!(o["verdict"].as_str(), Some("build-failed"), "{name}: {o}");
        assert!(o["build_rejection"].is_null(), "{name}: {o}");
    }
}

/// The body of the two refusal tests: `name` is the wrapper's name and `spelling` the
/// family's refusal line with `FLAG` left to fill.
fn profile_refusal_is_build_failed(name: &str, spelling: &str) {
    let work = common::Work::new("fakedriver", &format!("profile-refused-{name}"));
    let probes = [
        "warn-all",
        "format-security",
        "hardened-downgrade",
        "pic-shared-link",
        "stack-canary",
    ];
    let diag_checks = [
        "warn-all",
        "format-security-is-error",
        "hardened-downgrade-warned",
        "pic-shared-link",
    ];
    let refusal = spelling.replace("FLAG", "-fchard-no-such-flag");
    let control_refusal = spelling.replace("FLAG", "-fhardened");
    // The wrapper refuses the profile's flag in the family's words, after a line of the
    // driver's own chatter, so the refusal is never the first line of stderr; and
    // `-fhardened`, which both arms of `hardened-downgrade-warned` carry, as clang does.
    let driver = fake_driver_named(
        work.dir(),
        name,
        &real_cc(),
        &format!(
            r#"case "$*" in
  *-fchard-no-such-flag*)
    echo "{name}: warning: argument unused during compilation: '-O2'" >&2
    echo "{name}: error: {refusal}" >&2
    exit 1 ;;
  *-fhardened*)
    echo "{name}: error: {control_refusal}" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#
        ),
    );
    let measure = |tag: &str, flags: &str| {
        measure_explicit_published(&work, &driver, &format!("{name}-{tag}"), flags, &probes)
    };

    // The profile the driver refuses: every cell of every probe, whatever its channel.
    let refused = measure("refused", "-O2 -fchard-no-such-flag");
    assert_every_cell_refused(name, &refused, &diag_checks, &refusal);

    // The profile the driver accepts: the control flag's refusal is the toolchain's
    // own fact, and the sibling cells measure.
    let accepted = measure("accepted", "-O2");
    let downgrade = observation(&accepted, "hardened-downgrade-warned");
    assert_eq!(
        downgrade["verdict"].as_str(),
        Some("unsupported"),
        "{name}: a control flag the driver refuses, under a profile it accepts: {downgrade}"
    );
    assert_eq!(
        downgrade["gating"]["rule"].as_str(),
        Some("flag-unknown-to-driver"),
        "{name}: {downgrade}"
    );
    assert!(
        downgrade["build_rejection"].is_null(),
        "{name}: a control's refusal is not the profile's: {downgrade}"
    );
    for check in ["warn-all", "format-security-is-error", "pic-shared-link"] {
        let o = observation(&accepted, check);
        assert_ne!(
            o["verdict"].as_str(),
            Some("build-failed"),
            "{name}: {check} under a profile the driver accepts: {o}"
        );
        assert!(o["build_rejection"].is_null(), "{name}: {check}: {o}");
    }
}

/// Every observation of `report` is `build-failed` naming `-fchard-no-such-flag` as the
/// profile's, with no control built and no gating rule, and each of `diag_checks` carries
/// the refused build's exit status and `refusal` line as its reason.
fn assert_every_cell_refused(name: &str, report: &Value, diag_checks: &[&str], refusal: &str) {
    let observations = report["observations"].as_array().expect("observations");
    assert!(
        observations.len() > diag_checks.len(),
        "{name}: the siblings on the other channels were selected too: {}",
        report["coverage"]
    );
    for o in observations {
        let check = o["check"].as_str().unwrap_or("?");
        assert_eq!(
            o["verdict"].as_str(),
            Some("build-failed"),
            "{name}: {check} under a profile the driver refused: {o}"
        );
        let rejection = o["build_rejection"].as_str().unwrap_or_else(|| {
            panic!("{name}: {check} is build-failed and names no rejection: {o}")
        });
        assert!(
            rejection.contains("-fchard-no-such-flag")
                && rejection.contains("supplied by the profile not by this check"),
            "{name}: {check}: {rejection}"
        );
        assert!(
            o["controls"].is_null(),
            "{name}: {check} built a control for a measured build the driver refused: {o}"
        );
        assert!(
            o["gating"].is_null(),
            "{name}: {check} published a gating rule over a refused build: {o}"
        );
    }
    for check in diag_checks {
        let o = observation(report, check);
        let observed = o["evidence"]["observed"].as_str().unwrap_or("");
        assert!(
            observed.starts_with("the build exited 1: ") && observed.contains(refusal),
            "{name}: {check}'s reason is the refused build's exit and the refused line: {o}"
        );
        assert!(
            !observed.contains("argument unused"),
            "{name}: {check}'s reason quotes the refusal, not the first line of stderr: {o}"
        );
    }
}

/// Measure `probes` through `driver` under `--profile explicit --flags FLAGS`, asserting
/// the report was published (exit 0, nothing quarantined, no contradiction), and return it.
fn measure_explicit_published(
    work: &common::Work,
    driver: &Path,
    tag: &str,
    flags: &str,
    probes: &[&str],
) -> Value {
    let output_path = work.path(&format!("{tag}.json"));
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .arg("--cc")
        .arg(driver)
        .arg("--workdir")
        .arg(work.path(&format!("w-{tag}")))
        .args(["--profile", "explicit", "--flags", flags])
        .args(probes.iter().flat_map(|p| ["--probe", p]))
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("spawning chard");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{tag}: the report was refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !work.path(&format!("{tag}.json.contradicted")).exists(),
        "{tag}: a quarantined report was written beside the published one"
    );
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(&output_path).expect("the report was written"),
    )
    .expect("the report is JSON");
    assert!(
        report["consistency"]["contradictions"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && report["consistency"]["status"] == "consistent",
        "{tag}: {}",
        report["consistency"]
    );
    report
}

/// Measure every probe in [`owes_regime_arm`] under `bare-optimized` through a wrapper
/// that rejects each regime arm's build, asserting the report was published and nothing
/// was quarantined. Returns the report and how many builds the wrapper rejected.
fn measure_rejecting_regime_arms(work: &common::Work) -> (Value, usize) {
    let log = work.path("regime-builds");
    let driver = fake_driver(
        work.dir(),
        &format!(
            r#"case "$*" in
  *-regime-neg*)
    echo "$*" >> '{}'
    echo "fakecc: error: unrecognized command line option '-fregime-arm'" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
            log.display()
        ),
    );
    let output_path = work.path("report.json");
    let mut probes: Vec<&str> = owes_regime_arm().iter().map(|(p, _)| *p).collect();
    probes.dedup();
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .arg("--cc")
        .arg(&driver)
        .arg("--workdir")
        .arg(work.path("w"))
        .args(["--profile", "bare-optimized"])
        .args(probes.iter().flat_map(|p| ["--probe", p]))
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("spawning chard");
    assert_eq!(
        output.status.code(),
        Some(0),
        "the report was refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !work.path("report.json.contradicted").exists(),
        "a quarantined report was written beside the published one"
    );
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(&output_path).expect("the report was written"),
    )
    .expect("the report is JSON");
    assert!(
        report["consistency"]["contradictions"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && report["consistency"]["status"] == "consistent",
        "{}",
        report["consistency"]
    );

    let rejected = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .count();
    (report, rejected)
}

/// The checks whose observable the link's startup objects decide, as
/// `report::LINK_INPUT_READINGS` lists them, spelled here so the test reads the published
/// report alone.
const LINK_INPUT_READINGS: [&str; 8] = [
    "cet-marked",
    "branch-protection-marked",
    "gcs-marked",
    "noexecstack",
    "linker-default-noexecstack",
    "noexecstack-enforced",
    "shadow-stack-enforced",
    "textrel-absent",
];

#[test]
fn a_startup_input_only_the_measured_link_combines_withholds_the_checks_it_decides() {
    startup_input_withholds("unmarked-input.o");
}

#[test]
fn a_startup_input_without_an_extension_withholds_the_checks_it_decides() {
    startup_input_withholds("unmarked-input");
}

#[test]
fn a_linkage_form_the_profile_chooses_is_normalised_in_the_arms_listing() {
    if !can_run("that the arms' link listing is taken under the measured link's form") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "link-form normalisation",
            "a Mach-O artifact is unread, so the linked checks withhold before their controls",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "link-form-normalised");
    let cc = real_cc();
    let bare = Command::new(&cc)
        .args(["-###", "-x", "c", "/dev/null", "-o", "/dev/null"])
        .output()
        .expect("running the driver's -###");
    let listing = String::from_utf8_lossy(&bare.stderr);
    let default_pie = listing
        .split_whitespace()
        .any(|word| word.trim_matches('"') == "-pie");
    // A PIE needs position-independent code behind it: `-pie` alone fails to link a probe
    // compiled position-dependent (measured 2026-10-08 on Fedora 44 x86_64, whose gcc 16.1.1
    // is not PIE by default: `relocation R_X86_64_32 against .chard.report can not be used
    // when making a PIE object`), so the PIE form carries `-fPIE`, a code-generation flag no
    // arm carries and the listing does not read.
    let (form, pie_verdict) = if default_pie {
        ("-no-pie", "off")
    } else {
        ("-fPIE -pie", "on")
    };
    let hardening = if cfg!(target_arch = "x86_64") {
        " -fcf-protection=full"
    } else {
        ""
    };
    let flags = format!("-O2{hardening} {form}");
    let report = measure(
        Path::new(&cc),
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            &flags,
            "--probe",
            "link-defaults",
            "--probe",
            "stack-exec-runtime",
        ],
    );
    let observations = report["observations"].as_array().expect("observations");
    let (mut examined, mut measured) = (0, 0);
    for o in observations {
        let check = o["check"].as_str().unwrap_or_default();
        let verdict = o["verdict"].as_str().unwrap_or_default();
        if check == "pie" {
            assert_eq!(
                verdict, pie_verdict,
                "the profile's {form} took effect in the measured link: {o}"
            );
        }
        if !LINK_INPUT_READINGS.contains(&check) {
            continue;
        }
        examined += 1;
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("link-inputs-unmatched-by-arms"),
            "{check} is withheld as if the arms linked other startup objects under {form}: {o}"
        );
        if matches!(verdict, "on" | "off" | "partial") {
            measured += 1;
        }
    }
    assert!(
        examined >= 2,
        "the two probes carry link-input checks; {examined} examined"
    );
    assert!(
        measured >= 1,
        "no link-input check read a measurement under {form}: {observations:?}"
    );
}

/// The body of the two tests above: measure through a wrapper that hands every link an
/// unmarked object named `name` under a marker `-specs=`, and require the checks it
/// decides withheld, counting the observations examined against coverage.
fn startup_input_withholds(name: &str) {
    if !can_run("that a link input the arms lack withholds the checks it decides") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "link-input comparison",
            "a Mach-O artifact is unread, so the linked checks withhold before their controls",
        );
        return;
    }
    let work = common::Work::new("fakedriver", &format!("link-inputs-{name}"));
    let x86 = cfg!(target_arch = "x86_64");
    let (driver, marker) = unmarked_input_driver(&work, x86, name);
    let probes = [
        "link-defaults",
        "shared-object-defaults",
        "stack-exec-runtime",
        "shadow-stack",
        "linker-default-execstack",
        "stack-canary",
    ];
    let hardening = if x86 { " -fcf-protection=full" } else { "" };
    let flags = format!("-O2{hardening} -specs={}", marker.display());
    let mut args = vec!["--profile", "explicit", "--flags", flags.as_str()];
    for probe in &probes {
        args.push("--probe");
        args.push(probe);
    }
    let report = measure_establishing_the_kernel(&driver, work.dir(), &args);
    // The architecture the gates decided under, as the report publishes it, rather than the
    // test binary's own: it is the premise of every `arch-gated` reading below.
    let target_arch = report["toolchain"]["target"]["arch"]
        .as_str()
        .expect("the report names the architecture its gates decided under");
    // The by-name requirements below are keyed on the test binary's architecture (`x86`),
    // the derivation on the report's; the fake driver wraps the host compiler, so they agree,
    // and a cross toolchain would make this the first thing to fail rather than a confusing set.
    assert_eq!(
        x86,
        target_arch == "x86_64",
        "the test binary's architecture and the report's target ({target_arch}) disagree"
    );
    let admitted = link_input_checks_admitted(&probes, target_arch);
    let observations = report["observations"].as_array().expect("observations");
    let mut withheld = Vec::new();
    let mut kernel_borrowed = Vec::new();
    let mut examined = 0;
    for o in observations {
        let check = o["check"].as_str().unwrap_or_default();
        let rule = o["gating"]["rule"].as_str();
        examined += 1;
        // Not `execution-mode-assumed`: the measurement asserts the kernel where the report
        // would read the default, so that rule here is the harness not doing so.
        assert_ne!(
            rule,
            Some("execution-mode-assumed"),
            "{check} was withheld on the default, so the harness asserted no kernel: {o}"
        );
        let earlier = matches!(rule, Some("arch-gated" | "no-check-on-target" | "needs-vm"));
        if LINK_INPUT_READINGS.contains(&check)
            && earlier
            && gated_before_the_rule_agrees(o, target_arch, &admitted)
        {
            kernel_borrowed.push(check);
        }
        if LINK_INPUT_READINGS.contains(&check) && check != "linker-default-noexecstack" && !earlier
        {
            assert_eq!(
                rule,
                Some("link-inputs-unmatched-by-arms"),
                "{check} read {} over arms linked without the measured link's input: {o}",
                o["verdict"]
            );
            assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{o}");
            let reason = o["gating"]["reason"].as_str().unwrap_or_default();
            assert!(
                reason.contains(&format!("{name} where")),
                "the reason names the input only the measured link combines: {reason}"
            );
            withheld.push(check);
        } else {
            assert_ne!(
                rule,
                Some("link-inputs-unmatched-by-arms"),
                "{check} is not decided by the link's startup objects: {o}"
            );
        }
    }
    withheld.sort_unstable();
    eprintln!(
        "link-input comparison ({name}): {examined} observations from {} probes under \
         {target_arch}; gates admit {admitted:?}, kernel borrowed {kernel_borrowed:?}, \
         {} withheld: {withheld:?}",
        probes.len(),
        withheld.len()
    );
    assert_eq!(
        examined,
        report["coverage"]["checks_attempted"].as_u64().unwrap_or(0),
        "every attempted check was examined"
    );
    withheld_is_the_admitted_set(target_arch, &admitted, &kernel_borrowed, &withheld, x86);
}

/// The closing assertion of [`startup_input_withholds`]: `withheld`, sorted, is exactly
/// `admitted` less `kernel_borrowed`, and the checks the test was written for are in it by
/// name, so a corpus edit that gated one of them away from x86_64 fails here rather than
/// shrinking the derived set quietly. `noexecstack` is portable and required on every target;
/// `textrel-absent` and `cet-marked` are required where `x86` says the test binary is x86_64.
fn withheld_is_the_admitted_set(
    target_arch: &str,
    admitted: &[&str],
    kernel_borrowed: &[&str],
    withheld: &[&str],
    x86: bool,
) {
    let mut expected: Vec<&str> = admitted
        .iter()
        .copied()
        .filter(|check| !kernel_borrowed.contains(check))
        .collect();
    expected.sort_unstable();
    assert_eq!(
        withheld, expected,
        "the link-input checks whose gates admit {target_arch} were withheld, and no other"
    );
    assert!(
        withheld.contains(&"noexecstack"),
        "noexecstack, portable, was withheld on every target: {withheld:?}"
    );
    if x86 {
        for check in ["textrel-absent", "cet-marked"] {
            assert!(
                withheld.contains(&check),
                "{check} is read on x86_64 and was withheld there: {withheld:?}"
            );
        }
    }
}

/// The checks in [`LINK_INPUT_READINGS`] that `probes` carry and whose gate admits `arch`,
/// less `linker-default-noexecstack`, which reads the clean build the marker does not reach:
/// the set [`startup_input_withholds`] expects under `link-inputs-unmatched-by-arms`, derived
/// from the corpus so it is the running target's rather than one target's spelled out.
fn link_input_checks_admitted(probes: &[&str], arch: &str) -> Vec<&'static str> {
    let admitted: Vec<&'static str> = probes
        .iter()
        .map(|id| chard::probe::find(id).unwrap_or_else(|| panic!("{id} is a probe")))
        .flat_map(|probe| probe.checks.iter())
        .filter(|check| {
            LINK_INPUT_READINGS.contains(&check.id)
                && check.id != "linker-default-noexecstack"
                && (check.gate.arch.is_empty() || check.gate.arch.contains(&arch))
        })
        .map(|check| check.id)
        .collect();
    assert!(
        !admitted.is_empty(),
        "no link-input check's gate admits {arch}: the derivation has an empty frame"
    );
    admitted
}

/// A link-input observation `o` gated before the rule, under `arch-gated`,
/// `no-check-on-target` or `needs-vm`, is one the derivation in
/// [`startup_input_withholds`]
/// must agree about: the first two are the gate not admitting `target_arch` (the mechanism
/// absent there, or present and read by no check), so the check must be outside `admitted`;
/// `needs-vm` is a
/// gate that declares the reading the kernel's, read under a kernel that is not the run's
/// own (a container the suite recognises), so the corpus must declare it;
/// `execution-mode-assumed` cannot stand here, since the measurement asserts the kernel
/// where the report would read the default. Either read for a check that fails its condition is
/// a frame error, and panics. Returns whether the kernel withheld it, for the caller to
/// subtract from the set the gates admit.
fn gated_before_the_rule_agrees(o: &Value, target_arch: &str, admitted: &[&str]) -> bool {
    let check = o["check"].as_str().unwrap_or_default();
    let gate = chard::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == check)
        .unwrap_or_else(|| panic!("{check} is a check in the corpus"))
        .gate;
    if let Some(rule @ ("arch-gated" | "no-check-on-target")) = o["gating"]["rule"].as_str() {
        assert!(
            !admitted.contains(&check),
            "{check} read {rule} under {target_arch}, which its gate {:?} admits: {o}",
            gate.arch
        );
        return false;
    }
    assert!(
        gate.needs_vm,
        "{check} read a kernel rule without declaring needs_vm: {o}"
    );
    true
}

/// A wrapper that builds everything with the real driver and, where it linked an
/// executable, moves it aside and leaves in its place a shell script that touches `$MARK`
/// and execs it: a file that runs as the probe would and is no object at all.
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
  printf '#!/bin/sh\n: > "%s"\nexec "%s" "$@"\n' "$MARK" "$(realpath "$out.real")" > "$out"
  chmod +x "$out"
fi
exit 0"#;

#[test]
fn a_script_left_in_the_executables_place_is_withheld_and_never_run() {
    if !can_run("that a file the reader refuses is withheld as unwitnessed and never run") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "a script in the executable's place",
            "this host's cc emits Mach-O, so the run has no witness and the script is read as \
             every artifact there is",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "script-in-place");
    let mark = work.path("the-script-ran");
    let driver = fake_driver(
        work.dir(),
        &format!(
            "MARK='{}'\n{SCRIPT_IN_PLACE_OF_THE_EXECUTABLE}",
            mark.display()
        ),
    );
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "bare",
            "--execution",
            "host",
            "--probe",
            "stack-clash",
            "--probe",
            "stack-exec-runtime",
            "--probe",
            "ub-null-check",
        ],
    );
    let facts = &report["facts"];
    let mut withheld = 0;
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("an observation names its check");
        let Some(sha) = o["build"]["artifact_sha256"].as_str() else {
            // Decided before any build: an arch gate or the mechanism table.
            assert_ne!(o["verdict"], "on", "{check} published with no build: {o}");
            continue;
        };
        assert_eq!(
            facts[sha]["kind"].as_str(),
            Some("unreadable"),
            "{check}'s build is a script the reader refuses: {}",
            facts[sha]
        );
        assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{check}: {o}");
        assert_eq!(
            o["gating"]["rule"].as_str(),
            Some("artifact-lacks-run-witness"),
            "{check}: {o}"
        );
        let reason = o["gating"]["reason"]
            .as_str()
            .expect("a withholding carries a reason");
        // The store names the artifact `<artifact>` and the reason names it as built; the
        // refusal's own words are what both carry.
        let refusal = facts[sha]["error"].as_str().expect("the refusal is stored");
        let words = refusal
            .rsplit(": ")
            .next()
            .expect("the refusal has words after the artifact's name");
        assert!(
            reason.contains("the ELF reader refused") && reason.contains(words),
            "{check}: the reason quotes the stored refusal `{refusal}`: {reason}"
        );
        assert!(o.get("run").is_none(), "{check} was run: {o}");
        assert!(o.get("controls").is_none(), "{check} built a triple: {o}");
        withheld += 1;
    }
    assert!(
        withheld >= 3,
        "{withheld} check(s) over a refused artifact were withheld"
    );
    assert!(
        !mark.exists(),
        "the script left in the executable's place was run"
    );
    assert_eq!(report["consistency"]["status"], "consistent");
}

#[test]
fn a_kernel_policy_check_is_withheld_where_nothing_established_the_kernel_on_a_live_run() {
    if !can_run("that an unestablished execution mode withholds the kernel-policy checks") {
        return;
    }
    let work = common::Work::new("fakedriver", "kernel-policy-unestablished");
    let cc = real_cc();
    let report = measure(
        Path::new(&cc),
        work.dir(),
        &[
            "--profile",
            "bare",
            "--probe",
            "stack-exec-runtime",
            "--probe",
            "shadow-stack",
        ],
    );
    let execution = &report["environment"]["execution"];
    let basis = execution["mode_evidence"]["basis"]
        .as_str()
        .expect("the report says how the mode was arrived at");
    let observation = execution["mode_evidence"]["observation"]
        .as_str()
        .expect("the report says what chard looked at");
    let expected = match (execution["mode"].as_str(), basis) {
        (Some("host"), "assumed-host") => "execution-mode-assumed",
        (Some("container"), "measured") => "needs-vm",
        (mode, basis) => panic!("a run with no --execution reads {mode:?} on {basis}"),
    };
    // The two positive markers are held to this host where the run
    // read `host` by default; `the_markers_silence_is_what_this_host_reads` says how.
    if cfg!(target_os = "linux") && expected == "execution-mode-assumed" {
        the_markers_silence_is_what_this_host_reads(observation);
    }
    let (mut held, mut noexecstack) = (0, false);
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("an observation names its check");
        let rule = o["gating"]["rule"].as_str();
        let declares = chard::probe::CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .any(|c| c.id == check && c.gate.needs_vm);
        if !declares {
            assert_ne!(rule, Some(expected), "{check} declares no needs_vm: {o}");
            continue;
        }
        if matches!(
            rule,
            Some("arch-gated" | "no-check-on-target" | "arch-outside-table")
        ) {
            // The table decided the target before the kernel gate was asked.
            continue;
        }
        held += 1;
        noexecstack |= check == "noexecstack-enforced";
        assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{o}");
        assert_eq!(rule, Some(expected), "{check}: {o}");
        assert_eq!(o["gating"]["needs_vm"].as_bool(), Some(true), "{o}");
        assert!(
            o["build"].is_null() && o["run"].is_null() && o["controls"].is_null(),
            "{check} was withheld before any build: {o}"
        );
        if expected == "execution-mode-assumed" {
            let reason = o["gating"]["reason"]
                .as_str()
                .expect("a withholding carries a reason");
            assert!(
                reason.contains(observation) && reason.contains("--execution host"),
                "the reason quotes the observation and the word that establishes it: {reason}"
            );
        }
    }
    assert!(
        held >= 1 && noexecstack,
        "{held} kernel-policy check(s) reached the kernel gate; noexecstack-enforced: {noexecstack}"
    );
}

/// What this host's two positive markers read, as the sentence a run that read `host` by
/// default must carry: each marker's reading as this test reads it, absence, a refusal (named
/// as such, not as absence) and content without the word told apart. A non-empty file or a
/// word would have read `container`, so the caller does not reach here with one. The paths
/// are the library's constants, so a misspelt path changes the sentence this checks. Linux
/// only: the other platforms read neither and say so.
fn the_markers_silence_is_what_this_host_reads(observation: &str) {
    use chard::env::{PID1_ENVIRON, SYSTEMD_CONTAINER_MARKER};
    let refusal = |e: &std::io::Error| match e.raw_os_error() {
        Some(code) => format!("{}, os error {code}", e.kind()),
        None => e.kind().to_string(),
    };
    let file = match std::fs::read(SYSTEMD_CONTAINER_MARKER) {
        Ok(bytes) if String::from_utf8_lossy(&bytes).trim().is_empty() => {
            format!("{SYSTEMD_CONTAINER_MARKER} is empty")
        }
        Ok(bytes) => panic!(
            "{SYSTEMD_CONTAINER_MARKER} holds {} byte(s) and the run read host by default",
            bytes.len()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            format!("no {SYSTEMD_CONTAINER_MARKER}")
        }
        Err(e) => format!("{SYSTEMD_CONTAINER_MARKER} unreadable ({})", refusal(&e)),
    };
    let word = match std::fs::read(PID1_ENVIRON) {
        Ok(environ) => match environ
            .split(|b| *b == 0)
            .find_map(|entry| entry.strip_prefix(&b"container="[..]))
        {
            None => "no `container=` word in PID 1's environment".to_owned(),
            Some([]) => "PID 1's environment carries `container=` with no value".to_owned(),
            Some(value) => panic!(
                "PID 1's environment carries container={} and the run read host by default",
                String::from_utf8_lossy(value)
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => format!("{PID1_ENVIRON} not found"),
        Err(e) => format!("{PID1_ENVIRON} unreadable ({})", refusal(&e)),
    };
    for said in [file, word] {
        assert!(
            observation.contains(&said),
            "the sentence says what this test read ({said}): {observation}"
        );
    }
}

/// The wrapper [`a_startup_input_only_the_measured_link_combines_withholds_the_checks_it_decides`]
/// measures through, and the marker file whose `-specs=` it answers, in `work`.
fn unmarked_input_driver(work: &common::Work, x86: bool, name: &str) -> (PathBuf, PathBuf) {
    let source = work.write("unmarked-input.c", "int chard_unmarked_input;\n");
    let object = work.path(name);
    let mut compile = Command::new(real_cc());
    compile.arg("-c");
    if x86 {
        compile.arg("-fcf-protection=none");
    }
    let status = compile
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .status()
        .expect("compiling the unmarked input");
    assert!(status.success(), "the host's cc compiles an empty object");
    let marker = work.write("startfile.specs", "*startfile:\n+ unmarked\n");
    let script = format!(
        "links=1; seen=0
for a; do
  case \"$a\" in -c|-E|-S|-M|-MM|-dM|-print-*|-dumpmachine|-dumpversion|--version|-v) links=0;; esac
done
for a; do
  shift
  case \"$a\" in -specs={marker}) seen=1; continue;; esac
  set -- \"$@\" \"$a\"
done
if [ \"$seen\" = 1 ] && [ \"$links\" = 1 ]; then set -- \"$@\" -x none '{object}'; fi
exec \"$REAL\" \"$@\"",
        marker = marker.display(),
        object = object.display()
    );
    (fake_driver(work.dir(), &script), marker)
}

/// The checks whose observable the compile's headers or predefined macros decide, as
/// `report::COMPILE_INPUT_READINGS` lists them, spelled here so the test reads the
/// published report alone.
const COMPILE_INPUT_READINGS: [&str; 19] = [
    "ssp-level",
    "fortify-requested",
    "fortify-effective",
    "pie-macro",
    "pic-macro",
    "cet-macro",
    "gcs-macro",
    "branch-protection-macro",
    "optimization-enabled",
    "exceptions-macro",
    "cxx-hardening-requested",
    "fortify-printf-flag",
    "fortify-enforced-known",
    "fortify-enforced-dynamic",
    "fortify-level-ge-2-subobject",
    "fortify-level-ge-2-percent-n",
    "strict-flex-arrays-enforced",
    "cxx-stdlib-assertions",
    "cxx-assertions-symbol",
];

#[test]
fn a_header_directory_only_the_measured_compile_reads_withholds_the_checks_it_decides() {
    if !can_run("that a header directory the arms lack withholds the checks it decides") {
        return;
    }
    header_directory_withholds("compile-inputs", "", "");
}

#[test]
fn a_header_directory_under_the_system_root_withholds_the_checks_it_decides() {
    if !can_run("that a sysroot-relative header directory the arms lack withholds the checks") {
        return;
    }
    header_directory_withholds("compile-inputs-sysroot", "=", " --sysroot=/");
}

#[test]
fn a_declining_header_under_the_profiles_own_isystem_reads_probe_invalid_never_off() {
    if !can_run("that a declining header under the profile's own -isystem reads probe-invalid") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-isystem-declining");
    let shim = work.path("declining-include");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::fs::write(
        shim.join("features.h"),
        "#include_next <features.h>\n#undef __USE_FORTIFY_LEVEL\n#define __USE_FORTIFY_LEVEL 0\n",
    )
    .expect("the shim header");
    let mut fed = 0_usize;
    for (tag, prefix, extra) in [("absolute", "", ""), ("sysroot", "=", " --sysroot=/")] {
        let flags = format!(
            "-O2 -D_FORTIFY_SOURCE=3{extra} -isystem {prefix}{}",
            shim.display()
        );
        let report = implied_fortify_report(
            Path::new(&real_cc()),
            &work,
            tag,
            &["--profile", "explicit", "--flags", flags.as_str()],
        );
        assert_own_header_silences_the_positive_arm(
            &report,
            ("unsupported", Some("fortify-level-declined")),
            &["-isystem".to_owned(), format!("{prefix}{}", shim.display())],
            &[
                "fortify-effective",
                "fortify-printf-flag",
                "fortify-enforced-known",
            ],
            &[("fortify-requested", "on")],
            &format!("own -isystem, {tag}"),
        );
        fed = fed.saturating_add(1);
    }
    assert_eq!(fed, 2, "both spellings were fed");
}

#[test]
fn an_include_undefining_fortify_source_under_the_profiles_own_include_reads_probe_invalid() {
    if !can_run("that an -include undefining _FORTIFY_SOURCE reads probe-invalid") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-include-undef");
    let header = work.write("undef-fortify.h", "#undef _FORTIFY_SOURCE\n");
    let flags = format!("-O2 -D_FORTIFY_SOURCE=3 -include {}", header.display());
    let dir = work.path("undef");
    std::fs::create_dir_all(&dir).expect("a work directory for the run");
    let mut args = vec!["--profile", "explicit", "--flags", flags.as_str()];
    for probe in COMPILE_INPUT_C_PROBES {
        args.push("--probe");
        args.push(probe);
    }
    let report = measure(Path::new(&real_cc()), &dir, &args);
    assert_own_header_silences_the_positive_arm(
        &report,
        ("probe-invalid", None),
        &["-include".to_owned(), header.display().to_string()],
        &[
            "fortify-requested",
            "fortify-effective",
            "fortify-printf-flag",
            "fortify-enforced-known",
            "fortify-enforced-dynamic",
            "fortify-level-ge-2-subobject",
            "fortify-level-ge-2-percent-n",
        ],
        &[("strict-flex-arrays-enforced", "probe-invalid")],
        "own -include undefining _FORTIFY_SOURCE",
    );
}

#[test]
fn as_needed_under_the_profiles_own_undef_reads_probe_invalid_on_gcc() {
    if !can_run("that as-needed under the profile's own -undef reads probe-invalid on gcc") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-undef");
    let report = measure(
        Path::new(&real_cc()),
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            "-O2 -undef",
            "--probe",
            "link-unused-library",
        ],
    );
    assert_schema_valid("own -undef", &report);
    if report["toolchain"]["kind"] != "gcc" {
        common::capability_gap(
            "as-needed under -undef",
            "the host's cc is not gcc, and only gcc builds the probe without its predefined macros",
        );
        return;
    }
    let (cell, rule) = cell_and_rule(&report, "as-needed");
    assert_eq!(rule, None, "nothing withheld the reading: {cell}");
    assert_eq!(cell["verdict"], "probe-invalid", "{cell}");
    assert_eq!(
        cell["controls"]["withheld_because"], "positive-indeterminate",
        "{}",
        cell["controls"]
    );
    assert_eq!(cell["controls"]["positive"]["outcome"], "indeterminate");
    assert_eq!(cell["controls"]["negative"]["outcome"], "absent");
    for which in ["positive", "negative"] {
        let arm: Vec<&str> = cell["controls"][which]["flags"]
            .as_array()
            .unwrap_or_else(|| panic!("as-needed publishes no {which} arm flags"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            arm.first(),
            Some(&"-undef"),
            "the {which} arm leads with the word: {arm:?}"
        );
    }
}

/// Every C probe carrying a check of [`COMPILE_INPUT_READINGS`]: [`COMPILE_INPUT_PROBES`]
/// and the six the undefining include decides beyond them.
const COMPILE_INPUT_C_PROBES: [&str; 10] = [
    "toolchain-macros",
    "fortify-printf-flag",
    "fortify-known-object",
    "stack-canary",
    "fortify-dynamic-object",
    "fortify-subobject",
    "fortify-percent-n",
    "strict-flex-arrays",
    "strict-flex-arrays-enforced",
    "exceptions",
];

#[test]
fn the_compile_input_c_probes_are_the_corpus_s() {
    let derived: Vec<&str> = chard::probe::CORPUS
        .iter()
        .filter(|p| {
            p.lang == chard::probe::Lang::C
                && p.checks
                    .iter()
                    .any(|c| COMPILE_INPUT_READINGS.contains(&c.id))
        })
        .map(|p| p.id)
        .collect();
    let beside = ["stack-canary", "strict-flex-arrays"];
    for probe in beside {
        assert!(
            !derived.contains(&probe),
            "{probe} carries a compile-input reading now, so it is not the exception"
        );
    }
    let mut listed: Vec<&str> = COMPILE_INPUT_C_PROBES
        .iter()
        .copied()
        .filter(|p| !beside.contains(p))
        .collect();
    let mut derived_sorted = derived.clone();
    listed.sort_unstable();
    derived_sorted.sort_unstable();
    assert_eq!(
        listed, derived_sorted,
        "the C compile-input probes of the corpus"
    );
    assert_eq!(
        derived.len() + beside.len(),
        COMPILE_INPUT_C_PROBES.len(),
        "fed {} probes and the two beside them",
        derived.len()
    );
}

#[test]
fn an_include_undefining_exceptions_under_the_profiles_own_include_reads_probe_invalid() {
    if !can_run("that an -include undefining __EXCEPTIONS reads probe-invalid") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-include-unexc");
    let header = work.write("unexc.h", "#undef __EXCEPTIONS\n");
    let flags = format!("-O2 -fexceptions -include {}", header.display());
    let report = measure(
        Path::new(&real_cc()),
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            flags.as_str(),
            "--probe",
            "exceptions",
        ],
    );
    assert_schema_valid("own -include undefining __EXCEPTIONS", &report);
    let mut seen = 0_usize;
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().unwrap_or_default();
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("compile-inputs-unmatched-by-arms"),
            "{check} was withheld where every arm carries the include: {o}"
        );
        match check {
            "exceptions-macro" => {
                assert_eq!(o["verdict"], "probe-invalid", "{o}");
                assert_eq!(o["controls"]["withheld_because"], "positive-silent", "{o}");
                seen += 1;
            }
            "except-table-emitted" => {
                assert_eq!(o["verdict"], "on", "{o}");
                assert_eq!(o["gating"]["rule"].as_str(), None, "{o}");
                seen += 1;
            }
            _ => {}
        }
    }
    assert_eq!(
        seen, 2,
        "both readings of the exceptions probe were examined"
    );
}

#[test]
fn an_include_defining_fortify_source_under_the_profiles_own_include_reads_probe_invalid() {
    if !can_run("that an -include defining _FORTIFY_SOURCE reads probe-invalid") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-include-define");
    let header = work.write(
        "define-fortify.h",
        "#undef _FORTIFY_SOURCE\n#define _FORTIFY_SOURCE 3\n",
    );
    let flags = format!("-O2 -include {}", header.display());
    let report = implied_fortify_report(
        Path::new(&real_cc()),
        &work,
        "define",
        &["--profile", "explicit", "--flags", flags.as_str()],
    );
    let observations = report["observations"].as_array().expect("observations");
    let mut held = 0_usize;
    for o in observations {
        let check = o["check"].as_str().unwrap_or_default();
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("compile-inputs-unmatched-by-arms"),
            "{check} was withheld where every arm carries the include: {o}"
        );
        if [
            "fortify-requested",
            "fortify-effective",
            "fortify-printf-flag",
            "fortify-enforced-known",
        ]
        .contains(&check)
        {
            assert_eq!(
                (
                    o["verdict"].as_str(),
                    o["controls"]["withheld_because"].as_str()
                ),
                (Some("probe-invalid"), Some("negative-also-shows")),
                "{check}: the include defines the macro in the negative arm too: {o}"
            );
            held = held.saturating_add(1);
        }
    }
    assert_eq!(held, 4, "every fortify check of the four probes was held");
}

#[test]
fn an_include_keyed_on_a_profile_macro_acts_on_the_measured_build_alone() {
    if !can_run("that an include keyed on a profile-only macro reads of the measured build") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-include-conditional");
    let header = work.write("cond.h", "#ifdef NDEBUG\n#undef _FORTIFY_SOURCE\n#endif\n");
    let flags = format!(
        "-O2 -DNDEBUG -D_FORTIFY_SOURCE=3 -include {}",
        header.display()
    );
    let report = implied_fortify_report(
        Path::new(&real_cc()),
        &work,
        "cond",
        &["--profile", "explicit", "--flags", flags.as_str()],
    );
    let mut held = 0_usize;
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().unwrap_or_default();
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("compile-inputs-unmatched-by-arms"),
            "{check} was withheld where both listings carry the include and the macro: {o}"
        );
        if [
            "fortify-requested",
            "fortify-printf-flag",
            "fortify-enforced-known",
        ]
        .contains(&check)
        {
            assert_eq!(
                (
                    o["verdict"].as_str(),
                    o["controls"]["discriminating"].as_bool()
                ),
                (Some("off"), Some(true)),
                "{check}: the request-less build did not read off with discriminating arms: {o}"
            );
            held = held.saturating_add(1);
        }
        // The one of the four with no artifact twin: the forced include is an input the
        // spoof rule cannot read by name, so it is withheld rather than read `off`
        // (`measure::twinless_unread_input`), its arms discriminating all the same.
        if check == "fortify-effective" {
            assert_eq!(o["verdict"], "indeterminate", "{check}: {o}");
            assert_eq!(
                o["gating"]["rule"].as_str(),
                Some("macro-supplied-by-profile"),
                "{check}: {o}"
            );
            assert_eq!(o["controls"]["discriminating"], true, "{check}: {o}");
            held = held.saturating_add(1);
        }
    }
    assert_eq!(held, 4, "every fortify check of the four probes was held");
}

/// Every attempted observation of `report` examined: none withheld under
/// `compile-inputs-unmatched-by-arms`; each check of `silenced` reads the verdict and gating
/// rule `expected` names over controls withheld as `positive-silent`, both arms' flags
/// carrying the header word and its value as the contiguous `pair`, and each of `read` its
/// verdict; and no `fortify-` check reads `off`.
fn assert_own_header_silences_the_positive_arm(
    report: &Value,
    expected: (&str, Option<&str>),
    pair: &[String],
    silenced: &[&str],
    read: &[(&str, &str)],
    shape: &str,
) {
    let observations = report["observations"].as_array().expect("observations");
    let mut examined = 0;
    let mut seen: Vec<&str> = Vec::new();
    for o in observations {
        let check = o["check"].as_str().unwrap_or_default();
        examined += 1;
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("compile-inputs-unmatched-by-arms"),
            "{shape}: {check} was withheld where every arm carries the profile's header word: {o}"
        );
        if check.starts_with("fortify-") || check == "strict-flex-arrays-enforced" {
            assert_ne!(
                o["verdict"].as_str(),
                Some("off"),
                "{shape}: {check} read off over a header both the build and the arms see: {o}"
            );
        }
        if silenced.contains(&check) {
            assert_eq!(
                (o["verdict"].as_str(), o["gating"]["rule"].as_str()),
                (Some(expected.0), expected.1),
                "{shape}: {check} is decided by the header, which silences its positive arm: {o}"
            );
            assert_eq!(
                o["controls"]["withheld_because"].as_str(),
                Some("positive-silent"),
                "{shape}: {check}'s positive arm was silenced by the header: {}",
                o["controls"]
            );
            for which in ["positive", "negative"] {
                let flags: Vec<&str> = o["controls"][which]["flags"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{shape}: {check} publishes no {which} arm flags"))
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                assert!(
                    flags.windows(pair.len()).any(|w| w == pair),
                    "{shape}: {check}'s {which} arm carries `{}`: {flags:?}",
                    pair.join(" ")
                );
            }
            seen.push(check);
        }
        if let Some((_, verdict)) = read.iter().find(|(id, _)| *id == check) {
            assert_eq!(
                o["verdict"].as_str(),
                Some(*verdict),
                "{shape}: {check} is not decided by the header: {o}"
            );
            seen.push(check);
        }
    }
    assert_eq!(
        examined,
        report["coverage"]["checks_attempted"].as_u64().unwrap_or(0),
        "{shape}: every attempted check was examined"
    );
    let mut want: Vec<&str> = silenced
        .iter()
        .chain(read.iter().map(|(id, _)| id))
        .copied()
        .collect();
    want.sort_unstable();
    seen.sort_unstable();
    assert_eq!(
        seen, want,
        "{shape}: every named check was attempted and examined"
    );
    eprintln!(
        "{shape}: {examined} observations, {} held to a verdict",
        seen.len()
    );
}

/// Every observation of `report` as (check, verdict, level), sorted, for a comparison of two
/// runs check for check.
fn sorted_verdicts(report: &Value) -> Vec<(String, String, String)> {
    let mut v: Vec<(String, String, String)> = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .map(|o| {
            (
                o["check"].as_str().unwrap_or_default().to_owned(),
                o["verdict"].as_str().unwrap_or_default().to_owned(),
                o["level"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn the_profiles_own_header_words_publish_as_the_plain_level_does() {
    if !can_run("that the profile's own header words publish as -O2 alone does") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-header-words-publish");
    let dir = work.path("empty-include");
    std::fs::create_dir_all(&dir).expect("the empty include directory");
    let header = work.write("forced.h", "#include <stdio.h>\n");
    // A macro file for `-imacros`, which keeps a file's macros and discards the rest: one
    // that includes `stdio.h` leaves its include guard defined and its declarations
    // dropped, so the probe's own `#include <stdio.h>` is empty and the measured build
    // fails on `puts` (gcc 16.1.1), an honest `build-failed` of the build the profile
    // makes and not this test's subject.
    let macros = work.write("macros.h", "#define CHARD_FORCED 1\n");
    let run = |tag: &str, flags: &str| -> Value {
        let out = work.path(tag);
        std::fs::create_dir_all(&out).expect("a work directory for the run");
        let mut args = vec!["--profile", "explicit", "--flags", flags];
        for probe in COMPILE_INPUT_PROBES
            .iter()
            .chain(["linker-default-execstack"].iter())
        {
            args.push("--probe");
            args.push(probe);
        }
        measure(Path::new(&real_cc()), &out, &args)
    };
    let plain = run("plain", "-O2");
    let expected = sorted_verdicts(&plain);
    for check in ["fortify-effective", "linker-default-noexecstack"] {
        assert!(
            expected.iter().any(|(id, verdict, _)| id == check
                && verdict != "indeterminate"
                && verdict != "build-failed"),
            "the plain run read {check}: {expected:?}"
        );
    }
    let words = [
        ("pthread", "-pthread".to_owned()),
        ("idir", format!("-I{}", dir.display())),
        ("isystem", format!("-isystem {}", dir.display())),
        ("idirafter", format!("-idirafter {}", dir.display())),
        ("iquote", format!("-iquote{}", dir.display())),
        ("include", format!("-include {}", header.display())),
        ("imacros", format!("-imacros {}", macros.display())),
    ];
    let mut fed = 0_usize;
    for (tag, word) in &words {
        let report = run(tag, &format!("-O2 {word}"));
        let mut arms_inspected = 0_usize;
        for o in report["observations"].as_array().expect("observations") {
            assert_ne!(
                o["gating"]["rule"].as_str(),
                Some("compile-inputs-unmatched-by-arms"),
                "{word}: {} was withheld where every arm carries the word: {o}",
                o["check"]
            );
            if COMPILE_INPUT_READINGS.contains(&o["check"].as_str().unwrap_or_default())
                && o["gating"]["rule"].is_null()
            {
                let first: Vec<String> = word.split_whitespace().map(str::to_owned).collect();
                for which in ["positive", "negative"] {
                    let flags: Vec<String> = o["controls"][which]["flags"]
                        .as_array()
                        .unwrap_or_else(|| {
                            panic!("{word}: {} publishes no {which} arm", o["check"])
                        })
                        .iter()
                        .map(|f| f.as_str().unwrap_or_default().to_owned())
                        .collect();
                    assert!(
                        flags.starts_with(&first),
                        "{word}: {}'s {which} arm leads with the word: {flags:?}",
                        o["check"]
                    );
                    arms_inspected = arms_inspected.saturating_add(1);
                }
            }
        }
        assert!(
            arms_inspected >= 12,
            "{word}: too few arms of the published compile-input checks inspected: {arms_inspected}"
        );
        let expected_here =
            twinless_under_unread_input(&report, word, *tag != "pthread", &expected);
        assert_eq!(
            sorted_verdicts(&report),
            expected_here,
            "{word}: every other check reads what it reads under -O2 alone"
        );
        fed = fed.saturating_add(1);
    }
    assert_eq!(fed, 7, "every word was fed");
}

/// A forced include or macro file is an input the spoof rule does not read by name, and a
/// header search directory one under which a header the probe includes can be shadowed
/// (`unread`): under either the macro check with no twin, `fortify-effective`, is withheld
/// (`measure::settle`), and so is `optimization-enabled` where its artifact twin is not a
/// measurement in the run, as where the run's probes leave `optimization-object` out
/// (`measure::withhold_where_no_twin_measured`); where the twin is one, it holds the reading
/// instead and nothing else moves. Under `-pthread` nothing is withheld there. Returns
/// `expected`, the `-O2` readings, with those set to the withholding where `unread`.
fn twinless_under_unread_input(
    report: &Value,
    word: &str,
    unread: bool,
    expected: &[(String, String, String)],
) -> Vec<(String, String, String)> {
    let observations = report["observations"].as_array().expect("observations");
    let twin_measured = observations.iter().any(|o| {
        o["check"] == "optimization-applied" && (o["verdict"] == "on" || o["verdict"] == "off")
    });
    let held: Vec<&str> = if twin_measured {
        vec!["fortify-effective"]
    } else {
        vec!["fortify-effective", "optimization-enabled"]
    };
    let mut expected_here = expected.to_vec();
    let mut withheld = 0_usize;
    for o in observations {
        let check = o["check"].as_str().unwrap_or_default();
        if unread && held.contains(&check) {
            assert_eq!(o["verdict"], "indeterminate", "{word}: {o}");
            assert_eq!(
                o["gating"]["rule"].as_str(),
                Some("macro-supplied-by-profile"),
                "{word}: {o}"
            );
            if let Some(slot) = expected_here.iter_mut().find(|(id, _, _)| id == check) {
                "indeterminate".clone_into(&mut slot.1);
                slot.2.clear();
            }
            withheld += 1;
        }
    }
    let present = held
        .iter()
        .filter(|id| observations.iter().any(|o| o["check"] == **id))
        .count();
    assert_eq!(
        withheld,
        if unread { present } else { 0 },
        "{word}: macro checks no twin holds are withheld under a directory or include word alone"
    );
    expected_here.sort();
    expected_here
}

#[test]
fn a_profiles_own_include_keyed_on_its_own_macro_is_held_by_the_optimisation_twin() {
    // The rest of the test, for the line cap.
    optimisation_twin_shapes();
}

/// A forging shape of the test above in a run whose selection leaves the twin's probe out:
/// no twin is a measurement, so the input clause holds the reading
/// (`measure::withhold_where_no_twin_measured`), its reason naming the macro and the twin.
fn held_by_the_input_without_the_twin(work: &common::Work, tag: &str, flags: &str) {
    let alone = work.path(&format!("{tag}-alone"));
    std::fs::create_dir_all(&alone).expect("a workdir per shape");
    let report = measure(
        Path::new(&real_cc()),
        &alone,
        &[
            "--profile",
            "explicit",
            "--flags",
            flags,
            "--probe",
            "toolchain-macros",
        ],
    );
    assert_schema_valid(tag, &report);
    let (cell, rule) = cell_and_rule(&report, "optimization-enabled");
    assert_eq!(cell["verdict"], "indeterminate", "{tag} alone: {cell}");
    assert_eq!(
        rule,
        Some("macro-supplied-by-profile"),
        "{tag} alone: {cell}"
    );
    let reason = cell["gating"]["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("`__OPTIMIZE__`")
            && reason.contains(
                "`optimization-applied` is not in this run, its probe `optimization-object` \
                 not selected"
            ),
        "{tag} alone: {reason}"
    );
    input_clause_warning(&report, tag, Some("optimization-object"));
}

/// The one warning `measure::withhold_where_no_twin_measured` publishes in `report`'s
/// diagnostics for `optimization-enabled`, naming the probe to select where `select` is set,
/// and no other.
fn input_clause_warning(report: &Value, tag: &str, select: Option<&str>) {
    let warnings: Vec<&Value> = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| {
            d["context"] == "optimization-enabled"
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("no twin of it is a measurement"))
        })
        .collect();
    assert_eq!(warnings.len(), 1, "{tag}: {}", report["diagnostics"]);
    assert_eq!(warnings[0]["severity"], "warning", "{tag}: {}", warnings[0]);
    let message = warnings[0]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("under macro-supplied-by-profile"),
        "{tag}: {message}"
    );
    match select {
        Some(probe) => assert!(
            message.contains(&format!("adds `--probe {probe}`")),
            "{tag}: {message}"
        ),
        None => assert!(!message.contains("--probe"), "{tag}: {message}"),
    }
}

#[test]
fn a_slim_lto_object_leaves_a_forged_optimize_to_the_input_clause() {
    if !can_run("that a slim -flto twin leaves a forged __OPTIMIZE__ to the input clause") {
        return;
    }
    let work = common::Work::new("fakedriver", "slim-lto-twin");
    let on = work.write("opt.h", "#ifdef GATE\n#define __OPTIMIZE__ 1\n#endif\n");
    let dir = work.path("lto");
    std::fs::create_dir_all(&dir).expect("a workdir");
    let flags = format!("-O0 -flto -DGATE -include {}", on.display());
    let report = measure(
        Path::new(&real_cc()),
        &dir,
        &[
            "--profile",
            "explicit",
            "--flags",
            &flags,
            "--probe",
            "toolchain-macros",
            "--probe",
            "optimization-object",
        ],
    );
    assert_schema_valid("slim-lto", &report);
    let (twin, _) = cell_and_rule(&report, "optimization-applied");
    if twin["verdict"] == "on" || twin["verdict"] == "off" {
        common::refuse(
            &format!(
                "this driver's -flto object is read as code ({}), so the slim shape is not here",
                twin["verdict"]
            ),
            "that a slim -flto twin leaves a forged __OPTIMIZE__ to the input clause",
        );
        return;
    }
    assert_eq!(twin["verdict"], "indeterminate", "slim-lto: {twin}");
    let (cell, rule) = cell_and_rule(&report, "optimization-enabled");
    assert_eq!(cell["verdict"], "indeterminate", "slim-lto: {cell}");
    assert_eq!(rule, Some("macro-supplied-by-profile"), "slim-lto: {cell}");
    let reason = cell["gating"]["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("`optimization-applied` reads `indeterminate`"),
        "slim-lto: {reason}"
    );
    assert_eq!(
        cell["evidence"]["macros"]["__OPTIMIZE__"].as_str(),
        Some("1"),
        "slim-lto: the header acted on the measured build: {}",
        cell["evidence"]["macros"]
    );
    input_clause_warning(&report, "slim-lto", None);
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["message"]
                .as_str()
                .is_some_and(|m| m.contains("(`optimization-applied` reads `indeterminate`"))),
        "slim-lto: the warning names the twin's reading: {}",
        report["diagnostics"]
    );
}

/// The body of
/// [`a_profiles_own_include_keyed_on_its_own_macro_is_held_by_the_optimisation_twin`].
fn optimisation_twin_shapes() {
    if !can_run("that a keyed forced include cannot forge optimization-enabled past its twin") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-include-twinless");
    let shapes = optimisation_forging_shapes(&work);
    let mut fed = 0_usize;
    for (tag, flags, held, forged) in &shapes {
        optimisation_twin_shape(&work, tag, flags, *held, *forged);
        fed += 1;
    }
    assert_eq!(fed, shapes.len(), "every shape was fed");
}

/// The shapes [`optimisation_twin_shapes`] measures, their headers written under `work`:
/// (tag, flags, withheld under the rule, the measured build's self-report of
/// `__OPTIMIZE__`, which a withheld cell still carries in `evidence.macros`).
fn optimisation_forging_shapes(
    work: &common::Work,
) -> Vec<(&'static str, String, bool, Option<&'static str>)> {
    let on = work.write("opt.h", "#ifdef GATE\n#define __OPTIMIZE__ 1\n#endif\n");
    let off = work.write("unopt.h", "#ifdef GATE\n#undef __OPTIMIZE__\n#endif\n");
    // A header that also renames the twin probe's dead call to its anchor and its branch to
    // a literal zero by macro, which the probe's `#undef` lines stop: the twin still reads
    // the call kept.
    let rename = work.write(
        "rename.h",
        "#ifdef GATE\n#define __OPTIMIZE__ 1\n#define chard_opt_dead chard_opt_anchor\n\
         #define if(c) if (0)\n#endif\n",
    );
    // A shadow of a header the probe includes, under the profile's own `-I`: the next
    // `stdio.h` and then the keyed define, which the arms (carrying the directory and not
    // `-DGATE`) read as inert.
    let shadow = work.path("shadow-inc");
    std::fs::create_dir_all(&shadow).expect("the shadow directory");
    std::fs::write(
        shadow.join("stdio.h"),
        "#include_next <stdio.h>\n#ifdef GATE\n#define __OPTIMIZE__ 1\n#endif\n",
    )
    .expect("the shadow header");
    vec![
        (
            "forged-on",
            format!("-O0 -DGATE -include {}", on.display()),
            true,
            Some("1"),
        ),
        (
            "forged-off",
            format!("-O2 -DGATE -include {}", off.display()),
            true,
            None,
        ),
        (
            "shadow-on",
            format!("-O0 -DGATE -I{}", shadow.display()),
            true,
            Some("1"),
        ),
        (
            "forged-rename",
            format!("-O0 -DGATE -include {}", rename.display()),
            true,
            Some("1"),
        ),
        ("plain", "-O0 -DGATE".to_owned(), false, None),
        ("plain-optimised", "-O2 -DGATE".to_owned(), false, Some("1")),
    ]
}

/// One shape of [`optimisation_twin_shapes`], measured with the twin's probe in the run.
fn optimisation_twin_shape(
    work: &common::Work,
    tag: &str,
    flags: &str,
    held: bool,
    forged: Option<&str>,
) {
    let dir = work.path(tag);
    std::fs::create_dir_all(&dir).expect("a workdir per shape");
    let report = measure(
        Path::new(&real_cc()),
        &dir,
        &[
            "--profile",
            "explicit",
            "--flags",
            flags,
            "--probe",
            "toolchain-macros",
            "--probe",
            "optimization-object",
        ],
    );
    assert_schema_valid(tag, &report);
    let (cell, rule) = cell_and_rule(&report, "optimization-enabled");
    let (twin, twin_rule) = cell_and_rule(&report, "optimization-applied");
    // The twin reads the build as it was: optimised only where the profile's own `-O2`
    // made it so, whatever the header told the preprocessor.
    let optimised = flags.starts_with("-O2");
    assert_eq!(
        twin["verdict"],
        if optimised { "on" } else { "off" },
        "{tag}: {twin}"
    );
    assert_eq!(twin_rule, None, "{tag}: {twin}");
    if held {
        assert_eq!(cell["verdict"], "indeterminate", "{tag}: {cell}");
        assert_eq!(
            rule,
            Some("macro-contradicted-by-artifact"),
            "{tag}: {cell}"
        );
        let reason = cell["gating"]["reason"].as_str().expect("a reason");
        let read = if optimised { "off" } else { "on" };
        let twin_read = if optimised { "on" } else { "off" };
        assert!(
            reason.contains(&format!("`optimization-enabled` read `{read}`"))
                && reason.contains(&format!(
                    "`optimization-applied` reads `{twin_read}` on the elf-static channel"
                )),
            "{tag}: {reason}"
        );
        assert_eq!(
            cell["controls"]["discriminating"], true,
            "{tag}: the arms discriminated; the twin rule read the artifact, not the triple"
        );
        held_by_the_input_without_the_twin(work, tag, flags);
    } else {
        let (verdict, twin_verdict) = if optimised {
            ("on", "on")
        } else {
            ("off", "off")
        };
        assert_eq!(cell["verdict"], verdict, "{tag}: {cell}");
        assert_eq!(twin["verdict"], twin_verdict, "{tag}: {twin}");
        assert_eq!(rule, None, "{tag}: {cell}");
    }
    // The header did act on the measured build: its self-report carries the forged
    // macro where the header defined it, and none where it undefined it, so a header
    // the test left inert would fail here rather than pass under a withholding.
    assert_eq!(
        cell["evidence"]["macros"]["__OPTIMIZE__"].as_str(),
        forged,
        "{tag}: the measured build's self-report: {}",
        cell["evidence"]["macros"]
    );
}

/// An exception model only the measured compile is under withholds `except-table-emitted`
/// under `compile-inputs-unmatched-by-arms`, with the model's own sentence, and only then:
/// a header difference alone leaves it read, and beside a header difference it still carries
/// the model's sentence while the macro check carries the headers'.
///
/// The wrapper stands in for a configuration file choosing clang's exception model, on any
/// driver: under a marker `-specs=` it drops the flag and, on a `-###` listing, writes
/// `-exception-model=sjlj` after each compile program, as clang 22.1.8's `-cc1` line carried
/// it under such a file (Fedora 44 x86_64, 2026-10-21), and, when asked, hands every
/// invocation `-isystem` a directory too. On clang 19.1.7 on Raspbian 13 armv6 the check read
/// `off` under a `--config=` file holding `-fsjlj-exceptions` before the comparison.
#[test]
fn an_exception_model_only_the_measured_compile_is_under_withholds_except_table_emitted() {
    if !can_run("that an exception model the arms lack withholds except-table-emitted") {
        return;
    }
    exception_model_withholds("model", true, false);
    exception_model_withholds("model-and-header", true, true);
    exception_model_withholds("header", false, true);
}

/// Measure the `exceptions` probe through a wrapper that, under a marker `-specs=`, names
/// `-exception-model=sjlj` in the `-###` listings (`model`) and hands every invocation
/// `-isystem` a directory (`header`), and require `except-table-emitted` to be withheld
/// exactly where the model differs and `exceptions-macro` exactly where the headers do.
fn exception_model_withholds(name: &str, model: bool, header: bool) {
    let work = common::Work::new("fakedriver", &format!("exception-model-{name}"));
    let shim = work.path("plain-include");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::fs::write(shim.join("features.h"), "#include_next <features.h>\n")
        .expect("the shim header");
    let marker = work.write("model.specs", "*cpp:\n\n");
    let script = format!(
        "seen=0
listing=0
for a; do
  shift
  case \"$a\" in -specs={marker}) seen=1; continue;; -###) listing=1;; esac
  set -- \"$@\" \"$a\"
done
if [ \"$seen\" = 1 ] && [ {header} = 1 ]; then set -- \"$@\" -isystem '{shim}'; fi
if [ \"$seen\" = 1 ] && [ {model} = 1 ] && [ \"$listing\" = 1 ]; then
  \"$REAL\" \"$@\" 2>&1 | sed 's#/cc1 #/cc1 -exception-model=sjlj #' >&2
  exit 0
fi
exec \"$REAL\" \"$@\"",
        marker = marker.display(),
        shim = shim.display(),
        header = u8::from(header),
        model = u8::from(model),
    );
    let driver = fake_driver(work.dir(), &script);
    let flags = format!("-O2 -fexceptions -specs={}", marker.display());
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            flags.as_str(),
            "--probe",
            "exceptions",
        ],
    );
    let observations = report["observations"].as_array().expect("observations");
    let read = |id: &str| -> &Value {
        observations
            .iter()
            .find(|o| o["check"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("{id} is in the report ({name})"))
    };
    let table = read("except-table-emitted");
    let rule = table["gating"]["rule"].as_str();
    if model {
        assert_eq!(
            rule,
            Some("compile-inputs-unmatched-by-arms"),
            "({name}) {table}"
        );
        assert_eq!(
            table["verdict"].as_str(),
            Some("indeterminate"),
            "({name}) {table}"
        );
        let reason = table["gating"]["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains(
                "its exception model is -exception-model=sjlj where the arms' is the default"
            ) && !reason.contains("header options"),
            "({name}) the reason names the model and not the headers: {reason}"
        );
    } else {
        assert_ne!(
            rule,
            Some("compile-inputs-unmatched-by-arms"),
            "({name}) a header difference alone does not withhold the table: {table}"
        );
    }
    let macro_check = read("exceptions-macro");
    let macro_rule = macro_check["gating"]["rule"].as_str();
    if header {
        assert_eq!(
            macro_rule,
            Some("compile-inputs-unmatched-by-arms"),
            "({name}) {macro_check}"
        );
        let reason = macro_check["gating"]["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("header options") && !reason.contains("exception model is"),
            "({name}) the macro check carries the headers' sentence: {reason}"
        );
    } else {
        assert_ne!(
            macro_rule,
            Some("compile-inputs-unmatched-by-arms"),
            "({name}) the model alone does not withhold the macro check: {macro_check}"
        );
    }
}

/// Measure four probes through a wrapper that, under a marker `-specs=`, hands every
/// invocation `-isystem {prefix}<shim>`, with `-O2 -D_FORTIFY_SOURCE=3{extra}` and the
/// marker as the profile, and require exactly the checks of [`COMPILE_INPUT_READINGS`]
/// to be withheld, counting the observations examined against `coverage`.
fn header_directory_withholds(name: &str, prefix: &str, extra: &str) {
    let work = common::Work::new("fakedriver", name);
    let shim = work.path("declining-include");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::fs::write(
        shim.join("features.h"),
        "#include_next <features.h>\n#undef __USE_FORTIFY_LEVEL\n#define __USE_FORTIFY_LEVEL 0\n",
    )
    .expect("the shim header");
    let marker = work.write("isystem.specs", "*cpp:\n+ -isystem declining-include\n");
    let script = format!(
        "seen=0
for a; do
  shift
  case \"$a\" in -specs={marker}) seen=1; continue;; esac
  set -- \"$@\" \"$a\"
done
if [ \"$seen\" = 1 ]; then set -- \"$@\" -isystem '{prefix}{shim}'; fi
exec \"$REAL\" \"$@\"",
        marker = marker.display(),
        shim = shim.display()
    );
    let driver = fake_driver(work.dir(), &script);
    let probes = [
        "toolchain-macros",
        "fortify-printf-flag",
        "fortify-known-object",
        "stack-canary",
    ];
    let flags = format!("-O2 -D_FORTIFY_SOURCE=3{extra} -specs={}", marker.display());
    let mut args = vec!["--profile", "explicit", "--flags", flags.as_str()];
    for probe in &probes {
        args.push("--probe");
        args.push(probe);
    }
    let report = measure(&driver, work.dir(), &args);
    let observations = report["observations"].as_array().expect("observations");
    let mut withheld = Vec::new();
    let mut examined = 0;
    for o in observations {
        let check = o["check"].as_str().unwrap_or_default();
        let rule = o["gating"]["rule"].as_str();
        examined += 1;
        let earlier = matches!(
            rule,
            Some("arch-gated" | "no-check-on-target" | "needs-vm" | "probe-unmeasured")
        );
        if COMPILE_INPUT_READINGS.contains(&check) && !earlier {
            assert_eq!(
                rule,
                Some("compile-inputs-unmatched-by-arms"),
                "{check} read {} over arms compiled without the measured build's headers: {o}",
                o["verdict"]
            );
            assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{o}");
            let reason = o["gating"]["reason"].as_str().unwrap_or_default();
            // The report writes a path under the work directory relative to it.
            assert!(
                reason.contains("its header options include -isystem ")
                    && reason.contains("declining-include where"),
                "the reason names the directory only the measured compile reads: {reason}"
            );
            withheld.push(check);
        } else {
            assert_ne!(
                rule,
                Some("compile-inputs-unmatched-by-arms"),
                "{check} is not decided by the compile's headers or macros: {o}"
            );
        }
    }
    eprintln!(
        "compile-input comparison ({name}): {examined} observations from {} probes, {} withheld: {withheld:?}",
        probes.len(),
        withheld.len()
    );
    assert_eq!(
        examined,
        report["coverage"]["checks_attempted"].as_u64().unwrap_or(0),
        "every attempted check was examined"
    );
    assert!(
        withheld.contains(&"fortify-effective") && withheld.contains(&"optimization-enabled"),
        "the macro channel's checks were withheld: {withheld:?}"
    );
    assert!(
        observations
            .iter()
            .any(|o| o["check"] == "canary-emitted" && o["gating"]["rule"].is_null()),
        "the control probe's check was read"
    );
}

/// The four probes the compile-input comparison is exercised over: three holding a check in
/// [`COMPILE_INPUT_READINGS`] and `stack-canary`, whose `canary-emitted` reads the probe's
/// own code and keeps its reading whatever the comparison says.
const COMPILE_INPUT_PROBES: [&str; 4] = [
    "toolchain-macros",
    "fortify-printf-flag",
    "fortify-known-object",
    "stack-canary",
];

/// A wrapper standing in for a driver whose specs add `addition` to a compile with the
/// optimisation level: where the last `-O` word matches `trigger` (`-O*` for any but a
/// last `-O0`, as Ubuntu's gcc's `%{!O0:%{O*:...}}` reads, or one level), unless the line
/// names `-D_FORTIFY_SOURCE=` or `-U_FORTIFY_SOURCE`, joined or as two words, where `unless_named` (Ubuntu's
/// `%{!D_FORTIFY_SOURCE=*:%{!U_FORTIFY_SOURCE:...}}`; a `-Wp,` spelling is not seen, as
/// the real specs do not see it), and, with `gate` testing `$seen`, only where the line
/// also names the marker `-specs=` the wrapper swallows, as a file the profile names
/// would. With `when` `0` the addition goes to a line the trigger did NOT match (a driver
/// that adds something only without optimisation); `otherwise` goes to every other line.
/// Returns the wrapper and the marker.
fn level_bound_driver(
    work: &common::Work,
    trigger: &str,
    when: &str,
    unless_named: bool,
    gate: &str,
    (addition, otherwise): (&str, &str),
) -> (PathBuf, PathBuf) {
    let marker = work.write("implied.specs", "*cpp:\n+ -D_FORTIFY_SOURCE=3\n");
    let script = format!(
        "opt=0 named=0 seen=0 prev=
for a; do
  shift
  case \"$a\" in
    -specs={marker}) seen=1; continue;;
    -O0) opt=0;;
    {trigger}) opt=1;;
    -O*) opt=0;;
    -D_FORTIFY_SOURCE*|-U_FORTIFY_SOURCE) named=1;;
    _FORTIFY_SOURCE*) case \"$prev\" in -D|-U) named=1;; esac;;
  esac
  prev=$a
  set -- \"$@\" \"$a\"
done
if [ \"$opt\" = {when} ]{named}{gate}; then set -- \"$@\" {addition}; else set -- \"$@\" {otherwise}; fi
exec \"$REAL\" \"$@\"",
        marker = marker.display(),
        named = if unless_named {
            " && [ \"$named\" = 0 ]"
        } else {
            ""
        }
    );
    (fake_driver(work.dir(), &script), marker)
}

/// [`level_bound_driver`] adding Ubuntu's own `-D_FORTIFY_SOURCE=3` under any `-O` but a
/// last `-O0`.
fn implied_fortify_driver(work: &common::Work, gate: &str) -> (PathBuf, PathBuf) {
    level_bound_driver(work, "-O*", "1", true, gate, ("-D_FORTIFY_SOURCE=3", ""))
}

/// Measure [`COMPILE_INPUT_PROBES`] through `driver` under `profile` (`--profile` and its
/// arguments), in a fresh work directory named `tag` under `work`.
fn implied_fortify_report(
    driver: &Path,
    work: &common::Work,
    tag: &str,
    profile: &[&str],
) -> Value {
    let dir = work.path(tag);
    std::fs::create_dir_all(&dir).expect("a work directory for the run");
    let mut args: Vec<&str> = profile.to_vec();
    for probe in &COMPILE_INPUT_PROBES {
        args.push("--probe");
        args.push(probe);
    }
    measure(driver, &dir, &args)
}

/// Every attempted observation of `report` examined: none withheld under
/// `compile-inputs-unmatched-by-arms`, the `fortify-requested` and `optimization-enabled`
/// readings published, and `fortify-requested`'s verdict, level and the macro its dump read
/// as `expected` says, over a measured line that never names the macro.
fn assert_fortify_read(report: &Value, expected: (&str, Option<&str>, Option<&str>), shape: &str) {
    let observations = report["observations"].as_array().expect("observations");
    let mut examined = 0;
    let mut read = Vec::new();
    for o in observations {
        examined += 1;
        let check = o["check"].as_str().unwrap_or_default();
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("compile-inputs-unmatched-by-arms"),
            "{shape}: {check} was withheld over a macro the driver adds to the arms' compile too: {o}"
        );
        if COMPILE_INPUT_READINGS.contains(&check) && o["gating"]["rule"].is_null() {
            read.push(check);
        }
    }
    assert_eq!(
        examined,
        report["coverage"]["checks_attempted"].as_u64().unwrap_or(0),
        "{shape}: every attempted check was examined"
    );
    assert!(
        read.contains(&"fortify-requested") && read.contains(&"optimization-enabled"),
        "{shape}: the macro channel's checks were read: {read:?}"
    );
    let requested = observations
        .iter()
        .find(|o| o["check"] == "fortify-requested")
        .expect("fortify-requested was attempted");
    let line = requested["build"]["argv"]
        .as_array()
        .expect("the measured build's argv");
    assert!(
        line.iter()
            .all(|w| !w.as_str().unwrap_or_default().contains("_FORTIFY_SOURCE")),
        "{shape}: the measured line names the macro itself: {line:?}"
    );
    let (verdict, level, macro_value) = expected;
    assert_eq!(requested["verdict"], verdict, "{shape}: {requested}");
    assert_eq!(requested["level"].as_str(), level, "{shape}: {requested}");
    assert_eq!(
        requested["evidence"]["macros"]["_FORTIFY_SOURCE"].as_str(),
        macro_value,
        "{shape}: {requested}"
    );
    assert_eq!(
        requested["controls"]["positive"]["outcome"], "present",
        "{shape}: {requested}"
    );
    assert_eq!(
        requested["controls"]["negative"]["outcome"], "absent",
        "{shape}: {requested}"
    );
    eprintln!(
        "{shape}: {examined} observations from {} probes, {} compile-input readings read: {read:?}",
        COMPILE_INPUT_PROBES.len(),
        read.len()
    );
}

/// The checks of [`COMPILE_INPUT_PROBES`] in [`COMPILE_INPUT_READINGS`] with an arm at an
/// optimisation level other than the profile's `profile_words` (none, or `-O0`, under a
/// `-O2` profile): what a driver changes with the level, other than a macro the controls
/// set, withholds exactly these, as `listings::arm_optimization_classes` classes them.
fn checks_at_other_levels(profile_words: &[&str]) -> Vec<&'static str> {
    let words = |flags: &[&str]| {
        let owned: Vec<String> = flags.iter().map(|s| (*s).to_owned()).collect();
        chard::compile_inputs::optimization_words(&owned)
    };
    let profile = words(profile_words);
    let mut out = Vec::new();
    for probe in chard::probe::CORPUS
        .iter()
        .filter(|p| COMPILE_INPUT_PROBES.contains(&p.id))
    {
        for check in probe
            .checks
            .iter()
            .filter(|c| COMPILE_INPUT_READINGS.contains(&c.id))
        {
            let mut arms = vec![words(check.positive), words(check.negative)];
            if let Some(arm) = check.regime_arm() {
                arms.push(words(&[profile_words, arm].concat()));
            }
            if arms.iter().any(|a| *a != profile) {
                out.push(check.id);
            }
        }
    }
    assert!(
        !out.is_empty(),
        "no listed check has an arm at another level"
    );
    out
}

/// Every attempted observation of `report` examined: each check of
/// [`COMPILE_INPUT_READINGS`] in `withheld_ids` (every one no earlier rule decided, where
/// `withheld_ids` is empty) is withheld under `compile-inputs-unmatched-by-arms` with a
/// reason carrying each of `needles`, and no other check is.
fn assert_compile_inputs_withheld(
    report: &Value,
    withheld_ids: &[&str],
    needles: &[&str],
    shape: &str,
) {
    let observations = report["observations"].as_array().expect("observations");
    let mut withheld = Vec::new();
    let mut examined = 0;
    for o in observations {
        let check = o["check"].as_str().unwrap_or_default();
        let rule = o["gating"]["rule"].as_str();
        examined += 1;
        let earlier = matches!(
            rule,
            Some("arch-gated" | "no-check-on-target" | "needs-vm" | "probe-unmeasured")
        );
        let expected = COMPILE_INPUT_READINGS.contains(&check)
            && !earlier
            && (withheld_ids.is_empty() || withheld_ids.contains(&check));
        if expected {
            assert_eq!(
                rule,
                Some("compile-inputs-unmatched-by-arms"),
                "{shape}: {check} read {} over arms compiled without what the measured compile received: {o}",
                o["verdict"]
            );
            let reason = o["gating"]["reason"].as_str().unwrap_or_default();
            for needle in needles {
                assert!(
                    reason.contains(needle),
                    "{shape}: the reason does not say {needle:?}: {reason}"
                );
            }
            withheld.push(check);
        } else {
            assert_ne!(
                rule,
                Some("compile-inputs-unmatched-by-arms"),
                "{shape}: {check} was withheld where the arms read what the measured compile read: {o}"
            );
        }
    }
    assert_eq!(
        examined,
        report["coverage"]["checks_attempted"].as_u64().unwrap_or(0),
        "{shape}: every attempted check was examined"
    );
    assert!(
        !withheld.is_empty(),
        "{shape}: nothing was withheld, so nothing was tested"
    );
    eprintln!(
        "{shape}: {examined} observations, {} withheld: {withheld:?}",
        withheld.len()
    );
}

#[test]
fn a_macro_the_driver_adds_under_the_optimisation_level_reaches_the_arms() {
    if !can_run("that a macro the driver adds under -O reaches the arms' listing") {
        return;
    }
    let work = common::Work::new("fakedriver", "compile-inputs-implied");
    let (driver, _marker) = implied_fortify_driver(&work, "");
    let report = implied_fortify_report(
        &driver,
        &work,
        "bare-optimized",
        &["--profile", "bare-optimized"],
    );
    assert_fortify_read(&report, ("on", Some("3"), Some("3")), "bare-optimized");
    let report = implied_fortify_report(
        &driver,
        &work,
        "o0-then-o2",
        &["--profile", "explicit", "--flags", "-O0 -O2"],
    );
    assert_fortify_read(&report, ("on", Some("3"), Some("3")), "-O0 -O2");
    let report = implied_fortify_report(
        &driver,
        &work,
        "o2-then-o0",
        &["--profile", "explicit", "--flags", "-O2 -O0"],
    );
    assert_fortify_read(&report, ("off", None, None), "-O2 -O0");
    let report = implied_fortify_report(&driver, &work, "bare", &["--profile", "bare"]);
    assert_fortify_read(&report, ("off", None, None), "bare");
}

#[test]
fn a_header_the_driver_adds_at_the_profiles_level_alone_withholds_the_arms_at_another() {
    if !can_run("that a header the driver adds at the profile's level alone withholds") {
        return;
    }
    let work = common::Work::new("fakedriver", "compile-inputs-level-bound-header");
    let shim = work.path("declining-include");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::fs::write(
        shim.join("features.h"),
        "#include_next <features.h>\n#undef __USE_FORTIFY_LEVEL\n#define __USE_FORTIFY_LEVEL 0\n",
    )
    .expect("the shim header");
    let addition = format!("-isystem '{}'", shim.display());
    let (driver, _marker) = level_bound_driver(&work, "-O3", "1", false, "", (&addition, ""));
    let report = implied_fortify_report(
        &driver,
        &work,
        "o3",
        &[
            "--profile",
            "explicit",
            "--flags",
            "-O3 -D_FORTIFY_SOURCE=3",
        ],
    );
    assert_compile_inputs_withheld(
        &report,
        &[],
        &["at these arms' own", "its header options include -isystem "],
        "a header at -O3 alone",
    );
}

#[test]
fn a_macro_no_control_sets_added_with_the_level_withholds_the_arms_that_carry_none() {
    if !can_run("that a macro no control sets, added under -O, withholds the arms without -O") {
        return;
    }
    let work = common::Work::new("fakedriver", "compile-inputs-unowned-macro");
    let prefix = work.path("prefix");
    std::fs::create_dir_all(&prefix).expect("the prefix directory");
    let (driver, _marker) =
        level_bound_driver(&work, "-O*", "1", false, "", ("-D__SSP_STRONG__=3", ""));
    let flags = format!("-O2 -B{}", prefix.display());
    let report = implied_fortify_report(
        &driver,
        &work,
        "forged",
        &["--profile", "explicit", "--flags", flags.as_str()],
    );
    assert_compile_inputs_withheld(
        &report,
        &checks_at_other_levels(&["-O2"]),
        &[
            "at these arms' own",
            "-D__SSP_STRONG__=3",
            "no control arm sets",
        ],
        "a forged macro under -O",
    );
    let requested = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .find(|o| o["check"] == "fortify-requested")
        .expect("fortify-requested was attempted");
    assert!(
        requested["gating"]["rule"].is_null(),
        "fortify-requested's controls carry -O2 and received the macro too: {requested}"
    );
}

#[test]
fn a_macro_the_driver_adds_only_without_the_level_withholds_the_arms_that_carry_none() {
    if !can_run("that a macro the driver adds only without -O withholds the arms without -O") {
        return;
    }
    let work = common::Work::new("fakedriver", "compile-inputs-converse-macro");
    let (driver, _marker) =
        level_bound_driver(&work, "-O*", "0", false, "", ("-DCHARD_UNOPTIMISED=1", ""));
    let report =
        implied_fortify_report(&driver, &work, "converse", &["--profile", "bare-optimized"]);
    assert_compile_inputs_withheld(
        &report,
        &checks_at_other_levels(&["-O2"]),
        &[
            "at these arms' own",
            "-DCHARD_UNOPTIMISED=1",
            "no control arm sets",
        ],
        "a macro only without -O",
    );
    let requested = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .find(|o| o["check"] == "fortify-requested")
        .expect("fortify-requested was attempted");
    assert!(
        requested["gating"]["rule"].is_null(),
        "fortify-requested's controls are at the profile's level and never saw the macro: {requested}"
    );
}

#[test]
fn the_same_unowned_macros_in_another_order_with_the_level_withhold_the_arms_at_another() {
    if !can_run("that unowned macros reordered with the level withhold the arms at another") {
        return;
    }
    let work = common::Work::new("fakedriver", "compile-inputs-reordered-macros");
    let (driver, _marker) = level_bound_driver(
        &work,
        "-O3",
        "1",
        false,
        "",
        ("-DREVIEW_X=1 -UREVIEW_X", "-UREVIEW_X -DREVIEW_X=1"),
    );
    let report = implied_fortify_report(
        &driver,
        &work,
        "reordered",
        &["--profile", "explicit", "--flags", "-O3"],
    );
    assert_compile_inputs_withheld(
        &report,
        &checks_at_other_levels(&["-O3"]),
        &[
            "at these arms' own",
            "in another order or number",
            "no control arm sets",
        ],
        "reordered macros with the level",
    );
}

#[test]
fn a_macro_a_named_file_adds_under_the_optimisation_level_still_withholds() {
    if !can_run("that a macro a named file adds under -O still withholds") {
        return;
    }
    let work = common::Work::new("fakedriver", "compile-inputs-implied-by-file");
    let (driver, marker) = implied_fortify_driver(&work, " && [ \"$seen\" = 1 ]");
    let flags = format!("-O2 -specs={}", marker.display());
    let report = implied_fortify_report(
        &driver,
        &work,
        "named",
        &["--profile", "explicit", "--flags", flags.as_str()],
    );
    assert_compile_inputs_withheld(
        &report,
        &[],
        &[
            "its macro operations include -D_FORTIFY_SOURCE=3",
            "where the arms' include none",
        ],
        "a named file",
    );
}

#[test]
fn a_clang_link_under_lto_is_not_read_as_position_independent_code() {
    if !can_run("that pic-shared-link withholds a link that succeeded under clang's -flto") {
        return;
    }
    // The check reads an ELF shared-object link.
    if !cfg!(target_os = "linux") {
        common::capability_gap(
            "clang LTO arm",
            "pic-shared-link reads an ELF link; this host does not link ELF",
        );
        return;
    }
    let clang = Command::new("sh")
        .args(["-c", "command -v clang"])
        .output()
        .expect("sh is available");
    let clang = String::from_utf8_lossy(&clang.stdout).trim().to_owned();
    if clang.is_empty() {
        common::capability_gap("clang arm", "no clang on the PATH");
        return;
    }
    let work = common::Work::new("fakedriver", "clang-lto");
    let driver = fake_driver_named(work.dir(), "fakeclang", &clang, r#"exec "$REAL" "$@""#);
    let config = work.write("lto.cfg", "-flto\n");
    let config_flags = format!("-O2 --config={}", config.display());
    let read = |flags: &str| -> (String, Option<String>) {
        let report = measure(
            &driver,
            work.dir(),
            &[
                "--profile",
                "explicit",
                "--flags",
                flags,
                "--probe",
                "pic-shared-link",
            ],
        );
        let cell = &report["observations"][0];
        assert_eq!(cell["check"], "pic-shared-link", "{cell}");
        (
            cell["verdict"].as_str().unwrap_or_default().to_owned(),
            cell["gating"]["rule"].as_str().map(str::to_owned),
        )
    };
    let (plain, plain_rule) = read("-O2");
    assert_eq!(
        (plain.as_str(), plain_rule),
        ("off", None),
        "-O2 alone: the link refuses code no -fPIC described"
    );
    // Where this clang's LTO link refuses the code too (clang 18.1.3 on Ubuntu 24.04 aarch64
    // under GNU ld, lld and mold), no link succeeds under LTO and the shape the rule withholds
    // does not arise: `off` stands, as it should.
    if read("-O2 -flto").0 == "off" {
        common::capability_gap(
            "clang LTO arm",
            "this clang's LTO link refuses code no -fPIC described, so no LTO link succeeds",
        );
        return;
    }
    for flags in [
        "-O2 -flto",
        "-O2 -flto=thin",
        "-O2 -fno-lto -flto",
        config_flags.as_str(),
    ] {
        let (verdict, rule) = read(flags);
        assert_eq!(
            (verdict.as_str(), rule.as_deref()),
            ("indeterminate", Some("lto-codegen-at-link")),
            "{flags}: a link that succeeded under LTO is not the code the flags describe"
        );
    }
    // The last word decides: LTO turned off again is the plain build.
    let (verdict, rule) = read("-O2 -flto -fno-lto");
    assert_eq!(
        verdict, plain,
        "-fno-lto last reads as the build without -flto"
    );
    assert_eq!(rule, None);
}

#[test]
fn a_replay_holds_the_lto_gating_to_the_published_listing() {
    if !can_run("that detect re-derives lto-codegen-at-link from the published listing") {
        return;
    }
    if !cfg!(target_os = "linux") {
        common::capability_gap(
            "clang LTO arm",
            "pic-shared-link reads an ELF link; this host does not link ELF",
        );
        return;
    }
    let clang = Command::new("sh")
        .args(["-c", "command -v clang"])
        .output()
        .expect("sh is available");
    let clang = String::from_utf8_lossy(&clang.stdout).trim().to_owned();
    if clang.is_empty() {
        common::capability_gap("clang arm", "no clang on the PATH");
        return;
    }
    let work = common::Work::new("fakedriver", "lto-replay");
    let driver = fake_driver_named(work.dir(), "fakeclang", &clang, r#"exec "$REAL" "$@""#);
    let read = |flags: &str| -> Value {
        measure(
            &driver,
            work.dir(),
            &[
                "--profile",
                "explicit",
                "--flags",
                flags,
                "--probe",
                "pic-shared-link",
            ],
        )
    };
    let check = chard::detect::check_by_id("pic-shared-link").expect("a corpus check");
    let gates = |report: &Value| -> (bool, Vec<chard::detect::GateReplayed>) {
        let replay = chard::detect::replay_report(report, check, None).expect("the report replays");
        (replay.agrees(), replay.gates)
    };
    let lto = read("-O2 -flto");
    let cell = &lto["observations"][0];
    // Where this clang's LTO link refuses the code, as the test above allows for, no link
    // succeeds under LTO and the rule has nothing to withhold; anywhere else it must fire.
    if cell["verdict"] == "off" {
        common::capability_gap(
            "clang LTO arm",
            "this clang's LTO link refuses code no -fPIC described, so no LTO link succeeds",
        );
        return;
    }
    assert_eq!(cell["gating"]["rule"], "lto-codegen-at-link", "{cell}");
    let (agrees, as_written) = gates(&lto);
    assert!(agrees, "{as_written:?}");
    assert_eq!(as_written.len(), 1, "one gate per observation");
    assert_eq!(
        as_written[0].outcome,
        chard::detect::GateOutcome::Agrees,
        "{as_written:?}"
    );

    let mut edits = 0;
    // The gating deleted and the verdict set to the link's `on`.
    let mut ungated = lto.clone();
    let o = &mut ungated["observations"][0];
    o.as_object_mut().expect("an observation").remove("gating");
    o["verdict"] = Value::from("on");
    let (agrees, found) = gates(&ungated);
    assert!(!agrees, "a deleted gating replays as agreeing: {found:?}");
    assert_eq!(
        found[0].rederived,
        [Some("lto-codegen-at-link")],
        "{found:?}"
    );
    edits += 1;

    // The listing's LTO words removed beneath the published gating.
    let mut unlisted = lto.clone();
    let listing = &mut unlisted["listings"]["pic-shared-link"]["measured_compile"]["answer"];
    assert!(listing.is_object(), "{}", unlisted["listings"]);
    listing["lto"] = Value::Array(Vec::new());
    let (agrees, found) = gates(&unlisted);
    assert!(
        !agrees,
        "a gating its listing does not license agrees: {found:?}"
    );
    edits += 1;

    // A listing rule's gating added where none fired.
    let plain = read("-O2");
    assert_eq!(plain["observations"][0]["verdict"], "off", "{plain}");
    assert!(gates(&plain).0, "the -O2 report replays");
    let mut gated = plain.clone();
    let o = &mut gated["observations"][0];
    o["verdict"] = Value::from("indeterminate");
    o["gating"] = lto["observations"][0]["gating"].clone();
    let (agrees, found) = gates(&gated);
    assert!(!agrees, "an added gating agrees: {found:?}");
    edits += 1;
    assert_eq!(edits, 3);
}

#[test]
fn a_link_under_a_hidden_notext_is_read_from_the_objects_dt_textrel() {
    if !can_run("that pic-shared-link withholds a link whose shared object carries DT_TEXTREL") {
        return;
    }
    let work = common::Work::new("fakedriver", "hidden-notext");
    let driver = fake_driver(
        work.dir(),
        r#"case " $* " in
  *" -shared "*) ;;
  *) exec "$REAL" "$@" ;;
esac
case " $* " in
  *" -mcmodel=large "*"-fPIE "*)
    echo "ld.lld: error: relocation R_X86_64_GOTOFF64 cannot be used against symbol 'chard_pic_anchor'; recompile with -fPIC" >&2
    exit 1 ;;
esac
exec "$REAL" "$@" -Wl,-z,notext"#,
    );
    let read = |flags: &str| -> (Value, Value) {
        let report = measure(
            &driver,
            work.dir(),
            &[
                "--profile",
                "explicit",
                "--flags",
                flags,
                "--probe",
                "pic-shared-link",
            ],
        );
        let cell = report["observations"][0].clone();
        assert_eq!(cell["check"], "pic-shared-link", "{cell}");
        (report, cell)
    };
    let (report, large) = read("-O2 -fno-pic -mcmodel=large");
    if !targets_x86_64(&report) {
        common::capability_gap("hidden-notext arm", "the toolchain does not target x86_64");
        return;
    }
    let argv = large["build"]["argv"].to_string();
    assert!(
        !argv.contains("notext"),
        "the flag is hidden from the line: {argv}"
    );
    assert_eq!(
        large["controls"]["regime_negative"]["outcome"], "absent",
        "the wrapper refuses the regime arm, as lld does: {large}"
    );
    assert_eq!(
        large["build"]["exit_status"], 0,
        "the hidden flag lets it link: {large}"
    );
    let textrel = |cell: &Value| -> bool {
        let sha = cell["build"]["artifact_sha256"]
            .as_str()
            .expect("an artifact");
        report_textrel(&report, sha)
    };
    assert!(textrel(&large), "the object carries DT_TEXTREL: {large}");
    assert_ne!(
        large["verdict"], "on",
        "a shared object carrying DT_TEXTREL is not read as position-independent code"
    );
    let observed = large["evidence"]["observed"].as_str().unwrap_or_default();
    assert!(observed.contains("DT_TEXTREL"), "{observed}");

    // GNU ld and lld refuse the small model whatever the flag; a linker that links it takes
    // it by text relocation, and the tag withholds it.
    let (_, small) = read("-O2 -fno-pic");
    if small["build"]["exit_status"] == 0 {
        assert_ne!(small["verdict"], "on", "{small}");
    } else {
        assert_eq!(small["verdict"], "off", "{small}");
    }

    let (report, pic) = read("-O2 -fPIC");
    let sha = pic["build"]["artifact_sha256"]
        .as_str()
        .expect("an artifact");
    if report_textrel(&report, sha) {
        assert_ne!(pic["verdict"], "on", "{pic}");
    } else {
        assert_eq!(pic["verdict"], "on", "{pic}");
    }
}

/// The `textrel` fact the report's store holds for the artifact `sha`.
fn report_textrel(report: &Value, sha: &str) -> bool {
    let entry = &report["facts"][sha];
    assert_eq!(
        entry["kind"], "elf",
        "the store reads the artifact {sha}: {entry}"
    );
    entry["elf"]["textrel"]
        .as_bool()
        .expect("the facts carry textrel")
}

#[test]
fn a_clang_link_under_lto_reads_on_where_the_compile_resolves_to_pic() {
    if !can_run("that pic-shared-link reads on from the -cc1 relocation model under -flto") {
        return;
    }
    let clang = Command::new("sh")
        .args(["-c", "command -v clang"])
        .output()
        .expect("sh is available");
    let clang = String::from_utf8_lossy(&clang.stdout).trim().to_owned();
    if clang.is_empty() {
        common::capability_gap("clang arm", "no clang on the PATH");
        return;
    }
    let work = common::Work::new("fakedriver", "clang-lto-pic");
    let driver = fake_driver_named(work.dir(), "fakeclang", &clang, r#"exec "$REAL" "$@""#);
    let pic = work.write("pic.cfg", "-fPIC\n");
    let pie = work.write("pie.cfg", "-fPIE\n");
    let read = |flags: &str| -> (String, Option<String>, String) {
        let report = measure(
            &driver,
            work.dir(),
            &[
                "--profile",
                "explicit",
                "--flags",
                flags,
                "--probe",
                "pic-shared-link",
            ],
        );
        let cell = &report["observations"][0];
        assert_eq!(cell["check"], "pic-shared-link", "{cell}");
        (
            cell["verdict"].as_str().unwrap_or_default().to_owned(),
            cell["gating"]["rule"].as_str().map(str::to_owned),
            cell["evidence"]["observed"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    };
    let config_pic = format!("-O2 -flto --config={}", pic.display());
    for (flags, level) in [
        ("-O2 -flto -fPIC", "-pic-level 2"),
        ("-O2 -flto -fpic", "-pic-level 1"),
        ("-O2 -flto -fPIE -fPIC", "-pic-level 2"),
        (config_pic.as_str(), "-pic-level 2"),
    ] {
        let (verdict, rule, observed) = read(flags);
        assert_eq!(
            verdict, "on",
            "{flags}: the compile resolved to PIC ({rule:?})"
        );
        assert_eq!(rule, None, "{flags}");
        assert!(
            observed.contains("-mrelocation-model pic")
                && observed.contains(level)
                && !observed.contains("-pic-is-pie"),
            "{flags}: the cell quotes the words it read: {observed}"
        );
    }
    // Not PIC, or PIE: the readings of the other resolutions stand.
    let config_pie = format!("-O2 -flto --config={}", pie.display());
    for flags in [
        "-O2 -flto",
        "-O2 -flto -fno-pic",
        "-O2 -flto -fPIE",
        "-O2 -flto -fPIC -fPIE",
        config_pie.as_str(),
    ] {
        let (verdict, rule, _) = read(flags);
        assert_ne!(verdict, "on", "{flags}: no PIC without PIE was resolved");
        if let Some(rule) = rule {
            assert_eq!(rule, "lto-codegen-at-link", "{flags}");
        }
    }
    // LTO off again is the plain build, which needs no listing to read on.
    let (verdict, rule, observed) = read("-O2 -flto -fno-lto -fPIC");
    assert_eq!((verdict.as_str(), rule), ("on", None));
    assert!(!observed.contains("-mrelocation-model"), "{observed}");
}

#[test]
fn a_structured_stderr_the_profile_did_not_ask_for_withholds_the_diag_check() {
    if !can_run("that a SARIF stderr from a specs or configuration file is withheld") {
        return;
    }
    let work = common::Work::new("fakedriver", "sarif-stream");
    let pass = fake_driver(work.dir(), "exec \"$REAL\" \"$@\"\n");
    let sarif = fake_driver_named(
        work.dir(),
        "fakecc-sarif",
        &real_cc(),
        r#"for a in "$@"; do
  case "$a" in */warn-all-measured|warn-all-measured)
    "$REAL" "$@" 2>/dev/null
    rc=$?
    printf '%s\n' '{"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",' \
      ' "version": "2.1.0",' ' "runs": [{"results": [],' \
      ' "artifacts": [{"contents": {"text": "chard_wall_dead_label: ;"}}]}]}' >&2
    exit $rc ;;
  esac
done
exec "$REAL" "$@"
"#,
    );
    let args = [
        "--profile",
        "explicit",
        "--flags",
        "-O2",
        "--probe",
        "warn-all",
    ];
    let verdict = |driver: &Path, tag: &str| -> (String, String) {
        let dir = work.dir().join(tag);
        std::fs::create_dir_all(&dir).expect("creating the work directory");
        let report = measure(driver, &dir, &args);
        let o = report["observations"]
            .as_array()
            .and_then(|all| all.iter().find(|o| o["check"] == "warn-all"))
            .expect("an observation for warn-all");
        (
            o["verdict"].as_str().unwrap_or_default().to_owned(),
            o["evidence"]["observed"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    };
    let (control, _) = verdict(&pass, "pass");
    assert_eq!(control, "off", "the pass-through wrapper must read off");
    let (got, observed) = verdict(&sarif, "sarif");
    assert_eq!(
        got, "indeterminate",
        "a SARIF stderr must be withheld, not read: {observed}"
    );
    assert!(
        observed.contains("diag-stream-is-text-unless-recognised"),
        "the withheld reading names its rule: {observed}"
    );
}

/// The shortfall lines a failed `--fail-on-missing` owes `report`, by check id, re-derived
/// from the report's own words: a measurement, or a limitation with its rule attached, is
/// settled (a limitation beside a rule reserving the other verdict is refused at
/// publication, so it is not met here); any other observation is named with the reason the
/// report records (the gating rule's, else the triple's, else the detector's `observed`) and
/// then the ids of its causes, the gating rule's and the controls', and a corpus check no
/// observation carries is not attempted.
fn gate_lines(report: &Value, corpus: &[&str]) -> Vec<(String, String)> {
    let observations = report["observations"].as_array().expect("observations");
    let observed: std::collections::BTreeSet<&str> = observations
        .iter()
        .map(|o| o["check"].as_str().expect("a check id"))
        .collect();

    let mut expected: Vec<(String, String)> = corpus
        .iter()
        .filter(|id| !observed.contains(*id))
        .map(|id| ((*id).to_owned(), format!("{id}: not attempted")))
        .collect();
    for o in observations {
        let verdict = o["verdict"].as_str().expect("a verdict");
        let settled = matches!(verdict, "on" | "off" | "partial")
            || (matches!(verdict, "unsupported" | "not-applicable") && o["gating"].is_object());
        if settled {
            continue;
        }
        let check = o["check"].as_str().expect("a check id").to_owned();
        let causes: Vec<String> = o["gating"]["rule"]
            .as_str()
            .map(|id| format!("gating.rule {id}"))
            .into_iter()
            .chain(
                o["controls"]["withheld_because"]
                    .as_str()
                    .map(|cause| format!("controls.withheld_because {cause}")),
            )
            .collect();
        let reason = o["gating"]["reason"]
            .as_str()
            .or_else(|| o["controls"]["failure_reason"].as_str())
            .or_else(|| o["evidence"]["observed"].as_str())
            .map(|reason| reason.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|reason| !reason.is_empty());
        let said = match reason {
            Some(reason) => format!("{check}: {verdict}: {reason}"),
            None => format!("{check}: {verdict}; the report records no reason beside it"),
        };
        let ids = if causes.is_empty() {
            String::new()
        } else {
            format!(" [{}]", causes.join("; "))
        };
        expected.push((check, format!("{said}{ids}")));
    }
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    expected
}

#[test]
fn a_failed_completeness_gate_names_each_check_that_failed_it() {
    if !can_run("that a failed --fail-on-missing names each check that failed it") {
        return;
    }
    let work = common::Work::new("fakedriver", "gate-lines");
    let driver = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*macros-toolchain-macros-*)
    "$REAL" "$@"
    echo "fakecc: fatal error: late.h: No such file or directory" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
    );
    let report_path = work.path("report.json");
    let run = |gate: bool| {
        let mut command = Command::new(chard_binary());
        command
            .arg("measure")
            .args(PROBE_DEADLINE)
            .arg("--cc")
            .arg(&driver)
            .arg("--workdir")
            .arg(work.path("wd"))
            .args(["--profile", "bare", "--probe", "toolchain-macros", "-o"])
            .arg(&report_path);
        if gate {
            command.arg("--fail-on-missing");
        }
        command.output().expect("spawning chard")
    };

    let ungated = run(false);
    let stderr = String::from_utf8_lossy(&ungated.stderr);
    assert_eq!(ungated.status.code(), Some(0), "stderr was:\n{stderr}");
    assert!(
        !stderr.contains("--fail-on-missing"),
        "a run without the gate names nothing; stderr was:\n{stderr}"
    );

    let gated = run(true);
    let stderr = String::from_utf8_lossy(&gated.stderr).into_owned();
    assert_eq!(gated.status.code(), Some(1), "stderr was:\n{stderr}");
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(&report_path).expect("the report was written"),
    )
    .expect("the report is JSON");
    let listing = Command::new(chard_binary())
        .arg("probes")
        .output()
        .expect("spawning chard probes");
    let listing: Value = serde_json::from_slice(&listing.stdout).expect("the listing is JSON");
    let corpus: Vec<&str> = listing["probes"]
        .as_array()
        .expect("probes")
        .iter()
        .flat_map(|p| p["checks"].as_array().expect("checks"))
        .map(|c| c["id"].as_str().expect("a check id"))
        .collect();
    let expected = gate_lines(&report, &corpus);
    let withheld = expected
        .iter()
        .filter(|(_, line)| !line.ends_with("not attempted"))
        .count();
    assert!(
        withheld > 0,
        "the failing dump withheld no verdict; stderr was:\n{stderr}"
    );

    let mut after_report: Vec<&str> = stderr
        .lines()
        .skip_while(|l| !l.starts_with("chard: report written"))
        .skip(1)
        .collect();
    assert_the_gate_block_closes(&mut after_report, &expected);
    assert_eq!(
        after_report.len(),
        expected.len() + 1,
        "one line after the report for each check that failed the gate: {after_report:?}"
    );
}

/// The two lines a narrowed run's failed gate ends on, taken off `after_report`: the block's
/// exit status with the remedy for the checks `--probe` left out, then `measure`'s closing
/// line, which `measure_closes_every_run_with_one_line_naming_what_it_wrote` holds whole.
fn assert_the_gate_block_closes(after_report: &mut Vec<&str>, expected: &[(String, String)]) {
    let closing = after_report.pop().expect("a closing line");
    assert!(
        closing.starts_with("chard: measure exits 1 (--fail-on-missing: "),
        "{closing}"
    );
    let last = after_report.pop().expect("the gate's last line");
    let not_attempted = expected
        .iter()
        .filter(|(_, line)| line.ends_with("not attempted"))
        .count();
    assert!(
        last.starts_with("chard: --fail-on-missing: exit 1, the report written; ")
            && last.contains(&format!(
                "a run without --probe attempts the {not_attempted} not attempted"
            )),
        "the gate's lines end on the exit status and the remedy for a narrowed run: {last}"
    );
}

/// `measure` through `driver` with `args`, and its exit status beside the report.
fn measure_with_status(driver: &Path, workdir: &Path, args: &[&str]) -> (Option<i32>, Value) {
    let output = Command::new(chard_binary())
        .arg("measure")
        .args(PROBE_DEADLINE)
        .args(["-o", "-"])
        .arg("--cc")
        .arg(driver)
        .arg("--workdir")
        .arg(workdir)
        .args(args)
        .output()
        .expect("spawning chard");
    assert_ne!(
        output.status.code(),
        Some(3),
        "the report contradicted itself: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("a JSON report");
    assert!(report.get("error").is_none(), "{}", report["error"]);
    assert!(
        report["consistency"]["contradictions"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && report["consistency"]["status"] == "consistent",
        "{}",
        report["consistency"]
    );
    (output.status.code(), report)
}

/// Does `stderr` hold a line on which `tool` stopped and named `flag`?
fn refuses(stderr: &str, tool: &str, flag: &str) -> bool {
    stderr.lines().any(|line| {
        line.trim_start().starts_with(&format!("{tool}:"))
            && (line.contains(&format!("'{flag}'"))
                || line.contains(&format!("\u{2018}{flag}\u{2019}")))
            && !line.contains("warning:")
            && !line.contains("note:")
    })
}

/// The report's `profile-flag-rejected` diagnostics, each held to the cells it counts:
/// they lead `diagnostics`; each one's `cells_withheld` is the number of `build-failed`
/// cells whose published build stderr has its tool refusing its flag, read by
/// [`refuses`], against every cell attempted; every cell with a `build_rejection` is
/// counted by at least one, the one its first refusal names among them.
fn rejections(report: &Value) -> Vec<Value> {
    let diagnostics = report["diagnostics"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let found: Vec<Value> = diagnostics
        .iter()
        .filter(|d| d["context"] == "profile-flag-rejected")
        .cloned()
        .collect();
    assert_eq!(
        diagnostics[..found.len()],
        found[..],
        "the rejections lead the diagnostics: {diagnostics:#?}"
    );
    let observations = report["observations"].as_array().expect("observations");
    let mut counted = std::collections::BTreeSet::new();
    for d in &found {
        let r = &d["rejection"];
        let tool = r["tool"].as_str().expect("a tool");
        let flag = r["flag"].as_str().expect("a flag");
        let cells: Vec<&Value> = observations
            .iter()
            .filter(|o| {
                o["verdict"] == "build-failed"
                    && refuses(o["build"]["stderr"].as_str().unwrap_or(""), tool, flag)
            })
            .collect();
        assert!(!cells.is_empty(), "{d}");
        assert_eq!(
            r["cells_withheld"].as_u64(),
            u64::try_from(cells.len()).ok(),
            "{d}"
        );
        assert_eq!(
            r["cells_attempted"].as_u64(),
            u64::try_from(observations.len()).ok(),
            "{d}"
        );
        assert_eq!(
            report["coverage"]["checks_attempted"], r["cells_attempted"],
            "the frame is the run's own"
        );
        let message = d["message"].as_str().unwrap_or("");
        assert!(
            message.contains(&format!(": {tool} refused {flag} in ")),
            "the message names the tool and the flag: {message}"
        );
        for word in ["typo", "misspel", "too new", "newer", "older", "driver"] {
            assert!(!message.contains(word), "{word}: {d}");
        }
        for o in &cells {
            if o["build_rejection"]
                .as_str()
                .is_some_and(|b| b.starts_with(&format!("{tool} rejected ")) && b.contains(flag))
            {
                counted.insert(o["check"].as_str().unwrap_or("").to_owned());
            }
        }
    }
    let with_rejection: std::collections::BTreeSet<String> = observations
        .iter()
        .filter(|o| o.get("build_rejection").is_some())
        .map(|o| o["check"].as_str().unwrap_or("").to_owned())
        .collect();
    assert_eq!(
        counted, with_rejection,
        "every refused cell is counted under the refusal its build_rejection names"
    );
    found
}

/// The probes the rejection shapes run: one compiled and linked by the C driver alone
/// (`no_plt.c`), one linked (`link_defaults.c`), and the macro dump.
const REJECTION_PROBES: [&str; 6] = [
    "--probe",
    "no-plt",
    "--probe",
    "link-defaults",
    "--probe",
    "toolchain-macros",
];

#[test]
fn an_explicit_compile_flag_the_driver_rejects_is_named_once_with_its_count() {
    if !can_run("that a compile flag the driver rejects is named once") {
        return;
    }
    let work = common::Work::new("fakedriver", "rejected-cflag");
    let mut args = vec!["--profile", "explicit", "--flags", "-O2 -fno-such-flag"];
    args.extend(REJECTION_PROBES);
    let (status, report) = measure_with_status(Path::new(&real_cc()), work.dir(), &args);
    assert_eq!(status, Some(0), "a published report exits 0");
    let found = rejections(&report);
    assert_eq!(found.len(), 1, "{found:#?}");
    let r = &found[0]["rejection"];
    assert_eq!(r["flag"], "-fno-such-flag");
    assert_eq!(r["supplied_by"], "operator");
    assert_eq!(found[0]["severity"], "warning");
    let message = found[0]["message"].as_str().unwrap_or("");
    assert!(
        message.starts_with("a flag the operator supplied is rejected: "),
        "{message}"
    );
    assert!(
        message.ends_with(r["line"].as_str().expect("a line")),
        "the line as read: {message}"
    );
}

#[test]
fn two_flags_the_driver_rejects_in_one_build_are_both_named() {
    if !can_run("that two flags rejected in one build are both named") {
        return;
    }
    let work = common::Work::new("fakedriver", "rejected-two-in-one");
    let mut args = vec![
        "--profile",
        "explicit",
        "--flags",
        "-O2 -fno-aaa-flag -fno-bbb-flag",
    ];
    args.extend(REJECTION_PROBES);
    let (status, report) = measure_with_status(Path::new(&real_cc()), work.dir(), &args);
    assert_eq!(status, Some(0), "a published report exits 0");
    let found = rejections(&report);
    let mut flags: Vec<&str> = found
        .iter()
        .filter_map(|d| d["rejection"]["flag"].as_str())
        .collect();
    flags.sort_unstable();
    assert_eq!(flags, ["-fno-aaa-flag", "-fno-bbb-flag"], "{found:#?}");
    assert_eq!(
        found[0]["rejection"]["cells_withheld"], found[1]["rejection"]["cells_withheld"],
        "both flags are refused in every build that carries them: {found:#?}"
    );
}

#[test]
fn an_explicit_link_flag_the_linker_rejects_is_named_once_with_its_count() {
    if !can_run("that a link flag the linker rejects is named once") {
        return;
    }
    let work = common::Work::new("fakedriver", "rejected-ldflag");
    let mut args = vec![
        "--profile",
        "explicit",
        "--flags",
        "-O2",
        "--ldflags",
        "-Wl,--no-such-option",
    ];
    args.extend(REJECTION_PROBES);
    let (status, report) = measure_with_status(Path::new(&real_cc()), work.dir(), &args);
    assert_eq!(status, Some(0), "a published report exits 0");
    let found = rejections(&report);
    assert_eq!(found.len(), 1, "{found:#?}");
    let r = &found[0]["rejection"];
    assert_eq!(r["flag"], "--no-such-option", "the linker's spelling: {r}");
    assert_eq!(r["supplied_by"], "operator");
}

/// A fake driver refusing the given `openssf-tldr` flags, one line each, as gcc 9 does.
fn refusing_driver(work: &Path, flags: &[&str]) -> PathBuf {
    use std::fmt::Write as _;
    let mut cases = String::new();
    for f in flags {
        writeln!(
            cases,
            "    {f}) echo \"fakecc: error: unrecognized command-line option '{f}'\" >&2; \
             refused=1 ;;"
        )
        .expect("writing to a String");
    }
    fake_driver(
        work,
        &format!(
            "refused=0\nfor a in \"$@\"; do\n  case \"$a\" in\n{cases}  esac\ndone\n\
             [ $refused = 1 ] && exit 1\nexec \"$REAL\" \"$@\""
        ),
    )
}

#[test]
fn a_built_in_profile_flag_the_driver_lacks_reads_the_profile_and_is_not_refused() {
    if !can_run("that a built-in profile's rejected flag is named and not refused") {
        return;
    }
    let work = common::Work::new("fakedriver", "rejected-builtin");
    let driver = refusing_driver(work.dir(), &["-fstrict-flex-arrays=3"]);
    let mut args = vec!["--profile", "openssf-tldr"];
    args.extend(REJECTION_PROBES);
    let (status, report) = measure_with_status(&driver, work.dir(), &args);
    assert_eq!(status, Some(0), "a published report exits 0");
    let found = rejections(&report);
    assert_eq!(found.len(), 1, "{found:#?}");
    let r = &found[0]["rejection"];
    assert_eq!(r["tool"], "fakecc");
    assert_eq!(r["flag"], "-fstrict-flex-arrays=3");
    assert_eq!(r["supplied_by"], "built-in-profile");
    let message = found[0]["message"].as_str().unwrap_or("");
    assert!(
        message.starts_with(
            "this toolchain rejects a flag the openssf-tldr profile supplies: fakecc refused \
             -fstrict-flex-arrays=3 in "
        ),
        "{message}"
    );
}

#[test]
fn two_built_in_profile_flags_the_driver_lacks_are_both_named() {
    if !can_run("that two built-in profile flags a driver lacks are both named") {
        return;
    }
    let work = common::Work::new("fakedriver", "rejected-builtin-two");
    let driver = refusing_driver(
        work.dir(),
        &["-fstrict-flex-arrays=3", "-fzero-call-used-regs=used-gpr"],
    );
    let mut args = vec!["--profile", "openssf-tldr"];
    args.extend(REJECTION_PROBES);
    let (status, report) = measure_with_status(&driver, work.dir(), &args);
    assert_eq!(status, Some(0), "a published report exits 0");
    let found = rejections(&report);
    let mut flags: Vec<&str> = found
        .iter()
        .filter_map(|d| d["rejection"]["flag"].as_str())
        .collect();
    flags.sort_unstable();
    assert_eq!(
        flags,
        ["-fstrict-flex-arrays=3", "-fzero-call-used-regs=used-gpr"],
        "{found:#?}"
    );
    for d in &found {
        assert_eq!(d["rejection"]["supplied_by"], "built-in-profile");
    }
}

#[test]
fn two_rejected_flags_are_two_diagnostics_in_a_fixed_order_and_none_is_none() {
    if !can_run("that two rejected flags give two diagnostics in a fixed order") {
        return;
    }
    let work = common::Work::new("fakedriver", "rejected-two");
    // A measured build carries both flags; the driver names `-fzzz-one` for the no-plt
    // probe's source and `-fzzz-two` for every other, so each flag withholds its own cells.
    let driver = fake_driver(
        work.dir(),
        r#"profile=0
for a in "$@"; do
  [ "$a" = -fzzz-one ] && profile=1
done
if [ $profile = 1 ]; then
  case "$*" in
    *no_plt.c*) echo "fakecc: error: unrecognized command-line option '-fzzz-one'" >&2 ;;
    *) echo "fakecc: error: unrecognized command-line option '-fzzz-two'" >&2 ;;
  esac
  exit 1
fi
exec "$REAL" "$@""#,
    );
    let mut orders = Vec::new();
    for (n, flags) in ["-O2 -fzzz-one -fzzz-two", "-O2 -fzzz-two -fzzz-one"]
        .iter()
        .enumerate()
    {
        let dir = work.dir().join(format!("order-{n}"));
        std::fs::create_dir_all(&dir).expect("a workdir per order");
        let mut args = vec!["--profile", "explicit", "--flags", flags];
        args.extend(REJECTION_PROBES);
        let (status, report) = measure_with_status(&driver, &dir, &args);
        assert_eq!(status, Some(0), "a published report exits 0");
        let found = rejections(&report);
        let order: Vec<Value> = found
            .iter()
            .map(|d| d["rejection"]["flag"].clone())
            .collect();
        assert_eq!(order, ["-fzzz-two", "-fzzz-one"], "{found:#?}");
        assert!(
            found[0]["rejection"]["cells_withheld"].as_u64()
                > found[1]["rejection"]["cells_withheld"].as_u64(),
            "{found:#?}"
        );
        orders.push(found);
    }
    assert_eq!(orders[0], orders[1], "the profile's order moves nothing");

    let clean = work.dir().join("clean");
    std::fs::create_dir_all(&clean).expect("a workdir");
    let mut args = vec!["--profile", "bare-optimized"];
    args.extend(REJECTION_PROBES);
    let (status, report) = measure_with_status(Path::new(&real_cc()), &clean, &args);
    assert_eq!(status, Some(0));
    assert!(rejections(&report).is_empty(), "{}", report["diagnostics"]);
}

/// `measure`'s closing line, re-derived from what the run left: the counts from the report's
/// own `coverage`, the file, the work directory and the command to read it with.
fn closing_of_a_published_run(
    report: &Value,
    file: &str,
    workdir: &str,
    how: &str,
    replacing: bool,
) -> String {
    let coverage = &report["coverage"];
    let count = |verdict: &str| coverage["verdict_counts"][verdict].as_u64().unwrap_or(0);
    let limitations = coverage["withholding"]["earned_limitations"]["count"]
        .as_u64()
        .expect("earned_limitations.count");
    let withheld = coverage["withholding"]["instrument_withholdings"]["count"]
        .as_u64()
        .expect("instrument_withholdings.count");
    let attempted = coverage["checks_attempted"]
        .as_u64()
        .expect("checks_attempted");
    let others: u64 = coverage["verdict_counts"]
        .as_object()
        .expect("verdict_counts")
        .iter()
        .filter(|(verdict, _)| !matches!(verdict.as_str(), "on" | "partial" | "off"))
        .map(|(_, n)| n.as_u64().expect("a count"))
        .sum();
    assert_eq!(
        (
            count("on") + count("partial") + count("off") + others,
            others
        ),
        (attempted, limitations + withheld),
        "the closing line's five counts are the report's verdict_counts, split by withholding"
    );
    let checks = if attempted == 1 { "check" } else { "checks" };
    let replacing = if replacing {
        ", replacing the earlier report there"
    } else {
        ""
    };
    format!(
        "chard: measure exits {how}: wrote {file}{replacing} ({attempted} {checks}: {} on, {} \
         partial, {} off, \
         {limitations} unsupported or not-applicable, {withheld} withheld); work directory \
         {workdir} kept; next: chard table {file}",
        count("on"),
        count("partial"),
        count("off"),
    )
}

/// The one line on stderr that starts `chard: measure exits `, which must be the last, and
/// whose status must be the one the process exited with.
fn closing_line_of(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let closing: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("chard: measure exits "))
        .collect();
    assert_eq!(closing.len(), 1, "one closing line; stderr was:\n{stderr}");
    assert_eq!(
        stderr.lines().last(),
        Some(closing[0]),
        "the closing line is the last; stderr was:\n{stderr}"
    );
    let status = output.status.code().expect("an exit status");
    assert!(
        closing[0].starts_with(&format!("chard: measure exits {status}")),
        "the line names the status the process exited with ({status}): {}",
        closing[0]
    );
    closing[0].to_owned()
}

#[test]
fn measure_closes_every_run_with_one_line_naming_what_it_wrote() {
    if !can_run("that measure closes every run with one line naming what it wrote") {
        return;
    }
    let work = common::Work::new("fakedriver", "closing-line");
    // The toolchain's macro dump fails, so the macro checks are withheld and every count the
    // line carries has something in it to get wrong.
    let driver = fake_driver(
        work.dir(),
        r#"case "$*" in
  *-dM*macros-toolchain-macros-*)
    "$REAL" "$@"
    echo "fakecc: fatal error: late.h: No such file or directory" >&2
    exit 1 ;;
esac
exec "$REAL" "$@""#,
    );
    let run = |args: &[&str]| {
        Command::new(chard_binary())
            .current_dir(work.dir())
            .arg("measure")
            .args(PROBE_DEADLINE)
            .args(args)
            .output()
            .expect("spawning chard")
    };
    let cc = driver.to_str().expect("a UTF-8 path");
    let measure = ["--cc", cc, "--workdir", "wd", "--probe", "toolchain-macros"];
    let default = work.path("chard-fakecc-bare.json");
    let read = |path: &Path| -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("the report was written"))
            .expect("the report is JSON")
    };

    let first = run(&measure);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    assert!(
        first.stdout.is_empty(),
        "the report went to stdout: {first:?}"
    );
    let withheld = &read(&default)["coverage"]["withholding"]["instrument_withholdings"]["count"];
    assert!(
        withheld.as_u64().is_some_and(|n| n > 0),
        "the failing dump withheld nothing, so the withheld count is not exercised: {withheld}"
    );
    assert_eq!(
        closing_line_of(&first),
        closing_of_a_published_run(&read(&default), "chard-fakecc-bare.json", "wd", "0", false)
    );

    let again = run(&measure);
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert_eq!(again.status.code(), Some(0), "{again:?}");
    assert!(
        stderr.contains("chard-fakecc-bare.json is set aside as chard-fakecc-bare.json.previous"),
        "a rerun sets its own earlier report aside: {stderr}"
    );
    assert!(
        !work.path("chard-fakecc-bare.json.previous").exists(),
        "and removes it once it publishes"
    );
    assert_eq!(
        closing_line_of(&again),
        closing_of_a_published_run(&read(&default), "chard-fakecc-bare.json", "wd", "0", true)
    );

    let before = std::fs::read(&default).expect("the default report");
    let streamed = run(&[&measure[..], &["-o", "-"]].concat());
    assert_eq!(streamed.status.code(), Some(0), "{streamed:?}");
    serde_json::from_slice::<Value>(&streamed.stdout).expect("-o - puts the report on stdout");
    assert_eq!(
        std::fs::read(&default).expect("the default report"),
        before,
        "-o - leaves the default file alone"
    );
    let gated = run(&[&measure[..], &["--fail-on-missing"]].concat());
    assert_eq!(gated.status.code(), Some(1), "{gated:?}");
    assert!(
        closing_line_of(&gated).starts_with("chard: measure exits 1 (--fail-on-missing: ")
            && closing_line_of(&gated).ends_with("next: chard table chard-fakecc-bare.json"),
        "{gated:?}"
    );

    the_refusals_close_with_what_they_left(&run, cc, &work);
}

/// The half of [`measure_closes_every_run_with_one_line_naming_what_it_wrote`] whose runs
/// write no report: a failure after the set-aside, naming the earlier report kept; a
/// refusal before it; and a command line clap refuses.
fn the_refusals_close_with_what_they_left(
    run: &dyn Fn(&[&str]) -> std::process::Output,
    cc: &str,
    work: &common::Work,
) {
    std::fs::write(work.path("r.json"), "earlier\n").expect("an earlier file");
    let failed = run(&["--cc", "./no-such-cc", "--workdir", "wd", "-o", "r.json"]);
    assert_eq!(failed.status.code(), Some(2), "{failed:?}");
    let envelope: Value = serde_json::from_slice(&failed.stdout).expect("the envelope");
    assert!(envelope["error"].is_object(), "{envelope}");
    assert_eq!(
        std::fs::read_to_string(work.path("r.json.previous")).expect("kept"),
        "earlier\n"
    );
    // An older run's `.previous`, with nothing at the path: this run set nothing aside, and
    // its line names none.
    std::fs::write(work.path("s.json.previous"), "older\n").expect("an older run's file");
    let failed = run(&["--cc", "./no-such-cc", "--workdir", "wd", "-o", "s.json"]);
    assert_eq!(failed.status.code(), Some(2), "{failed:?}");
    assert!(
        closing_line_of(&failed).contains("s.json.previous"),
        "{failed:?}"
    );

    let refused = run(&["--cc", cc, "--workdir", "wd2", "--probe", "no-such-probe"]);
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
    assert!(closing_line_of(&refused).starts_with("chard: measure exits 2"));
    assert!(!work.path("wd2").exists(), "nothing was made");

    let usage = run(&["--no-such-option"]);
    assert_eq!(usage.status.code(), Some(2), "{usage:?}");
    assert_eq!(closing_line_of(&usage), closing_line_of(&refused));
}

#[test]
fn chard_digest_prints_the_block_a_report_leads_with() {
    if !can_run("that chard digest prints the block a report leads with") {
        return;
    }
    let work = common::Work::new("fakedriver", "digest");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let path = work.path("report.json");
    let run = |args: &[&OsStr]| {
        Command::new(chard_binary())
            .current_dir(work.dir())
            .args(args)
            .output()
            .expect("spawning chard")
    };
    let measured = run(&[
        OsStr::new("measure"),
        OsStr::new(PROBE_DEADLINE[0]),
        OsStr::new(PROBE_DEADLINE[1]),
        OsStr::new("--cc"),
        driver.as_os_str(),
        OsStr::new("--workdir"),
        OsStr::new("wd"),
        OsStr::new("--probe"),
        OsStr::new("link-defaults"),
        OsStr::new("-o"),
        path.as_os_str(),
    ]);
    assert_eq!(measured.status.code(), Some(0), "{measured:?}");
    let text = std::fs::read_to_string(&path).expect("the report was written");
    assert!(
        text.starts_with("{\n  \"digest\": {\n    \"chard_schema\": "),
        "the digest is not the report's first key: {}",
        text.chars().take(80).collect::<String>()
    );
    let report: Value = serde_json::from_str(&text).expect("JSON");

    let printed = run(&[OsStr::new("digest"), path.as_os_str()]);
    assert_eq!(printed.status.code(), Some(0), "{printed:?}");
    let digest: Value = serde_json::from_slice(&printed.stdout).expect("the digest is JSON");
    assert_eq!(digest, report["digest"]);
    assert!(
        printed.stdout.len() * 10 < text.len(),
        "the digest ({} bytes) is not small beside the report ({} bytes)",
        printed.stdout.len(),
        text.len()
    );
    let rpath = digest["checks"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["check"] == "rpath-absent")
        .expect("the link-defaults probe carries rpath-absent");
    assert_eq!(rpath["polarity"], "weaken");

    // Refused: an edited row, a quarantine by its name, and a report with no digest, which
    // `table` refuses too.
    let refused = |name: &str, edit: &dyn Fn(&mut Value), needle: &str| {
        let mut edited = report.clone();
        edit(&mut edited);
        let file = work.path(name);
        std::fs::write(&file, serde_json::to_string(&edited).expect("json")).expect("write");
        let out = run(&[OsStr::new("digest"), file.as_os_str()]);
        assert_eq!(out.status.code(), Some(2), "{name}: {out:?}");
        let envelope: Value = serde_json::from_slice(&out.stdout).expect("an envelope");
        assert_eq!(envelope["error"]["code"], "USER_INPUT", "{name}");
        let message = envelope["error"]["message"].as_str().expect("a message");
        assert!(message.contains(needle), "{name}: {message}");
        file
    };
    let flip: &dyn Fn(&mut Value) = &|r| {
        let rows = r["digest"]["checks"].as_array_mut().expect("rows");
        let row = rows.iter_mut().find(|r| r["check"] == "pie").expect("pie");
        row["verdict"] = if row["verdict"] == "on" { "off" } else { "on" }.into();
    };
    refused(
        "edited.json",
        flip,
        "fails `digest-disagrees-with-report` when the rule is re-run on read \
         (digest.checks[pie].verdict",
    );
    refused(
        "kept.json.contradicted",
        &|_| {},
        "the quarantine `measure` writes",
    );
    let older = refused(
        "older.json",
        &|r| {
            r.as_object_mut().expect("object").remove("digest");
        },
        "carries no `digest`",
    );
    let table = run(&[OsStr::new("table"), older.as_os_str()]);
    assert_eq!(table.status.code(), Some(2), "table refuses it: {table:?}");
    let envelope: Value = serde_json::from_slice(&table.stdout).expect("an envelope");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("carries no `digest`")),
        "{envelope}"
    );

    every_reader_refuses_another_chard_schema_and_a_missing_digest(&work, &path, &report);
    the_renderers_carry_the_polarity(&path);
}

/// `chard` in `work` with `args`.
fn chard_in(work: &common::Work, args: &[&OsStr]) -> std::process::Output {
    Command::new(chard_binary())
        .current_dir(work.dir())
        .args(args)
        .output()
        .expect("spawning chard")
}

/// The four readers of a report over `path`: `table`, `matrix`, `digest`, and `detect` for
/// `pie`, which `link-defaults` measures.
fn the_four_readers(work: &common::Work, path: &Path) -> Vec<(&'static str, std::process::Output)> {
    let detect = [
        OsStr::new("detect"),
        OsStr::new("pie"),
        OsStr::new("--evidence"),
        path.as_os_str(),
    ];
    vec![
        (
            "table",
            chard_in(work, &[OsStr::new("table"), path.as_os_str()]),
        ),
        (
            "matrix",
            chard_in(work, &[OsStr::new("matrix"), path.as_os_str()]),
        ),
        (
            "digest",
            chard_in(work, &[OsStr::new("digest"), path.as_os_str()]),
        ),
        ("detect", chard_in(work, &detect)),
    ]
}

/// The message of a refusal: exit 2 under `USER_INPUT`, or the test fails naming `reader`.
fn refusal_of(reader: &str, out: &std::process::Output) -> String {
    assert_eq!(out.status.code(), Some(2), "{reader}: {out:?}");
    let envelope: Value = serde_json::from_slice(&out.stdout).expect("an envelope");
    assert_eq!(
        envelope["error"]["code"], "USER_INPUT",
        "{reader}: {envelope}"
    );
    envelope["error"]["message"]
        .as_str()
        .expect("a message")
        .to_owned()
}

/// One forged report: its name, the edit, and what the refusal says the file carries.
type Forge<'a> = (&'a str, Box<dyn Fn(&mut Value) + 'a>, &'a str);

fn without_digest(report: &mut Value) {
    report.as_object_mut().expect("object").remove("digest");
}

/// `table`, `matrix`, `digest` and `detect` refuse a report whose `chard_schema` is not the
/// one this chard writes, exit 2 under `USER_INPUT` with the message naming what the file
/// carries and the version this chard reads, digest or no digest: the field set to `"99"`
/// with the digest removed and with it kept, the field removed, a number, and a string with
/// a space. The version is named before the digest rule: a report of another version whose
/// digest was also edited is refused for its version. The honest report is read by all
/// four, as a control. Then [`a_report_with_no_digest_is_refused_by_the_readers_of_verdicts`]
/// and [`a_forged_report_leaves_the_earlier_output_and_refuses_the_set`] over the first
/// forged file.
fn every_reader_refuses_another_chard_schema_and_a_missing_digest(
    work: &common::Work,
    honest: &Path,
    report: &Value,
) {
    let reads = format!("`chard_schema` \"{}\"", chard::report::SCHEMA_VERSION);
    let mut fed = 0;
    for (reader, out) in the_four_readers(work, honest) {
        fed += 1;
        assert_eq!(
            out.status.code(),
            Some(0),
            "{reader} over the honest report: {out:?}"
        );
    }
    assert_eq!(fed, 4, "four readers over the honest report");

    let flip_a_row = |r: &mut Value| {
        let rows = r["digest"]["checks"].as_array_mut().expect("rows");
        let row = rows.iter_mut().find(|r| r["check"] == "pie").expect("pie");
        row["verdict"] = if row["verdict"] == "on" { "off" } else { "on" }.into();
    };
    let shapes: [Forge; 6] = [
        (
            "v99-no-digest",
            Box::new(|r| {
                r["chard_schema"] = "99".into();
                without_digest(r);
            }),
            "carries `chard_schema` \"99\"",
        ),
        (
            "v99-digest-kept",
            Box::new(|r| r["chard_schema"] = "99".into()),
            "carries `chard_schema` \"99\"",
        ),
        (
            "v99-digest-forged",
            Box::new(|r| {
                r["chard_schema"] = "99".into();
                flip_a_row(r);
            }),
            "carries `chard_schema` \"99\"",
        ),
        (
            "version-absent",
            Box::new(|r| {
                r.as_object_mut().expect("object").remove("chard_schema");
            }),
            "carries no `chard_schema`",
        ),
        (
            "version-a-number",
            Box::new(|r| r["chard_schema"] = 1.into()),
            "carries `chard_schema` 1,",
        ),
        (
            "version-with-a-space",
            Box::new(|r| r["chard_schema"] = "1 ".into()),
            "carries `chard_schema` \"1 \"",
        ),
    ];
    let mut refused = 0;
    let mut first = None;
    for (name, edit, carries) in &shapes {
        let mut forged = report.clone();
        edit(&mut forged);
        let path = work.path(&format!("{name}.json"));
        std::fs::write(&path, serde_json::to_string(&forged).expect("json")).expect("write");
        for (reader, out) in the_four_readers(work, &path) {
            let said = refusal_of(reader, &out);
            refused += 1;
            assert!(
                said.contains(carries) && said.contains(&reads),
                "{name} {reader}: the refusal names both versions: {said}"
            );
            assert!(
                !said.contains("digest-disagrees-with-report"),
                "{name} {reader}: the version is named before the digest rule: {said}"
            );
        }
        first.get_or_insert(path);
    }
    assert_eq!(refused, 24, "six shapes through four readers");
    a_report_with_no_digest_is_refused_by_the_readers_of_verdicts(work, report);
    a_forged_report_leaves_the_earlier_output_and_refuses_the_set(
        work,
        honest,
        &first.expect("a forged report"),
    );
}

/// A report at this version with no digest is refused by `table`, `matrix` and `digest`,
/// naming the missing digest, and replayed by `detect`, which re-derives readings from the
/// report's facts rather than rendering its verdicts.
fn a_report_with_no_digest_is_refused_by_the_readers_of_verdicts(
    work: &common::Work,
    report: &Value,
) {
    let mut older = report.clone();
    without_digest(&mut older);
    let path = work.path("no-digest.json");
    std::fs::write(&path, serde_json::to_string(&older).expect("json")).expect("write");
    let mut held = 0;
    for (reader, out) in the_four_readers(work, &path) {
        held += 1;
        if reader == "detect" {
            assert_eq!(out.status.code(), Some(0), "detect replays it: {out:?}");
            continue;
        }
        let said = refusal_of(reader, &out);
        assert!(said.contains("carries no `digest`"), "{reader}: {said}");
        // A refusal of the read: an earlier output at `-o` is left as it was.
        let earlier = work.path(&format!("{reader}.no-digest.earlier"));
        std::fs::write(&earlier, "an earlier output\n").expect("an earlier output");
        let args = [
            OsStr::new(reader),
            path.as_os_str(),
            OsStr::new("-o"),
            earlier.as_os_str(),
        ];
        refusal_of(reader, &chard_in(work, &args));
        assert_eq!(
            std::fs::read_to_string(&earlier).expect("the earlier output is there"),
            "an earlier output\n",
            "{reader}"
        );
        let previous = work.path(&format!("{reader}.no-digest.earlier.previous"));
        assert!(!previous.exists(), "{reader} set the earlier output aside");
    }
    assert_eq!(held, 4, "four readers over the report with no digest");
}

/// `matrix` over a set where one of three is `forged` refuses the set, naming the file; and
/// each reader given `-o` over an earlier output and `forged` leaves that output as it was,
/// with no `.previous` beside it: nothing was read as a report.
fn a_forged_report_leaves_the_earlier_output_and_refuses_the_set(
    work: &common::Work,
    honest: &Path,
    forged: &Path,
) {
    let copy = work.path("honest-copy.json");
    std::fs::copy(honest, &copy).expect("a copy");
    let set = chard_in(
        work,
        &[
            OsStr::new("matrix"),
            honest.as_os_str(),
            forged.as_os_str(),
            copy.as_os_str(),
        ],
    );
    let said = refusal_of("matrix over a set", &set);
    assert!(
        said.contains(&forged.display().to_string()),
        "the refusal names the forged file: {said}"
    );

    let mut kept = 0;
    for reader in ["table", "matrix", "digest", "detect"] {
        let earlier = work.path(&format!("{reader}.earlier"));
        std::fs::write(&earlier, "an earlier output\n").expect("an earlier output");
        let mut args = vec![OsStr::new(reader)];
        if reader == "detect" {
            args.extend([OsStr::new("pie"), OsStr::new("--evidence")]);
        }
        args.extend([forged.as_os_str(), OsStr::new("-o"), earlier.as_os_str()]);
        refusal_of(reader, &chard_in(work, &args));
        kept += 1;
        assert_eq!(
            std::fs::read_to_string(&earlier).expect("the earlier output is there"),
            "an earlier output\n",
            "{reader}"
        );
        let previous = work.path(&format!("{reader}.earlier.previous"));
        assert!(!previous.exists(), "{reader} set the earlier output aside");
    }
    assert_eq!(kept, 4, "four readers given an earlier output");
}

/// `table`'s legend names the `weaken` inversion and `matrix`'s cell carries each flag's
/// polarity, over the report at `path`, which measured `link-defaults`.
fn the_renderers_carry_the_polarity(path: &Path) {
    let run = |command: &str| {
        Command::new(chard_binary())
            .arg(command)
            .arg(path)
            .output()
            .expect("spawning chard")
    };
    let table = run("table");
    assert_eq!(table.status.code(), Some(0), "{table:?}");
    let rendered = String::from_utf8_lossy(&table.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        rendered.contains("A row for a flag that weakens a protection (`polarity` `weaken`"),
        "the legend names the inversion: {rendered}"
    );
    let matrix = run("matrix");
    assert_eq!(matrix.status.code(), Some(0), "{matrix:?}");
    let matrix: Value = serde_json::from_slice(&matrix.stdout).expect("a matrix");
    assert_eq!(matrix["cells"][0]["polarity"]["-Wl,-rpath"], "weaken");
    assert_eq!(matrix["cells"][0]["polarity"]["-pie"], "harden");
}

/// A wrapper body that passes everything to `$REAL`, removes `.chard.report` from every
/// program it links, adds `lie` to the `-dM -E` dumps alone, and appends one line to `log`
/// for each dump it lied to, so a test can show the lie was told on a host whose compiler
/// defines the lied-about macro by itself.
fn strips_the_self_report(lie: &str, log: &Path) -> String {
    format!(
        r#"LOG='{}'
out=; prev=; link=1
for a in "$@"; do
  [ "$prev" = "-o" ] && out=$a
  case "$a" in -c|-E|-S|-fsyntax-only|-###|-dumpmachine|--version|-v) link=0;; esac
  prev=$a
done
case " $* " in
  *" -dM "*) echo "lied: $*" >> "$LOG"; exec "$REAL" {lie} "$@" ;;
esac
"$REAL" "$@" || exit $?
if [ -n "$out" ] && [ "$link" = 1 ] && [ -f "$out" ]; then
  objcopy --remove-section .chard.report "$out" || exit 97
fi
exit 0"#,
        log.display()
    )
}

/// The lines `strips_the_self_report`'s wrapper logged: one per dump it lied to.
fn lies_told(log: &Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |text| text.lines().count())
}

/// The observation of `check` in `report`, with the gating it carries, asserted withheld
/// under `artifact-lacks-self-report` with a reason naming the section's absence and the
/// dump the macros came from.
fn assert_withheld_for_the_missing_section(report: &Value, check: &str) {
    let obs = observation(report, check);
    assert_eq!(obs["verdict"], "indeterminate", "{check}: {obs}");
    assert!(
        obs.get("level").is_none(),
        "{check} publishes no level: {obs}"
    );
    assert_eq!(
        obs["gating"]["rule"], "artifact-lacks-self-report",
        "{check}: {}",
        obs["gating"]
    );
    assert!(obs["gating"]["reason"].is_string(), "a reason");
    assert_eq!(
        obs["evidence"]["macro_source"], "preprocessor",
        "{check}: the macros were the dump's, and the report says so: {}",
        obs["evidence"]
    );
    assert_eq!(
        obs["controls"]["discriminating"], true,
        "{check}: the arms, dump readings, do not discriminate: {}",
        obs["controls"]
    );
}

/// The report says why once, under `probe`, naming the way the section is missing, and the
/// corroboration group carries no macro reading to disagree with the artifact's.
fn assert_one_warning_and_no_disagreement(report: &Value, probe: &str) {
    // The report says why, once per probe, and the corroboration group carries no macro
    // reading to disagree with the artifact's.
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    let about_section: Vec<&Value> = diagnostics
        .iter()
        .filter(|d| {
            d["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("probe embeds a .chard.report section"))
        })
        .collect();
    assert_eq!(about_section.len(), 1, "{diagnostics:?}");
    assert_eq!(about_section[0]["context"], probe);
    assert!(
        about_section[0]["message"]
            .as_str()
            .is_some_and(|m| m.contains("sections and no `.chard.report`")),
        "{}",
        about_section[0]
    );
    assert!(
        !diagnostics.iter().any(|d| d["message"]
            .as_str()
            .is_some_and(|m| m.contains("CHANNELS DISAGREE"))),
        "a withheld macro reading does not disagree with the artifact's: {diagnostics:?}"
    );
}

#[test]
fn a_driver_that_strips_the_self_report_withholds_every_macro_verdict() {
    if !can_run("that a macro reading over an artifact without its .chard.report is withheld") {
        return;
    }
    if !on_path("objcopy") {
        common::capability_gap(
            "stripped self-report",
            "no objcopy on PATH, so the wrapper cannot remove the section after the link",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "strip-self-report");
    let log = work.path("lies.log");
    let driver = fake_driver(
        work.dir(),
        &strips_the_self_report("-fstack-protector-strong", &log),
    );
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "bare-optimized",
            "--probe",
            "toolchain-macros",
            "--probe",
            "stack-canary",
        ],
    );

    let macro_checks: Vec<&Value> = macro_observations(&report)
        .into_iter()
        .filter(|o| o["probe"] == "toolchain-macros")
        .collect();
    let mut withheld = 0usize;
    let mut gated_out = 0usize;
    for obs in &macro_checks {
        let check = obs["check"].as_str().expect("a check id");
        // A check the target's mechanism table gates out at applicability never built a
        // triple and keeps that rule (`gcs-macro` and `branch-protection-macro` on x86_64,
        // `cet-macro` on aarch64): it publishes no `controls`.
        if obs.get("controls").is_none() {
            assert!(
                obs["gating"]["rule"].is_string(),
                "{check}: no triple and no rule: {obs}"
            );
            gated_out += 1;
            continue;
        }
        assert_withheld_for_the_missing_section(&report, check);
        withheld += 1;
    }
    eprintln!(
        "stripped self-report: {withheld} macro checks withheld, {gated_out} gated at applicability, of {}",
        macro_checks.len()
    );
    assert_eq!(withheld + gated_out, macro_checks.len());
    assert!(
        withheld >= 6,
        "the probe's macro checks were measured: {withheld}"
    );
    // `ssp-level` is the one the dump lied about, and it carries no level now.
    assert_withheld_for_the_missing_section(&report, "ssp-level");
    // The lie reached the dump: the withheld reading carries the macro the dump-only
    // flag defined, which the stripped artifact could not contradict.
    let ssp = observation(&report, "ssp-level");
    assert!(
        ssp["evidence"]["macros"]["__SSP_STRONG__"].is_string(),
        "the withheld reading does not carry the dump the wrapper lied to: {}",
        ssp["evidence"]
    );
    assert!(
        lies_told(&log) > 0,
        "the wrapper never saw a -dM job, so the macro above is the compiler's own default"
    );

    // The elf-static reading over the same artifact is its own: the symbol table was read
    // whole, the section it lacks is not one that check reads.
    let canary = observation(&report, "canary-emitted");
    assert!(
        matches!(canary["verdict"].as_str(), Some("on" | "off")),
        "canary-emitted is a measurement over the stripped artifact: {canary}"
    );
    assert!(canary.get("gating").is_none(), "{canary}");

    assert_one_warning_and_no_disagreement(&report, "toolchain-macros");
    let by_rule = &report["coverage"]["withholding"]["instrument_withholdings"]["by_rule"];
    assert_eq!(
        by_rule["artifact-lacks-self-report"].as_u64(),
        Some(u64::try_from(withheld).expect("a small count")),
        "{by_rule}"
    );
    assert_eq!(report["consistency"]["status"], "consistent");
}

#[test]
fn a_cpp_only_assertions_request_over_a_stripped_artifact_reads_indeterminate_not_on() {
    if !can_run("that the C++ macro check over an artifact without its .chard.report is withheld") {
        return;
    }
    let Some(cxx) = real_cxx() else {
        common::capability_gap(
            "stripped C++ self-report",
            "no c++ on PATH beside cc, so the C++ probe cannot link here",
        );
        return;
    };
    if !on_path("objcopy") {
        common::capability_gap(
            "stripped C++ self-report",
            "no objcopy on PATH, so the wrapper cannot remove the section after the link",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "strip-cxx-self-report");
    let driver = fake_driver_named(work.dir(), "fake-cc", &real_cc(), r#"exec "$REAL" "$@""#);
    let log = work.path("lies.log");
    fake_driver_named(
        work.dir(),
        "fake-c++",
        &cxx,
        &strips_the_self_report("-D_GLIBCXX_ASSERTIONS", &log),
    );
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "bare-optimized",
            "--probe",
            "cxx-stdlib-assertions",
        ],
    );
    assert!(
        report["toolchain"]["cxx_driver"]
            .as_str()
            .is_some_and(|p| p.ends_with("fake-c++")),
        "the C++ wrapper must be found beside the C one: {}",
        report["toolchain"]
    );
    assert_withheld_for_the_missing_section(&report, "cxx-hardening-requested");
    assert!(lies_told(&log) > 0, "the wrapper never saw a -dM job");
    let requested = observation(&report, "cxx-hardening-requested");
    assert_eq!(
        requested["evidence"]["macros"]["_GLIBCXX_ASSERTIONS"], "1",
        "the dump the wrapper lied to is what the withheld reading carries: {}",
        requested["evidence"]
    );
    // The compiled code has no assertions, and the artifact channels say so over the same
    // stripped artifact.
    let runtime = observation(&report, "cxx-stdlib-assertions");
    assert_eq!(runtime["verdict"], "off", "{runtime}");
    let symbol = observation(&report, "cxx-assertions-symbol");
    assert_eq!(symbol["verdict"], "off", "{symbol}");
    let by_rule = &report["coverage"]["withholding"]["instrument_withholdings"]["by_rule"];
    assert_eq!(
        by_rule["artifact-lacks-self-report"].as_u64(),
        Some(1),
        "{by_rule}"
    );
}

/// The rule a macro check is withheld under over a build that gave no account of its
/// macros: the witness's where the build left an artifact the run could hold to it and
/// did not confirm, and the self-report's otherwise.
fn rule_over_no_account(unwitnessed: bool) -> &'static str {
    if unwitnessed {
        "artifact-lacks-run-witness"
    } else {
        "artifact-lacks-self-report"
    }
}

/// A run carries a witness exactly where its artifacts are ELF. Whether it does is the
/// host's fact, never read off the report under test: a run that lost its witness would
/// otherwise be held to the rule a run without one publishes, and pass.
fn assert_witnessed_where_elf(tag: &str, report: &Value) {
    assert_eq!(
        report["run"].get("artifact_witness").is_some(),
        common::ELF_HOST,
        "{tag}: a run carries a witness exactly where its artifacts are ELF"
    );
}

/// The witness rule's reason quotes the reader's own refusal of the build under `key`: the
/// words the store keeps after the artifact's name.
fn assert_quotes_the_stored_refusal(tag: &str, report: &Value, key: Option<&str>, reason: &str) {
    let refusal = key
        .and_then(|key| report["facts"][key]["error"].as_str())
        .expect("the refusal is stored");
    let words = refusal.rsplit(": ").next().expect("the refusal's words");
    assert!(
        reason.contains("the ELF reader refused") && reason.contains(words),
        "{tag}: the reason quotes the stored refusal `{refusal}`: {reason}"
    );
}

/// Every macro check of `report` that built is withheld as unwitnessed: nothing of the dump
/// is published beside the withholding, and no arm is built.
fn assert_every_macro_check_is_unwitnessed(tag: &str, report: &Value) {
    let mut withheld = 0;
    for obs in macro_observations(report) {
        // Decided before any build: an arch gate.
        if obs.get("build").is_none() {
            continue;
        }
        let check = &obs["check"];
        assert_eq!(
            obs["gating"]["rule"], "artifact-lacks-run-witness",
            "{tag}: {check}"
        );
        assert_eq!(obs["verdict"], "indeterminate", "{tag}: {check}");
        assert!(obs.get("controls").is_none(), "{tag}: {check}");
        assert!(
            obs["evidence"].get("macros").is_none(),
            "{tag}: {check} publishes the dump's macros: {obs}"
        );
        withheld += 1;
    }
    assert!(withheld >= 6, "{tag}: {withheld} withheld");
    assert_eq!(report["consistency"]["status"], "consistent", "{tag}");
}

#[test]
fn a_driver_that_leaves_no_readable_artifact_withholds_every_macro_verdict() {
    if !can_run("that a macro reading over an artifact the reader refused is withheld") {
        return;
    }
    let shapes: [(&str, &str, &str); 4] = [
        (
            "garbage",
            r#"printf 'not an object\n' > "$out""#,
            "could not be read by chard's ELF reader",
        ),
        ("refused-elf", REFUSED_ELF, "unknown EI_CLASS"),
        // A thin 64-bit Mach-O header off macOS: the reader's typed finding reaches the
        // published entry, and the gate holds, since the exemption is macOS's alone.
        ("mach-o", PLANTED_MACH_O, "a Mach-O object"),
        (
            "deleted",
            r#"rm -f "$out""#,
            "was never written: the build exited 0",
        ),
    ];
    for (tag, after_link, says) in shapes {
        let work = common::Work::new("fakedriver", &format!("unread-self-report-{tag}"));
        let log = work.path("lies.log");
        let script = strips_the_self_report("-fstack-protector-strong", &log).replace(
            r#"objcopy --remove-section .chard.report "$out" || exit 97"#,
            after_link,
        );
        assert!(
            script.contains(after_link),
            "the wrapper body was rewritten"
        );
        let driver = fake_driver(work.dir(), &script);
        let report = measure(
            &driver,
            work.dir(),
            &["--profile", "bare-optimized", "--probe", "toolchain-macros"],
        );
        let ssp = observation(&report, "ssp-level");
        let key = ssp["build"]["artifact_sha256"].as_str();
        assert_eq!(
            key.is_some(),
            tag != "deleted",
            "{tag}: the build's digest: {ssp}"
        );
        if tag == "mach-o" && report["environment"]["distro"]["id"] == "macos" {
            // On a macOS host a Mach-O object is the by-design dump reading.
            assert!(ssp.get("gating").is_none(), "{tag}: {ssp}");
            continue;
        }
        assert_eq!(ssp["verdict"], "indeterminate", "{tag}: {ssp}");
        assert!(ssp.get("level").is_none(), "{tag}: {ssp}");
        // Under a witness (every run but macOS's) an artifact the reader refused is one it
        // could not hold to the witness, and is withheld before the self-report gate asks
        // anything of it, on every check and with no triple built.
        assert_witnessed_where_elf(tag, &report);
        let unwitnessed = key.is_some() && common::ELF_HOST;
        let rule = rule_over_no_account(unwitnessed);
        assert_eq!(ssp["gating"]["rule"], rule, "{tag}: {ssp}");
        let reason = ssp["gating"]["reason"].as_str().expect("a reason");
        if unwitnessed {
            assert_quotes_the_stored_refusal(tag, &report, key, reason);
        } else {
            assert!(reason.contains(says), "{tag}: {reason}");
        }
        assert_eq!(
            ssp["evidence"]["macro_source"], "preprocessor",
            "{tag}: {ssp}"
        );
        if let Some(key) = key {
            let entry = &report["facts"][key];
            assert_eq!(entry["kind"], "unreadable", "{tag}: {entry}");
            assert_eq!(
                entry.get("mach_o").is_some(),
                tag == "mach-o",
                "{tag}: only the reader's Mach-O finding sets mach_o: {entry}"
            );
        }
        assert!(
            lies_told(&log) > 0,
            "{tag}: the wrapper never saw a -dM job"
        );
        let mut withheld = 0;
        if unwitnessed {
            assert_every_macro_check_is_unwitnessed(tag, &report);
            continue;
        }
        assert!(
            ssp["evidence"]["macros"]["__SSP_STRONG__"].is_string(),
            "{tag}: the lie reached the dump: {ssp}"
        );
        for obs in macro_observations(&report) {
            // No triple, or a triple that did not discriminate (`pie-macro` and `pic-macro`
            // under Apple clang 21 on macOS 27): the gate leaves those readings standing.
            if obs.get("controls").is_none() || obs["verdict"] == "probe-invalid" {
                continue;
            }
            assert_eq!(
                obs["gating"]["rule"], "artifact-lacks-self-report",
                "{tag}: {}",
                obs["check"]
            );
            withheld += 1;
        }
        assert!(withheld >= 6, "{tag}: {withheld} withheld");
        assert_eq!(report["consistency"]["status"], "consistent", "{tag}");
    }
}

#[test]
fn a_report_whose_fields_all_read_undefined_is_the_artifacts_account() {
    if !can_run("that an all-undefined self-report is kept as the artifact's account") {
        return;
    }
    if !on_path("objcopy") {
        common::capability_gap(
            "all-undefined self-report",
            "no objcopy on PATH, so the wrapper cannot rewrite the section after the link",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "all-undefined-self-report");
    let report_text = work.write(
        "undefined.report",
        "CHARD-REPORT-V2\n__SSP__ undefined\n__SSP_STRONG__ undefined\n__SSP_ALL__ undefined\n\
         __SSP_EXPLICIT__ undefined\n_FORTIFY_SOURCE undefined\n__USE_FORTIFY_LEVEL undefined\n\
         __OPTIMIZE__ undefined\n__PIE__ undefined\n__PIC__ undefined\n__CET__ undefined\n\
         CHARD-REPORT-END\n",
    );
    let script = format!(
        r#"out=; prev=; link=1
for a in "$@"; do
  [ "$prev" = "-o" ] && out=$a
  case "$a" in -c|-E|-S|-fsyntax-only|-###|-dumpmachine|--version|-v) link=0;; esac
  prev=$a
done
"$REAL" "$@" || exit $?
case "$out" in
  *-measured) objcopy --update-section .chard.report='{}' "$out" || exit 97 ;;
esac
exit 0"#,
        report_text.display()
    );
    let driver = fake_driver(work.dir(), &script);
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare-optimized", "--probe", "toolchain-macros"],
    );
    let ssp = observation(&report, "ssp-level");
    assert_eq!(ssp["verdict"], "off", "{ssp}");
    assert!(ssp.get("gating").is_none(), "{ssp}");
    assert_eq!(
        ssp["evidence"]["macro_source"], "compiled-artifact",
        "{ssp}"
    );
    assert_eq!(
        ssp["evidence"]["macros"],
        serde_json::json!({}),
        "the account that nothing is defined is an empty map: {ssp}"
    );
    assert_eq!(ssp["controls"]["discriminating"], true, "{ssp}");
    assert_eq!(report["consistency"]["status"], "consistent");
    let optimized = observation(&report, "optimization-enabled");
    assert_eq!(optimized["verdict"], "off", "{optimized}");

    // `detect` replays the artifact's account the same way: no disagreement.
    let path = work.path("report.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&report).expect("a serializable report"),
    )
    .expect("writing the report");
    let replay = Command::new(chard_binary())
        .args(["detect", "ssp-level", "--evidence"])
        .arg(&path)
        .args(["-o", "-"])
        .output()
        .expect("spawning chard detect");
    let text = String::from_utf8_lossy(&replay.stdout);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "detect disagrees with measure over the all-undefined report:\n{text}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replayed: Value = serde_json::from_str(&text).expect("detect writes JSON");
    assert_eq!(replayed["expected"], replayed["replayed"], "{replayed}");
}

/// A wrapper line that overwrites the linked program at `$out` with an ELF identification
/// whose class (3) the reader has no layout for, padded to a header's length: an artifact
/// with the ELF magic that chard's reader refuses.
const REFUSED_ELF: &str =
    r#"{ printf '\177ELF\003\001\001'; head -c 57 /dev/zero; } > "$out" || exit 97"#;

/// A wrapper line that overwrites the linked program at `$out` with a thin 64-bit
/// little-endian Mach-O magic (`MH_CIGAM_64` on disk), padded to a header's length.
const PLANTED_MACH_O: &str =
    r#"{ printf '\317\372\355\376'; head -c 60 /dev/zero; } > "$out" || exit 97"#;

#[test]
fn an_arm_that_lost_its_self_report_says_so_in_its_own_macro_source() {
    if !can_run("that a control arm without its .chard.report discloses it") {
        return;
    }
    if !on_path("objcopy") {
        common::capability_gap(
            "arm self-report",
            "no objcopy on PATH, so the wrapper cannot remove the section after the link",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "arm-self-report");
    let driver = fake_driver(
        work.dir(),
        r#"out=; prev=; link=1
for a in "$@"; do
  [ "$prev" = "-o" ] && out=$a
  case "$a" in -c|-E|-S|-fsyntax-only|-###|-dumpmachine|--version|-v) link=0;; esac
  prev=$a
done
"$REAL" "$@" || exit $?
case "$out" in
  *ssp-level-neg) [ "$link" = 1 ] && { objcopy --remove-section .chard.report "$out" || exit 97; } ;;
esac
exit 0"#,
    );
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare-optimized", "--probe", "toolchain-macros"],
    );
    let ssp = observation(&report, "ssp-level");
    assert!(
        matches!(ssp["verdict"].as_str(), Some("on" | "off")),
        "the measured build kept its section, so its reading is a measurement: {ssp}"
    );
    assert!(ssp.get("gating").is_none(), "{ssp}");
    assert_eq!(
        ssp["evidence"]["macro_source"], "compiled-artifact",
        "{ssp}"
    );
    let controls = &ssp["controls"];
    assert_eq!(
        controls["negative"]["macro_source"], "preprocessor",
        "the stripped arm says it read the dump: {controls}"
    );
    assert_eq!(
        controls["positive"]["macro_source"], "compiled-artifact",
        "{controls}"
    );
    assert_eq!(controls["discriminating"], true, "{controls}");
    // Another check's negative arm is another program, and kept its section.
    let pie = observation(&report, "pie-macro");
    assert_eq!(
        pie["controls"]["negative"]["macro_source"], "compiled-artifact",
        "{}",
        pie["controls"]
    );
    // No diagnostic names the arm's loss: the per-probe warning reads the measured build.
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    assert!(
        !diagnostics.iter().any(|d| d["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("probe embeds a .chard.report section"))),
        "{diagnostics:?}"
    );
    assert_eq!(report["consistency"]["status"], "consistent");
}

/// A wrapper body that passes everything to `$REAL` and overwrites the `.chard.report`
/// section of every program it links with as many zero bytes, so the section holds no
/// report and the program keeps the layout the linker wrote. A program without the section
/// is left alone.
const BLANKS_THE_SELF_REPORT: &str = r#"out=; prev=; link=1
for a in "$@"; do
  [ "$prev" = "-o" ] && out=$a
  case "$a" in -c|-E|-S|-fsyntax-only|-###|-dumpmachine|--version|-v) link=0;; esac
  prev=$a
done
"$REAL" "$@" || exit $?
if [ -n "$out" ] && [ "$link" = 1 ] && [ -f "$out" ]; then
  objcopy --dump-section .chard.report="$out.section" "$out" 2>/dev/null || exit 0
  head -c "$(wc -c < "$out.section")" /dev/zero > "$out.blank" || exit 97
  objcopy --update-section .chard.report="$out.blank" "$out" || exit 97
  rm -f "$out.section" "$out.blank"
fi
exit 0"#;

/// Each observation of `probes` in `report`: its probe, check, verdict and level, in the
/// report's order.
fn readings_of(report: &Value, probes: &[&str]) -> Vec<(String, String, Value, Value)> {
    report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o["probe"].as_str().is_some_and(|p| probes.contains(&p)))
        .map(|o| {
            (
                o["probe"].as_str().expect("a probe").to_owned(),
                o["check"].as_str().expect("a check").to_owned(),
                o["verdict"].clone(),
                o.get("level").cloned().unwrap_or(Value::Null),
            )
        })
        .collect()
}

/// The probes `report`'s per-probe self-report warning names.
fn self_report_warnings(report: &Value) -> std::collections::BTreeSet<String> {
    report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| {
            d["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("probe embeds a .chard.report section"))
        })
        .map(|d| d["context"].as_str().expect("a context").to_owned())
        .collect()
}

#[test]
fn a_probe_without_a_macro_check_reads_no_verdict_from_its_self_report() {
    if !can_run("that a probe without a macro check reads no verdict from its self-report") {
        return;
    }
    if !on_path("objcopy") {
        common::capability_gap(
            "provenance-only self-report",
            "no objcopy on PATH, so the wrapper cannot remove the section after the link",
        );
        return;
    }
    let probes: Vec<&str> = chard::probe::CORPUS
        .iter()
        .filter(|p| {
            p.embeds_self_report()
                && !p
                    .checks
                    .iter()
                    .any(|c| c.channel() == chard::probe::Channel::Macro)
        })
        .map(|p| p.id)
        .collect();
    assert!(
        probes.len() >= 10,
        "the corpus's provenance-only probes, fewer than expected: {probes:?}"
    );
    let mut args = vec!["--profile", "bare-optimized"];
    for id in &probes {
        args.extend(["--probe", id]);
    }
    let honest_work = common::Work::new("fakedriver", "provenance-honest");
    let honest = measure(
        &fake_driver(honest_work.dir(), r#"exec "$REAL" "$@""#),
        honest_work.dir(),
        &args,
    );
    let work = common::Work::new("fakedriver", "provenance-stripped");
    let stripped = measure(
        &fake_driver(work.dir(), BLANKS_THE_SELF_REPORT),
        work.dir(),
        &args,
    );
    let (before, after) = (
        readings_of(&honest, &probes),
        readings_of(&stripped, &probes),
    );
    assert!(!before.is_empty(), "no observation of {probes:?}");
    assert_eq!(
        before.len(),
        after.len(),
        "the two runs measured different checks"
    );
    let moved: Vec<_> = before.iter().zip(&after).filter(|(b, a)| b != a).collect();
    assert!(
        moved.is_empty(),
        "a verdict of a probe without a macro check moved with its section: {moved:#?}"
    );
    let measured = before
        .iter()
        .filter(|(_, _, v, _)| matches!(v.as_str(), Some("on" | "off" | "partial")))
        .count();
    eprintln!(
        "provenance-only self-report: {} probes, {} observations, {measured} measured, 0 moved",
        probes.len(),
        before.len()
    );
    assert!(measured > 0, "nothing was measured: {before:?}");

    // The warning, in the stripped run alone, once for each probe whose measured build's
    // artifact the reader read and the wrapper had linked.
    assert!(
        self_report_warnings(&honest).is_empty(),
        "{:?}",
        self_report_warnings(&honest)
    );
    let read_and_linked: std::collections::BTreeSet<String> = stripped["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o["probe"].as_str().is_some_and(|p| probes.contains(&p)))
        .filter(|o| {
            let linked = chard::probe::CORPUS
                .iter()
                .any(|p| o["probe"] == p.id && p.link_mode != chard::probe::LinkMode::Object);
            let read = o["build"]["artifact_sha256"]
                .as_str()
                .is_some_and(|k| stripped["facts"][k]["kind"] == "elf");
            linked && read
        })
        .map(|o| o["probe"].as_str().expect("a probe").to_owned())
        .collect();
    assert!(!read_and_linked.is_empty(), "no linked probe was read");
    assert_eq!(self_report_warnings(&stripped), read_and_linked);
    assert_eq!(honest["consistency"]["status"], "consistent");
    assert_eq!(stripped["consistency"]["status"], "consistent");
}

#[test]
fn a_refused_elf_artifact_on_a_macos_run_is_no_by_design_dump_reading() {
    if !can_run("that a refused ELF artifact on a macOS run withholds the macro channel") {
        return;
    }
    let work = common::Work::new("fakedriver", "macos-refused-elf");
    let log = work.path("lies.log");
    let script = strips_the_self_report("", &log).replace(
        r#"objcopy --remove-section .chard.report "$out" || exit 97"#,
        REFUSED_ELF,
    );
    assert!(
        script.contains(REFUSED_ELF),
        "the wrapper body was rewritten"
    );
    let driver = fake_driver(work.dir(), &script);
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare-optimized", "--probe", "toolchain-macros"],
    );
    let ssp = observation(&report, "ssp-level");
    // Withheld on the live run, by the witness where the run has one (the reader could
    // read none from an artifact it refused) and by the self-report gate where it has not.
    assert_witnessed_where_elf("refused-elf", &report);
    let live_rule = if common::ELF_HOST {
        "artifact-lacks-run-witness"
    } else {
        "artifact-lacks-self-report"
    };
    assert_eq!(ssp["gating"]["rule"], live_rule, "{ssp}");
    let key = ssp["build"]["artifact_sha256"]
        .as_str()
        .expect("the build wrote an artifact")
        .to_owned();
    assert_eq!(
        report["facts"][&key]["kind"], "unreadable",
        "{}",
        report["facts"][&key]
    );
    assert!(
        report["facts"][&key].get("mach_o").is_none(),
        "an ELF the reader refused is not a Mach-O object: {}",
        report["facts"][&key]
    );

    // The rule's findings when the edited report is read, through `table`.
    let rule_fires = |name: &str, edit: &dyn Fn(&mut Value)| -> bool {
        let mut edited = report.clone();
        let observations = edited["observations"].as_array_mut().expect("observations");
        let o = observations
            .iter_mut()
            .find(|o| o["check"] == "ssp-level")
            .expect("ssp-level");
        o["verdict"] = "on".into();
        o.as_object_mut().expect("an object").remove("gating");
        edit(&mut edited);
        let file = work.path(name);
        std::fs::write(&file, serde_json::to_vec(&edited).expect("json")).expect("write");
        let out = Command::new(chard_binary())
            .arg("table")
            .arg(&file)
            .output()
            .expect("spawning chard table");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{name}: the edit is refused by the rules that re-count the cells: {out:?}"
        );
        let envelope: Value = serde_json::from_slice(&out.stdout).expect("an envelope");
        let message = envelope["error"]["message"].as_str().expect("a message");
        message.contains("macro-verdict-unearned-by-artifact")
    };
    let macos = |r: &mut Value| r["environment"]["distro"]["id"] = "macos".into();
    assert!(
        rule_fires("macos-refused-elf.json", &macos),
        "a refused ELF on a macOS run reads the dump by design"
    );
    let mach_o = |r: &mut Value| {
        r["facts"][&key]["mach_o"] = true.into();
        r["facts"][&key]["error"] = format!("<artifact>: {}", chard::elf::MACH_O_REFUSAL).into();
    };
    assert!(
        !rule_fires("macos-mach-o.json", &|r| {
            macos(r);
            mach_o(r);
        }),
        "a Mach-O object the reader refused on a macOS run is the by-design dump reading"
    );
    assert!(
        rule_fires("linux-mach-o.json", &|r| {
            r["environment"]["distro"]["id"] = "fedora".into();
            mach_o(r);
        }),
        "a Mach-O object off macOS is an artifact that gave no account"
    );
    // `mach_o` set beside the reader's ELF refusal is a finding naming the rule, not the
    // exemption: the two fields are written from one typed refusal.
    assert!(
        rule_fires("macos-mach-o-over-elf.json", &|r| {
            macos(r);
            r["facts"][&key]["mach_o"] = true.into();
        }),
        "a mach_o the error text contradicts must not read as the by-design dump reading"
    );
}

/// `fhardened-effective`'s fortify bar, through `measure` itself: the driver's own
/// `-fhardened -O2 -dM -E` where the driver takes the option, and the C library the
/// headers name beside the triple the driver reports where it does not.
///
/// Each wrapper answers the `-fhardened` dump one way: refusing the token as clang does,
/// defining a level, or defining one while warning `-Whardened` that the option yielded to a
#[test]
fn the_fortify_bar_reads_the_driver_s_own_dump_and_else_the_headers_library() {
    if !can_run("that the fortify bar reads the driver's own -fhardened dump") {
        return;
    }
    let real = real_cc();
    let output = Command::new(&real)
        .arg("-dumpmachine")
        .output()
        .expect("the real driver runs");
    let native = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !(output.status.success() && native.contains("-linux")) {
        common::capability_gap(
            "fortify bar under a musl reading",
            &format!("this host's cc targets {native:?}, and the wrapper edits a Linux dump"),
        );
        return;
    }
    let arch = native.split('-').next().unwrap_or_default().to_owned();
    let work = common::Work::new("fakedriver", "fortify-bar-triple");
    let args = [
        "--profile",
        "explicit",
        "--flags",
        "-O2 -D_FORTIFY_SOURCE=2",
        "--probe",
        "toolchain-macros",
    ];
    let mut examined = 0_usize;
    for row in bar_rows(&arch, &native) {
        let dir = work.path(&format!("w-{}", row.name));
        std::fs::create_dir_all(&dir).expect("a workdir");
        let script = format!(
            r#"case "$*" in
  -dumpmachine) echo {}; exit 0 ;;
  *-fhardened*-dM*) {} ;;
  *-dM*macros-fhardened-baseline.c) {} ;;
  *-dM*macros-with-headers.c)
    {} ;;
esac
exec "$REAL" "$@""#,
            row.triple, row.fhardened, row.baseline, row.headers
        );
        let driver = fake_driver_named(work.dir(), row.name, &real, &script);
        let report = measure(&driver, &dir, &args);
        let name = row.name;
        assert_eq!(
            report["environment"]["libc"]["impl"], row.libc,
            "{name}: the wrapper's dump did not read as {}: {}",
            row.libc, report["environment"]["libc"]
        );
        // The glibc rows tell the readings apart only where the library would ask 3.
        if row.libc == "glibc" && !glibc_asks_three(&report) {
            common::capability_gap(
                "fortify bar under a glibc reading",
                &format!(
                    "this host's glibc reads {}, where the library asks 2",
                    report["environment"]["libc"]["version"]
                ),
            );
            continue;
        }
        assert_eq!(
            report["toolchain"]["target_triple"].as_str(),
            Some(row.triple.as_str()),
            "{name}"
        );
        let fortify = report["observations"]
            .as_array()
            .and_then(|o| o.iter().find(|o| o["check"] == "fortify-effective"))
            .cloned()
            .unwrap_or(Value::Null);
        let in_force = matches!(fortify["verdict"].as_str(), Some("on" | "partial"));
        if !(in_force && fortify["level"] == "2") {
            common::capability_gap(
                "fortify bar under a musl reading",
                &format!(
                    "this host's cc measured fortify-effective {} at level {} under -O2 \
                     -D_FORTIFY_SOURCE=2, not level 2 in force",
                    fortify["verdict"], fortify["level"]
                ),
            );
            return;
        }
        let slot = fhardened_fortify_slot(&report);
        assert_eq!(
            slot["state"], row.want,
            "{name} under {}: {slot}",
            row.triple
        );
        assert!(
            slot["note"].as_str().is_some_and(|n| n.contains(row.note)),
            "{name}: the note names the reading: {slot}"
        );
        examined = examined.saturating_add(1);
    }
    assert!(
        examined >= 3,
        "the three musl rows run on any Linux host with gcc, examined {examined}"
    );
}

/// A wrapper's answer to the `-fhardened -O2 -dM -E` dump: refusing the token, as clang does.
const FHARDENED_REFUSED: &str =
    r#"echo "fakecc: error: unrecognized command-line option '-fhardened'" >&2; exit 1"#;
/// A wrapper's answer to the with-headers dump: musl's, the glibc macros dropped and one of
/// musl's own `__NEED_` guards added.
const MUSL_HEADERS: &str = r#""$REAL" "$@" | sed -e '/__GLIBC/d' -e '/__GNU_LIBRARY__/d' -e '1i\
#define __NEED_size_t'
    exit 0"#;
/// A wrapper's answer to the with-headers dump: the host's own.
const OWN_HEADERS: &str = r#"exec "$REAL" "$@""#;
/// A wrapper's answer to the control dump: the host's own, with any level the host's driver
/// defines under `-O2` alone taken out (Ubuntu's and Alpine's do), so a row's control is the
/// row's own.
const OWN_DUMP: &str = r#""$REAL" "$@" | sed -e '/_FORTIFY_SOURCE/d'; exit 0"#;

/// A wrapper's answer to the `-fhardened` dump that took the option and defined `level`, from
/// a dump the host's driver takes without `-fhardened`, so the row does not depend on it.
fn fhardened_defines(level: &str) -> String {
    format!(
        r#"{{ "$REAL" -O2 -dM -E -x c /dev/null | sed -e '/_FORTIFY_SOURCE/d'; echo '#define _FORTIFY_SOURCE {level}'; }}; exit 0"#
    )
}

/// One shape of [`the_fortify_bar_reads_the_driver_s_own_dump_and_else_the_headers_library`].
struct BarRow {
    name: &'static str,
    triple: String,
    fhardened: String,
    /// The answer to the control dump, `-O2` without `-fhardened`.
    baseline: String,
    headers: &'static str,
    /// The C library the report must read.
    libc: &'static str,
    /// The fortify slot's state under a level-2 build.
    want: &'static str,
    /// What the slot's note names: every reading names its bar's source.
    note: &'static str,
}

/// The seven shapes, on the host's architecture and its own triple.
fn bar_rows(arch: &str, native: &str) -> [BarRow; 7] {
    let musl = format!("{arch}-pc-linux-musl");
    [
        BarRow {
            name: "fakecc-musl-native",
            triple: musl.clone(),
            fhardened: FHARDENED_REFUSED.to_owned(),
            baseline: OWN_DUMP.to_owned(),
            headers: MUSL_HEADERS,
            libc: "musl",
            want: "in-force",
            note: "in force: level >= 2 on musl",
        },
        BarRow {
            name: "fakecc-musl-gcc",
            triple: format!("{arch}-redhat-linux"),
            fhardened: FHARDENED_REFUSED.to_owned(),
            baseline: OWN_DUMP.to_owned(),
            headers: MUSL_HEADERS,
            libc: "musl",
            want: "not-established",
            note: "unrecognized command-line option",
        },
        BarRow {
            name: "fakecc-glibc-configured-old",
            triple: native.to_owned(),
            fhardened: fhardened_defines("2"),
            baseline: OWN_DUMP.to_owned(),
            headers: OWN_HEADERS,
            libc: "glibc",
            want: "in-force",
            note: "in force: level >= 2 by the driver's -fhardened -O2 dump",
        },
        BarRow {
            name: "fakecc-glibc-yielded",
            triple: native.to_owned(),
            fhardened: format!(
                r#"echo "cc1: warning: '_FORTIFY_SOURCE' is not enabled by '-fhardened' because it was specified in '-D' or '-U' [-Whardened]" >&2; {}"#,
                fhardened_defines("2")
            ),
            baseline: OWN_DUMP.to_owned(),
            headers: OWN_HEADERS,
            libc: "glibc",
            want: "absent",
            note: "the library sets the bar because the driver's -fhardened -O2 dump said",
        },
        BarRow {
            name: "fakecc-glibc-silenced",
            triple: native.to_owned(),
            fhardened: fhardened_defines("2"),
            // A specs `-D_FORTIFY_SOURCE=2` under `-w`: both dumps define 2, no warning.
            baseline: fhardened_defines("2"),
            headers: OWN_HEADERS,
            libc: "glibc",
            want: "absent",
            note: "defines _FORTIFY_SOURCE 2 as well",
        },
        BarRow {
            name: "fakecc-musl-raises-to-three",
            triple: musl.clone(),
            fhardened: fhardened_defines("3"),
            // A default of 2 that the option raises: the option's level is its own.
            baseline: fhardened_defines("2"),
            headers: MUSL_HEADERS,
            libc: "musl",
            want: "absent",
            note: "needs level >= 3 by the driver's -fhardened -O2 dump",
        },
        BarRow {
            name: "fakecc-musl-asks-three",
            triple: musl,
            fhardened: fhardened_defines("3"),
            baseline: OWN_DUMP.to_owned(),
            headers: MUSL_HEADERS,
            libc: "musl",
            want: "absent",
            note: "needs level >= 3 by the driver's -fhardened -O2 dump",
        },
    ]
}

/// Does the report's glibc ask level 3 of `-fhardened` (2.35 or later)?
fn glibc_asks_three(report: &Value) -> bool {
    let version = report["environment"]["libc"]["version"]
        .as_str()
        .unwrap_or_default();
    version.starts_with("2.")
        && version
            .split('.')
            .nth(1)
            .and_then(|m| m.parse::<u32>().ok())
            .is_some_and(|m| m >= 35)
}

/// `fhardened-effective`'s fortify slot, or null.
fn fhardened_fortify_slot(report: &Value) -> Value {
    report["composites"]
        .as_array()
        .and_then(|c| c.iter().find(|c| c["id"] == "fhardened-effective"))
        .and_then(|c| c["constituents"].as_array())
        .and_then(|k| k.iter().find(|k| k["check"] == "fortify-effective"))
        .cloned()
        .unwrap_or(Value::Null)
}

#[test]
fn a_link_that_clears_a_marking_the_object_carries_is_read_from_the_object() {
    if !can_run("that a link clearing a marking is read from the unlinked object") {
        return;
    }
    let machine = Command::new(real_cc())
        .arg("-dumpmachine")
        .output()
        .expect("cc -dumpmachine");
    let triple = String::from_utf8_lossy(&machine.stdout).trim().to_owned();
    let (off, check) = if triple.starts_with("x86_64") || triple.starts_with("amd64") {
        ("-fcf-protection=none", "cet-marked")
    } else if triple.starts_with("aarch64") {
        ("-mbranch-protection=none", "branch-protection-marked")
    } else {
        common::capability_gap(
            "a link clearing a marking",
            "the host compiler targets neither x86_64 nor aarch64, whose markings a link ANDs",
        );
        return;
    };
    let work = common::Work::new("fakedriver", "link-drop");
    let source = work.write(
        "unmarked.c",
        "int chard_unmarked_input(void) { return 0; }\n",
    );
    let object = work.path("unmarked.o");
    let built = Command::new(real_cc())
        .args([off, "-c", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .expect("compiling the unmarked input");
    assert!(built.success(), "the unmarked input did not compile");
    let driver = fake_driver(
        work.dir(),
        &format!(
            r#"link=1; src=0
for a in "$@"; do case "$a" in -c|-E|-S|-M|-MM|-###) link=0 ;; *.c) src=1 ;; esac; done
if [ $link = 1 ] && [ $src = 1 ]; then exec "$REAL" "$@" '{}'; fi
exec "$REAL" "$@""#,
            object.display()
        ),
    );
    let report = measure_probes(&driver, work.dir(), &["link-defaults"]);
    let o = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .find(|o| o["check"] == check)
        .expect("the probe observes the marking");
    assert_eq!(
        o["gating"]["rule"].as_str(),
        Some("link-drops-marking"),
        "{o:#}"
    );
    assert!(
        o["gating"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("while the same arm compiled and not linked does")),
        "{o:#}"
    );
}

#[test]
fn the_link_input_rule_compares_only_for_a_check_reading_the_profile_s_build() {
    if !can_run("that the link-input rule compares only where a check reads the profile") {
        return;
    }
    let work = common::Work::new("fakedriver", "pg-inputs");
    let report = measure_probes_under(
        &PathBuf::from(real_cc()),
        work.dir(),
        &["--profile", "explicit", "--flags", "-pg"],
        &["link-defaults", "linker-default-execstack"],
    );
    let rule = |id: &str| {
        report["observations"]
            .as_array()
            .expect("observations")
            .iter()
            .find(|o| o["check"] == id)
            .and_then(|o| o["gating"]["rule"].as_str())
            .map(ToOwned::to_owned)
    };
    if rule("noexecstack").as_deref() != Some("link-inputs-unmatched-by-arms") {
        common::capability_gap(
            "a profile moving the startup objects",
            "-pg links the same startup objects as the arms here, so the comparison finds \
             nothing to withhold either check over",
        );
    }
    assert_ne!(
        rule("linker-default-noexecstack").as_deref(),
        Some("link-inputs-unmatched-by-arms")
    );
}

/// A wrapper with a two-token option of its own, `--chard-test-pair VALUE`, which it drops
/// with its value before handing the rest to the host's `cc`: an option no reader of chard's
/// knows, so chard reads its value as a word of the profile's own.
fn pair_driver(work: &Path) -> PathBuf {
    fake_driver(
        work,
        r#"skip=0
for a in "$@"; do shift
if [ $skip = 1 ]; then skip=0; continue; fi
case "$a" in --chard-test-pair) skip=1 ;; *) set -- "$@" "$a" ;; esac
done
exec "$REAL" "$@""#,
    )
}

/// An `ld` in `dir` that runs the host's `ld` and logs each command line to `log`; with
/// `force`, it links every program for which the line asks no stack mode with an executable
/// stack, so a link through it that reads a non-executable stack did not go through it.
/// The mode is read from whole words, since the probe's output names carry `execstack`.
fn prefix_ld(dir: &Path, log: &Path, force: bool) {
    let output = Command::new("sh")
        .args(["-c", "command -v ld"])
        .output()
        .expect("sh is available");
    let real = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(
        output.status.success() && !real.is_empty(),
        "a host that links has an `ld` on PATH"
    );
    std::fs::create_dir_all(dir).expect("creating the prefix directory");
    let forced = if force { "-z execstack " } else { "" };
    common::executable(
        &dir.join("ld"),
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nfor a in \"$@\"; do case \"$a\" in \
             execstack|noexecstack) exec '{real}' \"$@\" ;; esac; done\nexec '{real}' {forced}\"$@\"",
            log.display()
        ),
    );
}

/// `o` was withheld under `clean-link-unmatched-by-measured` by a difference the driver's
/// answers showed, not by an answer it could not give, and the reason names `dir` on the
/// clean build's side; the arms discriminated, so the rule and not the triple withheld.
fn assert_clean_link_differed(o: &Value, dir: &Path) {
    assert_eq!(o["verdict"], "indeterminate", "{o:#}");
    assert_eq!(
        o["gating"]["rule"].as_str(),
        Some("clean-link-unmatched-by-measured"),
        "{o:#}"
    );
    let reason = o["gating"]["reason"].as_str().expect("a gating's reason");
    let named = format!("where the clean build's include {}", dir.display());
    assert!(
        reason.contains(") differ: ")
            && reason.contains(&named)
            && !reason.contains("did not answer")
            && !reason.contains(" on -print-search-dirs ")
            && !reason.contains("-### listing"),
        "the reason names a difference on the clean build's side: {reason}"
    );
    assert_eq!(
        o["controls"]["discriminating"].as_bool(),
        Some(true),
        "{o:#}"
    );
}

/// The observation of `linker-default-noexecstack` in a run of its probe alone, or `None`
/// where the probe is gated off this target (it builds on x86 alone), after announcing the
/// gap.
fn default_execstack_observation(report: &Value, verifies: &str) -> Option<Value> {
    if !targets_x86_64(report) {
        common::capability_gap(verifies, "linker-default-execstack builds on x86_64 alone");
        return None;
    }
    Some(observation(report, "linker-default-noexecstack").clone())
}

#[test]
fn a_clean_build_linking_through_a_prefix_the_measured_build_never_chose_is_withheld() {
    let verifies = "that a clean build linking through another prefix is withheld";
    if !can_run(verifies) {
        return;
    }
    let work = common::Work::new("fakedriver", "clean-link-pair");
    let driver = pair_driver(work.dir());
    let prefix = work.path("px");
    let log = work.path("ld.log");
    prefix_ld(&prefix, &log, true);
    let flags = format!("-O2 --chard-test-pair -B{}/", prefix.display());
    let report = measure_probes_under(
        &driver,
        &work.path("w"),
        &["--profile", "explicit", "--flags", &flags],
        &["linker-default-execstack"],
    );
    let Some(o) = default_execstack_observation(&report, verifies) else {
        return;
    };
    assert_eq!(o["verdict"], "indeterminate", "{o:#}");
    assert_eq!(
        o["gating"]["rule"].as_str(),
        Some("clean-link-unmatched-by-measured"),
        "{o:#}"
    );
    assert_clean_link_differed(&o, &prefix);
    let ran = std::fs::read_to_string(&log).expect("the planted ld ran and logged");
    assert!(
        ran.lines()
            .any(|l| l.contains("linker-default-execstack-clean")),
        "the clean build linked through the planted ld:\n{ran}"
    );
}

#[test]
fn a_clean_build_linking_as_the_measured_build_does_reads_its_default() {
    let verifies = "that a clean build linking as the measured build does reads its default";
    if !can_run(verifies) {
        return;
    }
    for (force, expected) in [(false, "on"), (true, "off")] {
        let work = common::Work::new("fakedriver", &format!("clean-link-agree-{force}"));
        let driver = pair_driver(work.dir());
        let prefix = work.path("px");
        let log = work.path("ld.log");
        prefix_ld(&prefix, &log, force);
        let flags = format!("-O2 -B{}/", prefix.display());
        let report = measure_probes_under(
            &driver,
            &work.path("w"),
            &["--profile", "explicit", "--flags", &flags],
            &["linker-default-execstack"],
        );
        let Some(o) = default_execstack_observation(&report, verifies) else {
            return;
        };
        assert_eq!(o["verdict"], expected, "force {force}: {o:#}");
        assert!(o["gating"].is_null(), "force {force}: {o:#}");
        assert_eq!(
            o["controls"]["discriminating"].as_bool(),
            Some(true),
            "force {force}: {o:#}"
        );
        let ran = std::fs::read_to_string(&log).expect("the planted ld ran and logged");
        assert!(
            ran.lines()
                .any(|l| l.contains("linker-default-execstack-clean")),
            "force {force}: the clean build linked through the prefix's ld:\n{ran}"
        );
    }
}

#[test]
fn a_clean_build_searching_a_library_directory_the_measured_build_never_chose_is_withheld() {
    let verifies = "that a clean build searching another library directory is withheld";
    if !can_run(verifies) {
        return;
    }
    let work = common::Work::new("fakedriver", "clean-link-libdir");
    let dir = work.path("lx");
    std::fs::create_dir_all(&dir).expect("creating the library directory");
    let found = Command::new(real_cc())
        .arg("-print-file-name=libc.so")
        .output()
        .expect("running the host's cc");
    let script = std::fs::read_to_string(String::from_utf8_lossy(&found.stdout).trim());
    let Some(group) = script
        .as_deref()
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("GROUP (")))
        .and_then(|l| l.trim_end().strip_suffix(')'))
    else {
        common::capability_gap(verifies, "the host's libc.so is not a GROUP linker script");
        return;
    };
    let source = work.write(
        "x.s",
        ".section .note.GNU-stack,\"x\",@progbits\n.globl chard_exec_marker\nchard_exec_marker: ret\n",
    );
    let object = dir.join("x.o");
    let built = Command::new(real_cc())
        .args(["-c", "-o"])
        .arg(&object)
        .arg(&source)
        .status()
        .expect("assembling the marked object");
    assert!(built.success(), "the marked object did not assemble");
    std::fs::write(
        dir.join("libc.so"),
        format!("{group} {} )\n", object.display()),
    )
    .expect("writing the script");
    let driver = pair_driver(work.dir());
    let flags = format!("-O2 --chard-test-pair -L{}", dir.display());
    let report = measure_probes_under(
        &driver,
        &work.path("w"),
        &["--profile", "explicit", "--flags", &flags],
        &["linker-default-execstack"],
    );
    let Some(o) = default_execstack_observation(&report, verifies) else {
        return;
    };
    assert_clean_link_differed(&o, &dir);
    assert!(
        o["gating"]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("library directories include none")),
        "{o:#}"
    );
}

#[test]
fn a_search_dirs_answer_the_driver_cannot_give_withholds_the_clean_build() {
    let verifies = "that an unreadable search-dirs answer withholds the clean build's reading";
    if !can_run(verifies) {
        return;
    }
    // Each answer, and the side whose answer it is: the clean build's flags here are the
    // prefix alone, so `-O2` on a command line marks the measured build's.
    let refused = "echo 'cc: error: refused' >&2; exit 1";
    let measured = "for the measured build, ";
    let clean = "for the clean build, ";
    let lacks = "lacks its programs: or its libraries: list";
    for (name, answer, _, _) in [
        ("empty", "exit 0".to_owned(), measured, lacks),
        (
            "one-list",
            "echo 'programs: =/usr/bin'; exit 0".to_owned(),
            measured,
            lacks,
        ),
        (
            "refused",
            refused.to_owned(),
            measured,
            "exited 1 on -print-search-dirs",
        ),
        (
            "clean-refused",
            format!("[ $o2 = 1 ] || {{ {refused}; }}"),
            clean,
            "exited 1 on -print-search-dirs",
        ),
    ] {
        let work = common::Work::new("fakedriver", &format!("clean-link-{name}"));
        let driver = fake_driver(
            work.dir(),
            &format!(
                "o2=0; for a in \"$@\"; do [ \"$a\" = -O2 ] && o2=1; done\n\
                 for a in \"$@\"; do case \"$a\" in -print-search-dirs) {answer} ;; esac; done\n\
                 exec \"$REAL\" \"$@\""
            ),
        );
        let prefix = work.path("px");
        prefix_ld(&prefix, &work.path("ld.log"), false);
        let flags = format!("-O2 -B{}/", prefix.display());
        let report = measure_probes_under(
            &driver,
            &work.path("w"),
            &["--profile", "explicit", "--flags", &flags],
            &["linker-default-execstack"],
        );
        let Some(o) = default_execstack_observation(&report, verifies) else {
            return;
        };
        assert_eq!(o["verdict"], "indeterminate", "{name}: {o:#}");
        assert_eq!(
            o["gating"]["rule"].as_str(),
            Some("clean-link-unmatched-by-measured"),
            "{name}: {o:#}"
        );
        assert!(o["gating"]["reason"].is_string(), "a gating's reason");
    }
}

#[test]
fn a_linker_the_profile_selects_reaches_both_compared_lines() {
    let verifies = "that a profile's --ld-path agrees in the clean-link comparison";
    if !can_run(verifies) {
        return;
    }
    let found = Command::new("sh")
        .args(["-c", "command -v clang"])
        .output()
        .expect("sh is available");
    let clang = String::from_utf8_lossy(&found.stdout).trim().to_owned();
    if !found.status.success() || clang.is_empty() {
        common::capability_gap(verifies, "no clang on PATH to take --ld-path=");
        return;
    }
    let work = common::Work::new("fakedriver", "clean-link-ld-path");
    let driver = fake_driver_named(work.dir(), "fake-clang", &clang, "exec \"$REAL\" \"$@\"");
    let dir = work.path("pt");
    let log = work.path("ld.log");
    prefix_ld(&dir, &log, false);
    let flags = format!("-O2 --ld-path={}/ld", dir.display());
    let report = measure_probes_under(
        &driver,
        &work.path("w"),
        &["--profile", "explicit", "--flags", &flags],
        &["linker-default-execstack"],
    );
    let Some(o) = default_execstack_observation(&report, verifies) else {
        return;
    };
    assert_eq!(o["verdict"], "on", "{o:#}");
    assert!(o["gating"].is_null(), "{o:#}");
    let ran = std::fs::read_to_string(&log).expect("the selected ld ran and logged");
    assert!(
        ran.lines()
            .any(|l| l.contains("linker-default-noexecstack-pos")),
        "the arms linked through the selected ld:\n{ran}"
    );
}

#[test]
fn a_measure_names_its_mode_and_only_the_diagnostics_it_earned() {
    if !can_run("that a measure names its mode and only the diagnostics it earned") {
        return;
    }
    let driver = PathBuf::from(real_cc());
    for mode in ["container", "vm"] {
        let work = common::Work::new("fakedriver", &format!("mode-{mode}"));
        let report = measure_probes_under(
            &driver,
            work.dir(),
            &["--profile", "bare", "--execution", mode],
            &["link-defaults"],
        );
        assert_eq!(report["environment"]["execution"]["mode"], mode);
        let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
        for d in diagnostics {
            let message = d["message"].as_str().expect("a diagnostic's message");
            assert_ne!(d["severity"], "error", "{mode}: {d}");
            assert!(
                !message.starts_with("--structured-diagnostics")
                    && !message.contains("non-discriminating controls"),
                "{mode}: {d}"
            );
        }
    }
}

#[test]
fn a_probe_invalid_cell_is_counted_in_a_warning() {
    if !can_run("that a probe-invalid cell is counted in a warning") {
        return;
    }
    let work = common::Work::new("fakedriver", "probe-invalid-count");
    let driver = fake_driver(
        work.dir(),
        r#"for a in "$@"; do shift; case "$a" in -fstack-protector*) ;; *) set -- "$@" "$a" ;; esac; done
exec "$REAL" "$@""#,
    );
    let report = measure_probes(&driver, work.dir(), &["toolchain-macros"]);
    let invalid = report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o["verdict"] == "probe-invalid")
        .count();
    assert!(invalid > 0, "the dropped flag left every triple standing");
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["message"]
                .as_str()
                .is_some_and(|m| m.starts_with(&format!(
                    "{invalid} check(s) had non-discriminating controls"
                )))),
        "{}",
        report["diagnostics"]
    );
}

#[test]
fn a_linker_known_from_its_artifacts_alone_is_named_in_a_warning() {
    if !can_run("that a linker known from its artifacts alone is named in a warning") {
        return;
    }
    if !(common::ELF_HOST && on_path("objcopy") && on_path("ld")) {
        common::capability_gap(
            "a linker known from its artifacts alone",
            "the host has no ELF ld and objcopy to sign an output with",
        );
        return;
    }
    let ld = Command::new("sh")
        .args(["-c", "command -v ld"])
        .output()
        .expect("sh is available");
    let ld = String::from_utf8_lossy(&ld.stdout).trim().to_owned();
    let work = common::Work::new("fakedriver", "artifact-only");
    let shims = work.path("shims");
    std::fs::create_dir_all(&shims).expect("the shim directory");
    let shim = common::executable(
        &shims.join("ld"),
        &format!(
            r#"case "$1" in --version) echo 'MysteryLinker 1.0'; exit 0 ;; esac
out=a.out; prev=
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
'{ld}' "$@" || exit $?
printf 'GCC: (GNU) 16\0Linker: LLD 22.1.8\0' > "$out.comment"
objcopy --update-section .comment="$out.comment" "$out" 2>/dev/null \
  || objcopy --add-section .comment="$out.comment" "$out" || exit 1
rm -f "$out.comment""#
        ),
    );
    let driver = fake_driver(
        work.dir(),
        &format!(
            r#"case " $* " in
  *" -print-prog-name=ld "*) echo '{shim}'; exit 0 ;;
  *" -### "*) echo ' "{shim}" "-o" "/dev/null"' >&2; exit 0 ;;
esac
exec "$REAL" -B'{dir}/' "$@""#,
            shim = shim.display(),
            dir = shims.display()
        ),
    );
    let report = measure_probes(&driver, work.dir(), &["link-defaults"]);
    let linker = &report["toolchain"]["linker"];
    assert_eq!(
        linker["artifact"]["agreement"], "artifact-only",
        "{linker:#}"
    );
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .any(|d| d["severity"] == "warning"
                && d["message"].as_str().is_some_and(|m| m.starts_with(
                    "the linker under toolchain.linker is known from its artifacts alone"
                ))),
        "{}",
        report["diagnostics"]
    );
}

/// A wrapper that adds `extra` to the build whose `-o` name ends in one of `suffixes`, as a
/// toolchain recognising which build it is compiling would, and passes every other build
/// to `cc` with `otherwise` ahead of its arguments. The matched build's extra words go
/// ahead of the arguments too, so a control arm's own flag, later on the line, still wins.
fn recognising_driver(work: &Path, suffixes: &[&str], extra: &str, otherwise: &str) -> PathBuf {
    let cases = suffixes
        .iter()
        .map(|s| format!("*{s}"))
        .collect::<Vec<_>>()
        .join("|");
    fake_driver(
        work,
        &format!(
            r#"out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
case "$out" in
  {cases}) exec "$REAL" {extra} "$@" ;;
  *) exec "$REAL" {otherwise} "$@" ;;
esac"#
        ),
    )
}

/// The cell `check` in `report`, and the id of the rule that withheld it, if one did.
fn cell_and_rule<'r>(report: &'r Value, check: &str) -> (&'r Value, Option<&'r str>) {
    let cell = observation(report, check);
    (cell, cell["gating"]["rule"].as_str())
}

/// The CET probes of the forged-macro shapes: the macro check's probe and the three whose
/// artifact readings are its twins.
const CET_PROBES: [&str; 8] = [
    "--probe",
    "toolchain-macros",
    "--probe",
    "link-defaults",
    "--probe",
    "cet-endbr",
    "--probe",
    "cet-object",
];

/// `cet-macro` in `report` is withheld under `macro-contradicted-by-artifact` with the
/// reason naming the three artifact readings, which keep their `off`; the report is
/// consistent, carries the warning, and its `cet` group is uncorroborated rather than
/// disagreeing. `false` off x86_64, where `cet-macro` is gated at applicability and that is
/// what is asserted.
fn assert_cet_macro_withheld_by_its_artifacts(tag: &str, report: &Value) -> bool {
    assert_schema_valid(tag, report);
    let (cet, rule) = cell_and_rule(report, "cet-macro");
    if !targets_x86_64(report) {
        assert!(
            matches!(
                rule,
                Some("arch-gated" | "no-check-on-target" | "arch-outside-table")
            ),
            "{tag}: off x86_64 cet-macro is gated at applicability: {cet}"
        );
        eprintln!("{tag}: not x86_64, cet-macro gated under {rule:?}; nothing more to assert");
        return false;
    }
    assert_eq!(cet["verdict"], "indeterminate", "{tag}: {cet}");
    assert_eq!(rule, Some("macro-contradicted-by-artifact"), "{tag}: {cet}");
    assert!(
        cet["level"].is_null(),
        "{tag}: a withheld reading carries no level"
    );
    let reason = cet["gating"]["reason"].as_str().expect("a reason");
    for needle in [
        "`cet-macro` read `on` at `full` on the macro channel",
        "`cet-marked` reads `off` on the elf-static channel",
        "`cet-endbr-emitted` reads `off` on the elf-static channel",
        "`cet-marked-object` reads `off` on the elf-static channel",
    ] {
        assert!(reason.contains(needle), "{tag}: {needle}: {reason}");
    }
    assert_eq!(
        cet["controls"]["discriminating"], true,
        "{tag}: the arms discriminated; the rule read the verdict, not the triple"
    );
    for twin in ["cet-marked", "cet-endbr-emitted", "cet-marked-object"] {
        let (t, rule) = cell_and_rule(report, twin);
        assert_eq!(t["verdict"], "off", "{tag}: {twin} keeps its reading: {t}");
        assert_eq!(rule, None, "{tag}: {twin}");
    }
    assert_eq!(
        report["consistency"]["status"], "consistent",
        "{tag}: {}",
        report["consistency"]
    );
    let warned = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .any(|d| {
            d["context"] == "cet-macro"
                && d["severity"] == "warning"
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("`cet-marked` reads `off`"))
        });
    assert!(
        warned,
        "{tag}: no warning in cet-macro's context: {}",
        report["diagnostics"]
    );
    let note = report["corroboration"]["cet"]["note"]
        .as_str()
        .expect("the cet group has a note");
    assert!(
        note.starts_with("CONTRADICTED: `cet-macro`") && !note.contains("not a disagreement"),
        "{tag}: {note}"
    );
    assert_eq!(
        report["corroboration"]["cet"]["withheld"]["cet-macro"],
        "indeterminate"
    );
    true
}

#[test]
fn a_driver_that_forges_a_cet_macro_into_the_measured_build_is_withheld_by_its_artifacts() {
    if !can_run("that a macro reading the artifact contradicts is withheld") {
        return;
    }
    let work = common::Work::new("fakedriver", "forged-cet");
    let gate = work.path("gate.h");
    std::fs::write(&gate, "#ifdef GATE\n#define __CET__ 3\n#endif\n").expect("writing gate.h");
    let forged = [
        ("define", "-D__CET__=3".to_owned()),
        ("gate", format!("-DGATE -include {}", gate.display())),
    ];
    let mut held = 0;
    for (tag, extra) in &forged {
        let dir = work.path(tag);
        std::fs::create_dir_all(&dir).expect("a workdir per shape");
        let driver = recognising_driver(&dir, &["-measured"], extra, "");
        let mut args = vec![
            "--profile",
            "explicit",
            "--flags",
            "-O2 -fcf-protection=none",
        ];
        args.extend(CET_PROBES);
        let report = measure(&driver, &dir, &args);
        if assert_cet_macro_withheld_by_its_artifacts(tag, &report) {
            held += 1;
        }
    }
    if held == 0 {
        common::capability_gap(
            "forged __CET__",
            "the target is not x86_64, so cet-macro is gated before the twin rule can read it",
        );
        return;
    }
    assert_eq!(
        held,
        forged.len(),
        "every shape is held on an x86_64 target"
    );
}

#[test]
fn a_profiles_own_include_keyed_on_its_own_macro_cannot_forge_a_cet_macro() {
    if !can_run(
        "that a forced include keyed on a profile-only macro cannot forge the macro channel",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "own-include-gate");
    let gate = work.write("gate.h", "#ifdef GATE\n#define __CET__ 3\n#endif\n");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let flags = format!(
        "-O2 -fcf-protection=none -DGATE -include {}",
        gate.display()
    );
    let mut args = vec!["--profile", "explicit", "--flags", flags.as_str()];
    args.extend(CET_PROBES);
    let report = measure(&driver, work.dir(), &args);
    for o in report["observations"].as_array().expect("observations") {
        assert_ne!(
            o["gating"]["rule"].as_str(),
            Some("compile-inputs-unmatched-by-arms"),
            "{} was withheld where every arm carries the include: {o}",
            o["check"]
        );
    }
    if !assert_cet_macro_withheld_by_its_artifacts("own -include gate", &report) {
        common::capability_gap(
            "forged __CET__ through the profile's own include",
            "the target is not x86_64, so cet-macro is gated before the twin rule can read it",
        );
        return;
    }
    let (cet, _) = cell_and_rule(&report, "cet-macro");
    assert_eq!(
        cet["evidence"]["macros"]["__CET__"].as_str(),
        Some("3"),
        "the measured build's own self-report carried the forged macro: {cet}"
    );
    let include = ["-include".to_owned(), gate.display().to_string()];
    for which in ["positive", "negative"] {
        let arm: Vec<&str> = cet["controls"][which]["flags"]
            .as_array()
            .unwrap_or_else(|| panic!("cet-macro publishes no {which} arm flags"))
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            arm.windows(2).any(|w| w == include),
            "the {which} arm carries the include: {arm:?}"
        );
        assert!(
            !arm.contains(&"-DGATE"),
            "the {which} arm carries none of the profile's macro words: {arm:?}"
        );
    }
}

#[test]
fn a_profile_defining_a_cet_macro_is_still_the_spoof_rules() {
    if !can_run("that the profile's own -D stays under the spoof rule") {
        return;
    }
    let work = common::Work::new("fakedriver", "profile-cet");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let mut args = vec![
        "--profile",
        "explicit",
        "--flags",
        "-O2 -fcf-protection=none -D__CET__=3",
    ];
    args.extend(CET_PROBES);
    let report = measure(&driver, work.dir(), &args);
    assert_schema_valid("profile -D__CET__", &report);
    let (cet, rule) = cell_and_rule(&report, "cet-macro");
    if targets_x86_64(&report) {
        assert_eq!(cet["verdict"], "indeterminate", "{cet}");
        assert_eq!(rule, Some("macro-supplied-by-profile"), "{cet}");
    }
    assert_eq!(report["consistency"]["status"], "consistent");
}

#[test]
fn a_driver_that_hardens_only_the_builds_it_recognises_has_its_macro_reading_withheld() {
    if !can_run("that a wrapper recognising the measured build cannot forge the macro channel") {
        return;
    }
    let work = common::Work::new("fakedriver", "recognising-wrapper");
    let driver = recognising_driver(
        work.dir(),
        &["-clean", "-measured"],
        "-fstack-protector-strong",
        "-fno-stack-protector",
    );
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "bare",
            "--probe",
            "toolchain-macros",
            "--probe",
            "ssp-function-map",
            "--probe",
            "stack-canary",
        ],
    );
    assert_schema_valid("recognising wrapper", &report);
    let (emitted, _) = cell_and_rule(&report, "ssp-level-emitted");
    let (canary, _) = cell_and_rule(&report, "canary-emitted");
    assert_eq!(
        emitted["verdict"], "off",
        "the function map is read from an object the wrapper left alone: {emitted}"
    );
    assert_eq!(
        canary["verdict"], "on",
        "the canary is read from an executable the wrapper hardened: {canary}"
    );
    let (ssp, rule) = cell_and_rule(&report, "ssp-level");
    assert_eq!(ssp["verdict"], "indeterminate", "{ssp}");
    assert_eq!(rule, Some("macro-contradicted-by-artifact"), "{ssp}");
    let reason = ssp["gating"]["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("`ssp-level` read `on` at `strong` on the macro channel")
            && reason.contains("`ssp-level-emitted` reads `off` on the elf-static channel")
            && reason.contains("`canary-emitted` reads `on` on the elf-static channel, agreeing"),
        "{reason}"
    );
    let note = report["corroboration"]["stack-protector"]["note"]
        .as_str()
        .expect("the group has a note");
    assert!(
        note.starts_with("CONTRADICTED: `ssp-level`")
            && note.contains("the other members of this group disagree among themselves"),
        "{note}"
    );
    assert_eq!(report["consistency"]["status"], "consistent");
}

#[test]
fn a_driver_whose_headers_decline_fortification_names_the_headers_the_profile_selects() {
    if !can_run("that a declined fortify level names the headers the profile selects") {
        return;
    }
    let work = common::Work::new("fakedriver", "declining-headers");
    let shim = work.path("shim");
    std::fs::create_dir_all(&shim).expect("the shim directory");
    std::fs::write(
        shim.join("features.h"),
        "#include_next <features.h>\n#undef __USE_FORTIFY_LEVEL\n#define __USE_FORTIFY_LEVEL 0\n",
    )
    .expect("writing the shim");
    let driver = fake_driver(
        work.dir(),
        &format!(r#"exec "$REAL" -isystem "{}" "$@""#, shim.display()),
    );
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            "-O2 -D_FORTIFY_SOURCE=3",
            "--probe",
            "toolchain-macros",
            "--probe",
            "fortify-printf-flag",
        ],
    );
    if report["environment"]["libc"]["impl"] != "glibc" {
        common::capability_gap(
            "declining features.h",
            "the shim wraps glibc's features.h, and this host's C library is another",
        );
        return;
    }
    assert_schema_valid("declining headers", &report);
    for check in ["fortify-effective", "fortify-printf-flag"] {
        let (cell, rule) = cell_and_rule(&report, check);
        assert_eq!(cell["verdict"], "unsupported", "{check}: {cell}");
        assert_eq!(rule, Some("fortify-level-declined"), "{check}: {cell}");
        assert!(cell["gating"]["reason"].is_string(), "a reason");
    }
    let (requested, rule) = cell_and_rule(&report, "fortify-requested");
    assert_eq!(
        requested["verdict"], "on",
        "the request is read as made: {requested}"
    );
    assert_eq!(rule, None);
}

#[test]
fn a_profile_defining_a_macro_a_probe_branches_on_withholds_the_probes_checks_by_name() {
    if !can_run("that a probe steered by a profile's macro is withheld") {
        return;
    }
    let work = common::Work::new("fakedriver", "probe-branch");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            "-O0 -D__OPTIMIZE__=1",
            "--probe",
            "ub-signed-overflow",
            "--probe",
            "toolchain-macros",
        ],
    );
    assert_schema_valid("probe branch", &report);
    let (overflow, rule) = cell_and_rule(&report, "no-strict-overflow");
    assert_eq!(overflow["verdict"], "indeterminate", "{overflow}");
    assert_eq!(rule, Some("macro-supplied-by-profile"), "{overflow}");
    let reason = overflow["gating"]["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("`__OPTIMIZE__`") && reason.contains("`ub-signed-overflow`"),
        "{reason}"
    );
    let (opt, rule) = cell_and_rule(&report, "optimization-enabled");
    assert_eq!(opt["verdict"], "indeterminate", "{opt}");
    assert_eq!(rule, Some("macro-supplied-by-profile"), "{opt}");
    assert!(
        !opt["gating"]["reason"]
            .as_str()
            .expect("a reason")
            .contains("branches on it"),
        "the macro check keeps the spoof clause's own reason: {opt}"
    );
    assert_eq!(report["consistency"]["status"], "consistent");
}

/// The major version of the report's gcc, `None` where the compiler is not gcc or the version
/// does not parse.
fn gcc_major(report: &Value) -> Option<u32> {
    if report["toolchain"]["kind"] != "gcc" {
        return None;
    }
    report["toolchain"]["version"]
        .as_str()?
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// Measures `zero-init-padding` through `driver` with `profile` (the `--profile` words and any
/// `--flags`), and hands back its one observation, or `None` with the gap announced where the
/// host's compiler is not gcc 15 or later, the first gcc whose driver knows
/// `-fzero-init-padding-bits`. The gap is decided from the compiler's version alone, so on gcc
/// 15 or later any reading, `unsupported` included, reaches the caller's assertions.
fn zero_init_padding_cell(
    driver: &Path,
    work: &Path,
    profile: &[&str],
    arm: &str,
) -> Option<Value> {
    let mut args: Vec<&str> = profile.to_vec();
    args.extend(["--probe", "zero-init-padding"]);
    let report = measure(driver, work, &args);
    assert_eq!(report["consistency"]["status"], "consistent", "{profile:?}");
    if gcc_major(&report).is_none_or(|major| major < 15) {
        common::capability_gap(
            arm,
            "the host cc is not gcc 15 or later, the first whose driver knows \
             -fzero-init-padding-bits",
        );
        return None;
    }
    let cell = report["observations"][0].clone();
    assert_eq!(cell["check"], "zero-init-padding-bits", "{cell}");
    Some(cell)
}

/// A profile setting that zeroes the union's inactive bytes itself is withheld by the regime
/// arm, not read as the flag. The wrapper stands for such a setting: wherever the line carries
/// `-Og` it appends `-fzero-init-padding-bits=all`, after every flag chard gave, so the measured
/// build and the regime arm (the profile's flags with `-fzero-init-padding-bits=standard`) both
/// zero the union, while the profile-free controls, which carry no `-Og`, discriminate. The
/// verdict is asserted before the arm, so on a tree without the arm the failure shows the `on`
/// it published. Needs gcc 15 or later; elsewhere the gap is announced.
#[test]
fn a_profile_that_zeroes_the_union_is_withheld_as_regime_confounded() {
    if !can_run("that zero-init-padding-bits withholds a union the profile zeroes") {
        return;
    }
    let work = common::Work::new("fakedriver", "zipb-regime");
    let driver = fake_driver(
        work.dir(),
        r#"case " $* " in
  *" -Og "*) exec "$REAL" "$@" -fzero-init-padding-bits=all ;;
esac
exec "$REAL" "$@""#,
    );
    let Some(cell) = zero_init_padding_cell(
        &driver,
        work.dir(),
        &["--profile", "explicit", "--flags", "-Og"],
        "zero-init-padding-bits regime arm",
    ) else {
        return;
    };
    assert_eq!(cell["verdict"], "probe-invalid", "{cell}");
    assert_eq!(
        cell["controls"]["withheld_because"], "regime-confounded",
        "{cell}"
    );
    let arm = &cell["controls"]["regime_negative"];
    assert_eq!(
        arm["flags"],
        serde_json::json!(["-Og", "-fzero-init-padding-bits=standard"]),
        "the arm is the profile with the countermand last: {arm}"
    );
    assert_eq!(arm["outcome"], "present", "{cell}");
    assert_eq!(cell["controls"]["positive"]["outcome"], "present", "{cell}");
    assert_eq!(cell["controls"]["negative"]["outcome"], "absent", "{cell}");
}

#[test]
fn a_toolchain_that_zeroes_the_union_under_bare_is_withheld_by_the_negative_control() {
    if !can_run("that zero-init-padding-bits withholds a union a clean profile's toolchain zeroes")
    {
        return;
    }
    let work = common::Work::new("fakedriver", "zipb-clean");
    let driver = fake_driver(
        work.dir(),
        r#"case " $* " in *" -### "*) exec "$REAL" "$@" ;; esac
standard=
for a in "$@"; do
  case "$a" in -fzero-init-padding-bits=standard) standard=1 ;; esac
done
[ -n "$standard" ] || exec "$REAL" "$@" -fzero-init-padding-bits=all
n=$#
while [ "$n" -gt 0 ]; do
  a=$1; shift
  case "$a" in -fzero-init-padding-bits=standard) a=-fzero-init-padding-bits=all ;; esac
  set -- "$@" "$a"; n=$((n - 1))
done
exec "$REAL" "$@""#,
    );
    let Some(cell) = zero_init_padding_cell(
        &driver,
        work.dir(),
        &["--profile", "bare"],
        "zero-init-padding-bits negative control under a clean profile",
    ) else {
        return;
    };
    assert_eq!(cell["verdict"], "probe-invalid", "{cell}");
    assert_eq!(
        cell["controls"]["withheld_because"], "negative-also-shows",
        "{cell}"
    );
    for arm in ["positive", "negative"] {
        for key in ["overridden", "overridden_unread"] {
            assert!(cell["controls"][arm][key].is_null(), "{arm} {key}: {cell}");
        }
    }
    assert!(
        cell["controls"]["regime_negative"].is_null(),
        "a clean profile owes no arm: {cell}"
    );
    assert_eq!(cell["controls"]["negative"]["outcome"], "present", "{cell}");
}

#[test]
fn a_specs_file_that_appends_after_an_arm_is_named_on_the_withheld_triple() {
    if !can_run("that a withheld triple names the word a specs file put after its control's") {
        return;
    }
    let work = common::Work::new("fakedriver", "self-spec-appends");
    let spec = work.dir().join("append.spec");
    std::fs::write(&spec, "*self_spec:\n+ -fstack-protector-strong\n\n").expect("the specs file");
    let through_spec = format!(r#"exec "$REAL" -specs='{}' "$@""#, spec.display());
    let unlisted = format!(
        r#"case " $* " in
  *" -fno-stack-protector -### "*) echo "fakecc: error: no listing" >&2; exit 1 ;;
esac
{through_spec}"#
    );
    let appended_argv = r#"exec "$REAL" "$@" -fstack-protector-strong"#.to_owned();
    let args = ["--profile", "bare", "--probe", "stack-canary"];
    let run = |name: &str, driver: &Path| {
        let dir = work.dir().join(name);
        std::fs::create_dir_all(&dir).expect("a workdir for the run");
        let report = measure(driver, &dir, &args);
        assert_schema_valid(name, &report);
        report
    };

    let plain = run("plain", Path::new(&real_cc()));
    if plain["toolchain"]["kind"] != "gcc" {
        common::capability_gap(
            "a specs file appending after an arm",
            "the host's cc is not gcc, and a specs file is gcc's",
        );
        return;
    }
    let (cell, _) = cell_and_rule(&plain, "canary-emitted");
    assert_eq!(cell["controls"]["discriminating"], true, "{cell}");
    for arm in ["positive", "negative"] {
        for key in ["overridden", "overridden_unread"] {
            assert!(cell["controls"][arm][key].is_null(), "{cell}");
        }
    }

    let mut withheld = 0;
    let named =
        serde_json::json!({ "flag": "-fno-stack-protector", "by": "-fstack-protector-strong" });
    let overridden = "negative-overridden";
    let rows = [
        ("appended", &through_spec, overridden, named.clone(), None),
        (
            "unlisted",
            &unlisted,
            "negative-also-shows",
            Value::Null,
            Some("fakecc: error: no listing"),
        ),
        ("appended-argv", &appended_argv, overridden, named, None),
    ];
    for (name, script, cause, record, unread) in rows {
        let driver = fake_driver_named(work.dir(), name, &real_cc(), script);
        let report = run(&format!("{name}-run"), &driver);
        let (cell, rule) = cell_and_rule(&report, "canary-emitted");
        assert_eq!(rule, None, "{name}: no rule gates the cell: {cell}");
        assert_eq!(cell["verdict"], "probe-invalid", "{name}: {cell}");
        let controls = &cell["controls"];
        assert_eq!(controls["withheld_because"], cause, "{name}: {controls}");
        assert_eq!(
            controls["negative"]["overridden"], record,
            "{name}: {controls}"
        );
        let said = controls["negative"]["overridden_unread"].as_str();
        assert_eq!(said.is_some(), unread.is_some(), "{name}: {controls}");
        if let (Some(said), Some(quoted)) = (said, unread) {
            assert!(said.contains(quoted), "{name}: {controls}");
        }
        for key in ["overridden", "overridden_unread"] {
            assert!(controls["positive"][key].is_null(), "{name}: {controls}");
        }
        assert_eq!(
            controls["positive"]["outcome"], "present",
            "{name}: {controls}"
        );
        assert_eq!(
            controls["negative"]["outcome"], "present",
            "{name}: {controls}"
        );
        assert_eq!(
            controls["negative"]["flags"],
            serde_json::json!(["-fno-stack-protector"]),
            "{name}: {controls}"
        );
        withheld += 1;
    }
    assert_eq!(withheld, 3, "the three wrapped runs were read");
}

#[test]
fn a_specs_file_that_appends_after_a_positive_arm_is_named_on_that_arm() {
    if !can_run(
        "that a withheld triple names the word a specs file put after its positive control's",
    ) {
        return;
    }
    let work = common::Work::new("fakedriver", "self-spec-positive");
    let spec = work.dir().join("append.spec");
    std::fs::write(&spec, "*self_spec:\n+ -ftrivial-auto-var-init=zero\n\n")
        .expect("the specs file");
    let driver = fake_driver(
        work.dir(),
        &format!(r#"exec "$REAL" -specs='{}' "$@""#, spec.display()),
    );
    let report = measure(
        &driver,
        work.dir(),
        &["--profile", "bare", "--probe", "auto-var-init"],
    );
    assert_schema_valid("a specs file after a positive arm", &report);
    let (cell, _) = cell_and_rule(&report, "auto-var-init-pattern");
    // The gap is the host's, read off the compiler and not off the reading under test: a
    // gcc before 12 has no -ftrivial-auto-var-init.
    if gcc_major(&report).is_none_or(|major| major < 12) {
        common::capability_gap(
            "a specs file appending after a positive arm",
            "the host's cc is not a gcc that knows -ftrivial-auto-var-init (12 or later)",
        );
        return;
    }
    assert_eq!(cell["verdict"], "probe-invalid", "{cell}");
    let controls = &cell["controls"];
    assert_eq!(
        controls["withheld_because"], "positive-overridden",
        "{controls}"
    );
    assert_eq!(controls["positive"]["outcome"], "absent", "{controls}");
    assert_eq!(controls["negative"]["outcome"], "absent", "{controls}");
    assert_eq!(
        controls["positive"]["overridden"],
        serde_json::json!({
            "flag": "-ftrivial-auto-var-init=pattern",
            "by": "-ftrivial-auto-var-init=zero",
        }),
        "{controls}"
    );
    for key in ["overridden", "overridden_unread"] {
        assert!(controls["negative"][key].is_null(), "{controls}");
    }
    assert!(
        controls["positive"]["overridden_unread"].is_null(),
        "{controls}"
    );
}

#[test]
fn a_clang_wrapper_that_appends_is_named_by_what_cc1_resolved() {
    if !can_run("that a withheld triple names what clang's -cc1 resolved a control's flag to") {
        return;
    }
    let found = Command::new("sh")
        .args(["-c", "command -v clang"])
        .output()
        .expect("sh is available");
    let clang = String::from_utf8_lossy(&found.stdout).trim().to_owned();
    if !found.status.success() || clang.is_empty() {
        common::capability_gap("a clang wrapper that appends", "no clang on PATH");
        return;
    }
    let work = common::Work::new("fakedriver", "clang-appends");
    let args = [
        "--profile",
        "bare",
        "--probe",
        "stack-canary",
        "--probe",
        "auto-var-init",
    ];
    let run = |name: &str, script: &str| {
        let dir = work.dir().join(format!("{name}-run"));
        std::fs::create_dir_all(&dir).expect("a workdir for the run");
        let driver = fake_driver_named(work.dir(), name, &clang, script);
        let report = measure(&driver, &dir, &args);
        assert_schema_valid(name, &report);
        report
    };

    let plain = run("plain", r#"exec "$REAL" "$@""#);
    assert_eq!(
        plain["toolchain"]["kind"], "clang",
        "{}",
        plain["toolchain"]
    );
    let mut discriminated = 0;
    for check in ["canary-emitted", "auto-var-init-active"] {
        let (cell, _) = cell_and_rule(&plain, check);
        if cell["controls"]["discriminating"] != true {
            continue;
        }
        for arm in ["positive", "negative"] {
            for key in ["overridden", "overridden_unread"] {
                assert!(cell["controls"][arm][key].is_null(), "{check}: {cell}");
            }
        }
        discriminated += 1;
    }
    assert_eq!(
        discriminated, 2,
        "this clang's own controls discriminate both checks with no wrapper"
    );

    let appended = run(
        "appending",
        r#"exec "$REAL" "$@" -fstack-protector-strong -ftrivial-auto-var-init=zero"#,
    );
    let mut named = 0;
    for (check, arm, flag, by) in [
        (
            "canary-emitted",
            "negative",
            "-fno-stack-protector",
            "-stack-protector 2",
        ),
        (
            "auto-var-init-active",
            "negative",
            "-ftrivial-auto-var-init=uninitialized",
            "-ftrivial-auto-var-init=zero",
        ),
        (
            "auto-var-init-pattern",
            "positive",
            "-ftrivial-auto-var-init=pattern",
            "-ftrivial-auto-var-init=zero",
        ),
    ] {
        let (cell, _) = cell_and_rule(&appended, check);
        assert_eq!(cell["verdict"], "probe-invalid", "{check}: {cell}");
        let controls = &cell["controls"];
        assert_eq!(
            controls["withheld_because"],
            format!("{arm}-overridden"),
            "{check}: {controls}"
        );
        assert_eq!(
            controls[arm]["overridden"],
            serde_json::json!({ "flag": flag, "by": by }),
            "{check}: {controls}"
        );
        for other in ["positive", "negative"].into_iter().filter(|a| *a != arm) {
            assert!(
                controls[other]["overridden"].is_null(),
                "{check}: {controls}"
            );
        }
        named += 1;
    }
    assert_eq!(named, 3, "the three checks were read");
}

#[test]
fn optimized_gcc_builds_answer_by_the_flag() {
    if !can_run("that zero-init-padding-bits answers optimized gcc builds") {
        return;
    }
    let work = common::Work::new("fakedriver", "zipb-routes");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let ubsan = "-O2 -fsanitize=undefined -fsanitize-trap=undefined";
    let standard = "-fzero-init-padding-bits=standard";
    let routes = [
        (format!("-O0 {standard}"), "off"),
        (format!("-Og {standard}"), "off"),
        (format!("{ubsan} {standard}"), "off"),
        ("-O0 -fzero-init-padding-bits=all".to_owned(), "on"),
        ("-Og -fzero-init-padding-bits=all".to_owned(), "on"),
        (format!("{ubsan} -fzero-init-padding-bits=all"), "on"),
        ("-O2 -fzero-init-padding-bits=all".to_owned(), "on"),
        ("-O2 -fzero-init-padding-bits=unions".to_owned(), "on"),
    ];
    for (i, (flags, verdict)) in routes.iter().enumerate() {
        let dir = work.dir().join(format!("route-{i}"));
        std::fs::create_dir_all(&dir).expect("a workdir per route");
        let Some(cell) = zero_init_padding_cell(
            &driver,
            &dir,
            &["--profile", "explicit", "--flags", flags],
            "zero-init-padding-bits on optimized gcc builds",
        ) else {
            return;
        };
        assert_eq!(cell["verdict"], *verdict, "{flags}: {cell}");
        assert_eq!(
            cell["controls"]["regime_negative"]["outcome"], "absent",
            "{flags}: {cell}"
        );
    }
}

/// The words a build's command line carries for the run's witness, as one string.
fn witness_words() -> String {
    chard::compile::RunWitness::compile_words().join(" ")
}

/// A wrapper that is a cache keyed by the command line alone: it keeps what the compiler
/// wrote at `-o` under a digest of the words it was called with (the output by its file
/// name, so two work directories share an entry) and serves that file to the next call
/// with the same words, whatever the files named on the line hold by then and whatever the
/// environment is. The preprocessor's own jobs and the driver's listings pass through.
fn command_line_cache(work: &Path) -> (PathBuf, PathBuf) {
    let store = work.join("store");
    std::fs::create_dir_all(&store).expect("the cache's store");
    let driver = fake_driver(
        work,
        &format!(
            r#"STORE='{}'
[ $# -eq 0 ] && exit 0
out=""; prev=""; words=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; words="$words ${{a##*/}}"; else words="$words $a"; fi
  prev="$a"
done
case " $* " in *" -E "*|*" -### "*) exec "$REAL" "$@";; esac
[ -n "$out" ] || exec "$REAL" "$@"
key=$(printf '%s' "$words" | cksum | tr ' ' '-')
if [ -f "$STORE/$key" ]; then cp "$STORE/$key" "$out"; exit 0; fi
"$REAL" "$@"; status=$?
[ "$status" -eq 0 ] && [ -f "$out" ] && cp "$out" "$STORE/$key"
exit $status"#,
            store.display()
        ),
    );
    (driver, store)
}

/// What a run through [`command_line_cache`] is asked: a flagged profile over an
/// executable probe, a linked probe read through `.dynamic`, an object probe, a macro
/// probe and a probe that is run.
const CACHED_MEASUREMENT: [&str; 14] = [
    "--profile",
    "explicit",
    "--flags",
    "-O2 -fstack-protector-strong",
    "--probe",
    "stack-canary",
    "--probe",
    "link-defaults",
    "--probe",
    "cet-object",
    "--probe",
    "toolchain-macros",
    "--probe",
    "ub-null-check",
];

/// The run's nonce and where it came from, as the report publishes them.
fn published_witness(report: &Value) -> (String, String) {
    let witness = &report["run"]["artifact_witness"];
    (
        witness["nonce"].as_str().expect("a nonce").to_owned(),
        witness["source"].as_str().expect("a source").to_owned(),
    )
}

/// The observations that carry a build with an artifact, which are the ones a witness can
/// be asked of.
fn built_observations(report: &Value) -> Vec<&Value> {
    report["observations"]
        .as_array()
        .expect("observations")
        .iter()
        .filter(|o| o["build"]["artifact_sha256"].is_string())
        .collect()
}

/// Every observation of `report` that built an artifact is withheld under
/// `artifact-lacks-run-witness`: `indeterminate`, no level, no triple, no run record, a
/// reason and an `observed` that contain `says`, and a store entry that is `unreadable`
/// and opens with the words of an artifact set aside. Returns how many.
fn assert_every_build_is_unwitnessed(report: &Value, says: &str) -> usize {
    let built = built_observations(report);
    for o in &built {
        let check = o["check"].as_str().expect("a check");
        assert_eq!(o["verdict"], "indeterminate", "{check}: {o}");
        assert_eq!(
            o["gating"]["rule"], "artifact-lacks-run-witness",
            "{check}: {o}"
        );
        assert_eq!(
            o["gating"]["premise"], "instrument-limitation",
            "{check}: {o}"
        );
        for field in ["level", "controls", "run"] {
            assert!(o.get(field).is_none(), "{check} carries `{field}`: {o}");
        }
        let reason = o["gating"]["reason"].as_str().expect("a reason");
        let observed = o["evidence"]["observed"].as_str().expect("an observed");
        assert!(
            reason.contains(says) && observed.contains(says),
            "{check}: `{says}` is not in the reason and the observed: {reason} / {observed}"
        );
        let key = o["build"]["artifact_sha256"].as_str().expect("a digest");
        let entry = &report["facts"][key];
        assert_eq!(entry["kind"], "unreadable", "{check}: {entry}");
        assert!(
            entry["error"]
                .as_str()
                .is_some_and(|e| e.starts_with("set aside unread:") && e.contains(says)),
            "{check}: {entry}"
        );
    }
    // What built nothing was decided before any build, and publishes no measurement.
    for o in report["observations"].as_array().expect("observations") {
        if !o["build"]["artifact_sha256"].is_string() {
            assert!(
                !matches!(o["verdict"].as_str(), Some("on" | "off" | "partial")),
                "a check with no artifact published a measurement: {o}"
            );
        }
    }
    assert!(
        report["facts"]
            .as_object()
            .expect("facts")
            .values()
            .all(|entry| entry["kind"] != "elf" && entry["kind"] != "elf-delta"),
        "the store holds facts read from an unwitnessed artifact"
    );
    let named = report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|d| {
            d["severity"] == "error"
                && d["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("artifact-lacks-run-witness") && m.contains(says))
        })
        .count();
    assert!(
        named > 0,
        "no error diagnostic names the unwitnessed artifact"
    );
    assert_eq!(report["consistency"]["status"], "consistent");
    built.len()
}

#[test]
fn an_object_a_command_line_cache_kept_from_another_run_is_withheld_and_never_run() {
    if !can_run("that an object a cache kept from another run is withheld as unwitnessed") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "the run witness through a command-line cache",
            "this host's cc emits Mach-O, so the run has no witness to hold an artifact to",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "command-line-cache");
    let (driver, store) = command_line_cache(work.dir());

    let first = measure(&driver, &work.path("first"), &CACHED_MEASUREMENT);
    let (first_nonce, first_source) = published_witness(&first);
    assert_eq!(first_source, "os-random");
    assert!(
        built_observations(&first)
            .iter()
            .all(|o| o["gating"]["rule"] != "artifact-lacks-run-witness"),
        "the run that built its own artifacts withheld one as unwitnessed"
    );
    for check in ["canary-emitted", "ssp-level"] {
        assert_eq!(
            observation(&first, check)["verdict"],
            "on",
            "the first run read nothing worth serving for {check}"
        );
    }
    assert!(
        files_under(&store).0 > 0,
        "the first run left nothing in the cache's store"
    );

    let second = measure(&driver, &work.path("second"), &CACHED_MEASUREMENT);
    let (second_nonce, second_source) = published_witness(&second);
    assert_eq!(second_source, "os-random");
    assert_ne!(first_nonce, second_nonce, "two runs drew one nonce");
    let withheld = assert_every_build_is_unwitnessed(&second, &first_nonce);
    assert!(
        withheld >= 12,
        "{withheld} observation(s) of the second run built an artifact"
    );
    let reason = observation(&second, "canary-emitted")["gating"]["reason"]
        .as_str()
        .expect("a reason")
        .to_owned();
    assert!(
        reason.contains("did not write") && !reason.contains(&second_nonce),
        "the reason names the value found and not this run's own: {reason}"
    );
}

#[test]
fn a_derived_witness_tells_a_run_from_one_asked_something_else() {
    if !can_run("what a derived witness tells apart") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "the derived run witness",
            "this host's cc emits Mach-O, so the run has no witness to hold an artifact to",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "derived-witness");
    let (driver, store) = command_line_cache(work.dir());
    let normalized = |more: &[&'static str]| -> Vec<&str> {
        std::iter::once("--normalize")
            .chain(CACHED_MEASUREMENT)
            .chain(more.iter().copied())
            .collect()
    };
    let verdicts = |report: &Value| -> Vec<(String, String)> {
        report["observations"]
            .as_array()
            .expect("observations")
            .iter()
            .map(|o| {
                (
                    o["check"].as_str().expect("a check").to_owned(),
                    o["verdict"].as_str().expect("a verdict").to_owned(),
                )
            })
            .collect()
    };

    let first = measure(&driver, &work.path("first"), &normalized(&[]));
    let (first_nonce, first_source) = published_witness(&first);
    assert_eq!(first_source, "derived");
    assert!(files_under(&store).0 > 0, "the first run stored nothing");

    // The same question again, served from the store: the same nonce, read as its own.
    let again = measure(&driver, &work.path("again"), &normalized(&[]));
    assert_eq!(
        published_witness(&again),
        (first_nonce.clone(), first_source)
    );
    assert_eq!(verdicts(&again), verdicts(&first));
    assert!(
        built_observations(&again)
            .iter()
            .all(|o| o["gating"]["rule"] != "artifact-lacks-run-witness"),
        "a second run of one normalized measurement withheld an artifact as unwitnessed"
    );

    // Another question, the same command lines: another nonce, and nothing read.
    let other = measure(
        &driver,
        &work.path("other"),
        &normalized(&["--env", "CHARD_TEST_UNKEYED=1"]),
    );
    let (other_nonce, other_source) = published_witness(&other);
    assert_eq!(other_source, "derived");
    assert_ne!(other_nonce, first_nonce);
    assert!(assert_every_build_is_unwitnessed(&other, &first_nonce) >= 12);
}

/// A wrapper that takes the run-witness words off a command line whose output's file name
/// matches the shell pattern `only`, and hands every other line to the real driver whole.
fn witness_dropping_driver(work: &Path, only: &str) -> PathBuf {
    witness_dropping_driver_saying(work, only, "")
}

/// [`witness_dropping_driver`], running the shell `says` on each line it takes the words
/// off, before the real driver: what the wrapper prints beside the artifact it leaves.
fn witness_dropping_driver_saying(work: &Path, only: &str, says: &str) -> PathBuf {
    fake_driver(
        work,
        &format!(
            r#"[ $# -eq 0 ] && exit 0
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
case "${{out##*/}}" in
  {only}) ;;
  *) exec "$REAL" "$@" ;;
esac
skip=0
for a in "$@"; do
  shift
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  if [ "$a" = "-include" ] && [ "$1" = "{}" ]; then skip=1; continue; fi
  set -- "$@" "$a"
done
{says}
exec "$REAL" "$@""#,
            chard::compile::RUN_WITNESS_HEADER_NAME
        ),
    )
}

#[test]
fn a_build_that_drops_the_witness_header_is_withheld() {
    if !can_run("that an artifact with no run witness is withheld") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "an artifact with no run witness",
            "this host's cc emits Mach-O, so the run has no witness to hold an artifact to",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "witness-dropped");
    let driver = witness_dropping_driver(work.dir(), "*");
    let report = measure(&driver, work.dir(), &CACHED_MEASUREMENT);
    let withheld = assert_every_build_is_unwitnessed(&report, "carries no run witness");
    assert!(
        withheld >= 12,
        "{withheld} observation(s) built an artifact"
    );
    // The words were on the line chard recorded; the wrapper is what removed them.
    for o in built_observations(&report) {
        let argv: Vec<&str> = o["build"]["argv"]
            .as_array()
            .expect("argv")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(argv.join(" ").contains(&witness_words()), "{argv:?}");
    }
}

/// The output names of one kind of control arm, as a shell pattern for
/// [`witness_dropping_driver_saying`]: `kind` is `pos` or `neg`.
fn arm_outputs(kind: &str) -> String {
    format!("*-{kind}|*-{kind}.o|*-{kind}.so")
}

/// Shell that prints, for each `-f`, `-W`, `-m`, `-U`, `-D`, `-O` and `-z` word of the command line, the line a
/// driver prints for an option it does not know: what a cache replays beside an object it
/// kept from a toolchain that refused the arm's flag.
const SAYS_EVERY_FLAG_IS_UNKNOWN: &str = r#"for a in "$@"; do
  case "$a" in -[fWmUDOz]*) echo "cc1: error: unrecognized command-line option '$a'" >&2 ;; esac
done"#;

/// The observations of `report` whose `arm` (`positive` or `negative`) was built to an
/// output of that arm's own name, each held to an unwitnessed arm's reading: `probe-invalid`
/// with the arm unevaluable, no outcome and no run on the arm, a detail that says its
/// artifact carries no run witness, and no gating. Returns the channels seen.
fn assert_unwitnessed_arms(report: &Value, arm: &str, kind: &str) -> Vec<String> {
    let mut channels = std::collections::BTreeSet::new();
    let suffixes = [
        format!("-{kind}"),
        format!("-{kind}.o"),
        format!("-{kind}.so"),
    ];
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("a check");
        assert_ne!(
            o["gating"]["rule"], "artifact-lacks-run-witness",
            "{check}: the measured build carries the witness: {o}"
        );
        let built = &o["controls"][arm];
        let own_output = built["build"]["argv"].as_array().is_some_and(|argv| {
            argv.iter()
                .filter_map(Value::as_str)
                .any(|word| suffixes.iter().any(|s| word.ends_with(s.as_str())))
        });
        if !own_output {
            continue;
        }
        // Never `unsupported` or `indeterminate` under a rule of the declared family: the
        // arm's stderr says every flag is unknown, and it is not this run's to quote.
        assert_eq!(o["verdict"], "probe-invalid", "{check}: {o}");
        assert!(o.get("gating").is_none(), "{check}: {o}");
        assert_eq!(
            o["controls"]["withheld_because"],
            format!("{arm}-unevaluable"),
            "{check}: {o}"
        );
        assert!(built.get("outcome").is_none(), "{check}: {built}");
        assert!(built.get("run").is_none(), "{check}: {built}");
        assert!(
            built["detail"]
                .as_str()
                .is_some_and(|d| d.contains("carries no run witness")),
            "{check}: {built}"
        );
        assert!(
            built["build"]["stderr"]
                .as_str()
                .is_some_and(|e| e.contains("unrecognized command-line option")),
            "{check}: the arm's stderr does not carry the planted line: {built}"
        );
        channels.insert(o["channel"].as_str().expect("a channel").to_owned());
    }
    channels.into_iter().collect()
}

#[test]
fn an_arm_whose_artifact_is_unwitnessed_is_unevaluable_and_says_nothing() {
    if !can_run("that an unwitnessed control arm is unevaluable") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "an unwitnessed control arm",
            "this host's cc emits Mach-O, so the run has no witness to hold an artifact to",
        );
        return;
    }
    let asked = [
        "--profile",
        "bare",
        "--probe",
        "stack-canary",
        "--probe",
        "cet-object",
        "--probe",
        "toolchain-macros",
        "--probe",
        "ub-null-check",
        "--probe",
        "warn-format",
        "--probe",
        "trampolines",
    ];
    let every_channel = ["compiler-diag", "elf-static", "macro", "runtime"];
    for (arm, kind, expected) in [
        ("positive", "pos", &every_channel[..]),
        ("negative", "neg", &["elf-static", "macro"][..]),
    ] {
        let work = common::Work::new("fakedriver", &format!("witness-dropped-{kind}"));
        let driver = witness_dropping_driver_saying(
            work.dir(),
            &arm_outputs(kind),
            SAYS_EVERY_FLAG_IS_UNKNOWN,
        );
        let report = measure(&driver, work.dir(), &asked);
        let channels = assert_unwitnessed_arms(&report, arm, kind);
        for channel in expected {
            assert!(
                channels.iter().any(|c| c == channel),
                "no unwitnessed {arm} arm was withheld on the {channel} channel: {channels:?}"
            );
        }
        assert_eq!(report["consistency"]["status"], "consistent", "{arm}");
    }
}

#[test]
fn every_build_names_the_witness_and_every_artifact_read_carries_it() {
    if !can_run("that every build carries the run witness") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "the run witness in every build",
            "this host's cc emits Mach-O, so the run has no witness",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "witness-everywhere");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "bare-optimized",
            "--probe",
            "stack-canary",
            "--probe",
            "shared-object-defaults",
            "--probe",
            "cet-object",
            "--probe",
            "linker-default-execstack",
            "--probe",
            "copy-dt-needed",
            "--probe",
            "trapv",
            "--probe",
            "toolchain-macros",
        ],
    );
    let (nonce, _) = published_witness(&report);
    let words = witness_words();
    let mut builds = 0usize;
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("a check");
        assert_ne!(
            o["gating"]["rule"], "artifact-lacks-run-witness",
            "{check}: {o}"
        );
        let arms = ["positive", "negative", "regime_negative"]
            .into_iter()
            .map(|arm| &o["controls"][arm]["build"]);
        for build in std::iter::once(&o["build"]).chain(arms) {
            let Some(argv) = build["argv"].as_array() else {
                continue;
            };
            let line: Vec<&str> = argv.iter().filter_map(Value::as_str).collect();
            let line = line.join(" ");
            assert_eq!(
                line.matches(&words).count(),
                1,
                "{check}: a build does not name the run's header once: {line}"
            );
            assert!(
                line.find(&words) < line.find(" -o "),
                "{check}: the header is named after the output: {line}"
            );
            builds += 1;
        }
    }
    assert!(builds >= 20, "{builds} build(s) were examined");

    let mut read = 0usize;
    for (key, entry) in report["facts"].as_object().expect("facts") {
        match entry["kind"].as_str() {
            Some("elf") => {
                assert_eq!(
                    entry["elf"]["run_witness"],
                    serde_json::json!([nonce]),
                    "{key}: a stored artifact does not carry the run's nonce alone"
                );
                read += 1;
            }
            // A delta states what differs from its base, and the witness never does.
            Some("elf-delta") => {
                assert!(
                    entry["elf_changes"].get("run_witness").is_none(),
                    "{key}: an arm's witness differs from its base's: {entry}"
                );
                read += 1;
            }
            Some("unreadable") => panic!("{key}: an honest build was not read: {entry}"),
            _ => {}
        }
    }
    assert!(read >= 8, "{read} stored artifact(s) were examined");
}

#[test]
fn a_library_the_probe_links_that_is_unwitnessed_withholds_the_probe() {
    if !can_run("that an unwitnessed library of a probe's chain withholds the probe") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "an unwitnessed library of a probe's chain",
            "this host's cc emits Mach-O, so the run has no witness to hold a library to",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "witness-dropped-library");
    let driver = witness_dropping_driver(work.dir(), "lib*.so");
    let asked = ["--profile", "bare", "--probe", "copy-dt-needed"];
    let report = measure(&driver, &work.path("dropped"), &asked);
    let honest = measure(
        &fake_driver_named(
            work.dir(),
            "fakecc-whole",
            &real_cc(),
            r#"exec "$REAL" "$@""#,
        ),
        &work.path("whole"),
        &asked,
    );
    let mut withheld = 0;
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("a check");
        let whole = observation(&honest, check);
        assert!(
            matches!(whole["verdict"].as_str(), Some("on" | "off")),
            "{check} is not measured with the libraries whole: {whole}"
        );
        assert_eq!(o["verdict"], "indeterminate", "{check}: {o}");
        assert_eq!(
            o["gating"]["rule"], "artifact-lacks-run-witness",
            "{check}: {o}"
        );
        let reason = o["gating"]["reason"].as_str().expect("a reason");
        assert!(
            reason.contains("a library the probe's link takes")
                && reason.contains("carries no run witness")
                && reason.contains("libchard"),
            "{check}: {reason}"
        );
        for field in ["build", "controls", "run"] {
            assert!(o.get(field).is_none(), "{check} carries `{field}`: {o}");
        }
        withheld += 1;
    }
    assert!(withheld >= 1, "no check of the probe was observed");
    assert_eq!(report["consistency"]["status"], "consistent");
}

#[test]
fn an_lto_object_is_withheld_for_its_ir_and_blames_no_cache() {
    if !can_run("that an object of LTO IR is withheld with the IR named") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "an object of LTO IR under the run witness",
            "this host's cc emits Mach-O, so the run has no witness",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "witness-lto-object");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            "-O2 -flto",
            "--probe",
            "cet-object",
            "--probe",
            "stack-canary",
        ],
    );
    let object = observation(&report, "cet-marked-object");
    if object["build"]["exit_status"] != 0 {
        common::capability_gap(
            "an object of LTO IR under the run witness",
            "the host's cc did not build the object probe under -flto",
        );
        return;
    }
    assert_eq!(object["verdict"], "indeterminate", "{object}");
    assert_eq!(
        object["gating"]["rule"], "artifact-lacks-run-witness",
        "{object}"
    );
    let reason = object["gating"]["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("compiler IR") && reason.contains("link-time optimization"),
        "the reason does not say the IR is why: {reason}"
    );
    assert!(
        !reason.contains("cache") && !reason.contains("wrapper"),
        "the reason blames a cache for what the profile explains: {reason}"
    );
    for d in report["diagnostics"].as_array().expect("diagnostics") {
        let message = d["message"].as_str().unwrap_or("");
        assert!(
            !(message.contains("compiler IR") && message.contains("cache")),
            "a diagnostic blames a cache for an object of IR: {message}"
        );
    }
    // The linked probe's code is generated at the link, with the note.
    let linked = observation(&report, "canary-emitted");
    assert_ne!(
        linked["gating"]["rule"], "artifact-lacks-run-witness",
        "{linked}"
    );
    assert!(
        !stored_elf(&report, linked).is_null(),
        "the linked probe under -flto was not read: {linked}"
    );
    assert_eq!(report["consistency"]["status"], "consistent");
}

#[test]
fn a_clang_lto_object_is_named_as_bitcode_and_blames_no_cache() {
    const TEST: &str = "a clang LTO object under the run witness";
    if !can_run("that clang's bitcode object is withheld with the IR named") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            TEST,
            "this host's cc emits Mach-O, so the run has no witness",
        );
        return;
    }
    let host_path = std::env::var_os("PATH").unwrap_or_default();
    let Some(clang) = resolved_on(&host_path, "clang") else {
        common::capability_gap(TEST, "no clang on PATH");
        return;
    };
    let work = common::Work::new("fakedriver", "witness-lto-bitcode");
    let report = measure(
        &clang,
        work.dir(),
        &[
            "--profile",
            "explicit",
            "--flags",
            "-O2 -flto",
            "--probe",
            "cet-object",
        ],
    );
    let object = observation(&report, "cet-marked-object");
    if object["build"]["exit_status"] != 0 {
        common::capability_gap(TEST, "clang did not build the object probe under -flto");
        return;
    }
    assert_eq!(object["verdict"], "indeterminate", "{object}");
    assert_eq!(
        object["gating"]["rule"], "artifact-lacks-run-witness",
        "{object}"
    );
    let reason = object["gating"]["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("LLVM bitcode") && reason.contains("compiler IR"),
        "the reason does not name the bitcode: {reason}"
    );
    assert!(
        !reason.contains("cache") && !reason.contains("wrapper") && !reason.contains("refused"),
        "the reason reads as a file something else left: {reason}"
    );
    let key = object["build"]["artifact_sha256"]
        .as_str()
        .expect("a digest");
    assert_eq!(report["facts"][key]["kind"], "unreadable");
    assert_eq!(report["consistency"]["status"], "consistent");
}

#[cfg(unix)]
#[test]
fn the_resolved_driver_is_published_beside_the_path_that_was_run() {
    if !can_run("that the driver's resolved path is published") {
        return;
    }
    let work = common::Work::new("fakedriver", "driver-resolved");
    let real = PathBuf::from(real_cc());
    let link = work.dir().join("linked-cc");
    std::os::unix::fs::symlink(&real, &link).expect("a link to the host's cc");
    let report = measure(
        &link,
        &work.path("w"),
        &["--profile", "bare", "--probe", "warn-format"],
    );
    let toolchain = &report["toolchain"];
    assert_eq!(
        toolchain["driver"].as_str().map(PathBuf::from),
        Some(link.clone()),
        "{toolchain}"
    );
    let resolved = std::fs::canonicalize(&real).expect("the host's cc resolves");
    assert_ne!(resolved, link);
    assert_eq!(
        toolchain["driver_resolved"].as_str().map(PathBuf::from),
        Some(resolved),
        "{}",
        toolchain["driver_resolved"]
    );
}

#[test]
fn a_normalized_runs_nonce_is_derived_from_the_question_its_report_publishes() {
    if !can_run("that a derived nonce is the report's own question's") {
        return;
    }
    if !common::ELF_HOST {
        common::capability_gap(
            "the derived nonce's question",
            "this host's cc emits Mach-O, so the run has no witness",
        );
        return;
    }
    let work = common::Work::new("fakedriver", "witness-question");
    let driver = fake_driver(work.dir(), r#"exec "$REAL" "$@""#);
    let report = measure(
        &driver,
        &work.path("w"),
        &[
            "--normalize",
            "--profile",
            "explicit",
            "--flags",
            "-O2 -g",
            "--cxxflags",
            "-O1",
            "--ldflags",
            "-Wl,--as-needed",
            "--env",
            "CHARD_TEST_PAIR=one",
            "--probe",
            "warn-format",
        ],
    );
    let words = |list: &Value| -> Vec<String> {
        list.as_array()
            .expect("a flag list")
            .iter()
            .map(|w| w.as_str().expect("a word").to_owned())
            .collect()
    };
    let profile = &report["profile"];
    let (cflags, cxxflags, ldflags) = (
        words(&profile["cflags"]),
        words(&profile["cxxflags"]),
        words(&profile["ldflags"]),
    );
    assert_eq!(cflags, ["-O2", "-g"]);
    assert_eq!(cxxflags, ["-O1"]);
    assert_eq!(ldflags, ["-Wl,--as-needed"]);
    let toolchain = &report["toolchain"];
    let question = chard::compile::WitnessQuestion {
        cflags: &cflags,
        cxxflags: &cxxflags,
        ldflags: &ldflags,
        env: vec![("CHARD_TEST_PAIR", "one")],
        driver: toolchain["driver"].as_str().expect("a driver"),
        version_raw: toolchain["version_raw"].as_str(),
        target_triple: toolchain["target_triple"].as_str(),
        probe_corpus_sha256: report["run"]["probe_corpus_sha256"]
            .as_str()
            .expect("a corpus digest"),
    };
    assert!(question.version_raw.is_some() && question.target_triple.is_some());
    let scratch = work.path("recomputed");
    std::fs::create_dir_all(&scratch).expect("a directory for the recomputed header");
    let expected =
        chard::compile::RunWitness::derived_in(question.lines(), &scratch).expect("a witness");
    assert_eq!(
        published_witness(&report),
        (expected.nonce_hex().to_owned(), "derived".to_owned())
    );
}
