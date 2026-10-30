// SPDX-License-Identifier: BSD-3-Clause

//! Measurements taken through a driver that misbehaves in one named way.
//!
//! Every test here wraps the host's real `cc` in a shell script that passes everything
//! through except the one invocation under test, and then runs the built `chard` against
//! the wrapper. The host's compiler still does the compiling, so the tests run wherever
//! `cc` does, including a Mach-O host; what is being exercised is how chard reads the
//! driver's answer, and the wrapper is what puts a specific answer in front of it.
//!
//! The alternative, a real toolchain in the state each test wants, is not available on
//! any one machine: a preprocessor that exits non-zero after printing its dump takes a
//! missing include and a specific compiler, and a driver that reports a configuration
//! file takes a distribution's clang packaging. A wrapper produces the same stdout,
//! stderr and exit status as the real thing would, which is all chard ever reads.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use std::ffi::OsStr;

mod common;

fn chard_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("chard")
}

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
///
/// Named `fakecc` on purpose: `compile::cxx_driver_for` maps a driver name by its
/// `-`-separated components, and a name with no `gcc`, `clang` or `cc` component maps to
/// nothing, so the C++ probes are withheld under `no-driver` and the run stays about the
/// C driver the test is shaping.
fn fake_driver(work: &Path, script: &str) -> PathBuf {
    fake_driver_named(work, "fakecc", &real_cc(), script)
}

/// [`fake_driver`] under a name of the test's choosing, proxying to `real`.
///
/// Written through `common::executable`, which waits out `ETXTBSY` before handing the
/// path back; every wrapper here is run by a `chard` this process spawns, which is the
/// shape that trips it.
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
///
/// Decided from `toolchain.target_triple`, the field the arch gate itself reads, so the
/// expectation comes from what the host is and the result is held to it: a probe that
/// failed to build on x86_64 fails the assertion, where deciding from whether the store
/// happened to hold its facts would let it pass as the gated arm.
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
            "off x86_64 the probe is gated by the table's decision for {arch}, whatever else \
             happened: {o}"
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
///
/// chard withholds such a check under `execution-mode-assumed` where
/// nothing observed the mode and nobody asserted it, so a test of what the check reads
/// would examine nothing on every host the suite runs on that is not a container. This
/// asserts the word the suite can give, that the hosts it runs on (developer machines, CI's
/// hosted runners) run their own kernels. It is never passed up front: in a container the suite
/// recognises, an asserted `host` is a contradicted assertion and chard refuses the
/// report (exit 3), and the plain run reads `needs-vm` there.
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
/// `.args(PROBE_DEADLINE)`, and an argument list naming `"measure"` carries both words; which
/// tests/ratchets.rs holds.
const PROBE_DEADLINE: [&str; 2] = ["--timeout", "60"];

/// [`measure`], with `envs` set in chard's own environment.
///
/// What chard hands the driver is what is under test, so the variable is set on chard
/// and read back through the wrapper; a test setting it on the wrapper directly would
/// be testing the shell.
///
/// Each probe run gets [`PROBE_DEADLINE`] rather than chard's 5: these tests compare
/// what the wrapper changes, and a run killed at the deadline withholds its reading, so on a
/// busy host one run of a pair could read `probe-invalid` where the other read
/// `indeterminate`. It did: `strict-flex-arrays-enforced`'s control, which crashes
/// five children whose cores go to the host's core handler, ran past 5 s on a host at a
/// load of 44 on 32 processors, and in 1.7 s otherwise.
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

/// A preprocessor that exits non-zero after printing its defines withholds every macro
/// verdict, and the report says why.
///
/// The published shape this closes: gcc 16.1.1 with `-include` of a missing header exits
/// 1 after 882 `#define` lines, and chard published `ssp-level on/strong`, both fortify
/// checks and `optimization-enabled on` over that prefix, with `checks_valid: 6` and no
/// diagnostic. The wrapper fails only the per-variant dumps, whose source is named
/// `macros-<probe>-<tag>.c`, so `toolchain::detect`'s own dumps still succeed and the
/// run reaches the measurement loop rather than being refused at the door.
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

/// A preprocessor that exits 0 and defines nothing withholds the channel too, with a
/// reason that says emptiness rather than an exit status.
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

/// A control arm whose own dump fails is withheld as unevaluable, and the arm says why
/// and carries the job.
///
/// `positive-unevaluable` was published with `detail: None` and no record of the dump:
/// a reader was told the positive control did not build or run, beside a build record
/// that had succeeded. The wrapper fails only the positive arms' dumps, whose source is
/// named `macros-<probe>-<check>-pos.c`, so the measured variant's own dump succeeds and
/// the withholding is the arm's alone.
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

/// A measured build that failed to link withholds every macro verdict over it as
/// `build-failed`, beside a dump that succeeded, and the observation quotes the build.
///
/// The published shape this closes: on macOS arm64 (Apple clang 21) under `openssf-tldr`,
/// ld64 rejects `-z` and every measured build fails, while `branch-protection-macro` and
/// `gcs-macro` read `on` from the `-dM -E` dump and carried two defect rollups to
/// `partial` with nothing linked. The wrapper fails only the measured build's link, whose
/// output is named `toolchain-macros-measured`, with ld64's sentence, and passes every dump
/// through, so the preprocessor still answers and only the build is missing.
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

/// A macro control arm whose build failed is unevaluable, and the arm names the build.
///
/// The arm's dump answers for the arm's flags, and the arm is the build those flags make:
/// where that build failed, the reading validates a detector over a build that does not
/// exist. The wrapper fails only the positive arms' links, named
/// `toolchain-macros-<check>-pos`, and passes their dumps through, so before the rule the
/// triple discriminated over the dumps alone.
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
///
/// This is the shape of a PIE-default driver (`--enable-default-pie` gcc, the PIE-default
/// clangs) for the one property the arms depend on, and it holds on any host: the real
/// failure is an absolute relocation the PIE link cannot take, which needs an x86_64 ELF
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

/// On a driver that links PIE by default, the negative arms of `pie-macro` and `pic-macro`
/// link, read their macros from the artifact, and discriminate.
///
/// With the two negative arms `-fno-PIE` and `-fno-pic` alone, a PIE-default driver links
/// them `-pie` and the link fails on the probe's own reference to its `.chard.report` (76
/// cells of a fleet sweep on 2026-10-06). Their dumps show the macros absent, correctly, but
/// a macro arm whose build failed is unevaluable, so both checks would read `probe-invalid`.
/// The arms carry `-no-pie` and link as the build PIE-off is.
///
/// The wrapper's log is the count: exactly one position-dependent link per check, the
/// negative arm's, and none refused. Without `-no-pie` it would log two refusals and both
/// checks would be `negative-unevaluable`.
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

/// A driver that does not know `-no-pie` withholds `pie-macro` and `pic-macro` under the
/// rule that names the refused control, quoting the driver, and never reads `off`.
///
/// gcc took `-no-pie` in 6; an older one says "unrecognized command line option" of it,
/// in the dump and the link alike. No such driver is in the fleet, so the wrapper is the
/// fixture: it rejects `-no-pie` with gcc's sentence wherever it appears. The `pie` check's
/// negative arm has carried the flag throughout, and is read beside them.
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

/// The driver is not handed the operator's `TMPDIR`.
///
/// gcc and clang put their temporary objects where it points, a linker warning names
/// the object, and the name reaches the published stderr and a control arm's `detail`.
/// The scrubber knows the roots the drivers use when nothing redirects them, so an
/// operator's `TMPDIR` put the object outside them and two normalized runs of one
/// measurement differed again on the one line the scrubber existed for. The wrapper
/// reports what it sees in its own environment on every invocation, and chard is
/// started with the variable set, so `unset` below can only have come from chard.
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

/// A `-m32` inside a response file is refused before any invocation carries it.
///
/// chard builds each control arm with the target and linker the profile's flags select,
/// and reads them from the flags as written, so a `-m32` inside `@file` reached the
/// measured build and no arm: the triple validated each detector on x86_64 while the cell
/// measured i386. The refusal is `CONFIGURATION`, names the argument and its list, and
/// comes before the driver is handed any profile flag; the wrapper logs every argument
/// vector it receives, so a build that carried the file would be in the log. The flag-free
/// toolchain interrogation that precedes profile resolution is in it, which is what makes
/// the absence a measurement.
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

/// Each spelling that selects x32, 16-bit or aarch64 ILP32 code is refused before any
/// invocation carries it, from whichever of the three lists it is in.
///
/// chard does not measure those targets (decided 2026-10-07), and
/// `toolchain::unsupported_target_flags` says which spellings select them. The refusal is
/// `CONFIGURATION`, says chard does not measure the target and names the words that select
/// it (each row's third element; a driver word between the two halves of a `cc1` pair, or
/// an option that took an `-Xclang` as its own value, is not named); the wrapper logs every
/// argument vector it receives, so a build that carried
/// one would be in the log beside the flag-free toolchain interrogation.
#[test]
#[allow(
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
    // wrapper at all. One run with nothing refused is the positive control: it reaches the wrapper,
    // so an empty log above is the refusal's doing and not a wrapper that logs nothing.
    // `common::executable` spawns the wrapper once with no arguments to wait out `ETXTBSY`, which
    // logs one empty line, so only a line with arguments on it is a run's.
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

/// The driver is handed none of the variables `compile::COMPILER_ENV_NAMED` names,
/// and each pin in `compile::COMPILER_ENV_PINNED` at its pinned value.
///
/// `tests/register.rs` holds the list to `THREAT_MODEL.md`; this holds it to the
/// process chard actually spawns. chard is started with every listed variable set, and
/// the wrapper reports each one on every invocation, so `unset` can only have come from
/// chard. The values are the work directory, which is harmless to chard itself and would
/// be visible in the wrapper's report if it arrived.
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

/// The variables the 2026-10-09 inventory found a toolchain reading and moving a
/// measurement with, each spelled out here and not read from `COMPILER_ENV_NAMED`.
///
/// The test above holds the spawned process to whatever the list says, so it cannot notice
/// an entry that was never on the list. This one names the variables, so an entry leaving
/// the list, or the process leaking one of these, fails by name. The classes are in the
/// comment on `compile::COMPILER_ENV_NAMED`.
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

/// The driver's whole environment is `compile::COMPILER_ENV_PASSED` and the pins: a
/// variable no list names, set in chard's own environment, does not reach it.
///
/// The two tests above set names someone found; this one is what makes a name nobody has
/// found harmless. The wrapper reports every name in its environment, and chard is started
/// with variables of three kinds set: one no toolchain and no list names, a loader variable
/// the removal list never held (`LD_LIBRARY_PATH`, at the work directory, which no program
/// here loads from), and `CCACHE_DISABLE`, which a `ccache` masquerade directory on `PATH`
/// would read. The shell running the wrapper adds some of `PWD`, `SHLVL` and `_` itself
/// (measured under `env -i` on 2026-10-11: bash, `/bin/sh` on Fedora 44 and on macOS, adds
/// all three; dash on Ubuntu 22.04 adds `PWD`; busybox on Alpine adds `PWD` and `SHLVL`), so
/// those three are allowed and nothing else is.
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
         exec \"$REAL\" \"$@\"",
    );
    let envs: Vec<(&str, &Path)> = [
        "CHARD_TEST_VARIABLE_NO_LIST_NAMES",
        "LD_LIBRARY_PATH",
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
    for stderr in builds {
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

/// A driver that runs only with a variable chard's environment holds and the clear keeps
/// from it is refused: exit 2, the no-macros message, and a hint spelling the environment
/// the compiler is given as an `env -i` command.
///
/// The wrapper exits 1 unless `CHARD_TEST_DRIVER_NEEDS` is set, the shape of a toolchain
/// that runs only under `LD_LIBRARY_PATH`. Run directly with the variable, it dumps
/// macros, so the refusal is the clear's doing and not a wrapper that never works. chard is
/// run with the variable set; before the clear, that run published a report.
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
///
/// The intrinsic dump decides the compiler's `kind` and `version`, the arch gate's macro
/// witness and the width and byte order it publishes. Tested only for emptiness, a listing
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
            "macro definitions and exited 1: fakecc: fatal error: late.h: No such file or directory;"
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
            .contains("macro definitions and was killed by a signal: fakecc: about to be killed;")),
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
///
/// Not refused, unlike the intrinsic dump: every macro-channel arm takes its own
/// with-headers dump, and what is at stake is the libc and what it gates. A failed dump can
/// lack macros and cannot gain them, so a library a macro names stands; reading it as
/// `unknown` instead lowers `fhardened-effective`'s fortify bar on glibc 2.43 from 3 to 2,
/// and a level-2 build reads `in-force`. The detection names the failure rather than being
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
    // ended is read whole: `__GLIBC__` listed last still names glibc 2.43. A last line its
    // output ended partway through is dropped, whatever the status (here a signal):
    // `__GLIBC_MINOR__ 4` from `43` is not read as glibc 2.4, and glibc stands with no version.
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
    assert!(
        cut["detection"].as_str().is_some_and(
            |d| d.contains("was killed by a signal") && d.contains("the version is not read")
        ),
        "{cut}"
    );
}

/// A with-headers dump cut off partway through its last define under a driver that exits 0,
/// as gcc's does when its `cc1` dies of a closed pipe, names glibc with no version, and its
/// detection and `toolchain.libc_headers_error` name the cut, rather than reading glibc 2.4
/// from the cut define.
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
        libc["detection"]
            .as_str()
            .is_some_and(|d| d.contains(said) && d.contains("the version is not read")),
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

/// A variant's `-dM -E` dump cut off partway through its last define under a driver that
/// exits 0 withholds every macro verdict read through it, as a dump that exited non-zero
/// does, and its record says the output was cut.
///
/// gcc's driver exits 0 when its `cc1`'s stdout is cut by a closed pipe, so no status reading
/// sees the cut. A record that kept no trace of the missing newline would parse the cut define
/// as a define and publish the verdicts read from the listing.
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

/// The driver's flagless dump cut off partway through its last define under a driver that
/// exits 0 is refused at detection, as one that exited non-zero is: `kind`, `version` and
/// the arch gate's witness are read from it, and `#define __clang_major__ 2` cut from `22`
/// is another compiler.
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
                "macro definitions and exited 0 with its output cut off partway through a line;"
            )),
        "{}",
        parsed["error"]
    );
}

/// The intrinsic dump under the profile's flags, cut off partway through its last define
/// under a driver that exits 0, witnesses no target (`dump-failed`), and says it was cut.
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

/// A wrapper configured through a variable of its own is measured as configured when the
/// variable is an `--env` pair, and as it behaves without it otherwise, whatever chard's own
/// environment holds; the report publishes the pair and joins it into `profile.id`.
///
/// The wrapper adds `-fstack-protector-strong` under `CHARD_TEST_HARDEN=canary` and
/// `-fno-stack-protector` under anything else, the shape of nixpkgs' cc-wrapper and its
/// `NIX_HARDENING_ENABLE`. Four runs under `bare`: with the pair, `canary-emitted` reads `on`;
/// with the variable in chard's own environment and no pair, `off`, which is the clear
/// keeping it from the driver; with another value, `off` again under a third id. (A probe's
/// run never receives a pair: `run::execute` builds its environment from
/// `run::PROBE_ENVIRONMENT` alone, which `run`'s own tests hold.)
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

/// An `--env` naming a variable chard passes or pins, a malformed one, or one whose value
/// holds a relative path (which the interrogations and the builds would read against two
/// directories), is refused with exit 2 before any toolchain runs: the wrapper records each
/// of its invocations, and the record stays absent.
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

/// An ambient deployment target moves neither the triple a Darwin-targeting clang compiles
/// for nor the macro dump the report digests and publishes, and the dump states the target.
///
/// The Darwin driver is part of every clang, so a Linux host with clang on `PATH` can
/// reproduce the Apple case by asking for `--target=arm64-apple-darwin25.0.0` (a triple
/// whose version is the kernel's, the shape a default triple has on macOS): there
/// `MACOSX_DEPLOYMENT_TARGET=10.15` moves `-triple` to `macosx10.15.0` and
/// `__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__` to `101500`. The builds fail with no SDK,
/// which this test does not look at; it reads the detection. Two runs, one with the variable
/// and one without, must publish one dump, and the dump must carry the version macro, which
/// is the record of a Darwin run's deployment target. A host without clang announces the gap.
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

/// The wrapper itself passes a healthy run through unchanged, so the tests above
/// are failing chard on the one invocation they shape rather than on the wrapper.
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
        "a bare column behind a configuration file is not a measurement of compiled-in \
         defaults: {}",
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
    assert!(
        bare["profile"]["toolchain_note"]
            .as_str()
            .is_some_and(|n| n.contains("so it read no configuration file")),
        "a bare column whose configuration went unread says so beside flags_source: {}",
        bare["profile"]
    );
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
///
/// While the status went unread, the failed job's first line was published as the
/// driver's version string and keyed the report's identity.
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
/// `gcc -v` opens with `Reading specs from <path>` when an installed specs file
/// replaces the built-in specs, and only clang's `Configuration file:` line was read,
/// so a gcc measured through a specs file published `flags_source: none`. The wrapper
/// prepends gcc's line to the `-v` output, where gcc prints it.
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
///
/// The ledger's own reproduction of the finding: the program chard resolves is the one
/// that lies, and the real driver still does every build. The shim sits beside the
/// wrapper under `ld/`, so the path the wrapper prints is absolute and `path_source`
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
///
/// The ledger's reproduction: `exec clang -fuse-ld=lld "$@"` answered
/// `-print-prog-name=ld` with the default `ld`, which ignores `-fuse-ld=`, and the report
/// published GNU ld while every link went through ld.lld (Fedora 44 aarch64, clang
/// 22.1.8, 2026-09-28). Here the wrapper's `-###` link line runs a shim whose banner is
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
///
/// The ledger's reproduction (2026-10-07, Fedora 44 x86_64, clang 22.1.8): a wrapper that
/// printed a listing running `/usr/bin/ld.lld` on `-###` and exited 1 had that path
/// published as `toolchain.linker` (kind read from its banner, `path_source` `driver`)
/// while every link went through GNU ld. A non-zero exit means the driver rejected the
/// command it was asked to list, the rule `link_inputs::listing` holds the two input
/// comparisons to, so the line is not read and the detection opens with the status and
/// names the route it fell back to, `-print-prog-name=ld`. Here the listing runs a shim
/// whose banner no real linker prints, so the published `version` says whether the line
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
        "the detection opens with the status and the query's scope, then names the \
         fallback: {linker}"
    );
}

/// A wrapper exiting 1 on `-###` under a profile with flags: the detection names the scope
/// the query ran under, the profile's link-selection words, and does not call the profile
/// flagless.
///
/// `read_link_line` hands the query only the profile's `-fuse-ld=`, `--ld-path=` and `-B`
/// words, so under `openssf-tldr` it runs under none of them. `under no flags` would be a
/// claim about the profile, false of every profile without a selection. Runs on any host: only
/// detection is under test.
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
/// path published relative, as every build record and gating reason is.
///
/// The quoted line lands in `toolchain.linker.detection`, which no later pass rewrites.
/// Quoted as written, a driver naming its work directory (a response file it could not read,
/// a wrapper naming itself) would put the absolute spelling in the report. Runs on any host: only
/// detection is under test.
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
///
/// An arm of the detection that dropped the cause would read a `--ld-path=` under a driver
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

/// A `bfd` or `gold` banner over artifacts no linker signed is published as
/// uncorroborated.
///
/// The ledger's repro: a program on `PATH` answering `--version` as gold while the real
/// `ld` links. GNU ld and gold write nothing of their own into `.comment`, so the
/// artifacts cannot contradict the banner and must not be read as confirming it; the
/// honest value is `no-signature`, with the compiler's line quoted so a reader sees what
/// was read. On a host whose compiler emits Mach-O nothing ELF is read, and the value
/// is `no-linked-artifact` with a zero denominator, which is the other absence the
/// vocabulary keeps apart. The arm is chosen by the host (`common::ELF_HOST`), and the
/// ELF arm then asserts that facts were read: the expectation comes from what the host
/// is, and the result is held to it.
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

/// A banner the artifacts contradict is published as a disagreement, beside the banner,
/// with an error diagnostic.
///
/// The same shim answering as lld while the real `ld` links: lld writes `Linker: LLD`
/// into every output and these artifacts carry no such line, so the program that
/// answered `--version` is not the one that linked them. `kind` stays `lld`, because
/// that is what the banner said and `detection` says so; `artifact.agreement` says
/// `disagrees` and the diagnostic names the evidence. Needs a linked ELF artifact, so on
/// a Mach-O host only the shape of the absence is checked.
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

/// A profile that selects a self-signing linker is corroborated by the artifacts it
/// linked: `agrees`, with the line quoted, and the clean-build artifact of the check that
/// measures the toolchain default named and left out of the count.
///
/// Runs the real `cc` under `--flags -fuse-ld=<name>` for each of lld and mold that is on
/// `PATH`, and announces the arm as not exercised for each that is not. Both linkers were
/// measured to write their line on 2026-09-28 (lld 22.1.8, mold 2.40.4, Fedora 44
/// aarch64); this is the same measurement taken by the test suite. `linker-default-execstack`
/// rides along because its one check reads the clean build, which the driver's default
/// linked: fed as a measured artifact it carried no linker line beside `link-defaults`'
/// signed one, and the run published `disagrees` with an error diagnostic on a banner
/// that was exactly right. The probe is gated to x86_64, and the arm is chosen by the
/// target the report names: there the clean artifact is named beside the selection it
/// was linked without, and elsewhere the probe is arch-gated and named as contributing
/// nothing.
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
                "the clean-build artifact is named beside the selection and left \
                 uncounted: {evidence}"
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

/// A control arm links with the linker the profile selects, whenever its check reads a
/// link or what it produced.
///
/// The controls were profile-free down to the linker: under `-fuse-ld=lld` the measured
/// build linked with ld.lld and both controls with the driver's default, so the triple
/// validated a detector on a linker the cell never used (Fedora 44 aarch64, clang 22.1.8,
/// 2026-09-28: `no-copy-dt-needed` read `on` beside a positive control quoting GNU ld).
/// `-B` over an empty directory is a selection `toolchain::linker_selecting_flags`
/// consults and every driver links under unchanged, so the runtime half runs on any host;
/// the elf-static half needs an artifact chard reads, so a Mach-O host announces the gap.
/// A compiler-diag arm carries it too, since the record's own check reads the linker's
/// stderr there. A macro check's arms carry it as well: `-B` chooses the
/// startup objects, the compiler proper and, for gcc, a header directory
/// (`toolchain::runtime_selecting_flags`), so it is the runtime selection's on every
/// channel, and a linking arm carries it once, not again as the linker's.
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
///
/// A probe build names its output in the work directory (its source is relative, the
/// driver running there), and a macro dump names its source there (`.c`, or `.cpp` through the
/// C++ driver); the interrogations
/// name neither, except the two flagless dumps `toolchain::detect` takes before any
/// profile is read, which are the toolchain's and carry no profile flag at all.
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

/// Every probe build, on every channel, carries the runtime the profile selects, in each
/// spelling clang accepts and from either flag list: the measured build, the clean build,
/// both control arms and the probe's own chain libraries.
///
/// Were only the measured build to take it, then under `--gcc-install-dir=` naming a copy of
/// the gcc install directory whose `crtbegin*.o` carries no x86 feature note, `cet-marked`
/// would read `off` with `-fcf-protection=full` over a positive control linked against the
/// host's marked `crtbeginS.o` (Fedora 44 x86_64, clang 22.1.8; `measure::arm_flags`). The wrapper
/// logs every argument vector and strips the selection before handing it to the host's
/// `cc`, which may be a gcc that refuses every spelling; what is under test is what chard
/// hands the driver. Each logged probe build is classified by the output it names, and
/// every class must have been seen, so a run that built no arm cannot pass.
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
            "no {class} was logged, so it was not tested; seen {classes:?} over {builds} \
             probe builds"
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
/// `toolchain::header_selecting_flags` takes stripped, in POSIX `sh`.
const STRIP_HEADER_SELECTION: &str = "skip=0
for a; do
  shift
  if [ \"$skip\" = 1 ]; then skip=0; continue; fi
  case \"$a\" in
    -I|-isystem|-idirafter|-iquote|-include|-imacros) skip=1; continue;;
    -I*|-isystem*|-idirafter*|-iquote*|-include*|-imacros*) continue;;
    -undef|-pthread) continue;;
  esac
  set -- \"$@\" \"$a\"
done
exec \"$REAL\" \"$@\"";

/// Every probe build on every channel carries the headers the profile selects, in each
/// spelling the drivers accept and from either flag list: the measured build, both control
/// arms and the chain libraries the measured build and the arms link. The clean build
/// carries none of them (`measure::clean_flags` says why), and the two chain libraries it
/// links carry none either, so the probe that links a chain, `copy-dt-needed`, is fed alone
/// and the clean build's pair is told from the rest by count.
///
/// Were only the measured build to take this selection, an explicit profile carrying `-I`,
/// `-isystem`, `-include` or gcc's `-pthread` would withhold every compile-input reading
/// under `compile-inputs-unmatched-by-arms` (17 of 72 on Fedora 44 x86_64, gcc 16.1.1 and
/// clang 22.1.8; `measure::arm_flags`). The wrapper logs every
/// argument vector and strips the selection before handing it to the host's `cc`, since the
/// files it names do not exist and `-undef` would silence the macro channel; what is under
/// test is what chard hands the driver. Each logged probe build is classified by the output
/// it names, and every class must have been seen, so a run that built no arm cannot pass.
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

/// A two-token selection spelled long reaches every probe build as the measured line's own
/// pair and nothing more: under `--library-directory <dir>/`, which gcc and clang read as
/// `-L <dir>/`, every build class carries the pair (the target selection reaches the clean
/// build too), and no build's argument vector holds `<dir>/` anywhere but right after
/// `--library-directory`, so no build runs under a word the measured line never handed the
/// driver. The selection readers are projections of one walk (`toolchain::selections`), and
/// the long spelling is `-L` to every reader (`toolchain::LONG_ALIASES`). A value that
/// spells another reader's option, `--library-directory -B<dir>/`, is the directory named
/// `-B<dir>/` to both drivers and a relative path, refused before any build as `-L -B<dir>/`
/// is (the second half); a reader that read the value as a prefix of its own put `-B<dir>/`
/// on every arm and the clean build once more, alone, and with a `specs` file or an `ld` in
/// `<dir>` they read specs and ran a linker the measured build did not
/// (`toolchain::selections` has both measurements, 13 of 72 checks withheld on gcc and a
/// wrong `off` on clang).
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
        "the linker was detected and published, so its profile flags are read from the \
         record rather than from an absent object: {linker}"
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
                    "`{prefix}` reached the driver as a word of its own, which the measured \
                     line never had:\n{line}"
                );
            }
        }
        lines = lines.saturating_add(1);
    }
    assert!(lines > 0, "the wrapper logged no argument vector");
}

/// The second half of the pair law: a two-token selection whose value spells another
/// reader's option, `--library-directory -B<dir>/`, is the directory named `-B<dir>/` to both
/// drivers and a relative path, refused before any build under the long spelling, gcc's
/// abbreviation `--li` and the short `-L` alike (`toolchain::LONG_ALIASES`); the wrapper logs
/// no build carrying the pair. Counted against the spellings fed.
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

/// A selection spelled as the value of a two-token option that selects nothing reaches no
/// probe build as the selection: under `-u -B<dir>/`, the undefined symbol named `-B<dir>/`
/// to both drivers, the measured build, the profile interrogation and the regime arm carry
/// the pair as the profile's own words, no control arm and no clean build carries a word of
/// it (those are profile-free, and the pair selects nothing), no build's argument vector holds `-B<dir>/`
/// anywhere but right after `-u`, and the linker is detected under no flag of the profile.
/// A reader that read the value as a prefix of its own put `-B<dir>/` on every arm and the
/// clean build, alone, and with an `ld` in `<dir>` they linked through a linker the
/// measured build never chose (`toolchain::Hand::Value` has the measurement, a wrong `off`
/// on clang's `linker-default-noexecstack`).
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
        "the linker was detected and published, so its profile flags are read from the \
         record rather than from an absent object: {linker}"
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
                    "`{prefix}` reached the driver as a word of its own, a search prefix the \
                     measured line never had:\n{line}"
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

/// A profile with flags that select no linker holds its linker to the clean-build
/// artifact too, since both builds went through the same link line.
///
/// `bare-optimized` is `-O2` and no selection, so `linker-default-execstack`'s clean
/// artifact is linked by the same driver default as `link-defaults`' measured one and
/// counts beside it, and the evidence names no selection. Were the clean artifact left out
/// under every profile with flags, a run of that one probe under a lying lld banner would
/// publish `no-linked-artifact` over an artifact it had read, and every x86_64 report under
/// this profile would assert a selection the profile never made. Needs
/// a linked ELF artifact, so a Mach-O host announces the gap.
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

/// A linker selection present only in cxxflags reaches the report as the C++ probes'
/// linker, with the flag in its own `profile_flags`.
///
/// The project ledger's criterion this closes. `cxx-stdlib-assertions` is the one C++ probe, and
/// it is built with cxxflags when the profile has them, so `-fuse-ld=` there reached a
/// real link and was invisible in the report. The wrapper pair is named `fake-cc` and
/// `fake-c++` so `compile::cxx_driver_for` finds the C++ driver by component; the
/// existing `fakecc` name deliberately maps to nothing. On a host with lld the C++
/// artifact's `.comment` carries lld's line and `linker.cxx.artifact` agrees, while the C
/// linker keeps its own verdict over the C artifacts; without lld the selection is still
/// published, with `kind: unknown`, which is what makes the field a record of the
/// request. A host with `cc` and no `c++` cannot link the C++ probe, and announces that.
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

/// A measured artifact whose symbol tables the reader could not reach withholds the check
/// that reads them, under a rule naming the table, while the checks reading the tables the
/// reader did finish publish over the same artifact.
///
/// The wrapper builds every variant with the real driver and then replaces the two
/// clean artifacts with the checked-in section-header-stripped fixture, which is what
/// `objcopy --strip-section-headers` leaves: `.dynamic` and the property note reachable
/// through their segments, the symbol tables not reachable at all. Under `bare` the
/// profile is clean, no `-measured` variant is built, and the clean build is the subject
/// of every check (`measure::Conditions::profile_is_clean`), so the clean artifact is the
/// one to replace; a swap keyed on `-measured` would match nothing and measure the real
/// object. `canary-emitted` reads the symbol tables and `separate-code` the section names,
/// and neither may read `off`; `relro` and
/// `noexecstack` read the program headers and `.dynamic` and are measured. The control
/// arms are the real driver's own output, so the triple discriminates and the withholding
/// is the subject reading's alone, which is what separates `indeterminate` under
/// `artifact-unreadable` from a `probe-invalid`.
///
/// The fixture is ELF whatever the host emits, so on a Mach-O host the swap lands but the
/// control arms cannot be read as ELF and the triple withholds for that reason instead.
/// The test announces the gap there and runs where `cc` emits ELF.
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

    let report = measure(
        &driver,
        work.dir(),
        &[
            "--profile",
            "bare",
            "--probe",
            "stack-canary",
            "--probe",
            "link-defaults",
        ],
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

    // The same artifact, read through the tables the reader finished.
    for (id, verdict) in [("relro", "on"), ("noexecstack", "on")] {
        let obs = find(id);
        assert_eq!(
            obs["verdict"].as_str(),
            Some(verdict),
            "{id}: a check reading tables the reader finished publishes over the same \
             artifact: {obs}"
        );
        assert!(obs["gating"].is_null(), "{id}: no rule withheld it: {obs}");
        assert_eq!(
            stored_elf(&report, obs)["truncations"][0]["table"].as_str(),
            Some("symbols"),
            "{id}: the artifact is the swapped one"
        );
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
        "the measured case is counted by its gating rule, on the checks reading a cut table \
         alone"
    );
    // One cut artifact is one error: under `bare` the clean build is the measured one,
    // and `measure::fault_roles` lists it once, under the label the build was read under.
    // The wrapper swaps two clean artifacts, so the cut `symbols` table is named once for
    // each probe, whether or not a check of that probe declares the table.
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

/// A wrapper that builds every variant with the real driver and then replaces the two
/// clean artifacts with the checked-in section-header-stripped fixture.
///
/// Matched on the artifact's name after `-o`, so the macro dumps, whose source files
/// carry the same stem, are left alone.
fn artifact_swapping_driver(work: &Path) -> PathBuf {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/elf/elf64-le-x86_64-exec-stripped-section-headers.elf");
    fake_driver(
        work,
        &format!(
            r#"FIXTURE='{}'
"$REAL" "$@"
status=$?
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then
    case "$(basename "$arg")" in
      stack-canary-clean|link-defaults-clean) cp "$FIXTURE" "$arg" ;;
    esac
  fi
  prev="$arg"
done
exit $status"#,
            fixture.display()
        ),
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
///
/// The wrapper adds `-m32` to every invocation but `-dumpmachine`, which it answers with the
/// host's own triple. The arch gate reads x86_64, the driver's macro dump defines `__i386__`,
/// and the profile resolves to the guide's x86_64 row under the one and to the block alone
/// under the other, so it has no single architecture to be chosen by. Unrefused, such a run
/// would be measured under the x86_64 row and its CET checks would read that row's request. The
/// arm needs an x86_64 `cc` that defines `__i386__` under `-m32`; elsewhere it is a gap.
#[allow(
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
    // over every arch-gated observation. The report publishes (the consistency pass admits
    // the overwrite); a form of `kernel-gate-disagrees-with-execution-mode` that did not admit
    // it would refuse the report.
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
///
/// The wrapper answers `-dumpmachine` with the other of x86_64 and aarch64 from the one
/// the host's `cc` targets and passes every build through, so the arch gate decides for
/// one architecture and the artifacts are of the other: the shape of a cross driver
/// whose triple is wrong, or a wrapper that prints a fixed one. On a Mach-O host no ELF
/// artifact exists to hold the gate to and the block reads `no-elf-artifact`; the macro
/// dump still names the host's machine, reads `disagrees`, and withholds by that machine,
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
///
/// The wrapper answers `-dumpmachine` with `riscv64-linux-gnu`, a family none of the
/// architecture macros names, and passes the macro dump through, so the dump tells the
/// truth on every host. `cet-object` is gated to x86 alone, so under the lie it builds
/// nothing anywhere and no ELF artifact exists to hold the gate to; on a Mach-O host
/// `toolchain-macros` joins it, since its build is no ELF artifact there either. The gate
/// decides every arch-gated check outside the mechanism table under riscv64, and under the
/// host's own machine, which the dump names, each is measured or gated out instead, so
/// every arch-gated check of the selection is withheld, whichever host runs it. The gate's
/// decision is compared whole: compared only for the checks measured under the host's
/// machine, a check gated out there (`cet-marked-object` on aarch64) would keep
/// `arch-outside-table` beside a witness that contradicts the premise.
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
/// `__x86_64__`, `__i386__` and `__aarch64__` definitions from every macro dump it
/// passes through, the shape a target outside the three families produces. `cet-object`
/// is gated to x86, so under the claim it builds nothing and no ELF artifact exists to
/// overrule the dump; on a Mach-O host `toolchain-macros` joins it, since its build is no
/// ELF artifact there either. The dump witnesses a machine the mechanism table has no row
/// for, under which every gate decides otherwise than it did under aarch64, so every
/// arch-gated check of the selection is withheld: `cet-marked-object`, gated out under
/// aarch64 as `unsupported`, included. A gate decision compared only in part would keep that
/// `unsupported`, with the reason "this build targets aarch64" beside the dump that says
/// otherwise.
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
        "every arch-gated check of the selection is withheld, the one gated out under \
         aarch64 included"
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
///
/// The wrapper adds `-undef` to every `-dM` invocation and passes every build through, so
/// the flagless dump defines none of the architecture macros while every ELF artifact the
/// run built carries the host's own machine: the shape a profile's `-undef` makes of the
/// dump under its flags, here made of the flagless one so that `bare` reaches it. The
/// artifacts overrule the dump: `toolchain.target.macros.agreement` reads `overruled`, the
/// one diagnostic under `toolchain.target` is a warning saying so, no error says a witness
/// contradicts the read architecture, and no check is withheld under
/// `target-arch-contradicted`. The contradiction's sentence, which says the dump contradicts
/// the architecture and that no verdict moved because no gate decided otherwise, would be
/// false on both counts for a dump set aside.
#[test]
fn a_dump_the_artifacts_overrule_is_published_as_overruled_and_withholds_nothing() {
    if !common::ELF_HOST {
        eprintln!("skipped: the overrule needs an ELF artifact of the host's family");
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

/// The same wrapper under `bare-optimized`: the dump under the profile's flags (`-O2`) is
/// overruled too, and its evidence names no cause, since no flag among `-O2` suppresses the
/// predefined macros, so it does not blame "a flag among them".
#[test]
fn an_overruled_dump_under_flags_that_silence_nothing_names_no_cause() {
    if !common::ELF_HOST {
        eprintln!("skipped: the overrule needs an ELF artifact of the host's family");
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
    assert!(
        under["evidence"].as_str().is_some_and(|e| e
            .contains("no flag this dump was taken under is one chard knows")
            && e.contains("does not establish")
            && !e.contains("among them suppresses")),
        "the evidence names no cause: {under}"
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

/// The aarch64 cross driver made to emit the other byte order (`-mbig-endian`) and the
/// other width (`-mabi=ilp32`): `-dumpmachine` and the family macro still say aarch64, so
/// the machine comparison agrees, and the width and byte order are what contradict it. The
/// dump names `ELF64 big-endian` or `ELF32 little-endian`; `toolchain.target.abi` reads
/// `disagrees`, one error is published under `toolchain.target`, and every arch-gated check
/// is withheld under `target-abi-contradicted`, the one gated out under aarch64 included.
/// Which branch runs depends on the cross gcc: with a C library (a sysroot) the object probe
/// builds and its artifact carries the width and order, which the artifact arm below holds;
/// without one (a host without one) every probe fails at its first include,
/// no artifact is read, and the dump alone witnesses. Neither run publishes its gated
/// verdicts as aarch64's. The host-gcc test after this one holds the same wiring
/// with no cross compiler.
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

/// The host's own driver behind a wrapper adding `-mx32`: the intrinsic dump names
/// `__SIZEOF_POINTER__` 4 beside `__x86_64__`, so `toolchain.target.abi` reads `disagrees`
/// from the dump alone (no x32 C library on the host, so every probe fails to compile and no
/// artifact is read) and every arch-gated check is withheld under `target-abi-contradicted`.
/// This is the test that holds `main::cross_check_target`'s wiring of the flagless dump's
/// width (`with_intrinsic_abi`) on a host with no cross compiler: dropping that call fails
/// here.
#[test]
fn a_wrapper_adding_mx32_to_the_host_driver_withholds_from_the_dump_alone() {
    if !cfg!(target_arch = "x86_64") || !common::ELF_HOST {
        eprintln!("skipped: -mx32 is an x86_64 driver's flag");
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

/// A target the profile's flags select, on a run that reads no ELF artifact, is witnessed
/// by the macro dump taken under those flags, where `-dumpmachine` and the flagless dump
/// agree with each other by construction.
///
/// The wrapper answers `-dumpmachine` with `riscv64-linux-gnu`, strips the three
/// architecture macros from every dump so the flagless one agrees with that answer, and
/// defines `__x86_64__` in a dump run under `-DCHARD_SELECTS_X86_64`: the shape of a
/// profile carrying `--target=x86_64-linux-gnu` or `-arch x86_64`. `cet-object` is gated
/// to x86, so under riscv64 it builds nothing and no ELF artifact exists. Under `bare` the
/// gate stands with no dump under profile flags to publish; under `explicit` with the
/// sentinel, the dump names `x86_64` and `cet-marked-object` is withheld.
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

/// A target only the profile's C++ flags select, on a run that reads no ELF artifact, is
/// witnessed by the C++ driver's macro dump taken under those flags, where the C dumps
/// under no flags and under the C flags agree with `-dumpmachine`.
///
/// The shape is `--cxxflags -m32` beside plain `--flags`, with a sentinel standing for the
/// flag so the host's own compiler need not target another architecture. `cet-object` is
/// gated to x86 and is a C probe, so under riscv64 it builds nothing and no ELF artifact
/// exists; the C++ dump names `x86_64`, reads `disagrees` with an error diagnostic, and
/// withholds nothing, since no C++ probe was selected. Where no C++ driver sits beside the
/// C one, no C++ probe builds and no C++ dump is taken or published. The corpus's one C++
/// probe gates none of its checks by architecture, so which verdicts the C++ witness
/// withholds is held by `report::tests`, over a corpus-free observation.
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

/// A target the profile's flags select is the one the arch gate reads, from the dump taken
/// under those flags, where `-dumpmachine` names another; the artifacts corroborate it, the
/// flagless dump is `superseded`, and no verdict is withheld.
///
/// Through [`SELECTED_TARGET_SCRIPT`]: under `bare` the gate reads `riscv64` from
/// `-dumpmachine`, as it always did. Under `explicit` with `--target=chard-host`, it reads the
/// host's own architecture from `profile_macros`, every ELF artifact agrees with it (none is
/// read on a Mach-O host), and every arch-gated check gates for that architecture, with no
/// `target-arch-contradicted` and no error diagnostic under `toolchain.target`.
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

/// A run that publishes replaces an earlier report at `-o` and leaves nothing set aside.
///
/// `measure` moves an earlier file at the requested path to `<output>.previous` before it
/// does any work, so a run that ends short of publishing leaves no earlier report there
/// (`tests/error_classes.rs`, `a_measure_that_fails_leaves_no_earlier_report_at_the_output`).
/// This is the other half: the set-aside file outlives only such a run. The earlier file
/// is read-only, as one an operator protected would be, which would make a `measure` that
/// writes through it fail at publication with `PERMISSION` after the whole sweep; the rename
/// does not need the file's own write permission.
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
        Vec::<std::path::PathBuf>::new(),
        "the temporary file was renamed into place"
    );
}

/// A writable earlier report in a directory chard cannot write is replaced by a run that
/// publishes, exit 0.
///
/// `report::set_aside` renames the earlier file, which needs the directory; where that is
/// refused it empties the file in place instead. A `set_aside` that refused the run there
/// with `PERMISSION` before measuring would leave the earlier report at the path and stop a
/// run that can publish.
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
        Vec::<std::path::PathBuf>::new(),
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

/// A toolchain that rejects a regime arm's flag publishes the arm as unevaluable, and the
/// report stands.
///
/// `cet-marked`'s regime arm is built `-O2 -fcf-protection=none`, and gcc 7.5, clang 6.0
/// and 6.0.1 reject the option. An unevaluable arm published with a synthetic
/// `indeterminate` outcome and no reading behind it would have the report refused under
/// `decoded-reading-disagrees-with-facts`, as five `bare-optimized` reports of a fleet sweep
/// were. The wrapper rejects every regime arm's build, whatever its flags, the way those
/// drivers reject the one, so every C check that owes the arm is exercised on the
/// channel it reads. The C++ check that owes one (`cxx-stdlib-assertions`) is not
/// reached: a driver named `fakecc` has no C++ driver beside it.
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

/// A profile flag the driver refuses fails every cell of the probes it reaches as
/// `build-failed` naming the flag, the compiler-diagnostic cells included, under gcc's
/// spelling of a refusal; and where the driver would also refuse a control flag, the
/// profile's refusal is the one published, because the measured build is the subject of
/// the cell. The control flag's own `unsupported` is published only where the measured
/// build stood. `Variant::sufficient_for_measured` carries the rule and its history.
#[test]
fn a_profile_flag_gcc_refuses_is_build_failed_on_the_diagnostic_channel() {
    if !can_run("that a profile flag gcc refuses fails the diagnostic cells too") {
        return;
    }
    // A name with no `gcc`, `clang` or `cc` component, so no C++ driver is found beside it
    // and the run stays about the C driver (see `fake_driver`).
    profile_refusal_is_build_failed("fakegnu", "unrecognized command-line option 'FLAG'");
}

/// [`a_profile_flag_gcc_refuses_is_build_failed_on_the_diagnostic_channel`] under clang's
/// spelling, as its own test so that each family's line is shown to discriminate on its own.
#[test]
fn a_profile_flag_clang_refuses_is_build_failed_on_the_diagnostic_channel() {
    if !can_run("that a profile flag clang refuses fails the diagnostic cells too") {
        return;
    }
    profile_refusal_is_build_failed("fakellvm", "unknown argument: 'FLAG'");
}

/// A profile flag the driver only warns about and goes on without does not fail the
/// build, so a cell whose own diagnostic failed the build keeps its measured verdict, with
/// no `build_rejection`: clang's `warning: unknown warning option` line, and gcc's front
/// end's `note:` that an unknown `-Wno-` option may have been meant to silence earlier
/// diagnostics. The wrapper prints the family's line and hands the build to the host's
/// compiler without the flag, which is what the real driver does with it.
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
                "{name}: {check} failed its build on its own diagnostic, which is the \
                 reading: {o}"
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

/// A specs file that adds an input to every link reaches the measured build and no control
/// arm, and the checks that input decides are withheld under
/// `link-inputs-unmatched-by-arms` rather than read over a triple linked without it.
///
/// The wrapper stands in for a gcc specs file whose `*startfile` names one more object, on
/// any driver: under a `-specs=` naming the marker file it drops the flag and, on every
/// invocation that links (the probe builds and the `-###` listing alike), hands the driver
/// an object compiled without `-fcf-protection` (on x86_64), so the measured link combines
/// an input the arms do not. Without the rule, on Fedora 44 x86_64 with gcc 16.1.1 and
/// clang 22.1.8 (2026-10-06), `cet-marked` reads `off` here over a positive arm linked
/// without that input, where the same profile without the marker reads `on`. Off x86_64 the
/// object carries no feature note to drop and no reading is wrong, and the rule is held
/// all the same, since the listing differs on every target. `linker-default-noexecstack`
/// reads the clean build, which the marker does not reach, and keeps its reading.
#[test]
fn a_startup_input_only_the_measured_link_combines_withholds_the_checks_it_decides() {
    startup_input_withholds("unmarked-input.o");
}

/// [`a_startup_input_only_the_measured_link_combines_withholds_the_checks_it_decides`] with
/// an input whose name has no extension. ld reads such a file as an input object as it
/// reads `crtbegin.o`, and a specs `*startfile` can name one; before the listing was read
/// by position rather than by suffix, this read `cet-marked` `off` with no gating on
/// Fedora 44 x86_64 under gcc 16.1.1 (2026-10-06).
#[test]
fn a_startup_input_without_an_extension_withholds_the_checks_it_decides() {
    startup_input_withholds("unmarked-input");
}

/// A linkage form the profile chooses is normalised in the arms' link listing, not read as a
/// difference. Under a form other than the driver's default, the measured link names one set of
/// startup objects (`crt1.o` and `crtbegin.o` for a position-dependent link, `Scrt1.o` and
/// `crtbeginS.o` for a PIE) and the arms, which carry no form, would name the other, so without
/// the measured form appended to the arms' query every link-input check the probes carry reads
/// `link-inputs-unmatched-by-arms`; with it none does, and `pie` reads the form the profile
/// chose. The form is picked against the driver's own default, read from the `-###` of a bare
/// link: `-no-pie` on a PIE-default driver (Ubuntu's and Debian's), `-fPIE -pie` on one that is
/// not (Fedora's gcc and clang, which take PIE from the rpm macros, not the driver), so the
/// test discriminates on both. This is the test that fails without the line appending the
/// form: bypassing it in `measure::unmatched_link_inputs` leaves every other test binary
/// green.
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
        "no link-input check read a measurement under {form}, so the arms' listing was never \
         shown to match: {observations:?}"
    );
}

/// The body of the two tests above: measure through a wrapper that hands every link an
/// unmarked object named `name` under a marker `-specs=`, and require the checks it
/// decides withheld, counting the observations examined against coverage.
///
/// The set expected withheld is derived, not spelled: every link-input check the selected
/// probes carry whose gate admits the architecture the report says its gates decided under
/// ([`link_input_checks_admitted`]), less the ones the run's kernel withheld first under
/// `needs-vm` (a container the suite recognises; on an unmarked host the measurement asserts
/// `--execution host`, [`measure_establishing_the_kernel`], so the two `needs_vm` checks are
/// examined there). The closing assertion does not name `textrel-absent` as a check "every
/// ELF target reads", which would fail natively on an aarch64 host (Fedora 44 aarch64, gcc
/// 16.2.1, clang 22.1.8) with the verdicts right: `textrel-absent`'s gate admits
/// `x86_64` and `x86` alone, because its positive control is manufactured with
/// `-mcmodel=large`, an x86 code model, so on aarch64 it reads `unsupported` under
/// `arch-gated` before the link-input rule is consulted and is never in the withheld set.
/// That gate conflates the mechanism (the linker's, present on every ELF target: `TEXTREL`
/// is produced there by hand, see "`arch-gated` states an absence chard did not measure" in
/// the project ledger) with the control that discriminates it (x86's). The architecture work
/// that entry records is to settle the conflation and remove `textrel-absent`'s gate on its
/// terms; once it has, the gate should admit aarch64 and `textrel-absent` return to the
/// withheld set here, which this test is expected to follow with no edit. So the expectation
/// follows the gate either way rather than hard-coding one target's answer. On x86_64 three
/// checks, `noexecstack`, `textrel-absent` and `cet-marked`, are required by name below, so a
/// corpus edit that gated one of them away from x86_64 would fail here rather than shrink the
/// derived set quietly.
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
///
/// `needs_vm` is not consulted here: it withholds under a borrowed kernel and measures under
/// the run's own, so whether it fired is the report's to say, and the caller subtracts the
/// checks it did. Every probe named is required to exist, and the set to be non-empty, since
/// a derivation over nothing would make the exact-set assertion vacuous.
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

/// The wrapper of [`a_machine_reading_over_an_artifact_the_reader_refused_is_withheld_on_a_live_run`]:
/// the real driver builds everything, and where it linked an executable the wrapper moves
/// it aside and writes a shell script that execs it in its place, so the probe runs as built
/// while chard's reader refuses the artifact it is handed. The reviewer's shape of the
/// 2026-10-15 review, kept as the one live route to an `unreadable` entry on Linux.
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
  printf '#!/bin/sh\nexec "%s" "$@"\n' "$(realpath "$out.real")" > "$out"
  chmod +x "$out"
fi
exit 0"#;

/// A runtime artifact the reader refuses is a record that holds nothing to the kernel, so a
/// `Machine` reading over it is withheld under `run-under-emulation`, quoting the refusal,
/// on a live run: the Darwin half, where every artifact is Mach-O and an
/// `-arch x86_64` program runs under Rosetta 2 with nothing in the record to say so,
/// exercised on Linux through [`SCRIPT_IN_PLACE_OF_THE_EXECUTABLE`]. It binds
/// `measure::run_check` handing the reader's refusal to the rule, which the unit tests over
/// `settle_emulation` cannot: with the call site handing `None` instead, the reason would
/// say no record was stored. A `Program` reading over the same kind of record is left to
/// its own verdict. The kernel is asserted so the `needs_vm` check reaches the run.
#[test]
fn a_machine_reading_over_an_artifact_the_reader_refused_is_withheld_on_a_live_run() {
    if !can_run("that an artifact the reader refuses withholds a machine reading") {
        return;
    }
    let work = common::Work::new("fakedriver", "unreadable-record");
    let driver = fake_driver(work.dir(), SCRIPT_IN_PLACE_OF_THE_EXECUTABLE);
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
    let (mut machine, mut program) = (0, 0);
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("an observation names its check");
        let basis = chard::probe::CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .find(|c| c.id == check)
            .and_then(chard::probe::Check::run_basis);
        let Some(sha) = o["build"]["artifact_sha256"].as_str() else {
            panic!("{check} built nothing: {o}");
        };
        assert_eq!(
            facts[sha]["kind"].as_str(),
            Some("unreadable"),
            "{check}'s build is a script the reader refuses: {}",
            facts[sha]
        );
        let rule = o["gating"]["rule"].as_str();
        match basis {
            Some(chard::probe::RunBasis::Machine) => {
                machine += 1;
                assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{check}: {o}");
                assert_eq!(rule, Some("run-under-emulation"), "{check}: {o}");
                let reason = o["gating"]["reason"]
                    .as_str()
                    .expect("a withholding carries a reason");
                // The store names the artifact `<artifact>` and the reason names it as
                // built; the refusal's own words are what both carry.
                let refusal = facts[sha]["error"].as_str().expect("the refusal is stored");
                let words = refusal
                    .rsplit(": ")
                    .next()
                    .expect("the refusal has words after the artifact's name");
                assert!(
                    reason.contains("the reader refused it") && reason.contains(words),
                    "{check}: the reason quotes the stored refusal `{refusal}`: {reason}"
                );
            }
            Some(chard::probe::RunBasis::Program) => {
                program += 1;
                assert_ne!(rule, Some("run-under-emulation"), "{check}: {o}");
            }
            None => {}
        }
    }
    assert!(
        machine >= 2 && program >= 1,
        "{machine} machine reading(s) and {program} program reading(s) over refused records"
    );
}

/// [`SCRIPT_IN_PLACE_OF_THE_EXECUTABLE`] with the script printing the line a Darwin probe
/// prints natively, `CHARD-TRANSLATION 0`, before it execs the probe.
const SCRIPT_CLAIMING_A_NATIVE_RUN: &str = r#"out=""; link=1; prev=""
for a in "$@"; do
  case "$a" in -c|-S|-E|-fsyntax-only|-shared|-M|-MM|-dM) link=0;; esac
  [ "$prev" = "-o" ] && out="$a"
  case "$a" in -o?*) out="${a#-o}";; esac
  prev="$a"
done
"$REAL" "$@" || exit $?
if [ "$link" = 1 ] && [ -n "$out" ] && [ "$out" != "-" ] && [ -f "$out" ]; then
  mv "$out" "$out.real"
  printf '#!/bin/sh\necho "CHARD-TRANSLATION 0"\nexec "%s" "$@"\n' "$(realpath "$out.real")" > "$out"
  chmod +x "$out"
fi
exit 0"#;

/// Off macOS the translation line settles nothing on a live run: over the refused record of
/// [`a_machine_reading_over_an_artifact_the_reader_refused_is_withheld_on_a_live_run`], a
/// run whose stdout opens with `CHARD-TRANSLATION 0` is withheld under
/// `run-under-emulation` with the reason that has no translation clause, as without the
/// line. It binds `measure::run_check` handing the platform to the rule: with the call site
/// handing `true`, the stack-clash reading would publish here.
#[test]
fn a_translation_line_off_macos_settles_nothing_on_a_live_run() {
    if !can_run("that a translation line off macOS settles nothing") {
        return;
    }
    let work = common::Work::new("fakedriver", "translation-line-off-macos");
    let driver = fake_driver(work.dir(), SCRIPT_CLAIMING_A_NATIVE_RUN);
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
        ],
    );
    assert_ne!(
        report["environment"]["distro"]["id"].as_str(),
        Some("macos"),
        "the suite's hosts are not macOS"
    );
    let mut machine = 0;
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().expect("an observation names its check");
        let basis = chard::probe::CORPUS
            .iter()
            .flat_map(|p| p.checks.iter())
            .find(|c| c.id == check)
            .and_then(chard::probe::Check::run_basis);
        if basis != Some(chard::probe::RunBasis::Machine) {
            continue;
        }
        let stdout = o["run"]["stdout"].as_str().unwrap_or("");
        if !stdout.starts_with("CHARD-TRANSLATION 0") {
            continue;
        }
        machine += 1;
        assert_eq!(o["verdict"].as_str(), Some("indeterminate"), "{check}: {o}");
        assert_eq!(
            o["gating"]["rule"].as_str(),
            Some("run-under-emulation"),
            "{check}: {o}"
        );
        let reason = o["gating"]["reason"].as_str().expect("a reason");
        assert!(
            reason.contains("the reader refused it") && !reason.contains("proc_translated"),
            "{check}: the Linux reason, without the line's clause: {reason}"
        );
    }
    assert!(
        machine >= 1,
        "no machine reading ran with the line in its stdout"
    );
}

/// A live run with no `--execution` reads the checks that declare `needs_vm` by what chard
/// established about the kernel, before any build: on a host it observes nothing about,
/// `host` on an `assumed-host` basis, each is withheld under `execution-mode-assumed`
/// with the observation quoted and `needs_vm` set; in a container it recognises, under
/// `needs-vm`. Neither basis is the operator's word, so a measured verdict is the one
/// reading this refuses, whichever host runs the suite (its hosts are bare machines and
/// containers; a VM lane asserts `vm`, which chard never observes). Off x86_64 the
/// mechanism table decides `shadow-stack-enforced` first, so only the checks the kernel
/// gate reached are held, and `noexecstack-enforced`, measured on x86_64 and aarch64, is
/// required among them. A default that measured both would let an unrecognised container
/// publish the host kernel's policy under the distribution's name.
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
        (mode, basis) => panic!(
            "a run with no --execution reads {mode:?} on {basis}: chard observes a container \
             or nothing, so only `container` measured or `host` by default can stand here"
        ),
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
        "{held} kernel-policy check(s) reached the kernel gate, noexecstack-enforced among \
         them: {noexecstack}"
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

/// A specs file that puts a header directory ahead of the C library's reaches the measured
/// build and no control arm, and the checks the headers decide are withheld under
/// `compile-inputs-unmatched-by-arms` rather than read over a triple compiled against
/// other headers.
///
/// The wrapper stands in for a gcc specs file whose `*cpp` adds `-isystem`, on any
/// driver: under a `-specs=` naming the marker file it drops the flag and hands every
/// invocation (the probe builds, the macro dumps and the `-###` listings alike) `-isystem`
/// a directory whose `features.h` includes the C library's and then sets
/// `__USE_FORTIFY_LEVEL` to `0`, as a C library declining fortification does. Without the
/// rule, on Fedora 44 x86_64 with gcc 16.1.1 (2026-10-07), `fortify-effective` and
/// `fortify-printf-flag` read `off` here, and `fortify-enforced-known` with them, over
/// positive controls compiled against the host's `features.h`, where the same profile
/// without the marker reads `on`. Off glibc the fortify checks are declared unsupported
/// first and the macro-channel checks hold the rule all the same, since the listing
/// differs on every host. `canary-emitted` reads the probe's own code and keeps its
/// reading.
#[test]
fn a_header_directory_only_the_measured_compile_reads_withholds_the_checks_it_decides() {
    if !can_run("that a header directory the arms lack withholds the checks it decides") {
        return;
    }
    header_directory_withholds("compile-inputs", "", "");
}

/// The same directory named relative to the system root, as a specs file for a cross or
/// sysroot toolchain writes it (`-isystem =dir`), under `--sysroot=/`, which the arms
/// carry as target selection. A comparison that tested every search directory as written
/// and left out one that was not a directory would leave `=dir` out of the measured listing
/// alone, the two listings would be equal, and on Fedora 44 x86_64 with gcc 16.1.1
/// `fortify-effective`, `fortify-printf-flag` and `fortify-enforced-known` would read `off`
/// with no gating, where the absolute spelling above withholds them.
#[test]
fn a_header_directory_under_the_system_root_withholds_the_checks_it_decides() {
    if !can_run("that a sysroot-relative header directory the arms lack withholds the checks") {
        return;
    }
    header_directory_withholds("compile-inputs-sysroot", "=", " --sysroot=/");
}

/// The same declining `features.h` under the profile's own `-isystem`, which every arm
/// carries as the header selection: nothing is withheld under
/// `compile-inputs-unmatched-by-arms`, and the fortify checks the header decides are read
/// over a positive arm the header silenced as it silenced the measured build, never `off`:
/// the positive arm's own artifact reports the request arrived and the C library's headers,
/// as the profile selects them, settled the level at 0, which `fortify-level-declined` reads
/// as `unsupported` (Fedora 44 x86_64, gcc 16.1.1, at the change that took the selection;
/// until then the whole probe was withheld). `fortify-requested`, which the header does not
/// decide, reads `on`. The absolute spelling and the `=dir` one under `--sysroot=/` are
/// both fed.
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

/// A forced include that undefines `_FORTIFY_SOURCE` under the profile's own `-include`,
/// which every arm carries: the driver reads a `-include` after every `-D` and `-U` of the
/// line, so the measured build and both fortify arms compile without the macro, nothing is
/// withheld under `compile-inputs-unmatched-by-arms`, and the seven fortify checks read
/// `probe-invalid` over a silent positive arm, never `off`, as does
/// `strict-flex-arrays-enforced`, whose probe the header leaves without the request it
/// branches on. Every C probe with a compile-input reading is fed, so the claim is held for
/// each check the header decides and not for the four probes the other shapes feed.
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

/// The profile's own `-undef`, which every arm carries: under gcc's `-O2 -undef` the
/// `as-needed` probe builds, its positive arm (`-undef -Wl,--as-needed`) is built without
/// the predefined macros as the measured build is and reads `indeterminate`, and the check
/// reads `probe-invalid` over `positive-indeterminate` where, with the arms built with the
/// macros, it read `off` from a triple that vouched for a compile the measured build did
/// not make (gcc 16.1.1, Fedora 44 x86_64; `-undef` withheld nothing before, since the
/// comparison reads neither its word nor the macros it removes). Under clang `as-needed`
/// reads `off` before and after, both arms discriminating, so the reading this test holds
/// is gcc's, and a clang host asserts nothing and says so.
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

/// [`COMPILE_INPUT_C_PROBES`] is the corpus's own list, derived: every C probe carrying a
/// check of [`COMPILE_INPUT_READINGS`], plus the two fed beside them that carry none
/// (`stack-canary`, whose `canary-emitted` keeps its reading whatever the comparison says,
/// and `strict-flex-arrays`, the sibling the forced-include clause withholds), and no
/// other, so the list cannot go stale beside the corpus without this failing.
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

/// A forced include that undefines `__EXCEPTIONS` under the profile's own `-include`, which
/// every arm carries: `-O2 -fexceptions -include <h>` reads `exceptions-macro`
/// `probe-invalid` over a silent positive arm (the include undefines the macro in the arm
/// built with `-fexceptions` as in the measured build), `except-table-emitted` `on` from the
/// artifact, and nothing withheld under `compile-inputs-unmatched-by-arms`; the register
/// row `legacy-self-report-question-mark-reads-undefined` quotes the reading.
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

/// The converse: a forced include that defines `_FORTIFY_SOURCE` reaches the negative arm,
/// whose `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0` the include overrides (a `-include` is read
/// after every `-D` and `-U`), so the negative arm shows the observable, the triple cannot
/// discriminate, and `fortify-requested` and the checks downstream read `probe-invalid` over
/// `negative-also-shows`, never `on` from a triple that proved nothing.
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

/// A forced include whose effect turns on a macro only the profile defines: under
/// `-O2 -DNDEBUG -D_FORTIFY_SOURCE=3 -include <h>`, `h` undefining `_FORTIFY_SOURCE` under
/// `NDEBUG`, the measured build compiles without the request and the arms, which carry the
/// include and never the profile's macro words, read the header as inert, so the triple
/// discriminates and the fortify checks read `off` of the build the profile makes, not
/// withheld under `compile-inputs-unmatched-by-arms` (the stand-in listing carries the
/// profile's `-D` words beside the include, as the measured line does). The reading is the
/// same kind as under `-D_FORTIFY_SOURCE=3 -U_FORTIFY_SOURCE`, and the same as a system
/// header keyed on a profile macro gives; `toolchain::header_selecting_flags` says so.
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
                "{check}: the build the profile makes has no request, and the arms read the \
                 header as inert: {o}"
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
                "{shape}: {check} read off over a header that reaches the measured build and \
                 the arms alike: {o}"
            );
        }
        if silenced.contains(&check) {
            assert_eq!(
                (o["verdict"].as_str(), o["gating"]["rule"].as_str()),
                (Some(expected.0), expected.1),
                "{shape}: {check} is decided by the header, which silences its positive arm \
                 as it silences the measured build: {o}"
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

/// The profile's own header words publish: under `-O2` with `-pthread`, `-I<dir>`,
/// `-isystem <dir>`, `-idirafter <dir>`, `-iquote<dir>`, `-include <file>` and `-imacros
/// <file>` (an empty directory, a C header, a macro file) nothing is withheld under
/// `compile-inputs-unmatched-by-arms`, every check reads the verdict and level it reads
/// under `-O2` alone, and each arm leads with the word. Were the arms not to take the
/// selection, a profile carrying any of them would withhold every compile-input reading of
/// these probes on gcc, and every word but `-pthread` on clang (Fedora 44 x86_64, gcc 16.1.1 and
/// clang 22.1.8; `measure::arm_flags` has the frame). `-undef` is the eighth word of the selection,
/// and is not fed here: it moves `as-needed` on gcc and nothing on clang
/// (`as_needed_under_the_profiles_own_undef_reads_probe_invalid_on_gcc`). The assembly probe's
/// default check is fed too: it reads the clean build, which carries no header word, so under
/// `-include` a C header it still reads what it reads under `-O2` alone (`measure::clean_flags`).
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
            "{word}: the arms of the published compile-input checks were inspected: \
             {arms_inspected}"
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
/// (`unread`): under either the two macro checks with no twin are withheld
/// (`measure::settle`), and nothing else moves; under `-pthread` nothing is withheld
/// there. Returns `expected`, the `-O2` readings, with those two set to the withholding
/// where `unread`.
fn twinless_under_unread_input(
    report: &Value,
    word: &str,
    unread: bool,
    expected: &[(String, String, String)],
) -> Vec<(String, String, String)> {
    let mut expected_here = expected.to_vec();
    let mut withheld = 0_usize;
    for o in report["observations"].as_array().expect("observations") {
        let check = o["check"].as_str().unwrap_or_default();
        if unread && ["optimization-enabled", "fortify-effective"].contains(&check) {
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
    assert_eq!(
        withheld,
        if unread { 2 } else { 0 },
        "{word}: the twinless macro checks are withheld under a directory or include word alone"
    );
    expected_here.sort();
    expected_here
}

/// The hold's shape for a macro check with no twin, through the profile's own list:
/// `-O0 -DGATE -include h` with `h` defining `__OPTIMIZE__ 1` under `GATE`, and `-O2
/// -DGATE -include h` with `h` undefining it, each read `optimization-enabled`
/// `indeterminate` under `macro-supplied-by-profile`, the reason naming the unread input
/// and the check, where the arms (which carry the include and never `-DGATE`) discriminate
/// and would have vouched for a forged `on` or `off`; `-O0 -DGATE` alone, with no such
/// input, reads `off` as the build is. Any C driver.
#[test]
fn a_profiles_own_include_keyed_on_its_own_macro_cannot_forge_a_twinless_macro() {
    if !can_run("that a keyed forced include cannot forge a macro check with no twin") {
        return;
    }
    let work = common::Work::new("fakedriver", "own-include-twinless");
    let on = work.write("opt.h", "#ifdef GATE\n#define __OPTIMIZE__ 1\n#endif\n");
    let off = work.write("unopt.h", "#ifdef GATE\n#undef __OPTIMIZE__\n#endif\n");
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
    // (tag, flags, withheld under the rule, the self-report's `__OPTIMIZE__` where the
    // build was forged, which a withheld cell still carries in `evidence.macros`)
    let shapes = [
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
        ("plain", "-O0 -DGATE".to_owned(), false, None),
    ];
    let mut fed = 0_usize;
    for (tag, flags, held, forged) in &shapes {
        let dir = work.path(tag);
        std::fs::create_dir_all(&dir).expect("a workdir per shape");
        let report = measure(
            Path::new(&real_cc()),
            &dir,
            &[
                "--profile",
                "explicit",
                "--flags",
                flags.as_str(),
                "--probe",
                "toolchain-macros",
            ],
        );
        assert_schema_valid(tag, &report);
        let (cell, rule) = cell_and_rule(&report, "optimization-enabled");
        if *held {
            assert_eq!(cell["verdict"], "indeterminate", "{tag}: {cell}");
            assert_eq!(rule, Some("macro-supplied-by-profile"), "{tag}: {cell}");
            let reason = cell["gating"]["reason"].as_str().expect("a reason");
            assert!(
                reason.contains("`__OPTIMIZE__`") && reason.contains("`optimization-enabled`"),
                "{tag}: {reason}"
            );
            assert_eq!(
                cell["controls"]["discriminating"], true,
                "{tag}: the arms discriminated; the rule read the list, not the triple"
            );
        } else {
            assert_eq!(cell["verdict"], "off", "{tag}: {cell}");
            assert_eq!(rule, None, "{tag}: {cell}");
        }
        // The header did act on the measured build: its self-report carries the forged
        // macro where the header defined it, and none where it undefined it, so a header
        // the test left inert would fail here rather than pass under a withholding.
        assert_eq!(
            cell["evidence"]["macros"]["__OPTIMIZE__"].as_str(),
            *forged,
            "{tag}: the measured build's self-report: {}",
            cell["evidence"]["macros"]
        );
        fed += 1;
    }
    assert_eq!(fed, shapes.len(), "every shape was fed");
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
    let read = |id: &str| -> &serde_json::Value {
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
/// set, withholds exactly these, as `measure::arm_optimization_classes` classes them.
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

/// A macro operation the driver adds by itself under the profile's optimisation level
/// reaches the measured build and the control arms alike, so the checks the compile's
/// inputs decide are read and not withheld (`src/compile_inputs.rs`'s module note has the
/// Ubuntu measurement this stands in for). The fortify controls carry their own `-O2` and
/// name the macro, and the arms' listing carries the profile's `-O` words as written:
/// under `bare-optimized` (`-O2`) the driver adds the macro to both listings and
/// `fortify-requested` reads the driver's request as the toolchain's, `on` at level 3 from a
/// line that names no `-D`; under `-O0 -O2` likewise; under `-O2 -O0` the driver adds nothing
/// to either and the check reads `off`. Without the carried words every reading of these
/// probes is withheld (the first shape fails at its first observation); with a stand-in
/// hard-wired to `-O2` the third shape is withheld, since the driver would add the macro to
/// the stand-in and not to the measured line; under `bare` nothing is compared and the
/// check reads `off` from a line the driver adds nothing to.
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

/// A header directory the driver adds by itself at the profile's optimisation level alone
/// reaches the measured build and the stand-in at that level, and not the fortify controls,
/// which carry their own `-O2`: the wrapper adds `-isystem` the declining `features.h` of
/// `header_directory_withholds` under `-O3` only, and the profile is `-O3 -D_FORTIFY_SOURCE=3`.
/// The listing at the controls' level lacks the directory, so every check the compile's
/// inputs decide is withheld with the reason naming it, where a stand-in at the profile's
/// level alone would otherwise read `fortify-effective` and its kin `off` over a triple that
/// discriminates.
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

/// A macro no control arm sets, added by the driver with the optimisation level, as a
/// `specs` in a prefix the profile selects with `-B` adds one under `%{O*:...}`: the arms
/// carry the prefix, so the forged `__SSP_STRONG__` reaches the measured build and the
/// stand-in and not the arms that carry no `-O`, whose triple discriminates on its own
/// flags, and `ssp-level` would read a forged `on`. The listing at those arms' level lacks
/// the macro and no control sets it, so every listed check with an arm at another level
/// (`ssp-level` and its kin, `optimization-enabled` for its `-O0` negative) is withheld with
/// the reason naming it, while the fortify checks, whose controls carry `-O2` and so receive
/// it too, are read.
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

/// The converse: a macro no control sets that the driver adds only to a compile that is
/// NOT optimising reaches the arms that carry no `-O` and `optimization-enabled`'s `-O0`
/// negative, and neither the measured build nor the stand-in at the profile's level. The
/// listing at those arms' level carries what the stand-in lacks, so every listed check with
/// an arm at another level is withheld with the reason naming the macro, while the fortify
/// checks, at the profile's level, are read.
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

/// The same unowned macro operations in another order with the level: the driver adds
/// `-DREVIEW_X=1 -UREVIEW_X` under `-O3` and the reverse order otherwise, under an `-O3`
/// profile. No word is on one side alone, so a comparison of the words only on one side
/// admitted it (fix check 1); the sequences with the controls' own macros removed differ,
/// and every listed check, all of whose arms are at another level than `-O3`, is withheld.
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

/// The same macro added under the same `-O2` by a file the profile names still withholds:
/// the arms do not carry the file, so the narrowing is on the optimisation words the arms
/// carry and not on the macro's name.
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

/// `pic-shared-link` under clang's link-time optimization, through the real clang.
///
/// clang's `-flto` writes bitcode and the `-shared` link generates the code, at the
/// position-independence it picks itself: on Fedora 44 x86_64 (clang 22.1.8, GNU ld 2.46.1)
/// `--profile explicit --flags '-O2'` read `off` (`recompile with -fPIC`) and `-O2 -flto`
/// read `on`, over a triple that discriminated, with no `-fPIC` in either. The flag
/// arrives here three ways, each of which the driver's `-###` command resolves to
/// `-flto=full`: on the profile's flags, after a `-fno-lto`, and from a `--config=` file.
/// `-fno-lto` last is no LTO and keeps the reading the non-LTO build gets. Skipped, with
/// the gap announced, where no `clang` is on the PATH.
#[test]
fn a_clang_link_under_lto_is_not_read_as_position_independent_code() {
    if !can_run("that pic-shared-link withholds a link that succeeded under clang's -flto") {
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
    let (plain, _) = read("-O2");
    for flags in [
        "-O2 -flto",
        "-O2 -flto=thin",
        "-O2 -fno-lto -flto",
        config_flags.as_str(),
    ] {
        let (verdict, rule) = read(flags);
        assert_ne!(
            verdict, "on",
            "{flags}: a link that succeeded under LTO is not the code the flags describe \
             (without -flto: {plain})"
        );
        if let Some(rule) = rule {
            assert_eq!(rule, "lto-codegen-at-link", "{flags}");
        }
    }
    // The last word decides: LTO turned off again is the plain build.
    let (verdict, rule) = read("-O2 -flto -fno-lto");
    assert_eq!(
        verdict, plain,
        "-fno-lto last reads as the build without -flto"
    );
    assert_eq!(rule, None);
}

/// `pic-shared-link` under a `-z notext` the link line does not show, through the real `cc`.
///
/// The wrapper stands for a specs or configuration file: it appends `-Wl,-z,notext` to every
/// `-shared` link, so chard's argv never carries it, and it refuses a large-model `-fPIE`
/// link in lld's words, which is what makes the regime arm unable to withhold. Measured
/// 2026-10-11 in the Fedora 44 x86_64 image (gcc 16.2.1 with a specs file and clang 22.1.8
/// with a configuration file, LLD 22.1.8), `-O2 -fno-pic -mcmodel=large -fuse-ld=lld` linked
/// `-shared` with exit 0, an empty stderr and `DT_TEXTREL`, the regime arm was refused with
/// the line quoted below, and the check read `on`. Here the host's own linker takes the
/// hidden flag; GNU ld 2.46.1 links the code in silence with `DT_TEXTREL` set, as LLD does.
/// The shared object's tag is what withholds it. `-O2 -fno-pic` is refused whatever the
/// flag and stays `off`, and `-O2 -fPIC` reads `on` wherever its object carries no tag.
/// Skipped, with the gap announced, off x86_64, where `-mcmodel=large` is not this shape.
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

/// `pic-shared-link` under clang's `-flto` reads `on` where the driver's `-cc1` command
/// resolves the compile to position-independent code without PIE, and only there.
///
/// Measured on Fedora 44 x86_64 (clang 22.1.8): `-flto -fPIC` prints `-mrelocation-model pic
/// -pic-level 2`, `-flto -fpic` the same with `-pic-level 1`, `-flto -fPIE` adds `-pic-is-pie`,
/// and `-flto` and `-flto -fno-pic` print `-mrelocation-model static`; a `--config=` file's
/// `-fPIC` prints as the command-line one does, and the last of `-fPIC` and `-fPIE` decides.
/// The cell's `evidence.observed` quotes those words, and `-fPIE` and `-fno-pic` keep the
/// readings the other compile resolutions give.
/// Skipped, with the gap announced, where no `clang` is on the PATH.
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

/// A driver that writes its diagnostics as SARIF, by a specs file or a configuration file
/// rather than the profile, withholds the compiler-diag checks it would otherwise read off.
///
/// The wrapper answers the measured `warn-all` build with a SARIF document that embeds the
/// probe's source, as gcc 16.1.1 does whenever it reports anything (Fedora 44 x86_64,
/// 2026-10-09: `-O2 -fdiagnostics-format=sarif-stderr` read `warn-all` `on` where `-O2` read
/// `off`). The needle `chard_wall_dead_label` sits on a line of the document, and no `-Wall`
/// is passed. The arms are left alone, so only the measured build is structured. A wrapper
/// that changes nothing is the control: the same run reads `off`.
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

/// A failed `--fail-on-missing` names, on stderr after the report, each check that failed
/// it: here the macro checks a failing dump withheld and every corpus check `--probe` did
/// not select, by id, re-derived from the report it wrote and the corpus `chard probes`
/// lists. Without the flag the same run exits 0 and names nothing.
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
        "the failing dump withheld no verdict, so the unsettled half is not exercised: \
         stderr was:\n{stderr}"
    );

    let mut after_report: Vec<&str> = stderr
        .lines()
        .skip_while(|l| !l.starts_with("chard: report written"))
        .skip(1)
        .collect();
    assert_the_gate_block_closes(&mut after_report, &expected);
    let mut want = vec![format!(
        "chard: --fail-on-missing: {} of the corpus's {} checks are not attempted or not \
         settled; this run selected {} with --probe, and the gate counts the whole corpus",
        expected.len(),
        corpus.len(),
        report["coverage"]["checks_expected"]
    )];
    want.extend(
        expected
            .iter()
            .map(|(_, line)| format!("chard: --fail-on-missing: {line}")),
    );
    assert_eq!(
        after_report, want,
        "the lines after the report name each check that failed the gate, by id, with its \
         reason"
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
///
/// Refuses a run that contradicted itself or published a contradiction, as
/// [`measure_probes_under`] does, and hands back the status so a test can hold it to 0.
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
///
/// The test's own reading, written apart from chard's reader: a line opening `tool:`,
/// carrying the flag between quotes, and no `warning:` or `note:`.
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

/// A compile flag the real driver rejects, from `--profile explicit`, is one diagnostic
/// naming the operator as its source, the tool, the flag and the cells it withheld, and the
/// run still exits 0 (the shape measured on Fedora 44 x86_64, gcc).
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

/// Two compile flags the real driver rejects in one build, one line each, are two
/// diagnostics, each counting every cell: the second is named though each cell's
/// `build_rejection` names only the first.
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

/// A linker option the real linker rejects, from `--profile explicit --ldflags`, is one
/// diagnostic under the linker's name and spelling, and the run exits 0.
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

/// A built-in profile on a driver that lacks one of its flags is measured and published,
/// not refused, and its diagnostic says this toolchain rejects a flag the named profile
/// supplies.
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

/// A built-in profile on a driver that lacks two of its flags names both, the shape of an
/// older gcc under `openssf-tldr`.
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

/// Two flags rejected in different cells are two diagnostics, the one withholding more
/// cells first, whatever order the profile names them in; a run with no refusal has none.
#[test]
fn two_rejected_flags_are_two_diagnostics_in_a_fixed_order_and_none_is_none() {
    if !can_run("that two rejected flags give two diagnostics in a fixed order") {
        return;
    }
    let work = common::Work::new("fakedriver", "rejected-two");
    // A measured build carries both flags; the driver names `-fzzz-one` for the no-plt
    // probe's source and `-fzzz-two` for every other, so each flag withholds its own cells.
    // A control arm carries neither and goes through.
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

/// `measure` never exits without its closing line, on each path a run can end on short of a
/// contradiction (which no run reaches without a defect in chard; `closing_line`'s unit
/// tests hold those two lines): a report written to the default file in the current
/// directory, named from the compiler and the profile, then again over it with the earlier
/// one set aside and removed; the report to stdout under `-o -`, leaving the file alone; the
/// gate; a failure after the set-aside, naming the earlier report kept; a refusal before it;
/// and a command line clap refuses.
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
    let on_stdout: Value =
        serde_json::from_slice(&streamed.stdout).expect("-o - puts the report on stdout");
    assert_eq!(
        std::fs::read(&default).expect("the default report"),
        before,
        "-o - leaves the default file alone"
    );
    let line = closing_line_of(&streamed);
    let counts = closing_of_a_published_run(&on_stdout, "X", "wd", "0", false);
    let counts = &counts[counts.find(" (").expect("counts")..counts.find(';').expect("end")];
    assert_eq!(
        line,
        format!(
            "chard: measure exits 0: sent the report to stdout{counts}; work directory wd \
             kept; next: chard table on a file holding what stdout received"
        )
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
        closing_line_of(&failed),
        "chard: measure exits 2: refused or failed, the envelope on stdout says why; r.json \
         holds no report from this run, and the earlier report is kept as r.json.previous; \
         work directory wd kept; next: the envelope's hint"
    );
    assert_eq!(
        std::fs::read_to_string(work.path("r.json.previous")).expect("kept"),
        "earlier\n"
    );
    // An older run's `.previous`, with nothing at the path: this run set nothing aside, and
    // its line names none.
    std::fs::write(work.path("s.json.previous"), "older\n").expect("an older run's file");
    let failed = run(&["--cc", "./no-such-cc", "--workdir", "wd", "-o", "s.json"]);
    assert_eq!(failed.status.code(), Some(2), "{failed:?}");
    assert_eq!(
        closing_line_of(&failed),
        "chard: measure exits 2: refused or failed, the envelope on stdout says why; s.json \
         holds no report from this run, and an older run's s.json.previous is beside it; work \
         directory wd kept; next: the envelope's hint"
    );

    let refused_line = "chard: measure exits 2: refused or failed, the envelope on stdout says \
                        why; refused before the run started, so an earlier report is where it \
                        was and nothing was built; next: the envelope's hint";
    let refused = run(&["--cc", cc, "--workdir", "wd2", "--probe", "no-such-probe"]);
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
    assert_eq!(closing_line_of(&refused), refused_line);
    assert!(!work.path("wd2").exists(), "nothing was made");

    let usage = run(&["--no-such-option"]);
    assert_eq!(usage.status.code(), Some(2), "{usage:?}");
    assert_eq!(closing_line_of(&usage), refused_line);
}

/// `chard digest` prints the block a report leads with and nothing else, and refuses the
/// reports `table` refuses: one whose digest is not the one its own fields give, and one
/// with no digest, which `table` refuses too. Every reader holds the report's
/// `chard_schema` and its digest's presence before any rule
/// ([`every_reader_refuses_another_chard_schema_and_a_missing_digest`]). The `weaken`
/// check's polarity reaches `table`'s legend and `matrix`'s cell.
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
///
/// A reader that did not compare the field would render a gcc `bare` report with its digest
/// removed and `chard_schema` `"99"` through `table` with exit 0.
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
///
/// The stripping is what a tool run after the link does (`objcopy --remove-section`); no
/// spec or configuration file reaches a linked program after the link, and every probe
/// with a macro-channel check references the section from its code, so a linker does not
/// collect it (`tests/probe_sources.rs`). The dump-only `lie` is the `*cpp_options`-only
/// spec shape `DESIGN.md` describes, which the artifact's own section would show up
/// and a stripped artifact cannot. The compile-only, preprocess-only and query
/// invocations are passed through untouched, so `toolchain::detect`'s listings are the
/// real driver's; its own `-dM -E` dumps take the lie too, which is the spec-file shape.
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
    let reason = obs["gating"]["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("and no `.chard.report`") && reason.contains("`-dM -E` dump's alone"),
        "{check}: {reason}"
    );
    assert_eq!(
        obs["evidence"]["macro_source"], "preprocessor",
        "{check}: the macros were the dump's, and the report says so: {}",
        obs["evidence"]
    );
    assert_eq!(
        obs["controls"]["discriminating"], true,
        "{check}: the arms are dump readings and discriminate; the gate is on the measured \
         build, not a probe-invalid: {}",
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

/// A driver that removes `.chard.report` after each link withholds every macro-channel
/// verdict of a probe that embeds it, and a `-fstack-protector-strong` handed to the
/// `-dM -E` job alone does not publish `ssp-level` `strong` beside `canary-emitted` `off`.
///
/// The shape is a driver wrapper that strips the section after each link. Read from the dump,
/// it publishes six macro checks of `toolchain-macros` `off` and one `on` at
/// `confidence: high` with `discriminating: true`, and under the dump-only flag `ssp-level`
/// `on`, level `strong`, beside `canary-emitted` `off`, with `consistency.status`
/// `consistent` and exit 0 (Fedora 44 x86_64, gcc 16.1.1, 2026-10-20). The only mark of the
/// strip is then one warning, and under the dump-only flag one `CHANNELS DISAGREE` error
/// diagnostic beside it, which moves neither the status nor the exit. Every macro check over
/// the stripped artifact is `indeterminate` under `artifact-lacks-self-report`, the warning
/// says the artifact lists no such section, the elf-static reading over the same artifact
/// stands, and the group does not disagree.
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
        "the dump the wrapper lied to is what the withheld reading carries (the value is the \
         compiler's: gcc defines `__SSP_STRONG__` as 3, clang as 2): {}",
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

/// A C++ driver that removes `.chard.report` after each link and defines
/// `_GLIBCXX_ASSERTIONS` for the `-dM -E` job alone reads `cxx-hardening-requested`
/// `indeterminate`, not `on`.
///
/// A real toolchain reaches this shape where a probe source does not reference its report:
/// a `--gc-sections` link on a compiler without `retain` drops the section and the dump
/// stands in. Read from the dump, this wrapper publishes `cxx-hardening-requested` `on` at
/// `confidence: high` beside `cxx-stdlib-assertions` `off` and `cxx-assertions-symbol` `off`
/// (Fedora 44 x86_64, g++ 16.1.1, 2026-10-20), the two artifact channels reading the code the
/// dump lies about. The runtime and elf-static readings over the same artifact stand.
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

/// A driver that leaves an artifact chard's ELF reader refuses, or none at all, with a
/// `-fstack-protector-strong` handed to the `-dM -E` job alone, reads every macro check
/// `indeterminate` under `artifact-lacks-self-report`, not `ssp-level` `on`.
///
/// The other half of the gate: the artifact gates inside `settle` read the artifact's
/// facts, and here there are none. Without that half, both wrappers publish `ssp-level` `on`,
/// level `strong`, from the dump beside an error diagnostic naming only the elf-static checks
/// as withheld (Fedora 44 x86_64, gcc 16.1.1). On macOS the dump is
/// read by design over a Mach-O object the reader refused, and over nothing else it
/// refused (`report::artifact_account_missing`); the refused ELF below is withheld there
/// too, which `a_refused_elf_artifact_on_a_macos_run_is_no_by_design_dump_reading` holds.
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
        assert_eq!(
            ssp["gating"]["rule"], "artifact-lacks-self-report",
            "{tag}: {ssp}"
        );
        let reason = ssp["gating"]["reason"].as_str().expect("a reason");
        assert!(reason.contains(says), "{tag}: {reason}");
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
            ssp["evidence"]["macros"]["__SSP_STRONG__"].is_string(),
            "{tag}: the lie reached the dump: {ssp}"
        );
        assert!(
            lies_told(&log) > 0,
            "{tag}: the wrapper never saw a -dM job"
        );
        let mut withheld = 0;
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

/// A measured artifact whose report says every macro is undefined is the artifact's own
/// account: `measure` keeps it over the dump as an empty map, the macro checks read `off`
/// from it with `macro_source: compiled-artifact`, and `chard detect` replays the same
/// reading from the stored facts.
///
/// `measure` and `detect` read such a report the same way, rather than `measure` dropping it
/// for the dump while `detect` reads no macros, two readings of one input. The wrapper rewrites the
/// section of the measured build alone, so the control arms keep the compiler's own report and the
/// triple discriminates; an honest dump beside it defines none of the watched macros under
/// `bare-optimized`, so the two views agree.
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

/// A driver that removes `.chard.report` from one control arm's program alone leaves the
/// measured verdict the artifact's own reading, and the arm says it read the dump in its
/// own `macro_source`, the one mark the loss leaves.
///
/// The gate `artifact-lacks-self-report` is on the measured build
/// (`report::self_report_limitation`): an arm without its section is a dump reading whose
/// outcome the triple takes as it is, and no warning names an arm's artifact, since
/// `measure::evidence_faults` reads the measured build's. The register entry
/// `self-report-absent-withholds-the-macro-channel` names that as the residual this test
/// holds. The wrapper keys on the variant's name in `-o`, which `-dM -E` jobs do not carry,
/// so the arm's dump is the compiler's own.
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

/// A probe with no macro-channel check that embeds `.chard.report` publishes the same
/// verdicts and levels with the section and without it, and the per-probe warning is the
/// one mark the loss leaves.
///
/// Such a probe carries the section as provenance, and most never reference it from code,
/// so a `--gc-sections` link on a compiler without the `retain` attribute (gcc before 11,
/// clang before 13) can drop it, as it can drop the C++ probe's. Their
/// checks read the artifact or the run. The section reaches the fortify runtime detectors,
/// which credit a trap to fortify-headers or Apple's implementation (`decode::runtime`'s
/// `fortify_impl`) or name a library without subobject bounds from it, withhold without it,
/// and do not arise on a glibc host; and the declared family's choice among the reasons for
/// a `probe-invalid`.
/// The wrapper overwrites the section of every linked program, the arms' included, with
/// as many zero bytes, so the section holds no report and the program's layout is the
/// one the linker wrote; an object-mode probe's `-c` output keeps its section, and the
/// warning is expected exactly where the measured build's artifact was read. Removing the
/// section instead (`objcopy --remove-section`) rewrites the program's layout, and on
/// Fedora 44 x86_64 under gcc 16.1.1 on 2026-10-20 it moved `link-defaults`' `relro` from
/// `partial` to `probe-invalid`: a reading of the segments the rewrite moved, not of the
/// section.
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

/// The macOS exemption is the reader's Mach-O finding on a macOS run, never the platform
/// alone: an ELF artifact the reader refused, in a report that says macOS, is an artifact
/// that gave no account, and a macro measurement over it is refused on read.
///
/// No macOS run can be had on this host, so the shape is planted in the report. A driver
/// overwrites each linked program with an ELF identification the reader refuses
/// ([`REFUSED_ELF`]), `measure` withholds `ssp-level` under `artifact-lacks-self-report`,
/// and the report is then edited to say `macos` and to publish `ssp-level` `on` from the
/// dump, as a macOS run with an ELF cross-compiler does. An exemption keyed on
/// `environment.distro` alone would leave `macro-verdict-unearned-by-artifact` silent over
/// that report; it fires. The same report with the `unreadable` entry
/// marked `mach_o`, the reader's finding over a Mach-O object, is the by-design reading and
/// the rule is silent, as it is off macOS over the edited verdict with `mach_o` unset.
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
    assert_eq!(ssp["gating"]["rule"], "artifact-lacks-self-report", "{ssp}");
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
/// `-D`. A build at level 2 then reads in force under a bar of 2 and absent under 3, so each
/// row tells the readings apart: musl's headers under a musl triple with a refusing driver
/// hold the library's 2; the same headers under a glibc-configured triple (Fedora's
/// `musl-gcc` shape) set no bar; a driver configured against a glibc older than 2.35 asks 2
/// over newer headers, where the library would ask 3; a driver that warned it yielded sets no
/// bar from its dump, so the library's 3 stands; a driver whose control defines the same 2
/// (a specs `-D` under `-w`) sets none either; a driver whose `-fhardened` raises a default of
/// 2 to 3 over musl's headers holds the build to 3; and so does one asking 3 with no default.
/// A `measure` that read the headers alone fails the third, sixth and seventh rows, one that
/// read the dump without its diagnostic the fourth, one without its control the fifth, one
/// that refused every control defining a level the sixth, and one that dropped the triple the
/// first two. Every row's note names the reading that set its bar.
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

/// A link that clears a marking the probe's own object carries is read from that object.
/// The wrapper adds one input compiled with the protection off to every link with a source
/// on it, so the linked positive control reads absent while the same arm compiled and not
/// linked reads present, and the cell is withheld under `link-drops-marking`, naming the
/// unlinked object, rather than read from the linked arm alone.
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

/// The link-input rule compares the measured link with the arms' only for a check that reads
/// the profile's build: under `-pg`, which adds a startup object the arms do not link,
/// `noexecstack` is withheld under `link-inputs-unmatched-by-arms`, and
/// `linker-default-noexecstack`, which reads the toolchain's default build, is not.
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

/// A clean build that would link through a linker the measured build never chose is
/// withheld under `clean-link-unmatched-by-measured`, and the reason names the prefix that led
/// it there. The route is one the input tables do not read: under `-O2 --chard-test-pair
/// -B<dir>/` the wrapper drops the pair, so the measured build takes no prefix, while chard
/// reads `-B<dir>/` as the profile's search prefix and hands it to the clean build, which
/// links through `<dir>/ld`, an `ld` that gives every program an executable stack. The
/// arms carry the prefix too and pass the stack mode, so the triple discriminates over the
/// clean build's `off`: the wrong `off` this rule withholds, as `-u -B<dir>/` read it on
/// clang 22.1.8 before the value-taking table (`toolchain::Hand::Value`).
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

/// Where the clean build and the measured build would link alike, the clean build's reading
/// stands, and it follows the linker both run: under `-O2 -B<dir>/`, a prefix both builds
/// carry, `linker-default-noexecstack` reads `on` through an `ld` there that passes every
/// link through and `off` through one that gives every program an executable stack, each
/// over a discriminating triple and with no gating.
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

/// A library directory the clean build alone searches is withheld too, though it reaches
/// neither `-print-search-dirs` list: under `-O2 --chard-test-pair -L<dir>` the measured
/// build takes no directory, while the clean build reads `<dir>`'s copy of the C library's
/// `libc.so` script, which adds an object asking for an executable stack, and reads `off`
/// over a discriminating triple without the link line's directories compared.
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

/// An answer the driver cannot give withholds as a difference does: under `-O2 -B<dir>/`,
/// which both builds carry and so agree on, a driver that answers `-print-search-dirs` with
/// nothing or with one list, or refuses it for every build or for the clean build alone,
/// reads `linker-default-noexecstack` `indeterminate` under `clean-link-unmatched-by-measured`,
/// the reason naming the side and the answer it could not read.
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
    for (name, answer, side, said) in [
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
        let reason = o["gating"]["reason"].as_str().expect("a gating's reason");
        assert!(
            reason.contains(&format!("{side}the driver")) && reason.contains(said),
            "{name}: {reason}"
        );
    }
}

/// A linker the profile selects by `--ld-path=` reaches both link lines the rule compares,
/// so it agrees and the clean build's reading stands: under clang `-O2 --ld-path=<dir>/ld`
/// the arms link through `<dir>/ld` and `linker-default-noexecstack` reads `on` with no
/// gating. Compared against the clean build's own line instead, which carries no program
/// selection, the two programs would differ on every such profile.
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

/// A measure names the execution mode it was told, and publishes only the diagnostics its
/// run earned: a run of agreeing groups, with no `--structured-diagnostics` and no
/// probe-invalid cell, carries no error, no structured-diagnostics warning and no
/// probe-invalid count.
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

/// A cell whose positive control the driver did not honour is probe-invalid, and the run
/// counts it in a warning: the wrapper drops every `-fstack-protector` word, so the forced
/// stack protector is not there to see.
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

/// `chard table` over two reports of one corpus is one dataset, so a flag one of them did
/// not measure reads `.`; over a report of another corpus (the checked-in sample with its
/// corpus digest, and the digest's copy of it, rewritten, so the test holds whichever
/// revision wrote the sample) it refuses without `--allow-mixed`, and with it a flag outside
/// a report's corpus reads `~`.
#[test]
fn the_table_reads_whether_its_reports_share_a_corpus() {
    if !can_run("that the table reads whether its reports share a corpus") {
        return;
    }
    let work = common::Work::new("fakedriver", "table-corpora");
    let driver = PathBuf::from(real_cc());
    let measured = |name: &str, profile: &str, probe: &str| {
        let report = measure_probes_under(
            &driver,
            &work.path(&format!("w-{name}")),
            &["--profile", profile],
            &[probe],
        );
        let path = work.path(&format!("{name}.json"));
        std::fs::write(&path, report.to_string()).expect("writing a report");
        path
    };
    let links = measured("links", "bare", "link-defaults");
    let copies = measured("copies", "bare-optimized", "copy-dt-needed");
    let table = |inputs: &[&Path], mixed: bool| {
        let mut args: Vec<&OsStr> = vec![
            OsStr::new("table"),
            OsStr::new("--format"),
            OsStr::new("markdown"),
        ];
        if mixed {
            args.push(OsStr::new("--allow-mixed"));
        }
        args.extend(inputs.iter().map(|p| p.as_os_str()));
        Command::new(chard_binary())
            .args(&args)
            .output()
            .expect("spawning chard table")
    };
    let row = |out: &std::process::Output, label: &str| -> String {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find(|l| l.starts_with(&format!("| `{label}")))
            .unwrap_or_else(|| panic!("no {label} row: {}", String::from_utf8_lossy(&out.stdout)))
            .to_owned()
    };
    let one = table(&[&links, &copies], false);
    assert_eq!(
        one.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&one.stderr)
    );
    let copied = row(&one, "-Wl,--no-copy-dt-needed-entries");
    assert!(
        copied.contains(" . |") && !copied.contains(" ~ |"),
        "{copied}"
    );

    let mut other: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-report.json"),
        )
        .expect("the sample fixture reads"),
    )
    .expect("the sample fixture is JSON");
    let corpus = serde_json::json!("cd".repeat(32));
    other["run"]["probe_corpus_sha256"] = corpus.clone();
    other["digest"]["run"]["probe_corpus_sha256"] = corpus;
    let sample = work.path("other-corpus.json");
    std::fs::write(&sample, other.to_string()).expect("writing the other corpus's report");
    let refused = table(&[&sample, &links], false);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("these reports are not one dataset"),
        "{}",
        String::from_utf8_lossy(&refused.stdout)
    );
    let mixed = table(&[&sample, &links], true);
    assert_eq!(
        mixed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&mixed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&mixed.stdout)
            .lines()
            .any(|l| l.contains(" ~ |")),
        "{}",
        String::from_utf8_lossy(&mixed.stdout)
    );
}

/// A linker whose banner names no kind chard recognises, and whose every output carries a
/// linker's signature, is published as known from its artifacts alone, in a warning. The
/// shim answers `--version` with an unknown banner, links with the host's `ld`, and stamps
/// `Linker: LLD 22.1.8` into each output's `.comment`.
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

/// A driver that forges `__CET__` into the measured build alone, by `-D` and by a forced
/// include gated on a profile-only macro, reads `cet-macro` `indeterminate` under
/// `macro-contradicted-by-artifact` ([`assert_cet_macro_withheld_by_its_artifacts`]).
///
/// The forged-marking shape: `-O2 -fcf-protection=none -DGATE -include h` with `h`
/// defining `__CET__ 3` under `GATE` read `cet-macro` `on` at `full` over discriminating
/// arms beside `cet-marked` and `cet-endbr-emitted` `off`, and the report published it
/// beside a `CHANNELS DISAGREE` error (gcc 16.1.1, Fedora 44 x86_64, 2026-10-28). Here the
/// route is a wrapper, which the arms' listing comparison cannot see, so the twin rule is
/// what withholds it on this main.
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

/// The same forced include in the profile's own list, which every arm carries as the header
/// selection (`measure::arm_flags`): `-O2 -fcf-protection=none -DGATE -include h` with `h`
/// defining `__CET__ 3` under `GATE`. The arms carry the include and never the profile's
/// `-D`, so the header is inert there, the triple discriminates, and the measured build's
/// self-report says `__CET__` while its objects were compiled without the protection: the
/// forged `on` the arms cannot see, held by the twin rule as the wrapper's is
/// ([`assert_cet_macro_withheld_by_its_artifacts`]). The arms carry the include, so
/// `compile-inputs-unmatched-by-arms` does not withhold the reading on a listing difference,
/// and the fortify checks of the same run read of the build the profile makes, as under any
/// profile with `-O2` and no request.
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

/// The same macro in the profile's own list is the input layer's: `cet-macro` is withheld
/// under `macro-supplied-by-profile`, consulted first, and the twin rule reads a reading
/// already withheld as nothing to hold.
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

/// A driver that hardens only the builds whose names it recognises reads the macro channel
/// `on` from a hardened executable and `ssp-level-emitted` `off` from an object it left
/// alone, and the macro reading is withheld under the twin rule, the reason naming the
/// reading that contradicts it as such and the one that agrees as agreeing.
///
/// `THREAT_MODEL.md`'s redirected-toolchain row, whose wrapper hardens `-clean` and
/// `-measured` outputs, can publish seven forged `on` verdicts beside an error saying they
/// should not be published. The wrapper here forces the other builds to
/// `-fno-stack-protector` ahead of their own flags, so the shape is the same on a host
/// whose driver defaults to the protector; a control arm's own flag, later on the line,
/// still wins.
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

/// A driver whose own `-isystem` puts a `features.h` that declines fortification ahead of
/// the C library's reads the fortify checks `unsupported` under `fortify-level-declined`,
/// and the reason names the C library's headers as the profile selects them, not "this
/// libc": the library that declined is the one the selection chose.
///
/// The shape is the forged marking's `shim-*` reproduction with the selection moved from the
/// profile, where `compile-inputs-unmatched-by-arms` withholds it on this main, to the driver,
/// which every arm goes through. glibc's `features.h` is the one the shim wraps, so the test asks
/// for glibc.
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
        let reason = cell["gating"]["reason"].as_str().expect("a reason");
        assert!(
            reason.contains("the C library's headers, as the profile selects them, declining")
                && reason.contains("`__USE_FORTIFY_LEVEL=0`")
                && !reason.contains("this libc"),
            "{check}: {reason}"
        );
    }
    let (requested, rule) = cell_and_rule(&report, "fortify-requested");
    assert_eq!(
        requested["verdict"], "on",
        "the request is read as made: {requested}"
    );
    assert_eq!(rule, None);
}

/// A profile that defines a macro a probe's own source branches on has that probe's
/// runtime reading withheld under `macro-supplied-by-profile`, the reason naming the macro
/// and the probe, beside the macro check the spoof clause withholds.
///
/// `ub_signed_overflow.c` prints `optimize=` from `__OPTIMIZE__`, which its decoder reads;
/// `-O0 -D__OPTIMIZE__=1` makes it say the optimiser ran over a build it did not, and without
/// this rule only `optimization-enabled` would be withheld (gcc 16.1.1, Fedora 44 x86_64).
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
