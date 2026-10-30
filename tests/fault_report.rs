// SPDX-License-Identifier: BSD-3-Clause

//! The fault reporter in `probes/chard_selfreport.h`, exercised on the host.
//!
//! `tests/fault_classes.c` provokes one fault per build. Each case is built, run through
//! [`chard::run::execute`] exactly as a probe is, and the record's [`RunRecord::fault`]
//! read back: the C half (what the handler writes, and that the process still dies by
//! the signal it took) and the Rust half (how the line is classified) are held together
//! here, on whatever hardware runs the suite. The unit tests in `src/run.rs` hold the
//! classification to lines measured on each architecture; this file is where a line is
//! produced.
//!
//! What runs is decided by the host: the x86 cases on x86_64, the aarch64 cases on
//! aarch64, and the BTI and PAC cases only where the kernel lists `bti` and `paca`. No
//! gate in this repository runs on aarch64, so the aarch64 cases run only where someone
//! runs the suite on aarch64 Linux by hand. A case the host cannot run says so on stderr,
//! which `cargo test` hides; set `CHARD_REQUIRE_FAULT_CASES=1` (read by this test alone)
//! to make every such skip a failure, so a run meant to cover the aarch64 path cannot
//! pass without it.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use chard::probe;
use chard::run::{self, Fault, FaultArch, RunRecord};

const SOURCE: &str = include_str!("fault_classes.c");

/// Whether a skip is a failure for this run.
fn required() -> bool {
    std::env::var_os("CHARD_REQUIRE_FAULT_CASES").is_some_and(|v| v == "1")
}

/// A case group this host cannot run: said on stderr, or a failure when required.
fn skip(why: &str) {
    assert!(!required(), "CHARD_REQUIRE_FAULT_CASES=1, and {why}");
    eprintln!("{why}");
}

/// Whether the kernel lists `feature` for this CPU. An unreadable `/proc/cpuinfo` is a
/// failure, not a CPU without the feature: on Linux the file is always there.
fn cpu_has(feature: &str) -> bool {
    let info = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_else(|e| panic!("reading /proc/cpuinfo: {e}"));
    info.lines()
        .filter(|line| line.starts_with("Features"))
        .any(|line| line.split_whitespace().any(|word| word == feature))
}

/// Build `case` with `cc` and `flags`, run it as chard runs a probe, return the record.
fn provoke_with(work: &common::Work, cc: &str, case: &str, flags: &[&str]) -> RunRecord {
    work.write(probe::SELFREPORT_HEADER_NAME, probe::SELFREPORT_HEADER);
    let source = work.write("fault_classes.c", SOURCE);
    let bin: PathBuf = work.path(&format!("fault-{cc}-{case}-{}", flags.len()));
    let mut build = Command::new(cc);
    build.arg("-O2");
    if cfg!(target_arch = "aarch64") {
        build.arg("-mbranch-protection=standard");
    }
    let out = build
        .args(flags)
        .arg(format!("-DCHARD_FAULT_CASE=\"{case}\""))
        .arg("-I")
        .arg(work.dir())
        .arg("-o")
        .arg(&bin)
        .arg(&source)
        .output()
        .expect("spawning the compiler");
    assert!(
        out.status.success(),
        "{cc} could not build the {case} case:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    run::execute(&bin, work.dir(), Duration::from_secs(10), &[]).expect("running the case")
}

fn provoke(work: &common::Work, case: &str) -> RunRecord {
    provoke_with(work, "cc", case, &[])
}

/// The case dies by `signal`, its report names this architecture, and it classifies as
/// `fault`; `trapped()` agrees.
fn expect_with(
    work: &common::Work,
    cc: &str,
    case: &str,
    flags: &[&str],
    signal: &str,
    fault: Fault,
) -> RunRecord {
    let run = provoke_with(work, cc, case, flags);
    assert_eq!(
        run.signal.as_deref(),
        Some(signal),
        "{case}: the handler re-raises, so the death is the signal taken; record: {run:?}"
    );
    let arch = if cfg!(target_arch = "aarch64") {
        FaultArch::Aarch64
    } else {
        FaultArch::X86_64
    };
    assert_eq!(
        run.fault_report().map(|r| r.arch),
        Some(arch),
        "{case}: {:?}",
        run.stderr
    );
    assert_eq!(run.fault(), Some(fault), "{case}: {:?}", run.stderr);
    assert_eq!(run.trapped(), fault == Fault::CompilerTrap, "{case}");
    run
}

fn expect(work: &common::Work, case: &str, signal: &str, fault: Fault) -> RunRecord {
    expect_with(work, "cc", case, &[], signal, fault)
}

/// Whether `program` runs here.
fn on_path(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The cases every architecture shares.
fn shared_cases(work: &common::Work, trap_signal: &str) {
    // A segv and a jump to an unmapped address: no word is read where si_addr is not the
    // pc, or where the pc cannot be read.
    let segv = expect(work, "segv", "SIGSEGV", Fault::Other);
    assert_eq!(segv.fault_report().and_then(|r| r.word), None);
    let wild = expect(work, "jump-unmapped", "SIGSEGV", Fault::Other);
    let report = wild.fault_report().expect("a report");
    assert_eq!(
        (report.pc, report.addr, report.word),
        (16, 16, None),
        "{report:?}"
    );
    // A trap away from the declared target says so.
    let elsewhere = expect(work, "trap-elsewhere", trap_signal, Fault::CompilerTrap);
    assert_eq!(
        elsewhere.fault_report().and_then(|r| r.at_target),
        Some(false)
    );
    // Signals the probe sends itself: kill (SI_USER, 0) and raise (SI_TKILL, -6).
    let sent = expect(work, "kill", "SIGILL", Fault::Other);
    assert_eq!(
        sent.fault_report().map(|r| (r.sent, r.code)),
        Some((true, 0))
    );
    let raised = expect(work, "raise", "SIGILL", Fault::Other);
    assert_eq!(
        raised.fault_report().map(|r| (r.sent, r.code)),
        Some((true, -6))
    );
    // A read past the end of a mapped empty file.
    expect(work, "bus", "SIGBUS", Fault::Other);
    // A sanitizer trap the compiler emitted, from every compiler here.
    let sanitize = [
        "-fsanitize=signed-integer-overflow",
        "-fsanitize-trap=signed-integer-overflow",
    ];
    expect_with(
        work,
        "cc",
        "overflow",
        &sanitize,
        trap_signal,
        Fault::CompilerTrap,
    );
    if on_path("clang") {
        let clang = expect_with(
            work,
            "clang",
            "overflow",
            &sanitize,
            trap_signal,
            Fault::CompilerTrap,
        );
        if cfg!(target_arch = "x86_64") {
            // clang's trap is ud1 behind an address-size prefix: the bytes must reach
            // the classifier whole, prefix included.
            let word = clang.fault_report().and_then(|r| r.word).unwrap_or(0);
            assert_eq!(word & 0xff_ffff, 0xb9_0f67, "{word:#x}");
        }
    } else {
        skip("clang is not on PATH; the clang sanitizer trap did not run");
    }
}

#[test]
fn each_fault_the_host_can_provoke_is_reported_and_classified() {
    if !cfg!(target_os = "linux") {
        skip("the fault reporter emits on Linux only; nothing to exercise here");
        return;
    }
    if !common::require_cc("the fault reporter's classes") {
        return;
    }
    let work = common::Work::new("chard-fault", "classes");
    if cfg!(target_arch = "x86_64") {
        expect(&work, "trap", "SIGILL", Fault::CompilerTrap);
        expect(&work, "ud1", "SIGILL", Fault::CompilerTrap);
        let int3 = expect(&work, "int3", "SIGTRAP", Fault::CompilerTrap);
        assert_eq!(int3.fault_report().and_then(|r| r.word), None);
        // The read stops at the page end: the two bytes there are enough to classify.
        let edge = expect(&work, "page-end", "SIGILL", Fault::CompilerTrap);
        assert_eq!(edge.fault_report().and_then(|r| r.word), Some(0x0b0f));
        shared_cases(&work, "SIGILL");
    } else if cfg!(target_arch = "aarch64") {
        expect(&work, "trap", "SIGTRAP", Fault::CompilerTrap);
        expect(&work, "udf", "SIGILL", Fault::IllegalInstruction);
        shared_cases(&work, "SIGTRAP");
        if cpu_has("bti") {
            let bti = expect(&work, "bti-declared", "SIGILL", Fault::BtiFault);
            assert_eq!(bti.fault_report().and_then(|r| r.at_target), Some(true));
            expect(&work, "bti-undeclared", "SIGILL", Fault::IllegalInstruction);
            let landing = provoke(&work, "bti-landing");
            assert!(
                landing.exited_cleanly(),
                "a landing pad is a legal target: {landing:?}"
            );
            assert!(landing.output_contains("returned 7"));
        } else {
            skip("this CPU lists no bti; the BTI cases did not run");
        }
        if cpu_has("paca") {
            // With FEAT_FPAC the authenticating instruction faults; without it the
            // poisoned return address faults on use, which is not a PacFailure.
            let run = provoke(&work, "pac");
            match run.signal.as_deref() {
                Some("SIGILL") => {
                    assert_eq!(run.fault(), Some(Fault::PacFailure), "{:?}", run.stderr);
                }
                Some("SIGSEGV") => {
                    assert_eq!(run.fault(), Some(Fault::Other));
                    skip("no FEAT_FPAC here: the PAC case faulted on use, as expected without it");
                }
                other => panic!("the PAC case died by {other:?}: {run:?}"),
            }
        } else {
            skip("this CPU lists no paca; the PAC case did not run");
        }
    } else {
        skip("no fault cases for this architecture");
    }
}

/// Without `CHARD_WANT_FAULT_REPORT` the header adds nothing to a probe: no handler, no
/// line, and the death reads by its bare signal.
#[test]
fn a_probe_that_does_not_ask_for_the_reporter_writes_no_report() {
    if !cfg!(target_os = "linux") || !common::require_cc("the fault reporter's opt-in") {
        return;
    }
    let work = common::Work::new("chard-fault", "opt-in");
    work.write(probe::SELFREPORT_HEADER_NAME, probe::SELFREPORT_HEADER);
    // Without the opt-in the header defines neither call, so they become no-ops here
    // and the program is otherwise the one the reporter runs.
    let source = SOURCE.replace(
        "#define CHARD_WANT_FAULT_REPORT\n",
        "#define chard_report_faults() ((void)0)\n#define chard_declare_fault_target(p) ((void)(p))\n",
    );
    assert_ne!(source, SOURCE, "the opt-in line is in the source");
    let path = work.write("fault_classes.c", &source);
    let bin = work.path("fault-plain");
    let out = Command::new("cc")
        .args(["-O2", "-DCHARD_FAULT_CASE=\"trap\"", "-I"])
        .arg(work.dir())
        .arg("-o")
        .arg(&bin)
        .arg(&path)
        .output()
        .expect("spawning cc");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let run = run::execute(Path::new(&bin), work.dir(), Duration::from_secs(10), &[]).expect("run");
    assert!(!run.stderr.contains("chard-fault-v1"), "{:?}", run.stderr);
    assert_eq!(run.fault(), None);
    assert!(run.trapped(), "the bare signal decides: {run:?}");
}
