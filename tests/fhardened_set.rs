// SPDX-License-Identifier: BSD-3-Clause

//! The `-fhardened` set chard reduces over, against the one the host gcc prints.

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

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use chard::composite::{FHARDENED_FLAGS, FHARDENED_FORTIFY};

mod common;

/// The line gcc 14 and later print above the option lines, under `LC_ALL=C`.
const HEADER: &str = "The following options are enabled by -fhardened:";

/// gcc's fortify line, whitespace collapsed, formatted from the rule the composite applies.
/// The fortify slot carries no level, because the composite picks it at run time: from the
/// driver's own `-fhardened -O2` dump where it answers (`composite::fhardened_bar`), else from
/// the C library and target triple under `composite::FHARDENED_FORTIFY` (`composite::fortify_bar`);
/// gcc 16.1.1 prints this line for level 3, fallback 2 and glibc 2.35.
fn fortify_line() -> String {
    let rule = FHARDENED_FORTIFY;
    format!(
        "-D_FORTIFY_SOURCE={} (or ={} for glibc < {}.{})",
        rule.level, rule.fallback, rule.glibc.0, rule.glibc.1
    )
}

/// The `relro` slot, which gcc prints as two lines.
const RELRO_SLOT: &str = "-Wl,-z,relro -Wl,-z,now";

/// The option lines gcc is expected to print for the constant, on every compared target.
fn expected_lines() -> Vec<String> {
    let mut lines = Vec::new();
    for flag in FHARDENED_FLAGS {
        match flag {
            "-D_FORTIFY_SOURCE" => lines.push(fortify_line()),
            RELRO_SLOT => lines.extend(RELRO_SLOT.split(' ').map(str::to_owned)),
            other => lines.push(other.to_owned()),
        }
    }
    lines
}

/// What one comparison examined, printed whether it passes or fails.
struct Frame {
    /// Option lines read after the header.
    read: usize,
    /// Option lines the constant's slots expand to.
    expected: usize,
    /// One sentence per line present on one side only, gcc's side first.
    differences: Vec<String>,
}

/// Compare `help`, the text of `gcc --help=hardened`, with the constant's expansion.
fn compare(help: &str) -> Frame {
    let expected = expected_lines();
    let mut lines = help.lines();
    if !lines.any(|line| line.trim() == HEADER) {
        return Frame {
            read: 0,
            expected: expected.len(),
            differences: vec![format!("no `{HEADER}` line in the output")],
        };
    }
    let printed: Vec<String> = lines
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect();

    let mut differences = Vec::new();
    for line in &printed {
        if !expected.contains(line) {
            differences.push(format!(
                "gcc prints `{line}`, which no slot of FHARDENED_FLAGS expands to"
            ));
        }
    }
    for line in &expected {
        if !printed.contains(line) {
            differences.push(format!(
                "FHARDENED_FLAGS expands to `{line}`, which gcc does not print"
            ));
        }
    }
    let mut counts = BTreeMap::new();
    for line in &printed {
        *counts.entry(line.as_str()).or_insert(0_usize) += 1;
    }
    for (line, n) in counts {
        if n > 1 {
            differences.push(format!("gcc prints `{line}` {n} times"));
        }
    }
    Frame {
        read: printed.len(),
        expected: expected.len(),
        differences,
    }
}

/// Run `gcc` with `args` under the environment chard's compiles use, returning stdout, or
/// `None` when it could not be spawned or exited non-zero.
fn gcc(driver: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new(driver)
        .args(args)
        .env_clear()
        .envs(chard::compile::compiler_environment())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Why this host's gcc cannot be compared, or `None` when it can; `name` is what the
/// failure message calls it.
fn gap(driver: Option<&Path>, name: &mut String) -> Option<String> {
    let Some(driver) = driver else {
        return Some("no `gcc` on PATH".to_owned());
    };
    let version = gcc(driver, &["--version"]).unwrap_or_default();
    let first = version.lines().next().unwrap_or("").trim().to_owned();
    if first.contains("clang") {
        return Some(format!(
            "`gcc` is clang ({first}), which has no --help=hardened"
        ));
    }
    let full = gcc(driver, &["-dumpfullversion"]).unwrap_or_default();
    let full = full.trim();
    let machine = gcc(driver, &["-dumpmachine"]).unwrap_or_default();
    let machine = machine.trim();
    *name = format!("gcc {full} ({machine})");
    let major: Option<u32> = full.split('.').next().and_then(|m| m.parse().ok());
    match major {
        None => {
            return Some(format!(
                "`gcc -dumpfullversion` printed `{full}`, which names no major version"
            ));
        }
        Some(major) if major < 14 => {
            return Some(format!(
                "{name} predates gcc 14, which introduced -fhardened"
            ));
        }
        Some(_) => {}
    }
    target_gap(name, machine)
}

/// The targets whose `--help=hardened` text is recorded in this tree, as the first
/// component of `gcc -dumpmachine`.
const COMPARED_ARCHES: [&str; 2] = ["x86_64", "aarch64"];

/// Why a gcc whose `-dumpmachine` is `machine` cannot be compared, or `None` when it can;
/// `name` is what the reason calls the compiler.
fn target_gap(name: &str, machine: &str) -> Option<String> {
    let arch = machine.split('-').next().unwrap_or("");
    if !COMPARED_ARCHES.contains(&arch) {
        return Some(format!(
            "{name}: the expected lines are recorded for x86_64 and aarch64 only; what gcc \
             prints for --help=hardened on this target is not recorded in this tree"
        ));
    }
    if !machine.contains("-linux") {
        return Some(format!(
            "{name}: gcc documents -fhardened for GNU/Linux only, and what a gcc for another \
             system prints for --help=hardened is not recorded in this tree"
        ));
    }
    None
}

#[test]
fn the_target_gate_compares_x86_64_and_aarch64_linux_only() {
    let table = [
        ("x86_64-redhat-linux", true),
        ("x86_64-linux-gnu", true),
        ("x86_64-pc-linux-gnu", true),
        ("aarch64-redhat-linux", true),
        ("aarch64-linux-gnu", true),
        ("aarch64-unknown-linux-gnu", true),
        ("riscv64-redhat-linux", false),
        ("powerpc64le-linux-gnu", false),
        ("s390x-linux-gnu", false),
        ("i686-linux-gnu", false),
        ("aarch64_be-linux-gnu", false),
        ("x86_64-unknown-freebsd", false),
        ("x86_64-w64-mingw32", false),
        ("aarch64-apple-darwin", false),
        ("", false),
    ];
    let mut classified = 0_usize;
    let mut compared = 0_usize;
    for (machine, expect_compared) in table {
        let why = target_gap("gcc", machine);
        assert_eq!(
            why.is_none(),
            expect_compared,
            "`{machine}`: expected {}, got {why:?}",
            if expect_compared {
                "a comparison"
            } else {
                "a gap"
            }
        );
        classified = classified.saturating_add(1);
        if why.is_none() {
            compared = compared.saturating_add(1);
        }
    }
    eprintln!(
        "fhardened_set: {classified} of {} machines classified, {compared} compared, {} gaps",
        table.len(),
        classified.saturating_sub(compared)
    );
    assert_eq!(classified, table.len());
    assert_eq!(compared, 6, "three x86_64 and three aarch64 Linux triples");
}

#[test]
fn the_fhardened_constant_is_the_set_the_host_gcc_prints() {
    let driver = chard::toolchain::resolve_driver("gcc").ok();
    let mut name = "gcc".to_owned();
    let mut compared = 0_usize;
    let mut gaps = 0_usize;
    if let Some(why) = gap(driver.as_deref(), &mut name) {
        common::capability_gap("the -fhardened comparison", &why);
        gaps = gaps.saturating_add(1);
    } else {
        let driver = driver.expect("a gcc that is not a gap was resolved");
        let help = gcc(&driver, &["--help=hardened"]).unwrap_or_default();
        let frame = compare(&help);
        compared = compared.saturating_add(1);
        eprintln!(
            "fhardened_set: {name}: {} option lines read, {} expected from {} slots of \
             FHARDENED_FLAGS, {} difference(s)",
            frame.read,
            frame.expected,
            FHARDENED_FLAGS.len(),
            frame.differences.len()
        );
        assert!(
            frame.differences.is_empty(),
            "{name}'s --help=hardened and FHARDENED_FLAGS disagree:\n  {}\n--- help ---\n{help}",
            frame.differences.join("\n  ")
        );
        assert!(frame.read > 0, "{name} printed no option lines");
    }
    eprintln!("fhardened_set: {compared} of 1 comparison made, {gaps} announced as a gap");
    assert_eq!(
        compared.saturating_add(gaps),
        1,
        "the comparison is either made or announced as a gap"
    );
}

#[test]
fn a_doctored_help_text_is_reported_in_both_directions() {
    const GCC_16_1_1: &str = "The following options are enabled by -fhardened:\n  \
        -D_FORTIFY_SOURCE=3 (or =2 for glibc < 2.35)\n  \
        -D_GLIBCXX_ASSERTIONS\n  \
        -ftrivial-auto-var-init=zero\n  \
        -fPIE  -pie\n  \
        -Wl,-z,now\n  \
        -Wl,-z,relro\n  \
        -fstack-protector-strong\n  \
        -fstack-clash-protection\n  \
        -fcf-protection=full\n\n";
    /// gcc 16.2.1 (Red Hat 16.2.1-2), `aarch64-redhat-linux`, Fedora 44 with glibc 2.43, run
    /// under qemu-user in an arm64 container with no network, `LC_ALL=C`, on 2026-10-06.
    /// Not checked on native aarch64 hardware. Byte for byte the x86_64 16.1.1 text (md5
    /// 92f86ee1ca8d5a57c1b89cda0738bdc1 for both), `-fcf-protection=full` included, though
    /// that gcc rejects the option for its target.
    const GCC_16_2_1_AARCH64: &str = "The following options are enabled by -fhardened:\n  \
        -D_FORTIFY_SOURCE=3 (or =2 for glibc < 2.35)\n  \
        -D_GLIBCXX_ASSERTIONS\n  \
        -ftrivial-auto-var-init=zero\n  \
        -fPIE  -pie\n  \
        -Wl,-z,now\n  \
        -Wl,-z,relro\n  \
        -fstack-protector-strong\n  \
        -fstack-clash-protection\n  \
        -fcf-protection=full\n\n";

    let clean_texts = [
        ("gcc 16.1.1 x86_64", GCC_16_1_1),
        ("gcc 16.2.1 aarch64", GCC_16_2_1_AARCH64),
    ];
    let mut clean_compared = 0_usize;
    for (label, text) in clean_texts {
        let clean = compare(text);
        assert_eq!(
            (clean.read, clean.expected),
            (9, 9),
            "{label} prints nine option lines and the constant expands to nine"
        );
        assert!(
            clean.differences.is_empty(),
            "{label}: {:?}",
            clean.differences
        );
        clean_compared = clean_compared.saturating_add(1);
    }
    eprintln!(
        "fhardened_set: {clean_compared} of {} recorded texts clean",
        clean_texts.len()
    );
    assert_eq!(clean_compared, clean_texts.len());

    let cases = [
        (
            "an added member",
            GCC_16_1_1.replace(
                "  -fcf-protection=full\n",
                "  -fcf-protection=full\n  -fzero-call-used-regs=used-gpr\n",
            ),
            "gcc prints `-fzero-call-used-regs=used-gpr`",
        ),
        (
            "a dropped member",
            GCC_16_1_1.replace("  -fstack-clash-protection\n", ""),
            "expands to `-fstack-clash-protection`, which gcc does not print",
        ),
        (
            "half of the relro slot",
            GCC_16_1_1.replace("  -Wl,-z,now\n", ""),
            "expands to `-Wl,-z,now`, which gcc does not print",
        ),
        (
            "a changed fortify rule",
            GCC_16_1_1.replace("=2 for glibc < 2.35", "=2 for glibc < 2.40"),
            "gcc prints `-D_FORTIFY_SOURCE=3 (or =2 for glibc < 2.40)`",
        ),
        (
            "no header",
            GCC_16_1_1.replace(HEADER, "cc1: warning: unrecognized option"),
            "no `The following options are enabled by -fhardened:` line",
        ),
    ];
    let mut reported = 0_usize;
    for (case, text, wanted) in &cases {
        let frame = compare(text);
        assert!(
            frame.differences.iter().any(|d| d.contains(wanted)),
            "{case}: expected a difference containing {wanted:?}, got {:?}",
            frame.differences
        );
        reported = reported.saturating_add(1);
    }
    eprintln!(
        "fhardened_set: {reported} of {} doctored texts reported",
        cases.len()
    );
    assert_eq!(reported, cases.len());
}
