// SPDX-License-Identifier: BSD-3-Clause

//! Unit tests for `decode::runtime`, kept out of the module so its file holds detector code
//! alone.

use super::*;
use crate::probe::tests::elf_with_report;
use crate::probe::{Outcome, SELFREPORT_HEADER, SELFREPORT_HEADER_NAME};

fn tavi_run(stdout: &str) -> RunRecord {
    RunRecord {
        argv: vec!["probe".to_owned()],
        exit_status: 0,
        signal: None,
        stdout: stdout.to_owned(),
        stderr: String::new(),
        timed_out: false,
        deadline_ms: None,
        output_error: None,
        output_truncated: false,
        duration_ms: 1,
        environment: None,
    }
}

fn tavi_detect(stdout: &str) -> Detection {
    let macros = BTreeMap::new();
    let run = tavi_run(stdout);
    detect_auto_var_init(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

#[test]
fn a_uniform_zero_fill_is_the_zero_mode() {
    let d = tavi_detect("TAVI arr=00 word=00 small=00 ctrl=5a ctrl_supported=1");
    assert_eq!(d.outcome, Outcome::Present);
    assert_eq!(d.level.as_deref(), Some("zero"));
}

#[test]
fn both_compilers_pattern_bytes_are_recognized() {
    for line in [
        "TAVI arr=fe word=fe small=fe ctrl=5a ctrl_supported=1",
        "TAVI arr=aa word=aa small=aa ctrl=5a ctrl_supported=1",
    ] {
        let d = tavi_detect(line);
        assert_eq!(d.outcome, Outcome::Present, "{line}");
        assert_eq!(d.level.as_deref(), Some("pattern"), "{line}");
    }
}

/// The pre-dirtying is what makes absence provable: 0x5A surviving means
/// nothing wrote over it.
#[test]
fn the_surviving_dirt_byte_proves_nothing_initialized_the_variable() {
    let d = tavi_detect("TAVI arr=5a word=5a small=5a ctrl=5a ctrl_supported=1");
    assert_eq!(d.outcome, Outcome::Absent);
}

/// Uninitialized garbage differs between variable shapes, and it routinely
/// contains a 0x00 by chance. Treating a stray 0x00 as ambiguous made gcc's
/// negative control flake between runs and withheld sound verdicts.
#[test]
fn disagreeing_shapes_are_absence_even_when_one_byte_looks_like_a_fill() {
    for line in [
        "TAVI arr=1a word=f8 small=fd ctrl=5a ctrl_supported=1",
        "TAVI arr=1a word=00 small=fd ctrl=5a ctrl_supported=1",
        "TAVI arr=00 word=aa small=5a ctrl=5a ctrl_supported=1",
    ] {
        assert_eq!(
            tavi_detect(line).outcome,
            Outcome::Absent,
            "non-uniform fill must read as absent: {line}"
        );
    }
}

#[test]
fn a_missing_or_malformed_tavi_line_is_indeterminate_not_absent() {
    for line in [
        "",
        "no marker here",
        "TAVI arr=zz word=00 small=00 ctrl=5a ctrl_supported=1",
        "TAVI arr=00 ctrl=5a ctrl_supported=1",
    ] {
        assert_eq!(
            tavi_detect(line).outcome,
            Outcome::Indeterminate,
            "unparseable output must not be read as a measurement: {line:?}"
        );
    }
}

/// The pattern check must not accept a zero fill, which is what clang produces
/// incidentally and what `=zero` produces deliberately.
#[test]
fn the_pattern_check_rejects_a_zero_fill() {
    let macros = BTreeMap::new();
    let run = tavi_run("TAVI arr=00 word=00 small=00 ctrl=5a ctrl_supported=1");
    let d = detect_auto_var_init_pattern(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    });
    assert_eq!(d.outcome, Outcome::Absent);
}

/// An artifact's facts with its ELF class set, as the header reports it.
fn elf_of_class(class: u8) -> crate::elf::ElfFacts {
    let mut elf = elf_with_report("");
    elf.elf_class = class;
    if class == 32 {
        elf.machine = "i386".to_owned();
    }
    elf
}

/// Both fill detectors over one recorded line and one artifact.
fn tavi_both(stdout: &str, elf: Option<&crate::elf::ElfFacts>) -> [Detection; 2] {
    let macros = BTreeMap::new();
    let run = tavi_run(stdout);
    let ev = Evidence {
        macros: &macros,
        elf,
        build: None,
        run: Some(&run),
        workdir: None,
    };
    [detect_auto_var_init(&ev), detect_auto_var_init_pattern(&ev)]
}

/// The lines the probe printed on 2026-09-30, verbatim, at -O0, -O1 and -O2 alike: clang
/// 14.0.6 natively in Debian 12 i386, clang 14.0.0 `-m32` in `ubuntu:22.04` and clang
/// 22.1.8 `-m32` in `fedora:44` under `=pattern`; gcc 12.2.0 natively and gcc 16.2.1
/// `-m32` under `=pattern`; and every one of them under `=uninitialized`.
const I386_CLANG_PATTERN: &str = "TAVI arr=ff word=ff small=ff ctrl=5a ctrl_supported=1";
const I386_GCC_PATTERN: &str = "TAVI arr=fe word=fe small=fe ctrl=5a ctrl_supported=1";
const I386_UNINITIALIZED: &str = "TAVI arr=5a word=5a small=5a ctrl=5a ctrl_supported=1";

/// clang fills with 0xFF where pointers are narrower than 64 bits, and both detectors read
/// that as `=pattern` on an ELFCLASS32 artifact. Read otherwise, the pattern check's
/// positive control would read `fill=0xff` as absent and the check would be
/// `probe-invalid` on every i386 clang measured, and the generic check would read an i386
/// `=pattern` build as `absent`, "uniform but not an initializer's value".
#[test]
fn clangs_i386_pattern_fill_is_a_pattern_on_a_32_bit_artifact() {
    let i386 = elf_of_class(32);
    for line in [I386_CLANG_PATTERN, I386_GCC_PATTERN] {
        for d in tavi_both(line, Some(&i386)) {
            assert_eq!(d.outcome, Outcome::Present, "{line}");
            assert_eq!(d.level.as_deref(), Some("pattern"), "{line}");
        }
    }
}

/// Each target is held to the byte its compiler writes: 0xFF is no pattern on a 64-bit
/// artifact, and 0xAA none on a 32-bit one. Neither is read as `absent` there either: each
/// is clang's pattern on some target, the class names the pointer width only by
/// inference (assumption `elf-class-names-clang-pattern-width`), and clang 22.1.8 emits an
/// `ELFCLASS32` object filled with 0xAA for `aarch64-linux-gnu_ilp32`. Both are withheld,
/// so the inference failing cannot publish an `off`. With no ELF facts 0xFF is withheld
/// too: on a 32-bit target whose header went unread it is the pattern.
#[test]
fn a_pattern_byte_counts_only_on_the_pointer_width_that_writes_it() {
    let x86_64 = elf_of_class(64);
    let i386 = elf_of_class(32);
    for (line, elf) in [
        (I386_CLANG_PATTERN, Some(&x86_64)),
        (
            "TAVI arr=aa word=aa small=aa ctrl=5a ctrl_supported=1",
            Some(&i386),
        ),
        (I386_CLANG_PATTERN, None),
    ] {
        for d in tavi_both(line, elf) {
            assert_eq!(
                d.outcome,
                Outcome::Indeterminate,
                "{line} on {:?}",
                elf.map(|e| e.elf_class)
            );
        }
    }
    // clang's 64-bit byte is still read where there are no ELF facts: a Mach-O artifact.
    for elf in [None, Some(&x86_64)] {
        for d in tavi_both("TAVI arr=aa word=aa small=aa ctrl=5a ctrl_supported=1", elf) {
            assert_eq!(d.outcome, Outcome::Present);
        }
    }
    // A uniform byte that is no initializer's value is still absent on either class.
    for elf in [Some(&x86_64), Some(&i386)] {
        for d in tavi_both("TAVI arr=7c word=7c small=7c ctrl=5a ctrl_supported=1", elf) {
            assert_eq!(d.outcome, Outcome::Absent);
        }
    }
}

/// The negative arm stays distinguishable on i386: the dirt survives, and a ctrl that did
/// not survive refuses the line whatever its fill.
#[test]
fn the_i386_negative_arm_and_a_broken_witness_are_not_a_pattern() {
    let i386 = elf_of_class(32);
    for d in tavi_both(I386_UNINITIALIZED, Some(&i386)) {
        assert_eq!(d.outcome, Outcome::Absent);
    }
    for d in tavi_both(
        "TAVI arr=ff word=ff small=ff ctrl=ff ctrl_supported=1",
        Some(&i386),
    ) {
        assert_eq!(d.outcome, Outcome::Indeterminate);
    }
    for line in [
        "TAVI arr=ff word=ff small=5a ctrl=5a ctrl_supported=1",
        "TAVI arr=00 word=00 small=00 ctrl=5a ctrl_supported=1",
    ] {
        assert_eq!(
            tavi_both(line, Some(&i386))[1].outcome,
            Outcome::Absent,
            "{line}"
        );
    }
}

fn trap_run(signal: &str) -> RunRecord {
    RunRecord {
        argv: vec!["probe".to_owned()],
        exit_status: -1,
        signal: Some(signal.to_owned()),
        stdout: String::new(),
        stderr: String::new(),
        timed_out: false,
        deadline_ms: None,
        output_error: None,
        output_truncated: false,
        duration_ms: 1,
        environment: None,
    }
}

/// The identity survives a platform whose artifact chard cannot read.
///
/// This is the gap the Apple trap credit fell into: `fortify_impl` read the section
/// through `self.elf`, Mach-O has no ELF facts, and so an arm written for Apple could
/// never fire on Apple. Measured on arm64 — `otool -s __DATA .chard.report` shows
/// `_FORTIFY_IMPL=apple` in a bare build, so the value was right there and unreachable.
#[test]
fn the_self_report_is_readable_where_the_container_is_not() {
    let macros = BTreeMap::new();
    let printed = |stdout: &str| {
        let mut run = trap_run("SIGTRAP");
        run.stdout = stdout.to_owned();
        let ev = Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: None,
        };
        ev.fortify_impl()
    };

    let whole = "CHARD-REPORT-V1\n_FORTIFY_IMPL=apple\n_USE_FORTIFY_LEVEL=2\n\
                 CHARD-REPORT-END\n";
    assert_eq!(printed(whole).as_deref(), Some("apple"));

    // A probe's own output shares the stream, and the region is what bounds the parse.
    // `stack-clash-guard-page` prints `dist=` and `n=` lines exactly like this.
    let mixed = format!("SCPRT dist=8367487 n=66977792\n{whole}no-check-fired\n");
    assert_eq!(printed(&mixed).as_deref(), Some("apple"));

    // Killed mid-write: an opening marker and a truncated body. Half a report read as
    // a whole one is how an absent field becomes a confident answer.
    assert_eq!(printed("CHARD-REPORT-V1\n_FORTIFY_IMPL=app"), None);
    assert_eq!(printed("no-check-fired\n"), None);
    assert_eq!(printed(""), None);
}

/// The trap-credit branch, which none of the 1,011 recorded fixtures exercises: every
/// recorded fortify run either aborted with glibc's message or exited cleanly.
///
/// That gap is not only about Darwin. The fortify-headers arm is live for Alpine and
/// Chimera and is equally unexercised by the fixtures, so without this test a change to
/// the gate could break it with nothing to say so.
#[test]
fn a_silent_trap_is_credited_only_to_an_implementation_that_named_itself() {
    let macros = BTreeMap::new();
    let outcome = |report: Option<&str>, signal: &str| {
        let elf = report.map(elf_with_report);
        let run = trap_run(signal);
        detect_fortify_runtime(&Evidence {
            macros: &macros,
            elf: elf.as_ref(),
            build: None,
            run: Some(&run),
            workdir: None,
        })
        .outcome
    };

    for implementation in ["fortify-headers", "apple"] {
        let report = format!("CHARD-REPORT-V1\n_FORTIFY_IMPL={implementation}\n");
        // `ud2` on x86_64, `brk` on aarch64. Same trap, and the architecture must not
        // decide whether it counts.
        for signal in ["SIGILL", "SIGTRAP"] {
            assert_eq!(
                outcome(Some(&report), signal),
                Outcome::Present,
                "{implementation} traps silently, so {signal} plus its own identity \
                 is the whole of the evidence available"
            );
        }
    }

    // The gate, from both sides. A trap with no identity is an illegal instruction
    // from an unknown cause, and glibc must not be credited for one: its failure
    // carries a message and is matched on that.
    assert_eq!(
        outcome(Some("CHARD-REPORT-V1\n_FORTIFY_IMPL=glibc\n"), "SIGTRAP"),
        Outcome::Indeterminate,
        "glibc aborts with a diagnostic, so a bare trap is not its signature"
    );
    assert_eq!(
        outcome(
            Some("CHARD-REPORT-V2\n_FORTIFY_IMPL undefined\n"),
            "SIGTRAP"
        ),
        Outcome::Indeterminate,
        "an unidentified implementation cannot be credited for a silent death"
    );
    // No self-report at all, which is every Mach-O artifact today: the identity is
    // unreadable, so the trap stays unattributed rather than being guessed at.
    assert_eq!(
        outcome(None, "SIGTRAP"),
        Outcome::Indeterminate,
        "withholding is the correct answer when the artifact cannot be read"
    );
}

/// FreeBSD's `__chk_fail` aborts with nothing in band, so the credit rests on three
/// witnesses together: the self-report names FreeBSD's wrappers, the artifact calls a
/// checking function, and the death is SIGABRT. Each missing one withholds, with the
/// reason naming what was missing; a trap is not its signature, and the symbol must be a
/// reference, since a definition is the probe's own.
#[test]
fn a_silent_abort_is_freebsds_only_with_its_identity_and_a_checking_call() {
    use crate::elf::SymbolFact;
    let macros = BTreeMap::new();
    let report = "CHARD-REPORT-V2\n_FORTIFY_IMPL=freebsd\n__SSP_FORTIFY_LEVEL=2\n\
                  __FreeBSD__=15\nCHARD-REPORT-END\n";
    let with = |report: &str, symbols: &[(&str, bool)], tables: &[&str], signal: &str| {
        let mut elf = elf_with_report(report);
        elf.symbol_tables = tables.iter().map(|t| (*t).to_owned()).collect();
        for (name, defined) in symbols {
            elf.watched_symbols.insert(
                (*name).to_owned(),
                SymbolFact {
                    defined: *defined,
                    tables: vec![".dynsym".to_owned()],
                    versioned: Vec::new(),
                },
            );
        }
        let run = trap_run(signal);
        detect_fortify_runtime(&Evidence {
            macros: &macros,
            elf: Some(&elf),
            build: None,
            run: Some(&run),
            workdir: None,
        })
    };

    // The string family reaches `__*_chk`; a wrapper that checks inline calls `__chk_fail`.
    for symbol in ["__memcpy_chk", "__strcpy_chk", "__chk_fail"] {
        let d = with(report, &[(symbol, false)], &[".dynsym"], "SIGABRT");
        assert_eq!(d.outcome, Outcome::Present, "{symbol}: {}", d.observed);
        assert!(d.observed.contains(symbol), "{}", d.observed);
        // The sentence names what chard read, and not FreeBSD's log line, which it did not.
        assert!(
            d.observed.contains("SIGABRT with nothing on stderr")
                && d.observed.contains("no survival marker on stdout")
                && !d.observed.contains("syslog"),
            "{}",
            d.observed
        );
    }
    // The canary's own symbol is not a checking function.
    let d = with(
        report,
        &[("__stack_chk_fail", false)],
        &[".dynsym"],
        "SIGABRT",
    );
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(
        d.observed.contains("references no checking function"),
        "{}",
        d.observed
    );
    // A defined checking function is the probe's own, not the library's wrapper.
    let d = with(report, &[("__memcpy_chk", true)], &[".dynsym"], "SIGABRT");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    // No symbol table to read, or a cut one, is named rather than read as no call.
    let d = with(report, &[], &[], "SIGABRT");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(d.observed.contains("no symbol table"), "{}", d.observed);
    let mut cut = elf_with_report(report);
    cut.symbol_tables = vec![".dynsym".to_owned()];
    cut.truncations.push(crate::elf::Truncation {
        table: crate::elf::ElfTable::Symbols,
        kind: crate::elf::TruncationKind::Unread,
        detail: "mutated: symbols cut".to_owned(),
    });
    let run = trap_run("SIGABRT");
    let d = detect_fortify_runtime(&Evidence {
        macros: &macros,
        elf: Some(&cut),
        build: None,
        run: Some(&run),
        workdir: None,
    });
    assert!(d.observed.contains("not read whole"), "{}", d.observed);
    let mut run = trap_run("SIGABRT");
    run.stdout = report.to_owned();
    let d = detect_fortify_runtime(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    });
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(d.observed.contains("was not read"), "{}", d.observed);
    // A trap is not FreeBSD's signature, whatever the artifact calls.
    for signal in ["SIGILL", "SIGTRAP", "SIGSEGV"] {
        let d = with(report, &[("__memcpy_chk", false)], &[".dynsym"], signal);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{signal}: {}",
            d.observed
        );
    }
    // Another implementation's abort with a checking call is not credited by this rule:
    // glibc's carries its message, and 14.5's self-report names none.
    for other in ["_FORTIFY_IMPL=glibc", "_FORTIFY_IMPL undefined"] {
        let report = format!("CHARD-REPORT-V2\n{other}\n__FreeBSD__=14\nCHARD-REPORT-END\n");
        let d = with(&report, &[("__memcpy_chk", false)], &[".dynsym"], "SIGABRT");
        assert_eq!(d.outcome, Outcome::Indeterminate, "{other}: {}", d.observed);
    }
}

/// The credit also needs the abort to be the silent one, and a referenced rather than a
/// defined checking function: a static link is named, text on stderr is another abort's
/// (an assert, an allocator, the stack protector), and the survival marker on stdout says
/// the copy was not what died. The last four were forged by the assurance review of
/// 2026-10-27 before the rule read the streams.
#[test]
fn a_loud_or_survived_abort_is_not_freebsds_kill() {
    use crate::elf::SymbolFact;
    let macros = BTreeMap::new();
    let report = "CHARD-REPORT-V2\n_FORTIFY_IMPL=freebsd\n__SSP_FORTIFY_LEVEL=2\n\
                  __FreeBSD__=15\nCHARD-REPORT-END\n";
    let with = |report: &str, symbols: &[(&str, bool)], tables: &[&str], signal: &str| {
        let mut elf = elf_with_report(report);
        elf.symbol_tables = tables.iter().map(|t| (*t).to_owned()).collect();
        for (name, defined) in symbols {
            elf.watched_symbols.insert(
                (*name).to_owned(),
                SymbolFact {
                    defined: *defined,
                    tables: vec![".dynsym".to_owned()],
                    versioned: Vec::new(),
                },
            );
        }
        let run = trap_run(signal);
        detect_fortify_runtime(&Evidence {
            macros: &macros,
            elf: Some(&elf),
            build: None,
            run: Some(&run),
            workdir: None,
        })
    };
    // A defined checking function is a static link, named as such.
    let d = with(report, &[("__memcpy_chk", true)], &[".dynsym"], "SIGABRT");
    assert!(d.observed.contains("static link"), "{}", d.observed);
    let mut elf = elf_with_report(report);
    elf.symbol_tables = vec![".dynsym".to_owned()];
    elf.watched_symbols.insert(
        "__memcpy_chk".to_owned(),
        SymbolFact {
            defined: false,
            tables: vec![".dynsym".to_owned()],
            versioned: Vec::new(),
        },
    );
    let streams = |stdout: &str, stderr: &str| {
        let mut run = trap_run("SIGABRT");
        run.stdout = stdout.to_owned();
        run.stderr = stderr.to_owned();
        detect_fortify_runtime(&Evidence {
            macros: &macros,
            elf: Some(&elf),
            build: None,
            run: Some(&run),
            workdir: None,
        })
    };
    for (stdout, stderr, names) in [
        (
            "",
            "Assertion failed: (n < 16), function main, file p.c, line 9.\n",
            "stderr",
        ),
        (
            "",
            "<jemalloc>: Error in malloc(): out of memory\n",
            "stderr",
        ),
        (
            "",
            "*** stack smashing detected ***: terminated\n",
            "stderr",
        ),
        (
            "CHARD-REPORT-V2\n_FORTIFY_IMPL=freebsd\nCHARD-REPORT-END\nno-check-fired A\n",
            "",
            "survived",
        ),
    ] {
        let d = streams(stdout, stderr);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{stdout:?} {stderr:?}: {}",
            d.observed
        );
        assert!(d.observed.contains(names), "{}", d.observed);
    }
    assert_eq!(streams("", "").outcome, Outcome::Present);
}

/// Every checking function the silent-abort credit reads is one the ELF reader watches,
/// so a name here that the facts could never hold is caught rather than silently never
/// matched.
#[test]
fn every_freebsd_checking_call_is_watched() {
    for name in FREEBSD_CHECKING_CALLS {
        assert!(
            crate::elf::WATCHED_SYMBOLS.contains(name),
            "{name} is read by the FreeBSD credit and not watched"
        );
    }
    // The list exactly, so a name dropped from it is a decision rather than a silence: each
    // was measured referenced on FreeBSD 15.1 or is the checking function its header declares.
    assert_eq!(
        FREEBSD_CHECKING_CALLS,
        &[
            "__chk_fail",
            "__memcpy_chk",
            "__memmove_chk",
            "__memset_chk",
            "__strcpy_chk",
            "__strncpy_chk",
            "__strcat_chk",
            "__sprintf_chk",
            "__snprintf_chk",
            "__vsnprintf_chk",
            "__read_chk",
        ]
    );
    assert!(!FREEBSD_CHECKING_CALLS.contains(&"__stack_chk_fail"));
}

/// libc++ can trap instead of printing, and its identity has two spellings: chard's
/// own `_CXX_STDLIB` summary, which lives only in the self-report, and the real
/// `_LIBCPP_VERSION` the preprocessor dump carries whatever the object format is.
#[test]
fn a_libcpp_trap_is_credited_through_either_spelling_of_its_identity() {
    let run = trap_run("SIGTRAP");
    let outcome = |pairs: &[(&str, &str)]| {
        let macros: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        detect_cxx_assertions(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: None,
        })
        .outcome
    };

    assert_eq!(outcome(&[("_CXX_STDLIB", "libc++")]), Outcome::Present);
    assert_eq!(outcome(&[("_LIBCPP_VERSION", "210000")]), Outcome::Present);
    assert_eq!(
        outcome(&[("_CXX_STDLIB", "libstdc++")]),
        Outcome::Indeterminate,
        "libstdc++ prints a message, so a silent trap is not its signature"
    );
    assert_eq!(
        outcome(&[]),
        Outcome::Indeterminate,
        "no identity, no credit"
    );
}

/// The uninitialized witness decides whether *any* of the run can be read, and it
/// fails toward withholding.
///
/// `ctrl` carries `__attribute__((uninitialized))`, so the flag must never touch it
/// and it must read back the dirt byte. When it does not, frame reuse did not happen
/// and the three readings beside it describe nothing — including, and especially, a
/// uniform zero, which is exactly what a working `-ftrivial-auto-var-init=zero` looks
/// like. Inverting the comparison publishes that false clean result and refuses every
/// genuine one, and both directions are asserted here because either alone passes.
#[test]
fn a_failed_uninitialized_witness_refuses_the_whole_reading() {
    // The witness held: `ctrl` read back the dirt byte, so the zero fill beside it is
    // the flag's doing.
    let held = tavi_detect("TAVI ctrl_supported=1 ctrl=5a arr=00 word=00 small=00");
    assert_eq!(held.outcome, Outcome::Present);
    assert_eq!(held.level.as_deref(), Some("zero"));

    // The witness failed: the same three readings, and now they mean nothing.
    let failed = tavi_detect("TAVI ctrl_supported=1 ctrl=00 arr=00 word=00 small=00");
    assert_eq!(
        failed.outcome,
        Outcome::Indeterminate,
        "a zero fill under a failed witness is the reading that looks like success"
    );

    // A compiler with no opt-out attribute says so, and the witness is skipped rather
    // than failed — otherwise every such compiler would report indeterminate.
    let unsupported = tavi_detect("TAVI ctrl_supported=0 ctrl=00 arr=00 word=00 small=00");
    assert_eq!(unsupported.outcome, Outcome::Present);
    assert_eq!(unsupported.level.as_deref(), Some("zero"));
}

/// A `RunRecord` carrying only the flex-array probe's stdout line.
fn flex_run(stdout: &str) -> RunRecord {
    RunRecord {
        argv: vec!["probe".to_owned()],
        exit_status: 0,
        signal: None,
        stdout: stdout.to_owned(),
        stderr: String::new(),
        timed_out: false,
        deadline_ms: None,
        output_error: None,
        output_truncated: false,
        duration_ms: 1,
        environment: None,
    }
}

fn flex_detect(stdout: &str) -> Detection {
    let macros = BTreeMap::new();
    let run = flex_run(stdout);
    detect_strict_flex_arrays(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

/// Each `-fstrict-flex-arrays` level is read from the three bounds it implies, and
/// nothing else is read as a level.
///
/// The flag exempts trailing-array spellings in order — `[]`, then `[0]`, then `[1]`
/// — so the three `__builtin_object_size` answers move together and only four of the
/// eight combinations describe a real level. The rest mean one of the three readings
/// is not measuring what it is meant to, and saying so is the only honest answer:
/// picking the nearest level would publish a posture the toolchain never had.
#[test]
fn each_flex_array_level_is_read_from_the_bounds_it_implies() {
    for (stdout, level) in [
        ("flex-two=2 flex-one=1 flex-zero=0", "3"),
        ("flex-two=2 flex-one=1 flex-zero=9", "2"),
        ("flex-two=2 flex-one=9 flex-zero=9", "1"),
    ] {
        let d = flex_detect(stdout);
        assert_eq!(d.outcome, Outcome::Present, "{stdout}");
        assert_eq!(d.level.as_deref(), Some(level), "{stdout}");
    }

    // Level 0 is an absence, not a level: every trailing array is still flexible, so
    // there is no bound for the flag to have tightened. The readings are deliberately
    // non-negative — `0` is a real size here, and a guard that treated it as "no
    // answer" would report this build as unmeasurable rather than as unhardened.
    let none = flex_detect("flex-two=0 flex-one=0 flex-zero=8");
    assert_eq!(none.outcome, Outcome::Absent);
    assert_eq!(none.level, None);

    // Bounded at a wider spelling than a narrower one. No level produces it.
    let impossible = flex_detect("flex-two=9 flex-one=1 flex-zero=0");
    assert_eq!(impossible.outcome, Outcome::Indeterminate);
    assert!(
        impossible
            .observed
            .contains("no -fstrict-flex-arrays level"),
        "{}",
        impossible.observed
    );
}

/// `-1` is `__builtin_object_size` declining to answer, and it is never read as a
/// level.
///
/// Without optimization it answers `-1` for every query whatever the flag was set to,
/// so treating it as "unbounded" would report the flag off for a build that set it —
/// absence of an answer taken as an answer. Each reading is tested alone, with the
/// other two forming a combination that *would* otherwise decide a level, because a
/// guard that only fires when all three are negative would pass a test that made them
/// negative together.
#[test]
fn a_size_the_compiler_could_not_determine_is_not_a_level() {
    for stdout in [
        "flex-two=-1 flex-one=9 flex-zero=9",
        "flex-two=9 flex-one=-1 flex-zero=9",
        "flex-two=9 flex-one=9 flex-zero=-1",
    ] {
        let d = flex_detect(stdout);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{stdout} was read as a level"
        );
        assert!(
            d.observed.contains("could not determine a size"),
            "{stdout}: {}",
            d.observed
        );
    }
}

/// The reason for a `-1` names the cause the probe reported, and neither when it
/// reported none.
///
/// OpenBSD 7.9's negative arm prints `-1` at `-O2` because its driver passes
/// `-fno-builtin-malloc` and its `malloc` carries no `alloc_size`; the reason blamed a
/// build without optimization there. The optimization marker is read as a whole field,
/// so `optimize=yes` is not found inside a longer token, and evidence without
/// the optimization marker names both causes.
#[test]
fn a_size_the_compiler_could_not_determine_names_the_cause_the_probe_reported() {
    let unoptimized = flex_detect("flex-two=-1 flex-one=-1 flex-zero=-1\noptimize=no");
    let optimized = flex_detect("flex-two=-1 flex-one=-1 flex-zero=-1\noptimize=yes");
    let unreported = flex_detect("flex-two=-1 flex-one=-1 flex-zero=-1");
    let embedded = flex_detect("flex-two=-1 flex-one=-1 flex-zero=-1 xoptimize=yes");
    for d in [&unoptimized, &optimized, &unreported, &embedded] {
        assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    }
    assert!(
        unoptimized.observed.contains("was not optimized"),
        "{}",
        unoptimized.observed
    );
    assert!(
        !unoptimized.observed.contains("alloc_size"),
        "{}",
        unoptimized.observed
    );
    assert!(
        optimized
            .observed
            .contains("could not bound the allocation"),
        "{}",
        optimized.observed
    );
    assert!(
        !optimized.observed.contains("not optimized"),
        "{}",
        optimized.observed
    );
    for d in [&unreported, &embedded] {
        assert!(
            d.observed.contains("did not report whether"),
            "{}",
            d.observed
        );
    }
}

/// The declared-storage construct has no allocator, so its optimized `-1` does not blame
/// one.
///
/// The probe queries objects declared in static unions and prints
/// `storage=declared`. An unoptimized build still withholds for the unoptimized cause; an
/// optimized one, for which chard knows no cause, withholds naming no allocator. Its level
/// readings decode exactly as the heap construct's did.
#[test]
fn the_declared_construct_withholds_without_blaming_an_allocator() {
    let unoptimized =
        flex_detect("flex-two=-1 flex-one=-1 flex-zero=-1\noptimize=no\nstorage=declared");
    let optimized =
        flex_detect("flex-two=-1 flex-one=-1 flex-zero=-1\noptimize=yes\nstorage=declared");
    let unreported = flex_detect("flex-two=-1 flex-one=-1 flex-zero=-1\nstorage=declared");
    for d in [&unoptimized, &optimized, &unreported] {
        assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
        assert!(!d.observed.contains("alloc"), "{}", d.observed);
    }
    assert!(
        unoptimized.observed.contains("was not optimized"),
        "{}",
        unoptimized.observed
    );
    assert!(
        optimized.observed.contains("no cause chard knows of"),
        "{}",
        optimized.observed
    );
    assert!(
        unreported.observed.contains("did not report whether"),
        "{}",
        unreported.observed
    );

    let off = flex_detect("flex-two=36 flex-one=36 flex-zero=32\noptimize=yes\nstorage=declared");
    assert_eq!(off.outcome, Outcome::Absent, "{}", off.observed);
    let on = flex_detect("flex-two=2 flex-one=1 flex-zero=0\noptimize=yes\nstorage=declared");
    assert_eq!(on.outcome, Outcome::Present, "{}", on.observed);
    assert_eq!(on.level.as_deref(), Some("3"), "{}", on.observed);
}

/// No readings at all, and no run at all, are different facts and both withhold.
#[test]
fn a_probe_that_printed_no_flex_array_readings_withholds() {
    let silent = flex_detect("");
    assert_eq!(silent.outcome, Outcome::Indeterminate);
    assert!(
        silent.observed.contains("no flex-array readings"),
        "{}",
        silent.observed
    );

    let macros = BTreeMap::new();
    let unrun = detect_strict_flex_arrays(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: None,
        workdir: None,
    });
    assert_eq!(unrun.outcome, Outcome::Indeterminate);
    assert_eq!(unrun.observed, "probe not executed");
}

/// A `RunRecord` for a probe that died on a signal with a diagnostic on stderr.
fn died_run(signal: &str, stderr: &str) -> RunRecord {
    let mut run = trap_run(signal);
    run.stderr = stderr.to_owned();
    run
}

/// A `RunRecord` for a probe that exited normally.
fn exited_run(status: i32, stdout: &str) -> RunRecord {
    RunRecord {
        argv: vec!["probe".to_owned()],
        exit_status: status,
        signal: None,
        stdout: stdout.to_owned(),
        stderr: String::new(),
        timed_out: false,
        deadline_ms: None,
        output_error: None,
        output_truncated: false,
        duration_ms: 1,
        environment: None,
    }
}

/// A guard that ran in an unoptimized build says something only on gcc 8 and later.
///
/// The published defect: clang keeps the guard at `-O0` whether or not the flag was
/// passed, and reading that as `present` credited every clang measured under a bare
/// profile with a `-fno-strict-overflow` default it does not have — while the control
/// arms, which carry their own `-O2`, discriminated perfectly and vouched for the
/// cell.
#[test]
fn an_unoptimized_overflow_guard_is_read_only_where_the_compiler_folds_it() {
    let macros = BTreeMap::new();
    let overflow_of = |stdout: &str| {
        let run = exited_run(0, stdout);
        detect_no_strict_overflow(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: None,
        })
        .outcome
    };

    assert_eq!(
        overflow_of("optimize=yes\nfrontend=clang\noverflow-guard=ran"),
        Outcome::Present,
        "optimized, so the guard surviving is the flag's doing on either compiler"
    );
    assert_eq!(
        overflow_of("optimize=no\nfrontend=gcc\ngcc-major=8\noverflow-guard=ran"),
        Outcome::Present,
        "gcc 8 and later fold this at -O0, so an unoptimized build that ran the guard was \
         told to keep it"
    );
    assert_eq!(
        overflow_of("optimize=no\nfrontend=gcc\ngcc-major=7\noverflow-guard=ran"),
        Outcome::Indeterminate,
        "gcc 7 keeps the guard at -O0 regardless, as clang does; crediting it is a false `on`"
    );
    assert_eq!(
        overflow_of("optimize=no\nfrontend=gcc\noverflow-guard=ran"),
        Outcome::Indeterminate,
        "gcc evidence without the probe's version line cannot say which side \
         of gcc 8 produced it"
    );
    assert_eq!(
        overflow_of("optimize=no\nfrontend=gcc\ngcc-major=7\noverflow-guard=deleted"),
        Outcome::Absent,
        "a folded guard is attributable on any gcc"
    );
    assert_eq!(
        overflow_of("optimize=yes\nfrontend=gcc\ngcc-major=7\noverflow-guard=ran"),
        Outcome::Indeterminate,
        "optimized on gcc 7 with no build record: the level cannot be read, and gcc 7 keeps \
         the guard at -O1 and -Og without the flag, so it is withheld rather than read as -O2"
    );
    assert_eq!(
        overflow_of("optimize=no\nfrontend=clang\noverflow-guard=ran"),
        Outcome::Indeterminate,
        "clang keeps the guard at -O0 regardless; crediting it is a false `on`"
    );
    assert_eq!(
        overflow_of("optimize=no\nfrontend=clang\noverflow-guard=deleted"),
        Outcome::Absent,
        "a folded guard is attributable at any level: nothing but the optimizer or \
         the front end removes it"
    );
    assert_eq!(
        overflow_of("overflow-guard=ran"),
        Outcome::Indeterminate,
        "evidence without these markers cannot say which \
         compiler produced it, and is withheld rather than assumed"
    );
}

/// Each sentence the gcc and clang branches publish is whole: one space between words, and
/// the version it read named in it.
///
/// The published defect: the gcc and clang literals lost their line continuations, so the
/// four gcc 4.8 to 7.5 bare reports of the fleet carried "a front end" followed by a run of
/// spaces inside the sentence, and the clang reading two such runs.
#[test]
fn an_unoptimized_guard_reading_is_published_whole() {
    for (stdout, named) in [
        (
            "optimize=no\nfrontend=gcc\ngcc-major=16\noverflow-guard=ran",
            "gcc 16,",
        ),
        (
            "optimize=no\nfrontend=gcc\ngcc-major=7\noverflow-guard=ran",
            "gcc 7:",
        ),
        (
            "optimize=no\nfrontend=gcc\ngcc-major=x\noverflow-guard=ran",
            "no readable",
        ),
        (
            "optimize=no\nfrontend=gcc\noverflow-guard=ran",
            "no readable",
        ),
        (
            "optimize=no\nfrontend=clang\noverflow-guard=ran",
            "clang keeps it",
        ),
        (
            "optimize=no\nfrontend=other\noverflow-guard=ran",
            "gcc or clang",
        ),
        ("optimize=no\noverflow-guard=ran", "gcc or clang"),
        (
            "optimize=yes\nfrontend=gcc\ngcc-major=7\noverflow-guard=ran",
            "gcc 7 with no build record",
        ),
    ] {
        let d = overflow_reading(stdout, "");
        assert!(
            !d.observed.contains("  ") && !d.observed.contains('\n'),
            "{stdout:?}: a run of whitespace inside the sentence: {:?}",
            d.observed
        );
        assert!(
            d.observed.contains(named),
            "{stdout:?}: the sentence names {named:?}: {:?}",
            d.observed
        );
    }
}

/// The reading of `detect_no_strict_overflow` for a guard that ran, silently, in an
/// optimized gcc build of `major` (`None`: a run with no `gcc-major=` line), compiled by the
/// words `flags` after the driver.
fn optimized_gcc_reading(major: Option<u32>, flags: Option<&[&str]>) -> Detection {
    let macros = BTreeMap::new();
    let version = major.map_or(String::new(), |major| format!("gcc-major={major}\n"));
    let run = exited_run(
        0,
        &format!("optimize=yes\nfrontend=gcc\n{version}overflow-guard=ran"),
    );
    let build = flags.map(|flags| {
        let mut argv = vec!["/usr/bin/cc".to_owned()];
        argv.extend(flags.iter().map(|w| (*w).to_owned()));
        argv.extend(
            ["-o", "ub-signed-overflow-measured", "ub_signed_overflow.c"].map(str::to_owned),
        );
        crate::compile::BuildRecord {
            argv,
            dropped_flags: Vec::new(),
            exit_status: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
            artifact_sha256: None,
            stdout_sha256: None,
            stdout_unterminated: false,
        }
    });
    detect_no_strict_overflow(&Evidence {
        macros: &macros,
        elf: None,
        build: build.as_ref(),
        run: Some(&run),
        workdir: None,
    })
}

/// One row of the optimized-gcc tables: the reading of a gcc 7 build compiled by `flags`
/// is `want`, its sentence names `named` and is whole.
fn optimized_gcc_7_row(flags: &[&str], want: Outcome, named: &str) {
    let d = optimized_gcc_reading(Some(7), Some(flags));
    assert_eq!(d.outcome, want, "{flags:?}: {:?}", d.observed);
    assert!(
        d.observed.contains(named),
        "{flags:?}: names {named:?}: {:?}",
        d.observed
    );
    assert!(
        !d.observed.contains("  "),
        "{flags:?}: a run of spaces: {:?}",
        d.observed
    );
}

/// An optimized gcc before 8 that ran the guard is read by the last of the driver's own
/// `-O` words on its compile line: `on` at a level that gcc folds the guard at without the
/// flag, withheld at one it keeps it at.
///
/// The defect this holds out: read by the guard alone, `--profile explicit --flags -O1` reads
/// `on` under gcc 4.8.4, 5.4.0 and 7.5.0 (x86_64), whose guard runs at -O1 without the flag.
/// The rows are the levels gcc accepts, the orders two words can come in, and the `-O` words
/// that are not the driver's; each sentence names the level, and is whole.
#[test]
fn an_optimized_gcc_before_8_guard_is_read_by_its_compile_lines_last_level() {
    let p = Outcome::Present;
    let i = Outcome::Indeterminate;
    let row = optimized_gcc_7_row;
    // The lists are pinned to the measured sets, and each level is a literal row, so a level
    // moved from one list to the other fails here rather than reading as its new list says.
    assert_eq!(GCC_BEFORE_8_FOLDING_LEVELS, ["-O2", "-O3", "-Os", "-Ofast"]);
    assert_eq!(GCC_BEFORE_8_KEEPING_LEVELS, ["-O", "-O1", "-Og"]);
    row(&["-O2"], p, "at -O2:");
    row(&["-O3"], p, "at -O3:");
    row(&["-Os"], p, "at -Os:");
    row(&["-Ofast"], p, "at -Ofast:");
    // The keeping sentence is told from the unmeasured-level one by the clause after the
    // colon, so a level dropped from the keeping list fails its row.
    let keeps = "gcc 4.8, 5.4 and 7.5 keep it";
    row(&["-O"], i, &format!("at -O on gcc 7: {keeps}"));
    row(&["-O1"], i, &format!("at -O1 on gcc 7: {keeps}"));
    row(&["-Og"], i, &format!("at -Og on gcc 7: {keeps}"));
    row(&["-O1", "-O2"], p, "at -O2:");
    row(&["-O2", "-O1"], i, &format!("at -O1 on gcc 7: {keeps}"));
    row(&["-O2", "-Og", "-O3"], p, "at -O3:");
    row(&["-Wl,-O1", "-O2"], p, "at -O2:");
    row(&["-O2", "-Wl,-O1"], p, "at -O2:");
    row(&["-O2", "-Xlinker", "-O1"], p, "at -O2:");
    row(&["-O2", "-Xassembler", "-O1"], p, "at -O2:");
    row(&["-O2", "-Xpreprocessor", "-O1"], p, "at -O2:");
}

/// Where no level is readable the reading is withheld, never `on`: no `-O` word, `-O0` as
/// the last word beside an optimized run, a level not measured, or no build record; and
/// gcc 8 and later are read without the words, gcc 4 as gcc 7 is.
#[test]
fn an_optimized_gcc_before_8_guard_withholds_where_no_level_is_readable() {
    let p = Outcome::Present;
    let i = Outcome::Indeterminate;
    let row = optimized_gcc_7_row;
    row(&["-Xlinker", "-O2"], i, "no -O word");
    row(&["-fno-strict-overflow"], i, "no -O word");
    row(&[], i, "no -O word");
    row(&["-O0"], i, "last -O word is -O0");
    row(&["-O2", "-O0"], i, "last -O word is -O0");
    row(&["-Oz"], i, "at -Oz on gcc 7, a level not measured");
    row(&["-O4"], i, "at -O4 on gcc 7, a level not measured");
    row(
        &["-O2", "-ObjC"],
        i,
        "at -ObjC on gcc 7, a level not measured",
    );
    let none = optimized_gcc_reading(Some(7), None);
    assert_eq!(none.outcome, i, "{:?}", none.observed);
    assert!(
        none.observed.contains("no build record"),
        "{:?}",
        none.observed
    );
    // gcc 8 and later are read without the words: the level decides nothing there.
    for flags in [&["-O1"][..], &["-O2"], &[]] {
        let d = optimized_gcc_reading(Some(8), Some(flags));
        assert_eq!(d.outcome, p, "gcc 8 {flags:?}: {:?}", d.observed);
        assert_eq!(d.observed, "the overflow guard survived and fired");
    }
    let d = optimized_gcc_reading(Some(4), Some(&["-O1"]));
    assert_eq!(d.outcome, i, "gcc 4: {:?}", d.observed);
    assert!(d.observed.contains("on gcc 4"), "{:?}", d.observed);
}

/// The spellings and words beyond the plain `-O` levels: gcc's `--optimize` and
/// `--optimize=X` are read as the `-O` word gcc makes of them (gcc 7.5.0 ran the guard under
/// `-O2 --optimize=1` and `-O2 --optimize` and folded it under `-O1 --optimize=2`), and a
/// `-specs` or `-wrapper` word withholds whatever the levels say (a specs file appending
/// `-O1` to `cc1_options` under `-O2` ran the guard on 7.5.0).
#[test]
fn an_optimized_gcc_guards_long_spellings_and_specs_files_are_read_safely() {
    let p = Outcome::Present;
    let i = Outcome::Indeterminate;
    let row = optimized_gcc_7_row;
    let keeps = "gcc 4.8, 5.4 and 7.5 keep it";
    row(
        &["-O2", "--optimize=1"],
        i,
        &format!("at --optimize=1 (gcc's -O1) on gcc 7: {keeps}"),
    );
    row(
        &["-O2", "--optimize"],
        i,
        &format!("at --optimize (gcc's -O) on gcc 7: {keeps}"),
    );
    row(&["--optimize=2"], p, "at --optimize=2 (gcc's -O2):");
    row(&["-O1", "--optimize=2"], p, "at --optimize=2 (gcc's -O2):");
    row(&["--optimize=s"], p, "at --optimize=s (gcc's -Os):");
    row(
        &["--optimize=0"],
        i,
        "last -O word is --optimize=0 (gcc's -O0)",
    );
    // Not the long name: gcc refuses it, and the reader carries no level from it.
    row(&["--optimizer=2"], i, "no -O word");
    row(&["-O2", "-specs=low.specs"], i, "carries -specs=low.specs");
    row(&["-O2", "-specs", "low.specs"], i, "carries -specs,");
    row(
        &["-O2", "--specs=low.specs"],
        i,
        "carries --specs=low.specs",
    );
    row(&["-specs=low.specs", "-O2"], i, "carries -specs=low.specs");
    row(&["-O2", "-wrapper", "/opt/w"], i, "carries -wrapper,");
    row(&["-O2", "-B/opt/tc/"], i, "carries -B/opt/tc/,");
    row(&["-O2", "-B", "/opt/tc/"], i, "carries -B,");
    row(
        &["-O2", "--prefix=/opt/tc/"],
        i,
        "carries --prefix=/opt/tc/,",
    );
    row(
        &["--optimize=fast"],
        p,
        "at --optimize=fast (gcc's -Ofast):",
    );
    row(
        &["-O2", "--optimize="],
        i,
        "at --optimize= (gcc's -O) on gcc 7: gcc 4.8",
    );
}

/// The abbreviations gcc's driver completes to `--optimize` read as the level they name
/// (7.5.0 ran the guard under `-O2 --opti`), a word that is not the long name is an
/// unmeasured level, and a forced include, which can carry `#pragma GCC optimize`, withholds
/// in each spelling (7.5.0 ran the guard under `-O2 -include h`, `-Wp,-include,h` and
/// `-Xpreprocessor -include h` with `#pragma GCC optimize ("O1")` in `h`).
#[test]
fn an_optimized_gcc_guards_abbreviations_and_forced_includes_are_read_safely() {
    let p = Outcome::Present;
    let i = Outcome::Indeterminate;
    let row = optimized_gcc_7_row;
    let keeps = "gcc 4.8, 5.4 and 7.5 keep it";
    row(
        &["-O2", "--opti"],
        i,
        &format!("at --opti (gcc's -O) on gcc 7: {keeps}"),
    );
    // An abbreviation joined to a level gcc refuses (`--op=2` and longer, measured on
    // 16.1.1; `toolchain::LONG_ALIASES`): no level is read from it, and the line's `-O1`
    // stands.
    row(
        &["-O1", "--optimiz=2"],
        i,
        &format!("at -O1 on gcc 7: {keeps}"),
    );
    row(
        &["-O1", "--op"],
        i,
        &format!("at --op (gcc's -O) on gcc 7: {keeps}"),
    );
    row(&["--optimize=2", "--o"], p, "at --optimize=2 (gcc's -O2):");
    // `--o=1` names no option to gcc (`--op` is the shortest it takes, and no abbreviation
    // joins a level), so nothing is read from it and the line's `-O2` stands.
    row(&["-O2", "--o=1"], p, "at -O2:");
    row(
        &["-O2", "--optimize=01"],
        i,
        "at --optimize=01 (gcc's -O01) on gcc 7, a level not",
    );
    // `--output` is gcc's `-o`, not a level, so it is not read as one.
    row(&["-O2", "--output=x"], p, "at -O2:");
    row(&["-O2", "-include", "/opt/h"], i, "carries -include,");
    row(&["-O2", "-include/opt/h"], i, "carries -include/opt/h,");
    row(&["-O2", "-imacros", "/opt/h"], i, "carries -imacros,");
    row(
        &["-O2", "-Wp,-include,/opt/h"],
        i,
        "carries -Wp,-include,/opt/h,",
    );
    row(
        &[
            "-O2",
            "-Xpreprocessor",
            "-include",
            "-Xpreprocessor",
            "/opt/h",
        ],
        i,
        "carries -include,",
    );
    row(&["-O2", "-Wp,-D_FORTIFY_SOURCE=2"], p, "at -O2:");
    // gcc takes the forced include with two dashes as well (7.5.0 ran the guard under
    // `-O2 --include h`, `--include=h` and `-Wp,--include,h` with the pragma in `h`).
    row(&["-O2", "--include", "/opt/h"], i, "carries --include,");
    row(&["-O2", "--include=/opt/h"], i, "carries --include=/opt/h,");
    row(&["-O2", "--imacros=/opt/h"], i, "carries --imacros=/opt/h,");
    row(
        &["-O2", "-Wp,--include,/opt/h"],
        i,
        "carries -Wp,--include,/opt/h,",
    );
    // The include anywhere in the `-Wp,` list, not only first.
    row(
        &["-O2", "-Wp,-D_X,-include,/opt/h"],
        i,
        "carries -Wp,-D_X,-include,/opt/h,",
    );
    row(&["-O2", "---include"], p, "at -O2:");
    // gcc's driver completes an unambiguous prefix of a long option (7.5.0 ran the guard
    // under `-O2 --pref /dir/` and `-O2 --spec file` with the specs file of the rows above),
    // so a prefix of the route words from four letters is one of them; shorter ones gcc
    // rejects (`--inc`, `--includ=h`), so they never build. A plugin can do anything to the
    // compile, so `-fplugin` withholds too.
    row(&["-O2", "--pref", "/opt/tc/"], i, "carries --pref,");
    row(&["-O2", "--spec", "/opt/f"], i, "carries --spec,");
    row(&["-O2", "--imacr", "/opt/h"], i, "carries --imacr,");
    // `--incl` names no option to gcc (`--include` begins several, so no prefix of it is
    // unique; measured on 16.1.1), and nothing is read from it; the abbreviation of
    // `--imacros` gcc takes, `--im`, is a forced macro file and withholds.
    row(&["-O2", "--incl=/opt/h"], p, "at -O2:");
    row(&["-O2", "--im", "/opt/h"], i, "carries --im,");
    row(
        &["-O2", "-fplugin=/opt/p.so"],
        i,
        "carries -fplugin=/opt/p.so,",
    );
    row(&["-O2", "--prefer-x"], p, "at -O2:");
    row(&["-O2", "--special"], p, "at -O2:");
    // The value of an option that takes the next word is no word of its own: `-u -B` names
    // a symbol, `-o --pref` an output file, `-L -specs` a directory, and `-Xlinker` hands
    // `-specs=f` to the linker; the pair is passed over as the classifier reads it, and a
    // resetting word after the pair is still found.
    row(&["-O2", "-u", "-B"], p, "at -O2:");
    row(&["-O2", "-o", "--pref"], p, "at -O2:");
    row(&["-O2", "-L", "-specs"], p, "at -O2:");
    row(&["-O2", "--force-link", "-B", "-O2"], p, "at -O2:");
    row(&["-O2", "-Xlinker", "-specs=f"], p, "at -O2:");
    row(&["-O2", "-u", "-B", "-specs=f"], i, "carries -specs=f,");
    // Handed to `cc1`, which loads a plugin and reads a forced include; applied by clang for
    // one architecture; and gcc's generic map (`--plugin=` is `-fplugin=`).
    row(
        &["-O2", "-Xpreprocessor", "-fplugin=/opt/p.so"],
        i,
        "carries -fplugin=/opt/p.so,",
    );
    row(
        &["-O2", "-Xarch_x86_64", "-B/opt/tc/"],
        i,
        "carries -B/opt/tc/,",
    );
    row(&["-O2", "-Xarch_x86_64", "-O1"], p, "at -O2:");
    row(
        &["-O2", "--plugin=/opt/p.so"],
        i,
        "carries --plugin=/opt/p.so,",
    );
    row(
        &["-O2", "-Wp,-D_X,-fplugin=/opt/p.so"],
        i,
        "carries -Wp,-D_X,-fplugin=/opt/p.so,",
    );
}

/// A gcc that reported no major version (a run with no `gcc-major=` line, or one that is no
/// number) is read as a gcc before 8 is, since the version that would excuse it is absent:
/// `on` at -O2, withheld at -O1, with no word and with no build record.
#[test]
fn an_optimized_gcc_without_a_readable_version_is_read_as_a_gcc_before_8() {
    let p = Outcome::Present;
    let i = Outcome::Indeterminate;
    let who = "a gcc that reported no readable major version";
    let row = |flags: &[&str], want: Outcome, named: &str| {
        let d = optimized_gcc_reading(None, Some(flags));
        assert_eq!(d.outcome, want, "{flags:?}: {:?}", d.observed);
        assert!(
            d.observed.contains(named),
            "{flags:?}: names {named:?}: {:?}",
            d.observed
        );
    };
    row(
        &["-O1"],
        i,
        &format!("at -O1 on {who}: gcc 4.8, 5.4 and 7.5 keep it"),
    );
    row(&["-O2"], p, &format!("on {who} at -O2:"));
    row(
        &[],
        i,
        &format!("{who} whose compile line carries no -O word"),
    );
    let unversioned = optimized_gcc_reading(None, None);
    assert_eq!(unversioned.outcome, i, "{:?}", unversioned.observed);
    assert!(
        unversioned
            .observed
            .contains(&format!("{who} with no build record")),
        "{:?}",
        unversioned.observed
    );
    let unreadable = overflow_reading(
        "optimize=yes\nfrontend=gcc\ngcc-major=x\noverflow-guard=ran",
        "",
    );
    assert_eq!(unreadable.outcome, i, "{:?}", unreadable.observed);
}

/// The `no-strict-overflow` check's published notes say what the decoder does with an
/// optimized gcc before 8: every folding level is named as read `on`, every keeping level
/// as withheld, and no sentence says a build at those levels "reads on with or without the
/// flag", which the decoder contradicts. The notes reach every report and
/// `chard probes`, so they are a second copy of the rule, held here to the constants.
#[test]
fn the_overflow_checks_notes_name_the_levels_the_decoder_reads() {
    let check = crate::probe::CORPUS
        .iter()
        .flat_map(|p| p.checks)
        .find(|c| c.id == "no-strict-overflow")
        .expect("the no-strict-overflow check");
    let notes = check.notes;
    assert!(
        !notes.contains("reads on with or without the flag"),
        "a sentence the decoder contradicts: {notes}"
    );
    let folding = GCC_BEFORE_8_FOLDING_LEVELS
        .join(", ")
        .replacen(", -Ofast", " and -Ofast", 1);
    let keeping = GCC_BEFORE_8_KEEPING_LEVELS
        .join(", ")
        .replacen(", -Og", " and -Og", 1);
    assert!(
        notes.contains(&format!("on at {folding}")),
        "the notes name the folding levels {folding}: {notes}"
    );
    assert!(
        notes.contains(&format!("withheld at {keeping}")),
        "the notes name the keeping levels {keeping}: {notes}"
    );
    assert!(!notes.contains("  "), "a run of spaces: {notes}");
    assert!(
        notes.contains(
            "where no word, a specs file, a prefix directory, a forced include, a plugin or a \
             wrapper leaves the level unreadable"
        ),
        "the notes name the unreadable cases: {notes}"
    );
    assert!(
        notes.contains("-Ofast measured on 7.5 alone"),
        "the notes name -Ofast's measured scope: {notes}"
    );
}

/// The version decides on each side of [`GCC_FOLDS_UNOPTIMIZED_FROM`], read from the
/// constant so the test moves with it, and `gcc-major=` is read as the decoder's doc says:
/// the last line carrying the key, trimmed, its first word a number or no version at all.
#[test]
fn an_unoptimized_gcc_guard_is_read_by_the_last_version_line_and_the_threshold() {
    let from = GCC_FOLDS_UNOPTIMIZED_FROM;
    let unoptimized = |version_lines: &str| {
        overflow_reading(
            &format!("optimize=no\nfrontend=gcc\n{version_lines}overflow-guard=ran"),
            "",
        )
        .outcome
    };
    for major in [0, 4, 5, 6, from - 1, from, from + 1, 16, 99] {
        let want = if major >= from {
            Outcome::Present
        } else {
            Outcome::Indeterminate
        };
        assert_eq!(
            unoptimized(&format!("gcc-major={major}\n")),
            want,
            "gcc {major} against the threshold {from}"
        );
    }
    for (lines, want, why) in [
        (
            "gcc-major=7\ngcc-major=8\n",
            Outcome::Present,
            "the last line wins",
        ),
        (
            "gcc-major=8\ngcc-major=7\n",
            Outcome::Indeterminate,
            "the last line wins, downward too",
        ),
        (
            "gcc-major=8\ngcc-major=x\n",
            Outcome::Indeterminate,
            "an unreadable last line is no version; the earlier one is not consulted",
        ),
        ("  gcc-major=8  \n", Outcome::Present, "the line is trimmed"),
        (
            "gcc-major=8 trailing\n",
            Outcome::Present,
            "the first word is the value",
        ),
        (
            "gcc-major=8x\n",
            Outcome::Indeterminate,
            "a word that is not a number",
        ),
        (
            "gcc-major=-8\n",
            Outcome::Indeterminate,
            "a negative is no version",
        ),
        (
            "x gcc-major=8\n",
            Outcome::Indeterminate,
            "the key opens its line",
        ),
    ] {
        assert_eq!(unoptimized(lines), want, "{lines:?}: {why}");
    }
}

/// An optimized gcc below 8 that ran the guard is read by its compile line, and with no
/// build record to read it from is withheld by a sentence naming the levels the probe cannot
/// see, as is a gcc with no version line; from gcc 8 on, and on clang, the sentence is the
/// plain one.
#[test]
fn an_optimized_old_gcc_on_names_the_levels_it_cannot_tell_apart() {
    for (stdout, who) in [
        (
            "optimize=yes\nfrontend=gcc\ngcc-major=7\noverflow-guard=ran",
            "gcc 7",
        ),
        (
            "optimize=yes\nfrontend=gcc\noverflow-guard=ran",
            "no readable major version",
        ),
    ] {
        let old = overflow_reading(stdout, "");
        assert_eq!(old.outcome, Outcome::Indeterminate, "{stdout:?}");
        assert!(
            old.observed.contains("no build record")
                && old.observed.contains("-O1")
                && old.observed.contains(who),
            "{stdout:?}: {:?}",
            old.observed
        );
    }
    for stdout in [
        "optimize=yes\nfrontend=gcc\ngcc-major=8\noverflow-guard=ran",
        "optimize=yes\nfrontend=clang\noverflow-guard=ran",
    ] {
        let d = overflow_reading(stdout, "");
        assert_eq!(d.outcome, Outcome::Present, "{stdout:?}");
        assert_eq!(
            d.observed, "the overflow guard survived and fired",
            "{stdout:?}"
        );
    }
}

/// The reading of `detect_no_strict_overflow` for a run with this stdout and stderr.
fn overflow_reading(stdout: &str, stderr: &str) -> Detection {
    let macros = BTreeMap::new();
    let mut run = exited_run(0, stdout);
    run.stderr = stderr.to_owned();
    detect_no_strict_overflow(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

/// A guard kept by a sanitizer's checked add is not the flag.
///
/// The published defect: clang 22.1.8 on Fedora 44 x86_64 read `-O2` as `off` and
/// `-O2 -fsanitize=undefined` as `on`. The sanitizer's checked add cannot be folded, so
/// the guard survives and fires without `-fwrapv` or `-fno-strict-overflow`, and the
/// control arms, built from their own flags alone, discriminated over a cell the
/// sanitizer had produced. The stderr strings here are the runs' own, measured under the
/// shapes in the test's names.
#[test]
fn a_guard_kept_beside_a_sanitizer_report_is_withheld() {
    const RAN: &str = "optimize=yes\nfrontend=clang\noverflow-guard=ran";
    let full = "ub_signed_overflow.c:55:11: runtime error: signed integer overflow: \
                2147483647 + 1 cannot be represented in type 'int'\n\
                SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ub_signed_overflow.c:55:11";
    let minimal = "ubsan: add-overflow by 0x00000000004013d6";

    for (shape, stderr) in [
        ("-fsanitize=undefined", full),
        ("-fsanitize=signed-integer-overflow", full),
        ("-fsanitize=integer", full),
        ("-fwrapv -fsanitize=signed-integer-overflow", full),
        ("-fsanitize=undefined -fsanitize-minimal-runtime", minimal),
        (
            "-fsanitize=signed-integer-overflow -fsanitize-minimal-runtime",
            minimal,
        ),
    ] {
        let d = overflow_reading(RAN, stderr);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{shape}: a guard that ran beside the sanitizer's report is the sanitizer's"
        );
        assert!(
            d.observed.contains("stderr"),
            "{shape}: the withheld reading names its cause: {}",
            d.observed
        );
    }
}

/// What the withholding must leave alone.
#[test]
fn a_guard_with_a_silent_stderr_or_none_at_all_reads_as_before() {
    let ran = "optimize=yes\nfrontend=clang\noverflow-guard=ran";
    let deleted = "optimize=yes\nfrontend=clang\noverflow-guard=deleted";
    assert_eq!(
        overflow_reading(ran, "").outcome,
        Outcome::Present,
        "-fwrapv, and -fwrapv -fsanitize=undefined, where clang drops the signed-overflow \
         check: the guard ran and nothing reported"
    );
    assert_eq!(
        overflow_reading(ran, "\n  \n").outcome,
        Outcome::Present,
        "blank lines are not output"
    );
    assert_eq!(
        overflow_reading(ran, "qemu: uncaught target signal 4 (Illegal instruction)").outcome,
        Outcome::Present,
        "the emulator's line about a death is not the probe's"
    );
    assert_eq!(
        overflow_reading(deleted, "").outcome,
        Outcome::Absent,
        "-fsanitize=undefined -fno-sanitize=signed-integer-overflow and -fsanitize=bounds: \
         a folded guard is attributable whatever else is compiled in"
    );
    assert_eq!(
        overflow_reading("", "").outcome,
        Outcome::Indeterminate,
        "a trapped or aborted sanitizer build printed no guard line"
    );
}

fn fortify_runtime_of(run: &RunRecord) -> Detection {
    let macros = BTreeMap::new();
    detect_fortify_runtime(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(run),
        workdir: None,
    })
}

/// Fortify is credited only for an abort that said it was fortify, and an absence is
/// credited only for a survivor that said it survived.
///
/// Both readings are conjunctions and both fail toward withholding, because each has
/// a neighbouring death that looks like it from one side only. A canary abort is an
/// abort — crediting it to fortify is a false `on` over a binary whose overflow was
/// caught by something else entirely — and a silent clean exit is a clean exit, but
/// one that never reached the check it was built to trip, so reading it as `off`
/// invents a result the probe did not produce.
#[test]
fn a_neighbouring_death_is_credited_to_neither_fortify_nor_its_absence() {
    let fortified = died_run("SIGABRT", "*** buffer overflow detected ***: terminated");
    assert_eq!(fortify_runtime_of(&fortified).outcome, Outcome::Present);

    // An abort, and not fortify's. The stack protector reached the overflow first.
    let canary = died_run("SIGABRT", "*** stack smashing detected ***: terminated");
    let d = fortify_runtime_of(&canary);
    assert_eq!(
        d.outcome,
        Outcome::Indeterminate,
        "a canary abort credited to fortify is a false `on`"
    );
    assert!(
        d.observed.contains("stack protector fired first"),
        "{}",
        d.observed
    );

    let survived = exited_run(0, PROBE_SURVIVED);
    assert_eq!(fortify_runtime_of(&survived).outcome, Outcome::Absent);

    // A clean exit that printed nothing never reached the check.
    let silent = fortify_runtime_of(&exited_run(0, ""));
    assert_eq!(silent.outcome, Outcome::Indeterminate);
    assert!(
        silent.observed.contains("unexpected termination"),
        "{}",
        silent.observed
    );

    // ...and the marker without a clean exit is not a survival either.
    let marker_but_died = fortify_runtime_of(&died_run("SIGSEGV", PROBE_SURVIVED));
    assert_eq!(marker_but_died.outcome, Outcome::Indeterminate);
}

/// Why the probe failed to measure is recorded, and `77` is not just another failure.
///
/// The probe exits 77 when it could not allocate the buffer it was going to overflow,
/// which says nothing about the toolchain and everything about the machine it ran on.
/// Folding it into "unexpected termination" would put a resource problem and a real
/// anomaly in the same cell, and a reader triaging a sweep needs them apart.
#[test]
fn a_probe_that_could_not_allocate_says_so_rather_than_reporting_an_anomaly() {
    let starved = fortify_runtime_of(&exited_run(77, ""));
    assert_eq!(starved.outcome, Outcome::Indeterminate);
    assert!(
        starved.observed.contains("probe could not allocate"),
        "{}",
        starved.observed
    );

    let anomalous = fortify_runtime_of(&exited_run(1, ""));
    assert_eq!(anomalous.outcome, Outcome::Indeterminate);
    assert!(
        anomalous.observed.contains("unexpected termination"),
        "{}",
        anomalous.observed
    );

    // The heap probe found its own size known to the compiler. Level 2 would then
    // fire like level 3, so neither level may be published from this run, and the
    // cell says which precondition failed rather than reading as an anomaly.
    let opaque_no_more = fortify_runtime_of(&exited_run(PROBE_EXIT_OPACITY_LOST, ""));
    assert_eq!(opaque_no_more.outcome, Outcome::Indeterminate);
    assert!(
        opaque_no_more.observed.contains("statically known"),
        "{}",
        opaque_no_more.observed
    );

    // The known-object probe found nothing of its own after `dst`, and the heap
    // probe found a chunk geometry its margin was not computed from. Each is the
    // probe declining to overflow into memory it cannot vouch for, and each names
    // itself rather than joining the anomalies.
    let unguarded = fortify_runtime_of(&exited_run(PROBE_EXIT_LAYOUT, ""));
    assert_eq!(unguarded.outcome, Outcome::Indeterminate);
    assert!(
        unguarded.observed.contains("no guard object"),
        "{}",
        unguarded.observed
    );
    let other_allocator = fortify_runtime_of(&exited_run(PROBE_EXIT_HEAP_GEOMETRY, ""));
    assert_eq!(other_allocator.outcome, Outcome::Indeterminate);
    assert!(
        other_allocator.observed.contains("chunk geometry"),
        "{}",
        other_allocator.observed
    );

    let timed_out = {
        let mut run = exited_run(0, "");
        run.timed_out = true;
        run.deadline_ms = Some(5000);
        fortify_runtime_of(&run)
    };
    assert!(
        timed_out
            .observed
            .contains("probe timed out at its 5000 ms deadline"),
        "a timed-out reading names the deadline it hit: {}",
        timed_out.observed
    );
}

/// The `%n` rung is its own observable, and a plain overflow abort is not it.
///
/// Rung 2' asks whether glibc rejects a `%n` directive pointing into writable memory.
/// A "buffer overflow detected" abort here means some other check fired, so crediting
/// it would report a rung the C library never demonstrated.
#[test]
fn the_percent_n_rung_is_not_credited_to_a_plain_overflow_abort() {
    let macros = BTreeMap::new();
    let percent_n_of = |run: &RunRecord| {
        detect_fortify_percent_n(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(run),
            workdir: None,
        })
    };

    // Both spellings, written out rather than taken from the constant: a test that
    // reads its evidence from the thing under test cannot fail when that thing is
    // wrong, which is how a missing singular would survive.
    for message in [
        "*** %n in writable segments detected ***",
        "*** %n in writable segment detected ***",
    ] {
        let fired = died_run("SIGABRT", message);
        assert_eq!(
            percent_n_of(&fired).outcome,
            Outcome::Present,
            "glibc prints both of these in the field: {message}"
        );
    }

    let other_check = died_run("SIGABRT", "*** buffer overflow detected ***");
    assert_eq!(percent_n_of(&other_check).outcome, Outcome::Indeterminate);

    assert_eq!(
        percent_n_of(&exited_run(0, PROBE_SURVIVED)).outcome,
        Outcome::Absent
    );

    // A clean exit with no marker did not reach the directive.
    let silent = percent_n_of(&exited_run(0, ""));
    assert_eq!(silent.outcome, Outcome::Indeterminate);
    assert!(
        silent
            .observed
            .contains("unexpected termination for this rung"),
        "{}",
        silent.observed
    );
}

/// The runtime detector's `observed` goes through the same cut, so a libc message at
/// the end of a long stderr is quoted rather than lost.
#[test]
fn a_runtime_observed_string_quotes_the_end_of_a_long_stderr() {
    let padding = "x".repeat(400);
    let stderr = format!("{padding}\n*** buffer overflow detected ***: terminated");
    let d = fortify_runtime_of(&died_run("SIGABRT", &stderr));
    assert_eq!(d.outcome, Outcome::Present);
    assert!(
        d.observed.contains("buffer overflow detected"),
        "the message is the informative end and must be quoted: {}",
        d.observed
    );
    assert!(
        d.observed.contains("chars omitted]"),
        "a cut without a marker reads as the whole stream: {}",
        d.observed
    );
    assert!(
        !d.observed.contains(&padding),
        "the budget is a budget: {}",
        d.observed
    );
}

/// The exit statuses the detector reads are the ones the probes define.
///
/// Two spellings of one vocabulary, in two languages: `CHARD_EXIT_*` in the header
/// every probe includes and `PROBE_EXIT_*` here. A number that moved in one place
/// would turn a named precondition failure back into `unexpected termination`, which
/// is still withheld and does not say why. The header is embedded in the binary,
/// so it is read back rather than assumed.
#[test]
fn the_probe_exit_vocabulary_is_the_one_the_header_defines() {
    let reserved = header_exit_statuses();
    let mirrored = [
        ("CHARD_EXIT_NO_ALLOCATION", PROBE_EXIT_NO_ALLOCATION),
        ("CHARD_EXIT_LAYOUT", PROBE_EXIT_LAYOUT),
        ("CHARD_EXIT_HEAP_GEOMETRY", PROBE_EXIT_HEAP_GEOMETRY),
        ("CHARD_EXIT_OPACITY_LOST", PROBE_EXIT_OPACITY_LOST),
    ];
    for (name, value) in mirrored {
        assert_eq!(
            reserved.iter().find(|(n, _)| *n == name).map(|(_, v)| *v),
            Some(value),
            "{name} disagrees with src/decode/runtime.rs, or the header no longer defines it"
        );
    }
    let mut accounted: Vec<&str> = mirrored.iter().map(|(n, _)| *n).collect();
    accounted.extend(EXIT_READ_BY_LINE.iter().map(|(n, _, _)| *n));
    accounted.sort_unstable();
    let mut names: Vec<&str> = reserved.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    assert_eq!(
        names, accounted,
        "every status chard_selfreport.h reserves is either read by number here or listed \
         in EXIT_READ_BY_LINE with the line read instead"
    );
    let mut values: Vec<i32> = reserved.iter().map(|(_, v)| *v).collect();
    values.sort_unstable();
    values.dedup();
    assert_eq!(
        values.len(),
        reserved.len(),
        "two preconditions share a status"
    );
    assert!(
        values.iter().all(|v| *v != 0),
        "a precondition failure must never look like a survivor"
    );
}

/// The statuses `chard_selfreport.h` reserves that no detector reads by number, each with
/// the probe sources that must spell it and what is read instead.
const EXIT_READ_BY_LINE: &[(&str, &[&str], &str)] = &[(
    "CHARD_EXIT_DECLINED",
    &["stack_clash.c", "stack_exec_runtime.c"],
    "stack_clash.c and stack_exec_runtime.c print `probe-invalid=<reason>` first, and \
     detect_stack_clash and detect_stack_exec read that line",
)];

/// Every `#define CHARD_EXIT_<NAME> <status>` in the header, in order.
fn header_exit_statuses() -> Vec<(&'static str, i32)> {
    SELFREPORT_HEADER
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix('#'))
        .filter_map(|rest| rest.trim_start().strip_prefix("define"))
        .map(str::split_whitespace)
        .filter_map(|mut parts| Some((parts.next()?, parts.next()?, parts.next())))
        .filter(|(name, _, _)| name.starts_with("CHARD_EXIT_"))
        .map(|(name, value, rest)| {
            assert!(
                rest.is_none(),
                "{name}: the header's status is not one token"
            );
            let status = value
                .parse()
                .unwrap_or_else(|_| panic!("{name}: the header's status is not a bare integer"));
            (name, status)
        })
        .collect()
}

/// The value of a C integer literal: decimal, `0x` hex, `0b` binary or `0` octal, with any
/// `u`/`l` suffix; `None` for anything else.
fn c_integer(token: &str) -> Option<i64> {
    let lower = token
        .trim_end_matches(['u', 'U', 'l', 'L'])
        .to_ascii_lowercase();
    let (radix, digits) = if let Some(hex) = lower.strip_prefix("0x") {
        (16, hex)
    } else if let Some(binary) = lower.strip_prefix("0b") {
        (2, binary)
    } else if let Some(octal) = lower.strip_prefix('0').filter(|o| !o.is_empty()) {
        (8, octal)
    } else {
        (10, lower.as_str())
    };
    i64::from_str_radix(digits, radix).ok()
}

/// Each number a statement that ends the program spells in C `code` (comments and literals
/// already blanked), as the value and the line the statement starts on.
///
/// The statement is `return`, `exit`, `_exit`, `_Exit` or `quick_exit` up to its `;`,
/// across lines, and every integer literal in it counts, so `return ok ? 0 : 0x4d;` is
/// read; so does every name a `#define` in `code` gives an integer, other than the header's
/// own `CHARD_EXIT_*` names, which are the spelling asked for. It is a tripwire on
/// spelling, not a proof: a character literal, a macro naming another macro, and a status
/// carried in a variable or returned by a helper are beyond it.
fn bare_exit_statuses(code: &str) -> Vec<(i64, usize)> {
    let aliases: BTreeMap<&str, i64> = code
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix('#')?.trim_start();
            let mut parts = rest.strip_prefix("define")?.split_whitespace();
            let (name, value) = (parts.next()?, parts.next()?);
            if parts.next().is_some() || name.starts_with("CHARD_EXIT_") {
                return None;
            }
            Some((
                name,
                c_integer(value.trim_start_matches('(').trim_end_matches(')'))?,
            ))
        })
        .collect();
    let mut tokens: Vec<(&str, usize)> = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let mut start = None;
        for (i, c) in line.char_indices() {
            let word = c.is_alphanumeric() || c == '_';
            match (word, start) {
                (true, None) => start = Some(i),
                (false, Some(s)) => {
                    tokens.push((&line[s..i], n + 1));
                    start = None;
                }
                _ => {}
            }
            if matches!(c, ';' | '{' | '}') {
                tokens.push((&line[i..=i], n + 1));
            }
        }
        if let Some(s) = start {
            tokens.push((&line[s..], n + 1));
        }
    }
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(&(token, line)) = tokens.get(i) {
        i += 1;
        if !matches!(token, "return" | "exit" | "_exit" | "_Exit" | "quick_exit") {
            continue;
        }
        while let Some(&(part, _)) = tokens.get(i) {
            if matches!(part, ";" | "{" | "}") {
                break;
            }
            if let Some(value) = c_integer(part).or_else(|| aliases.get(part).copied()) {
                found.push((value, line));
            }
            i += 1;
        }
    }
    found
}

/// No probe source spells a status the header reserves as a bare number.
///
/// The vocabulary test above holds the header against the Rust mirrors; this holds the
/// probes against the header. Thirteen refusal exits in two probes were once spelled `77`,
/// the header's allocation-failure status, for a precondition that was no allocation, and
/// nothing read the probe sources to see it.
#[test]
fn no_probe_spells_a_reserved_exit_status_as_a_number() {
    let reserved = header_exit_statuses();
    let mut sources: Vec<(&str, &str)> = vec![(SELFREPORT_HEADER_NAME, SELFREPORT_HEADER)];
    for probe in crate::probe::CORPUS {
        sources.push((probe.source_name, probe.source));
        for aux in probe.aux_libs {
            sources.push((aux.source_name, aux.source));
        }
    }
    let mut problems = Vec::new();
    let mut named = 0usize;
    let mut codes = BTreeMap::new();
    for (name, source) in &sources {
        let code = crate::probe::tests::c_code_only(name, source);
        for (status, line) in bare_exit_statuses(&code) {
            if let Some((reserved_name, _)) = reserved
                .iter()
                .find(|(_, v)| i64::from(*v) == status.rem_euclid(256))
            {
                problems.push(format!("{name}:{line}: {status} is {reserved_name}"));
            }
        }
        if *name != SELFREPORT_HEADER_NAME
            && code.lines().any(|l| {
                l.trim_start()
                    .strip_prefix('#')
                    .and_then(|r| r.trim_start().strip_prefix("define"))
                    .is_some_and(|r| r.trim_start().starts_with("CHARD_EXIT_"))
            })
        {
            problems.push(format!("{name}: redefines a status the header reserves"));
        }
        named += reserved
            .iter()
            .map(|(n, _)| code.matches(n).count())
            .sum::<usize>();
        codes.insert(*name, code);
    }
    for (status, spelled_in, _) in EXIT_READ_BY_LINE {
        for name in *spelled_in {
            match codes.get(name) {
                Some(code) if code.contains(status) => {}
                Some(_) => problems.push(format!("{name}: does not spell {status} in code")),
                None => problems.push(format!("{name}: is not a probe source the scan read")),
            }
        }
    }
    assert!(
        problems.is_empty(),
        "a reserved exit status spelled as a number, where the header's name is what ties \
         the probe to the reader:\n{}",
        problems.join("\n")
    );
    let on_disk: Vec<String> = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/probes"))
        .expect("the probes directory")
        .map(|e| {
            e.expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let unread: Vec<&String> = on_disk
        .iter()
        .filter(|f| !codes.contains_key(f.as_str()))
        .collect();
    assert!(
        unread.is_empty() && !on_disk.is_empty(),
        "every file under probes/ is a source this scan reads; not read: {unread:?}"
    );
    assert!(named > 0, "no probe spells a reserved status by name");
    eprintln!(
        "exit vocabulary: {} sources, {} reserved statuses, {named} named spellings in code, \
         0 bare",
        sources.len(),
        reserved.len()
    );
}

/// The scan above finds each spelling of a bare exit and leaves what is not one.
#[test]
fn the_bare_exit_scan_finds_each_spelling_and_leaves_a_marker() {
    let code = "    return 77;\n    _exit(78);\n    exit ( 79 );\n    _Exit(80);\n\
                if (ret == 77) {}\n    return CHARD_EXIT_DECLINED;\n    return 0;\n";
    assert_eq!(
        bare_exit_statuses(code),
        vec![(77, 1), (78, 2), (79, 3), (80, 4), (0, 7)]
    );
    let blanked = crate::probe::tests::c_code_only(
        "t.c",
        &["/", "* return 77; *", "/ say(\"return 77;\");\n"].concat(),
    );
    assert_eq!(bare_exit_statuses(&blanked), Vec::<(i64, usize)>::new());
    let disguised = "    _exit(0x4d);\n    return 77u;\n    return ok ? 0 : 0115;\n    exit(\n\
                     \x20       78);\n#define LOCAL 79\n    _exit(LOCAL);\n\
                     \x20   return CHARD_EXIT_DECLINED;\n#define CHARD_EXIT_DECLINED 81\n\
                     \x20   quick_exit(80);\n";
    assert_eq!(
        bare_exit_statuses(disguised),
        vec![
            (77, 1),
            (77, 2),
            (0, 3),
            (77, 3),
            (78, 4),
            (79, 7),
            (80, 10)
        ]
    );
    let more = "#define PAREN (79)\n    return 0b1001101;\n    _exit(PAREN);\n";
    assert_eq!(bare_exit_statuses(more), vec![(77, 2), (79, 3)]);
}

/// An observed aliasing store is credited to the flag only where a witness separates the
/// flag from the optimization level.
///
/// The published defect: gcc enables the rule by default only from `-O2` and `-Os`, so
/// at `-O1` and `-Og` the store is observed with no flag passed, and this check read
/// `on` there while both control arms, carrying their own `-O2`, discriminated. Each
/// stdout below is one the probe printed on Fedora 44 x86_64 and aarch64 or in a
/// container on the x86_64 host, 2026-10-01, and the comment names the build.
#[test]
fn an_observed_aliasing_store_is_credited_only_where_a_witness_shows_the_flag() {
    let macros = BTreeMap::new();
    let aliasing_of = |stdout: &str| {
        let run = exited_run(0, stdout);
        detect_no_strict_aliasing(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: None,
        })
        .outcome
    };
    let gcc = |o2: &str, level: &str, sibling: &str, store: &str| {
        format!(
            "optimize=yes\nattribute-check=honoured\no2-witness={o2}\nlevel-witness={level}\n\
             sibling-call={sibling}\naliasing-store={store}\n"
        )
    };

    // gcc 11.4 to 16.2.1 at -O1 and -Og bare, and gcc 11.4 there with the flag: the
    // level, not the flag.
    assert_eq!(
        aliasing_of(&gcc("lost", "observed", "not-made", "observed")),
        Outcome::Indeterminate
    );
    // gcc 12.2 to 16.2.1 at -O1 and -Og with -fno-strict-aliasing. The flag is present
    // and inert: the level does not apply the rule, so the build's own copy observes the
    // store bare as well, and the -O2 copy observes it only because it keeps the flag.
    // Credited from the -O2 copy alone this would read `on`, because these lines without
    // the `sibling-call` one are byte for byte what -O2 with the flag prints (gcc 16.1.1,
    // Fedora 44 x86_64); the tail-call witness is what names the level, and the project
    // ledger's entry on this check records the decision. gcc
    // 16.1.1 and 16.2.1 at -O2 and -Os with the flag and any of
    // -fno-optimize-sibling-calls, -finstrument-functions, -fstrub=all and
    // -fstrub=at-calls print these same lines, so an `on` the build earned is withheld
    // there and the decoder cannot tell. The reverse, -O1 -fno-strict-aliasing
    // -foptimize-sibling-calls, prints the -O2 lines and reads `on`; that is the
    // assumption `sibling-calls-follow-the-aliasing-level`, not a case a decoder can see.
    assert_eq!(
        aliasing_of(&gcc("observed", "observed", "not-made", "observed")),
        Outcome::Indeterminate,
        "gcc 12 and later at -O1 and -Og with -fno-strict-aliasing withhold: the flag \
         changes nothing at those levels"
    );
    // gcc 12.2 to 16.2.1 with -fno-strict-aliasing at -Os, -Oz, -O2, -O3 and -Ofast: the
    // build's tail call became a jump, so its level is one that applies the rule.
    assert_eq!(
        aliasing_of(&gcc("observed", "observed", "made", "observed")),
        Outcome::Present
    );
    // gcc 11.4 with -fno-strict-aliasing at -Os, -O2, -O3 and -Ofast: the copy rebuilt
    // from the level's defaults lost the store the build kept.
    assert_eq!(
        aliasing_of(&gcc("lost", "lost", "made", "observed")),
        Outcome::Present
    );
    // Every gcc at -Os, -O2 and -O3 without the flag, and with -fstrict-aliasing at any
    // optimized level.
    assert_eq!(
        aliasing_of(&gcc("lost", "lost", "made", "lost")),
        Outcome::Absent
    );
    assert_eq!(
        aliasing_of(&gcc("lost", "observed", "made", "lost")),
        Outcome::Absent
    );
    // The probe revision before the tail-call witness, as the recorded fixtures carry it:
    // read as it was published.
    assert_eq!(
        aliasing_of(
            "optimize=yes\nattribute-check=honoured\no2-witness=observed\n\
             level-witness=observed\naliasing-store=observed\n"
        ),
        Outcome::Present
    );
    // clang 14 to 23.1.2: no copy is built, and the rule applies from -O1.
    assert_eq!(
        aliasing_of("optimize=yes\no2-witness=not-built\naliasing-store=observed\n"),
        Outcome::Present
    );
    assert_eq!(
        aliasing_of("optimize=yes\no2-witness=not-built\naliasing-store=lost\n"),
        Outcome::Absent
    );

    // Not measured on any toolchain; each is a reading the witnesses cannot vouch for.
    assert_eq!(
        aliasing_of(
            "optimize=yes\nattribute-check=ignored\no2-witness=observed\n\
             level-witness=observed\nsibling-call=made\naliasing-store=observed\n"
        ),
        Outcome::Indeterminate,
        "an attribute the compiler did not honour leaves the witnesses meaningless"
    );
    assert_eq!(
        aliasing_of(
            "optimize=yes\nattribute-check=ignored\no2-witness=observed\n\
             level-witness=observed\naliasing-store=observed\n"
        ),
        Outcome::Indeterminate,
        "an ignored attribute withholds ahead of the credit kept for evidence recorded \
         before the tail-call witness"
    );
    assert_eq!(
        aliasing_of(&gcc("observed", "lost", "made", "lost")),
        Outcome::Indeterminate,
        "the -O2 copy kept a store the build lost; no level and flag produce that"
    );
    assert_eq!(
        aliasing_of(
            "optimize=yes\nattribute-check=honoured\no2-witness=lost\naliasing-store=observed\n"
        ),
        Outcome::Indeterminate,
        "with the -O2 copy lost and no level reading, nothing separates flag from level"
    );
    assert_eq!(
        aliasing_of(
            "optimize=no\nattribute-check=honoured\no2-witness=observed\n\
             level-witness=observed\naliasing-store=observed\n"
        ),
        Outcome::Indeterminate,
        "the -O0 gate stands whatever the witnesses say"
    );
    // Evidence without the witnesses reads without them, which is what the recorded
    // fixtures carry.
    assert_eq!(
        aliasing_of("optimize=yes\naliasing-store=observed\n"),
        Outcome::Present
    );
}

/// A runtime stream quoting the work directory is cut after the directory is made
/// relative, so the excerpt and its count are one string under every `--workdir`.
///
/// glibc before 2.26 named the artifact in its fortify message, and a sanitizer's report
/// names the source it was compiled from; both reach `stderr` with the work directory in
/// them. The excerpt is the 160-character tail [`detect_fortify_runtime`] quotes, under
/// directories of 10 and 150 characters, and the stream is over that budget under both.
/// A cut made ahead of the rewrite would make the count carry the directory's length.
#[test]
fn one_runtime_stream_under_two_work_directories_publishes_one_excerpt() {
    let macros = BTreeMap::new();
    let observed = |dir: &str| {
        let mut run = tavi_run("");
        run.signal = Some("SIGABRT".to_owned());
        run.exit_status = 134;
        run.stderr = format!(
            "{dir}/fortify_runtime.c:31: copying 64 bytes into a 16-byte buffer\n\
             *** buffer overflow detected ***: {dir}/fortify_runtime-bare terminated\n\
             ======= Backtrace: =========\n\
             /lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f3a1b2c37e5]\n"
        );
        let workdir = std::path::Path::new(dir);
        let detection = detect_fortify_runtime(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: Some(workdir),
        });
        assert_eq!(detection.outcome, Outcome::Present);
        let stream = crate::measure::publish_text(&run.stderr, workdir);
        assert!(stream.chars().count() > 160, "over budget: {stream}");
        crate::measure::publish_text(&detection.observed, workdir)
    };
    let short = "/w/chard-w";
    let long = format!("/w/{}", "chard-sweep-".repeat(12));
    assert_eq!((short.len(), long.len()), (10, 147));
    let published = observed(short);
    assert!(
        crate::probe::carries_a_cut(&published),
        "the stream is cut: {published}"
    );
    assert_eq!(
        published,
        observed(&long),
        "the excerpt does not depend on the work directory"
    );
}

/// An observed aliasing store is credited to the flag only where the copy compiled
/// without sanitizer instrumentation agrees.
///
/// The published defect: clang's recoverable alignment check, part of
/// `-fsanitize=undefined`, keeps the reload the rule would fold, so the store is observed
/// with no flag passed and this check read `on`. Each stdout below is one the probe
/// printed on Fedora 44 x86_64 or aarch64, or in a container on the x86_64 host,
/// 2026-10-01, and the comment names the build; `probes/ub_strict_aliasing.c` carries the
/// full set.
#[test]
fn an_observed_aliasing_store_is_withheld_where_only_the_instrumentation_kept_it() {
    let macros = BTreeMap::new();
    let aliasing_of = |stdout: &str| {
        let run = exited_run(0, stdout);
        detect_no_strict_aliasing(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: None,
        })
        .outcome
    };
    let clang = |bare: &str, store: &str| {
        format!(
            "optimize=yes\no2-witness=not-built\nuninstrumented-store={bare}\n\
             aliasing-store={store}\n"
        )
    };

    // clang 14.0.0, 18.1.3 and 22.1.8 at -O1 to -O3 with -fsanitize=undefined or
    // -fsanitize=alignment and no flag, and clang 22.1.8 with -fsanitize=type with or
    // without it: the instrumentation, not the flag.
    assert_eq!(
        aliasing_of(&clang("lost", "observed")),
        Outcome::Indeterminate
    );
    // The same clangs with -fno-strict-aliasing, under any sanitizer measured except
    // -fsanitize=type, and with none.
    assert_eq!(
        aliasing_of(&clang("observed", "observed")),
        Outcome::Present
    );
    // The same clangs with no flag under no sanitizer, -fsanitize=address, -thread,
    // -memory, -null or -undefined with -fsanitize-trap=all.
    assert_eq!(aliasing_of(&clang("lost", "lost")), Outcome::Absent);
    // gcc 11.4 to 16.2.1 under -fsanitize=undefined, -address, -alignment and -thread:
    // the copy agrees with the build at every level, so the gcc witnesses decide as they
    // did; at -O1 bare that is the level speaking.
    assert_eq!(
        aliasing_of(
            "optimize=yes\nattribute-check=honoured\no2-witness=lost\n\
             level-witness=observed\nsibling-call=not-made\nuninstrumented-store=observed\n\
             aliasing-store=observed\n"
        ),
        Outcome::Indeterminate
    );
    assert_eq!(
        aliasing_of(
            "optimize=yes\nattribute-check=honoured\no2-witness=observed\n\
             level-witness=observed\nsibling-call=made\nuninstrumented-store=observed\n\
             aliasing-store=observed\n"
        ),
        Outcome::Present
    );
    // A compiler without the no_sanitize attribute reads as the probe did before the copy.
    assert_eq!(
        aliasing_of(&clang("not-built", "observed")),
        Outcome::Present
    );

    // Not measured on any toolchain: the uninstrumented copy kept a store the build lost.
    assert_eq!(
        aliasing_of(&clang("observed", "lost")),
        Outcome::Indeterminate,
        "no instrumentation measured makes the build lose a store its uninstrumented copy \
         kept"
    );
}

fn zcur_detect(stdout: &str) -> Detection {
    let macros = BTreeMap::new();
    let run = tavi_run(stdout);
    detect_zero_call_used_regs(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

/// The lines below are the probe's output as measured on Fedora 44 on 2026-10-01: x86_64
/// under gcc 16.1.1 and clang 22.1.8, aarch64 under gcc 16.2.1 and clang 22.1.8.
#[test]
fn zero_call_used_regs_reads_each_form_from_the_registers() {
    let cases: &[(&str, Outcome, Option<&str>)] = &[
        // =used-gpr and =all, both architectures.
        (
            "ZCUR args=6 temp=r11 null=kkkkkk/k target=zzzzzz/z",
            Outcome::Present,
            Some("gpr"),
        ),
        (
            "ZCUR args=8 temp=x10 null=kkkkkkkk/k target=zzzzzzzz/z",
            Outcome::Present,
            Some("gpr"),
        ),
        // =used-gpr-arg.
        (
            "ZCUR args=6 temp=r11 null=kkkkkk/k target=zzzzzz/o",
            Outcome::Present,
            Some("arg"),
        ),
        (
            "ZCUR args=8 temp=x10 null=kkkkkkkk/k target=zzzzzzzz/o",
            Outcome::Present,
            Some("arg"),
        ),
        // No flag, =skip, and =used-gpr followed by =skip: gcc -O2 x86_64, clang -O2
        // x86_64, gcc -O0 aarch64, clang -O2 aarch64.
        (
            "ZCUR args=6 temp=r11 null=kkkkkk/k target=okkkkk/o",
            Outcome::Absent,
            None,
        ),
        (
            "ZCUR args=6 temp=r11 null=kkkkkk/k target=okokok/o",
            Outcome::Absent,
            None,
        ),
        (
            "ZCUR args=8 temp=x10 null=kkkkkkkk/k target=ookkkkkk/o",
            Outcome::Absent,
            None,
        ),
        (
            "ZCUR args=8 temp=x10 null=kkkkkkkk/k target=kkkkkkkk/o",
            Outcome::Absent,
            None,
        ),
        // gcc 16.2.1 aarch64 -O2 -fstack-protector-all with no zeroing flag: the canary
        // comparison leaves two argument registers zero, and the kept ones decide.
        (
            "ZCUR args=8 temp=x10 null=kkkkkkkk/k target=ozzkkokk/o",
            Outcome::Absent,
            None,
        ),
    ];
    for (line, outcome, level) in cases {
        let d = zcur_detect(line);
        assert_eq!(d.outcome, *outcome, "{line}: {}", d.observed);
        assert_eq!(d.level.as_deref(), *level, "{line}");
    }
}

/// A trampoline that does not give back its own markers around a function that only
/// returns has read nothing, whatever the compiled function's line says, and a cleared
/// line in particular must not read `on`.
#[test]
fn zero_call_used_regs_withholds_when_the_witness_fails() {
    for line in [
        "ZCUR args=6 temp=r11 null=kkkkzk/k target=zzzzzz/z",
        "ZCUR args=6 temp=r11 null=kkkkkk/o target=zzzzzz/z",
        "ZCUR args=8 temp=x10 null=zzzzzzzz/z target=kkkkkkkk/o",
    ] {
        let d = zcur_detect(line);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{line}");
        assert!(d.observed.contains("witness failed"), "{}", d.observed);
    }
}

/// Neither all cleared nor any kept is neither reading, and a line that is not the probe's
/// shape, or a probe built where it has no witness, is no reading at all.
#[test]
fn zero_call_used_regs_withholds_what_is_neither_reading() {
    for line in [
        "ZCUR args=6 temp=r11 null=kkkkkk/k target=zzzozz/z",
        "ZCUR args=6 temp=r11 null=kkkkkk/k target=zzzzz/z",
        "ZCUR args=6 temp=r11 null=kkkkkk/k target=zzzzzx/z",
        // A count the probe never prints: nothing about it is a register to read, and
        // every letter test passes over an empty string.
        "ZCUR args=0 temp=r11 null=/k target=/z",
        // The other architecture's count under this one's temporary, and the reverse.
        "ZCUR args=8 temp=r11 null=kkkkkkkk/k target=zzzzzzzz/z",
        "ZCUR args=6 temp=x10 null=kkkkkk/k target=zzzzzz/z",
        "ZCUR args=7 temp=x10 null=kkkkkkk/k target=zzzzzzz/z",
        "ZCUR args=6 temp=r11 null=kkkkkk/k",
        "ZCUR unsupported-arch",
        "",
    ] {
        let d = zcur_detect(line);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{line:?}: {}",
            d.observed
        );
    }
}

/// A withheld line says which way it failed: a ZCUR line the probe could not have printed
/// is not "no ZCUR line", and an empty run is.
#[test]
fn zero_call_used_regs_names_a_rejected_line_apart_from_a_missing_one() {
    let rejected = zcur_detect("ZCUR args=0 temp=r11 null=/k target=/z");
    assert!(
        rejected
            .observed
            .starts_with("a ZCUR line this probe does not print"),
        "{}",
        rejected.observed
    );
    let missing = zcur_detect("");
    assert!(
        missing.observed.starts_with("no ZCUR line"),
        "{}",
        missing.observed
    );
}

/// A run of `probes/strict_flex_arrays_enforced.c`, from one outcome per row. The markers
/// and glibc's diagnostic are spelled out here rather than taken from the detector's
/// constants, so a change to either side is a disagreement this test sees.
fn sfa_enforced_run(rows: [&str; 5]) -> RunRecord {
    let names = ["ctrl", "two", "one", "zero", "flex"];
    let mut lines = vec!["CHARD-REPORT-V1", "_FORTIFY_IMPL=glibc", "CHARD-REPORT-END"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for (name, outcome) in names.iter().zip(rows) {
        lines.push(format!("CHARD-SFA-ENFORCED begin row={name}"));
        match outcome {
            "caught" => {
                lines.push("*** buffer overflow detected ***: terminated".to_owned());
                lines.push(format!("CHARD-SFA-ENFORCED end row={name} status=signal:6"));
            }
            "survived" => lines.push(format!("CHARD-SFA-ENFORCED end row={name} status=exit:0")),
            other => lines.push(format!("CHARD-SFA-ENFORCED end row={name} {other}")),
        }
    }
    let stderr = lines.join("\n") + "\n";
    RunRecord {
        stdout: "optimize=yes\nrows=5\n".to_owned(),
        stderr,
        ..flex_run("")
    }
}

fn sfa_enforced_detect(run: &RunRecord) -> Detection {
    let macros = BTreeMap::new();
    detect_strict_flex_arrays_enforced(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(run),
        workdir: None,
    })
}

/// Each level is read from the trailing rows a fortified copy caught, once the ctrl row
/// shows a subobject bound is checked at all: the matrix measured on Fedora 44 x86_64
/// and aarch64 under gcc and clang, `-O2 -D_FORTIFY_SOURCE=2` and `=3`.
#[test]
fn each_enforced_flex_array_level_is_read_from_the_rows_caught() {
    let (c, s) = ("caught", "survived");
    for (rows, level) in [
        ([c, c, c, c, s], "3"),
        ([c, c, c, s, s], "2"),
        ([c, c, s, s, s], "1"),
    ] {
        let d = sfa_enforced_detect(&sfa_enforced_run(rows));
        assert_eq!(d.outcome, Outcome::Present, "{rows:?}: {}", d.observed);
        assert_eq!(d.level.as_deref(), Some(level), "{rows:?}");
    }
    // Level 0 is earned: the ctrl copy was caught, so fortify checks subobject bounds in
    // this build, and no trailing copy was.
    let zero = sfa_enforced_detect(&sfa_enforced_run([c, s, s, s, s]));
    assert_eq!(zero.outcome, Outcome::Absent, "{}", zero.observed);
    // A narrower spelling enforced while a wider one is not is no level.
    let impossible = sfa_enforced_detect(&sfa_enforced_run([c, s, c, c, s]));
    assert_eq!(impossible.outcome, Outcome::Indeterminate);
}

/// The probe's `note` line, which it writes where the host refuses to make it non-dumpable,
/// sits outside every row's markers and changes no row: the same rows read the
/// same level with and without it.
#[test]
fn a_note_outside_the_rows_changes_no_reading() {
    let (c, s) = ("caught", "survived");
    for rows in [[c, c, c, c, s], [c, s, s, s, s], [s, s, s, s, s]] {
        let plain = sfa_enforced_run(rows);
        let mut noted = sfa_enforced_run(rows);
        noted.stderr = noted.stderr.replacen(
            "CHARD-REPORT-END\n",
            "CHARD-REPORT-END\nCHARD-SFA-ENFORCED note dumpable-unset errno=1\n",
            1,
        );
        assert_ne!(plain.stderr, noted.stderr, "the note was not fed");
        let (a, b) = (sfa_enforced_detect(&plain), sfa_enforced_detect(&noted));
        assert_eq!(
            (a.outcome, a.level),
            (b.outcome, b.level),
            "{rows:?}: {}",
            b.observed
        );
    }
}

/// The probe makes itself non-dumpable before its first row, on Linux, and says so where
/// that fails: a `core_pattern` piped to a handler ignores a core limit of 0, and the
/// handler's second or more per crashing row crossed chard's probe deadline on a busy host,
/// so the positive control read indeterminate. Pinned on the source, since no run on a host
/// whose handler is fast can tell the call is gone.
#[test]
fn the_flex_probe_is_non_dumpable_before_its_first_row() {
    let source = include_str!("../../probes/strict_flex_arrays_enforced.c");
    let main = source
        .split_once("int main(void)")
        .map(|(_, body)| body)
        .expect("the probe's main");
    let first_row = main.find("run_row(").expect("a row in main");
    let before = &main[..first_row];
    let guard = before
        .find("#ifdef __linux__")
        .expect("the call is under __linux__");
    let call = before
        .find("prctl(PR_SET_DUMPABLE, 0")
        .expect("PR_SET_DUMPABLE is set before the first row");
    assert!(guard < call, "the call sits inside the __linux__ guard");
    assert!(
        before.contains("CHARD-SFA-ENFORCED note dumpable-unset"),
        "a failed call is said, outside the rows"
    );
}

/// A silent ctrl row is fortify not checking subobject bounds, which makes every trailing
/// row silent whatever the flag says. Reading that as level 0 is the clean-looking zero;
/// it is withheld, naming the unoptimized build where the probe says it was one.
#[test]
fn a_silent_ctrl_row_withholds_rather_than_reading_level_zero() {
    let s = "survived";
    let run = sfa_enforced_run([s, s, s, s, s]);
    let d = sfa_enforced_detect(&run);
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(d.observed.contains("no subobject bound"), "{}", d.observed);

    let unoptimized = RunRecord {
        stdout: "optimize=no\nrows=5\n".to_owned(),
        ..run
    };
    let d = sfa_enforced_detect(&unoptimized);
    assert_eq!(d.outcome, Outcome::Indeterminate);
    assert!(d.observed.contains("not optimized"), "{}", d.observed);
}

/// The flex row is the invariant: a true flexible member is bounded at no level, so a
/// caught flex copy is the probe failing, not a level above 3.
#[test]
fn a_caught_flex_row_withholds() {
    let c = "caught";
    let d = sfa_enforced_detect(&sfa_enforced_run([c, c, c, c, c]));
    assert_eq!(d.outcome, Outcome::Indeterminate);
    assert!(d.observed.contains("flex row"), "{}", d.observed);
}

/// A row is read from its own markers alone. An abort without glibc's diagnostic (the
/// stack protector, heap corruption), a segfault, a missing marker, or a probe that did not
/// itself exit 0 is no reading.
#[test]
fn a_row_that_is_neither_caught_nor_survived_withholds() {
    let (c, s) = ("caught", "survived");
    for odd in ["status=signal:6", "status=signal:11", "status=exit:1"] {
        let d = sfa_enforced_detect(&sfa_enforced_run([c, c, odd, s, s]));
        assert_eq!(d.outcome, Outcome::Indeterminate, "{odd}: {}", d.observed);
        assert!(d.observed.contains("row one"), "{odd}: {}", d.observed);
    }

    // A diagnostic in another row's segment is not this row's.
    let mut run = sfa_enforced_run([c, s, s, s, s]);
    run.stderr = run.stderr.replace(
        "CHARD-SFA-ENFORCED end row=two status=exit:0",
        "*** buffer overflow detected ***: terminated\nCHARD-SFA-ENFORCED end row=two \
         status=exit:0",
    );
    let d = sfa_enforced_detect(&run);
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);

    // A cut stream: the last row never got its end marker.
    let mut run = sfa_enforced_run([c, s, s, s, s]);
    run.stderr = run
        .stderr
        .replace("CHARD-SFA-ENFORCED end row=flex status=exit:0\n", "");
    let d = sfa_enforced_detect(&run);
    assert_eq!(d.outcome, Outcome::Indeterminate);
    assert!(
        d.observed.contains("row flex has no end marker"),
        "{}",
        d.observed
    );

    // Every row read, and the parent then died.
    let run = RunRecord {
        exit_status: -1,
        signal: Some("SIGSEGV".to_owned()),
        ..sfa_enforced_run([c, c, c, c, s])
    };
    assert_eq!(sfa_enforced_detect(&run).outcome, Outcome::Indeterminate);
}

/// A trap is credited only where the self-report names an implementation that traps;
/// a bare SIGTRAP from a build whose report names glibc, or none, is withheld.
#[test]
fn a_trapped_row_is_caught_only_under_a_trapping_implementation() {
    let s = "survived";
    let trap = "status=signal:5";
    let run = sfa_enforced_run([trap, trap, trap, trap, s]);
    // The run's stdout carries no self-report and the evidence no ELF facts, so no
    // implementation is named.
    assert_eq!(sfa_enforced_detect(&run).outcome, Outcome::Indeterminate);

    let apple = RunRecord {
        stdout: "CHARD-REPORT-V1\n_FORTIFY_IMPL=apple\nCHARD-REPORT-END\noptimize=yes\n".to_owned(),
        ..run
    };
    let d = sfa_enforced_detect(&apple);
    assert_eq!(d.outcome, Outcome::Present, "{}", d.observed);
    assert_eq!(d.level.as_deref(), Some("3"));
}

/// A silent abort in a row is FreeBSD's `__chk_fail` under the rule
/// `detect_fortify_runtime` applies: its wrappers named, and a checking call in the one
/// artifact every row is a child of. Without the call, or under another implementation,
/// the row is neither caught nor survived and the reading is withheld.
#[test]
fn a_silently_aborted_row_is_caught_only_under_freebsds_wrappers_with_a_checking_call() {
    use crate::elf::SymbolFact;
    let s = "survived";
    let abort = "status=signal:6";
    let macros = BTreeMap::new();
    let run = RunRecord {
        stdout: "CHARD-REPORT-V2\n_FORTIFY_IMPL=freebsd\n__FreeBSD__=15\nCHARD-REPORT-END\n\
                 optimize=yes\nlibc=freebsd\nrows=5\n"
            .to_owned(),
        ..sfa_enforced_run([abort, abort, abort, abort, s])
    };
    let detect = |report: &str, call: Option<&str>| {
        let mut elf = elf_with_report(report);
        elf.symbol_tables = vec![".dynsym".to_owned()];
        if let Some(name) = call {
            elf.watched_symbols.insert(
                name.to_owned(),
                SymbolFact {
                    defined: false,
                    tables: vec![".dynsym".to_owned()],
                    versioned: Vec::new(),
                },
            );
        }
        detect_strict_flex_arrays_enforced(&Evidence {
            macros: &macros,
            elf: Some(&elf),
            build: None,
            run: Some(&run),
            workdir: None,
        })
    };
    let freebsd = "CHARD-REPORT-V2\n_FORTIFY_IMPL=freebsd\n__FreeBSD__=15\nCHARD-REPORT-END\n";
    let d = detect(freebsd, Some("__strcpy_chk"));
    assert_eq!(d.outcome, Outcome::Present, "{}", d.observed);
    assert_eq!(d.level.as_deref(), Some("3"));
    for (report, call) in [
        (freebsd, None),
        (
            "CHARD-REPORT-V2\n_FORTIFY_IMPL=glibc\nCHARD-REPORT-END\n",
            Some("__strcpy_chk"),
        ),
    ] {
        let d = detect(report, call);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    }
    // A row whose child wrote something before its abort is not the silent kill.
    let loud = RunRecord {
        stderr: run.stderr.replacen(
            "end row=ctrl status=signal:6",
            "Assertion failed\nCHARD-SFA-ENFORCED end row=ctrl status=signal:6",
            1,
        ),
        ..run.clone()
    };
    let mut elf = elf_with_report(freebsd);
    elf.symbol_tables = vec![".dynsym".to_owned()];
    elf.watched_symbols.insert(
        "__strcpy_chk".to_owned(),
        SymbolFact {
            defined: false,
            tables: vec![".dynsym".to_owned()],
            versioned: Vec::new(),
        },
    );
    let d = detect_strict_flex_arrays_enforced(&Evidence {
        macros: &macros,
        elf: Some(&elf),
        build: None,
        run: Some(&loud),
        workdir: None,
    });
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

/// A silent ctrl row reads `absent` only where the self-report and the probe's `libc=` line
/// show a C library with no subobject bound under a request of 2 or more in an optimized
/// build: musl alone, OpenBSD's libc, musl with fortify-headers, FreeBSD's wrappers (which
/// size every string destination as a whole object) or a FreeBSD without them, the cases
/// `report::libc_limitation` turns into `unsupported`. The same silence on an unrecognised
/// library, beside `__GLIBC__`, under Apple's wrappers, or without the request, stays
/// withheld.
#[test]
fn a_silent_ctrl_row_is_absent_only_on_a_library_with_no_subobject_bound() {
    let s = "survived";
    let with_report = |report: &str, libc: &str| RunRecord {
        stdout: format!(
            "CHARD-REPORT-V2\n{report}\nCHARD-REPORT-END\noptimize=yes\nlibc={libc}\nrows=5\n"
        ),
        ..sfa_enforced_run([s, s, s, s, s])
    };
    for (report, libc) in [
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL undefined\n__GLIBC__ undefined",
            "musl",
        ),
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL undefined\n__GLIBC__ undefined",
            "openbsd",
        ),
        (
            "_FORTIFY_SOURCE=3\n_FORTIFY_IMPL=fortify-headers\n__GLIBC__ undefined",
            "musl",
        ),
        // FreeBSD 15's wrappers, and a FreeBSD below 15, which has none.
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL=freebsd\n__FreeBSD__=15\n__GLIBC__ undefined",
            "freebsd",
        ),
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL undefined\n__FreeBSD__=14\n__GLIBC__ undefined",
            "freebsd",
        ),
    ] {
        let d = sfa_enforced_detect(&with_report(report, libc));
        assert_eq!(
            d.outcome,
            Outcome::Absent,
            "{report} {libc}: {}",
            d.observed
        );
    }
    for (report, libc) in [
        // An implementation the self-report does not recognise is not one that is absent:
        // bionic's wrappers check subobject bounds and print `libc=?`.
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL undefined\n__GLIBC__ undefined",
            "?",
        ),
        // glibc whose wrappers something suppressed: never a level-0 reading.
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL undefined\n__GLIBC__=2",
            "?",
        ),
        ("_FORTIFY_SOURCE=2\n_FORTIFY_IMPL=glibc\n__GLIBC__=2", "?"),
        // Apple's wrappers check subobject bounds, so their silence is something else.
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL=apple\n__GLIBC__ undefined",
            "?",
        ),
        // A FreeBSD 15 whose wrappers did not instantiate, or whose release is unreadable:
        // not a library without the bound.
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL undefined\n__FreeBSD__=15\n__SSP_FORTIFY_LEVEL=0\n__GLIBC__ undefined",
            "freebsd",
        ),
        (
            "_FORTIFY_SOURCE=2\n_FORTIFY_IMPL undefined\n__GLIBC__ undefined",
            "freebsd",
        ),
        // No request, or one below 2: the build's configuration, not the library.
        (
            "_FORTIFY_SOURCE undefined\n_FORTIFY_IMPL undefined\n__GLIBC__ undefined",
            "musl",
        ),
        (
            "_FORTIFY_SOURCE=1\n_FORTIFY_IMPL=fortify-headers\n__GLIBC__ undefined",
            "musl",
        ),
    ] {
        let d = sfa_enforced_detect(&with_report(report, libc));
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{report} {libc}: {}",
            d.observed
        );
    }
}

fn trapv_detect(stdout: &str, signal: Option<&str>, stderr: &str) -> Detection {
    let macros = BTreeMap::new();
    let run = RunRecord {
        exit_status: if signal.is_some() { -1 } else { 0 },
        signal: signal.map(str::to_owned),
        stderr: stderr.to_owned(),
        ..tavi_run(stdout)
    };
    detect_trapv(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

const TRAPV_GCC: &str = "frontend=gcc\nubsan=no\ntrapv-overflow=attempted\n";
const TRAPV_CLANG: &str = "frontend=clang\nubsan=no\ntrapv-overflow=attempted\n";

#[test]
fn a_silent_gcc_abort_in_the_addition_is_trapv() {
    let d = trapv_detect(TRAPV_GCC, Some("SIGABRT"), "");
    assert_eq!(d.outcome, Outcome::Present, "{}", d.observed);
}

#[test]
fn a_clang_trap_with_no_ubsan_check_is_trapv_on_either_architecture() {
    for signal in ["SIGILL", "SIGTRAP"] {
        let d = trapv_detect(TRAPV_CLANG, Some(signal), "");
        assert_eq!(d.outcome, Outcome::Present, "{signal}: {}", d.observed);
    }
}

#[test]
fn a_wrapped_sum_is_the_flag_off() {
    let stdout = format!("{TRAPV_GCC}trapv-overflow=wrapped sum=-2147483648\n");
    let d = trapv_detect(&stdout, None, "");
    assert_eq!(d.outcome, Outcome::Absent, "{}", d.observed);
}

#[test]
fn a_trap_that_trap_mode_ubsan_could_have_raised_is_withheld() {
    // clang beside a compiled-in UBSan check, or where the feature test was missing.
    for ubsan in ["yes", "unknown"] {
        let stdout = format!("frontend=clang\nubsan={ubsan}\ntrapv-overflow=attempted\n");
        let d = trapv_detect(&stdout, Some("SIGILL"), "");
        assert_eq!(d.outcome, Outcome::Indeterminate, "{ubsan}: {}", d.observed);
    }
    // gcc's -ftrapv aborts, so a gcc trap is never it, whatever the feature test said.
    let d = trapv_detect(TRAPV_GCC, Some("SIGILL"), "");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

#[test]
fn an_abort_that_printed_or_came_from_clang_is_withheld() {
    let d = trapv_detect(
        TRAPV_GCC,
        Some("SIGABRT"),
        "*** stack smashing detected ***",
    );
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    let d = trapv_detect(TRAPV_CLANG, Some("SIGABRT"), "");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

#[test]
fn a_ubsan_report_withholds_even_a_run_that_went_on() {
    let stdout = format!("{TRAPV_CLANG}trapv-overflow=wrapped sum=-2147483648\n");
    let d = trapv_detect(
        &stdout,
        None,
        "trapv.c:55:14: runtime error: signed integer overflow: 2147483647 + 1 cannot be \
         represented in type 'int'",
    );
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

#[test]
fn a_wrapped_sum_beside_the_minimal_runtime_or_a_ubsan_check_is_withheld() {
    // clang's minimal runtime reports without `runtime error:` and the run goes on.
    let wrapped = "trapv-overflow=wrapped sum=-2147483648\n";
    let stdout = format!("frontend=clang\nubsan=yes\ntrapv-overflow=attempted\n{wrapped}");
    let d = trapv_detect(&stdout, None, "ubsan: add-overflow by 0x0000000000401425\n");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    // The feature test alone withholds, with stderr empty.
    let d = trapv_detect(&stdout, None, "");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    // Any stderr alone withholds, with the feature test reading no.
    let stdout = format!("{TRAPV_CLANG}{wrapped}");
    let d = trapv_detect(&stdout, None, "ubsan: add-overflow by 0x0000000000401425\n");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

#[test]
fn a_run_that_never_reached_the_overflow_is_withheld() {
    let d = trapv_detect("frontend=gcc\nubsan=no\n", Some("SIGSEGV"), "");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    let d = trapv_detect(TRAPV_GCC, Some("SIGSEGV"), "");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

#[test]
fn the_line_qemu_user_appends_to_a_signal_death_is_not_the_probes_stderr() {
    let d = trapv_detect(
        TRAPV_GCC,
        Some("SIGABRT"),
        "qemu: uncaught target signal 6 (Aborted) - core dumped\n",
    );
    assert_eq!(d.outcome, Outcome::Present, "{}", d.observed);
    let d = trapv_detect(
        TRAPV_CLANG,
        Some("SIGTRAP"),
        "qemu: uncaught target signal 5 (Trace/breakpoint trap) - core dumped\n",
    );
    assert_eq!(d.outcome, Outcome::Present, "{}", d.observed);
    // Anything else beside it still withholds.
    let d = trapv_detect(
        TRAPV_GCC,
        Some("SIGABRT"),
        "*** stack smashing detected ***: terminated\nqemu: uncaught target signal 6 (Aborted) - core dumped\n",
    );
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

fn stack_exec_detect(stdout: &str, exit_status: i32, signal: Option<&str>) -> Detection {
    let macros = BTreeMap::new();
    let mut run = tavi_run(stdout);
    run.exit_status = exit_status;
    run.signal = signal.map(ToOwned::to_owned);
    detect_stack_exec(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

/// The two readings as the probe printed them on Fedora 44 on 2026-10-02, x86_64 (gcc
/// 16.1.1, clang 22.1.8) and aarch64 (gcc 16.2.1, clang 22.1.8), at every -O level:
/// `-Wl,-z,noexecstack` faults at the payload, `-Wl,-z,execstack` returns the marker.
#[test]
fn stack_exec_reads_a_fault_at_the_payload_and_the_payload_s_marker() {
    let d = stack_exec_detect(
        "NXRT arch=x86_64 calling\nNXRT stack-exec=no fault=payload\n",
        0,
        None,
    );
    assert_eq!(d.outcome, Outcome::Present, "{}", d.observed);
    let d = stack_exec_detect(
        "NXRT arch=aarch64 calling\nNXRT stack-exec=yes ret=77\n",
        0,
        None,
    );
    assert_eq!(d.outcome, Outcome::Absent, "{}", d.observed);
}

/// A crash is not a non-executable stack. Only a fault the handler placed at the payload's
/// own address reads `present`; every other ending, including a reading followed by an
/// unclean exit and a probe that never reached the call, is withheld.
#[test]
fn stack_exec_withholds_every_ending_that_is_not_one_of_the_two_readings() {
    for (stdout, exit, signal) in [
        (
            "NXRT arch=x86_64 calling\nNXRT stack-exec=unknown fault=elsewhere\n",
            0,
            None,
        ),
        (
            "NXRT arch=aarch64 calling\nNXRT stack-exec=unknown fault=sigill\n",
            0,
            None,
        ),
        (
            "NXRT arch=x86_64 calling\nNXRT stack-exec=unknown ret=0\n",
            0,
            None,
        ),
        ("NXRT arch=x86_64 calling\n", 0, Some("SIGSEGV")),
        (
            "NXRT arch=x86_64 calling\nNXRT stack-exec=no fault=payload\n",
            1,
            None,
        ),
        (
            "NXRT arch=x86_64 calling\nNXRT stack-exec=yes ret=77\n",
            0,
            Some("SIGSEGV"),
        ),
        ("NXRT stack-exec=no fault=payload\n", 0, None),
        (
            "NXRT probe-invalid=no-payload-for-this-architecture\n",
            77,
            None,
        ),
        // clang's -fsanitize=safe-stack, Fedora 44 x86_64, clang 22.1.8, 2026-10-02: the
        // buffer is on the separately mapped unsafe stack, and the probe declines before
        // the call under -z execstack and -z noexecstack alike.
        (
            "NXRT probe-invalid=buffer-not-on-the-initial-stack\n",
            77,
            None,
        ),
        (
            "NXRT arch=x86_64 calling\nNXRT stack-exec=no fault=payload\nNXRT stack-exec=yes ret=77\n",
            0,
            None,
        ),
        ("", 0, Some("SIGSEGV")),
    ] {
        let d = stack_exec_detect(stdout, exit, signal);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{stdout:?} exit={exit} signal={signal:?}: {}",
            d.observed
        );
    }
}

fn shstk_detect(stdout: &str) -> Detection {
    let macros = BTreeMap::new();
    let run = tavi_run(stdout);
    detect_shadow_stack(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

/// The lines measured on 2026-10-02: the Fedora 44 x86_64 host under the pin, with
/// `-fcf-protection=full` and with `=none`, and the KVM guests whose kernel or CPU offered
/// no shadow stack. Only the three readings agreeing reads either way.
#[test]
fn the_shadow_stack_is_read_from_three_agreeing_readings_of_one_process() {
    let on = shstk_detect(&format!("{UNPINNED_OFF}{PINNED_ON}"));
    assert_eq!(on.outcome, Outcome::Present, "{}", on.observed);
    let off = shstk_detect("SHSTK kernel=ok cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n");
    assert_eq!(off.outcome, Outcome::Absent, "{}", off.observed);

    // Each disagreement withholds: enabled with the return taken, a pointer with bit 0
    // clear, a fault of another kind, and the clobber never reported.
    for stdout in [
        "SHSTK kernel=ok cpu=ss features=0x1 ssp=nonzero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=ok cpu=ss features=0 ssp=nonzero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=ok cpu=ss features=0x1 ssp=nonzero\nSHSTK clobber=segv:128\n",
        "SHSTK kernel=ok cpu=ss features=0 ssp=zero\nSHSTK clobber=segv:1\n",
        "SHSTK kernel=ok cpu=ss features=0 ssp=zero\n",
        "SHSTK kernel=ok cpu=ss features=0 ssp=zero\nSHSTK clobber=returned\n",
    ] {
        let d = shstk_detect(stdout);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{stdout:?}: {}",
            d.observed
        );
    }
}

/// The pinned process's lines enforced, as the Fedora 44 x86_64 host printed them on
/// 2026-10-02 under `-fcf-protection=full`.
const PINNED_ON: &str = "SHSTK kernel=ok cpu=ss features=0x1 ssp=nonzero\nSHSTK clobber=cperr\n";
/// The unpinned process's lines on the same host, glibc 2.43 leaving the shadow stack off.
const UNPINNED_OFF: &str =
    "SHSTK-UNPINNED kernel=ok cpu=ss features=0 ssp=zero\nSHSTK-UNPINNED clobber=hijacked\n";
/// The unpinned process's lines where the C library enables the shadow stack by default.
const UNPINNED_ON: &str =
    "SHSTK-UNPINNED kernel=ok cpu=ss features=0x1 ssp=nonzero\nSHSTK-UNPINNED clobber=cperr\n";

/// The level is the run without the opt-in. Enforced there too is `default`, the ask; off
/// there is `opt-in`, below it, which upstream glibc 2.39 and later read. An unpinned
/// reading that establishes neither leaves a `present` with no level, which the graded
/// check withholds rather than publishing the opt-in's `on`; and the pinned reading alone
/// decides the outcome, so the controls discriminate whatever the unpinned run said.
#[test]
fn the_shadow_stack_level_is_the_run_without_the_opt_in() {
    let default = shstk_detect(&format!("{UNPINNED_ON}{PINNED_ON}"));
    assert_eq!(default.outcome, Outcome::Present, "{}", default.observed);
    assert_eq!(default.level.as_deref(), Some("default"));
    let opt_in = shstk_detect(&format!("{UNPINNED_OFF}{PINNED_ON}"));
    assert_eq!(opt_in.outcome, Outcome::Present, "{}", opt_in.observed);
    assert_eq!(opt_in.level.as_deref(), Some("opt-in"));
    assert!(
        opt_in.observed.contains("SHSTK-UNPINNED kernel=ok"),
        "{}",
        opt_in.observed
    );
    let grade = crate::probe::SHADOW_STACK_DEFAULT.grade().expect("graded");
    assert_eq!(grade.recommended, "default");
    assert!(crate::probe::SHADOW_STACK_DEFAULT.admits("opt-in"));

    for unpinned in [
        "",
        "SHSTK-UNPINNED exec=errno:2\n",
        "SHSTK-UNPINNED child=signal:11\n",
        "SHSTK-UNPINNED kernel=ok cpu=ss features=0x1 ssp=nonzero\nSHSTK-UNPINNED clobber=hijacked\n",
        "SHSTK-UNPINNED kernel=ok cpu=ss features=0 ssp=zero\n",
    ] {
        let d = shstk_detect(&format!("{unpinned}{PINNED_ON}"));
        assert_eq!(d.outcome, Outcome::Present, "{unpinned:?}: {}", d.observed);
        assert!(d.level.is_none(), "{unpinned:?} graded as {:?}", d.level);
    }

    // Off under the pin is off whatever the unpinned run said, but an unpinned run enforced
    // beside it contradicts the tunable and withholds.
    let pinned_off = "SHSTK kernel=ok cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n";
    for unpinned in ["", UNPINNED_OFF, "SHSTK-UNPINNED exec=errno:2\n"] {
        let d = shstk_detect(&format!("{unpinned}{pinned_off}"));
        assert_eq!(d.outcome, Outcome::Absent, "{unpinned:?}: {}", d.observed);
    }
    let d = shstk_detect(&format!("{UNPINNED_ON}{pinned_off}"));
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);

    // The unpinned lines are never read as the pinned ones.
    assert!(shadow_stack_reading(UNPINNED_ON).is_none());
}

/// A machine that cannot run a shadow stack reads neither way, whatever the rest of the
/// line says: the kernel's refusal (Ubuntu 22.04's 5.15 kernel answered errno 22) and a
/// CPU without `CET_SS` (every KVM guest measured) are not a toolchain that declined.
#[test]
fn a_machine_without_the_mechanism_is_never_absent() {
    for stdout in [
        "SHSTK kernel=errno:22 cpu=no-ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=ok cpu=no-ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=errno:22 cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=ok cpu=no-leaf7 features=0 ssp=zero\nSHSTK clobber=hijacked\n",
    ] {
        let d = shstk_detect(stdout);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{stdout:?}: {}",
            d.observed
        );
        let lack = shadow_stack_reading(stdout)
            .and_then(|r| r.machine_lacks())
            .expect("the reading names the machine's lack");
        assert!(d.observed.contains(&lack.sentence), "{}", d.observed);
        // The kernel's `EINVAL` is named first: without the interface no CPU can help.
        let part = if stdout.contains("errno:22") {
            LackingPart::Kernel
        } else {
            LackingPart::Cpu
        };
        assert_eq!(lack.part, part, "{stdout:?}");
    }
    assert!(
        shadow_stack_reading("SHSTK kernel=ok cpu=ss features=0 ssp=zero\n")
            .and_then(|r| r.machine_lacks())
            .is_none(),
        "a machine that answered both questions yes lacks nothing"
    );
}

/// A refusal of the status query other than `EINVAL` (a seccomp filter's `EPERM`, an
/// `ENOSYS`) names no machine: it reads neither way and the gating rule leaves it alone.
#[test]
fn a_refusal_other_than_einval_names_no_machine() {
    for stdout in [
        "SHSTK kernel=errno:1 cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=errno:38 cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
    ] {
        let d = shstk_detect(stdout);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{stdout:?}: {}",
            d.observed
        );
        assert!(
            shadow_stack_reading(stdout)
                .and_then(|r| r.machine_lacks())
                .is_none(),
            "{stdout:?} attributes a refusal of unmeasured cause to the kernel"
        );
    }
}

/// A line of another shape is no reading at all, and another architecture's line says so.
#[test]
fn a_malformed_or_foreign_shadow_stack_line_withholds() {
    for stdout in [
        "",
        "SHSTK kernel=maybe cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=errno: cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=ok cpu=ss features=zz ssp=zero\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=ok cpu=ss features=0 ssp=maybe\nSHSTK clobber=hijacked\n",
        "SHSTK kernel=ok cpu=sss features=0 ssp=zero\nSHSTK clobber=hijacked\n",
        "SHSTK unsupported-arch\n",
    ] {
        let d = shstk_detect(stdout);
        assert_eq!(
            d.outcome,
            Outcome::Indeterminate,
            "{stdout:?}: {}",
            d.observed
        );
    }
    assert!(shadow_stack_reading("SHSTK kernel=ok cpu=ss features=zz ssp=zero").is_none());
}

fn stack_clash_detect(stdout: &str) -> Detection {
    let macros = BTreeMap::new();
    let run = tavi_run(stdout);
    detect_stack_clash(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

/// The pre-2026-10-05 probe's `unsigned long` arithmetic on i386: `100 * dist` wrapped
/// mod 2^32 and printed a small ratio for an allocation whose first touch landed wholly
/// below the frame. Every line is a probing-off build's, measured on 2026-10-05 in compat
/// mode on a Fedora 44 x86_64 kernel 7.3.0-rc3: Debian 12 gcc 12.2.0 i386 at
/// `-O2 -fno-stack-clash-protection`, and Fedora 44 gcc 16.2.1 and clang 22.1.8 at
/// `-m32 -O2 -fno-stack-clash-protection`, under the `RLIMIT_STACK` named. Each read
/// `present`, a wrong `on`; the control triple withheld it only because the negative arm
/// wrapped the same way.
#[test]
fn a_ratio_that_wrapped_on_a_32_bit_target_withholds() {
    for (line, limit) in [
        (
            "SCPRT dist=67108879 n=67108864 ratio_pct=36",
            "8 MiB, gcc 12.2.0",
        ),
        (
            "SCPRT dist=67109027 n=67108864 ratio_pct=36",
            "8 MiB, clang 22.1.8",
        ),
        (
            "SCPRT dist=44040207 n=44040192 ratio_pct=2",
            "5376 KiB, gcc",
        ),
        (
            "SCPRT dist=536870927 n=536870912 ratio_pct=4",
            "64 MiB, gcc",
        ),
        (
            "SCPRT dist=2147483663 n=2147483648 ratio_pct=0",
            "256 MiB, gcc",
        ),
        (
            "SCPRT dist=4286578703 n=4286578688 ratio_pct=0",
            "511 MiB, gcc",
        ),
        (
            "SCPRT dist=738197519 n=738197504 ratio_pct=1",
            "600 MiB, gcc",
        ),
    ] {
        let d = stack_clash_detect(line);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{limit}: {line}");
        assert!(d.observed.contains("wrapped"), "{limit}: {}", d.observed);
    }

    // What the check must not move: 12 with probing, 100 without. The first four are
    // gcc 16.1.1 and clang 22.1.8 on Fedora 44 x86_64 natively at the default 8 MiB
    // limit; the next two are the probe on Debian 12 gcc 12.2.0 i386 in compat mode at
    // 8 MiB, the line a probe that wraps prints as the first case above; the last is gcc 16.1.1
    // x86_64 at 1 GiB, where `n` exceeds 32 bits. All measured on 2026-10-05.
    for (line, want) in [
        (
            "SCPRT dist=8384535 n=67108864 ratio_pct=12",
            Outcome::Present,
        ),
        (
            "SCPRT dist=8388815 n=67108864 ratio_pct=12",
            Outcome::Present,
        ),
        (
            "SCPRT dist=67108879 n=67108864 ratio_pct=100",
            Outcome::Absent,
        ),
        (
            "SCPRT dist=67109071 n=67108864 ratio_pct=100",
            Outcome::Absent,
        ),
        (
            "SCPRT dist=8388643 n=67108864 ratio_pct=12",
            Outcome::Present,
        ),
        (
            "SCPRT dist=67108895 n=67108864 ratio_pct=100",
            Outcome::Absent,
        ),
        (
            "SCPRT dist=8589934607 n=8589934592 ratio_pct=100",
            Outcome::Absent,
        ),
    ] {
        assert_eq!(stack_clash_detect(line).outcome, want, "{line}");
    }
}

/// `dist=0` is a probe's clamp for a first touch at or above the frame, which is
/// where a wrapped `sp - n` lands. Measured on 2026-10-05 with probing off: on Fedora 44
/// x86_64 natively (gcc 16.1.1 and clang 22.1.8, `-O2 -fno-stack-clash-protection`,
/// 4-level paging) at `RLIMIT_STACK` `16 TiB` and `17 TiB`, and on i386 in compat mode
/// (Fedora 44 gcc 16.2.1 and clang 22.1.8 `-m32`) at `4194303 KiB`. Each reads `present` to a
/// decoder that believes the ratio.
#[test]
fn a_first_touch_at_or_above_the_frame_withholds() {
    for line in [
        "SCPRT dist=0 n=140737488355328 ratio_pct=0",
        "SCPRT dist=0 n=149533581377536 ratio_pct=0",
        "SCPRT dist=0 n=4294959104 ratio_pct=0",
    ] {
        let d = stack_clash_detect(line);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{line}");
        assert!(
            d.observed.contains("at or above the frame"),
            "{}",
            d.observed
        );
    }
}

/// A fault before the size was recorded prints `n=0` and ratio 0; nothing was allocated,
/// so ratio 0 is not a page walk. Hand-authored, as the replay fixture
/// `synthetic:fault-before-allocation` is.
#[test]
fn a_fault_before_the_allocation_withholds() {
    let d = stack_clash_detect("SCPRT dist=140732916358152 n=0 ratio_pct=0");
    assert_eq!(d.outcome, Outcome::Indeterminate);
    assert!(
        d.observed.contains("before the allocation"),
        "{}",
        d.observed
    );
}

/// A ratio with no operands beside it cannot be checked, so it is not believed.
#[test]
fn a_ratio_without_its_operands_withholds() {
    let d = stack_clash_detect("SCPRT ratio_pct=12");
    assert_eq!(d.outcome, Outcome::Indeterminate);
}

/// Each address-space decline the probe prints is in its source and withholds by name.
/// Listed here so a decline renamed in the probe is renamed here too.
#[test]
fn every_address_space_decline_the_probe_prints_withholds() {
    let source = crate::probe::find("stack-clash")
        .expect("the stack-clash probe is in the corpus")
        .source;
    for why in [
        "allocation-overflow",
        "address-wrap",
        "sign-boundary",
        "fault-before-allocation",
        "no-fault-address",
        "fault-above-frame",
    ] {
        let line = format!("SCPRT probe-invalid={why}");
        assert!(source.contains(&line), "the probe prints {line:?}");
        let d = stack_clash_detect(&line);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{why}");
        assert!(d.observed.contains(why), "{}", d.observed);
    }
}

/// `--normalize` publishes `dist=<volatile>` (`report::VOLATILE_READINGS`) after the decoder
/// read the digits, and `chard detect --evidence` replays that published line. The ratio
/// survives the mask, so a normalized reading decodes as its digits did; what the mask
/// hides is withheld only where the digits could have withheld. The decided lines are
/// gcc 16.1.1's on Fedora 44 `x86_64` at the default 8-mebibyte stack limit (2026-10-05),
/// masked as `normalize` masks.
#[test]
fn a_normalized_distance_decodes_as_its_digits_did() {
    let masked = |line: &str| {
        let (_, rest) = line.split_once("dist=").expect("a distance");
        let (_, tail) = rest.split_once(' ').expect("fields after it");
        format!("SCPRT dist={} {tail}", crate::report::NORMALIZED_READING)
    };
    for line in [
        "SCPRT dist=8384535 n=67108864 ratio_pct=12",
        "SCPRT dist=67108879 n=67108864 ratio_pct=100",
    ] {
        let digits = stack_clash_detect(line);
        let normalized = stack_clash_detect(&masked(line));
        assert_eq!(
            normalized.outcome, digits.outcome,
            "{}",
            normalized.observed
        );
        assert_ne!(normalized.outcome, Outcome::Indeterminate, "{line}");
    }
    for (line, why) in [
        // Nothing was allocated, masked or not.
        (
            "SCPRT dist=140732916358152 n=0 ratio_pct=0",
            "before the allocation",
        ),
        // The digits might have been 0, which the unmasked line withholds.
        (
            "SCPRT dist=0 n=140737488355328 ratio_pct=0",
            "could have been",
        ),
    ] {
        let d = stack_clash_detect(&masked(line));
        assert_eq!(d.outcome, Outcome::Indeterminate, "{line}");
        assert!(d.observed.contains(why), "{}", d.observed);
    }
    // Only the exact marker is a normalized distance; any other non-number is missing.
    let d = stack_clash_detect("SCPRT dist=<other> n=67108864 ratio_pct=12");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

/// The witness is required, not optional: a `TAVI` line without `ctrl` or `ctrl_supported`
/// is not the live probe's line (which always prints both) and reads `indeterminate`
/// however clean its fill looks. Mirrors `zipb_reading`.
#[test]
fn a_tavi_line_without_the_witness_is_indeterminate() {
    for line in [
        "TAVI arr=00 word=00 small=00",
        "TAVI arr=00 word=00 small=00 ctrl_supported=1",
        "TAVI arr=00 word=00 small=00 ctrl=5a",
        "TAVI arr=00 word=00 small=00 ctrl=5a ctrl_supported=2",
        "TAVI arr=00 word=00 small=00 ctrl=zz ctrl_supported=1",
    ] {
        assert_eq!(
            tavi_detect(line).outcome,
            Outcome::Indeterminate,
            "an unwitnessed fill must not be read as a measurement: {line:?}"
        );
    }
}

/// Each line `chard_report_translation` writes reads as its own shape, and every other line
/// is no reading: stdout's first line is read, a marker on any later line is not the
/// probe's (a second one, or one after the probe's own output), only `0` and `1` are
/// readings, and `unreadable` carries one of the header's three words or is unrecognised.
/// A mutation reading `1`, an unreadable sysctl or no line as native fails here.
#[test]
fn each_translation_line_reads_as_its_own_shape_and_nothing_else_does() {
    let scprt = "SCPRT dist=8369711 n=66977792 ratio_pct=12";
    let exact = [
        (format!("CHARD-TRANSLATION 0\n{scprt}"), Translation::Native),
        (
            "CHARD-TRANSLATION 1\nNXRT arch=x86_64 calling".to_owned(),
            Translation::Translated,
        ),
        (
            "CHARD-TRANSLATION unreadable errno:2".to_owned(),
            Translation::Unreadable("errno:2".to_owned()),
        ),
        (
            "CHARD-TRANSLATION unreadable size:8".to_owned(),
            Translation::Unreadable("size:8".to_owned()),
        ),
        (
            "CHARD-TRANSLATION unreadable value:-1".to_owned(),
            Translation::Unreadable("value:-1".to_owned()),
        ),
        (String::new(), Translation::Unreported),
        (scprt.to_owned(), Translation::Unreported),
        // Indented, it is not the line the header writes at the start of one.
        (" CHARD-TRANSLATION 0".to_owned(), Translation::Unreported),
    ];
    for (stdout, want) in exact {
        assert_eq!(translation(&stdout), want, "{stdout:?}");
    }
    for stdout in [
        "CHARD-TRANSLATION 0\nCHARD-TRANSLATION 0",
        "CHARD-TRANSLATION 0\nCHARD-TRANSLATION 1",
        // After the probe's own output it is not the line the header writes first.
        "SCPRT dist=8369711 n=66977792 ratio_pct=12\nCHARD-TRANSLATION 0",
        "CHARD-TRANSLATION 0\nSCPRT dist=8369711 n=66977792 ratio_pct=12\nCHARD-TRANSLATION 0",
        "CHARD-TRANSLATION 2",
        "CHARD-TRANSLATION 0 native",
        "CHARD-TRANSLATION  0",
        "CHARD-TRANSLATION0",
        "CHARD-TRANSLATION",
        "CHARD-TRANSLATION unreadable",
        "CHARD-TRANSLATION unreadable errno:",
        "CHARD-TRANSLATION unreadable errno:x",
        "CHARD-TRANSLATION unreadable errno:-2",
        "CHARD-TRANSLATION unreadable size:-1",
        "CHARD-TRANSLATION unreadable signal:2",
        "CHARD-TRANSLATION unreadable errno:123456789012345678901",
    ] {
        assert!(
            matches!(translation(stdout), Translation::Unrecognised(_)),
            "{stdout:?} read as {:?}",
            translation(stdout)
        );
    }
    // A control character reaches the reason escaped, and a long line is cut and counted.
    let Translation::Unrecognised(quoted) = translation("CHARD-TRANSLATION \u{1b}[2J") else {
        panic!("an escape sequence is no reading");
    };
    assert!(
        quoted.contains("\\u{1b}") && !quoted.contains('\u{1b}'),
        "{quoted}"
    );
    let long = format!("CHARD-TRANSLATION {}", "9".repeat(100));
    let Translation::Unrecognised(cut) = translation(&long) else {
        panic!("a hundred digits are no reading");
    };
    assert!(cut.ends_with(" and 54 character(s) more"), "{cut}");
}

/// On Darwin the stream opens with the translation line, which the stack-clash quote
/// carries after the probe's own lines; the reading is quoted whole rather than run into it,
/// and a stream without the line is quoted as before.
#[test]
fn the_stack_clash_quote_keeps_the_reading_apart_from_the_translation_line() {
    let scprt = "SCPRT dist=8388620 n=67108864 ratio_pct=12";
    let with = stack_clash_detect(&format!("CHARD-TRANSLATION 0\n{scprt}"));
    let without = stack_clash_detect(scprt);
    assert_eq!(with.outcome, without.outcome);
    assert!(
        with.observed.contains("ratio_pct=12\\nCHARD-TRANSLATION 0"),
        "{}",
        with.observed
    );
    assert!(
        without.observed.ends_with("ratio_pct=12\""),
        "{}",
        without.observed
    );
}

/// The header writes the shapes [`translation`] reads: the marker is this module's, each
/// `snprintf` format renders to a line that parses as the variant it means, and the read's
/// branches print what they mean, in order.
#[test]
fn the_header_writes_the_translation_lines_the_reader_reads() {
    assert!(
        SELFREPORT_HEADER.contains(&format!(
            "#define CHARD_TRANSLATION_MARKER \"{TRANSLATION_MARKER}\""
        )),
        "the header's marker is TRANSLATION_MARKER"
    );
    for (format, rendered, want) in [
        (" %d\\n\"", "CHARD-TRANSLATION 0", Translation::Native),
        (" %d\\n\"", "CHARD-TRANSLATION 1", Translation::Translated),
        (
            " unreadable errno:%d\\n\"",
            "CHARD-TRANSLATION unreadable errno:2",
            Translation::Unreadable("errno:2".to_owned()),
        ),
        (
            " unreadable size:%lu\\n\"",
            "CHARD-TRANSLATION unreadable size:8",
            Translation::Unreadable("size:8".to_owned()),
        ),
        (
            " unreadable value:%d\\n\"",
            "CHARD-TRANSLATION unreadable value:-7",
            Translation::Unreadable("value:-7".to_owned()),
        ),
    ] {
        assert!(
            SELFREPORT_HEADER.contains(&format!("CHARD_TRANSLATION_MARKER \"{format}")),
            "the header writes `{format}`"
        );
        assert_eq!(translation(rendered), want, "{rendered}");
    }
    // No host in the suite compiles the Darwin branch, so its text is what is held: a
    // header printing `0` whatever the sysctl read, or taking any non-negative value as a
    // reading, fails here.
    let header = SELFREPORT_HEADER
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut from = 0;
    for step in [
        "int translated = -1;",
        "size_t size = sizeof translated;",
        r#"if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) != 0) {"#,
        r#"CHARD_TRANSLATION_MARKER " unreadable errno:%d\n", errno);"#,
        "} else if (size != sizeof translated) {",
        r#"CHARD_TRANSLATION_MARKER " unreadable size:%lu\n", (unsigned long) size);"#,
        "} else if (translated == 0 || translated == 1) {",
        r#"CHARD_TRANSLATION_MARKER " %d\n", translated);"#,
        "} else {",
        r#"CHARD_TRANSLATION_MARKER " unreadable value:%d\n", translated);"#,
    ] {
        let at = header[from..]
            .find(step)
            .unwrap_or_else(|| panic!("the header's read holds `{step}` in its place"));
        from += at + step.len();
    }
}

/// Every probe a `Machine` check runs opts into the read and calls it first in each `main`,
/// so on Darwin the line precedes anything the probe prints and survives a probe that dies.
#[test]
fn every_machine_probe_reports_its_translation_first() {
    let machine: Vec<&crate::probe::Probe> = crate::probe::CORPUS
        .iter()
        .filter(|p| {
            p.checks
                .iter()
                .any(|c| c.run_basis() == Some(crate::probe::RunBasis::Machine))
        })
        .collect();
    assert_eq!(
        machine.iter().map(|p| p.id).collect::<Vec<_>>(),
        ["stack-exec-runtime", "shadow-stack", "stack-clash"],
        "the probes whose checks rest on the machine"
    );
    for probe in machine {
        let source = probe.source;
        let opt_in = source
            .find("#define CHARD_WANT_TRANSLATION_REPORT")
            .unwrap_or_else(|| panic!("{} does not opt into the read", probe.id));
        let include = source
            .find("#include \"chard_selfreport.h\"")
            .unwrap_or_else(|| panic!("{} does not include the header", probe.id));
        assert!(
            opt_in < include,
            "{}: the opt-in precedes the include",
            probe.id
        );
        let mains: Vec<usize> = source
            .match_indices("\nint main(")
            .map(|(at, _)| at)
            .collect();
        assert!(!mains.is_empty(), "{} has a main", probe.id);
        for at in mains {
            let body = &source[at..];
            let open = body.find('{').expect("main has a body");
            let first_output = ["say(", "printf(", "write(", "return "]
                .iter()
                .filter_map(|w| body[open..].find(w))
                .min()
                .expect("main does something");
            assert!(
                body[open..open + first_output].contains("chard_report_translation();"),
                "{}: a main reaches `{}` before the read",
                probe.id,
                &body[open + first_output..open + first_output + 12]
            );
        }
    }
}

/// The line moves no reading: each `Machine` decoder reads a stdout opening with any of
/// the header's lines exactly as it reads the stdout without it.
#[test]
fn the_translation_line_moves_no_machine_reading() {
    let lines = [
        "CHARD-TRANSLATION 0\n",
        "CHARD-TRANSLATION 1\n",
        "CHARD-TRANSLATION unreadable errno:2\n",
    ];
    let same = |a: &Detection, b: &Detection, what: &str| {
        assert_eq!(
            (a.outcome, &a.level),
            (b.outcome, &b.level),
            "{what}: {} / {}",
            a.observed,
            b.observed
        );
    };
    for stdout in [
        "SCPRT dist=8388620 n=67108864 ratio_pct=12",
        "SCPRT dist=67108879 n=67108864 ratio_pct=100",
        "SCPRT probe-invalid=no-fault",
    ] {
        for line in lines {
            let with = stack_clash_detect(&format!("{line}{stdout}"));
            same(&with, &stack_clash_detect(stdout), stdout);
        }
    }
    for (stdout, exit, signal) in [
        (
            "NXRT arch=aarch64 calling\nNXRT stack-exec=no fault=payload",
            0,
            None,
        ),
        (
            "NXRT arch=x86_64 calling\nNXRT stack-exec=yes ret=77",
            0,
            None,
        ),
        ("NXRT arch=aarch64 calling", -1, Some("SIGSEGV")),
    ] {
        for line in lines {
            let with = stack_exec_detect(&format!("{line}{stdout}"), exit, signal);
            same(&with, &stack_exec_detect(stdout, exit, signal), stdout);
        }
    }
    for line in lines {
        let with = shstk_detect(&format!("{line}SHSTK unsupported-arch"));
        same(
            &with,
            &shstk_detect("SHSTK unsupported-arch"),
            "unsupported-arch",
        );
    }
}

/// The pinned process's lines on a Wolfi-derived rootfs's glibc 2.44-r23, which ignores
/// `GLIBC_TUNABLES`, its loader and libc linked into a `-fcf-protection=full` build on the Fedora 44 x86_64
/// host (kernel 7.3.0-rc3) on 2026-10-21: the witness tunable had no effect, and the program
/// ran with no shadow stack under the pin as without it.
const IGNORED_PINNED_OFF: &str = "SHSTK tunables=ignored\n\
    SHSTK-UNPINNED kernel=ok cpu=ss features=0 ssp=zero\n\
    SHSTK-UNPINNED clobber=hijacked\n\
    SHSTK kernel=ok cpu=ss features=0 ssp=zero\n\
    SHSTK clobber=hijacked\n";

/// A sentence says the opt-in was in force only where the pinned process's witness saw its
/// tunable take effect. On a C library that ignores `GLIBC_TUNABLES` the pinned process is an
/// unpinned one, and the reading still stands (the hijack happened), but "under glibc's
/// opt-in" would be false; with no witness line the sentence says the reach was not shown.
#[test]
fn the_opt_in_is_named_in_force_only_where_its_witness_took_effect() {
    let pinned_off = "SHSTK kernel=ok cpu=ss features=0 ssp=zero\nSHSTK clobber=hijacked\n";
    let honoured = shstk_detect(&format!(
        "SHSTK tunables=honoured\n{UNPINNED_OFF}{pinned_off}"
    ));
    assert_eq!(honoured.outcome, Outcome::Absent, "{}", honoured.observed);
    assert!(
        honoured.observed.ends_with("under glibc's opt-in"),
        "{}",
        honoured.observed
    );

    let ignored = shstk_detect(IGNORED_PINNED_OFF);
    assert_eq!(ignored.outcome, Outcome::Absent, "{}", ignored.observed);
    assert!(
        !ignored.observed.contains("under glibc's opt-in")
            && ignored
                .observed
                .contains("does not show that the opt-in reached"),
        "{}",
        ignored.observed
    );

    let unshown = shstk_detect(&format!("{UNPINNED_OFF}{pinned_off}"));
    assert!(
        unshown
            .observed
            .contains("could not show that it reached the C library"),
        "{}",
        unshown.observed
    );

    let applied = shstk_detect(&format!(
        "SHSTK tunables=honoured\n{UNPINNED_OFF}{PINNED_ON}"
    ));
    assert_eq!(applied.level.as_deref(), Some("opt-in"));
    assert!(
        applied.observed.contains("under glibc's opt-in"),
        "{}",
        applied.observed
    );
    let enforced_anyway =
        shstk_detect(&format!("SHSTK tunables=ignored\n{UNPINNED_ON}{PINNED_ON}"));
    assert_eq!(enforced_anyway.level.as_deref(), Some("default"));
    assert!(
        !enforced_anyway.observed.contains("under glibc's opt-in"),
        "{}",
        enforced_anyway.observed
    );

    // Enforced under the pin and off without it while the witness read `ignored`: the
    // enforcement shows the opt-in took effect and only the witness did not (a malloc a
    // profile replaced, say), so the level is graded as before and the sentence claims
    // nothing about the C library.
    let witness_lost = shstk_detect(&format!(
        "SHSTK tunables=ignored\n{UNPINNED_OFF}{PINNED_ON}"
    ));
    assert_eq!(
        witness_lost.level.as_deref(),
        Some("opt-in"),
        "{}",
        witness_lost.observed
    );
    assert!(
        witness_lost.observed.contains("with glibc's opt-in set"),
        "{}",
        witness_lost.observed
    );
    // A witness that could not run, or a word the probe does not print, is not `honoured`.
    for word in ["unallocated", "garbled"] {
        let d = shstk_detect(&format!(
            "SHSTK tunables={word}\n{UNPINNED_OFF}{pinned_off}"
        ));
        assert!(
            d.observed
                .contains("could not show that it reached the C library")
                && !d.observed.contains("under glibc's opt-in"),
            "{word}: {}",
            d.observed
        );
    }

    let reading = shadow_stack_reading(IGNORED_PINNED_OFF).expect("the pinned lines parse");
    assert_eq!(reading.tunables, Some(SHSTK_TUNABLES_IGNORED));
    let unpinned = shadow_stack_reading_under(IGNORED_PINNED_OFF, SHSTK_UNPINNED)
        .expect("the unpinned lines parse");
    assert_eq!(
        unpinned.tunables, None,
        "the unpinned process prints no witness"
    );
}

/// The `-z execstack` arm on a Wolfi-derived rootfs's glibc, 2026-10-21: the loader refused it
/// before `main`, exit 127, its line on stderr and nothing on stdout. The withheld reading names
/// the loader and quotes it; exit 127 without the line, or the line under another status, is
/// the generic "never reached the call", since nothing then shows the loader refused.
#[test]
fn stack_exec_names_the_loader_that_refused_the_program() {
    let refused = |exit: i32, stderr: &str| {
        let macros = BTreeMap::new();
        let mut run = tavi_run("");
        run.exit_status = exit;
        run.stderr = stderr.to_owned();
        detect_stack_exec(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: None,
        })
    };
    let line = "Fatal glibc error: executable stack is not allowed";
    let d = refused(127, &format!("{line}\n"));
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(
        d.observed.contains("loader refused to start the program") && d.observed.contains(line),
        "{}",
        d.observed
    );
    // A signal ended the run: whatever its stderr said, the loader is not shown to have
    // refused it, since the loader's refusal is an exit.
    let mut signalled = tavi_run("");
    signalled.exit_status = 127;
    signalled.signal = Some("SIGKILL".to_owned());
    signalled.stderr = format!("{line}\n");
    assert_eq!(loader_refusal(&signalled), None);
    for (exit, stderr) in [
        (127, "sh: probe: not found\n"),
        (1, "executable stack is not allowed\n"),
    ] {
        let d = refused(exit, stderr);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
        assert!(
            d.observed.contains("never reached the call") && !d.observed.contains("loader"),
            "{exit} {stderr:?}: {}",
            d.observed
        );
    }
}

/// A reading that withholds a guard that ran under `guard-kept-without-the-flag`, with a
/// sentence of its own branch (`own`) beside the shared "cannot answer the question".
fn names_the_rule(d: &Detection, what: &str, own: &str) {
    use crate::report::gating_rule::GUARD_KEPT_WITHOUT_THE_FLAG;

    assert_eq!(d.outcome, Outcome::Indeterminate, "{what}: {}", d.observed);
    assert_eq!(
        d.rule.map(|r| r.rule().id),
        Some(GUARD_KEPT_WITHOUT_THE_FLAG.id),
        "{what}: {}",
        d.observed
    );
    assert!(
        d.observed.contains("cannot answer the question") && d.observed.contains(own),
        "{what}: the sentence names its branch ({own:?}): {}",
        d.observed
    );
}

/// An optimized gcc before 8 whose guard ran names the rule from each of its branches:
/// no build record, a level-resetting word, no -O word, a keeping level, -O0 last, a
/// level not measured, and no readable version, each by a sentence of its own.
#[test]
fn an_optimized_gcc_before_8_guard_that_ran_names_the_rule_from_each_branch() {
    let named = names_the_rule;
    // Optimized gcc before 8: no build record, a level-resetting word, no -O word, a
    // keeping level, -O0 last, a level not measured, and no readable version.
    for (major, flags, own) in [
        (Some(7), None, "with no build record"),
        (
            Some(7),
            Some(&["-O2", "-specs=x.specs"][..]),
            "whose compile line carries -specs=x.specs",
        ),
        (Some(7), Some(&[][..]), "carries no -O word"),
        (
            Some(7),
            Some(&["-O1"][..]),
            "a build at -O1 on gcc 7: gcc 4.8",
        ),
        (Some(7), Some(&["-O2", "-O0"][..]), "last -O word is -O0"),
        (
            Some(7),
            Some(&["-Oz"][..]),
            "a level not measured on gcc before 8",
        ),
        (
            None,
            Some(&["-O1"][..]),
            "a build at -O1 on a gcc that reported no readable major version",
        ),
    ] {
        named(
            &optimized_gcc_reading(major, flags),
            &format!("gcc {major:?} {flags:?}"),
            own,
        );
    }
}

/// Every withholding of a guard that ran names `guard-kept-without-the-flag`, and a
/// reading that is no guard reading names no rule: the rule's members are exactly the
/// detector's "cannot answer the question" branches, each reached here by a sentence of its
/// own, with the rule at the stage `report::detector_gating` publishes from.
#[test]
fn a_guard_that_ran_and_cannot_be_credited_names_its_rule() {
    use crate::report::gating_rule::{GUARD_KEPT_WITHOUT_THE_FLAG, Stage};

    assert_eq!(GUARD_KEPT_WITHOUT_THE_FLAG.stage, Stage::Detector);
    let named = names_the_rule;
    // The sanitizer's checked add.
    named(
        &overflow_reading(
            "optimize=yes\nfrontend=clang\noverflow-guard=ran",
            "ubsan: add-overflow by 0x00000000004013d6",
        ),
        "sanitizer",
        "ran beside output on stderr",
    );
    // Unoptimized: clang, gcc before 8, no readable version, a compiler that is neither.
    for (stdout, own) in [
        (
            "optimize=no\nfrontend=clang\noverflow-guard=ran",
            "where clang keeps it",
        ),
        (
            "optimize=no\nfrontend=gcc\ngcc-major=7\noverflow-guard=ran",
            "on gcc 7: gcc 4.8, 5.4 and 7.5 keep it",
        ),
        (
            "optimize=no\nfrontend=gcc\ngcc-major=x\noverflow-guard=ran",
            "reported no readable major version",
        ),
        (
            "optimize=no\nfrontend=gcc\noverflow-guard=ran",
            "reported no readable major version",
        ),
        (
            "optimize=no\nfrontend=other\noverflow-guard=ran",
            "did not identify as gcc or clang",
        ),
    ] {
        named(&overflow_reading(stdout, ""), stdout, own);
    }
    // The readings that are not a guard that ran name no rule.
    for (stdout, what) in [
        (
            "optimize=yes\nfrontend=clang\noverflow-guard=deleted",
            "folded",
        ),
        ("optimize=yes\nfrontend=clang\n", "no guard reading"),
        (
            "optimize=yes\nfrontend=clang\noverflow-guard=ran",
            "credited",
        ),
        (
            "optimize=no\nfrontend=gcc\ngcc-major=8\noverflow-guard=ran",
            "gcc 8 credited",
        ),
    ] {
        let d = overflow_reading(stdout, "");
        assert!(
            d.rule.is_none(),
            "{what}: {} names {:?}",
            d.observed,
            d.rule.map(|r| r.rule().id)
        );
    }
    let macros = BTreeMap::new();
    let not_run = detect_no_strict_overflow(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: None,
        workdir: None,
    });
    assert_eq!(not_run.outcome, Outcome::Indeterminate);
    assert!(not_run.rule.is_none(), "{}", not_run.observed);
}
