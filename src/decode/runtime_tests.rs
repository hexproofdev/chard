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

#[test]
fn the_surviving_dirt_byte_proves_nothing_initialized_the_variable() {
    let d = tavi_detect("TAVI arr=5a word=5a small=5a ctrl=5a ctrl_supported=1");
    assert_eq!(d.outcome, Outcome::Absent);
}

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
fn elf_of_class(class: u8) -> ElfFacts {
    let mut elf = elf_with_report("");
    elf.elf_class = class;
    if class == 32 {
        elf.machine = "i386".to_owned();
    }
    elf
}

/// Both fill detectors over one recorded line and one artifact.
fn tavi_both(stdout: &str, elf: Option<&ElfFacts>) -> [Detection; 2] {
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
    let mixed = format!("SCPRT dist=8367487 n=66977792\n{whole}no-check-fired\n");
    assert_eq!(printed(&mixed).as_deref(), Some("apple"));

    // Killed mid-write: an opening marker and a truncated body.
    assert_eq!(printed("CHARD-REPORT-V1\n_FORTIFY_IMPL=app"), None);
    assert_eq!(printed("no-check-fired\n"), None);
    assert_eq!(printed(""), None);
}

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
        // `ud2` on x86_64, `brk` on aarch64.
        for signal in ["SIGILL", "SIGTRAP"] {
            assert_eq!(
                outcome(Some(&report), signal),
                Outcome::Present,
                "{implementation} traps silently, so {signal} plus its own identity \
                 is the whole of the evidence available"
            );
        }
    }

    // The gate from the other side: glibc's failure carries a message and is matched on that.
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
    // No self-report at all: the identity is unreadable, so the trap stays unattributed.
    assert_eq!(
        outcome(None, "SIGTRAP"),
        Outcome::Indeterminate,
        "withholding is the correct answer when the artifact cannot be read"
    );
}

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
        table: ElfTable::Symbols,
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

    // A compiler with no opt-out attribute says so, and the dirt on every shape is then the
    // witness: a zero fill, which a frame never dirtied reads too, is withheld.
    let unsupported = tavi_detect("TAVI ctrl_supported=0 ctrl=00 arr=00 word=00 small=00");
    assert_eq!(unsupported.outcome, Outcome::Indeterminate);
    let dirt = tavi_detect("TAVI ctrl_supported=0 ctrl=00 arr=5a word=5a small=5a");
    assert_eq!(dirt.outcome, Outcome::Absent);
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

    // Level 0 is an absence: every trailing array is still flexible.
    let none = flex_detect("flex-two=0 flex-one=0 flex-zero=8");
    assert_eq!(none.outcome, Outcome::Absent);
    assert_eq!(none.level, None);

    // Bounded at a wider spelling than a narrower one.
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

#[test]
fn an_unoptimized_guard_reading_is_published_whole() {
    for stdout in [
        "optimize=no\nfrontend=gcc\ngcc-major=16\noverflow-guard=ran",
        "optimize=no\nfrontend=gcc\ngcc-major=7\noverflow-guard=ran",
        "optimize=no\nfrontend=gcc\ngcc-major=x\noverflow-guard=ran",
        "optimize=no\nfrontend=gcc\noverflow-guard=ran",
        "optimize=no\nfrontend=clang\noverflow-guard=ran",
        "optimize=no\nfrontend=other\noverflow-guard=ran",
        "optimize=no\noverflow-guard=ran",
        "optimize=yes\nfrontend=gcc\ngcc-major=7\noverflow-guard=ran",
    ] {
        let d = overflow_reading(stdout, "");
        assert!(
            !d.observed.contains("  ") && !d.observed.contains('\n'),
            "{stdout:?}: a run of whitespace inside the sentence: {:?}",
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
/// is `want` and its sentence is whole.
fn optimized_gcc_7_row(flags: &[&str], want: Outcome, _named: &str) {
    let d = optimized_gcc_reading(Some(7), Some(flags));
    assert_eq!(d.outcome, want, "{flags:?}: {:?}", d.observed);
    assert!(
        !d.observed.contains("  "),
        "{flags:?}: a run of spaces: {:?}",
        d.observed
    );
}

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

#[test]
fn the_run_witness_header_is_no_forced_include_to_the_level_reader() {
    let p = Outcome::Present;
    let i = Outcome::Indeterminate;
    let row = optimized_gcc_7_row;
    let witness = crate::compile::RUN_WITNESS_HEADER_NAME;
    row(&["-O2", "-include", witness], p, "at -O2:");
    row(&["-include", witness, "-O2"], p, "at -O2:");
    row(&["-O1", "-include", witness], i, "at -O1 on gcc 7:");
    let joined = format!("-include{witness}");
    row(&["-O2", &joined], i, &format!("carries {joined},"));
    let pathed = format!("/opt/{witness}");
    row(&["-O2", "-include", &pathed], i, "carries -include,");
    row(
        &["-O2", "-include", "/opt/h", "-include", witness],
        i,
        "carries -include,",
    );
}

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
    // rejects (`--inc`, `--includ=h`), so they never build.
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
    // The value of an option that takes the next word is no word of its own (`-u -B` names
    // a symbol, `-Xlinker -specs=f` is the linker's), and a resetting word after it is found.
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

#[test]
fn an_optimized_gcc_without_a_readable_version_is_read_as_a_gcc_before_8() {
    let p = Outcome::Present;
    let i = Outcome::Indeterminate;
    let row = |flags: &[&str], want: Outcome| {
        let d = optimized_gcc_reading(None, Some(flags));
        assert_eq!(d.outcome, want, "{flags:?}: {:?}", d.observed);
    };
    row(&["-O1"], i);
    row(&["-O2"], p);
    row(&[], i);
    let unversioned = optimized_gcc_reading(None, None);
    assert_eq!(unversioned.outcome, i, "{:?}", unversioned.observed);
    let unreadable = overflow_reading(
        "optimize=yes\nfrontend=gcc\ngcc-major=x\noverflow-guard=ran",
        "",
    );
    assert_eq!(unreadable.outcome, i, "{:?}", unreadable.observed);
}

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

#[test]
fn a_neighbouring_death_is_credited_to_neither_fortify_nor_its_absence() {
    let fortified = died_run("SIGABRT", "*** buffer overflow detected ***: terminated");
    assert_eq!(fortify_runtime_of(&fortified).outcome, Outcome::Present);

    // An abort, and not fortify's.
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

    // The heap probe found its own size known to the compiler, where level 2 fires like
    // level 3, so neither level is published and the precondition is named.
    let opaque_no_more = fortify_runtime_of(&exited_run(PROBE_EXIT_OPACITY_LOST, ""));
    assert_eq!(opaque_no_more.outcome, Outcome::Indeterminate);
    assert!(
        opaque_no_more.observed.contains("statically known"),
        "{}",
        opaque_no_more.observed
    );

    // A probe declining to overflow into memory it cannot vouch for (nothing of its own
    // after `dst`, a chunk geometry its margin was not computed from) names itself.
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

    // Both spellings, written out rather than taken from the constant, so a constant that
    // lost one fails here.
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
    for input in crate::probe::POSITIVE_INPUTS {
        sources.push((input.source_name, input.source));
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
    // gcc 12.2 to 16.2.1 at -O1 and -Og with -fno-strict-aliasing: the flag is present and
    // inert, and the -O2 copy observes the store only because it keeps the flag.
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

#[test]
fn a_wrapper_that_loses_the_subobject_bound_is_the_toolchain_s_silence() {
    let (c, s) = ("caught", "survived");
    let detect = |rows: [&str; 5], stdout: &str| {
        let mut run = sfa_enforced_run(rows);
        run.stdout = stdout.to_owned();
        sfa_enforced_detect(&run)
    };
    let line = |fields: &str| format!("optimize=yes\nCHARD-BOS {fields}\nlibc=?\nrows=5\n");
    let lost = line("main1=2 main0=32 wrap1=32 glibc_wrappers=1 clang_path=?");
    let d = detect([s, s, s, s, s], &lost);
    assert_eq!(d.outcome, Outcome::Absent, "{}", d.observed);
    assert!(d.observed.contains("wrap1=32"), "{}", d.observed);
    for (case, stdout) in [
        (
            "the wrapper keeps the bound",
            line("main1=2 main0=32 wrap1=2 glibc_wrappers=1 clang_path=?"),
        ),
        (
            "a declined answer",
            line("main1=18446744073709551615 main0=18446744073709551615 wrap1=18446744073709551615 glibc_wrappers=1 clang_path=?"),
        ),
        (
            "glibc's clang path taken",
            line("main1=2 main0=32 wrap1=32 glibc_wrappers=1 clang_path=1"),
        ),
        (
            "no glibc wrappers",
            line("main1=2 main0=32 wrap1=32 glibc_wrappers=0 clang_path=?"),
        ),
        (
            "unoptimized",
            "optimize=no\nCHARD-BOS main1=2 main0=32 wrap1=32 glibc_wrappers=1 clang_path=?\nrows=5\n"
                .to_owned(),
        ),
        ("no line", "optimize=yes\nlibc=?\nrows=5\n".to_owned()),
    ] {
        let d = detect([s, s, s, s, s], &stdout);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{case}: {}", d.observed);
    }
    // A trailing row caught beside a silent ctrl row is withheld, whatever the line says.
    let caught_two = detect([s, c, s, s, s], &lost);
    assert_eq!(
        caught_two.outcome,
        Outcome::Indeterminate,
        "{}",
        caught_two.observed
    );
    let level = detect([c, c, c, c, s], &lost);
    assert_eq!(level.outcome, Outcome::Present, "{}", level.observed);
}

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

#[test]
fn a_caught_flex_row_withholds() {
    let c = "caught";
    let d = sfa_enforced_detect(&sfa_enforced_run([c, c, c, c, c]));
    assert_eq!(d.outcome, Outcome::Indeterminate);
    assert!(d.observed.contains("flex row"), "{}", d.observed);
}

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

    // What the check must not move: 12 with probing, 100 without.
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

#[test]
fn a_ratio_without_its_operands_withholds() {
    let d = stack_clash_detect("SCPRT ratio_pct=12");
    assert_eq!(d.outcome, Outcome::Indeterminate);
}

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
    for line in [
        // Nothing was allocated, masked or not.
        "SCPRT dist=140732916358152 n=0 ratio_pct=0",
        // The digits might have been 0, which the unmasked line withholds.
        "SCPRT dist=0 n=140737488355328 ratio_pct=0",
    ] {
        let d = stack_clash_detect(&masked(line));
        assert_eq!(d.outcome, Outcome::Indeterminate, "{line}");
    }
    // Only the exact marker is a normalized distance; any other non-number is missing.
    let d = stack_clash_detect("SCPRT dist=<other> n=67108864 ratio_pct=12");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
}

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
        [
            "stack-exec-runtime",
            "shadow-stack",
            "bti-enforced",
            "pac-ret-enforced",
            "stack-clash"
        ],
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
/// `GLIBC_TUNABLES`, its loader and libc linked into a `-fcf-protection=full` build on the
/// Fedora 44 x86_64 host (kernel 7.3.0-rc3) on 2026-10-21: the witness tunable had no
/// effect, and the program ran with no shadow stack under the pin as without it.
const IGNORED_PINNED_OFF: &str = "SHSTK tunables=ignored\n\
    SHSTK-UNPINNED kernel=ok cpu=ss features=0 ssp=zero\n\
    SHSTK-UNPINNED clobber=hijacked\n\
    SHSTK kernel=ok cpu=ss features=0 ssp=zero\n\
    SHSTK clobber=hijacked\n";

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
    // enforcement shows the opt-in took effect, so the level is graded and the sentence
    // claims nothing about the C library.
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

/// A reading that withholds a guard that ran under `guard-kept-without-the-flag`.
fn names_the_rule(d: &Detection, what: &str, _own: &str) {
    use crate::report::gating_rule::GUARD_KEPT_WITHOUT_THE_FLAG;

    assert_eq!(d.outcome, Outcome::Indeterminate, "{what}: {}", d.observed);
    assert_eq!(
        d.rule.map(|r| r.rule().id),
        Some(GUARD_KEPT_WITHOUT_THE_FLAG.id),
        "{what}: {}",
        d.observed
    );
}

#[test]
fn an_optimized_gcc_before_8_guard_that_ran_names_the_rule_from_each_branch() {
    let named = names_the_rule;
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

/// `bti_enforced.c`'s lines over a run that ended as given, beside an artifact whose property
/// note carries the BTI bit or not (`None` for no artifact read).
fn bti_detect(
    stdout: &str,
    exit_status: i32,
    signal: Option<&str>,
    stderr: &str,
    marked: Option<bool>,
) -> Detection {
    let macros = BTreeMap::new();
    let mut run = tavi_run(stdout);
    run.exit_status = exit_status;
    run.signal = signal.map(ToOwned::to_owned);
    run.stderr = stderr.to_owned();
    let elf = marked.map(|bti| {
        let mut elf = elf_with_report("");
        elf.machine = "aarch64".to_owned();
        elf.aarch64_bti = bti;
        elf
    });
    detect_bti_enforced(&Evidence {
        macros: &macros,
        elf: elf.as_ref(),
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

/// The probe's lines up to the branch, on a machine whose kernel reports BTI.
const BTI_ATTEMPTED_YES: &str = "BTI hwcap=yes\nBTI branch=attempted\n";
/// A BTI fault at the declared target, in the reporter's shape as measured on the M2 guest on
/// 2026-10-09 (`run::tests`), with the target's `mov w0, #42` as its word.
const BTI_FAULT_AT_TARGET: &str = "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 \
                                   pc=0xe8e60eb4f000 addr=0xe8e60eb4f000 word=0x52800540 \
                                   esr=none at-target=yes\n";

#[test]
fn bti_is_read_from_a_fault_at_the_target_or_the_branch_landing() {
    let on = bti_detect(
        BTI_ATTEMPTED_YES,
        -1,
        Some("SIGILL"),
        BTI_FAULT_AT_TARGET,
        Some(true),
    );
    assert_eq!(on.outcome, Outcome::Present, "{}", on.observed);
    assert!(on.level.is_none(), "{}", on.observed);
    assert!(
        on.observed.contains("carries the BTI bit"),
        "{}",
        on.observed
    );

    let landed = format!("{BTI_ATTEMPTED_YES}BTI branch=landed returned=42\n");
    for (marked, says) in [
        (Some(true), "carries the BTI bit"),
        (Some(false), "carries no BTI bit"),
    ] {
        let off = bti_detect(&landed, 0, None, "", marked);
        assert_eq!(off.outcome, Outcome::Absent, "{marked:?}: {}", off.observed);
        assert!(off.observed.contains(says), "{marked:?}: {}", off.observed);
    }
}

#[test]
fn a_kernel_without_hwcap2_bti_is_the_machine_s_lack() {
    let stdout = "BTI hwcap=no\nBTI branch=attempted\nBTI branch=landed returned=42\n";
    let d = bti_detect(stdout, 0, None, "", Some(true));
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(d.observed.contains("HWCAP2_BTI"), "{}", d.observed);
    let r = bti_reading(stdout).expect("the lines read");
    assert!(r.machine_lacks().is_some());
    assert!(
        bti_reading(BTI_ATTEMPTED_YES)
            .expect("the lines read")
            .machine_lacks()
            .is_none()
    );
}

/// A BTI case: its label, stdout, exit status, signal, stderr, the artifact's marking, and a
/// phrase of the reason it must withhold for.
type BtiCase<'a> = (
    &'a str,
    &'a str,
    i32,
    Option<&'a str>,
    &'a str,
    Option<bool>,
    &'a str,
);

/// Each case reads `indeterminate`.
fn assert_bti_withholds(cases: &[BtiCase<'_>]) {
    for &(label, stdout, exit, signal, stderr, marked, _) in cases {
        let d = bti_detect(stdout, exit, signal, stderr, marked);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{label}: {}", d.observed);
    }
}

#[test]
fn every_other_bti_death_withholds() {
    let undeclared = BTI_FAULT_AT_TARGET.replace("at-target=yes", "at-target=undeclared");
    let off_target = BTI_FAULT_AT_TARGET.replace("at-target=yes", "at-target=no");
    let esr_off_target = off_target.replace("esr=none", "esr=0x34000000");
    let unread_word = BTI_FAULT_AT_TARGET.replace("word=0x52800540", "word=none");
    let udf = BTI_FAULT_AT_TARGET.replace("word=0x52800540", "word=0x0");
    let segv = "chard-fault-v1 signal=11 code=1 sent=no arch=aarch64 pc=0x10 addr=0x10 \
                word=none esr=0x82000004 at-target=no\n";
    let ill = Some("SIGILL");
    let yes = BTI_ATTEMPTED_YES;
    assert_bti_withholds(&[
        (
            "before the branch",
            "BTI hwcap=yes\n",
            -1,
            ill,
            BTI_FAULT_AT_TARGET,
            Some(true),
            "did not print",
        ),
        (
            "undeclared target",
            yes,
            -1,
            ill,
            &undeclared,
            Some(true),
            "IllegalInstruction",
        ),
        (
            "elsewhere, no ESR",
            yes,
            -1,
            ill,
            &off_target,
            Some(true),
            "IllegalInstruction",
        ),
        (
            "elsewhere, a BTI ESR",
            yes,
            -1,
            ill,
            &esr_off_target,
            Some(true),
            "not at the target",
        ),
        (
            "an unread word",
            yes,
            -1,
            ill,
            &unread_word,
            Some(true),
            "Undetermined",
        ),
        (
            "a udf",
            yes,
            -1,
            ill,
            &udf,
            Some(true),
            "IllegalInstruction",
        ),
        (
            "a SIGSEGV",
            yes,
            -1,
            Some("SIGSEGV"),
            segv,
            Some(true),
            "Other",
        ),
        ("no report", yes, -1, ill, "", Some(true), "no fault report"),
        (
            "unmarked",
            yes,
            -1,
            ill,
            BTI_FAULT_AT_TARGET,
            Some(false),
            "contradicts",
        ),
    ]);
}

#[test]
fn every_other_bti_landing_or_line_withholds() {
    let other = format!("{BTI_ATTEMPTED_YES}BTI branch=landed returned=7\n");
    let landed = format!("{BTI_ATTEMPTED_YES}BTI branch=landed returned=42\n");
    let malformed = "BTI hwcap=maybe\nBTI branch=attempted\n";
    assert_bti_withholds(&[
        (
            "another value",
            &other,
            0,
            None,
            "",
            Some(true),
            "not the probe's",
        ),
        (
            "another exit",
            &landed,
            3,
            None,
            "",
            Some(true),
            "not the probe's",
        ),
        ("an unread note", &landed, 0, None, "", None, "was not read"),
        (
            "x86_64",
            "BTI unsupported-arch\n",
            0,
            None,
            "",
            None,
            "this architecture",
        ),
        (
            "macOS arm64",
            "BTI unsupported-os\n",
            0,
            None,
            "",
            None,
            "does not have",
        ),
        (
            "a malformed hwcap",
            malformed,
            0,
            None,
            "",
            None,
            "no `BTI hwcap=` line",
        ),
    ]);
}

/// `pac_ret_enforced.c`'s lines over a run that ended as given.
fn pac_detect(stdout: &str, exit_status: i32, signal: Option<&str>, stderr: &str) -> Detection {
    let macros = BTreeMap::new();
    let mut run = tavi_run(stdout);
    run.exit_status = exit_status;
    run.signal = signal.map(ToOwned::to_owned);
    run.stderr = stderr.to_owned();
    detect_pac_ret_enforced(&Evidence {
        macros: &macros,
        elf: None,
        build: None,
        run: Some(&run),
        workdir: None,
    })
}

/// The probe's lines up to the return, on a machine with PAC and FPAC.
const PAC_ATTEMPTED_FPAC: &str = "PAC hwcap=yes fpac=yes\nPAC return=attempted\n";
/// A PAC failure in the reporter's shape as measured on the M2 guest on 2026-10-09
/// (`run::tests`): SIGILL `ILL_ILLOPN` at `autiasp`, ESR class 0x1c.
const PAC_FAULT: &str = "chard-fault-v1 signal=4 code=2 sent=no arch=aarch64 pc=0xb95168ec0cdc \
                         addr=0xb95168ec0cdc word=0xd50323bf esr=0x72000000 at-target=no\n";

#[test]
fn pac_is_read_from_an_fpac_failure_or_the_marker_reached() {
    for fpac in ["yes", "unread"] {
        let stdout = format!("PAC hwcap=yes fpac={fpac}\nPAC return=attempted\n");
        let on = pac_detect(&stdout, -1, Some("SIGILL"), PAC_FAULT);
        assert_eq!(on.outcome, Outcome::Present, "{fpac}: {}", on.observed);
        assert!(on.observed.contains("FEAT_FPAC"), "{}", on.observed);
    }
    for fpac in ["yes", "no", "unread"] {
        let stdout =
            format!("PAC hwcap=yes fpac={fpac}\nPAC return=attempted\nPAC return=hijacked\n");
        let off = pac_detect(&stdout, 0, None, "");
        assert_eq!(off.outcome, Outcome::Absent, "{fpac}: {}", off.observed);
    }
}

#[test]
fn a_kernel_without_hwcap_paca_is_the_machine_s_lack() {
    let stdout = "PAC hwcap=no fpac=unread\nPAC return=attempted\nPAC return=hijacked\n";
    let d = pac_detect(stdout, 0, None, "");
    assert_eq!(d.outcome, Outcome::Indeterminate, "{}", d.observed);
    assert!(d.observed.contains("HWCAP_PACA"), "{}", d.observed);
    let run = tavi_run(stdout);
    assert!(matches!(
        pac_reading(stdout).expect("read").machine_lacks(&run),
        Some(PacLack::Hwcap(_))
    ));
    let fpac = tavi_run(PAC_ATTEMPTED_FPAC);
    assert!(
        pac_reading(PAC_ATTEMPTED_FPAC)
            .expect("read")
            .machine_lacks(&fpac)
            .is_none()
    );
}

/// A PAC case: its label, stdout, exit status, signal, stderr, and a phrase of the reason it
/// must withhold for.
type PacCase<'a> = (&'a str, &'a str, i32, Option<&'a str>, &'a str, &'a str);

#[test]
fn every_other_pac_run_withholds() {
    let no_fpac = "PAC hwcap=yes fpac=no\nPAC return=attempted\n";
    let unread = "PAC hwcap=yes fpac=unread\nPAC return=attempted\n";
    let segv = "chard-fault-v1 signal=11 code=1 sent=no arch=aarch64 pc=0x20000000400a8c \
                addr=0x20000000400a8c word=none esr=0x82000004 at-target=no\n";
    let ill = "chard-fault-v1 signal=4 code=1 sent=no arch=aarch64 pc=0x400a8c addr=0x400a8c \
               word=0x0 esr=none at-target=no\n";
    let returned = format!("{PAC_ATTEMPTED_FPAC}PAC return=returned\n");
    let hijacked = format!("{PAC_ATTEMPTED_FPAC}PAC return=hijacked\n");
    let s = Some("SIGSEGV");
    let i = Some("SIGILL");
    let cases: [PacCase<'_>; 12] = [
        (
            "before the return",
            "PAC hwcap=yes fpac=yes\n",
            -1,
            i,
            PAC_FAULT,
            "did not print",
        ),
        ("returned normally", &returned, 0, None, "", "did not take"),
        ("hijacked, then died", &hijacked, -1, s, segv, "did not end"),
        (
            "FPAC failure, fpac=no",
            no_fpac,
            -1,
            i,
            PAC_FAULT,
            "only FEAT_FPAC",
        ),
        (
            "poisoned, fpac=no",
            no_fpac,
            -1,
            s,
            segv,
            "poisoned pointer",
        ),
        (
            "poisoned, fpac=unread",
            unread,
            -1,
            s,
            segv,
            "poisoned pointer",
        ),
        (
            "SIGSEGV with FPAC",
            PAC_ATTEMPTED_FPAC,
            -1,
            s,
            segv,
            "Other",
        ),
        (
            "another SIGILL",
            PAC_ATTEMPTED_FPAC,
            -1,
            i,
            ill,
            "IllegalInstruction",
        ),
        (
            "no report",
            PAC_ATTEMPTED_FPAC,
            -1,
            i,
            "",
            "no fault report",
        ),
        (
            "x86_64",
            "PAC unsupported-arch\n",
            0,
            None,
            "",
            "this architecture",
        ),
        (
            "macOS arm64",
            "PAC unsupported-os\n",
            0,
            None,
            "",
            "does not have",
        ),
        (
            "a malformed line",
            "PAC hwcap=yes fpac=maybe\nPAC return=attempted\n",
            0,
            None,
            "",
            "no `PAC hwcap=` line",
        ),
    ];
    for (label, stdout, exit, signal, stderr, _) in cases {
        let d = pac_detect(stdout, exit, signal, stderr);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{label}: {}", d.observed);
    }
}

#[test]
fn an_unoptimized_build_names_the_rule_where_the_observable_needs_optimization() {
    use crate::report::gating_rule::UNOPTIMIZED_BUILD_CANNOT_SHOW;
    let macros = BTreeMap::new();
    let on = |detect: fn(&Evidence<'_>) -> Detection, run: &RunRecord| {
        detect(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(run),
            workdir: None,
        })
    };
    let rule = |d: &Detection| d.rule.map(|r| r.rule().id);
    let named = Some(UNOPTIMIZED_BUILD_CANNOT_SHOW.id);

    let aliasing = on(detect_no_strict_aliasing, &flex_run("optimize=no\n"));
    assert_eq!(
        aliasing.outcome,
        Outcome::Indeterminate,
        "{}",
        aliasing.observed
    );
    assert_eq!(rule(&aliasing), named, "{}", aliasing.observed);

    let no_size = "flex-two=-1 flex-one=-1 flex-zero=-1\nstorage=declared\n";
    let flex = on(
        detect_strict_flex_arrays,
        &flex_run(&format!("{no_size}optimize=no\n")),
    );
    assert_eq!(flex.outcome, Outcome::Indeterminate, "{}", flex.observed);
    assert_eq!(rule(&flex), named, "{}", flex.observed);
    let flex_o2 = on(
        detect_strict_flex_arrays,
        &flex_run(&format!("{no_size}optimize=yes\n")),
    );
    assert_eq!(rule(&flex_o2), None, "{}", flex_o2.observed);

    let mut died = flex_run("optimize=no\n");
    died.exit_status = -1;
    died.signal = Some("SIGSEGV".to_owned());
    let null = on(detect_no_delete_null_checks, &died);
    assert_eq!(null.outcome, Outcome::Indeterminate, "{}", null.observed);
    assert_eq!(rule(&null), named, "{}", null.observed);
    // A death that is not a memory fault (a deadline kill, an abort, a trap), an unoptimized
    // build with no signal, and an optimized build that died name no rule.
    for (stdout, signal) in [
        ("optimize=no\n", Some("SIGKILL")),
        ("optimize=no\n", Some("SIGABRT")),
        ("optimize=no\n", Some("SIGILL")),
        ("optimize=no\n", None),
        ("optimize=yes\n", Some("SIGSEGV")),
    ] {
        let mut other = flex_run(stdout);
        other.exit_status = -1;
        other.signal = signal.map(str::to_owned);
        let d = on(detect_no_delete_null_checks, &other);
        assert_eq!(rule(&d), None, "{stdout:?} {signal:?}: {}", d.observed);
    }
    let mut bus = flex_run("optimize=no\n");
    bus.exit_status = -1;
    bus.signal = Some("SIGBUS".to_owned());
    assert_eq!(rule(&on(detect_no_delete_null_checks, &bus)), named);
    died.stdout = String::new();
    let unsaid = on(detect_no_delete_null_checks, &died);
    assert_eq!(rule(&unsaid), None, "{}", unsaid.observed);

    let s = "survived";
    let mut sfa = sfa_enforced_run([s, s, s, s, s]);
    sfa.stdout = "optimize=no\nlibc=?\nrows=5\n".to_owned();
    let enforced = sfa_enforced_detect(&sfa);
    assert_eq!(
        enforced.outcome,
        Outcome::Indeterminate,
        "{}",
        enforced.observed
    );
    assert_eq!(rule(&enforced), named, "{}", enforced.observed);
    sfa.stdout = "optimize=yes\nlibc=?\nrows=5\n".to_owned();
    assert_eq!(rule(&sfa_enforced_detect(&sfa)), None);
}

#[test]
fn a_glibc_build_below_fortify_two_names_the_rule() {
    use crate::report::gating_rule::FORTIFY_BELOW_SUBOBJECT_LEVEL;
    let (c, s) = ("caught", "survived");
    let with = |rows: [&str; 5], report: &str, optimize: &str| {
        let run = RunRecord {
            stdout: format!(
                "CHARD-REPORT-V2\n{report}\nCHARD-REPORT-END\noptimize={optimize}\nlibc=?\nrows=5\n"
            ),
            ..sfa_enforced_run(rows)
        };
        sfa_enforced_detect(&run)
    };
    let rule = |d: &Detection| d.rule.map(|r| r.rule().id);
    let from_elf = |report: &str| {
        let elf = elf_with_report(&format!("CHARD-REPORT-V2\n{report}\nCHARD-REPORT-END\n"));
        let run = RunRecord {
            stdout: "optimize=yes\nlibc=?\nrows=5\n".to_owned(),
            ..sfa_enforced_run([s, s, s, s, s])
        };
        let macros = BTreeMap::new();
        detect_strict_flex_arrays_enforced(&Evidence {
            macros: &macros,
            elf: Some(&elf),
            build: None,
            run: Some(&run),
            workdir: None,
        })
    };
    for (report, d) in [
        "__GLIBC__=2\n__USE_FORTIFY_LEVEL=0",
        "__GLIBC__=2\n__USE_FORTIFY_LEVEL=1",
    ]
    .into_iter()
    .flat_map(|r| [(r, with([s, s, s, s, s], r, "yes")), (r, from_elf(r))])
    {
        assert_eq!(
            (d.outcome, rule(&d)),
            (
                Outcome::Indeterminate,
                Some(FORTIFY_BELOW_SUBOBJECT_LEVEL.id)
            ),
            "{report}: {}",
            d.observed
        );
        assert!(
            d.observed.contains("__USE_FORTIFY_LEVEL="),
            "{}",
            d.observed
        );
    }
    for (case, rows, report, optimize) in [
        (
            "a level given as undefined",
            [s, s, s, s, s],
            "__GLIBC__=2\n__USE_FORTIFY_LEVEL undefined",
            "yes",
        ),
        (
            "settled at 2",
            [s, s, s, s, s],
            "__GLIBC__=2\n__USE_FORTIFY_LEVEL=2",
            "yes",
        ),
        (
            "not glibc",
            [s, s, s, s, s],
            "__GLIBC__ undefined\n__USE_FORTIFY_LEVEL undefined",
            "yes",
        ),
        (
            "unoptimized",
            [s, s, s, s, s],
            "__GLIBC__=2\n__USE_FORTIFY_LEVEL =0",
            "no",
        ),
        (
            "a trailing row caught",
            [s, c, s, s, s],
            "__GLIBC__=2\n__USE_FORTIFY_LEVEL =0",
            "yes",
        ),
    ] {
        let d = with(rows, report, optimize);
        assert_ne!(
            rule(&d),
            Some(FORTIFY_BELOW_SUBOBJECT_LEVEL.id),
            "{case}: {}",
            d.observed
        );
    }
    let unoptimized = with([s, s, s, s, s], "__GLIBC__=2\n__USE_FORTIFY_LEVEL=0", "no");
    assert_eq!(
        rule(&unoptimized),
        Some(gating_rule::UNOPTIMIZED_BUILD_CANNOT_SHOW.id),
        "{}",
        unoptimized.observed
    );
}

#[test]
fn a_frame_not_reused_names_the_rule() {
    use crate::report::gating_rule::FRAME_REUSE_DID_NOT_HOLD;
    let macros = BTreeMap::new();
    let detect = |line: &str| {
        let run = exited_run(0, &format!("{line}\n"));
        detect_zero_init_padding(&Evidence {
            macros: &macros,
            elf: None,
            build: None,
            run: Some(&run),
            workdir: None,
        })
    };
    let rule = |d: &Detection| d.rule.map(|r| r.rule().id);
    for line in [
        "ZIPB pad=00 ctrl=1a ctrl_supported=1",
        "ZIPB pad=00 ctrl=00 ctrl_supported=1",
        "ZIPB pad=00 ctrl=00 ctrl_supported=0",
        "ZIPB pad=00 ctrl=f0 ctrl_supported=0",
        "ZIPB pad=00 ctrl=60 ctrl_supported=0",
        "ZIPB pad=00 ctrl=39 ctrl_supported=0",
        "ZIPB pad=5a ctrl=00 ctrl_supported=0",
        "ZIPB pad=5a ctrl=fe ctrl_supported=0",
        "ZIPB pad=77 ctrl=00 ctrl_supported=1",
        "ZIPB pad=77 ctrl=00 ctrl_supported=0",
        "ZIPB pad=00 ctrl=5b ctrl_supported=1",
        "ZIPB pad=00 ctrl=50 ctrl_supported=0",
    ] {
        let d = detect(line);
        assert_eq!(d.outcome, Outcome::Indeterminate, "{line}: {}", d.observed);
        assert_eq!(rule(&d), Some(FRAME_REUSE_DID_NOT_HOLD.id), "{line}");
        let pad = &line["ZIPB pad=".len()..][..2];
        let ctrl = &line["ZIPB pad=00 ctrl=".len()..][..2];
        let said = format!("read 0x{ctrl} rather than the dirt, 0x5a, so pad=0x{pad} establishes");
        assert!(d.observed.contains(&said), "{line}: {}", d.observed);
        assert!(
            d.observed.starts_with("frame reuse not witnessed: "),
            "{line}: {}",
            d.observed
        );
        let names_the_attribute = d.observed.contains("no __attribute__((uninitialized))");
        assert_eq!(
            names_the_attribute,
            line.ends_with("ctrl_supported=0"),
            "{line}: {}",
            d.observed
        );
        assert_eq!(
            d.observed.contains("the opted-out control read"),
            line.ends_with("ctrl_supported=1"),
            "{line}: {}",
            d.observed
        );
    }
    for (line, outcome) in [
        ("ZIPB pad=00 ctrl=5a ctrl_supported=1", Outcome::Present),
        ("ZIPB pad=5a ctrl=5a ctrl_supported=1", Outcome::Absent),
        ("ZIPB pad=00 ctrl=5a ctrl_supported=0", Outcome::Present),
        ("ZIPB pad=5a ctrl=5a ctrl_supported=0", Outcome::Absent),
        (
            "ZIPB pad=77 ctrl=5a ctrl_supported=1",
            Outcome::Indeterminate,
        ),
        (
            "ZIPB pad=77 ctrl=5a ctrl_supported=0",
            Outcome::Indeterminate,
        ),
    ] {
        let d = detect(line);
        assert_eq!(d.outcome, outcome, "{line}: {}", d.observed);
        assert_eq!(rule(&d), None, "{line}");
        if outcome == Outcome::Indeterminate {
            assert!(
                d.observed.contains("neither the dirt nor zero"),
                "{line}: {}",
                d.observed
            );
        }
    }
}

#[test]
fn a_tavi_reading_implies_its_frame_reuse_was_witnessed() {
    let elf = elf_of_class(64);
    let names = ["arr", "word", "small", "ctrl", "ctrl_supported"];
    let fills: [(&str, [&str; 3]); 4] = [
        ("dirt", ["5a", "5a", "5a"]),
        ("zero", ["00", "00", "00"]),
        ("pattern", ["fe", "fe", "fe"]),
        ("mixed", ["00", "5a", "13"]),
    ];
    let mut readings = 0;
    for mask in 0u8..32 {
        for supported in ["0", "1", "x"] {
            for ctrl in ["5a", "00"] {
                for (fill, shapes) in fills {
                    let values = [shapes[0], shapes[1], shapes[2], ctrl, supported];
                    let fields: Vec<String> = names
                        .iter()
                        .zip(values)
                        .enumerate()
                        .filter(|(i, _)| mask & (1 << i) != 0)
                        .map(|(_, (n, v))| format!("{n}={v}"))
                        .collect();
                    let line = format!("TAVI {}\n", fields.join(" "));
                    let all = mask == 31;
                    let witnessed = all
                        && match supported {
                            "1" => ctrl == "5a",
                            "0" => fill == "dirt",
                            _ => false,
                        };
                    for d in tavi_both(&line, Some(&elf)) {
                        if d.outcome != Outcome::Indeterminate {
                            readings += 1;
                            assert!(witnessed, "{line:?} read {:?}: {}", d.outcome, d.observed);
                        }
                    }
                }
            }
        }
    }
    assert!(readings > 0, "the enumeration reached no reading at all");

    for line in [
        "TAVI arr=5a word=5a small=5a ctrl=5a ctrl_supported=0",
        "TAVI arr=5a word=5a small=5a ctrl=13 ctrl_supported=0",
    ] {
        for d in tavi_both(line, Some(&elf)) {
            assert_eq!(d.outcome, Outcome::Absent, "{line}: {}", d.observed);
        }
    }
    for line in [
        "TAVI arr=00 word=00 small=00 ctrl=00 ctrl_supported=0",
        "TAVI arr=fe word=fe small=fe ctrl=fe ctrl_supported=0",
        "TAVI arr=00 word=5a small=5a ctrl=5a ctrl_supported=0",
    ] {
        for d in tavi_both(line, Some(&elf)) {
            assert_eq!(d.outcome, Outcome::Indeterminate, "{line}: {}", d.observed);
        }
    }
}

/// The probe prints the fields the decoder requires ([`TAVI_FIELDS`]), in its order, one
/// conversion and one argument each (`b[0]` to `b[3]`, then `ctrl_supported`): a field the
/// probe stopped printing would turn every run, controls included, into an unexplained
/// `indeterminate`, and an argument moved would hand a field another field's byte.
#[test]
fn the_tavi_probe_prints_every_field_its_decoder_requires() {
    let source = include_str!("../../probes/auto_var_init.c");
    let start = source
        .find("printf(\"TAVI ")
        .expect("the probe prints its TAVI line");
    let call = &source[start..start + source[start..].find(");").expect("the call ends")];
    let format_end = call[8..].find('"').expect("the format string ends") + 8;
    let format = &call[8..format_end];
    let names: Vec<&str> = format
        .trim_start_matches("TAVI ")
        .split_whitespace()
        .map(|w| w.split('=').next().unwrap_or(""))
        .collect();
    assert_eq!(names, TAVI_FIELDS, "the fields the probe prints: {format}");
    assert_eq!(
        format.matches('%').count(),
        TAVI_FIELDS.len(),
        "one conversion per field: {format}"
    );
    let args: Vec<String> = call[format_end + 1..]
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<String>()
        .split(',')
        .map(|a| a.trim().to_owned())
        .filter(|a| !a.is_empty())
        .collect();
    assert_eq!(
        args.len(),
        TAVI_FIELDS.len(),
        "one argument per conversion: {args:?}"
    );
    for (i, arg) in args.iter().take(4).enumerate() {
        assert_eq!(
            arg,
            &format!("b[{i}]"),
            "{} is printed from {arg}",
            TAVI_FIELDS[i]
        );
    }
}
