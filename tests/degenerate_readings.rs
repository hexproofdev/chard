// SPDX-License-Identifier: BSD-3-Clause

//! Every runtime decoder withholds the degenerate forms of the line it reads.
//!
//! A runtime reading is `not_replayable`: `report.rs` restates a reading as a verdict and
//! keeps no copy the verdict could be re-derived from. A decoder that accepts a degenerate
//! line (an empty stream, a count of zero, a field that is not there, a line from a target
//! the probe does not describe) therefore has no second check, and the verdict it publishes
//! reads as a measurement. `zcur_reading` accepting `args=0` was the first instance found.
//!
//! One table, [`ROWS`], has a row per runtime detector and four forms per row:
//!
//! - **empty**: nothing, or nothing the decoder reads;
//! - **zero**: the line's count or value field at zero, or a witness field at zero;
//! - **missing**: the line with a field removed, empty, or not of its type;
//! - **arch**: the line a probe prints on a target it has no witness for, or a reading
//!   from a target other than the one the decoder's constants describe.
//!
//! A form either lists cases, each of which must read `indeterminate`, or says why it does
//! not apply to that detector. Each row also carries a well-formed control line with the
//! verdict it must read, so a table that fed the detectors nothing readable would fail
//! here rather than pass every case as withheld.
//!
//! Completeness is checked from two directions, as `tests/inert_flags.rs` does for the
//! graded checks: the runtime detectors the corpus maps to the runtime channel must be
//! exactly the rows, and the `detect_*` functions `src/decode/runtime.rs` defines must be
//! exactly as many as the rows, so a detector added to the module without a row, or wired
//! into the corpus without a row, fails before it ships.
//!
//! A case a known defect makes fail carries its handle. The main test skips it and one
//! `#[ignore = "HANDLE: ..."]` test per handle runs it, so `cargo test -- --ignored` lists
//! what is still open and a fix removes the handle and the ignore together. A case that
//! exposed a defect no issue names carries a `NEW-` handle, described in the branch's
//! `new-defects.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use chard::elf::ElfFacts;
use chard::probe::{CORPUS, Decoder, Detection, Evidence, Outcome};
use chard::run::RunRecord;

/// One degenerate line, with the run around it.
#[derive(Clone, Copy)]
struct Case {
    label: &'static str,
    stdout: &'static str,
    stderr: &'static str,
    exit: i32,
    signal: Option<&'static str>,
    /// The compiler's macro dump, for a detector that reads the C++ library from it.
    macros: &'static [(&'static str, &'static str)],
    /// The artifact's ELF class, for a detector that reads the pointer width from it.
    elf_class: Option<u8>,
    /// The defect that makes this case fail today, `COR-n` for an issue that names it and
    /// `NEW-n` for one this table found.
    defect: Option<&'static str>,
}

const fn case(label: &'static str, stdout: &'static str) -> Case {
    Case {
        label,
        stdout,
        stderr: "",
        exit: 0,
        signal: None,
        macros: &[],
        elf_class: None,
        defect: None,
    }
}

/// A form of a row: the cases it feeds, or why it has none.
enum Form {
    Cases(&'static [Case]),
    NotApplicable(&'static str),
}

struct Row {
    detector: &'static str,
    /// A well-formed line and the verdict it reads, to show the harness reaches the decoder.
    control: Case,
    control_reads: Outcome,
    empty: Form,
    zero: Form,
    missing: Form,
    arch: Form,
}

const SIGABRT: Option<&str> = Some("SIGABRT");
const SIGILL: Option<&str> = Some("SIGILL");
const SIGTRAP: Option<&str> = Some("SIGTRAP");
const SIGSEGV: Option<&str> = Some("SIGSEGV");

const GLIBC_DIAGNOSTIC: &str = "*** buffer overflow detected ***: terminated\n";
const REPORT_GLIBC: &str = "CHARD-REPORT-V1\n_FORTIFY_IMPL=glibc\nCHARD-REPORT-END\n";
const REPORT_UNKNOWN_IMPL: &str = "CHARD-REPORT-V2\n_FORTIFY_IMPL undefined\nCHARD-REPORT-END\n";

// The strict-flex-arrays-enforced probe's stderr: one begin/end pair per row.
macro_rules! sfa_row {
    ($row:literal, $segment:literal, $status:literal) => {
        concat!(
            "CHARD-SFA-ENFORCED begin row=",
            $row,
            "\n",
            $segment,
            "CHARD-SFA-ENFORCED end row=",
            $row,
            " status=",
            $status,
            "\n"
        )
    };
}
const SFA_LEVEL_3: &str = concat!(
    sfa_row!("ctrl", "*** buffer overflow detected ***\n", "signal:6"),
    sfa_row!("two", "*** buffer overflow detected ***\n", "signal:6"),
    sfa_row!("one", "*** buffer overflow detected ***\n", "signal:6"),
    sfa_row!("zero", "*** buffer overflow detected ***\n", "signal:6"),
    sfa_row!("flex", "", "exit:0"),
);
const SFA_ALL_SURVIVED: &str = concat!(
    sfa_row!("ctrl", "", "exit:0"),
    sfa_row!("two", "", "exit:0"),
    sfa_row!("one", "", "exit:0"),
    sfa_row!("zero", "", "exit:0"),
    sfa_row!("flex", "", "exit:0"),
);
const SFA_ZERO_ROW_UNTERMINATED: &str = concat!(
    sfa_row!("ctrl", "*** buffer overflow detected ***\n", "signal:6"),
    sfa_row!("two", "*** buffer overflow detected ***\n", "signal:6"),
    sfa_row!("one", "*** buffer overflow detected ***\n", "signal:6"),
    "CHARD-SFA-ENFORCED begin row=zero\n",
    "*** buffer overflow detected ***\n",
    sfa_row!("flex", "", "exit:0"),
);
const SFA_CTRL_ONLY: &str = sfa_row!("ctrl", "*** buffer overflow detected ***\n", "signal:6");
const SFA_EMPTY_STATUS: &str = concat!(
    sfa_row!("ctrl", "*** buffer overflow detected ***\n", ""),
    sfa_row!("two", "", "exit:0"),
    sfa_row!("one", "", "exit:0"),
    sfa_row!("zero", "", "exit:0"),
    sfa_row!("flex", "", "exit:0"),
);
const SFA_TRAPS: &str = concat!(
    sfa_row!("ctrl", "", "signal:4"),
    sfa_row!("two", "", "signal:4"),
    sfa_row!("one", "", "signal:4"),
    sfa_row!("zero", "", "signal:4"),
    sfa_row!("flex", "", "exit:0"),
);

const SHSTK_PINNED_ENFORCED: &str = concat!(
    "SHSTK kernel=ok cpu=ss features=0x1 ssp=nonzero\n",
    "SHSTK clobber=cperr\n"
);

const ROWS: &[Row] = &[
    Row {
        detector: "detect_fortify_runtime",
        control: Case {
            stderr: GLIBC_DIAGNOSTIC,
            exit: -1,
            signal: SIGABRT,
            ..case("glibc abort carrying its diagnostic", "")
        },
        control_reads: Outcome::Present,
        empty: Form::Cases(&[
            case("both streams empty, clean exit", ""),
            Case {
                exit: -1,
                signal: SIGSEGV,
                ..case("both streams empty, killed by a segfault", "")
            },
        ]),
        zero: Form::NotApplicable(
            "the reading is an exit status and two message strings; there is no count or \
             value field to zero",
        ),
        missing: Form::Cases(&[
            case("the survival marker misspelled", "no-check-fire\n"),
            Case {
                exit: -1,
                signal: SIGABRT,
                ..case("an abort with no diagnostic", "")
            },
            Case {
                exit: 1,
                ..case(
                    "the survival marker beside a nonzero exit",
                    "no-check-fired\n",
                )
            },
            Case {
                exit: 77,
                ..case("the allocation-failure status and nothing else", "")
            },
        ]),
        arch: Form::Cases(&[
            Case {
                exit: -1,
                signal: SIGILL,
                ..case("a trap and no self-report naming an implementation", "")
            },
            Case {
                exit: -1,
                signal: SIGILL,
                ..case("a trap beside a glibc self-report", REPORT_GLIBC)
            },
            Case {
                exit: -1,
                signal: SIGTRAP,
                ..case(
                    "a trap beside an unrecognised implementation",
                    REPORT_UNKNOWN_IMPL,
                )
            },
            Case {
                exit: -1,
                signal: SIGILL,
                ..case(
                    "a trap beside a self-report that was never closed",
                    "CHARD-REPORT-V1\n_FORTIFY_IMPL=fortify-headers\n",
                )
            },
        ]),
    },
    Row {
        detector: "detect_fortify_percent_n",
        control: Case {
            stderr: "*** %n in writable segment detected ***\n",
            exit: -1,
            signal: SIGABRT,
            ..case("glibc abort carrying the %n diagnostic", "")
        },
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("both streams empty, clean exit", "")]),
        zero: Form::NotApplicable(
            "the reading is an exit status and one message string; there is no count or \
             value field to zero",
        ),
        missing: Form::Cases(&[
            Case {
                exit: -1,
                signal: SIGABRT,
                ..case("an abort with no diagnostic", "")
            },
            Case {
                exit: -1,
                signal: SIGABRT,
                stderr: "*** buffer overflow detected ***\n",
                ..case("an abort carrying the other rung's diagnostic", "")
            },
            Case {
                exit: 1,
                ..case(
                    "the survival marker beside a nonzero exit",
                    "no-check-fired\n",
                )
            },
        ]),
        arch: Form::Cases(&[Case {
            exit: -1,
            signal: SIGILL,
            ..case(
                "a trap, as an implementation with no %n diagnostic ends",
                "",
            )
        }]),
    },
    Row {
        detector: "detect_cxx_assertions",
        control: Case {
            stderr: "assertion __n < size() failed: out of range\n",
            exit: -1,
            signal: SIGABRT,
            ..case("libc++ abort carrying its assertion text", "")
        },
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("both streams empty, clean exit", "")]),
        zero: Form::NotApplicable(
            "the only value read is the `chard-opt=0` flag, which sets the evidence's \
             optimized note and never a verdict",
        ),
        missing: Form::Cases(&[
            Case {
                exit: -1,
                signal: SIGABRT,
                ..case("an abort with no standard-library diagnostic", "")
            },
            Case {
                exit: -1,
                signal: SIGABRT,
                stderr: "assertion",
                ..case("the diagnostic's word without the trailing space", "")
            },
            case("the optimization note alone", "chard-opt=0\n"),
        ]),
        arch: Form::Cases(&[
            Case {
                exit: -1,
                signal: SIGILL,
                ..case("a trap with no standard library named", "")
            },
            Case {
                exit: -1,
                signal: SIGILL,
                macros: &[("__GLIBCXX__", "20260101")],
                ..case("a trap under libstdc++, which asserts by abort", "")
            },
            Case {
                exit: -1,
                signal: SIGTRAP,
                macros: &[("__GLIBCXX__", "20260101")],
                ..case("a breakpoint trap under libstdc++", "")
            },
        ]),
    },
    Row {
        detector: "detect_stack_clash",
        control: case(
            "the first touch a page below a frame of eight thousand",
            "SCPRT dist=1000 n=8000 ratio_pct=12\n",
        ),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[
            case("empty stream", ""),
            Case {
                exit: -1,
                signal: SIGSEGV,
                ..case("empty stream, killed by a segfault", "")
            },
        ]),
        zero: Form::Cases(&[
            case("every field zero", "SCPRT dist=0 n=0 ratio_pct=0\n"),
            case("the size zero", "SCPRT dist=100 n=0 ratio_pct=0\n"),
            case("the distance zero", "SCPRT dist=0 n=8388608 ratio_pct=0\n"),
            case(
                "the ratio zero beside a distance that computes to ten",
                "SCPRT dist=100 n=1000 ratio_pct=0\n",
            ),
        ]),
        missing: Form::Cases(&[
            case("no distance or size", "SCPRT ratio_pct=12\n"),
            case("no ratio", "SCPRT dist=1000 n=8000\n"),
            case("no distance", "SCPRT n=8000 ratio_pct=12\n"),
            case("no size", "SCPRT dist=1000 ratio_pct=12\n"),
            case("an empty ratio", "SCPRT dist=1000 n=8000 ratio_pct=\n"),
            case(
                "a distance that is not a number",
                "SCPRT dist=abc n=8000 ratio_pct=12\n",
            ),
            case("a decline with no reason", "SCPRT probe-invalid=\n"),
        ]),
        arch: Form::Cases(&[
            case(
                "a 32-bit wrapped line",
                "SCPRT dist=67108879 n=67108864 ratio_pct=36\n",
            ),
            case(
                "a distance wider than 32 bits beside a small size",
                "SCPRT dist=4294967296 n=8000 ratio_pct=12\n",
            ),
            case(
                "the probe declining for want of a handler",
                "SCPRT probe-invalid=no-handler\n",
            ),
        ]),
    },
    Row {
        detector: "detect_strict_flex_arrays",
        control: case(
            "flex-two=2 flex-one=1 flex-zero=0, optimized",
            "flex-two=2 flex-one=1 flex-zero=0\noptimize=yes\nstorage=declared\n",
        ),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("empty stream", "")]),
        zero: Form::Cases(&[case(
            "all three sizes zero, which no declaration of these arrays can report",
            "flex-two=0 flex-one=0 flex-zero=0\noptimize=yes\nstorage=declared\n",
        )]),
        missing: Form::Cases(&[
            case("no flex-zero reading", "flex-two=2 flex-one=1\n"),
            case(
                "an empty flex-zero reading",
                "flex-two=2 flex-one=1 flex-zero=\n",
            ),
            case(
                "a reading that is not a number",
                "flex-two=x flex-one=1 flex-zero=0\n",
            ),
            case(
                "the compiler's no-size answer for all three",
                "flex-two=-1 flex-one=-1 flex-zero=-1\noptimize=no\nstorage=declared\n",
            ),
        ]),
        arch: Form::NotApplicable(
            "the three sizes are printed by `__builtin_object_size` over declared objects and \
             name no architecture or width",
        ),
    },
    Row {
        detector: "detect_strict_flex_arrays_enforced",
        control: Case {
            stderr: SFA_LEVEL_3,
            ..case(
                "all five rows, three caught and the true flexible member surviving",
                "",
            )
        },
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("both streams empty, clean exit", "")]),
        zero: Form::NotApplicable(
            "the rows carry a status, not a count; a row that did nothing is the `exit:0` form \
             and is the `survived` outcome the control witness reads",
        ),
        missing: Form::Cases(&[
            Case {
                stderr: SFA_ZERO_ROW_UNTERMINATED,
                ..case("the zero row's end marker missing", "")
            },
            Case {
                stderr: SFA_CTRL_ONLY,
                ..case("only the ctrl row", "")
            },
            Case {
                stderr: SFA_EMPTY_STATUS,
                ..case("the ctrl row's status empty", "")
            },
            Case {
                stderr: SFA_LEVEL_3,
                exit: 1,
                ..case("every row read and the probe itself exiting nonzero", "")
            },
            Case {
                stderr: SFA_ALL_SURVIVED,
                ..case("every row survived with no optimization note", "")
            },
        ]),
        arch: Form::Cases(&[
            Case {
                stderr: SFA_TRAPS,
                ..case("rows ending in a trap with no self-report", "")
            },
            Case {
                stderr: SFA_TRAPS,
                ..case(
                    "rows ending in a trap beside a glibc self-report",
                    REPORT_GLIBC,
                )
            },
            Case {
                stderr: SFA_ALL_SURVIVED,
                ..case(
                    "survived rows, optimized, level 2 requested, report never closed, musl",
                    "optimize=yes\nlibc=musl\nCHARD-REPORT-V1\n_FORTIFY_SOURCE=2\n",
                )
            },
            Case {
                stderr: SFA_ALL_SURVIVED,
                ..case(
                    "survived rows, optimized, fortify level 0 requested, musl",
                    "optimize=yes\nlibc=musl\nCHARD-REPORT-V1\n_FORTIFY_SOURCE=0\nCHARD-REPORT-END\n",
                )
            },
            Case {
                stderr: SFA_ALL_SURVIVED,
                ..case(
                    "survived rows, optimized, level 2, a library the probe does not name",
                    "optimize=yes\nlibc=?\nCHARD-REPORT-V1\n_FORTIFY_SOURCE=2\nCHARD-REPORT-END\n",
                )
            },
        ]),
    },
    Row {
        detector: "detect_no_strict_overflow",
        control: case(
            "the guard ran in an optimized clang build",
            "overflow-guard=ran\noptimize=yes\nfrontend=clang\n",
        ),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("empty stream", "")]),
        zero: Form::NotApplicable("the reading is a word, not a count or a value"),
        missing: Form::Cases(&[
            case(
                "the guard key with no value",
                "overflow-guard=\noptimize=yes\n",
            ),
            case(
                "the guard ran with no optimization or front-end note",
                "overflow-guard=ran\n",
            ),
            case(
                "the guard ran unoptimized under a front end that is neither named",
                "overflow-guard=ran\noptimize=no\nfrontend=other\n",
            ),
            case(
                "the guard ran unoptimized on gcc with no version line",
                "overflow-guard=ran\noptimize=no\nfrontend=gcc\n",
            ),
            case(
                "the guard ran optimized on gcc 7 with no build record to read the level from",
                "overflow-guard=ran\noptimize=yes\nfrontend=gcc\ngcc-major=7\n",
            ),
            case(
                "the guard ran unoptimized on gcc with an empty version",
                "overflow-guard=ran\noptimize=no\nfrontend=gcc\ngcc-major=\n",
            ),
            case(
                "the guard ran unoptimized on gcc with a version that is no number",
                "overflow-guard=ran\noptimize=no\nfrontend=gcc\ngcc-major=eight\n",
            ),
            case(
                "a guard value that merely begins with the word `ran`",
                "overflow-guard=ranged\noptimize=yes\nfrontend=clang\n",
            ),
        ]),
        arch: Form::NotApplicable(
            "the probe's output names no architecture; its only target-dependent facts are the \
             front end and gcc's version, which the missing form feeds",
        ),
    },
    Row {
        detector: "detect_no_delete_null_checks",
        control: case("the null check survived", "null-check=kept\n"),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[
            case("empty stream", ""),
            Case {
                exit: -1,
                signal: SIGSEGV,
                ..case("empty stream, killed by a segfault", "")
            },
        ]),
        zero: Form::NotApplicable("the reading is a word, not a count or a value"),
        missing: Form::Cases(&[
            case("the key with no value", "null-check=\n"),
            case("the value with no key", "kept\n"),
            case(
                "a value that merely begins with the word `kept`",
                "null-check=kept-over\n",
            ),
        ]),
        arch: Form::NotApplicable("the probe's output names no architecture"),
    },
    Row {
        detector: "detect_no_strict_aliasing",
        control: case(
            "the store was lost in an optimized build",
            "optimize=yes\naliasing-store=lost\n",
        ),
        control_reads: Outcome::Absent,
        empty: Form::Cases(&[case("empty stream", "")]),
        zero: Form::NotApplicable("the readings are words, not counts or values"),
        missing: Form::Cases(&[
            case(
                "the store key with no value",
                "optimize=yes\naliasing-store=\n",
            ),
            case(
                "only the uninstrumented copy's reading",
                "optimize=yes\nuninstrumented-store=lost\n",
            ),
            case(
                "only the -O2 witness",
                "optimize=yes\no2-witness=observed\n",
            ),
            case(
                "only the attribute check",
                "optimize=yes\nattribute-check=honoured\n",
            ),
            case(
                "the store observed, the -O2 witness lost, and no attribute check",
                "optimize=yes\naliasing-store=observed\no2-witness=lost\n",
            ),
            case(
                "a store reading from an unoptimized build",
                "optimize=no\naliasing-store=lost\n",
            ),
        ]),
        arch: Form::NotApplicable("the probe's output names no architecture"),
    },
    Row {
        detector: "detect_zero_init_padding",
        control: case(
            "a zeroed pad beside an intact witness",
            "ZIPB pad=00 ctrl=5a ctrl_supported=1\n",
        ),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("empty stream", "")]),
        zero: Form::Cases(&[case(
            "the witness zero where it is supported",
            "ZIPB pad=00 ctrl=00 ctrl_supported=1\n",
        )]),
        missing: Form::Cases(&[
            case("no ctrl or support field", "ZIPB pad=00\n"),
            case("no support field", "ZIPB pad=00 ctrl=5a\n"),
            case("no pad", "ZIPB ctrl=5a ctrl_supported=1\n"),
            case("an empty pad", "ZIPB pad= ctrl=5a ctrl_supported=1\n"),
            case(
                "a support flag that is neither 0 nor 1, beside a witness that failed",
                "ZIPB pad=00 ctrl=00 ctrl_supported=x\n",
            ),
        ]),
        arch: Form::NotApplicable("the probe's output names no architecture"),
    },
    Row {
        detector: "detect_auto_var_init",
        control: case(
            "a zero fill with the witness intact",
            "TAVI arr=00 word=00 small=00 ctrl=5a ctrl_supported=1\n",
        ),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("empty stream", "")]),
        zero: Form::Cases(&[case(
            "a zero fill beside a zeroed witness",
            "TAVI arr=00 word=00 small=00 ctrl=00 ctrl_supported=1\n",
        )]),
        missing: Form::Cases(&[
            case(
                "no small shape",
                "TAVI arr=00 word=00 ctrl=5a ctrl_supported=1\n",
            ),
            case(
                "empty shapes",
                "TAVI arr= word= small= ctrl=5a ctrl_supported=1\n",
            ),
            case(
                "a zero fill with no witness field",
                "TAVI arr=00 word=00 small=00\n",
            ),
            case(
                "a zero fill that claims a witness and prints none",
                "TAVI arr=00 word=00 small=00 ctrl_supported=1\n",
            ),
        ]),
        arch: Form::Cases(&[
            Case {
                elf_class: Some(64),
                ..case(
                    "clang's 32-bit pattern byte on a 64-bit artifact",
                    "TAVI arr=ff word=ff small=ff ctrl=5a ctrl_supported=1\n",
                )
            },
            Case {
                elf_class: Some(32),
                ..case(
                    "clang's 64-bit pattern byte on a 32-bit artifact",
                    "TAVI arr=aa word=aa small=aa ctrl=5a ctrl_supported=1\n",
                )
            },
            case(
                "clang's 32-bit pattern byte and no ELF header to place it",
                "TAVI arr=ff word=ff small=ff ctrl=5a ctrl_supported=1\n",
            ),
        ]),
    },
    Row {
        detector: "detect_auto_var_init_pattern",
        control: case(
            "gcc's pattern byte with the witness intact",
            "TAVI arr=fe word=fe small=fe ctrl=5a ctrl_supported=1\n",
        ),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("empty stream", "")]),
        zero: Form::Cases(&[case(
            "a pattern fill beside a zeroed witness",
            "TAVI arr=fe word=fe small=fe ctrl=00 ctrl_supported=1\n",
        )]),
        missing: Form::Cases(&[
            case(
                "no small shape",
                "TAVI arr=fe word=fe ctrl=5a ctrl_supported=1\n",
            ),
            case(
                "empty shapes",
                "TAVI arr= word= small= ctrl=5a ctrl_supported=1\n",
            ),
            case(
                "a pattern fill with no witness field",
                "TAVI arr=fe word=fe small=fe\n",
            ),
            case(
                "a pattern fill that claims a witness and prints none",
                "TAVI arr=fe word=fe small=fe ctrl_supported=1\n",
            ),
        ]),
        arch: Form::Cases(&[
            Case {
                elf_class: Some(64),
                ..case(
                    "clang's 32-bit pattern byte on a 64-bit artifact",
                    "TAVI arr=ff word=ff small=ff ctrl=5a ctrl_supported=1\n",
                )
            },
            Case {
                elf_class: Some(32),
                ..case(
                    "clang's 64-bit pattern byte on a 32-bit artifact",
                    "TAVI arr=aa word=aa small=aa ctrl=5a ctrl_supported=1\n",
                )
            },
            case(
                "clang's 32-bit pattern byte and no ELF header to place it",
                "TAVI arr=ff word=ff small=ff ctrl=5a ctrl_supported=1\n",
            ),
        ]),
    },
    Row {
        detector: "detect_zero_call_used_regs",
        control: case(
            "six argument registers and the temporary all zero, the x86_64 pair",
            "ZCUR args=6 temp=r11 null=kkkkkk/k target=zzzzzz/z\n",
        ),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("empty stream", "")]),
        zero: Form::Cases(&[
            case(
                "no argument registers, so every all-zero test holds vacuously",
                "ZCUR args=0 temp=r11 null=/k target=/z\n",
            ),
            case(
                "no argument registers and an unchanged temporary",
                "ZCUR args=0 temp=r11 null=/k target=/k\n",
            ),
            case(
                "a zero count beside letters for registers",
                "ZCUR args=0 temp=r11 null=kk/k target=zz/z\n",
            ),
        ]),
        missing: Form::Cases(&[
            case("no count", "ZCUR temp=r11 null=kkkkkk/k target=zzzzzz/z\n"),
            case("no target reading", "ZCUR args=6 temp=r11 null=kkkkkk/k\n"),
            case("no null reading", "ZCUR args=6 temp=r11 target=zzzzzz/z\n"),
            case(
                "a target with no temporary",
                "ZCUR args=6 temp=r11 null=kkkkkk/k target=zzzzzz\n",
            ),
            case(
                "a count that is not a number",
                "ZCUR args=x temp=r11 null=kkkkkk/k target=zzzzzz/z\n",
            ),
            case(
                "a letter outside the alphabet",
                "ZCUR args=6 temp=r11 null=kkkkkk/k target=zzzzzq/z\n",
            ),
        ]),
        arch: Form::Cases(&[
            case(
                "the probe's own unsupported-architecture line",
                "ZCUR unsupported-arch\n",
            ),
            case(
                "the unsupported line followed by a reading",
                "ZCUR unsupported-arch\nZCUR args=6 temp=r11 null=kkkkkk/k target=zzzzzz/z\n",
            ),
            case(
                "a count that is no architecture's argument-register count",
                "ZCUR args=1 temp=r11 null=k/k target=z/z\n",
            ),
        ]),
    },
    Row {
        detector: "detect_stack_exec",
        control: case(
            "the payload faulted",
            "NXRT arch=x86_64 calling\nNXRT stack-exec=no fault=payload\n",
        ),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[
            case("empty stream", ""),
            Case {
                exit: -1,
                signal: SIGSEGV,
                ..case("empty stream, killed by a segfault", "")
            },
        ]),
        zero: Form::Cases(&[
            case(
                "the payload returned zero rather than its marker",
                "NXRT arch=x86_64 calling\nNXRT stack-exec=yes ret=0\n",
            ),
            case(
                "the payload's marker padded to a zero-led number",
                "NXRT arch=x86_64 calling\nNXRT stack-exec=yes ret=077\n",
            ),
        ]),
        missing: Form::Cases(&[
            case("the call line and no result", "NXRT arch=x86_64 calling\n"),
            case(
                "a result and no call line",
                "NXRT stack-exec=no fault=payload\n",
            ),
            case(
                "a call line with no calling word",
                "NXRT arch=x86_64\nNXRT stack-exec=no fault=payload\n",
            ),
            Case {
                exit: -1,
                signal: SIGSEGV,
                ..case(
                    "a result, then a death",
                    "NXRT arch=x86_64 calling\nNXRT stack-exec=no fault=payload\n",
                )
            },
            case(
                "a call line whose architecture is empty",
                "NXRT arch= calling\nNXRT stack-exec=no fault=payload\n",
            ),
        ]),
        arch: Form::Cases(&[
            case(
                "the probe declining for an architecture it has no payload for",
                "NXRT probe-invalid=no-payload-for-this-architecture\n",
            ),
            case(
                "the decline after a call line",
                "NXRT arch=riscv64 calling\nNXRT probe-invalid=no-payload-for-this-architecture\n",
            ),
            case(
                "an unknown result",
                "NXRT arch=x86_64 calling\nNXRT stack-exec=unknown fault=sigill\n",
            ),
        ]),
    },
    Row {
        detector: "detect_shadow_stack",
        control: case("enforced under the pinned run", SHSTK_PINNED_ENFORCED),
        control_reads: Outcome::Present,
        empty: Form::Cases(&[case("empty stream", "")]),
        zero: Form::Cases(&[
            case(
                "status word zero beside a set shadow stack pointer and a faulted clobber",
                "SHSTK kernel=ok cpu=ss features=0x0 ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
            case(
                "status word set beside a zero shadow stack pointer and a faulted clobber",
                "SHSTK kernel=ok cpu=ss features=0x1 ssp=zero\nSHSTK clobber=cperr\n",
            ),
            case(
                "an empty status word",
                "SHSTK kernel=ok cpu=ss features= ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
        ]),
        missing: Form::Cases(&[
            case(
                "no ssp",
                "SHSTK kernel=ok cpu=ss features=0x1\nSHSTK clobber=cperr\n",
            ),
            case(
                "no clobber line",
                "SHSTK kernel=ok cpu=ss features=0x1 ssp=nonzero\n",
            ),
            case(
                "no features",
                "SHSTK kernel=ok cpu=ss ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
            case(
                "no cpu",
                "SHSTK kernel=ok features=0x1 ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
            case(
                "no kernel",
                "SHSTK cpu=ss features=0x1 ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
            case(
                "a status word that is not hex",
                "SHSTK kernel=ok cpu=ss features=0xzz ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
            case(
                "an ssp word that is neither",
                "SHSTK kernel=ok cpu=ss features=0x1 ssp=maybe\nSHSTK clobber=cperr\n",
            ),
            case(
                "an errno with no number",
                "SHSTK kernel=errno: cpu=ss features=0x1 ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
            case(
                "a cpu word outside the vocabulary",
                "SHSTK kernel=ok cpu=weird features=0x1 ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
            case(
                "a clobber that returned",
                "SHSTK kernel=ok cpu=ss features=0x1 ssp=nonzero\nSHSTK clobber=returned\n",
            ),
        ]),
        arch: Form::Cases(&[
            case(
                "the probe's own unsupported-architecture line",
                "SHSTK unsupported-arch\n",
            ),
            case(
                "a CPU that does not enumerate the feature",
                "SHSTK kernel=ok cpu=no-ss features=0x0 ssp=zero\nSHSTK clobber=hijacked\n",
            ),
            case(
                "a CPU with no leaf 7",
                "SHSTK kernel=ok cpu=no-leaf7 features=0x0 ssp=zero\nSHSTK clobber=hijacked\n",
            ),
            case(
                "a kernel without the feature",
                "SHSTK kernel=errno:22 cpu=ss features=0x0 ssp=zero\nSHSTK clobber=hijacked\n",
            ),
            case(
                "a kernel refusing for another cause",
                "SHSTK kernel=errno:1 cpu=ss features=0x1 ssp=nonzero\nSHSTK clobber=cperr\n",
            ),
        ]),
    },
    Row {
        detector: "detect_trapv",
        control: Case {
            exit: -1,
            signal: SIGABRT,
            ..case(
                "gcc aborting in the overflowing addition",
                "frontend=gcc\nubsan=no\ntrapv-overflow=attempted\n",
            )
        },
        control_reads: Outcome::Present,
        empty: Form::Cases(&[
            case("empty stream, clean exit", ""),
            Case {
                exit: -1,
                signal: SIGSEGV,
                ..case("empty stream, killed by a segfault", "")
            },
        ]),
        zero: Form::NotApplicable(
            "no field is a count; the sum the probe prints after a wrap is never read, which the \
             inventory records as a deliberate non-reading",
        ),
        missing: Form::Cases(&[
            case(
                "the overflow key with no value",
                "frontend=gcc\nubsan=no\ntrapv-overflow=\n",
            ),
            case(
                "front end and sanitizer notes and no overflow line",
                "frontend=gcc\nubsan=no\n",
            ),
            case(
                "attempted and then a clean exit",
                "frontend=gcc\nubsan=no\ntrapv-overflow=attempted\n",
            ),
            Case {
                exit: -1,
                signal: SIGABRT,
                ..case(
                    "an abort with the front end not reported",
                    "ubsan=no\ntrapv-overflow=attempted\n",
                )
            },
            Case {
                exit: -1,
                signal: SIGILL,
                ..case(
                    "a trap with the front end not reported",
                    "ubsan=no\ntrapv-overflow=attempted\n",
                )
            },
            case(
                "an overflow word outside the vocabulary",
                "frontend=gcc\nubsan=no\ntrapv-overflow=exploded\n",
            ),
        ]),
        arch: Form::Cases(&[
            Case {
                exit: -1,
                signal: SIGILL,
                ..case(
                    "a trap from a front end that is neither compiler",
                    "frontend=other\nubsan=unknown\ntrapv-overflow=attempted\n",
                )
            },
            Case {
                exit: -1,
                signal: SIGILL,
                ..case(
                    "a trap under gcc, whose -ftrapv aborts",
                    "frontend=gcc\nubsan=no\ntrapv-overflow=attempted\n",
                )
            },
            Case {
                exit: -1,
                signal: SIGABRT,
                ..case(
                    "an abort under clang, whose -ftrapv traps",
                    "frontend=clang\nubsan=no\ntrapv-overflow=attempted\n",
                )
            },
        ]),
    },
];

// --- the harness -----------------------------------------------------------------

fn run_record(c: &Case) -> RunRecord {
    RunRecord {
        argv: vec!["probe".to_owned()],
        exit_status: c.exit,
        signal: c.signal.map(ToOwned::to_owned),
        stdout: c.stdout.to_owned(),
        stderr: c.stderr.to_owned(),
        timed_out: false,
        deadline_ms: None,
        output_error: None,
        output_truncated: false,
        duration_ms: 1,
        environment: None,
    }
}

/// An artifact's facts with its ELF class set. The JSON is the shape `probe::tests`'
/// `elf_with_report` builds; `tests/schema_conformance.rs` holds `ElfFacts` to its schema, so a
/// field added there fails this fixture at the `expect`.
fn elf_of_class(class: u8) -> ElfFacts {
    serde_json::from_value(serde_json::json!({
        "aarch64_bti": false, "aarch64_pac": false, "bind_now": false,
        "df_1_noopen": false, "df_1_pie": false, "dt_debug": false,
        "dt_relr": false, "dt_soname": false,
        "dynamic_tags": [], "elf_class": class, "elf_data": "little-endian", "elf_type": "ET_EXEC",
        "aarch64_gcs": false, "gnu_property_types": [], "gnu_relro": true,
        "gnu_stack_executable": false, "gnu_stack_present": true,
        "has_dynamic": true, "has_interp": true, "machine": "x86_64",
        "needed": [], "pie": false, "recorded_command_line": "",
        "relro": "partial", "rpath": [], "runpath": [], "sections": [],
        "self_report": "", "shared_object": false, "static_pie": false,
        "statically_linked": false, "symbol_count": 35, "textrel": false,
        "watched_symbols": {}, "x86_ibt": false, "x86_shstk": false,
    }))
    .expect("the fixture matches ElfFacts")
}

/// The detector function the corpus wires to `name`, or `None` for a name no runtime check
/// uses. Taken from the corpus, so the function exercised is the one a report is made by.
fn corpus_detector(name: &str) -> Option<fn(&Evidence<'_>) -> Detection> {
    CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find_map(|check| match check.decoder {
            Decoder::Runtime { detect, .. } if detect.name == name => Some(detect.detect),
            _ => None,
        })
}

fn feed(detector: &str, c: &Case) -> Outcome {
    let detect = corpus_detector(detector)
        .unwrap_or_else(|| panic!("{detector}: no runtime check in the corpus uses it"));
    let macros: BTreeMap<String, String> = c
        .macros
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let run = run_record(c);
    let elf = c.elf_class.map(elf_of_class);
    detect(&Evidence {
        macros: &macros,
        elf: elf.as_ref(),
        build: None,
        run: Some(&run),
        workdir: None,
    })
    .outcome
}

fn forms(row: &Row) -> [(&'static str, &Form); 4] {
    [
        ("empty", &row.empty),
        ("zero", &row.zero),
        ("missing", &row.missing),
        ("arch", &row.arch),
    ]
}

fn cases_of(form: &Form) -> &'static [Case] {
    match form {
        Form::Cases(cases) => cases,
        Form::NotApplicable(_) => &[],
    }
}

fn all_cases() -> impl Iterator<Item = (&'static Row, &'static str, &'static Case)> {
    ROWS.iter().flat_map(|row| {
        forms(row)
            .into_iter()
            .flat_map(move |(name, form)| cases_of(form).iter().map(move |c| (row, name, c)))
    })
}

// --- the tests -------------------------------------------------------------------

#[test]
fn every_degenerate_form_is_withheld() {
    let expected = all_cases().filter(|(_, _, c)| c.defect.is_none()).count();
    let mut fed = 0usize;
    let mut accepted = Vec::new();
    for (row, form, c) in all_cases() {
        if c.defect.is_some() {
            continue;
        }
        fed += 1;
        let got = feed(row.detector, c);
        if got != Outcome::Indeterminate {
            accepted.push(format!(
                "{} / {form} / {}: read {} from {:?} (stderr {:?}, exit {}, signal {:?})",
                row.detector,
                c.label,
                got.as_str(),
                c.stdout,
                c.stderr,
                c.exit,
                c.signal
            ));
        }
    }
    assert_eq!(
        fed, expected,
        "the loop fed a different count than the table holds"
    );
    assert!(
        fed > 0,
        "a loop over no cases that passes is the failure this table exists to prevent"
    );
    assert!(
        accepted.is_empty(),
        "a degenerate line was read as a measurement:\n{}",
        accepted.join("\n")
    );
}

#[test]
fn each_rows_well_formed_line_reads_its_verdict() {
    let mut fed = 0usize;
    for row in ROWS {
        fed += 1;
        assert_eq!(
            feed(row.detector, &row.control),
            row.control_reads,
            "{}: the control line {:?} must read {}, or the table is not reaching the decoder",
            row.detector,
            row.control.label,
            row.control_reads.as_str()
        );
    }
    assert_eq!(fed, ROWS.len());
}

#[test]
fn a_row_with_cases_for_every_form_it_claims_and_a_reason_for_every_form_it_does_not() {
    for row in ROWS {
        assert!(
            matches!(row.empty, Form::Cases(c) if !c.is_empty()),
            "{}: the empty form applies to every decoder and needs a case",
            row.detector
        );
        for (name, form) in forms(row) {
            match form {
                Form::Cases(cases) => assert!(
                    !cases.is_empty(),
                    "{}: the {name} form lists no cases; say why it does not apply instead",
                    row.detector
                ),
                Form::NotApplicable(reason) => assert!(
                    reason.split_whitespace().count() >= 6,
                    "{}: the {name} form is not applicable without a reason that says why",
                    row.detector
                ),
            }
        }
        // Distinct labels inside a form: a pasted-twice case is a case not written.
        for (name, form) in forms(row) {
            let labels: BTreeSet<&str> = cases_of(form).iter().map(|c| c.label).collect();
            assert_eq!(
                labels.len(),
                cases_of(form).len(),
                "{}: the {name} form repeats a label",
                row.detector
            );
        }
    }
}

/// The completeness guard, corpus side: the detectors the corpus maps to the runtime channel
/// are the rows, no more and no fewer.
#[test]
fn every_runtime_detector_the_corpus_wires_has_a_row() {
    let mut wired: BTreeSet<&str> = BTreeSet::new();
    let mut checks = 0usize;
    for check in CORPUS.iter().flat_map(|p| p.checks.iter()) {
        if let Decoder::Runtime { detect, .. } = check.decoder {
            wired.insert(detect.name);
            checks += 1;
        }
    }
    assert!(
        checks > 0,
        "the corpus holds no runtime check; the scan read nothing"
    );
    let rows: Vec<&str> = ROWS.iter().map(|r| r.detector).collect();
    let row_set: BTreeSet<&str> = rows.iter().copied().collect();
    assert_eq!(rows.len(), row_set.len(), "a detector has two rows");
    let unrowed: Vec<&&str> = wired.difference(&row_set).collect();
    let unwired: Vec<&&str> = row_set.difference(&wired).collect();
    assert!(
        unrowed.is_empty(),
        "runtime detectors the corpus wires with no row in ROWS: {unrowed:?}"
    );
    assert!(
        unwired.is_empty(),
        "rows naming a detector no runtime check uses: {unwired:?}"
    );
}

/// The completeness guard, source side: every `detect_*` function `src/decode/runtime.rs`
/// defines is a row, so a detector added to the module and not yet wired into the corpus
/// still needs its shapes decided.
#[test]
fn every_detect_function_in_the_runtime_module_has_a_row() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/decode/runtime.rs");
    let text = std::fs::read_to_string(&path).expect("reading src/decode/runtime.rs");
    let defined: BTreeSet<String> = text
        .lines()
        .filter_map(|l| {
            let l = l
                .strip_prefix("pub(crate) ")
                .or_else(|| l.strip_prefix("pub "))?;
            let name = l.strip_prefix("fn ")?;
            let name: String = name
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            name.starts_with("detect_").then_some(name)
        })
        .collect();
    assert!(
        !defined.is_empty(),
        "the scan found no detector in runtime.rs"
    );
    let rows: BTreeSet<String> = ROWS.iter().map(|r| r.detector.to_owned()).collect();
    assert_eq!(
        defined, rows,
        "the detect_* functions in src/decode/runtime.rs and the rows of ROWS differ"
    );
}

// --- cases a defect makes fail ------------------------------------------------------

#[allow(
    dead_code,
    reason = "no handle is open; the next case a defect makes fail adds one and its \
              ignored test"
)]
fn run_defect(handle: &str) {
    let mut fed = 0usize;
    let mut accepted = Vec::new();
    for (row, form, c) in all_cases().filter(|(_, _, c)| c.defect == Some(handle)) {
        fed += 1;
        let got = feed(row.detector, c);
        if got != Outcome::Indeterminate {
            accepted.push(format!(
                "{} / {form} / {}: read {} from {:?}",
                row.detector,
                c.label,
                got.as_str(),
                c.stdout
            ));
        }
    }
    assert!(
        fed > 0,
        "{handle}: no case in the table carries this handle"
    );
    assert!(
        accepted.is_empty(),
        "{handle} is still open:\n{}",
        accepted.join("\n")
    );
}

/// A handle in the table has an ignored test that runs it, and an ignored test in this file
/// has cases: neither side can be dropped alone.
#[test]
fn every_defect_handle_has_its_ignored_test_and_the_reverse() {
    let source = include_str!("degenerate_readings.rs");
    let in_table: BTreeSet<&str> = all_cases().filter_map(|(_, _, c)| c.defect).collect();
    for handle in &in_table {
        let attribute = format!("#[ignore = \"{handle}: ");
        assert!(
            source.contains(&attribute),
            "{handle}: cases carry this handle and no #[ignore] test runs them"
        );
    }
    let ignored: BTreeSet<String> = source
        .lines()
        .filter_map(|l| l.strip_prefix("#[ignore = \""))
        .filter_map(|rest| rest.split_once(':').map(|(h, _)| h.to_owned()))
        .collect();
    let table: BTreeSet<String> = in_table.iter().map(|h| (*h).to_owned()).collect();
    assert_eq!(
        ignored, table,
        "the #[ignore] tests and the handles on the table's cases differ"
    );
}

// --- the other reader of a probe's line ------------------------------------------------

/// `report::machine_lacks_shadow_stack` reads the same SHSTK line as the detector and turns
/// it into a published gating sentence. A degenerate line must not produce one.
#[test]
fn the_machine_lack_gating_reads_no_degenerate_shadow_stack_line() {
    let check = CORPUS
        .iter()
        .flat_map(|p| p.checks.iter())
        .find(|c| c.id == chard::report::SHADOW_STACK_CHECK)
        .expect("the corpus holds the shadow-stack check");
    let row = ROWS
        .iter()
        .find(|r| r.detector == "detect_shadow_stack")
        .expect("a shadow-stack row");
    let gate = |stdout: &str| {
        chard::report::machine_lacks_shadow_stack(
            check,
            Some(Outcome::Indeterminate),
            Some(stdout),
            Some(true),
        )
    };
    let mut fed = 0usize;
    for (name, form) in [
        ("empty", &row.empty),
        ("zero", &row.zero),
        ("missing", &row.missing),
    ] {
        for c in cases_of(form) {
            fed += 1;
            assert!(
                gate(c.stdout).is_none(),
                "{name} / {}: the gating named a lack the line does not say: {:?}",
                c.label,
                c.stdout
            );
        }
    }
    assert!(fed > 0);
    // The control: a line that does say the kernel lacks the feature does gate.
    assert!(
        gate("SHSTK kernel=errno:22 cpu=ss features=0x0 ssp=zero\nSHSTK clobber=hijacked\n")
            .is_some(),
        "the gating declined a line that says the kernel has no shadow stack"
    );
    // And the arch-form lines that name a lack do gate, the unsupported-arch one does not.
    assert!(gate("SHSTK unsupported-arch\n").is_none());
}
